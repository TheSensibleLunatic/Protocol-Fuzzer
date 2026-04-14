"""
icmp_fuzzer.py — ICMP protocol fuzzer for marvell-proto-fuzzer.

Mutates the following ICMP fields:
- type  (out-of-range values: 0-255, reserved/unassigned types)
- code  (out-of-range values per type)
- checksum (intentionally wrong — breaks integrity)
- payload (random bytes, null bytes, max-length overflow)
- TTL=0 edge cases on the IP layer
- IP total length manipulation
"""

import struct
from typing import Optional

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw

from fuzzer.packet_generator import PacketGenerator, FuzzMode
from fuzzer.utils import setup_logger, internet_checksum, corrupt_checksum

logger = setup_logger(__name__)

# ICMP types with defined meanings (RFC 792 and extensions)
ICMP_KNOWN_TYPES = {0, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}
# Unassigned / reserved types that should cause MALFORMED classification
ICMP_INVALID_TYPES = [6, 7, 19, 20, 40, 41, 100, 127, 200, 250, 255]
# Invalid codes for type 3 (Destination Unreachable), which has codes 0-15
ICMP_INVALID_CODES_TYPE3 = [16, 17, 100, 200, 255]

# Maximum legal ICMP payload under a standard 1500-byte Ethernet MTU
MAX_ICMP_PAYLOAD = 1472  # 1500 - 20 (IP) - 8 (ICMP)


class ICMPFuzzer:
    """
    ICMP layer fuzzer.

    Parameters
    ----------
    generator: PacketGenerator
        Shared mutation engine (carries the seeded RNG + mode).
    iface: str
        Network interface name used for sending.
    src_ip: str
        Source IP address embedded in fuzzed packets.
    dst_ip: str
        Destination IP address.
    """

    def __init__(
        self,
        generator: PacketGenerator,
        iface: str = "lo",
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.2",
    ):
        self.gen = generator
        self.iface = iface
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self._rng = generator._rng

    # ------------------------------------------------------------------
    # Baseline (valid) packet
    # ------------------------------------------------------------------

    def _valid_icmp(self) -> bytes:
        """Return a well-formed ICMP echo request as raw bytes."""
        pkt = (
            Ether()
            / IP(src=self.src_ip, dst=self.dst_ip, ttl=64)
            / ICMP(type=8, code=0)
            / Raw(load=b"\x00" * 56)
        )
        return bytes(pkt)

    # ------------------------------------------------------------------
    # Field-level mutators (operate on Scapy layers in-place)
    # ------------------------------------------------------------------

    def _fuzz_type(self, icmp: ICMP) -> None:
        """Set ICMP type to an out-of-range or reserved value."""
        if self.gen.mode == FuzzMode.BOUNDARY:
            icmp.type = self._rng.choice(ICMP_INVALID_TYPES)
        elif self.gen.mode == FuzzMode.MUTATION:
            icmp.type = self._rng.choice(list(ICMP_KNOWN_TYPES) + ICMP_INVALID_TYPES)
        else:  # RANDOM
            icmp.type = self._rng.randint(0, 255)

    def _fuzz_code(self, icmp: ICMP) -> None:
        """Set ICMP code to an out-of-range value."""
        if self.gen.mode == FuzzMode.BOUNDARY:
            icmp.code = self._rng.choice([0, 1, 15, 16, 255])
        else:
            icmp.code = self.gen.fuzz_byte(icmp.code)

    def _fuzz_checksum(self, icmp: ICMP) -> ICMP:
        """Force a wrong checksum by computing the correct one then flipping it."""
        # Build the packet first to compute a valid checksum
        raw = bytes(icmp)
        valid_cs = internet_checksum(raw)
        bad_cs = corrupt_checksum(valid_cs)
        icmp.chksum = bad_cs
        return icmp

    def _fuzz_payload(self, frame: Ether) -> Ether:
        """Replace the ICMP payload with fuzzed data."""
        fuzzed = self.gen.fuzz_bytes(
            b"\x00" * 56, min_len=0, max_len=MAX_ICMP_PAYLOAD
        )
        # Rebuild from IP layer up
        ip = frame[IP]
        icmp = frame[ICMP]
        new_frame = (
            Ether(src=frame.src, dst=frame.dst)
            / IP(src=ip.src, dst=ip.dst, ttl=ip.ttl)
            / ICMP(type=icmp.type, code=icmp.code)
            / Raw(load=fuzzed)
        )
        return new_frame

    def _fuzz_ttl(self, ip: IP) -> None:
        """Set the IP TTL to an interesting boundary value (0, 1, 255)."""
        if self.gen.mode == FuzzMode.BOUNDARY:
            ip.ttl = self._rng.choice([0, 1, 2, 127, 255])
        elif self.gen.mode == FuzzMode.MUTATION:
            ip.ttl = max(0, (ip.ttl + self._rng.randint(1, 255)) % 256)
        else:
            ip.ttl = self._rng.randint(0, 255)

    def _fuzz_ip_length(self, ip: IP) -> None:
        """
        Corrupt the IP total length field:
        - Set to zero
        - Set to a value smaller than header (< 20)
        - Set to 65535
        """
        if self.gen.mode == FuzzMode.BOUNDARY:
            ip.len = self._rng.choice([0, 1, 19, 20, 0xFFFF])
        else:
            ip.len = self.gen.fuzz_word(ip.len or 0)

    def _fuzz_ip_src(self, ip: IP) -> None:
        ip.src = self.gen.fuzz_ip(ip.src or "0.0.0.0")

    def _fuzz_ip_dst(self, ip: IP) -> None:
        ip.dst = self.gen.fuzz_ip(ip.dst or "0.0.0.0")

    def _fuzz_ip_flags(self, ip: IP) -> None:
        """Set IP flags including forbidden combinations."""
        ip.flags = self._rng.randint(0, 7)  # 3-bit field; 7 = DF+MF (invalid)

    def _fuzz_fragment_offset(self, ip: IP) -> None:
        """Set fragment offset to a nonzero value, triggering re-assembly paths."""
        ip.frag = self._rng.randint(1, 8191)

    # ------------------------------------------------------------------
    # Public: generate a single fuzzed ICMP packet
    # ------------------------------------------------------------------

    def generate(self) -> bytes:
        """Return a single fuzzed ICMP packet as raw bytes."""
        # Build a valid base frame first
        frame = (
            Ether()
            / IP(src=self.src_ip, dst=self.dst_ip, ttl=64)
            / ICMP(type=8, code=0)
            / Raw(load=b"\x41" * 56)
        )

        ip_layer = frame[IP]
        icmp_layer = frame[ICMP]

        # Choose random subset of IP-level mutators
        ip_mutators = [
            self._fuzz_ttl,
            self._fuzz_ip_length,
            self._fuzz_ip_src,
            self._fuzz_ip_dst,
            self._fuzz_ip_flags,
            self._fuzz_fragment_offset,
        ]
        n_ip = self._rng.randint(0, len(ip_mutators))
        for m in self._rng.sample(ip_mutators, n_ip):
            m(ip_layer)

        # Choose random subset of ICMP-level mutators
        icmp_mutators_basic = [self._fuzz_type, self._fuzz_code]
        n_icmp = self._rng.randint(1, len(icmp_mutators_basic))
        for m in self._rng.sample(icmp_mutators_basic, n_icmp):
            m(icmp_layer)

        # Possibly corrupt checksum (40% chance)
        if self._rng.random() < 0.40:
            self._fuzz_checksum(icmp_layer)

        # Possibly replace payload (50% chance)
        if self._rng.random() < 0.50:
            frame = self._fuzz_payload(frame)

        raw = bytes(frame)
        logger.debug(
            "ICMP fuzzed: type=%s code=%s ttl=%s len=%d",
            frame[ICMP].type if ICMP in frame else "?",
            frame[ICMP].code if ICMP in frame else "?",
            frame[IP].ttl if IP in frame else "?",
            len(raw),
        )
        return raw

    def generate_batch(self, count: int) -> list[bytes]:
        """Return a list of *count* fuzzed ICMP packets."""
        return [self.generate() for _ in range(count)]
