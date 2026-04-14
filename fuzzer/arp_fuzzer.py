"""
arp_fuzzer.py — ARP protocol fuzzer for marvell-proto-fuzzer.

Mutates the following ARP fields:
- hwsrc / hwdst  (hardware addresses)
- psrc  / pdst   (protocol/IP addresses)
- op             (opcode — invalid values beyond 1/2)
- padding        (injected oversized padding)
- frame length   (undersized / oversized)
"""

import random
from typing import Optional

from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw

from fuzzer.packet_generator import PacketGenerator, FuzzMode
from fuzzer.utils import setup_logger, bytes_to_hex

logger = setup_logger(__name__)

# ARP opcodes: 1=REQUEST, 2=REPLY — anything else is invalid
VALID_ARP_OPS = {1, 2}
INVALID_ARP_OPS = [0, 3, 4, 5, 8, 255, 0xFFFF]

# ARP hardware types
HW_TYPE_ETHERNET = 1
INVALID_HW_TYPES = [0x0000, 0x0002, 0x00FF, 0xFFFF]

# ARP protocol types
PTYPE_IPV4 = 0x0800
INVALID_PTYPES = [0x0000, 0x0001, 0x86DD, 0xFFFF]


class ARPFuzzer:
    """
    ARP layer fuzzer.

    Parameters
    ----------
    generator: PacketGenerator
        Shared mutation engine (carries the seeded RNG + mode).
    iface: str
        Network interface name used for sending.
    """

    def __init__(self, generator: PacketGenerator, iface: str = "lo"):
        self.gen = generator
        self.iface = iface
        self._rng = generator._rng

    # ------------------------------------------------------------------
    # Baseline (valid) packet — used as mutation seed
    # ------------------------------------------------------------------

    def _valid_arp(self) -> Ether:
        """Return a well-formed ARP request frame."""
        return (
            Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op=1,
                hwsrc="aa:bb:cc:dd:ee:ff",
                hwdst="00:00:00:00:00:00",
                psrc="192.168.1.1",
                pdst="192.168.1.2",
            )
        )

    # ------------------------------------------------------------------
    # Individual field mutators
    # ------------------------------------------------------------------

    def _fuzz_hwsrc(self, pkt: ARP) -> None:
        pkt.hwsrc = self.gen.fuzz_mac(pkt.hwsrc or "00:00:00:00:00:00")

    def _fuzz_hwdst(self, pkt: ARP) -> None:
        pkt.hwdst = self.gen.fuzz_mac(pkt.hwdst or "ff:ff:ff:ff:ff:ff")

    def _fuzz_psrc(self, pkt: ARP) -> None:
        pkt.psrc = self.gen.fuzz_ip(pkt.psrc or "0.0.0.0")

    def _fuzz_pdst(self, pkt: ARP) -> None:
        pkt.pdst = self.gen.fuzz_ip(pkt.pdst or "0.0.0.0")

    def _fuzz_opcode(self, pkt: ARP) -> None:
        """Inject an invalid opcode."""
        if self.gen.mode == FuzzMode.BOUNDARY:
            pkt.op = self._rng.choice(INVALID_ARP_OPS)
        elif self.gen.mode == FuzzMode.MUTATION:
            pkt.op = self._rng.choice(INVALID_ARP_OPS + list(VALID_ARP_OPS))
        else:
            pkt.op = self._rng.randint(0, 0xFFFF)

    def _fuzz_hwtype(self, pkt: ARP) -> None:
        if self.gen.mode == FuzzMode.BOUNDARY:
            pkt.hwtype = self._rng.choice(INVALID_HW_TYPES)
        else:
            pkt.hwtype = self.gen.fuzz_word(pkt.hwtype)

    def _fuzz_ptype(self, pkt: ARP) -> None:
        if self.gen.mode == FuzzMode.BOUNDARY:
            pkt.ptype = self._rng.choice(INVALID_PTYPES)
        else:
            pkt.ptype = self.gen.fuzz_word(pkt.ptype)

    def _fuzz_hwlen(self, pkt: ARP) -> None:
        """Corrupt hardware address length field (normally 6)."""
        pkt.hwlen = self.gen.fuzz_byte(pkt.hwlen)

    def _fuzz_plen(self, pkt: ARP) -> None:
        """Corrupt protocol address length field (normally 4)."""
        pkt.plen = self.gen.fuzz_byte(pkt.plen)

    # ------------------------------------------------------------------
    # Padding / size mutation
    # ------------------------------------------------------------------

    def _add_random_padding(self, frame: Ether) -> Ether:
        """Append oversized or random padding to the frame."""
        pad_size = self._rng.choice([0, 1, 100, 500, 1500, 9000])
        if pad_size:
            frame = frame / Raw(load=self.gen.random_bytes(pad_size))
        return frame

    def _undersized_frame(self) -> bytes:
        """Return a raw ARP frame that is shorter than the minimum (28 bytes)."""
        full = bytes(self._valid_arp())
        trunc_len = self._rng.randint(1, min(27, len(full) - 1))
        return full[:trunc_len]

    # ------------------------------------------------------------------
    # Public: generate a single fuzzed packet
    # ------------------------------------------------------------------

    def generate(self) -> bytes:
        """
        Return a single fuzzed ARP packet as raw bytes.
        The choice of which fields to mutate is random on each call.
        """
        # Occasionally produce an undersized frame (10% chance)
        if self._rng.random() < 0.10:
            raw = self._undersized_frame()
            logger.debug("ARP undersized frame (%d bytes)", len(raw))
            return raw

        frame = self._valid_arp()
        arp_layer = frame[ARP]

        # Randomly pick a set of fields to mutate (1-6 fields)
        mutators = [
            self._fuzz_hwsrc,
            self._fuzz_hwdst,
            self._fuzz_psrc,
            self._fuzz_pdst,
            self._fuzz_opcode,
            self._fuzz_hwtype,
            self._fuzz_ptype,
            self._fuzz_hwlen,
            self._fuzz_plen,
        ]
        count = self._rng.randint(1, len(mutators))
        chosen = self._rng.sample(mutators, count)
        for mutator in chosen:
            mutator(arp_layer)

        # Possibly add padding (30% chance)
        if self._rng.random() < 0.30:
            frame = self._add_random_padding(frame)

        raw = bytes(frame)
        logger.debug(
            "ARP fuzzed: op=%s hwsrc=%s psrc=%s len=%d",
            arp_layer.op,
            arp_layer.hwsrc,
            arp_layer.psrc,
            len(raw),
        )
        return raw

    def generate_batch(self, count: int) -> list[bytes]:
        """Return a list of *count* fuzzed ARP packets."""
        return [self.generate() for _ in range(count)]
