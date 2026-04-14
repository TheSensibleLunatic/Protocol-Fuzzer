"""
packet_generator.py — Core mutation engine for proto-fuzzer.

Three mutation modes:
  random   – fully random field values seeded by --seed
  mutation – take a valid packet and flip random bits
  boundary – test boundary/edge-case values (0x00, 0xFF, max int, etc.)
"""

import random
import struct
from enum import Enum
from typing import Callable

from fuzzer.utils import (
    random_bytes,
    random_mac,
    random_ip,
    corrupt_bytes,
    boundary_byte_values,
    boundary_word_values,
    setup_logger,
)

logger = setup_logger(__name__)


class FuzzMode(str, Enum):
    RANDOM = "random"
    MUTATION = "mutation"
    BOUNDARY = "boundary"


class PacketGenerator:
    """
    Stateful mutation engine.

    Parameters
    ----------
    mode: FuzzMode
        Mutation strategy to apply.
    seed: int | None
        Seed for the random number generator.  When provided the same *seed*
        always produces the exact same packet sequence.
    """

    def __init__(self, mode: FuzzMode = FuzzMode.RANDOM, seed: int | None = None):
        self.mode = FuzzMode(mode)
        self.seed = seed
        self._rng = random.Random(seed)
        logger.debug("PacketGenerator init: mode=%s seed=%s", self.mode, self.seed)

    # ------------------------------------------------------------------
    # Public helpers consumed by the protocol-specific fuzzers
    # ------------------------------------------------------------------

    def random_field_byte(self) -> int:
        """Return a random byte value [0, 255]."""
        return self._rng.randint(0, 0xFF)

    def random_field_word(self) -> int:
        """Return a random 16-bit value [0, 65535]."""
        return self._rng.randint(0, 0xFFFF)

    def random_field_dword(self) -> int:
        """Return a random 32-bit value."""
        return self._rng.randint(0, 0xFFFFFFFF)

    def random_mac(self) -> str:
        """Return a random MAC address using the seeded RNG."""
        octets = [self._rng.randint(0, 0xFF) for _ in range(6)]
        octets[0] &= 0xFC  # unicast + globally unique
        return ":".join(f"{b:02x}" for b in octets)

    def random_ip(self) -> str:
        """Return a random dotted-decimal IP using the seeded RNG."""
        return ".".join(str(self._rng.randint(0, 255)) for _ in range(4))

    def random_bytes(self, length: int) -> bytes:
        """Return *length* random bytes using the seeded RNG."""
        return bytes(self._rng.randint(0, 255) for _ in range(length))

    def random_length(self, min_len: int = 0, max_len: int = 1500) -> int:
        """Return a random payload length within [min_len, max_len]."""
        return self._rng.randint(min_len, max_len)

    # ------------------------------------------------------------------
    # Mode-specific field generators
    # ------------------------------------------------------------------

    def fuzz_byte(self, original: int = 0) -> int:
        """Return a fuzzed byte value according to the current mode."""
        if self.mode == FuzzMode.RANDOM:
            return self._rng.randint(0, 0xFF)
        if self.mode == FuzzMode.MUTATION:
            bit = self._rng.randint(0, 7)
            return (original ^ (1 << bit)) & 0xFF
        # BOUNDARY
        return self._rng.choice(boundary_byte_values())

    def fuzz_word(self, original: int = 0) -> int:
        """Return a fuzzed 16-bit value according to the current mode."""
        if self.mode == FuzzMode.RANDOM:
            return self._rng.randint(0, 0xFFFF)
        if self.mode == FuzzMode.MUTATION:
            bit = self._rng.randint(0, 15)
            return (original ^ (1 << bit)) & 0xFFFF
        # BOUNDARY
        return self._rng.choice(boundary_word_values())

    def fuzz_bytes(self, data: bytes, min_len: int = 0, max_len: int = 1500) -> bytes:
        """
        Return a fuzzed bytes object.

        random   – random length, random content
        mutation – flip random bits in *data*
        boundary – empty, single byte, or max-length fill
        """
        if self.mode == FuzzMode.RANDOM:
            length = self._rng.randint(min_len, max_len)
            return self.random_bytes(length)
        if self.mode == FuzzMode.MUTATION:
            if not data:
                return self.random_bytes(self._rng.randint(1, 64))
            flips = max(1, len(data) // 8)
            flipped = bytearray(data)
            for _ in range(flips):
                idx = self._rng.randint(0, len(flipped) - 1)
                bit = self._rng.randint(0, 7)
                flipped[idx] ^= (1 << bit)
            return bytes(flipped)
        # BOUNDARY
        boundary_opts = [
            b"",
            b"\x00",
            b"\xFF",
            b"\x00" * max_len,
            b"\xFF" * max_len,
            b"\xDE\xAD\xBE\xEF",
            b"\x41" * 65535,  # 'A' * max TCP
        ]
        return self._rng.choice(boundary_opts)[:max_len]

    def fuzz_mac(self, original: str = "00:00:00:00:00:00") -> str:
        """Return a fuzzed MAC address according to the current mode."""
        if self.mode == FuzzMode.RANDOM:
            return self.random_mac()
        if self.mode == FuzzMode.MUTATION:
            parts = original.split(":")
            idx = self._rng.randint(0, 5)
            parts[idx] = f"{self._rng.randint(0, 0xFF):02x}"
            return ":".join(parts)
        # BOUNDARY
        boundary_macs = [
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",  # multicast
            "33:33:00:00:00:01",  # IPv6 multicast
        ]
        return self._rng.choice(boundary_macs)

    def fuzz_ip(self, original: str = "0.0.0.0") -> str:
        """Return a fuzzed IP address according to the current mode."""
        if self.mode == FuzzMode.RANDOM:
            return self.random_ip()
        if self.mode == FuzzMode.MUTATION:
            parts = [int(p) for p in original.split(".")]
            idx = self._rng.randint(0, 3)
            parts[idx] = (parts[idx] + self._rng.randint(1, 255)) % 256
            return ".".join(str(p) for p in parts)
        # BOUNDARY
        boundary_ips = [
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
            "169.254.0.1",     # link-local
            "192.168.0.0",
            "10.0.0.1",
        ]
        return self._rng.choice(boundary_ips)
