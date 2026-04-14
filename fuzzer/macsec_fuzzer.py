"""
macsec_fuzzer.py — Simulated MACsec (IEEE 802.1AE) stream fuzzer.

No hardware required — constructs raw Ethernet frames with EtherType 0x88E5
and a hand-crafted SecTAG + payload structure.

MACsec SecTAG (Security TAG) layout (8 bytes minimum):
  Octet 0:    MACsec EtherType high byte (0x88)
  Octet 1:    MACsec EtherType low  byte (0xE5)
  —— SecTAG ——
  Octet 2:    TCI/AN byte  [V(1) | ES(1) | SC(1) | SCB(1) | E(1) | C(1) | AN(2)]
  Octet 3:    SL (Short Length, 6 bits)
  Octets 4-7: PN (Packet Number / replay counter, 32-bit big-endian)
  Octets 8-13: SCI (Secure Channel Identifier, 8 bytes) — optional when SC=0
  Payload:   encrypted user data (simulated)
  ICV:       Integrity Check Value (16 bytes for AES-GCM-128)

This fuzzer mutates every field above plus the ICV and key-stream.
"""

import struct
from typing import Optional

from scapy.layers.l2 import Ether
from scapy.packet import Raw

from fuzzer.packet_generator import PacketGenerator, FuzzMode
from fuzzer.utils import setup_logger, corrupt_bytes

logger = setup_logger(__name__)

MACSEC_ETHERTYPE = 0x88E5
ICV_LENGTH = 16  # AES-GCM-128 ICV is 128 bits
MIN_PAYLOAD = 0
MAX_PAYLOAD = 1468  # 1500 - 14 (Ether) - 8 (SecTAG min) - 16 (ICV)


class MACsecFrame:
    """
    Helper that composes and decomposes a raw MACsec Ethernet frame.

    Fields
    ------
    src_mac, dst_mac : str
    tci_an           : int  — TCI + AN byte (1 byte)
    sl               : int  — Short Length (1 byte, 6-bit field)
    pn               : int  — Packet Number (32-bit)
    sci              : bytes — Secure Channel Identifier (8 bytes, optional)
    include_sci      : bool  — Whether to include the SCI in the SecTAG
    payload          : bytes — (simulated) encrypted data
    icv              : bytes — 16-byte Integrity Check Value
    """

    def __init__(
        self,
        src_mac: str = "aa:bb:cc:dd:ee:ff",
        dst_mac: str = "ff:ff:ff:ff:ff:ff",
        tci_an: int = 0x08,  # SC=0, E=0, C=0, AN=0 → minimal
        sl: int = 0,
        pn: int = 1,
        sci: Optional[bytes] = None,
        include_sci: bool = False,
        payload: bytes = b"\xde\xad\xbe\xef" * 4,
        icv: bytes = b"\x00" * ICV_LENGTH,
    ):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.tci_an = tci_an & 0xFF
        self.sl = sl & 0x3F   # 6-bit field
        self.pn = pn & 0xFFFFFFFF
        self.sci = sci or b"\x00" * 8
        self.include_sci = include_sci
        self.payload = payload
        self.icv = icv[:ICV_LENGTH].ljust(ICV_LENGTH, b"\x00")

    def to_bytes(self) -> bytes:
        """Serialise to a complete raw Ethernet frame."""
        # Build SecTAG
        sectag = struct.pack(">BBL", self.tci_an, self.sl, self.pn)
        if self.include_sci:
            sectag += self.sci[:8].ljust(8, b"\x00")

        # Full frame: Ether header + EtherType + SecTAG + payload + ICV
        ether_dst = bytes(int(b, 16) for b in self.dst_mac.split(":"))
        ether_src = bytes(int(b, 16) for b in self.src_mac.split(":"))
        ethertype = struct.pack(">H", MACSEC_ETHERTYPE)

        frame = ether_dst + ether_src + ethertype + sectag + self.payload + self.icv
        return frame

    @classmethod
    def from_bytes(cls, data: bytes) -> "MACsecFrame":
        """
        Reconstruct a MACsecFrame from raw bytes.
        Raises ValueError if the frame is too short.
        """
        if len(data) < 14 + 6 + ICV_LENGTH:  # Ether + min SecTAG + ICV
            raise ValueError(f"Frame too short ({len(data)} bytes) to be a valid MACsec frame")
        dst = ":".join(f"{b:02x}" for b in data[0:6])
        src = ":".join(f"{b:02x}" for b in data[6:12])
        # Skip EtherType (bytes 12-13)
        tci_an = data[14]
        sl = data[15] & 0x3F
        pn = struct.unpack(">L", data[16:20])[0]
        return cls(src_mac=src, dst_mac=dst, tci_an=tci_an, sl=sl, pn=pn)


class MACsecFuzzer:
    """
    Simulated MACsec stream fuzzer.

    Parameters
    ----------
    generator: PacketGenerator
        Shared mutation engine.
    iface: str
        Network interface name.
    base_pn: int
        Starting packet number (replay counter seed).
    """

    def __init__(
        self,
        generator: PacketGenerator,
        iface: str = "lo",
        base_pn: int = 1,
    ):
        self.gen = generator
        self.iface = iface
        self.base_pn = base_pn
        self._rng = generator._rng
        self._pkt_counter = 0

    # ------------------------------------------------------------------
    # Baseline frame
    # ------------------------------------------------------------------

    def _valid_frame(self) -> MACsecFrame:
        """Return a well-formed MACsec frame."""
        return MACsecFrame(
            src_mac="aa:bb:cc:dd:ee:ff",
            dst_mac="11:22:33:44:55:66",
            tci_an=0x2C,          # V=0 ES=0 SC=1 SCB=0 E=1 C=1 AN=0
            sl=0,
            pn=self.base_pn + self._pkt_counter,
            include_sci=True,
            sci=b"\xaa\xbb\xcc\xdd\xee\xff\x00\x01",
            payload=b"\x42" * 32,
            icv=b"\x01" * ICV_LENGTH,
        )

    # ------------------------------------------------------------------
    # Field-level mutators
    # ------------------------------------------------------------------

    def _fuzz_tci_an(self, frame: MACsecFrame) -> None:
        """Corrupt TCI/AN byte — invalid flag combinations."""
        if self.gen.mode == FuzzMode.BOUNDARY:
            # V bit MUST be 0; set it to 1 to trigger parse error
            frame.tci_an = self._rng.choice([0x80, 0xFF, 0x00, 0x7F, 0x40])
        else:
            frame.tci_an = self.gen.fuzz_byte(frame.tci_an)

    def _fuzz_sl(self, frame: MACsecFrame) -> None:
        """Corrupt Short Length — violate the 6-bit constraint."""
        if self.gen.mode == FuzzMode.BOUNDARY:
            frame.sl = self._rng.choice([0x00, 0x3F, 0x40, 0xFF])
        else:
            frame.sl = self.gen.fuzz_byte(frame.sl) & 0xFF  # allow > 0x3F

    def _fuzz_pn_replay(self, frame: MACsecFrame) -> None:
        """
        Manipulate Packet Number to simulate replay attacks:
        - Set to 0 (before the expected window)
        - Set to 0xFFFFFFFF (wrap-around)
        - Decrement below the last seen PN
        """
        if self.gen.mode == FuzzMode.BOUNDARY:
            frame.pn = self._rng.choice(
                [0x00000000, 0x00000001, 0xFFFFFFFE, 0xFFFFFFFF]
            )
        elif self.gen.mode == FuzzMode.MUTATION:
            # Go backwards (replay)
            replay_offset = self._rng.randint(1, max(1, frame.pn))
            frame.pn = max(0, frame.pn - replay_offset)
        else:
            frame.pn = self._rng.randint(0, 0xFFFFFFFF)

    def _fuzz_sci(self, frame: MACsecFrame) -> None:
        """Corrupt Secure Channel Identifier (8 bytes)."""
        frame.include_sci = True
        frame.sci = self.gen.fuzz_bytes(frame.sci, min_len=8, max_len=8)[:8].ljust(
            8, b"\x00"
        )

    def _corrupt_bytes_seeded(self, data: bytes, num_flips: int) -> bytes:
        """Bit-flip helper that exclusively uses self._rng for reproducibility."""
        if not data:
            return data
        ba = bytearray(data)
        for _ in range(num_flips):
            idx = self._rng.randint(0, len(ba) - 1)
            bit = self._rng.randint(0, 7)
            ba[idx] ^= (1 << bit)
        return bytes(ba)

    def _fuzz_icv(self, frame: MACsecFrame) -> None:
        """Corrupt the ICV — forces an integrity verification failure."""
        if self.gen.mode == FuzzMode.BOUNDARY:
            frame.icv = self._rng.choice(
                [
                    b"\x00" * ICV_LENGTH,
                    b"\xFF" * ICV_LENGTH,
                    b"\xDE\xAD\xBE\xEF" * 4,
                ]
            )
        else:
            # Flip a random number of bits in the ICV using the seeded RNG
            num_flips = self._rng.randint(1, ICV_LENGTH * 8)
            frame.icv = self._corrupt_bytes_seeded(frame.icv, num_flips)

    def _fuzz_payload(self, frame: MACsecFrame) -> None:
        """Replace the encrypted payload with fuzzed data (key-stream bit-flips)."""
        if self.gen.mode == FuzzMode.BOUNDARY:
            sizes = [0, 1, 46, 1500, MAX_PAYLOAD]
            size = self._rng.choice(sizes)
            frame.payload = self.gen.random_bytes(size) if size else b""
        elif self.gen.mode == FuzzMode.MUTATION:
            # Simulate key-stream bit-flip attack (seeded RNG for reproducibility)
            n = self._rng.randint(1, max(1, len(frame.payload)))
            frame.payload = self._corrupt_bytes_seeded(frame.payload, n)
        else:
            frame.payload = self.gen.random_bytes(
                self._rng.randint(MIN_PAYLOAD, MAX_PAYLOAD)
            )

    def _fuzz_dst_mac(self, frame: MACsecFrame) -> None:
        frame.dst_mac = self.gen.fuzz_mac(frame.dst_mac)

    def _fuzz_src_mac(self, frame: MACsecFrame) -> None:
        frame.src_mac = self.gen.fuzz_mac(frame.src_mac)

    def _truncated_frame(self) -> bytes:
        """Return a raw MACsec frame truncated below the minimum valid size."""
        raw = self._valid_frame().to_bytes()
        trunc_len = self._rng.randint(1, min(21, len(raw) - 1))
        return raw[:trunc_len]

    # ------------------------------------------------------------------
    # Public: generate a single fuzzed packet
    # ------------------------------------------------------------------

    def generate(self) -> bytes:
        """Return a single fuzzed MACsec Ethernet frame as raw bytes."""
        self._pkt_counter += 1

        # 8% chance of a truncated frame
        if self._rng.random() < 0.08:
            raw = self._truncated_frame()
            logger.debug("MACsec truncated frame (%d bytes)", len(raw))
            return raw

        frame = self._valid_frame()

        mutators = [
            self._fuzz_tci_an,
            self._fuzz_sl,
            self._fuzz_pn_replay,
            self._fuzz_sci,
            self._fuzz_icv,
            self._fuzz_payload,
            self._fuzz_dst_mac,
            self._fuzz_src_mac,
        ]
        count = self._rng.randint(1, len(mutators))
        chosen = self._rng.sample(mutators, count)
        for mutator in chosen:
            mutator(frame)

        raw = frame.to_bytes()
        logger.debug(
            "MACsec fuzzed: tci_an=0x%02x pn=%d icv=%s len=%d",
            frame.tci_an,
            frame.pn,
            frame.icv.hex()[:8] + "...",
            len(raw),
        )
        return raw

    def generate_batch(self, count: int) -> list[bytes]:
        """Return a list of *count* fuzzed MACsec frames."""
        return [self.generate() for _ in range(count)]
