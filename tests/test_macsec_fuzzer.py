"""
test_macsec_fuzzer.py — Unit tests for MACsec fuzzer module.

Tests:
- EtherType 0x88E5 is correctly embedded in all output frames
- ICV bit-flip changes at least one byte
- SecTAG boundary values are exercised (V-bit, PN=0, PN=0xFFFFFFFF)
- Replay counter manipulation produces decremented PN values
- Truncated frames are generated
- Seeded reproducibility
- MACsecFrame serialise / deserialise round-trip
"""

import struct
import pytest

from fuzzer.macsec_fuzzer import MACsecFuzzer, MACsecFrame, MACSEC_ETHERTYPE, ICV_LENGTH
from fuzzer.packet_generator import PacketGenerator, FuzzMode
from fuzzer.utils import corrupt_bytes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_ethertype(raw: bytes) -> int:
    """Extract EtherType from a raw Ethernet frame (bytes 12-13)."""
    if len(raw) < 14:
        return 0
    return struct.unpack(">H", raw[12:14])[0]


def _get_sectag_byte(raw: bytes, offset: int) -> int:
    """Return SecTAG byte at given offset (relative to end of Eth header)."""
    idx = 14 + offset
    if idx >= len(raw):
        return -1
    return raw[idx]


def _get_pn(raw: bytes) -> int:
    """Extract PN field (bytes 16-19 after Eth header)."""
    if len(raw) < 20:
        return -1
    return struct.unpack(">L", raw[16:20])[0]


# ---------------------------------------------------------------------------
# EtherType correctness
# ---------------------------------------------------------------------------

class TestMACsecEtherType:
    def test_ethertype_in_all_frames(self, macsec_fuzzer):
        """Every generated frame (except truncated) must have EtherType 0x88E5."""
        for _ in range(100):
            raw = macsec_fuzzer.generate()
            if len(raw) >= 14:
                et = _get_ethertype(raw)
                assert et == MACSEC_ETHERTYPE, \
                    f"Expected EtherType 0x88E5, got 0x{et:04X}"

    def test_ethertype_correct_in_valid_frame(self):
        """MACsecFrame.to_bytes() must embed EtherType 0x88E5."""
        frame = MACsecFrame()
        raw = frame.to_bytes()
        assert len(raw) >= 14
        assert _get_ethertype(raw) == MACSEC_ETHERTYPE


# ---------------------------------------------------------------------------
# ICV bit-flip
# ---------------------------------------------------------------------------

class TestMACsecICV:
    def test_icv_bitflip_changes_bytes(self):
        """corrupt_bytes() on ICV must produce a different ICV."""
        original_icv = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 2  # 16 bytes
        for num_flips in [1, 4, 8, 16]:
            corrupted = corrupt_bytes(original_icv, num_flips)
            assert corrupted != original_icv, \
                f"ICV must change after {num_flips} bit flip(s)"

    def test_icv_length_preserved_after_flip(self):
        """corrupt_bytes() must preserve the byte length."""
        original = bytes(range(ICV_LENGTH))
        corrupted = corrupt_bytes(original, 3)
        assert len(corrupted) == ICV_LENGTH

    def test_fuzzer_corrupts_icv(self, macsec_fuzzer):
        """MACsec fuzzer must produce frames with modified ICV in 100 attempts."""
        original_icv = b"\x01" * ICV_LENGTH
        found_different = False
        for _ in range(100):
            raw = macsec_fuzzer.generate()
            if len(raw) < 14 + 6 + ICV_LENGTH:
                continue
            # ICV is at the very end of the frame
            actual_icv = raw[-ICV_LENGTH:]
            if actual_icv != original_icv:
                found_different = True
                break
        assert found_different, "MACsecFuzzer must corrupt the ICV"


# ---------------------------------------------------------------------------
# SecTAG boundary values
# ---------------------------------------------------------------------------

class TestMACsecSecTAG:
    def test_v_bit_set_in_boundary_mode(self, macsec_fuzzer_boundary):
        """Boundary mode must produce at least one frame with V-bit=1 (byte 0x80+)."""
        found = False
        for _ in range(100):
            raw = macsec_fuzzer_boundary.generate()
            if len(raw) < 15:
                continue
            tci_an = raw[14]   # first byte of SecTAG
            if tci_an & 0x80:  # V-bit set
                found = True
                break
        assert found, "Boundary mode must set V-bit in TCI/AN byte"

    def test_pn_zero_produced(self, macsec_fuzzer_boundary):
        """Boundary mode must produce PN=0 (invalid per 802.1AE)."""
        found = False
        for _ in range(200):
            raw = macsec_fuzzer_boundary.generate()
            if len(raw) < 20:
                continue
            pn = _get_pn(raw)
            if pn == 0:
                found = True
                break
        assert found, "Boundary mode must produce PN=0"

    def test_pn_max_produced(self, macsec_fuzzer_boundary):
        """Boundary mode must produce PN=0xFFFFFFFF (wrap-around)."""
        found = False
        for _ in range(200):
            raw = macsec_fuzzer_boundary.generate()
            if len(raw) < 20:
                continue
            pn = _get_pn(raw)
            if pn == 0xFFFFFFFF:
                found = True
                break
        assert found, "Boundary mode must produce PN=0xFFFFFFFF"


# ---------------------------------------------------------------------------
# Replay counter manipulation
# ---------------------------------------------------------------------------

class TestMACsecReplayCounter:
    def test_mutation_mode_decrements_pn(self):
        """Mutation mode must sometimes produce PN below the starting value."""
        gen = PacketGenerator(mode=FuzzMode.MUTATION, seed=42)
        fuzzer = MACsecFuzzer(generator=gen, iface="lo", base_pn=1000)
        found_low = False
        for _ in range(200):
            raw = fuzzer.generate()
            if len(raw) < 20:
                continue
            pn = _get_pn(raw)
            if 0 < pn < 1000:
                found_low = True
                break
        assert found_low, "Mutation mode must produce replay (decremented PN) packets"


# ---------------------------------------------------------------------------
# Truncated frames
# ---------------------------------------------------------------------------

class TestMACsecTruncated:
    def test_truncated_frames_generated(self):
        """Fuzzer must generate frames shorter than 36 bytes in 500 attempts."""
        gen = PacketGenerator(mode=FuzzMode.RANDOM, seed=77)
        fuzzer = MACsecFuzzer(generator=gen, iface="lo")
        found = False
        for _ in range(500):
            raw = fuzzer.generate()
            if len(raw) < 36:
                found = True
                break
        assert found, "Truncated MACsec frames must be generated"


# ---------------------------------------------------------------------------
# MACsecFrame round-trip
# ---------------------------------------------------------------------------

class TestMACsecFrameRoundTrip:
    def test_to_bytes_length(self):
        """to_bytes() must return at least 14 (Eth) + 6 (SecTAG) + 16 (ICV) bytes."""
        frame = MACsecFrame(payload=b"\x42" * 32)
        raw = frame.to_bytes()
        assert len(raw) >= 36, "MACsecFrame must be at least 36 bytes"

    def test_mac_serialisation(self):
        """MAC addresses must be correctly serialised in the frame."""
        frame = MACsecFrame(
            src_mac="aa:bb:cc:dd:ee:ff",
            dst_mac="11:22:33:44:55:66",
        )
        raw = frame.to_bytes()
        assert raw[0:6] == bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])  # dst
        assert raw[6:12] == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])  # src

    def test_pn_serialisation(self):
        """Packet number must be correctly serialised in big-endian."""
        frame = MACsecFrame(pn=0xDEADBEEF)
        raw = frame.to_bytes()
        stored_pn = struct.unpack(">L", raw[16:20])[0]
        assert stored_pn == 0xDEADBEEF

    def test_invalid_frame_raises(self):
        """from_bytes() must raise ValueError on too-short input."""
        with pytest.raises(ValueError):
            MACsecFrame.from_bytes(b"\x00" * 5)


# ---------------------------------------------------------------------------
# Reproducibility & batch
# ---------------------------------------------------------------------------

class TestMACsecReproducibility:
    def test_same_seed_same_sequence(self):
        gen_a = PacketGenerator(mode=FuzzMode.RANDOM, seed=42)
        gen_b = PacketGenerator(mode=FuzzMode.RANDOM, seed=42)
        fuzz_a = MACsecFuzzer(generator=gen_a)
        fuzz_b = MACsecFuzzer(generator=gen_b)
        for _ in range(15):
            assert fuzz_a.generate() == fuzz_b.generate()

    def test_batch_count(self, macsec_fuzzer):
        assert len(macsec_fuzzer.generate_batch(25)) == 25

    def test_batch_all_bytes(self, macsec_fuzzer):
        for pkt in macsec_fuzzer.generate_batch(10):
            assert isinstance(pkt, bytes)
