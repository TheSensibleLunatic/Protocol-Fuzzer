"""
test_arp_fuzzer.py — Unit tests for ARP fuzzer module.

Tests:
- valid packet baseline produces parsable bytes
- malformed hwsrc accepted by Scapy (no exception raised)
- oversized padding makes frame larger than standard MTU
- invalid opcode range is exercised in boundary mode
- seeded reproducibility: same seed → same packet sequence
- batch generation returns requested count
"""

import pytest
from scapy.layers.l2 import Ether, ARP

from fuzzer.arp_fuzzer import ARPFuzzer, INVALID_ARP_OPS
from fuzzer.packet_generator import PacketGenerator, FuzzMode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_arp(raw: bytes):
    """Re-parse raw bytes with Scapy; return ARP layer or None."""
    try:
        pkt = Ether(raw)
        return pkt[ARP] if ARP in pkt else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

class TestARPBaseline:
    def test_valid_packet_is_parsable(self, arp_fuzzer):
        """The internal _valid_arp() should produce bytes parsable by Scapy."""
        raw = bytes(arp_fuzzer._valid_arp())
        assert len(raw) >= 42, "ARP frame must be at least 42 bytes"
        pkt = Ether(raw)
        assert ARP in pkt, "Scapy must recognise the ARP layer"

    def test_valid_arp_opcode(self, arp_fuzzer):
        """Baseline ARP should have opcode 1 (REQUEST)."""
        pkt = arp_fuzzer._valid_arp()
        assert pkt[ARP].op == 1

    def test_valid_arp_ether_broadcast(self, arp_fuzzer):
        """Baseline ARP destination must be broadcast."""
        pkt = arp_fuzzer._valid_arp()
        assert pkt[Ether].dst == "ff:ff:ff:ff:ff:ff"


# ---------------------------------------------------------------------------
# Field mutation tests
# ---------------------------------------------------------------------------

class TestARPFieldMutation:
    def test_malformed_hwsrc_accepted(self, arp_fuzzer):
        """Scapy must not raise an exception on any hwsrc value."""
        for _ in range(50):
            raw = arp_fuzzer.generate()
            assert isinstance(raw, bytes), "generate() must return bytes"
            assert len(raw) > 0, "Generated packet must be non-empty"

    def test_fuzz_changes_hwsrc(self, gen_mutation):
        """Mutation mode must change at least one MAC address byte."""
        fuzzer = ARPFuzzer(generator=gen_mutation, iface="lo")
        original = "aa:bb:cc:dd:ee:ff"
        changed = {fuzzer.gen.fuzz_mac(original) for _ in range(20)}
        # With 20 samples at least one should differ from original
        assert any(m != original for m in changed), \
            "fuzz_mac must produce at least one different MAC in 20 attempts"

    def test_invalid_opcode_boundary(self, arp_fuzzer_boundary):
        """Boundary mode must produce at least one invalid opcode over 50 packets."""
        found_invalid = False
        for _ in range(50):
            raw = arp_fuzzer_boundary.generate()
            pkt = _parse_arp(raw)
            if pkt is not None and pkt.op in INVALID_ARP_OPS:
                found_invalid = True
                break
        assert found_invalid, "Boundary mode must exercise invalid ARP opcodes"

    def test_invalid_opcode_type(self, arp_fuzzer_boundary):
        """Every generated opcode must be an int."""
        for _ in range(20):
            raw = arp_fuzzer_boundary.generate()
            pkt = _parse_arp(raw)
            if pkt is not None:
                assert isinstance(pkt.op, int)

    def test_oversized_padding(self, gen_random):
        """Packets with oversized padding must be larger than standard 60-byte minimum."""
        # Force padding by manipulating the RNG to trigger padding path
        import unittest.mock as mock
        gen = PacketGenerator(mode=FuzzMode.RANDOM, seed=99)
        fuzzer = ARPFuzzer(generator=gen, iface="lo")

        large_found = False
        for _ in range(200):
            raw = fuzzer.generate()
            if len(raw) > 1500:
                large_found = True
                break
        # They won't all be large, but over 200 attempts at least one should be
        assert large_found, "Oversized padding must be generated in 200 attempts"

    def test_undersized_frame(self, gen_random):
        """Undersized frames must be shorter than minimum ARP frame (42 bytes)."""
        gen = PacketGenerator(mode=FuzzMode.RANDOM, seed=99)
        fuzzer = ARPFuzzer(generator=gen, iface="lo")

        undersized_found = False
        for _ in range(200):
            raw = fuzzer.generate()
            if len(raw) < 42:
                undersized_found = True
                break
        assert undersized_found, "Undersized frames must be generated in 200 attempts"


# ---------------------------------------------------------------------------
# Reproducibility tests
# ---------------------------------------------------------------------------

class TestARPReproducibility:
    def test_same_seed_same_sequence(self):
        """Two generators with the same seed must produce identical packet sequences."""
        gen_a = PacketGenerator(mode=FuzzMode.RANDOM, seed=1234)
        gen_b = PacketGenerator(mode=FuzzMode.RANDOM, seed=1234)
        fuzz_a = ARPFuzzer(generator=gen_a, iface="lo")
        fuzz_b = ARPFuzzer(generator=gen_b, iface="lo")

        for _ in range(20):
            assert fuzz_a.generate() == fuzz_b.generate(), \
                "Same seed must produce identical packets"

    def test_different_seeds_differ(self):
        """Different seeds must not always produce the same packet."""
        gen_a = PacketGenerator(mode=FuzzMode.RANDOM, seed=1)
        gen_b = PacketGenerator(mode=FuzzMode.RANDOM, seed=2)
        fuzz_a = ARPFuzzer(generator=gen_a, iface="lo")
        fuzz_b = ARPFuzzer(generator=gen_b, iface="lo")

        packets_a = [fuzz_a.generate() for _ in range(10)]
        packets_b = [fuzz_b.generate() for _ in range(10)]
        assert packets_a != packets_b, "Different seeds must produce different sequences"


# ---------------------------------------------------------------------------
# Batch generation
# ---------------------------------------------------------------------------

class TestARPBatch:
    def test_batch_count(self, arp_fuzzer):
        """generate_batch(n) must return exactly n packets."""
        batch = arp_fuzzer.generate_batch(25)
        assert len(batch) == 25

    def test_batch_all_bytes(self, arp_fuzzer):
        """Every element in the batch must be bytes."""
        for pkt in arp_fuzzer.generate_batch(10):
            assert isinstance(pkt, bytes)

    def test_batch_not_all_identical(self, arp_fuzzer):
        """Batch must contain at least 2 distinct packets."""
        batch = arp_fuzzer.generate_batch(20)
        assert len(set(batch)) > 1, "Batch must not be all identical packets"
