"""
conftest.py — Shared pytest fixtures for marvell-proto-fuzzer test suite.
"""

import os
import tempfile
import pytest

from fuzzer.packet_generator import PacketGenerator, FuzzMode
from fuzzer.arp_fuzzer import ARPFuzzer
from fuzzer.icmp_fuzzer import ICMPFuzzer
from fuzzer.macsec_fuzzer import MACsecFuzzer
from fuzzer.reporter import Reporter


# ---------------------------------------------------------------------------
# Generators — one per mode, all with a fixed seed for reproducibility
# ---------------------------------------------------------------------------

@pytest.fixture
def gen_random() -> PacketGenerator:
    """Seeded random-mode generator."""
    return PacketGenerator(mode=FuzzMode.RANDOM, seed=42)


@pytest.fixture
def gen_mutation() -> PacketGenerator:
    """Seeded mutation-mode generator."""
    return PacketGenerator(mode=FuzzMode.MUTATION, seed=42)


@pytest.fixture
def gen_boundary() -> PacketGenerator:
    """Seeded boundary-mode generator."""
    return PacketGenerator(mode=FuzzMode.BOUNDARY, seed=42)


# ---------------------------------------------------------------------------
# Protocol fuzzers
# ---------------------------------------------------------------------------

@pytest.fixture
def arp_fuzzer(gen_random) -> ARPFuzzer:
    return ARPFuzzer(generator=gen_random, iface="lo")


@pytest.fixture
def arp_fuzzer_boundary(gen_boundary) -> ARPFuzzer:
    return ARPFuzzer(generator=gen_boundary, iface="lo")


@pytest.fixture
def arp_fuzzer_mutation(gen_mutation) -> ARPFuzzer:
    return ARPFuzzer(generator=gen_mutation, iface="lo")


@pytest.fixture
def icmp_fuzzer(gen_random) -> ICMPFuzzer:
    return ICMPFuzzer(
        generator=gen_random,
        iface="lo",
        src_ip="127.0.0.1",
        dst_ip="127.0.0.2",
    )


@pytest.fixture
def icmp_fuzzer_boundary(gen_boundary) -> ICMPFuzzer:
    return ICMPFuzzer(
        generator=gen_boundary,
        iface="lo",
        src_ip="127.0.0.1",
        dst_ip="127.0.0.2",
    )


@pytest.fixture
def macsec_fuzzer(gen_random) -> MACsecFuzzer:
    return MACsecFuzzer(generator=gen_random, iface="lo")


@pytest.fixture
def macsec_fuzzer_boundary(gen_boundary) -> MACsecFuzzer:
    return MACsecFuzzer(generator=gen_boundary, iface="lo")


# ---------------------------------------------------------------------------
# Dummy raw packets (for reporter / classification tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def dummy_arp_bytes() -> bytes:
    """Return a minimal valid ARP-over-Ethernet frame as bytes."""
    from scapy.layers.l2 import Ether, ARP
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
        hwdst="00:00:00:00:00:00", pdst="192.168.0.2"
    )
    return bytes(pkt)


@pytest.fixture
def dummy_icmp_bytes() -> bytes:
    """Return a minimal valid ICMP echo request frame as bytes."""
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, ICMP
    from scapy.packet import Raw
    pkt = (
        Ether()
        / IP(src="127.0.0.1", dst="127.0.0.2", ttl=64)
        / ICMP(type=8, code=0)
        / Raw(load=b"\x00" * 32)
    )
    return bytes(pkt)


@pytest.fixture
def dummy_macsec_bytes() -> bytes:
    """Return a valid-looking MACsec frame as bytes."""
    from fuzzer.macsec_fuzzer import MACsecFrame
    frame = MACsecFrame(
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        tci_an=0x2C,
        sl=0,
        pn=1,
        include_sci=True,
        sci=b"\xaa\xbb\xcc\xdd\xee\xff\x00\x01",
        payload=b"\x42" * 32,
        icv=b"\x01" * 16,
    )
    return frame.to_bytes()


# ---------------------------------------------------------------------------
# Temporary output directory
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_report_dir(tmp_path) -> str:
    """Return path to a temporary directory for JSON/summary output."""
    d = tmp_path / "reports"
    d.mkdir()
    return str(d)


@pytest.fixture
def reporter(tmp_report_dir) -> Reporter:
    """Pre-configured Reporter writing to a temp directory."""
    return Reporter(
        protocol="arp",
        mode="random",
        seed=42,
        output_path=os.path.join(tmp_report_dir, "fuzz_report.json"),
    )
