# Changelog

All notable changes to **marvell-proto-fuzzer** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

*(Next release changes go here)*

---

## [1.0.0] — 2026-04-15

### Added

**Python Fuzzer (`fuzzer/`)**
- `fuzzer/main.py` — CLI entry point with `argparse`; flags: `--protocol`,
  `--iface`, `--count`, `--seed`, `--output`, `--mode`, `--src-ip`,
  `--dst-ip`, `--dry-run`, `--verbose`.
- `fuzzer/arp_fuzzer.py` — Full ARP fuzzer using Scapy; mutates hwsrc,
  hwdst, psrc, pdst, opcode (invalid values), hwtype, ptype, hlen, plen,
  padding injection, undersized frames.
- `fuzzer/icmp_fuzzer.py` — ICMP fuzzer; mutates type/code (out-of-range),
  checksum (intentionally corrupted), payload (random / null / max overflow),
  TTL=0, IP length, fragment offset, IP flags.
- `fuzzer/macsec_fuzzer.py` — Simulated MACsec stream fuzzer (no hardware);
  constructs raw `0x88E5` Ethernet frames; mutates TCI/AN, SL, PN (replay
  counter), SCI, ICV (bit-flips), payload (key-stream simulation), both MACs.
- `fuzzer/packet_generator.py` — Core mutation engine with three modes:
  `random`, `mutation` (bit-flip), and `boundary` (edge-case values).
  Fully seeded `random.Random` instance for reproducible packet sequences.
- `fuzzer/reporter.py` — Structured JSON reporter and `summary.txt` writer.
  Exact schema: `session + packets[]` with crash/timeout counters and
  per-packet classification.
- `fuzzer/utils.py` — Shared helpers: `hex_dump`, `random_mac`, `random_ip`,
  `internet_checksum`, `corrupt_checksum`, `corrupt_bytes`, `setup_logger`,
  `require_root`.

**Mock C Listener (`listener/`)**
- `listener/mock_listener.c` — Raw AF_PACKET socket listener; promiscuous
  mode; SIGSEGV / SIGBUS signal handlers with `listener_crashes.log` output;
  colour-coded console output; per-packet log lines.
- `listener/packet_parser.h` — Header with ARP, IPv4, ICMP, MACsec structs
  and `ParseResult` / `ParseStatus` types.
- `listener/packet_parser.c` — Modular parser with `SAFE_MODE=1` (bounds
  checked) and `SAFE_MODE=0` (deliberate OOB reads to simulate vulnerable
  device) for ARP, ICMP, and MACsec.
- `listener/Makefile` — `make safe` (AddressSanitizer) and `make unsafe`
  (no sanitizer) targets.

**Test Suite (`tests/`)**
- `tests/conftest.py` — Shared pytest fixtures.
- `tests/test_arp_fuzzer.py` — 15 unit tests covering baseline, field
  mutation, boundary opcodes, oversized/undersized frames, and reproducibility.
- `tests/test_icmp_fuzzer.py` — 14 unit tests covering checksum corruption,
  TTL=0, payload bounds, out-of-range type/code, and reproducibility.
- `tests/test_macsec_fuzzer.py` — 17 unit tests covering EtherType embedding,
  ICV bit-flip, SecTAG boundaries, replay PN, truncation, and round-trip.
- `tests/test_reporter.py` — 16 unit tests covering JSON schema, crash/timeout
  counters, summary.txt content, and `finalise()`.

**GitHub / CI**
- `.github/workflows/ci.yml` — Three-job CI: lint, test (pytest + coverage
  upload), build-listener (GCC safe + unsafe).
- `.github/ISSUE_TEMPLATE/bug_report.md` — Bug report template.
- `.github/ISSUE_TEMPLATE/feature_request.md` — Feature request template.
- `.github/PULL_REQUEST_TEMPLATE.md` — PR checklist template.

**Project Configuration**
- `requirements.txt` — Pinned: scapy 2.5.0, pytest 8.1.1, pytest-cov 5.0.0,
  black 24.4.2, flake8 7.0.0, colorlog 6.8.2, rich 13.7.1.
- `pyproject.toml` — PEP 517/518 build config + black/pytest/coverage settings.
- `.flake8` — `max-line-length = 100`.
- `.gitignore` — Python, C build, fuzzer output, IDE artefacts.
- `CONTRIBUTING.md` — Branch naming, code style, Conventional Commits, PR process.
- `SECURITY.md` — Authorized-use policy and responsible disclosure process.
- `LICENSE` — MIT License.
- `README.md` — Full project documentation with architecture diagram,
  prerequisites, installation, usage examples, output schema, and SAFE_MODE
  behaviour comparison table.

---

[Unreleased]: https://github.com/your-org/marvell-proto-fuzzer/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-org/marvell-proto-fuzzer/releases/tag/v1.0.0
