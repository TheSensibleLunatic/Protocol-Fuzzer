# proto-fuzzer

![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/github/actions/workflow/status/your-org/proto-fuzzer/ci.yml?label=CI&logo=github-actions)
![Coverage](https://img.shields.io/badge/coverage-tracked-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux)

> **Production-quality Layer 2/3 Protocol Fuzzer** — injects malformed ARP, ICMP,
> and MACsec frames against a mock C listener to demonstrate QA maturity.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       proto-fuzzer                       │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Fuzzer Engine (Python)                 │   │
│  │                                                          │   │
│  │  ┌────────────────┐   ┌────────────────────────────┐    │   │
│  │  │  PacketGenerator│   │      Protocol Fuzzers       │    │   │
│  │  │  (mutation core)│──▶│  ARPFuzzer / ICMPFuzzer /  │    │   │
│  │  │  random         │   │       MACsecFuzzer          │    │   │
│  │  │  mutation       │   └────────────┬───────────────┘    │   │
│  │  │  boundary       │                │  raw bytes          │   │
│  │  └────────────────┘                │                     │   │
│  │                                    ▼                     │   │
│  │  ┌──────────────────────────────────────────────────┐   │   │
│  │  │         Reporter (JSON + summary.txt)             │   │   │
│  │  └──────────────────────────────────────────────────┘   │   │
│  └───────────────────────────┬──────────────────────────────┘   │
│                               │  Raw Socket (AF_PACKET / root)   │
└───────────────────────────────┼─────────────────────────────────┘
                                │
                   ┌────────────▼────────────┐
                   │   Network Interface      │
                   │     (eth0 / lo)          │
                   └────────────┬────────────┘
                                │
                   ┌────────────▼────────────┐
                   │   Mock C Listener        │
                   │  (listener_safe /        │
                   │   listener_unsafe)       │
                   │                          │
                   │  ┌─────────────────────┐│
                   │  │  packet_parser.c    ││
                   │  │  ARP / ICMP / MACsec││
                   │  │  SAFE_MODE=1 / 0    ││
                   │  └─────────────────────┘│
                   │          │               │
                   │    ┌─────▼──────┐        │
                   │    │ listener   │        │
                   │    │ .log       │        │
                   │    └────────────┘        │
                   │    ┌────────────┐        │
                   │    │ crashes    │        │
                   │    │ .log       │        │
                   │    └────────────┘        │
                   └──────────────────────────┘
```

**Data flow:**
`CLI (--protocol / --mode / --seed)` → `PacketGenerator` → `Protocol Fuzzer` →
`Raw Socket` → `C Listener` → `Log / Crash Report` ← `Reporter` ← `CLI output`

---

## Features

| Feature | Detail |
|---|---|
| **3 protocols** | ARP, ICMP, Simulated MACsec (0x88E5) |
| **3 mutation modes** | `random`, `mutation` (bit-flip), `boundary` (edge cases) |
| **Seed reproducibility** | `--seed N` always produces the exact same packet sequence |
| **C listener** | Promiscuous raw socket, dual compile targets |
| **SAFE_MODE** | Compile `safe` or `unsafe` to demonstrate graceful vs. crash behaviour |
| **SIGSEGV handler** | `listener_crashes.log` written on abnormal termination |
| **AddressSanitizer** | `make safe` compiles with `-fsanitize=address` |
| **JSON reports** | Structured schema: session metadata + per-packet results |
| **Rich CLI** | Progress bar, colour-coded crash/OK output via `rich` |
| **62 unit tests** | pytest suite with coverage across all modules |
| **CI pipeline** | GitHub Actions: lint → test → build (both C targets) |

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | f-string union types used |
| Scapy | 2.5.0 | Raw packet construction |
| GCC | Any recent | For compiling the C listener |
| libpcap-dev | Any | Required by Scapy on Linux |
| Root / sudo | — | Raw sockets require elevated privileges |
| Linux | — | `AF_PACKET` raw sockets are Linux-specific |

> **Windows users:** The Python fuzzer can be run with `--dry-run` for testing
> without sending packets. The C listener requires Linux.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/proto-fuzzer.git
cd proto-fuzzer

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Optional) Install as a package with the CLI entry point
pip install -e .

# 5. Compile the C mock listener (Linux only)
cd listener
make safe      # SAFE_MODE=1 + AddressSanitizer
make unsafe    # SAFE_MODE=0 (simulates vulnerable device)
cd ..
```

---

## Usage

> **All fuzzing commands require `sudo` (or root)** because they use raw sockets.
> Use `--dry-run` to test packet generation without sending.

### ARP Fuzzing

```bash
# Random mode — 200 ARP packets, seeded for reproducibility
sudo python -m fuzzer.main \
    --protocol arp \
    --iface eth0 \
    --count 200 \
    --seed 42 \
    --output reports/arp_random.json

# Boundary mode — exercises edge-case opcodes and MAC values
sudo python -m fuzzer.main \
    --protocol arp \
    --iface eth0 \
    --count 500 \
    --mode boundary \
    --output reports/arp_boundary.json

# Mutation mode — bit-flips applied to valid ARP frames
sudo python -m fuzzer.main \
    --protocol arp \
    --iface eth0 \
    --count 100 \
    --mode mutation \
    --seed 7 \
    --verbose
```

### ICMP Fuzzing

```bash
# Random mode with custom source/destination IPs
sudo python -m fuzzer.main \
    --protocol icmp \
    --iface lo \
    --count 100 \
    --src-ip 192.168.1.10 \
    --dst-ip 192.168.1.1 \
    --seed 42 \
    --output reports/icmp_random.json

# Boundary mode — TTL=0, max payload, invalid type/code
sudo python -m fuzzer.main \
    --protocol icmp \
    --iface eth0 \
    --count 300 \
    --mode boundary \
    --output reports/icmp_boundary.json

# Dry-run (no root needed) — verify packet generation
python -m fuzzer.main \
    --protocol icmp \
    --iface lo \
    --count 50 \
    --mode boundary \
    --dry-run \
    --verbose
```

### MACsec Fuzzing

```bash
# Random mode — 200 MACsec frames with ICV/SecTAG mutations
sudo python -m fuzzer.main \
    --protocol macsec \
    --iface eth0 \
    --count 200 \
    --seed 1337 \
    --output reports/macsec_random.json

# Boundary mode — V-bit set, PN=0, PN=0xFFFFFFFF, truncated frames
sudo python -m fuzzer.main \
    --protocol macsec \
    --iface eth0 \
    --count 500 \
    --mode boundary \
    --output reports/macsec_boundary.json

# Mutation mode — bit-flips on valid MACsec frames (key-stream attack sim)
sudo python -m fuzzer.main \
    --protocol macsec \
    --iface eth0 \
    --count 150 \
    --mode mutation \
    --seed 99 \
    --verbose
```

### Running the C Listener

```bash
# Terminal 1 — start the safe listener
cd listener
sudo ./listener_safe -i eth0 -l listener.log

# Terminal 2 — fuzz against it
sudo python -m fuzzer.main --protocol arp --iface eth0 --count 200 --seed 42

# Terminal 1 — stop with Ctrl+C; check the log
cat listener.log
```

---

## SAFE_MODE vs Unsafe Behaviour

The C listener is compiled with a `SAFE_MODE` flag that controls whether
malformed input is handled gracefully or triggers simulated vulnerabilities.

```bash
# Safe compile — all bounds checked, AddressSanitizer enabled
make safe
sudo ./listener_safe -i lo

# Unsafe compile — deliberate OOB reads, no sanitizer
make unsafe
sudo ./listener_unsafe -i lo
```

### Observable Differences (≥2 packet types)

| Malformed Input | `listener_safe` | `listener_unsafe` |
|---|---|---|
| **ARP with `hlen=255`** | Logs `MALFORMED` and continues | OOB read beyond ARP header → ASAN trap / segfault |
| **ICMP with `ip->tot_len=65535`** | Logs `MALFORMED` and continues | `icmp_payload[tot_len-1]` triggers OOB read |
| **MACsec with `sl=0xFF`** (corrupt high bits) | Logs `MALFORMED` and continues | `payload[sl]` OOB read → crash |
| **Crafted count field in payload** | Not trusted | Unbounded loop → CPU DoS |

> Run these tests with `--mode boundary --protocol arp` and `--protocol icmp`
> to trigger the above paths.

---

## Output

### JSON Report

Every fuzzing session produces a JSON report at the path given by `--output`:

```json
{
  "session": {
    "protocol": "icmp",
    "mode": "boundary",
    "seed": 42,
    "total_packets": 100,
    "crashes_detected": 3,
    "timeouts": 12,
    "timestamp": "2026-04-15T00:00:00+00:00"
  },
  "packets": [
    {
      "index": 1,
      "payload_hex": "ffffffffffff...",
      "response": "timeout",
      "crash": false,
      "classification": "no_response"
    },
    {
      "index": 7,
      "payload_hex": "deadbeef...",
      "response": "crash!",
      "crash": true,
      "classification": "unknown"
    }
  ]
}
```

### Classification Values

| Value | Meaning |
|---|---|
| `timeout` | No response within the timeout window |
| `rst` | TCP RST received (connection refused) |
| `malformed_response` | Response received but it violates protocol rules |
| `no_response` | No response (not even a timeout packet) |
| `icmp_error` | ICMP error message returned (e.g., port unreachable) |
| `valid_response` | Normal protocol response received |
| `unknown` | Unclassified result |

### summary.txt

A human-readable summary is written to the same directory as the JSON report:

```
========================================================================
  proto-fuzzer  —  Session Report
========================================================================
  Protocol       : ICMP
  Mode           : boundary
  Seed           : 42
  Timestamp      : 2026-04-15T00:00:00+00:00
------------------------------------------------------------------------
  Total packets  : 100
  Crashes        : 3 (3.0%)
  Timeouts       : 12 (12.0%)
------------------------------------------------------------------------
  Classification breakdown:
    no_response                         88
    unknown                              9
    timeout                              3
========================================================================
```

---

## Running Tests

```bash
# All tests with verbose output
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=fuzzer --cov-report=term-missing

# Single module
pytest tests/test_arp_fuzzer.py -v
pytest tests/test_icmp_fuzzer.py -v
pytest tests/test_macsec_fuzzer.py -v
pytest tests/test_reporter.py -v

# Generate HTML coverage report
pytest tests/ --cov=fuzzer --cov-report=html
open htmlcov/index.html
```

---

## Project Structure

```
proto-fuzzer/
├── fuzzer/
│   ├── __init__.py
│   ├── main.py              # CLI entry point (argparse + rich)
│   ├── arp_fuzzer.py        # ARP protocol fuzzer (Scapy)
│   ├── icmp_fuzzer.py       # ICMP protocol fuzzer (Scapy)
│   ├── macsec_fuzzer.py     # Simulated MACsec stream fuzzer
│   ├── packet_generator.py  # Core mutation engine (random/mutation/boundary)
│   ├── reporter.py          # JSON + summary.txt report writer
│   └── utils.py             # Shared helpers and logging
│
├── listener/
│   ├── mock_listener.c      # Raw socket listener (AF_PACKET, promiscuous)
│   ├── packet_parser.h      # Header: structs + ParseResult + API
│   ├── packet_parser.c      # ARP/ICMP/MACsec parser (SAFE_MODE / unsafe)
│   └── Makefile             # make safe | make unsafe | make clean
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py          # Shared pytest fixtures
│   ├── test_arp_fuzzer.py   # ARP fuzzer unit tests
│   ├── test_icmp_fuzzer.py  # ICMP fuzzer unit tests
│   ├── test_macsec_fuzzer.py # MACsec fuzzer unit tests
│   └── test_reporter.py     # Reporter unit tests
│
├── .github/
│   ├── workflows/
│   │   └── ci.yml           # GitHub Actions: lint + test + build
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
│
├── reports/                 # (gitignored) Generated JSON reports
├── requirements.txt         # Pinned Python dependencies
├── pyproject.toml           # PEP 517/518 build + black/pytest config
├── .flake8                  # Flake8 config (max-line-length=100)
├── .gitignore
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
└── LICENSE                  # MIT
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Branch naming conventions (`feat/`, `fix/`, `fuzz/`)
- Code style (black + flake8, C -Wall -Wextra)
- Conventional Commit message format
- How to add a new protocol fuzzer
- Pull request process

---

## Security & Responsible Use

See [SECURITY.md](SECURITY.md).

**This tool must only be used on networks and devices you own or have explicit
written authorisation to test. The authors accept no liability for misuse.**

---

## License

[MIT](LICENSE) © 2026 proto-fuzzer contributors
