# Contributing to proto-fuzzer

Thank you for your interest in contributing! This document covers everything you
need to know to make a successful contribution.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Branch Naming](#branch-naming)
4. [Development Workflow](#development-workflow)
5. [Code Style](#code-style)
6. [Commit Messages](#commit-messages)
7. [Pull Request Process](#pull-request-process)
8. [Adding a New Protocol Fuzzer](#adding-a-new-protocol-fuzzer)
9. [C Listener Contributions](#c-listener-contributions)

---

## Code of Conduct

By participating in this project you agree to behave professionally and
respectfully toward all contributors. Harassment of any kind will not be
tolerated.

---

## Getting Started

```bash
# 1. Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/proto-fuzzer.git
cd proto-fuzzer

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate             # Windows

# 3. Install dependencies (including dev extras)
pip install -r requirements.txt
pip install -e ".[dev]"

# 4. Compile the C listener (Linux only)
cd listener && make all && cd ..

# 5. Run the test suite to confirm everything works
pytest tests/ -v
```

---

## Branch Naming

Use the following prefixes for branch names:

| Prefix    | Purpose                                     |
|-----------|---------------------------------------------|
| `feat/`   | New feature or protocol fuzzer              |
| `fix/`    | Bug fix                                     |
| `fuzz/`   | Fuzzing strategy improvement                |
| `docs/`   | Documentation-only change                  |
| `ci/`     | CI/CD pipeline change                       |
| `refactor/` | Refactoring with no functional change     |

**Examples:**
```
feat/udp-fuzzer
fix/macsec-pn-overflow
fuzz/icmp-boundary-ttl
docs/readme-architecture
```

---

## Development Workflow

1. **Create a branch** from `main` (never commit directly to `main`).
2. **Write code** following the style guide below.
3. **Write tests** — all new functionality must have corresponding unit tests.
4. **Run the full test suite** before pushing:
   ```bash
   pytest tests/ -v --cov=fuzzer
   black --check .
   flake8 fuzzer/ tests/
   ```
5. **Push your branch** and open a Pull Request.

---

## Code Style

### Python

- Formatter: **black** with `line-length = 100`
- Linter: **flake8** with `max-line-length = 100`
- All public functions and classes must have **docstrings**.
- Type annotations are encouraged (but not mandatory for private helpers).
- Run formatting before committing:
  ```bash
  black fuzzer/ tests/
  flake8 fuzzer/ tests/
  ```

### C

- Follow the existing style in `listener/`.
- Compile with `-Wall -Wextra` — **zero warnings** required in SAFE_MODE.
- Every unsafe code path must be guarded by `#if !SAFE_MODE`.
- Validate all lengths and pointers before dereferencing.

---

## Commit Messages

This project follows **Conventional Commits** (`https://www.conventionalcommits.org`).

Format:
```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

**Types:**

| Type       | When to use                               |
|------------|-------------------------------------------|
| `feat`     | New feature                               |
| `fix`      | Bug fix                                   |
| `fuzz`     | Fuzzing strategy or coverage improvement  |
| `docs`     | Documentation change                      |
| `test`     | Adding or updating tests                  |
| `refactor` | Code restructuring without behaviour change |
| `ci`       | CI pipeline changes                       |
| `chore`    | Build scripts, dependencies, etc.         |

**Examples:**
```
feat(macsec): add SCI scrambling in mutation mode
fix(arp): prevent oversized padding from exceeding 65535 bytes
test(reporter): add JSON schema validation for empty sessions
ci: install libpcap in build-listener job
```

---

## Pull Request Process

1. Ensure **all CI checks pass** (lint → test → build-listener).
2. Fill in the **PR template** completely.
3. Request a review from at least **one maintainer**.
4. Address all review comments before merging.
5. Squash commits if the history is noisy (`git rebase -i`).
6. Update `CHANGELOG.md` under the `[Unreleased]` section.

---

## Adding a New Protocol Fuzzer

1. Create `fuzzer/<protocol>_fuzzer.py` following the pattern of `arp_fuzzer.py`.
2. The class must:
   - Accept a `PacketGenerator` and `iface` in `__init__`.
   - Implement `generate() -> bytes` and `generate_batch(count) -> list[bytes]`.
   - Support all three `FuzzMode` values (`random`, `mutation`, `boundary`).
3. Register the new `--protocol` choice in `fuzzer/main.py`.
4. Add corresponding unit tests in `tests/test_<protocol>_fuzzer.py`.
5. Add the protocol to the `listener/packet_parser.c` dispatcher (and update the `.h` header).
6. Document the new protocol in `README.md`.

---

## C Listener Contributions

- **Never** remove the `SAFE_MODE` guard.
- Every new parse function must have a safe path (`#if SAFE_MODE`) and —
  if demonstrating a vulnerability simulation — an unsafe path (`#if !SAFE_MODE`).
- Compile and test with **AddressSanitizer**:
  ```bash
  cd listener && make safe
  sudo ./listener_safe -i lo
  ```
- Verify zero warnings with `gcc -Wall -Wextra -DSAFE_MODE=1`.
