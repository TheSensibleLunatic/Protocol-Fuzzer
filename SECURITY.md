# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

---

## ⚠️ Authorized Use Only

**marvell-proto-fuzzer is an offensive security research tool.**

It is designed exclusively for:

- Testing **network devices you own** or have **explicit written permission** to test.
- QA validation in **isolated lab environments**.
- Academic research and education with **no production traffic affected**.

**Unauthorized use against systems you do not own is illegal and unethical.**
The authors disclaim all liability for misuse.

---

## Reporting a Vulnerability in This Tool

If you discover a security vulnerability **in marvell-proto-fuzzer itself**
(e.g., a path traversal in the reporter, command injection via the CLI, or
a memory safety issue in the C listener's safe mode), please follow responsible
disclosure:

### Do NOT open a public GitHub Issue.

Instead:

1. **Email** the maintainers at: `security@your-org.example.com`
   *(replace with your actual contact address before publishing)*
2. Include in your report:
   - A clear description of the vulnerability
   - Steps to reproduce (minimal PoC preferred)
   - Affected version / commit SHA
   - Your assessment of severity (CVSS score if possible)
3. We will acknowledge receipt within **72 hours** and aim to release
   a patch within **14 days** for critical issues.
4. You will be credited in the `CHANGELOG.md` and release notes
   (unless you prefer anonymity).

---

## Known Intentional "Vulnerabilities"

The following behaviours are **by design** in `SAFE_MODE=0` and are NOT
security bugs — they are deliberate simulations of a vulnerable device:

| Location | Behaviour | Purpose |
|---|---|---|
| `listener/packet_parser.c` (ARP, `!SAFE_MODE`) | OOB read via crafted `hlen` field | Demonstrate buffer over-read |
| `listener/packet_parser.c` (ICMP, `!SAFE_MODE`) | OOB read via crafted `ip->tot_len` | Demonstrate length trust issue |
| `listener/packet_parser.c` (MACsec, `!SAFE_MODE`) | OOB read via crafted `sl` field | Demonstrate SecTAG parsing vulnerability |
| `listener/mock_listener.c` (`!SAFE_MODE`) | Unbounded loop from payload count field | Demonstrate DoS via integer field trust |

**Never run the `unsafe` binary on production or shared networks.**

---

## Dependency Vulnerabilities

We monitor dependencies with `pip-audit`. If you find a CVE in any pinned
dependency listed in `requirements.txt`, please open a **private** GitHub
Security Advisory via the "Security" tab of the repository.
