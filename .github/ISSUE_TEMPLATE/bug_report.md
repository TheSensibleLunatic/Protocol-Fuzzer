---
name: Bug Report
about: Report a bug or unexpected behaviour in marvell-proto-fuzzer
title: "[BUG] "
labels: bug
assignees: ""
---

## Description
<!-- A clear and concise description of what the bug is. -->

## Reproduction Steps
<!-- Steps to reproduce the behaviour: -->
1. Run command: `sudo python -m fuzzer.main --protocol ... --iface ... --count ...`
2. Observe...

## Expected Behaviour
<!-- What you expected to happen. -->

## Actual Behaviour
<!-- What actually happened. Include any error messages or tracebacks. -->

## Environment
| Field            | Value                          |
|------------------|-------------------------------|
| OS               | e.g. Ubuntu 22.04             |
| Python version   | e.g. 3.11.4                   |
| Scapy version    | e.g. 2.5.0                    |
| GCC version      | e.g. 11.4.0                   |
| Interface        | e.g. eth0 / lo                |
| SAFE_MODE        | safe / unsafe                 |
| Fuzzer version   | e.g. v1.0.0 / git SHA         |

## Packet Capture
<!-- If applicable, attach a .pcap file or paste hex output from the fuzzer's JSON report. -->
```json
{
  "index": 1,
  "payload_hex": "...",
  "response": "...",
  "crash": true,
  "classification": "..."
}
```

## Additional Context
<!-- Any other context about the problem. Link to related issues if applicable. -->
