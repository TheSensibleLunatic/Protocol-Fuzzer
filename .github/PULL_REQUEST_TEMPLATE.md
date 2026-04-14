## Pull Request Description
<!-- Summarise the changes in this PR in 2-3 sentences. -->

## Related Issue(s)
<!-- Link to related issues: Closes #123 -->
Closes #

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] New fuzzing module (new protocol support)
- [ ] Documentation update
- [ ] CI / build improvement

## Affected Components
- [ ] `fuzzer/arp_fuzzer.py`
- [ ] `fuzzer/icmp_fuzzer.py`
- [ ] `fuzzer/macsec_fuzzer.py`
- [ ] `fuzzer/packet_generator.py`
- [ ] `fuzzer/reporter.py`
- [ ] `fuzzer/utils.py`
- [ ] `fuzzer/main.py`
- [ ] `listener/mock_listener.c`
- [ ] `listener/packet_parser.c`
- [ ] `tests/`
- [ ] `.github/`

## Checklist
- [ ] Tests added or updated for all new/changed behaviour
- [ ] All existing tests pass (`pytest tests/ -v`)
- [ ] Code is formatted with `black` (no diff)
- [ ] `flake8` reports zero errors
- [ ] Documentation updated (README, docstrings, CHANGELOG)
- [ ] C listener compiles cleanly with `make safe` and `make unsafe` (zero warnings)
- [ ] Protocol compatibility verified: ARP / ICMP / MACsec frames are still valid baselines
- [ ] CI pipeline is passing (lint + test + build-listener)
- [ ] Seed-based reproducibility not broken (same `--seed` → same packets)

## Testing Done
<!-- Describe the testing done. Include CLI commands used. -->
```bash
pytest tests/ -v
sudo python -m fuzzer.main --protocol arp --iface lo --count 50 --seed 42 --dry-run
```

## Screenshots / Logs (if applicable)
<!-- Paste relevant output or reports here. -->
