# Changelog

## 0.1.0 (2026-03-19)

Initial release.

- Technique-based detection: invisible Unicode payloads, GlassWorm decoder patterns, bidirectional override, Hangul filler, eval/Function sinks, credential harvesting, C2 communication patterns
- Known IoC matching: 21 malicious extensions, 4 npm packages, 14 C2 IPs, 3 Solana wallets, attacker artifacts
- 3+1 layer IoC system: hardcoded, bundled, user-local, custom file
- Scanners: directory, VS Code/Cursor extensions, node_modules, pip packages, git repos
- Output formats: console (Rich), JSON, SARIF
- Cross-scanner severity escalation
- `.glassworm.yml` config file support
- `--disable-rule`, `--exclude`, `--ioc-file` CLI options
- Offline by default, no telemetry
- `glassworm-hunter update` for IoC database updates
- CI: ruff lint/format, pytest across Python 3.10-3.13, daily automated IoC updates
