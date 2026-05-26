# Changelog

## 1.0.5 (2026-05-26)

### False positive reduction
- `xor_key` IOC now requires bitwise/XOR context (e.g. `^ 134`, `key = 134`) instead of bare substring match. Eliminates hundreds of false positives in minified JS bundles (KaTeX, mermaid, highlight.js etc.) where `134` appears as array index or ASCII code.
- `openvsx_publisher`, `github_account`, `persistence_file` artifacts no longer matched against arbitrary file content (was producing false positives on any incidental occurrence of those strings).

### Detection
- New `check_extension_publisher()` matches `package.json` publisher field against `openvsx_publisher` IOC list — catches new extensions from a compromised publisher (e.g. wave-5 `oorzc`, `laura6909`, `martina0094`) before the explicit `publisher.name` pair is added to the known-malicious list.

## 1.0.4 (2026-04-05)

### IoC Database
- Added 102 Wave-5 OpenVSX extensions (Socket.dev sleeper extensions, Koi Security wave-5 list, oorzc compromised account)
- Added 6 new C2 IP addresses from StepSecurity ForceMemo analysis and Aikido Chrome RAT research
- Added 2 new Solana wallet addresses (funding wallet, Chrome RAT C2 dead-drop)
- Added 8 new attacker artifacts (GitHub accounts, OpenVSX publishers, persistence indicators, crypto keys)
- Total IoCs: 123 extensions, 20 IPs, 4 npm packages, 5 wallets, 11 artifacts

### Sources
- Added Socket.dev as tracked IoC source (sleeper extensions, transitive campaign, oorzc disclosure)
- Updated all source check timestamps to 2026-04-05

## 1.0.3 (2026-03-19)

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
