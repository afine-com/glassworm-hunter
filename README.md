# glassworm-hunter

![Glassworm Hunter Logo](assets/images/logo.jpeg)

Detect GlassWorm supply chain attack payloads on your machine. Scans VS Code extensions, npm packages, Python packages, and git repositories.

This scanner **detects the attack technique itself** - invisible Unicode variation selector payloads, GlassWorm decoder patterns, C2 indicators, and credential harvesting code. It catches variants that don't exist yet.

## Install

```bash
pip install glassworm-hunter
```

Or with pipx:

```bash
pipx install glassworm-hunter
```

## Quick start

Scan your current directory without scanning VS Code/Cursor extensions:

```bash
glassworm-hunter scan --no-extensions
```

Scan a specific project:

```bash
glassworm-hunter scan /path/to/project
```

## What it detects

### Technique detection (catches unknown variants)

- **Invisible Unicode payloads** - variation selector characters (U+FE00-FE0F, U+E0100-E01EF) used to encode hidden code. Legitimate uses are 1-2 characters for emoji. GlassWorm uses thousands.
- **GlassWorm decoder patterns** - the codePointAt + variation selector range arithmetic that decodes invisible payloads
- **Bidirectional override characters** - Trojan Source attack (CVE-2021-42574)
- **Hangul filler** - invisible valid JavaScript identifiers (U+3164)
- **eval/Function with dynamic content** - execution sinks fed by decoded strings
- **Credential access** - code reading .npmrc, .gitcredentials, SSH keys, token env vars
- **C2 communication patterns** - Solana RPC calls, Google Calendar URLs, WebRTC data channels in unexpected contexts

### Known IOC matching (supplementary)

- 21 known malicious VS Code/OpenVSX extension IDs (all 5 waves)
- 4 known malicious npm packages
- 14 known C2 IP addresses
- 3 known Solana C2 wallet addresses
- Attacker email and build path artifacts

## Severity levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Active GlassWorm payload detected (invisible Unicode cluster in code, decoder pattern) |
| **HIGH** | Known malicious IOC matched (C2 IP, wallet, extension dependency on known malware) |
| **MEDIUM** | Suspicious pattern worth reviewing (eval + dynamic content, credential access, Trojan Source) |
| **LOW** | Informational (unusual zero-width character density, suspicious install scripts) |

## CLI options

```
glassworm-hunter scan [OPTIONS] [PATHS...]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--extensions / --no-extensions` | on | Scan VS Code/Cursor/Codium extensions |
| `--npm-scan / --no-npm-scan` | on | Scan node_modules |
| `--pip-scan / --no-pip-scan` | off | Scan Python site-packages |
| `--git / --no-git` | on | Scan git repositories |
| `--format [console\|json\|sarif]` | console | Output format |
| `--output FILE` | stdout | Write report to file |
| `--severity [critical\|high\|medium\|low]` | low | Minimum severity to report |
| `--max-file-size SIZE` | 10MB | Skip files larger than this |
| `--include-hidden` | off | Scan hidden files/directories |
| `--quiet` | off | Suppress progress output |
| `--verbose` | off | Show every file being scanned |
| `--exclude PATTERN` | — | Glob patterns to exclude (repeatable) |
| `--disable-rule RULE_ID` | — | Suppress specific detection rules (repeatable) |
| `--ioc-file FILE` | — | Load additional IoC indicators from a JSON file |

A Rich progress bar is shown on stderr during scanning. It is automatically suppressed with `--quiet` or `--verbose`. A summary line (files scanned, findings, output path) is always printed to stderr after the scan completes.

### Other commands

```bash
# List all detection rule IDs (for use with --disable-rule)
glassworm-hunter rules

# Update local IoC database from GitHub (default source:
# https://raw.githubusercontent.com/afine-com/glassworm-hunter/main/data/ioc.json)
glassworm-hunter update

# Update from a custom source (e.g. internal threat intelligence server)
glassworm-hunter update --source https://internal.corp/ioc.json

# Force overwrite existing local IoC database
glassworm-hunter update --force

# Print version
glassworm-hunter version
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings detected |
| 2 | Scanner error |

## If you find something

1. **Don't panic.** The scanner found an indicator, not a confirmed breach.
2. **Don't execute the flagged code.** Don't run, build, or test the affected project until resolved.
3. **CRITICAL findings:** Uninstall the extension/package immediately. Rotate your NPM tokens, GitHub tokens, SSH keys, and any other credentials on the machine.
4. **HIGH findings:** Investigate the flagged file. If it's in a dependency you didn't explicitly install, remove it.
5. **MEDIUM findings:** Review the code. These patterns are suspicious but may be legitimate in some contexts.

## CI/CD integration

JSON output for automated processing:

```bash
glassworm-hunter scan . --format json --output report.json --no-extensions
```

SARIF for GitHub Code Scanning:

```bash
glassworm-hunter scan . --format sarif --output results.sarif --no-extensions
```

Upload SARIF to GitHub:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Use exit codes in CI:

```bash
glassworm-hunter scan . --severity critical --no-extensions || exit 1
```

Exclude build artifacts and vendor code:

```bash
glassworm-hunter scan . --exclude "dist/**" --exclude "*.min.js" --no-extensions
```

## No network access

This scanner is fully offline by default. It reads local files only. No telemetry, no phone-home, no automatic update checks. IoC databases are bundled in the package.

The only command that makes a network request is `glassworm-hunter update`, which fetches the latest IoC database from GitHub (or a custom `--source` URL). It is never called automatically.

## Configuration file

Place a `.glassworm.yml` in your project root to set defaults:

```yaml
exclude:
  - "*.min.js"
  - "vendor/**"
  - "dist/**"

disable_rules:
  - zero-width-chars

severity: medium
```

CLI flags override config file values.

## Custom IoC files

Use `--ioc-file` to load additional indicators from a JSON file. This is useful for team-specific or internal threat intelligence:

```bash
glassworm-hunter scan /path --ioc-file /path/to/team_ioc.json
```

The file must follow the same schema as `data/ioc.json`:

```json
{
  "schema_version": "1.0",
  "extensions": [{"id": "publisher.name"}],
  "npm_packages": [{"name": "pkg", "malicious_versions": "1.0.0"}],
  "c2_ips": [{"ip": "1.2.3.4"}],
  "c2_wallets": [{"address": "..."}],
  "attacker_artifacts": [{"type": "email", "value": "attacker@example.com"}]
}
```

The custom file is merged on top of all other IoC layers (hardcoded → bundled → user `~/.glassworm/ioc.json` → `--ioc-file`).

## IoC database layers

The scanner uses a 3+1 layer IoC system (each layer merges on top of the previous, never removes):

1. **Hardcoded** — built into the Python source, always available
2. **Bundled** — `data/ioc.json` shipped with the package
3. **User** — `~/.glassworm/ioc.json`, updated via `glassworm-hunter update`
4. **Custom** — `--ioc-file` flag, highest priority

## Credits

- [Koi Security](https://www.koi.ai) - original discovery of GlassWorm (October 2025) and ongoing tracking across multiple waves, including the OpenVSX/VSCode campaign, Rust binary pivot, and macOS pivot. IoC data in this scanner builds on their published research.
- [Aikido Security](https://www.aikido.dev) - analysis of the March 2026 GlassWorm wave targeting GitHub repositories and npm packages, alongside Socket, Step Security, and the OpenSourceMalware community.
- [AFINE](https://afine.pl) - this scanner

## Windows

The scanner works on Windows. 4 tests fail unless you run an elevated (Administrator) command prompt.

## License

MIT
