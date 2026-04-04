"""Known indicators of compromise from all GlassWorm waves."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path
from typing import Any

from .models import DetectionType, Finding, Severity

# --- Known malicious VS Code / OpenVSX extensions ---
# Format: (publisher.name, wave, source, date)
MALICIOUS_EXTENSIONS: tuple[tuple[str, str, str, str], ...] = (
    # Wave 1 - Oct 2025 (OpenVSX)
    ("codejoy.codejoy-vscode-extension", "wave-1", "Koi Security", "2025-10-17"),
    ("l-igh-t.vscode-theme-seti-folder", "wave-1", "Koi Security", "2025-10-17"),
    ("kleinesfilmroellchen.serenity-dsl-syntaxhighlight", "wave-1", "Koi Security", "2025-10-17"),
    ("jscearcy.rust-doc-viewer", "wave-1", "Koi Security", "2025-10-17"),
    ("sirilmp.dark-theme-sm", "wave-1", "Koi Security", "2025-10-17"),
    ("codeinklingon.git-worktree-menu", "wave-1", "Koi Security", "2025-10-17"),
    ("ginfuru.better-nunjucks", "wave-1", "Koi Security", "2025-10-17"),
    ("ellacrity.recoil", "wave-1", "Koi Security", "2025-10-17"),
    ("grrrck.positron-plus-1-e", "wave-1", "Koi Security", "2025-10-17"),
    ("jeronimoekerdt.color-picker-universal", "wave-1", "Koi Security", "2025-10-17"),
    ("srcery-colors.srcery-colors", "wave-1", "Koi Security", "2025-10-17"),
    ("sissel.shopify-liquid", "wave-1", "Koi Security", "2025-10-17"),
    ("tretinv3.forts-api-extention", "wave-1", "Koi Security", "2025-10-17"),
    # Wave 1 - VS Code Marketplace
    ("cline-ai-main.cline-ai-agent", "wave-1", "Koi Security", "2025-10-19"),
    # Wave 2 - Nov 2025
    ("ai-driven-dev.ai-driven-dev", "wave-2", "Koi Security", "2025-11-06"),
    ("adhamu.history-in-sublime-merge", "wave-2", "Koi Security", "2025-11-06"),
    ("yasuyuky.transient-emacs", "wave-2", "Koi Security", "2025-11-06"),
    # Wave 4 - Dec 2025
    ("studio-velte-distributor.pro-svelte-extension", "wave-4", "Koi Security", "2025-12-19"),
    ("cudra-production.vsce-prettier-pro", "wave-4", "Koi Security", "2025-12-19"),
    (
        "puccin-development.full-access-catppuccin-pro-extension",
        "wave-4",
        "Koi Security",
        "2025-12-19",
    ),
    # Wave 5 - Mar 2026 (existing)
    ("quartz.quartz-markdown-editor", "wave-5", "Koi Security", "2026-03-12"),
    # Wave 5 - Compromised developer account (Socket.dev, Jan 2026)
    ("oorzc.ssh-tools", "wave-5", "Socket.dev", "2026-01-30"),
    ("oorzc.i18n-tools-plus", "wave-5", "Socket.dev", "2026-01-30"),
    ("oorzc.mind-map", "wave-5", "Socket.dev", "2026-01-30"),
    ("oorzc.scss-to-css-compile", "wave-5", "Socket.dev", "2026-01-30"),
    # Wave 5 - Sleeper activations (Socket.dev, Mar 12 2026)
    ("lauracode.wrap-selected-code", "wave-5", "Socket.dev", "2026-03-12"),
    ("96-studio.json-formatter", "wave-5", "Socket.dev", "2026-03-12"),
    # Wave 5 - Weekend wave impersonation (Socket.dev, Mar 14 2026)
    ("msw-tm.component-vetur-toolkit", "wave-5", "Socket.dev", "2026-03-14"),
    ("yamal-dext.wonder-workspace-icons", "wave-5", "Socket.dev", "2026-03-14"),
    ("marcus-tm.ruby-intelligence-toolkit", "wave-5", "Socket.dev", "2026-03-14"),
    ("namop-dex.claude-code-assistant", "wave-5", "Socket.dev", "2026-03-14"),
    ("awwwadem.language-professional-tools", "wave-5", "Socket.dev", "2026-03-14"),
    ("codevunm-tm.cluster-kuberntes-manager", "wave-5", "Socket.dev", "2026-03-14"),
    ("sweaty-tstudio.quarto-report-studio", "wave-5", "Socket.dev", "2026-03-14"),
    ("codbro-dxp.explorer-xml-xquery", "wave-5", "Socket.dev", "2026-03-14"),
    ("sxatvo-tm.compile-runnner-build", "wave-5", "Socket.dev", "2026-03-14"),
    ("calow-dex.prisma-database-schema-tools", "wave-5", "Socket.dev", "2026-03-14"),
    ("croct-studio.antigravity-model-usage-dashboard", "wave-5", "Socket.dev", "2026-03-14"),
    ("specstudio.code-wakatime-activity-tracker", "wave-5", "Socket.dev", "2026-03-14"),
    ("tool-studio.prettier-pro-code-format", "wave-5", "Socket.dev", "2026-03-14"),
    ("gorth-tm.your-project-manager-organizer", "wave-5", "Socket.dev", "2026-03-14"),
    ("dev-tm.code-python-indent-helper", "wave-5", "Socket.dev", "2026-03-14"),
    ("flape-osx.align-code-format-tool", "wave-5", "Socket.dev", "2026-03-14"),
    ("floktokbok.autoimport-smart-tool", "wave-5", "Socket.dev", "2026-03-14"),
    # Wave 5 - Koi Security full list (Mar 16 2026)
    ("aadarkcode.one-dark-material", "wave-5", "Koi Security", "2026-03-16"),
    ("aligntool.extension-align-professional-tool", "wave-5", "Koi Security", "2026-03-16"),
    ("angular-studio.ng-angular-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("awesome-codebase.codebase-dart-pro", "wave-5", "Koi Security", "2026-03-16"),
    ("awesomeco.wonder-for-vscode-icons", "wave-5", "Koi Security", "2026-03-16"),
    ("bhbpbarn.vsce-python-indent-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("blockstoks.easily-gitignore-manage", "wave-5", "Koi Security", "2026-03-16"),
    ("brategmaqendaalar-studio.pro-prettyxml-formatter", "wave-5", "Koi Security", "2026-03-16"),
    ("codbroks.compile-runnner-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("codevunmis.csv-sql-tsv-rainbow", "wave-5", "Koi Security", "2026-03-16"),
    ("codwayexten.code-way-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("cosmic-themes.sql-formatter", "wave-5", "Koi Security", "2026-03-16"),
    ("crotoapp.vscode-xml-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("daeumer-web.es-linter-for-vs-code", "wave-5", "Koi Security", "2026-03-16"),
    ("dark-code-studio.flutter-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("densy-little-studio.wonder-for-vscode-icons", "wave-5", "Koi Security", "2026-03-16"),
    ("dep-labs-studio.dep-proffesinal-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("dev-studio-sense.php-comp-tools-vscode", "wave-5", "Koi Security", "2026-03-16"),
    ("devmidu-studio.svg-better-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("dopbop-studio.vscode-tailwindcss-extension-toolkit", "wave-5", "Koi Security", "2026-03-16"),
    ("errlenscre.error-lens-finder-ex", "wave-5", "Koi Security", "2026-03-16"),
    ("exss-studio.yaml-professional-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("federicanc.dotenv-syntax-highlighting", "wave-5", "Koi Security", "2026-03-16"),
    ("flutxvs.vscode-kuberntes-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("gvotcha.claude-code-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("gvotcha.claude-code-extensions", "wave-5", "Koi Security", "2026-03-16"),
    ("intellipro.extension-json-intelligence", "wave-5", "Koi Security", "2026-03-16"),
    ("kharizma.vscode-extension-wakatime", "wave-5", "Koi Security", "2026-03-16"),
    ("ko-zu-gun-studio.synchronization-settings-vscode", "wave-5", "Koi Security", "2026-03-16"),
    ("kwitch-studio.auto-run-command-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("lavender-studio.theme-lavender-dreams", "wave-5", "Koi Security", "2026-03-16"),
    ("littensy-studio.magical-icons", "wave-5", "Koi Security", "2026-03-16"),
    ("lyu-wen-studio-web-han.better-formatter-vscode", "wave-5", "Koi Security", "2026-03-16"),
    ("markvalid.vscode-mdvalidator-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("mecreation-studio.pyrefly-pro-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("mswincx.antigravity-cockpit", "wave-5", "Koi Security", "2026-03-16"),
    ("mswincx.antigravity-cockpit-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("namopins.prettier-pro-vscode-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("oigotm.my-command-palette-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("otoboss.autoimport-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("ovixcode.vscode-better-comments", "wave-5", "Koi Security", "2026-03-16"),
    ("pessa07tm.my-js-ts-auto-commands", "wave-5", "Koi Security", "2026-03-16"),
    ("potstok.dotnet-runtime-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("pretty-studio-advisor.prettyxml-formatter", "wave-5", "Koi Security", "2026-03-16"),
    ("prismapp.prisma-vs-code-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("projmanager.your-project-manager-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("pubruncode.ccoderunner", "wave-5", "Koi Security", "2026-03-16"),
    ("pyflowpyr.py-flowpyright-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("pyscopexte.pyscope-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("redcapcollective.vscode-quarkus-elite-suite", "wave-5", "Koi Security", "2026-03-16"),
    ("rubyideext.ruby-ide-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("runnerpost.runner-your-code", "wave-5", "Koi Security", "2026-03-16"),
    ("shinypy.shiny-extension-for-vscode", "wave-5", "Koi Security", "2026-03-16"),
    ("sol-studio.solidity-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("ssgwysc.volar-vscode", "wave-5", "Koi Security", "2026-03-16"),
    ("studio-jjalaire-team.professional-quarto-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("sun-shine-studio.shiny-extension-for-vscode", "wave-5", "Koi Security", "2026-03-16"),
    ("sxatvo.jinja-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("tamokill12.foundry-pdf-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("thing-mn.your-flow-extension-for-icons", "wave-5", "Koi Security", "2026-03-16"),
    ("tima-web-wang.shell-check-utils", "wave-5", "Koi Security", "2026-03-16"),
    ("tokcodes.import-cost-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("toowespace.worksets-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("treedotree.tree-do-todoextension", "wave-5", "Koi Security", "2026-03-16"),
    ("tucyzirille-studio.angular-pro-tools-extension", "wave-5", "Koi Security", "2026-03-16"),
    ("turbobase.sql-turbo-tool", "wave-5", "Koi Security", "2026-03-16"),
    ("twilkbilk.color-highlight-css", "wave-5", "Koi Security", "2026-03-16"),
    ("vce-brendan-studio-eich.js-debuger-vscode", "wave-5", "Koi Security", "2026-03-16"),
    ("yamaprolas.revature-labs-extension", "wave-5", "Koi Security", "2026-03-16"),
    # Wave 5 - Extension pack droppers (Socket.dev, Mar 17 2026)
    ("spacetoow.vsc-python-indent", "wave-5", "Socket.dev", "2026-03-17"),
    ("cod-vok.arko-dev-devsecops", "wave-5", "Socket.dev", "2026-03-17"),
    ("oxigener-tmp.sql-turbo-manager", "wave-5", "Socket.dev", "2026-03-17"),
    ("otobo-vs.csv-query-tsv-rainbow", "wave-5", "Socket.dev", "2026-03-17"),
    ("awesome-codespace.jinja-language-support", "wave-5", "Socket.dev", "2026-03-17"),
    # Wave 5 - Secondary wave (Socket.dev, Mar 18 2026)
    ("daeumer-web.align-format-tool", "wave-5", "Socket.dev", "2026-03-18"),
    ("baksmink.vscode-quokka-extension", "wave-5", "Socket.dev", "2026-03-18"),
    ("bansheejust22.retro-vhs-theme", "wave-5", "Socket.dev", "2026-03-18"),
    ("craz2team.vscode-todo-extension", "wave-5", "Socket.dev", "2026-03-18"),
    ("quickrunn.auto-run-command-quick", "wave-5", "Socket.dev", "2026-03-18"),
)

_MALICIOUS_EXT_IDS: frozenset[str] = frozenset(ext_id for ext_id, _, _, _ in MALICIOUS_EXTENSIONS)

_MALICIOUS_EXT_META: dict[str, tuple[str, str, str]] = {
    ext_id: (wave, source, date) for ext_id, wave, source, date in MALICIOUS_EXTENSIONS
}

# --- Known malicious npm packages ---
MALICIOUS_NPM_PACKAGES: tuple[tuple[str, str, str, str, str], ...] = (
    ("@aifabrix/miso-client", "4.7.2", "wave-5", "Aikido Security", "2026-03-12"),
    ("@iflow-mcp/watercrawl-watercrawl-mcp", "1.3.0-1.3.4", "wave-5", "Koi Security", "2026-03-12"),
    ("react-native-country-select", "0.3.91", "wave-5", "Aikido Security", "2026-03-16"),
    (
        "react-native-international-phone-number",
        "0.11.8",
        "wave-5",
        "Aikido Security",
        "2026-03-16",
    ),
)

_MALICIOUS_NPM_NAMES: frozenset[str] = frozenset(
    name for name, _, _, _, _ in MALICIOUS_NPM_PACKAGES
)

# --- Known C2 IP addresses ---
C2_IPS: frozenset[str] = frozenset(
    {
        # Wave 1
        "217.69.3.218",
        "199.247.10.166",
        # Wave 3
        "217.69.13.229",
        "45.76.45.151",
        "45.32.151.157",
        "107.191.62.170",
        # Exfiltration
        "140.82.52.31",
        "199.247.13.106",
        "104.238.191.54",
        "108.61.208.161",
        # Wave 4
        "45.32.150.251",
        "217.69.11.60",
        # Wave 5 - Koi Security
        "70.34.242.255",
        "217.69.3.152",
        # Wave 5 - ForceMemo (StepSecurity)
        "45.32.150.97",
        "217.69.11.57",
        "217.69.11.99",
        "217.69.0.159",
        "45.76.44.240",
        # Wave 5 - Chrome RAT exfiltration (Aikido)
        "45.150.34.158",
    }
)

# --- Known Solana wallet addresses ---
C2_WALLETS: frozenset[str] = frozenset(
    {
        "28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2",  # Wave 1
        "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC",  # Wave 4
        "6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ",  # Wave 5
        "G2YxRa6wt1qePMwfJzdXZG62ej4qaTC7YURzuh2Lwd3t",  # Wave 5 - funding wallet (StepSecurity)
        "DSRUBTziADDHSik7WQvSMjvwCHFsbsThrbbjWMoJPUiW",  # Wave 5 - Chrome RAT C2 (Aikido)
    }
)

# --- Other IOCs ---
ATTACKER_EMAIL = "uhjdclolkdn@gmail.com"
ATTACKER_PATH_ARTIFACT = "/Users/davidioasd/Downloads/rust_implant/"
MARKER_VARIABLE = "lzcdrtfxyqiplpd"

# Additional artifacts loaded from JSON via 3-layer merge:
# - github_account: chiara585, francesca898
# - openvsx_publisher: oorzc, laura6909, martina0094
# - persistence_file: ~/init.json
# - xor_key: 134
# - aes_key: wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz

# IP address regex for content scanning
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Solana-style base58 address pattern (32-44 chars of base58)
_WALLET_RE = re.compile(
    r"\b([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{32,44})\b"
)

# --- 3-layer IoC loading ---

# Dev-time path (relative to source tree)
_DEV_IOC_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "ioc.json"
_USER_IOC_PATH = Path.home() / ".glassworm" / "ioc.json"

# Module-level cache
_merged_db: dict[str, Any] | None = None


def _load_json_iocs(path: Path) -> dict[str, Any] | None:
    """Load IoC database from a JSON file. Returns None if file doesn't exist or is invalid."""
    if not path.is_file():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "schema_version" not in data:
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def _load_bundled_iocs() -> dict[str, Any] | None:
    """Load bundled IoC database. Tries package resource first, then dev path."""
    try:
        ref = resources.files("glassworm_hunter") / "data" / "ioc.json"
        data = json.loads(ref.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "schema_version" in data:
            return data
    except (FileNotFoundError, TypeError, json.JSONDecodeError, OSError):
        pass
    return _load_json_iocs(_DEV_IOC_PATH)


def _hardcoded_to_dict() -> dict[str, Any]:
    """Convert hardcoded constants to the JSON schema format."""
    return {
        "extensions": [
            {"id": ext_id, "wave": wave, "source": source, "date_discovered": date}
            for ext_id, wave, source, date in MALICIOUS_EXTENSIONS
        ],
        "npm_packages": [
            {
                "name": name,
                "malicious_versions": ver,
                "wave": wave,
                "source": source,
                "date_discovered": date,
            }
            for name, ver, wave, source, date in MALICIOUS_NPM_PACKAGES
        ],
        "c2_ips": [{"ip": ip} for ip in C2_IPS],
        "c2_wallets": [{"address": addr} for addr in C2_WALLETS],
        "attacker_artifacts": [
            {"type": "email", "value": ATTACKER_EMAIL},
            {"type": "path", "value": ATTACKER_PATH_ARTIFACT},
            {"type": "marker_variable", "value": MARKER_VARIABLE},
        ],
    }


def _merge_ioc_dbs(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge overlay IoCs into base. Deduplicates by primary key per category. Never removes."""
    merged = dict(base)

    # Extensions: deduplicate by id
    existing_ext_ids = {e["id"] for e in merged.get("extensions", [])}
    for ext in overlay.get("extensions", []):
        if ext.get("id") and ext["id"] not in existing_ext_ids:
            merged.setdefault("extensions", []).append(ext)
            existing_ext_ids.add(ext["id"])

    # npm packages: deduplicate by name
    existing_npm = {e["name"] for e in merged.get("npm_packages", [])}
    for pkg in overlay.get("npm_packages", []):
        if pkg.get("name") and pkg["name"] not in existing_npm:
            merged.setdefault("npm_packages", []).append(pkg)
            existing_npm.add(pkg["name"])

    # C2 IPs: deduplicate by ip
    existing_ips = {e["ip"] for e in merged.get("c2_ips", [])}
    for ip_entry in overlay.get("c2_ips", []):
        if ip_entry.get("ip") and ip_entry["ip"] not in existing_ips:
            merged.setdefault("c2_ips", []).append(ip_entry)
            existing_ips.add(ip_entry["ip"])

    # Wallets: deduplicate by address
    existing_wallets = {e["address"] for e in merged.get("c2_wallets", [])}
    for w in overlay.get("c2_wallets", []):
        if w.get("address") and w["address"] not in existing_wallets:
            merged.setdefault("c2_wallets", []).append(w)
            existing_wallets.add(w["address"])

    # Attacker artifacts: deduplicate by value
    existing_artifacts = {e["value"] for e in merged.get("attacker_artifacts", [])}
    for a in overlay.get("attacker_artifacts", []):
        if a.get("value") and a["value"] not in existing_artifacts:
            merged.setdefault("attacker_artifacts", []).append(a)
            existing_artifacts.add(a["value"])

    return merged


# Optional extra IoC file set via --ioc-file CLI flag
_extra_ioc_path: Path | None = None


def set_extra_ioc_path(path: Path | None) -> None:
    """Set an additional IoC JSON file to load (highest priority layer)."""
    global _extra_ioc_path, _merged_db
    _extra_ioc_path = path
    _merged_db = None  # invalidate cache


def load_ioc_database() -> dict[str, Any]:
    """Load and merge IoC database from all layers. Cached after first call."""
    global _merged_db
    if _merged_db is not None:
        return _merged_db

    db = _hardcoded_to_dict()

    bundled = _load_bundled_iocs()
    if bundled:
        db = _merge_ioc_dbs(db, bundled)

    user = _load_json_iocs(_USER_IOC_PATH)
    if user:
        db = _merge_ioc_dbs(db, user)

    if _extra_ioc_path is not None:
        extra = _load_json_iocs(_extra_ioc_path)
        if extra:
            db = _merge_ioc_dbs(db, extra)

    _merged_db = db
    return db


def get_extension_ids() -> frozenset[str]:
    """Get all known malicious extension IDs from merged database."""
    db = load_ioc_database()
    return frozenset(e["id"] for e in db.get("extensions", []))


def get_extension_meta() -> dict[str, dict[str, str]]:
    """Get metadata for all known malicious extensions."""
    db = load_ioc_database()
    return {
        e["id"]: {
            "wave": e.get("wave", "unknown"),
            "source": e.get("source", "unknown"),
            "date": e.get("date_discovered", "unknown"),
        }
        for e in db.get("extensions", [])
    }


def get_npm_packages() -> frozenset[str]:
    """Get all known malicious npm package names."""
    db = load_ioc_database()
    return frozenset(e["name"] for e in db.get("npm_packages", []))


def get_npm_meta() -> dict[str, dict[str, str]]:
    """Get metadata for all known malicious npm packages."""
    db = load_ioc_database()
    return {
        e["name"]: {
            "malicious_versions": e.get("malicious_versions", "unknown"),
            "wave": e.get("wave", "unknown"),
            "source": e.get("source", "unknown"),
            "date": e.get("date_discovered", "unknown"),
        }
        for e in db.get("npm_packages", [])
    }


def get_c2_ips() -> frozenset[str]:
    """Get all known C2 IP addresses."""
    db = load_ioc_database()
    return frozenset(e["ip"] for e in db.get("c2_ips", []))


def get_c2_wallets() -> frozenset[str]:
    """Get all known C2 wallet addresses."""
    db = load_ioc_database()
    return frozenset(e["address"] for e in db.get("c2_wallets", []))


def get_attacker_artifacts() -> list[dict[str, str]]:
    """Get all known attacker artifacts (emails, paths, markers)."""
    db = load_ioc_database()
    return db.get("attacker_artifacts", [])


def reset_cache() -> None:
    """Reset the IoC database cache. Useful for testing."""
    global _merged_db, _extra_ioc_path
    _merged_db = None
    _extra_ioc_path = None


# --- Detection functions (use merged database) ---


def check_extension_id(publisher: str, name: str) -> Finding | None:
    """Check if a VS Code extension matches a known malicious extension."""
    ext_id = f"{publisher.lower()}.{name.lower()}"
    all_ids = get_extension_ids()
    meta = get_extension_meta()
    for known_id in all_ids:
        if ext_id == known_id.lower():
            info = meta[known_id]
            wave, source, date = info["wave"], info["source"], info["date"]
            return Finding(
                severity=Severity.CRITICAL,
                detection_type=DetectionType.KNOWN_MALICIOUS_EXTENSION,
                file_path=Path("."),
                title=f"Known GlassWorm extension: {known_id}",
                description=(
                    f"Extension '{known_id}' is a confirmed GlassWorm malware "
                    f"distribution vector, identified in {wave} by {source} "
                    f"on {date}."
                ),
                evidence=f"Extension ID: {known_id}",
                recommendation=(
                    "Uninstall this extension immediately. Check your NPM tokens, "
                    "GitHub credentials, and SSH keys for compromise. Rotate all "
                    "developer credentials on this machine."
                ),
                metadata={"wave": wave, "source": source, "date": date},
            )
    return None


def check_npm_package(name: str, version: str | None = None) -> Finding | None:
    """Check if an npm package matches a known malicious package."""
    all_names = get_npm_packages()
    if name in all_names:
        meta = get_npm_meta()
        info = meta[name]
        pkg_ver = info["malicious_versions"]
        wave, source, date = info["wave"], info["source"], info["date"]
        return Finding(
            severity=Severity.CRITICAL,
            detection_type=DetectionType.KNOWN_MALICIOUS_PACKAGE,
            file_path=Path("."),
            title=f"Known GlassWorm npm package: {name}",
            description=(
                f"Package '{name}' (malicious versions: {pkg_ver}) is a "
                f"confirmed GlassWorm distribution vector, identified in "
                f"{wave} by {source} on {date}."
            ),
            evidence=f"Package: {name}, installed version: {version or 'unknown'}",
            recommendation=(
                "Remove this package immediately with `npm uninstall`. "
                "Check your NPM tokens and GitHub credentials for compromise."
            ),
            metadata={
                "wave": wave,
                "source": source,
                "malicious_versions": pkg_ver,
            },
        )
    return None


def search_file_content_for_iocs(content: str, file_path: Path) -> list[Finding]:
    """Search file content for known IOC strings."""
    findings: list[Finding] = []

    c2_ips = get_c2_ips()
    c2_wallets = get_c2_wallets()
    artifacts = get_attacker_artifacts()

    # Search for C2 IPs
    for match in _IP_RE.finditer(content):
        ip = match.group(1)
        if ip in c2_ips:
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    detection_type=DetectionType.KNOWN_C2_IP,
                    file_path=file_path,
                    line_number=line_num,
                    column=match.start() - content.rfind("\n", 0, match.start()) - 1,
                    title=f"Known GlassWorm C2 IP address: {ip}",
                    description=(
                        f"Found known GlassWorm command-and-control IP address {ip} in source code."
                    ),
                    evidence=ip,
                    recommendation=(
                        "This file references a known GlassWorm C2 server. "
                        "Investigate how this IP ended up in your code. "
                        "If this is in a dependency, remove it immediately."
                    ),
                )
            )

    # Search for Solana wallet addresses
    for match in _WALLET_RE.finditer(content):
        addr = match.group(1)
        if addr in c2_wallets:
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    detection_type=DetectionType.KNOWN_C2_WALLET,
                    file_path=file_path,
                    line_number=line_num,
                    column=match.start() - content.rfind("\n", 0, match.start()) - 1,
                    title=f"Known GlassWorm Solana C2 wallet: {addr[:16]}...",
                    description=(
                        "Found known GlassWorm Solana wallet address used as a "
                        "command-and-control channel."
                    ),
                    evidence=addr,
                    recommendation=(
                        "This file references a known GlassWorm C2 wallet. "
                        "The Solana blockchain is used to distribute payload URLs. "
                        "Remove this file/package immediately."
                    ),
                )
            )

    # Search for attacker artifacts (from merged database)
    for artifact in artifacts:
        value = artifact.get("value", "")
        if not value or value not in content:
            continue
        artifact_type = artifact.get("type", "unknown")
        line_num = content[: content.index(value)].count("\n") + 1

        if artifact_type == "email":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    detection_type=DetectionType.C2_INDICATOR,
                    file_path=file_path,
                    line_number=line_num,
                    title="Known GlassWorm attacker email",
                    description=f"Found email address '{value}' associated with GlassWorm C2.",
                    evidence=value,
                    recommendation="Investigate this file immediately.",
                )
            )
        elif artifact_type == "path":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    detection_type=DetectionType.C2_INDICATOR,
                    file_path=file_path,
                    line_number=line_num,
                    title="GlassWorm attacker build path artifact",
                    description=(
                        f"Found path '{value}' - a known artifact "
                        "from GlassWorm Rust implant builds."
                    ),
                    evidence=value,
                    recommendation=(
                        "This file likely contains GlassWorm implant code. Remove immediately."
                    ),
                )
            )
        elif artifact_type == "marker_variable":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    detection_type=DetectionType.C2_INDICATOR,
                    file_path=file_path,
                    line_number=line_num,
                    title=f"GlassWorm marker variable: {value}",
                    description=(
                        f"Found marker variable '{value}' - a known artifact "
                        "from GlassWorm ForceMemo variant."
                    ),
                    evidence=value,
                    recommendation="Investigate this file immediately.",
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    detection_type=DetectionType.C2_INDICATOR,
                    file_path=file_path,
                    line_number=line_num,
                    title=f"GlassWorm attacker artifact: {value[:50]}",
                    description="Found known GlassWorm artifact in source code.",
                    evidence=value[:200],
                    recommendation="Investigate this file immediately.",
                )
            )

    return findings
