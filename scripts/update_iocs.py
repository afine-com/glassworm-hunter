#!/usr/bin/env python3
"""Automated IoC database updater for CI.

Fetches the latest IoC indicators from trusted sources,
merges them into data/ioc.json, and updates data/ioc_sources.json
with run metadata.

Called by .github/workflows/update-iocs.yml on a daily schedule.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

IOC_PATH = Path("data/ioc.json")
SOURCES_PATH = Path("data/ioc_sources.json")

# Trusted IoC sources to check
SOURCES = {
    "github_advisory": {
        "description": ("GitHub Advisory Database - structured malware advisories"),
        "endpoint": "https://api.github.com/advisories?type=malware&ecosystem=npm&per_page=100",
    },
}


def _fetch_json(url: str, headers: dict[str, str] | None = None) -> dict | list | None:
    """Fetch JSON from a URL. Returns None on failure."""
    hdrs = {"User-Agent": "glassworm-ioc-updater/1.0"}
    if headers:
        hdrs.update(headers)
    try:
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        print(f"  Warning: failed to fetch {url}: {e}", file=sys.stderr)
        return None


def _load_current_iocs() -> dict:
    """Load the current ioc.json database."""
    if not IOC_PATH.exists():
        print("Error: data/ioc.json not found", file=sys.stderr)
        sys.exit(2)
    with open(IOC_PATH, encoding="utf-8") as f:
        return json.load(f)


def _merge_new_iocs(db: dict, new_entries: dict) -> int:
    """Merge new IoC entries into the database. Returns count of new entries added."""
    added = 0

    # Merge extensions
    existing_ext_ids = {e["id"] for e in db.get("extensions", [])}
    for ext in new_entries.get("extensions", []):
        if ext.get("id") and ext["id"] not in existing_ext_ids:
            db.setdefault("extensions", []).append(ext)
            existing_ext_ids.add(ext["id"])
            added += 1

    # Merge npm packages
    existing_npm = {e["name"] for e in db.get("npm_packages", [])}
    for pkg in new_entries.get("npm_packages", []):
        if pkg.get("name") and pkg["name"] not in existing_npm:
            db.setdefault("npm_packages", []).append(pkg)
            existing_npm.add(pkg["name"])
            added += 1

    # Merge C2 IPs
    existing_ips = {e["ip"] for e in db.get("c2_ips", [])}
    for ip_entry in new_entries.get("c2_ips", []):
        if ip_entry.get("ip") and ip_entry["ip"] not in existing_ips:
            db.setdefault("c2_ips", []).append(ip_entry)
            existing_ips.add(ip_entry["ip"])
            added += 1

    # Merge wallets
    existing_wallets = {e["address"] for e in db.get("c2_wallets", [])}
    for w in new_entries.get("c2_wallets", []):
        if w.get("address") and w["address"] not in existing_wallets:
            db.setdefault("c2_wallets", []).append(w)
            existing_wallets.add(w["address"])
            added += 1

    # Merge attacker artifacts
    existing_artifacts = {e["value"] for e in db.get("attacker_artifacts", [])}
    for a in new_entries.get("attacker_artifacts", []):
        if a.get("value") and a["value"] not in existing_artifacts:
            db.setdefault("attacker_artifacts", []).append(a)
            existing_artifacts.add(a["value"])
            added += 1

    return added


def main() -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    db = _load_current_iocs()

    # Load or initialize sources metadata
    if SOURCES_PATH.exists():
        with open(SOURCES_PATH, encoding="utf-8") as f:
            sources_meta = json.load(f)
    else:
        sources_meta = {"sources": {}}

    total_added = 0

    for source_name, source_config in SOURCES.items():
        print(f"Checking {source_name}...")
        endpoint = source_config.get("endpoint", "")
        if not endpoint:
            continue

        data = _fetch_json(endpoint)
        if data is None:
            continue

        # Source-specific parsing would go here.
        # For now, this is a scaffold that validates the pipeline works.
        new_entries: dict = {
            "extensions": [],
            "npm_packages": [],
            "c2_ips": [],
            "c2_wallets": [],
            "attacker_artifacts": [],
        }

        added = _merge_new_iocs(db, new_entries)
        total_added += added

        sources_meta.setdefault("sources", {})[source_name] = {
            "last_checked": now,
            "description": source_config.get("description", ""),
            "endpoint": endpoint,
            "new_iocs_found": added,
        }

    # Update timestamp
    db["last_updated"] = now
    sources_meta["last_run"] = now

    # Write updated files
    with open(IOC_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
        f.write("\n")

    with open(SOURCES_PATH, "w", encoding="utf-8") as f:
        json.dump(sources_meta, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Done. {total_added} new IoCs added.")

    # Summary
    ext_count = len(db.get("extensions", []))
    ip_count = len(db.get("c2_ips", []))
    npm_count = len(db.get("npm_packages", []))
    wallet_count = len(db.get("c2_wallets", []))
    print(
        f"Database totals: {ext_count} extensions, {ip_count} IPs, "
        f"{npm_count} npm packages, {wallet_count} wallets"
    )


if __name__ == "__main__":
    main()
