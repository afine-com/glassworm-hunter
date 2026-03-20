"""SARIF v2.1.0 output reporter for GitHub Code Scanning."""

from __future__ import annotations

import json

from ..engine.models import DetectionType, Finding, Report, Severity

_SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

_RULE_DESCRIPTIONS: dict[DetectionType, tuple[str, str]] = {
    DetectionType.INVISIBLE_UNICODE: (
        "Invisible Unicode Payload",
        "Detects sequences of Unicode variation selector characters "
        "used to encode hidden payloads.",
    ),
    DetectionType.BIDI_OVERRIDE: (
        "Bidirectional Override Character",
        "Detects Unicode bidirectional override characters "
        "that can alter code appearance (Trojan Source).",
    ),
    DetectionType.ZERO_WIDTH_CHARS: (
        "Suspicious Zero-Width Characters",
        "Detects unusual density of zero-width characters in source code.",
    ),
    DetectionType.HANGUL_FILLER: (
        "Hangul Filler Character",
        "Detects invisible Hangul filler characters "
        "that can serve as valid JavaScript identifiers.",
    ),
    DetectionType.EVAL_PATTERN: (
        "Suspicious Execution Pattern",
        "Detects dynamic code execution patterns commonly used in supply chain attacks.",
    ),
    DetectionType.DECODER_PATTERN: (
        "GlassWorm Decoder Pattern",
        "Detects the specific codepoint-to-byte decoding pattern used by GlassWorm malware.",
    ),
    DetectionType.C2_INDICATOR: (
        "Command and Control Indicator",
        "Detects patterns associated with GlassWorm's C2 infrastructure.",
    ),
    DetectionType.CREDENTIAL_ACCESS: (
        "Credential Access Pattern",
        "Detects code that accesses sensitive credentials or tokens.",
    ),
    DetectionType.KNOWN_MALICIOUS_EXTENSION: (
        "Known Malicious Extension",
        "Matches a confirmed GlassWorm malware distribution extension.",
    ),
    DetectionType.KNOWN_MALICIOUS_PACKAGE: (
        "Known Malicious Package",
        "Matches a confirmed GlassWorm malware distribution npm package.",
    ),
    DetectionType.KNOWN_C2_IP: (
        "Known C2 IP Address",
        "Matches a known GlassWorm command-and-control server IP address.",
    ),
    DetectionType.KNOWN_C2_WALLET: (
        "Known C2 Wallet Address",
        "Matches a known GlassWorm Solana wallet used for C2 communication.",
    ),
    DetectionType.SUSPICIOUS_EXTENSION_DEPENDENCY: (
        "Suspicious Extension Dependency",
        "Extension depends on a known malicious extension (transitive infection).",
    ),
    DetectionType.SUSPICIOUS_INSTALL_SCRIPT: (
        "Suspicious Install Script",
        "Package has an install lifecycle script that executes code.",
    ),
}


def generate_sarif(report: Report) -> str:
    """Generate SARIF v2.1.0 report string."""
    # Collect all unique rules used
    used_types = set()
    for finding in report.all_findings:
        used_types.add(finding.detection_type)

    rules = []
    rule_index_map: dict[DetectionType, int] = {}
    for idx, dt in enumerate(sorted(used_types, key=lambda x: x.value)):
        name, desc = _RULE_DESCRIPTIONS.get(dt, (dt.value, dt.value))
        rules.append(
            {
                "id": dt.value,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": desc},
                "defaultConfiguration": {"level": "warning"},
            }
        )
        rule_index_map[dt] = idx

    results = []
    for finding in report.all_findings:
        result = _finding_to_sarif_result(finding, rule_index_map)
        results.append(result)

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "glassworm-hunter",
                        "version": report.scanner_version,
                        "informationUri": "https://github.com/afine-com/glassworm-hunter",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _finding_to_sarif_result(
    finding: Finding, rule_index_map: dict[DetectionType, int]
) -> dict[str, object]:
    """Convert a Finding to a SARIF result object."""
    location: dict[str, object] = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": str(finding.file_path),
            },
        }
    }

    if finding.line_number is not None:
        region: dict[str, int] = {"startLine": finding.line_number}
        if finding.column is not None:
            region["startColumn"] = finding.column + 1  # SARIF is 1-indexed
        location["physicalLocation"]["region"] = region  # type: ignore[index]

    return {
        "ruleId": finding.detection_type.value,
        "ruleIndex": rule_index_map.get(finding.detection_type, 0),
        "level": _SARIF_SEVERITY_MAP[finding.severity],
        "message": {"text": finding.description},
        "locations": [location],
    }
