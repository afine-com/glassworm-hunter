"""JSON output reporter."""

from __future__ import annotations

import json

from ..engine.models import Report, Severity


def generate_json(report: Report) -> str:
    """Generate JSON report string."""
    total_duration = sum(r.scan_duration_seconds for r in report.results)

    output = {
        "scanner": "glassworm-hunter",
        "version": report.scanner_version,
        "timestamp": report.scan_timestamp,
        "summary": {
            "files_scanned": report.total_files_scanned,
            "total_findings": report.total_findings,
            "critical": report.count_by_severity(Severity.CRITICAL),
            "high": report.count_by_severity(Severity.HIGH),
            "medium": report.count_by_severity(Severity.MEDIUM),
            "low": report.count_by_severity(Severity.LOW),
            "scan_duration_seconds": round(total_duration, 2),
        },
        "findings": [f.to_dict() for f in report.all_findings],
        "scanners": [
            {
                "name": r.scanner_name,
                "target": r.scan_target,
                "files_scanned": r.files_scanned,
                "findings": len(r.findings),
                "duration_seconds": round(r.scan_duration_seconds, 2),
                "errors": r.errors,
            }
            for r in report.results
        ],
    }

    return json.dumps(output, indent=2, ensure_ascii=False)
