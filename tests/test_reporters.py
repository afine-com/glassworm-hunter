"""Tests for output reporters."""

from __future__ import annotations

import json
from pathlib import Path

from glassworm_hunter.engine.models import (
    DetectionType,
    Finding,
    Report,
    ScanResult,
    Severity,
)
from glassworm_hunter.reporters.json_report import generate_json
from glassworm_hunter.reporters.sarif import generate_sarif


def _make_report(findings: list[Finding] | None = None) -> Report:
    """Create a test report."""
    result = ScanResult(
        scanner_name="test",
        scan_target="/tmp/test",
        findings=findings or [],
        files_scanned=10,
        scan_duration_seconds=1.5,
    )
    return Report(results=[result], scanner_version="0.1.0")


def _make_finding(severity: Severity = Severity.CRITICAL) -> Finding:
    """Create a test finding."""
    return Finding(
        severity=severity,
        detection_type=DetectionType.INVISIBLE_UNICODE,
        file_path=Path("/tmp/test/malicious.js"),
        line_number=42,
        column=10,
        title="Test finding",
        description="Test description",
        evidence="Test evidence",
        recommendation="Test recommendation",
    )


class TestJsonReporter:
    def test_valid_json(self) -> None:
        report = _make_report([_make_finding()])
        output = generate_json(report)
        parsed = json.loads(output)
        assert parsed["scanner"] == "glassworm-hunter"

    def test_empty_report(self) -> None:
        report = _make_report()
        output = generate_json(report)
        parsed = json.loads(output)
        assert parsed["summary"]["total_findings"] == 0
        assert parsed["findings"] == []

    def test_findings_in_output(self) -> None:
        report = _make_report(
            [
                _make_finding(Severity.CRITICAL),
                _make_finding(Severity.HIGH),
            ]
        )
        output = generate_json(report)
        parsed = json.loads(output)
        assert parsed["summary"]["total_findings"] == 2
        assert parsed["summary"]["critical"] == 1
        assert parsed["summary"]["high"] == 1
        assert len(parsed["findings"]) == 2

    def test_finding_fields(self) -> None:
        report = _make_report([_make_finding()])
        output = generate_json(report)
        parsed = json.loads(output)
        f = parsed["findings"][0]
        assert f["severity"] == "critical"
        assert f["detection_type"] == "invisible-unicode"
        assert f["line"] == 42
        assert f["column"] == 10


class TestSarifReporter:
    def test_valid_sarif_structure(self) -> None:
        report = _make_report([_make_finding()])
        output = generate_sarif(report)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1
        assert parsed["runs"][0]["tool"]["driver"]["name"] == "glassworm-hunter"

    def test_sarif_results(self) -> None:
        report = _make_report([_make_finding()])
        output = generate_sarif(report)
        parsed = json.loads(output)
        results = parsed["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "invisible-unicode"
        assert results[0]["level"] == "error"

    def test_empty_sarif(self) -> None:
        report = _make_report()
        output = generate_sarif(report)
        parsed = json.loads(output)
        assert len(parsed["runs"][0]["results"]) == 0

    def test_sarif_location(self) -> None:
        report = _make_report([_make_finding()])
        output = generate_sarif(report)
        parsed = json.loads(output)
        loc = parsed["runs"][0]["results"][0]["locations"][0]
        region = loc["physicalLocation"]["region"]
        assert region["startLine"] == 42
        assert region["startColumn"] == 11  # SARIF is 1-indexed
