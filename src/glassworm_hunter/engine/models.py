"""Data structures for scan findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class Severity(Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


class DetectionType(Enum):
    """Categories of detection rules."""

    INVISIBLE_UNICODE = "invisible-unicode"
    BIDI_OVERRIDE = "bidi-override"
    ZERO_WIDTH_CHARS = "zero-width-chars"
    HANGUL_FILLER = "hangul-filler"
    EVAL_PATTERN = "eval-pattern"
    DECODER_PATTERN = "decoder-pattern"
    C2_INDICATOR = "c2-indicator"
    CREDENTIAL_ACCESS = "credential-access"
    KNOWN_MALICIOUS_EXTENSION = "known-malicious-extension"
    KNOWN_MALICIOUS_PACKAGE = "known-malicious-package"
    KNOWN_C2_IP = "known-c2-ip"
    KNOWN_C2_WALLET = "known-c2-wallet"
    SUSPICIOUS_EXTENSION_DEPENDENCY = "suspicious-extension-dependency"
    SUSPICIOUS_INSTALL_SCRIPT = "suspicious-install-script"


@dataclass(frozen=True)
class Finding:
    """A single detection finding."""

    severity: Severity
    detection_type: DetectionType
    file_path: Path
    title: str
    description: str
    evidence: str
    recommendation: str
    line_number: int | None = None
    column: int | None = None
    metadata: dict[str, str | int | list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize to dictionary."""
        return {
            "severity": self.severity.value,
            "detection_type": self.detection_type.value,
            "file": str(self.file_path),
            "line": self.line_number,
            "column": self.column,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "metadata": dict(self.metadata),
        }


@dataclass
class ScanResult:
    """Results from a single scanner."""

    scanner_name: str
    scan_target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


@dataclass
class Report:
    """Aggregated scan report."""

    results: list[ScanResult]
    scanner_version: str
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def total_files_scanned(self) -> int:
        return sum(r.files_scanned for r in self.results)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self.results:
            findings.extend(r.findings)
        return findings

    @property
    def has_findings(self) -> bool:
        return self.total_findings > 0

    @property
    def max_severity(self) -> Severity | None:
        findings = self.all_findings
        if not findings:
            return None
        return max(f.severity for f in findings)

    def count_by_severity(self, severity: Severity) -> int:
        return sum(1 for f in self.all_findings if f.severity == severity)
