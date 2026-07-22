"""Typed, serialization-friendly models shared across IronVeil."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(StrEnum):
    SECRET = "secret"  # noqa: S105 - finding category, not a credential
    SENSITIVE_FILE = "sensitive-file"
    DEPENDENCY = "dependency"
    IAC = "iac"
    REPOSITORY = "repository"
    SCAN_ERROR = "scan-error"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    description: str
    category: Category
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str
    references: tuple[str, ...] = ()
    pattern: str | None = None
    detection_type: str = "regex"
    file_globs: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(slots=True)
class Finding:
    rule_id: str
    rule_name: str
    category: Category
    severity: Severity
    confidence: Confidence
    path: str
    line: int
    column: int
    message: str
    remediation: str
    fingerprint: str
    evidence: str
    references: tuple[str, ...] = ()
    source: str = "working-tree"
    commit: str | None = None
    baseline: bool = False
    suppressed: bool = False
    suppression_reason: str | None = None
    suppression_expires: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
            "evidence": self.evidence,
            "references": list(self.references),
            "source": self.source,
            "commit": self.commit,
            "baseline": self.baseline,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "suppression_expires": self.suppression_expires,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class ScanError:
    path: str
    message: str
    fatal: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "message": self.message, "fatal": self.fatal}


@dataclass(slots=True)
class ScanStats:
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    cache_hits: int = 0
    bytes_scanned: int = 0
    duration_seconds: float = 0.0

    @property
    def scan_rate(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return self.bytes_scanned / self.duration_seconds

    def to_dict(self) -> dict[str, int | float]:
        return {
            "files_discovered": self.files_discovered,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "cache_hits": self.cache_hits,
            "bytes_scanned": self.bytes_scanned,
            "duration_seconds": round(self.duration_seconds, 6),
            "scan_rate_bytes_per_second": round(self.scan_rate, 2),
        }


@dataclass(slots=True)
class ScanResult:
    root: Path
    command: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    config_digest: str = ""
    started_at: str = ""
    git_branch: str | None = None
    git_commit: str | None = None
    history_scanned: bool = False
    dependencies_scanned: bool = False

    def visible_findings(self) -> list[Finding]:
        return [item for item in self.findings if not item.suppressed]

    def new_findings(self) -> list[Finding]:
        return [item for item in self.findings if not item.suppressed and not item.baseline]

    def summary(self) -> dict[str, Any]:
        visible = self.visible_findings()
        by_severity = {item.value: 0 for item in Severity}
        by_category = {item.value: 0 for item in Category}
        for finding in visible:
            by_severity[finding.severity.value] += 1
            by_category[finding.category.value] += 1
        return {
            "total": len(visible),
            "new": sum(not item.baseline for item in visible),
            "baseline": sum(item.baseline for item in visible),
            "suppressed": sum(item.suppressed for item in self.findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
        }


def finding_sort_key(finding: Finding) -> tuple[int, str, int, int, str]:
    """Return a deterministic key with the most severe finding first."""

    return (
        -SEVERITY_RANK[finding.severity],
        finding.path.casefold(),
        finding.line,
        finding.column,
        finding.rule_id,
    )
