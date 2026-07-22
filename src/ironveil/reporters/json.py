"""Versioned JSON reports with a stable v1 document shape."""

from __future__ import annotations

import copy
import json as jsonlib
from dataclasses import dataclass
from typing import Any, cast

from ironveil import __version__
from ironveil.models import Category, ScanResult, Severity

from ._common import (
    SCHEMA_VERSION,
    TOOL_NAME,
    display_path,
    json_safe,
    ordered_errors,
    ordered_findings,
    ordered_warnings,
    report_safe_evidence,
    stable_fingerprint,
)

REPORT_SCHEMA_V1: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "IronVeil report v1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "tool",
        "metadata",
        "summary",
        "findings",
        "errors",
        "warnings",
        "stats",
    ],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "tool": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "version"],
            "properties": {
                "name": {"const": TOOL_NAME},
                "version": {"type": "string"},
            },
        },
        "metadata": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "scan_time",
                "root",
                "command",
                "config_digest",
                "git_branch",
                "git_commit",
                "history_scanned",
                "dependencies_scanned",
            ],
            "properties": {
                "scan_time": {"type": "string"},
                "root": {"type": "string"},
                "command": {"type": "string"},
                "config_digest": {"type": "string"},
                "git_branch": {"type": ["string", "null"]},
                "git_commit": {"type": ["string", "null"]},
                "history_scanned": {"type": "boolean"},
                "dependencies_scanned": {"type": "boolean"},
            },
        },
        "summary": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "total",
                "new",
                "baseline",
                "suppressed",
                "by_severity",
                "by_category",
                "errors",
                "warnings",
            ],
            "properties": {
                "total": {"type": "integer", "minimum": 0},
                "new": {"type": "integer", "minimum": 0},
                "baseline": {"type": "integer", "minimum": 0},
                "suppressed": {"type": "integer", "minimum": 0},
                "by_severity": {
                    "type": "object",
                    "required": [severity.value for severity in Severity],
                    "additionalProperties": False,
                    "properties": {
                        severity.value: {"type": "integer", "minimum": 0} for severity in Severity
                    },
                },
                "by_category": {
                    "type": "object",
                    "required": [category.value for category in Category],
                    "additionalProperties": False,
                    "properties": {
                        category.value: {"type": "integer", "minimum": 0} for category in Category
                    },
                },
                "errors": {"type": "integer", "minimum": 0},
                "warnings": {"type": "integer", "minimum": 0},
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "rule_id",
                    "rule_name",
                    "category",
                    "severity",
                    "confidence",
                    "path",
                    "line",
                    "column",
                    "message",
                    "remediation",
                    "fingerprint",
                    "evidence",
                    "references",
                    "source",
                    "commit",
                    "baseline",
                    "suppressed",
                    "suppression_reason",
                    "suppression_expires",
                    "metadata",
                ],
                "properties": {
                    "rule_id": {"type": "string"},
                    "rule_name": {"type": "string"},
                    "category": {"enum": [category.value for category in Category]},
                    "severity": {"enum": [severity.value for severity in Severity]},
                    "confidence": {"enum": ["high", "medium", "low"]},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "column": {"type": "integer"},
                    "message": {"type": "string"},
                    "remediation": {"type": "string"},
                    "fingerprint": {"type": "string", "minLength": 1},
                    "evidence": {"type": "string"},
                    "references": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "source": {"type": "string"},
                    "commit": {"type": ["string", "null"]},
                    "baseline": {"type": "boolean"},
                    "suppressed": {"type": "boolean"},
                    "suppression_reason": {"type": ["string", "null"]},
                    "suppression_expires": {"type": ["string", "null"]},
                    "metadata": {"type": "object"},
                },
            },
        },
        "errors": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "message", "fatal"],
                "properties": {
                    "path": {"type": "string"},
                    "message": {"type": "string"},
                    "fatal": {"type": "boolean"},
                },
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
        "stats": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "files_discovered",
                "files_scanned",
                "files_skipped",
                "cache_hits",
                "bytes_scanned",
                "duration_seconds",
                "scan_rate_bytes_per_second",
            ],
            "properties": {
                "files_discovered": {"type": "integer", "minimum": 0},
                "files_scanned": {"type": "integer", "minimum": 0},
                "files_skipped": {"type": "integer", "minimum": 0},
                "cache_hits": {"type": "integer", "minimum": 0},
                "bytes_scanned": {"type": "integer", "minimum": 0},
                "duration_seconds": {"type": ["number", "null"]},
                "scan_rate_bytes_per_second": {"type": ["number", "null"]},
            },
        },
    },
}


def report_dict(result: ScanResult, *, tool_version: str = __version__) -> dict[str, Any]:
    """Build the canonical report-v1 object without runtime timestamps."""

    findings: list[dict[str, Any]] = []
    for finding in ordered_findings(result):
        item = finding.to_dict()
        item["fingerprint"] = stable_fingerprint(finding)
        item["path"] = display_path(finding.path)
        item["evidence"] = report_safe_evidence(finding)
        findings.append(json_safe(item))

    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": str(tool_version)},
        "metadata": {
            "scan_time": result.started_at,
            "root": str(result.root),
            "command": result.command,
            "config_digest": result.config_digest,
            "git_branch": result.git_branch,
            "git_commit": result.git_commit,
            "history_scanned": result.history_scanned,
            "dependencies_scanned": result.dependencies_scanned,
        },
        "summary": result.summary(),
        "findings": findings,
        "errors": [error.to_dict() for error in ordered_errors(result)],
        "warnings": ordered_warnings(result),
        "stats": result.stats.to_dict(),
    }
    return cast(dict[str, Any], json_safe(document))


@dataclass(frozen=True, slots=True)
class JSONReporter:
    """Render the stable IronVeil JSON report schema."""

    name: str = "json"
    suffix: str = ".json"
    media_type: str = "application/json"

    def render(self, result: ScanResult, *, tool_version: str = __version__, indent: int = 2) -> str:
        if indent < 0:
            raise ValueError("JSON indentation must be zero or greater")
        return (
            jsonlib.dumps(
                report_dict(result, tool_version=tool_version),
                ensure_ascii=False,
                indent=indent,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        )


def get_schema() -> dict[str, Any]:
    """Return a copy so callers cannot mutate the package schema."""

    return copy.deepcopy(REPORT_SCHEMA_V1)


def render(result: ScanResult, *, tool_version: str = __version__, indent: int = 2) -> str:
    return JSONReporter().render(result, tool_version=tool_version, indent=indent)


render_json = render
to_dict = report_dict

__all__ = [
    "REPORT_SCHEMA_V1",
    "JSONReporter",
    "get_schema",
    "render",
    "render_json",
    "report_dict",
    "to_dict",
]
