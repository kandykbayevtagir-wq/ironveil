"""SARIF 2.1.0 output for GitHub Code Scanning."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, urlsplit

from ironveil import __version__
from ironveil.models import Confidence, Finding, ScanResult, Severity

from ._common import (
    TOOL_NAME,
    display_path,
    json_safe,
    ordered_errors,
    ordered_findings,
    ordered_warnings,
    sarif_timestamp,
    stable_fingerprint,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

_SEMVER = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.0",
}
_PRECISION: dict[Confidence, str] = {
    Confidence.HIGH: "high",
    Confidence.MEDIUM: "medium",
    Confidence.LOW: "low",
}


def _safe_help_uri(references: tuple[str, ...]) -> str | None:
    for reference in references:
        parsed = urlsplit(reference)
        if (
            parsed.scheme in {"https", "http"}
            and parsed.netloc
            and parsed.username is None
            and parsed.password is None
        ):
            return reference
    return None


def _artifact_uri(path: str, root: Path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        except ValueError:
            candidate = Path(candidate.name)
    normalized = display_path(str(candidate))
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return quote(normalized or "unknown", safe="/-._~")


def _rule_description(finding: Finding) -> str:
    description = finding.metadata.get("description")
    return str(description) if description else finding.message


def _rule_tags(finding: Finding) -> list[str]:
    metadata_tags = finding.metadata.get("tags", ())
    if isinstance(metadata_tags, str):
        tags = [metadata_tags]
    elif isinstance(metadata_tags, (list, tuple, set, frozenset)):
        tags = [str(tag) for tag in metadata_tags]
    else:
        tags = []
    tags.extend(("security", finding.category.value))
    return sorted(set(tags), key=str.casefold)


def _rule_descriptor(finding: Finding) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.rule_name or finding.rule_id,
        "shortDescription": {"text": finding.rule_name or finding.rule_id},
        "fullDescription": {"text": _rule_description(finding)},
        "help": {"text": finding.remediation},
        "defaultConfiguration": {
            "level": _LEVEL[finding.severity],
            "rank": float(_SECURITY_SEVERITY[finding.severity]) * 10,
        },
        "properties": {
            "tags": _rule_tags(finding),
            "category": finding.category.value,
            "severity": finding.severity.value,
            "precision": _PRECISION[finding.confidence],
            "problem.severity": (
                "error"
                if finding.severity in {Severity.CRITICAL, Severity.HIGH}
                else "warning"
                if finding.severity is Severity.MEDIUM
                else "recommendation"
            ),
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }
    help_uri = _safe_help_uri(finding.references)
    if help_uri:
        descriptor["helpUri"] = help_uri
    return descriptor


def _suppression(finding: Finding) -> dict[str, str]:
    configured_kind = str(finding.metadata.get("suppression_kind", "")).casefold()
    kind = "inSource" if configured_kind in {"inline", "insource"} else "external"
    return {
        "kind": kind,
        "status": "accepted",
        "justification": finding.suppression_reason or "Suppressed by IronVeil policy",
    }


def _result(finding: Finding, *, rule_index: int, root: Path) -> dict[str, Any]:
    fingerprint = stable_fingerprint(finding)
    item: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _artifact_uri(finding.path, root),
                    },
                    "region": {
                        "startLine": max(1, finding.line),
                        "startColumn": max(1, finding.column),
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
            "ironveilFingerprint/v1": fingerprint,
        },
        "baselineState": "unchanged" if finding.baseline else "new",
        "properties": {
            "category": finding.category.value,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "source": finding.source,
            "baseline": finding.baseline,
            "suppressed": finding.suppressed,
            "commit": finding.commit or "",
            "suppressionExpires": finding.suppression_expires or "",
        },
    }
    if finding.suppressed:
        item["suppressions"] = [_suppression(finding)]
    return item


def _notification(message: str, *, level: str, path: str | None = None, root: Path) -> dict[str, Any]:
    notification: dict[str, Any] = {
        "level": level,
        "message": {"text": message},
    }
    if path:
        notification["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": _artifact_uri(path, root)}}}
        ]
    return notification


def sarif_dict(
    result: ScanResult,
    *,
    tool_version: str = __version__,
    include_suppressed: bool = False,
) -> dict[str, Any]:
    """Build deterministic SARIF, hiding accepted findings by default."""

    findings = ordered_findings(result, include_suppressed=include_suppressed)
    representative_by_rule: dict[str, Finding] = {}
    for finding in findings:
        representative_by_rule.setdefault(finding.rule_id, finding)
    rule_ids = sorted(representative_by_rule, key=str.casefold)
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}

    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "version": str(tool_version),
        "informationUri": "https://github.com/kandykbayevtagir-wq/ironveil",
        "rules": [_rule_descriptor(representative_by_rule[rule_id]) for rule_id in rule_ids],
    }
    if _SEMVER.fullmatch(str(tool_version)):
        driver["semanticVersion"] = str(tool_version)

    notifications = [
        _notification(
            error.message,
            level="error" if error.fatal else "warning",
            path=error.path,
            root=result.root,
        )
        for error in ordered_errors(result)
    ]
    notifications.extend(
        _notification(warning, level="warning", root=result.root) for warning in ordered_warnings(result)
    )

    invocation: dict[str, Any] = {
        "executionSuccessful": not any(error.fatal for error in result.errors),
        "commandLine": result.command,
    }
    started_at = sarif_timestamp(result.started_at)
    if started_at:
        invocation["startTimeUtc"] = started_at
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    config_key = hashlib.sha256(result.config_digest.encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
    summary = result.summary()
    properties: dict[str, Any] = {
        "ironveil/configDigest": result.config_digest,
        "ironveil/gitBranch": result.git_branch or "",
        "ironveil/gitCommit": result.git_commit or "",
        "ironveil/historyScanned": result.history_scanned,
        "ironveil/dependenciesScanned": result.dependencies_scanned,
        "ironveil/findingsTotal": summary["total"],
        "ironveil/findingsNew": summary["new"],
        "ironveil/findingsBaseline": summary["baseline"],
        "ironveil/findingsSuppressed": summary["suppressed"],
        "ironveil/filesScanned": result.stats.files_scanned,
        "ironveil/bytesScanned": result.stats.bytes_scanned,
    }
    if math.isfinite(result.stats.duration_seconds) and result.stats.duration_seconds >= 0:
        properties["ironveil/durationSeconds"] = result.stats.duration_seconds

    run = {
        "tool": {"driver": driver},
        "automationDetails": {"id": f"ironveil/{config_key}"},
        "invocations": [invocation],
        "results": [
            _result(
                finding,
                rule_index=rule_index[finding.rule_id],
                root=result.root,
            )
            for finding in findings
        ],
        "properties": properties,
    }
    return cast(
        dict[str, Any],
        json_safe({"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}),
    )


@dataclass(frozen=True, slots=True)
class SARIFReporter:
    """Render GitHub-compatible SARIF 2.1.0."""

    name: str = "sarif"
    suffix: str = ".sarif"
    media_type: str = "application/sarif+json"

    def render(
        self,
        result: ScanResult,
        *,
        tool_version: str = __version__,
        indent: int = 2,
        include_suppressed: bool = False,
    ) -> str:
        if indent < 0:
            raise ValueError("SARIF indentation must be zero or greater")
        return (
            json.dumps(
                sarif_dict(
                    result,
                    tool_version=tool_version,
                    include_suppressed=include_suppressed,
                ),
                ensure_ascii=False,
                indent=indent,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        )


def render(
    result: ScanResult,
    *,
    tool_version: str = __version__,
    indent: int = 2,
    include_suppressed: bool = False,
) -> str:
    return SARIFReporter().render(
        result,
        tool_version=tool_version,
        indent=indent,
        include_suppressed=include_suppressed,
    )


render_sarif = render
to_dict = sarif_dict

__all__ = [
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SARIFReporter",
    "render",
    "render_sarif",
    "sarif_dict",
    "to_dict",
]
