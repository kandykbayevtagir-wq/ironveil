"""Baseline, suppression, and exit-code policy evaluation."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from ironveil.config import AllowlistEntry, PolicyConfig
from ironveil.exceptions import ConfigurationError
from ironveil.models import CONFIDENCE_RANK, SEVERITY_RANK, Finding, ScanResult

BASELINE_SCHEMA = "https://ironveil.dev/schemas/baseline/v1"
MAX_BASELINE_BYTES = 16 * 1024 * 1024
MAX_BASELINE_FINGERPRINTS = 200_000
BASELINE_FINGERPRINT_RE = re.compile(r"^iv1:[0-9a-f]{64}$")
INLINE_SUPPRESSION_RE = re.compile(
    r"ironveil:\s*allow\s+(?P<rule>[A-Za-z0-9_-]+)"
    r"(?:\s+reason=\"(?P<reason>[^\"]+)\")?"
    r"(?:\s+expires=\"(?P<expires>\d{4}-\d{2}-\d{2})\")?",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class InlineSuppression:
    rule: str
    reason: str
    expires: str | None

    @property
    def expired(self) -> bool:
        if not self.expires:
            return False
        try:
            return date.fromisoformat(self.expires) < date.today()
        except ValueError:
            return True


def parse_inline_suppression(line: str) -> InlineSuppression | None:
    match = INLINE_SUPPRESSION_RE.search(line)
    if not match:
        return None
    reason = match.group("reason")
    if not reason:
        return None
    expires = match.group("expires")
    return InlineSuppression(match.group("rule"), reason, expires)


def apply_suppressions(
    finding: Finding,
    source_lines: list[str],
    allowlist: list[AllowlistEntry],
    warnings: list[str],
) -> None:
    for entry in allowlist:
        if not entry.matches(finding.rule_id, finding.path):
            continue
        try:
            expired = bool(entry.expires and date.fromisoformat(entry.expires) < date.today())
        except ValueError:
            warnings.append(f"Invalid allowlist expiry for {entry.rule} at {entry.path}: {entry.expires}")
            continue
        if expired:
            warnings.append(
                f"Expired allowlist entry for {entry.rule} at {entry.path} (expired {entry.expires})"
            )
            continue
        finding.suppressed = True
        finding.suppression_reason = entry.reason
        finding.suppression_expires = entry.expires
        return
    indexes = {max(0, finding.line - 2), max(0, finding.line - 1)}
    for index in sorted(indexes):
        if index >= len(source_lines):
            continue
        suppression = parse_inline_suppression(source_lines[index])
        if suppression and suppression.rule in {finding.rule_id, "*"}:
            if suppression.expires:
                try:
                    date.fromisoformat(suppression.expires)
                except ValueError:
                    warnings.append(
                        f"Invalid inline suppression expiry for {finding.rule_id} "
                        f"at {finding.path}:{index + 1}: {suppression.expires}"
                    )
                    continue
            if suppression.expired:
                warnings.append(
                    f"Expired inline suppression for {finding.rule_id} at {finding.path}:{index + 1}"
                )
                continue
            finding.suppressed = True
            finding.suppression_reason = suppression.reason
            finding.suppression_expires = suppression.expires
            return


def load_baseline(path: Path) -> set[str]:
    if path.is_symlink():
        raise ConfigurationError(f"baseline: expected a regular file, refusing {path}")
    if not path.exists():
        return set()
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise ConfigurationError(f"baseline: expected a regular file, refusing {path}")
            if file_stat.st_size > MAX_BASELINE_BYTES:
                raise ConfigurationError(
                    f"baseline: file exceeds the {MAX_BASELINE_BYTES // (1024 * 1024)} MiB "
                    f"safety limit: {path}"
                )
            payload = handle.read(MAX_BASELINE_BYTES + 1)
        if len(payload) > MAX_BASELINE_BYTES:
            raise ConfigurationError(
                f"baseline: file exceeds the {MAX_BASELINE_BYTES // (1024 * 1024)} MiB safety limit: {path}"
            )
        raw = json.loads(payload.decode("utf-8"))
    except ConfigurationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"baseline: cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != BASELINE_SCHEMA:
        raise ConfigurationError(f"baseline: unsupported or missing schema in {path}")
    fingerprints = raw.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(isinstance(item, str) for item in fingerprints):
        raise ConfigurationError("baseline.fingerprints: expected an array of strings")
    if len(fingerprints) > MAX_BASELINE_FINGERPRINTS:
        raise ConfigurationError(
            f"baseline.fingerprints: exceeds the limit of {MAX_BASELINE_FINGERPRINTS} entries"
        )
    if any(not BASELINE_FINGERPRINT_RE.fullmatch(item) for item in fingerprints):
        raise ConfigurationError("baseline.fingerprints: contains an invalid fingerprint")
    return set(fingerprints)


def mark_baseline(result: ScanResult, fingerprints: set[str]) -> None:
    for finding in result.findings:
        finding.baseline = finding.fingerprint in fingerprints


def baseline_document(result: ScanResult) -> dict[str, object]:
    fingerprints = sorted({finding.fingerprint for finding in result.visible_findings()})
    return {
        "schema": BASELINE_SCHEMA,
        "tool": "ironveil",
        "fingerprints": fingerprints,
        "count": len(fingerprints),
    }


def policy_violations(result: ScanResult, policy: PolicyConfig) -> list[Finding]:
    if policy.no_fail:
        return []
    return [
        finding
        for finding in result.new_findings()
        if finding.category in policy.fail_on
        and SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[policy.fail_severity]
        and CONFIDENCE_RANK[finding.confidence] >= CONFIDENCE_RANK[policy.minimum_confidence]
    ]


def exit_code(result: ScanResult, policy: PolicyConfig) -> int:
    if any(error.fatal for error in result.errors):
        return 2
    if result.errors:
        return 3
    return 1 if policy_violations(result, policy) else 0
