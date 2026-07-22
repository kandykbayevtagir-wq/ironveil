"""Internal helpers shared by report formats."""

from __future__ import annotations

import hashlib
import math
import unicodedata
from collections.abc import Mapping
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from ironveil.models import Finding, ScanError, ScanResult, finding_sort_key
from ironveil.rules.secrets import redact_secrets

SCHEMA_VERSION = "1.0"
TOOL_NAME = "IronVeil"


def ordered_findings(result: ScanResult, *, include_suppressed: bool = True) -> list[Finding]:
    """Return findings in a stable order independent of scanner scheduling."""

    findings = result.findings if include_suppressed else result.visible_findings()
    return sorted(
        findings,
        key=lambda finding: (
            *finding_sort_key(finding),
            finding.fingerprint,
            finding.source,
            finding.commit or "",
            finding.message,
            finding.evidence,
        ),
    )


def ordered_errors(result: ScanResult) -> list[ScanError]:
    return sorted(
        result.errors,
        key=lambda error: (error.path.casefold(), error.message, not error.fatal),
    )


def ordered_warnings(result: ScanResult) -> list[str]:
    return sorted((str(warning) for warning in result.warnings), key=str.casefold)


def stable_fingerprint(finding: Finding) -> str:
    """Use the scanner fingerprint, deriving a safe fallback for malformed input."""

    supplied = finding.fingerprint.strip()
    if supplied:
        return supplied
    material = "\0".join(
        (
            finding.rule_id,
            finding.path.replace("\\", "/"),
            str(finding.line),
            str(finding.column),
            finding.message,
        )
    )
    return hashlib.sha256(material.encode("utf-8", errors="surrogatepass")).hexdigest()


def terminal_safe(value: object) -> str:
    """Make repository-controlled text inert when displayed in a terminal."""

    text = report_safe_text(value)
    output: list[str] = []
    for character in text:
        category = unicodedata.category(character)
        if category in {"Cc", "Cf", "Cs"}:
            codepoint = ord(character)
            if codepoint <= 0xFF:
                output.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                output.append(f"\\u{codepoint:04x}")
            else:
                output.append(f"\\U{codepoint:08x}")
        else:
            output.append(character)
    return "".join(output)


def report_safe_text(value: object, path: str = "") -> str:
    """Redact credentials and make malformed filesystem surrogates portable."""

    redacted = redact_secrets(str(value), path)
    output: list[str] = []
    for character in redacted:
        codepoint = ord(character)
        if 0xDC80 <= codepoint <= 0xDCFF:
            output.append(f"\\x{codepoint - 0xDC00:02x}")
        elif 0xD800 <= codepoint <= 0xDFFF:
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)
    return "".join(output)


def report_safe_evidence(finding: Finding) -> str:
    """Apply reporter-layer redaction even when a finding bypassed the scanner."""

    return report_safe_text(finding.evidence, finding.path)[:240]


def json_safe(value: Any) -> Any:
    """Convert model metadata to deterministic JSON-compatible values."""

    if value is None or isinstance(value, (int, bool)):
        return value
    if isinstance(value, str):
        return report_safe_text(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Enum):
        return json_safe(value.value)
    if isinstance(value, Path):
        return report_safe_text(value, str(value))
    if isinstance(value, Mapping):
        return {
            report_safe_text(key): json_safe(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (set, frozenset)):
        converted = [json_safe(item) for item in value]
        return sorted(converted, key=lambda item: repr(item))
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return report_safe_text(value)


def scan_reference_date(result: ScanResult) -> date:
    """Return the scan date for deterministic suppression-expiry presentation."""

    parsed = parse_datetime(result.started_at)
    return parsed.date() if parsed is not None else date.today()


def parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def sarif_timestamp(value: str) -> str | None:
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def suppression_expiry_status(finding: Finding, *, reference_date: date) -> tuple[str, str]:
    """Return a machine status and user-facing label for a suppression."""

    if not finding.suppressed:
        return "none", "Not suppressed"
    if not finding.suppression_expires:
        return "active", "Active (no expiry)"
    try:
        expires = date.fromisoformat(finding.suppression_expires)
    except ValueError:
        return "invalid", f"Invalid expiry: {finding.suppression_expires}"
    if expires < reference_date:
        return "expired", f"Expired {expires.isoformat()}"
    return "active", f"Active until {expires.isoformat()}"


def display_path(path: str) -> str:
    return report_safe_text(path.replace("\\", "/"), path) or "."
