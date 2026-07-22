"""Deterministic, terminal-safe text reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TextIO

from ironveil import __version__
from ironveil.models import ScanResult, Severity

from ._common import (
    TOOL_NAME,
    display_path,
    ordered_errors,
    ordered_findings,
    ordered_warnings,
    report_safe_evidence,
    terminal_safe,
)

_ANSI_RESET = "\x1b[0m"
_ANSI_BOLD = "\x1b[1m"
_SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.CRITICAL: "\x1b[1;31m",
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}


def _paint(value: str, prefix: str, *, enabled: bool) -> str:
    return f"{prefix}{value}{_ANSI_RESET}" if enabled else value


def _format_bytes(value: int) -> str:
    amount = float(max(0, value))
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or suffix == "TiB":
            if suffix == "B":
                return f"{int(amount)} {suffix}"
            return f"{amount:.1f} {suffix}"
        amount /= 1024
    return f"{amount:.1f} TiB"


@dataclass(frozen=True, slots=True)
class TextReporter:
    """Render a compact report suitable for terminals and CI logs."""

    name: str = "text"
    suffix: str = ".txt"
    media_type: str = "text/plain; charset=utf-8"

    def render(
        self,
        result: ScanResult,
        *,
        tool_version: str = __version__,
        color: bool = False,
        include_suppressed: bool = False,
    ) -> str:
        summary = result.summary()
        findings = ordered_findings(result, include_suppressed=include_suppressed)
        title = _paint(
            f"{TOOL_NAME} {terminal_safe(tool_version)} scan report",
            _ANSI_BOLD,
            enabled=color,
        )
        lines = [
            title,
            f"Root: {terminal_safe(result.root)}",
            f"Command: {terminal_safe(result.command)}",
        ]
        if result.started_at:
            lines.append(f"Started: {terminal_safe(result.started_at)}")
        if result.git_branch or result.git_commit:
            branch = terminal_safe(result.git_branch or "detached")
            commit = terminal_safe(result.git_commit or "unknown")
            lines.append(f"Git: {branch} @ {commit}")

        lines.extend(
            (
                "",
                (
                    "Summary: "
                    f"{summary['total']} active, {summary['new']} new, "
                    f"{summary['baseline']} baseline, "
                    f"{summary['suppressed']} suppressed"
                ),
                "Severity: "
                + ", ".join(
                    f"{severity.value}={summary['by_severity'][severity.value]}" for severity in Severity
                ),
                (
                    "Scan: "
                    f"{result.stats.files_scanned}/{result.stats.files_discovered} files, "
                    f"{_format_bytes(result.stats.bytes_scanned)}, "
                    f"{result.stats.duration_seconds:.3f}s"
                ),
            )
        )

        warnings = ordered_warnings(result)
        if warnings:
            lines.extend(("", f"Warnings ({len(warnings)}):"))
            lines.extend(f"  - {terminal_safe(warning)}" for warning in warnings)

        errors = ordered_errors(result)
        if errors:
            lines.extend(("", f"Scan errors ({len(errors)}):"))
            for error in errors:
                kind = "fatal" if error.fatal else "non-fatal"
                lines.append(
                    f"  - [{kind}] {terminal_safe(display_path(error.path))}: {terminal_safe(error.message)}"
                )

        if not findings:
            lines.extend(("", "No active findings."))
            return "\n".join(lines) + "\n"

        lines.extend(("", f"Findings ({len(findings)}):"))
        for finding in findings:
            severity = finding.severity.value.upper()
            severity = _paint(severity, _SEVERITY_COLOURS[finding.severity], enabled=color)
            state = "suppressed" if finding.suppressed else "baseline" if finding.baseline else "new"
            location = (
                f"{terminal_safe(display_path(finding.path))}:{max(1, finding.line)}:{max(1, finding.column)}"
            )
            lines.extend(
                (
                    "",
                    (
                        f"{severity} | {finding.confidence.value.upper()} confidence | "
                        f"{terminal_safe(finding.rule_id)} | {location} | {state}"
                    ),
                    f"  {terminal_safe(finding.message)}",
                )
            )
            if finding.evidence:
                lines.append(f"  Evidence: {terminal_safe(report_safe_evidence(finding))}")
            lines.append(f"  Remediation: {terminal_safe(finding.remediation)}")
            if finding.suppressed:
                reason = finding.suppression_reason or "No reason supplied"
                expiry = finding.suppression_expires or "no expiry"
                lines.append(f"  Suppression: {terminal_safe(reason)} ({terminal_safe(expiry)})")

        return "\n".join(lines) + "\n"

    def write(
        self,
        result: ScanResult,
        stream: TextIO,
        *,
        tool_version: str = __version__,
        color: bool | None = None,
        include_suppressed: bool = False,
    ) -> None:
        if color is None:
            isatty = getattr(stream, "isatty", None)
            try:
                color = bool(isatty()) if callable(isatty) else False
            except OSError:
                color = False
        stream.write(
            self.render(
                result,
                tool_version=tool_version,
                color=color,
                include_suppressed=include_suppressed,
            )
        )


def render(
    result: ScanResult,
    *,
    tool_version: str = __version__,
    color: bool = False,
    include_suppressed: bool = False,
) -> str:
    return TextReporter().render(
        result,
        tool_version=tool_version,
        color=color,
        include_suppressed=include_suppressed,
    )


render_text = render

__all__ = ["TextReporter", "render", "render_text"]
