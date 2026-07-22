"""JUnit XML reports for CI systems."""

from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import cast

from ironveil import __version__
from ironveil.models import Finding, ScanResult

from ._common import (
    TOOL_NAME,
    display_path,
    ordered_errors,
    ordered_findings,
    ordered_warnings,
    report_safe_evidence,
    report_safe_text,
    sarif_timestamp,
    stable_fingerprint,
)


def _xml_safe(value: object) -> str:
    output: list[str] = []
    for character in report_safe_text(value):
        codepoint = ord(character)
        if (
            codepoint in {0x09, 0x0A, 0x0D}
            or 0x20 <= codepoint <= 0xD7FF
            or 0xE000 <= codepoint <= 0xFFFD
            or 0x10000 <= codepoint <= 0x10FFFF
        ):
            output.append(character)
        else:
            output.append("\N{REPLACEMENT CHARACTER}")
    return "".join(output)


def _testcase_name(finding: Finding) -> str:
    return _xml_safe(f"{finding.rule_id}: {display_path(finding.path)}:{max(1, finding.line)}")


def _finding_details(finding: Finding) -> str:
    sections = [
        finding.message,
        f"Location: {display_path(finding.path)}:{max(1, finding.line)}:{max(1, finding.column)}",
        f"Severity: {finding.severity.value}",
        f"Confidence: {finding.confidence.value}",
        f"Fingerprint: {stable_fingerprint(finding)}",
    ]
    if finding.evidence:
        sections.append(f"Evidence: {report_safe_evidence(finding)}")
    sections.append(f"Remediation: {finding.remediation}")
    return _xml_safe("\n".join(sections))


def junit_element(result: ScanResult, *, tool_version: str = __version__) -> ET.Element:
    """Build one deterministic JUnit testsuite element."""

    findings = ordered_findings(result)
    errors = ordered_errors(result)
    failures = sum(not finding.suppressed and not finding.baseline for finding in findings)
    skipped = sum(finding.suppressed or finding.baseline for finding in findings)
    duration = result.stats.duration_seconds
    if not math.isfinite(duration) or duration < 0:
        duration = 0.0

    attributes = {
        "name": TOOL_NAME,
        "tests": str(len(findings) + len(errors)),
        "failures": str(failures),
        "errors": str(len(errors)),
        "skipped": str(skipped),
        "time": f"{duration:.6f}",
    }
    timestamp = sarif_timestamp(result.started_at)
    if timestamp:
        attributes["timestamp"] = timestamp
    suite = ET.Element("testsuite", attributes)

    properties = ET.SubElement(suite, "properties")
    for name, value in (
        ("ironveil.version", tool_version),
        ("ironveil.root", result.root),
        ("ironveil.command", result.command),
        ("ironveil.config_digest", result.config_digest),
        ("ironveil.git_branch", result.git_branch or ""),
        ("ironveil.git_commit", result.git_commit or ""),
        ("ironveil.history_scanned", str(result.history_scanned).lower()),
        (
            "ironveil.dependencies_scanned",
            str(result.dependencies_scanned).lower(),
        ),
    ):
        ET.SubElement(
            properties,
            "property",
            {"name": name, "value": _xml_safe(value)},
        )

    for finding in findings:
        testcase = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": _xml_safe(f"ironveil.{finding.category.value}"),
                "name": _testcase_name(finding),
                "file": _xml_safe(display_path(finding.path)),
                "line": str(max(1, finding.line)),
                "time": "0.000000",
            },
        )
        if finding.suppressed:
            reason = finding.suppression_reason or "Suppressed by IronVeil policy"
            expiry = (
                f"; expires {finding.suppression_expires}" if finding.suppression_expires else "; no expiry"
            )
            ET.SubElement(
                testcase,
                "skipped",
                {"message": _xml_safe(f"{reason}{expiry}")},
            )
        elif finding.baseline:
            ET.SubElement(
                testcase,
                "skipped",
                {"message": "Existing baseline finding"},
            )
        else:
            failure = ET.SubElement(
                testcase,
                "failure",
                {
                    "message": _xml_safe(finding.message),
                    "type": _xml_safe(f"ironveil.{finding.severity.value}.{finding.rule_id}"),
                },
            )
            failure.text = _finding_details(finding)

    for error in errors:
        testcase = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": "ironveil.scan",
                "name": _xml_safe(f"scan-error: {display_path(error.path)}"),
                "file": _xml_safe(display_path(error.path)),
                "time": "0.000000",
            },
        )
        error_element = ET.SubElement(
            testcase,
            "error",
            {
                "message": _xml_safe(error.message),
                "type": "ironveil.scan.fatal" if error.fatal else "ironveil.scan.nonfatal",
            },
        )
        error_element.text = _xml_safe(error.message)

    warnings = ordered_warnings(result)
    if warnings:
        system_out = ET.SubElement(suite, "system-out")
        system_out.text = _xml_safe("\n".join(f"Warning: {item}" for item in warnings))
    return suite


@dataclass(frozen=True, slots=True)
class JUnitReporter:
    """Render findings as JUnit failures and accepted findings as skips."""

    name: str = "junit"
    suffix: str = ".xml"
    media_type: str = "application/xml"

    def render(self, result: ScanResult, *, tool_version: str = __version__) -> str:
        root = junit_element(result, tool_version=tool_version)
        ET.indent(root, space="  ")
        payload = cast(
            bytes,
            ET.tostring(
                root,
                encoding="utf-8",
                xml_declaration=True,
                short_empty_elements=True,
            ),
        )
        return payload.decode("utf-8") + "\n"


def render(result: ScanResult, *, tool_version: str = __version__) -> str:
    return JUnitReporter().render(result, tool_version=tool_version)


render_junit = render

__all__ = ["JUnitReporter", "junit_element", "render", "render_junit"]
