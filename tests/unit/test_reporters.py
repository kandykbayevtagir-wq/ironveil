from __future__ import annotations

import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from jsonschema import validate  # type: ignore[import-untyped]

from ironveil.exceptions import ReportError
from ironveil.models import (
    Category,
    Confidence,
    Finding,
    ScanError,
    ScanResult,
    ScanStats,
    Severity,
)
from ironveil.reporters import (
    REPORT_SCHEMA_V1,
    ReporterRegistry,
    available_reporters,
    calculate_security_score,
    render_report,
    write_report,
)
from ironveil.reporters.html import CONTENT_SECURITY_POLICY


@pytest.fixture
def scan_result() -> ScanResult:
    return ScanResult(
        root=Path("/workspace/example"),
        command="scan .",
        findings=[
            Finding(
                rule_id="IV-IAC-001",
                rule_name="Public resource",
                category=Category.IAC,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                path="infra/main.tf",
                line=8,
                column=1,
                message="Resource is public",
                remediation="Restrict public access",
                fingerprint="baseline-fingerprint",
                evidence="public = true",
                baseline=True,
                metadata={"description": "Detects public infrastructure"},
            ),
            Finding(
                rule_id="IV-FILE-001",
                rule_name="Sensitive <script>alert(1)</script> file",
                category=Category.SENSITIVE_FILE,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                path="fixtures/<sample>.env",
                line=1,
                column=1,
                message="Synthetic <img src=x onerror=alert(1)> finding",
                remediation="Remove the synthetic file",
                fingerprint="suppressed-fingerprint",
                evidence="TOKEN=mask…mask",
                references=("javascript:alert(1)",),
                suppressed=True,
                suppression_reason="Synthetic <b>fixture</b>",
                suppression_expires="2025-01-01",
            ),
            Finding(
                rule_id="IV-SEC-001",
                rule_name="Masked credential",
                category=Category.SECRET,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                path="src/settings.py",
                line=3,
                column=4,
                message="Credential-like value",
                remediation="Rotate the credential and use a secret manager",
                fingerprint="new-fingerprint",
                evidence="tok…3f9",
                references=("https://example.com/remediation?a=1&b=2",),
                metadata={"tags": ["credential"], "description": "Credential detector"},
            ),
        ],
        errors=[ScanError(path="unreadable/<file>", message="Permission denied")],
        warnings=["Synthetic warning <review>"],
        stats=ScanStats(
            files_discovered=12,
            files_scanned=10,
            files_skipped=2,
            cache_hits=1,
            bytes_scanned=2048,
            duration_seconds=0.5,
        ),
        config_digest="deadbeef",
        started_at="2026-07-22T10:30:00Z",
        git_branch="main",
        git_commit="0123456789abcdef",
        history_scanned=True,
        dependencies_scanned=False,
    )


def test_registry_exposes_all_cli_formats(scan_result: ScanResult) -> None:
    assert available_reporters() == ("html", "json", "junit", "sarif", "text")
    for format_name in available_reporters():
        assert render_report(scan_result, format_name)
    with pytest.raises(ReportError, match="Unknown report format"):
        render_report(scan_result, "pdf")


def test_text_is_terminal_safe_deterministic_and_sorted(scan_result: ScanResult) -> None:
    scan_result.findings[0].path = "infra/\x1b[31mmain.tf"
    first = render_report(scan_result, "text")
    shuffled = replace(scan_result, findings=list(reversed(scan_result.findings)))
    second = render_report(shuffled, "text")

    assert first == second
    assert "\x1b" not in first
    assert "\\x1b[31m" in first
    assert first.index("IV-SEC-001") < first.index("IV-IAC-001")
    assert "Rotate the credential" in first


def test_json_matches_v1_schema_and_is_deterministic(scan_result: ScanResult) -> None:
    rendered = render_report(scan_result, "json")
    document = json.loads(rendered)
    validate(document, REPORT_SCHEMA_V1)

    shuffled = replace(scan_result, findings=list(reversed(scan_result.findings)))
    assert rendered == render_report(shuffled, "json")
    assert document["schema_version"] == "1.0"
    assert document["tool"]["name"] == "IronVeil"
    assert document["metadata"]["config_digest"] == "deadbeef"
    assert document["findings"][0]["evidence"] == "tok…3f9"
    assert document["summary"]["suppressed"] == 1


def test_sarif_has_github_metadata_locations_and_fingerprints(
    scan_result: ScanResult,
) -> None:
    document = json.loads(render_report(scan_result, "sarif"))
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    results = {item["ruleId"]: item for item in run["results"]}

    assert rules["IV-SEC-001"]["properties"]["severity"] == "critical"
    assert rules["IV-SEC-001"]["properties"]["security-severity"] == "9.5"
    assert "credential" in rules["IV-SEC-001"]["properties"]["tags"]
    secret = results["IV-SEC-001"]
    assert secret["level"] == "error"
    assert secret["locations"][0]["physicalLocation"]["region"] == {
        "startColumn": 4,
        "startLine": 3,
    }
    assert secret["partialFingerprints"]["primaryLocationLineHash"] == "new-fingerprint"
    assert results["IV-IAC-001"]["baselineState"] == "unchanged"
    assert "IV-FILE-001" not in results

    archival = json.loads(render_report(scan_result, "sarif", include_suppressed=True))
    archival_results = {item["ruleId"]: item for item in archival["runs"][0]["results"]}
    assert archival_results["IV-FILE-001"]["suppressions"][0]["status"] == "accepted"


def test_html_is_offline_escaped_filterable_and_explains_score(
    scan_result: ScanResult,
) -> None:
    rendered = render_report(scan_result, "html")
    assert "<script>alert(1)</script>" not in rendered
    assert "<img src=x onerror=alert(1)>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "Synthetic &lt;b&gt;fixture&lt;/b&gt;" in rendered
    assert "Expired 2025-01-01" in rendered
    assert 'id="severity-filter"' in rendered
    assert 'id="confidence-filter"' in rendered
    assert 'id="category-filter"' in rendered
    assert 'id="rule-filter"' in rendered
    assert 'id="path-search"' in rendered
    assert "prefers-color-scheme: dark" in rendered
    assert "No report assets require an internet connection" in rendered
    assert "default-src &#x27;none&#x27;" in rendered
    assert "<link" not in rendered
    assert '<script src="' not in rendered
    assert calculate_security_score(scan_result) == 65
    assert "25 x 1 critical" in rendered


def test_html_csp_hashes_match_embedded_assets(scan_result: ScanResult) -> None:
    rendered = render_report(scan_result, "html")
    style = re.search(r"<style>(.*?)</style>", rendered, flags=re.DOTALL)
    script = re.search(r"<script>(.*?)</script>", rendered, flags=re.DOTALL)
    assert style is not None
    assert script is not None

    import base64
    import hashlib

    style_hash = base64.b64encode(hashlib.sha256(style.group(1).encode()).digest()).decode()
    script_hash = base64.b64encode(hashlib.sha256(script.group(1).encode()).digest()).decode()
    assert f"style-src 'sha256-{style_hash}'" in CONTENT_SECURITY_POLICY
    assert f"script-src 'sha256-{script_hash}'" in CONTENT_SECURITY_POLICY


def test_junit_represents_new_findings_errors_and_accepted_findings(
    scan_result: ScanResult,
) -> None:
    suite = ET.fromstring(render_report(scan_result, "junit"))  # noqa: S314
    assert suite.attrib == {
        "name": "IronVeil",
        "tests": "4",
        "failures": "1",
        "errors": "1",
        "skipped": "2",
        "time": "0.500000",
        "timestamp": "2026-07-22T10:30:00Z",
    }
    assert len(suite.findall("testcase/failure")) == 1
    assert len(suite.findall("testcase/skipped")) == 2
    assert len(suite.findall("testcase/error")) == 1


def test_write_report_is_atomic_private_and_utf8(scan_result: ScanResult, tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    written = write_report(scan_result, "json", destination)
    assert written == destination
    assert json.loads(destination.read_text(encoding="utf-8"))["schema_version"] == "1.0"
    assert not list(tmp_path.glob(".*.tmp"))
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_isolated_registry_rejects_duplicates(scan_result: ScanResult) -> None:
    @dataclass(frozen=True)
    class ExampleReporter:
        name: str = "example"
        suffix: str = ".example"
        media_type: str = "text/plain"

        def render(self, result: ScanResult, *, tool_version: str = "test") -> str:
            return f"{tool_version}:{result.command}"

    registry = ReporterRegistry((ExampleReporter(),))
    assert registry.render(scan_result, "EXAMPLE", tool_version="1") == "1:scan ."
    with pytest.raises(ReportError, match="already registered"):
        registry.register(ExampleReporter())


def test_every_reporter_redacts_provider_tokens_embedded_in_all_public_text(
    scan_result: ScanResult,
) -> None:
    secret = "sk-proj-" + "Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St1Uv0Wx"
    finding = scan_result.findings[-1]
    finding.path = f"bad-{secret}.py"
    finding.message = f"Cannot inspect bad-{secret}.py"
    finding.remediation = f"Remove bad-{secret}.py"
    scan_result.root = Path(f"/tmp/repo-{secret}.dir")
    scan_result.errors = [ScanError(f"bad-{secret}.py", f"Cannot inspect bad-{secret}.py")]
    scan_result.warnings = [f"Warning in bad-{secret}.py"]

    for format_name in available_reporters():
        rendered = render_report(scan_result, format_name)
        assert secret not in rendered
        assert rendered.encode("utf-8")
