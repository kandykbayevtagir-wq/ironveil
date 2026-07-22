from __future__ import annotations

import hashlib
import json
import os
from datetime import date, timedelta
from pathlib import Path

import ironveil.policy as policy_module
from ironveil.config import AllowlistEntry, Config, CustomRuleConfig
from ironveil.core.cache import FileCache
from ironveil.core.fingerprint import fingerprint
from ironveil.core.scanner import Scanner
from ironveil.models import Category, Confidence, Finding, ScanResult, Severity
from ironveil.reporters import render_report
from ironveil.rules.secrets import detect_secret_matches


def _openai(marker: str) -> str:
    return f"sk-proj-Ab3Cd5Ef7Gh9{marker}2Lm4Np6Qr8St1Uv0WxYz"


def _github(marker: str) -> str:
    return f"github_pat_Ab3Cd5Ef7Gh9{marker}2Lm4Np6Qr8St1Uv0WxYzAb3Cd5Ef7Gh9"


def _scanner(*, use_cache: bool = False) -> Scanner:
    config = Config()
    config.scan.use_cache = use_cache
    return Scanner(config)


def test_every_secret_on_shared_evidence_line_is_redacted() -> None:
    first = _openai("A")
    second = _github("B")
    text = f'api_key = "{first}"; access_token = "{second}"'

    direct = detect_secret_matches(text, "settings.py")
    scanned = _scanner().scan_text("settings.py", text)

    assert direct
    assert scanned.findings
    for evidence in [*(match.evidence for match in direct), *(item.evidence for item in scanned.findings)]:
        assert first not in evidence
        assert second not in evidence


def test_iac_evidence_is_sanitized_against_adjacent_secret() -> None:
    secret = _openai("C")
    output = _scanner().scan_text(
        "main.tf",
        f'storage_encrypted = false # api_token = "{secret}"\n',
    )

    terraform = next(item for item in output.findings if item.rule_id == "IV-TF-003")
    assert secret not in terraform.evidence
    assert "<redacted:" in terraform.evidence


def test_reporters_redact_evidence_from_untrusted_finding() -> None:
    first = _openai("D")
    second = _github("E")
    finding = Finding(
        rule_id="CUSTOM-001",
        rule_name="Untrusted detector",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        path="settings.py",
        line=1,
        column=1,
        message="Synthetic finding",
        remediation="Remove it",
        fingerprint="iv1:synthetic",
        evidence=f'api_key = "{first}"; access_token = "{second}"',
    )
    result = ScanResult(root=Path("."), command="scan", findings=[finding])

    for format_name in ("text", "json", "html", "junit", "sarif"):
        rendered = render_report(result, format_name)
        assert first not in rendered
        assert second not in rendered


def test_cache_redacts_evidence_from_untrusted_finding(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    path = root / "settings.py"
    root.mkdir()
    path.write_text("answer = 42\n", encoding="utf-8")
    first = _openai("M")
    second = _github("N")
    finding = Finding(
        rule_id="CUSTOM-001",
        rule_name=f"Untrusted detector {first}",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        path=f"settings-{first}.py",
        line=1,
        column=1,
        message=f"Synthetic finding {second}",
        remediation=f"Remove {first}",
        fingerprint="iv1:synthetic",
        evidence=f'api_key = "{first}"; access_token = "{second}"',
        references=(f"https://invalid.example/{second}",),
        source=f"memory:{first}",
        commit=second,
        metadata={first: {"nested": second}},
    )
    cache = FileCache(tmp_path / "cache")

    cache.put(
        root,
        path,
        "config-digest",
        hashlib.sha256(path.read_bytes()).hexdigest(),
        [finding.to_dict()],
    )

    serialized = next((tmp_path / "cache").glob("*.json")).read_text(encoding="utf-8")
    assert first not in serialized
    assert second not in serialized
    assert "<redacted:" in serialized
    assert "path" not in json.loads(serialized)


def test_custom_secret_is_removed_from_all_public_fields_and_cache(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    cache = tmp_path / "cache"
    root.mkdir()
    value = "internal_" + "Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St1Uv0Wx"
    (root / "custom.conf").write_text(value, encoding="utf-8")
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))
    config = Config(
        rules=[
            CustomRuleConfig(
                id="CUSTOM-SEC-PUBLIC",
                name=f"Internal detector {value}",
                category=Category.SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                regex=r"internal_[A-Za-z0-9]{32}",
                message=f"Found {value}",
                remediation=f"Rotate {value}",
            )
        ]
    )

    result = Scanner(config).scan(root)
    finding = next(item for item in result.findings if item.rule_id == "CUSTOM-SEC-PUBLIC")

    assert value not in finding.rule_name
    assert value not in finding.message
    assert value not in finding.remediation
    for format_name in ("text", "json", "html", "junit", "sarif"):
        assert value not in render_report(result, format_name)
    assert value not in next(cache.glob("*.json")).read_text(encoding="utf-8")


def test_custom_positional_groups_cannot_expose_credential_in_report_or_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "repo"
    cache = tmp_path / "cache"
    root.mkdir()
    credential = "Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St1Uv0Wx"
    token = f"internal_foo_{credential}"
    (root / "settings.conf").write_text(f"token={token}\n", encoding="utf-8")
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))
    config = Config(
        rules=[
            CustomRuleConfig(
                id="CUSTOM-SEC-001",
                name="Internal credential",
                category=Category.SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                regex=r"internal_(foo)_([A-Za-z0-9]{32})",
                message="Internal credential found",
                remediation="Rotate it",
            )
        ]
    )
    result = Scanner(config).scan(root)

    custom = next(item for item in result.findings if item.rule_id == "CUSTOM-SEC-001")
    assert token not in custom.evidence
    assert credential not in custom.evidence
    assert token not in render_report(result, "json")
    assert credential not in render_report(result, "json")
    cached = next(cache.glob("*.json")).read_text(encoding="utf-8")
    assert token not in cached
    assert credential not in cached


def test_custom_secrets_redact_cross_detector_docker_evidence_reports_and_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "repo"
    cache = tmp_path / "cache"
    root.mkdir()
    named_secret = "vault-Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St1Uv0Wx"
    positional_value = "Zy9Xw7Vu5Ts3Rq1Po8Nm6Lk4Ji2Hg0Fe"
    positional_secret = f"positional_vault_{positional_value}"
    (root / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN apt-get install curl && \\\n"
        f'    echo "named_{named_secret}"\n'
        f'RUN apt-get install git && echo "{positional_secret}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))
    config = Config(
        rules=[
            CustomRuleConfig(
                id="CUSTOM-SEC-NAMED",
                name="Named internal credential",
                category=Category.SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                regex=r"named_(?P<secret>vault-[A-Za-z0-9]{32})",
                message="Named internal credential found",
                remediation="Rotate it",
            ),
            CustomRuleConfig(
                id="CUSTOM-SEC-POSITIONAL",
                name="Positional internal credential",
                category=Category.SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                regex=r"positional_(vault)_([A-Za-z0-9]{32})",
                message="Positional internal credential found",
                remediation="Rotate it",
            ),
        ]
    )

    result = Scanner(config).scan(root)

    assert {item.rule_id for item in result.findings} >= {
        "CUSTOM-SEC-NAMED",
        "CUSTOM-SEC-POSITIONAL",
        "IV-DOCKER-009",
    }
    assert next(item for item in result.findings if item.rule_id == "IV-DOCKER-002").evidence == (
        "No USER instruction"
    )
    for finding in result.findings:
        assert named_secret not in finding.evidence
        assert positional_secret not in finding.evidence
        assert positional_value not in finding.evidence
        assert "_fingerprint_digest" not in finding.metadata
    for format_name in ("text", "json", "html", "junit", "sarif"):
        rendered = render_report(result, format_name)
        assert named_secret not in rendered
        assert positional_secret not in rendered
        assert positional_value not in rendered
    cached = "\n".join(path.read_text(encoding="utf-8") for path in cache.glob("*.json"))
    assert named_secret not in cached
    assert positional_secret not in cached
    assert positional_value not in cached
    assert "_fingerprint_digest" not in cached


def test_fingerprint_changes_when_only_underlying_secret_changes() -> None:
    first = _scanner().scan_text("settings.py", f'api_key = "{_openai("F")}"')
    second = _scanner().scan_text("settings.py", f'api_key = "{_openai("G")}"')

    first_fingerprint = next(item.fingerprint for item in first.findings if item.rule_id == "IV-SEC-008")
    second_fingerprint = next(item.fingerprint for item in second.findings if item.rule_id == "IV-SEC-008")
    assert first_fingerprint != second_fingerprint
    assert _openai("F") not in first_fingerprint
    assert _openai("G") not in second_fingerprint


def test_private_key_fingerprint_uses_bounded_full_key_material() -> None:
    first_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-FIRST-BODY-Ab3Cd5Ef7Gh9\n-----END RSA PRIVATE KEY-----"
    )
    second_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-SECOND-BODY-Zy9Xw7Vu5Ts3\n-----END RSA PRIVATE KEY-----"
    )

    first = _scanner().scan_text("keys.pem", first_key)
    second = _scanner().scan_text("keys.pem", second_key)
    combined = _scanner().scan_text("keys.pem", f"{first_key}\n{second_key}\n")

    first_fingerprint = next(item.fingerprint for item in first.findings if item.rule_id == "IV-SEC-021")
    second_fingerprint = next(item.fingerprint for item in second.findings if item.rule_id == "IV-SEC-021")
    combined_keys = [item for item in combined.findings if item.rule_id == "IV-SEC-021"]
    assert first_fingerprint != second_fingerprint
    assert len(combined_keys) == 2


def test_fingerprint_preserves_case_sensitive_git_path_identity() -> None:
    upper = fingerprint("IV-SEC-008", "src/Foo.py", "same-secret", "same context")
    lower = fingerprint("IV-SEC-008", "src/foo.py", "same-secret", "same context")

    assert upper != lower


def test_cache_rejects_same_metadata_with_changed_content(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    cache = tmp_path / "cache"
    root.mkdir()
    path = root / "settings.py"
    path.write_text(f'api_key = "{_openai("H")}"\n', encoding="utf-8")
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))
    scanner = _scanner(use_cache=True)

    first = scanner.scan(root)
    original = path.stat()
    path.write_text(f'api_key = "{_openai("I")}"\n', encoding="utf-8")
    os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
    second = scanner.scan(root)

    assert first.stats.cache_hits == 0
    assert second.stats.cache_hits == 0
    assert {item.fingerprint for item in first.findings} != {item.fingerprint for item in second.findings}


def test_cache_miss_does_not_hash_source_file(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    path = root / "settings.py"
    root.mkdir()
    path.write_text("answer = 42\n", encoding="utf-8")
    cache = FileCache(tmp_path / "cache")

    def unexpected_hash(_path: Path):
        raise AssertionError("cache miss must not hash source content")

    monkeypatch.setattr("ironveil.core.cache._content_snapshot", unexpected_hash)

    assert cache.get(root, path, "config-digest") is None


def test_scanner_bypasses_cache_for_oversized_file(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "large.txt").write_bytes(b"a" * 512)
    config = Config()
    config.scan.max_size_mb = 0.0001
    scanner = Scanner(config)

    def unexpected_get(*_args, **_kwargs):
        raise AssertionError("oversized files must bypass cache validation")

    monkeypatch.setattr(scanner.cache, "get", unexpected_get)

    result = scanner.scan(root)

    assert not result.errors
    assert result.stats.files_skipped >= 1


def test_cache_never_restores_policy_state(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    cache = tmp_path / "cache"
    root.mkdir()
    (root / "settings.py").write_text(
        f'api_key = "{_openai("J")}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))
    scanner = _scanner(use_cache=True)

    first = scanner.scan(root)
    cache_path = next(cache.glob("*.json"))
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    assert all(not item["suppressed"] and not item["baseline"] for item in payload["findings"])
    for item in payload["findings"]:
        item.update(
            baseline=True,
            suppressed=True,
            suppression_reason="stale cached decision",
            suppression_expires="2999-01-01",
        )
    cache_path.write_text(json.dumps(payload), encoding="utf-8")

    second = scanner.scan(root)

    assert first.findings
    assert second.stats.cache_hits == 1
    assert all(not item.baseline and not item.suppressed for item in second.findings)
    assert all(item.suppression_reason is None for item in second.findings)
    assert all(item.suppression_expires is None for item in second.findings)


def test_cache_re_evaluates_suppression_expiry(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    cache = tmp_path / "cache"
    root.mkdir()
    (root / "settings.py").write_text(
        f'api_key = "{_openai("K")}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))
    expires = date.today() + timedelta(days=1)
    config = Config(
        allowlist=[
            AllowlistEntry(
                rule="IV-SEC-008",
                path="settings.py",
                reason="temporary synthetic exception",
                expires=expires.isoformat(),
            )
        ]
    )
    scanner = Scanner(config)

    first = scanner.scan(root)

    class FutureDate(date):
        @classmethod
        def today(cls) -> date:
            return expires + timedelta(days=1)

    monkeypatch.setattr(policy_module, "date", FutureDate)
    second = scanner.scan(root)

    assert next(item for item in first.findings if item.rule_id == "IV-SEC-008").suppressed
    assert second.stats.cache_hits == 1
    assert not next(item for item in second.findings if item.rule_id == "IV-SEC-008").suppressed
    assert any("Expired allowlist entry" in warning for warning in second.warnings)


def test_cache_is_bound_to_config_digest(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    cache = tmp_path / "cache"
    root.mkdir()
    (root / "settings.py").write_text(
        f'api_key = "{_openai("L")}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))

    first = _scanner(use_cache=True).scan(root)
    changed = Config(
        allowlist=[
            AllowlistEntry(
                rule="IV-SEC-008",
                path="settings.py",
                reason="new config context",
            )
        ]
    )
    second = Scanner(changed).scan(root)

    assert first.stats.cache_hits == 0
    assert second.stats.cache_hits == 0
    assert next(item for item in second.findings if item.rule_id == "IV-SEC-008").suppressed


def test_binary_metadata_suppression_and_skip_stats_are_stable_without_cache(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "repo"
    cache = tmp_path / "cache"
    root.mkdir()
    (root / ".env").write_bytes(b"synthetic\0binary")
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))
    config = Config(
        allowlist=[
            AllowlistEntry(
                rule="IV-FILE-001",
                path=".env",
                reason="Synthetic binary fixture",
            )
        ]
    )
    scanner = Scanner(config)

    first = scanner.scan(root)
    second = scanner.scan(root)

    assert next(item for item in first.findings if item.rule_id == "IV-FILE-001").suppressed
    assert next(item for item in second.findings if item.rule_id == "IV-FILE-001").suppressed
    assert first.stats.files_skipped == second.stats.files_skipped == 1
    assert first.stats.files_scanned == second.stats.files_scanned == 0
    assert first.stats.cache_hits == second.stats.cache_hits == 0
