from __future__ import annotations

import json
from pathlib import Path

import pytest

import ironveil.policy as policy_module
from ironveil.config import AllowlistEntry, PolicyConfig
from ironveil.exceptions import ConfigurationError
from ironveil.models import Category, Confidence, Finding, ScanError, ScanResult, Severity
from ironveil.policy import (
    BASELINE_SCHEMA,
    apply_suppressions,
    baseline_document,
    exit_code,
    load_baseline,
    mark_baseline,
    parse_inline_suppression,
)


def _finding() -> Finding:
    return Finding(
        rule_id="IV-SEC-001",
        rule_name="Synthetic rule",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        path="fixture.py",
        line=2,
        column=1,
        message="Synthetic finding",
        remediation="Remove it",
        fingerprint="iv1:abc",
        evidence="s…c (len=20)",
    )


def test_inline_suppression_requires_reason() -> None:
    assert parse_inline_suppression("# ironveil: allow IV-SEC-001") is None
    parsed = parse_inline_suppression(
        '# ironveil: allow IV-SEC-001 reason="synthetic fixture" expires="2099-01-01"'
    )
    assert parsed is not None
    assert parsed.reason == "synthetic fixture"


def test_allowlist_suppresses_finding() -> None:
    finding = _finding()
    warnings: list[str] = []

    apply_suppressions(
        finding,
        ["", "value"],
        [AllowlistEntry("IV-SEC-001", "fixture.py", "Synthetic fixture", "2099-01-01")],
        warnings,
    )

    assert finding.suppressed
    assert not warnings


def test_baseline_only_allows_old_findings() -> None:
    old = _finding()
    new = _finding()
    new.fingerprint = "iv1:new"
    result = ScanResult(root=Path("."), command="scan", findings=[old, new])

    mark_baseline(result, {"iv1:abc"})

    assert old.baseline
    assert not new.baseline
    assert exit_code(result, PolicyConfig()) == 1
    document = baseline_document(result)
    assert document["fingerprints"] == ["iv1:abc", "iv1:new"]


def test_expired_suppression_warns_but_does_not_hide() -> None:
    finding = _finding()
    warnings: list[str] = []

    apply_suppressions(
        finding,
        ["", "value"],
        [AllowlistEntry("*", "**", "Old exception", "2000-01-01")],
        warnings,
    )

    assert not finding.suppressed
    assert warnings and "Expired allowlist" in warnings[0]


def test_inline_suppression_and_expiry_paths() -> None:
    finding = _finding()
    warnings: list[str] = []
    apply_suppressions(
        finding,
        ['# ironveil: allow IV-SEC-001 reason="temporary" expires="2099-01-01"', "value"],
        [],
        warnings,
    )
    assert finding.suppressed

    expired = _finding()
    apply_suppressions(
        expired,
        ['# ironveil: allow IV-SEC-001 reason="old" expires="2000-01-01"', "value"],
        [],
        warnings,
    )
    assert not expired.suppressed
    assert any("Expired inline" in item for item in warnings)


def test_invalid_suppression_dates_warn_without_crashing() -> None:
    configured = _finding()
    warnings: list[str] = []
    apply_suppressions(
        configured,
        ["", "value"],
        [AllowlistEntry("*", "**", "Invalid date", "2099-13-40")],
        warnings,
    )
    assert not configured.suppressed
    assert any("Invalid allowlist expiry" in item for item in warnings)

    inline = _finding()
    apply_suppressions(
        inline,
        ['# ironveil: allow IV-SEC-001 reason="invalid" expires="2099-13-40"', "value"],
        [],
        warnings,
    )
    assert not inline.suppressed
    assert any("Invalid inline suppression expiry" in item for item in warnings)


def test_load_baseline_validation(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    valid_fingerprint = "iv1:" + "a" * 64
    path.write_text(
        json.dumps({"schema": BASELINE_SCHEMA, "fingerprints": [valid_fingerprint]}),
        encoding="utf-8",
    )
    assert load_baseline(path) == {valid_fingerprint}
    assert load_baseline(tmp_path / "missing.json") == set()

    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="cannot read"):
        load_baseline(path)
    path.write_text(json.dumps({"schema": "old", "fingerprints": []}), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="unsupported"):
        load_baseline(path)
    path.write_text(json.dumps({"schema": BASELINE_SCHEMA, "fingerprints": "wrong"}), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="expected an array"):
        load_baseline(path)
    path.write_text(
        json.dumps({"schema": BASELINE_SCHEMA, "fingerprints": ["iv1:not-a-digest"]}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="invalid fingerprint"):
        load_baseline(path)


def test_load_baseline_refuses_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps({"schema": BASELINE_SCHEMA, "fingerprints": []}),
        encoding="utf-8",
    )
    linked = tmp_path / "linked.json"
    linked.symlink_to(outside)

    with pytest.raises(ConfigurationError, match="regular file"):
        load_baseline(linked)


def test_load_baseline_bounds_file_size(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(policy_module, "MAX_BASELINE_BYTES", 64)
    path = tmp_path / "baseline.json"
    path.write_bytes(b"x" * 65)

    with pytest.raises(ConfigurationError, match="safety limit"):
        load_baseline(path)


def test_load_baseline_bounds_fingerprint_count(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(policy_module, "MAX_BASELINE_FINGERPRINTS", 1)
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps(
            {
                "schema": BASELINE_SCHEMA,
                "fingerprints": ["iv1:" + "a" * 64, "iv1:" + "b" * 64],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="exceeds the limit"):
        load_baseline(path)


def test_policy_no_fail_and_partial_result_exit_codes() -> None:
    result = ScanResult(root=Path("."), command="scan", findings=[_finding()])
    policy = PolicyConfig(no_fail=True)
    assert exit_code(result, policy) == 0
    result.errors.append(ScanError("file", "interrupted"))
    assert exit_code(result, policy) == 3
    result.errors.append(ScanError("root", "unavailable", fatal=True))
    assert exit_code(result, policy) == 2
