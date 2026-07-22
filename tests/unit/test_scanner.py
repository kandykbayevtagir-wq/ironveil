from __future__ import annotations

from pathlib import Path
from time import perf_counter
from urllib.parse import quote

import pytest

from ironveil.config import Config, CustomRuleConfig
from ironveil.core.git import GitLine
from ironveil.core.scanner import Scanner
from ironveil.exceptions import ConfigurationError
from ironveil.models import Category, Confidence, Severity
from ironveil.reporters import available_reporters, render_report


def _config() -> Config:
    config = Config()
    config.scan.use_cache = False
    config.scan.workers = 2
    return config


def test_scanner_masks_secret_and_is_deterministic(tmp_path: Path) -> None:
    secret = "sk-" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tV0xY1z"
    (tmp_path / "settings.py").write_text(f'OPENAI_API_KEY = "{secret}"\n', encoding="utf-8")

    first = Scanner(_config()).scan(tmp_path)
    second = Scanner(_config()).scan(tmp_path)

    matches = [item for item in first.findings if item.rule_id == "IV-SEC-008"]
    assert len(matches) == 1
    assert secret not in matches[0].evidence
    assert matches[0].evidence == next(
        item.evidence for item in second.findings if item.rule_id == "IV-SEC-008"
    )
    assert [item.fingerprint for item in first.findings] == [item.fingerprint for item in second.findings]


def test_inline_suppression_is_applied(tmp_path: Path) -> None:
    secret = "sk-" + "zY8xW6vU4tS2rQ0pN9mL7kJ5hG3fD1b"
    (tmp_path / "settings.py").write_text(
        '# ironveil: allow IV-SEC-008 reason="synthetic scanner test" expires="2099-01-01"\n'
        f'OPENAI_API_KEY = "{secret}"\n',
        encoding="utf-8",
    )

    result = Scanner(_config()).scan(tmp_path)

    finding = next(item for item in result.findings if item.rule_id == "IV-SEC-008")
    assert finding.suppressed
    assert finding.suppression_reason == "synthetic scanner test"


def test_large_and_binary_files_are_bounded(tmp_path: Path) -> None:
    config = _config()
    config.scan.max_size_mb = 0.0001
    (tmp_path / "large.txt").write_bytes(b"a" * 512)
    (tmp_path / "binary.bin").write_bytes(b"abc\0def")

    result = Scanner(config).scan(tmp_path)

    assert any(item.rule_id == "IV-FILE-010" for item in result.findings)
    assert result.stats.files_skipped >= 2
    assert result.stats.bytes_scanned == 0


def test_custom_declarative_rule_is_masked(tmp_path: Path) -> None:
    config = _config()
    config.rules.append(
        CustomRuleConfig(
            id="CUSTOM-001",
            name="Internal token",
            category=Category.SECRET,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            regex=r"internal_[A-Za-z0-9]{20}",
            message="Internal token found",
            remediation="Move it to the company secret manager",
        )
    )
    value = "internal_" + "A1b2C3d4E5f6G7h8I9j0"
    (tmp_path / "custom.conf").write_text(value, encoding="utf-8")

    result = Scanner(config).scan(tmp_path)

    finding = next(item for item in result.findings if item.rule_id == "CUSTOM-001")
    assert value not in finding.evidence


def test_cache_reuses_secret_safe_findings(tmp_path: Path, monkeypatch) -> None:
    cache_dir = tmp_path / "cache"
    root = tmp_path / "repo"
    root.mkdir()
    (root / "safe.py").write_text("answer = 42\n", encoding="utf-8")
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache_dir))
    config = Config()

    first = Scanner(config).scan(root)
    second = Scanner(config).scan(root)

    assert first.stats.cache_hits == 0
    assert second.stats.cache_hits == 1


def test_malformed_utf8_is_scanned_without_crashing(tmp_path: Path) -> None:
    (tmp_path / "broken.txt").write_bytes(b"prefix\xffsuffix")

    result = Scanner(_config()).scan(tmp_path)

    assert not result.errors
    assert result.stats.files_scanned == 1


def test_windows_style_virtual_path_is_normalized() -> None:
    result = Scanner(_config()).scan_text(r"folder\settings.py", "answer = 42")

    assert all(item.path == "folder/settings.py" for item in result.findings)


def test_missing_root_is_partial_result(tmp_path: Path) -> None:
    result = Scanner(_config()).scan(tmp_path / "missing")

    assert result.errors[0].fatal
    assert result.stats.files_scanned == 0


def test_custom_rule_cannot_replace_builtin() -> None:
    config = _config()
    config.rules.append(
        CustomRuleConfig(
            id="IV-SEC-001",
            name="Collision",
            category=Category.SECRET,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            regex="collision",
            message="collision",
            remediation="rename the rule",
        )
    )

    with pytest.raises(ConfigurationError, match="duplicates"):
        Scanner(config)


def test_worker_error_becomes_scan_error(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "file.py").write_text("safe", encoding="utf-8")
    scanner = Scanner(_config())

    def fail(*args, **kwargs):
        raise OSError("interrupted")

    monkeypatch.setattr(scanner, "_scan_file", fail)
    result = scanner.scan(tmp_path)

    assert result.errors and "interrupted" in result.errors[0].message


def test_git_line_mapping_preserves_original_location_and_commit() -> None:
    value = "sk-" + "bC5dE7fG9hJ1kL3mN4pQ6rS8tV0xY2z"
    lines = [
        GitLine(
            path="settings.py",
            line=41,
            text=f'OPENAI_API_KEY = "{value}"',
            source="diff:main...HEAD",
            commit="a" * 40,
        )
    ]

    result = Scanner(_config()).scan_git_lines(Path("."), lines, command="diff main...HEAD")

    finding = next(item for item in result.findings if item.rule_id == "IV-SEC-008")
    assert finding.line == 41
    assert finding.source == "diff:main...HEAD"
    assert finding.commit == "a" * 40


def test_git_metadata_only_path_still_detects_sensitive_file() -> None:
    lines = [GitLine(".env", 1, "", "staged", metadata_only=True)]

    result = Scanner(_config()).scan_git_lines(Path("."), lines, command="staged")

    assert any(item.rule_id == "IV-FILE-001" and item.path == ".env" for item in result.findings)


def test_git_fragments_skip_absence_rules_but_keep_high_signal_iac() -> None:
    lines = [
        GitLine("Dockerfile", 20, "RUN echo safe", "diff:main...HEAD"),
        GitLine("k8s/deployment.yaml", 35, "    privileged: true", "diff:main...HEAD"),
    ]

    result = Scanner(_config()).scan_git_lines(Path("."), lines, command="diff main...HEAD")
    ids = {item.rule_id for item in result.findings}

    assert "IV-DOCKER-002" not in ids
    assert "IV-DOCKER-008" not in ids
    assert "IV-K8S-001" in ids


@pytest.mark.parametrize(
    "path,text,rule_id",
    [
        ("Dockerfile", "FROM python:latest\n", "IV-DOCKER-003"),
        ("Dockerfile.prod", "FROM python:latest\n", "IV-DOCKER-003"),
        (
            ".github/workflows/ci.yml",
            "name: ci\non: push\npermissions: write-all\njobs: {}\n",
            "IV-GHA-001",
        ),
        ("main.tf", 'resource "x" "y" { storage_encrypted = false }\n', "IV-TF-003"),
        ("main.tf.json", '{"storage_encrypted": false}\n', "IV-TF-003"),
        (
            "pod.yaml",
            "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n",
            "IV-K8S-002",
        ),
    ],
)
def test_scanner_routes_iac_only_by_file_type(path: str, text: str, rule_id: str) -> None:
    output = Scanner(_config()).scan_text(path, text)

    assert any(item.rule_id == rule_id for item in output.findings)


def test_scanning_single_file_root(tmp_path: Path) -> None:
    path = tmp_path / "single.py"
    value = "sk-" + "D7fG9hJ1kL3mN5pQ6rS8tV0xY2zA4bC5"
    path.write_text(f'OPENAI_API_KEY = "{value}"\n', encoding="utf-8")

    result = Scanner(_config()).scan(path)

    assert result.stats.files_discovered == 1
    assert result.stats.files_scanned == 1
    assert result.findings
    assert {finding.path for finding in result.findings} == {"single.py"}


def test_unicode_path_scans_and_renders_as_valid_utf8(tmp_path: Path) -> None:
    relative = "данные/設定.py"
    path = tmp_path / relative
    path.parent.mkdir()
    value = "sk-" + "H9jK1mN3pQ5rS7tV0xY2zA4bC6dE8fG0"
    path.write_text(
        f'# Проверка Unicode: 日本語 🔐\nOPENAI_API_KEY = "{value}"\n',
        encoding="utf-8",
    )

    result = Scanner(_config()).scan(tmp_path)

    assert not result.errors
    finding = next(item for item in result.findings if item.rule_id == "IV-SEC-008")
    assert finding.path == relative
    encoded_path = quote(relative, safe="/-._~")
    for format_name in available_reporters():
        rendered = render_report(result, format_name)
        assert rendered.encode("utf-8").decode("utf-8") == rendered
        assert value not in rendered
        assert relative in rendered or encoded_path in rendered


@pytest.mark.benchmark
def test_scanner_benchmark_many_small_files_without_timing_gate(tmp_path: Path, record_property) -> None:
    file_count = 128
    for index in range(file_count):
        (tmp_path / f"module_{index:03d}.py").write_text(
            f"VALUE_{index} = {index}\n",
            encoding="utf-8",
        )

    started = perf_counter()
    result = Scanner(_config()).scan(tmp_path)
    elapsed = perf_counter() - started

    record_property("files_scanned", result.stats.files_scanned)
    record_property("elapsed_seconds", f"{elapsed:.6f}")
    assert not result.errors
    assert result.stats.files_discovered == file_count
    assert result.stats.files_scanned == file_count
