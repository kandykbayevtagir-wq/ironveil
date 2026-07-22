from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import ironveil.config as config_module
from ironveil.config import Config, load_config
from ironveil.exceptions import ConfigurationError
from ironveil.models import Category, Confidence, Severity


def test_defaults_are_local_first(tmp_path: Path) -> None:
    config = load_config(tmp_path)

    assert config.dependencies.online is False
    assert config.scan.follow_symlinks is False
    assert config.scan.respect_gitignore is True
    assert config.ui.host == "127.0.0.1"
    assert config.policy.fail_severity is Severity.HIGH


def test_config_loads_allowlist_and_custom_rule(tmp_path: Path) -> None:
    config_file = tmp_path / ".ironveil.toml"
    config_file.write_text(
        """
[scan]
workers = 2
exclude = ["generated/**"]

[policy]
fail_severity = "medium"
minimum_confidence = "low"
fail_on = ["secret", "error"]

[[allowlist]]
rule = "IV-SEC-001"
path = "tests/fixtures/**"
reason = "Synthetic fixture"
expires = "2099-01-01"

[[rules]]
id = "CUSTOM-001"
name = "Internal marker"
category = "secret"
severity = "high"
confidence = "high"
regex = "internal_[A-Za-z0-9]{20}"
message = "Possible internal marker"
remediation = "Store it in a secret manager"
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.scan.workers == 2
    assert config.policy.fail_severity is Severity.MEDIUM
    assert config.policy.minimum_confidence is Confidence.LOW
    assert config.policy.fail_on == [Category.SECRET, Category.SCAN_ERROR]
    assert config.allowlist[0].reason == "Synthetic fixture"
    assert config.rules[0].id == "CUSTOM-001"
    assert len(config.digest()) == 64


@pytest.mark.parametrize(
    "content,field",
    [
        ("[scan]\nworkers = 0\n", "scan.workers"),
        ("[scan]\ntracked_only = true\nall_files = true\n", "mutually exclusive"),
        ("[ui]\nhost = '0.0.0.0'\n", "ui.host"),
        ("[policy]\nfail_severity = 'urgent'\n", "policy.fail_severity"),
        ("unknown = true\n", "config.unknown"),
        ("[[allowlist]]\nrule='*'\npath='**'\n", "reason"),
        (
            "[[allowlist]]\nrule='*'\npath='**'\nreason='test'\nexpires='2099-13-40'\n",
            "expires",
        ),
        (
            "[[rules]]\nid='X'\nname='X'\ncategory='secret'\nseverity='high'\n"
            "confidence='high'\nregex='['\nmessage='x'\nremediation='x'\n",
            "regex",
        ),
    ],
)
def test_invalid_config_names_field(tmp_path: Path, content: str, field: str) -> None:
    (tmp_path / ".ironveil.toml").write_text(content, encoding="utf-8")

    with pytest.raises(ConfigurationError, match=field.replace(".", r"\.")):
        load_config(tmp_path)


def test_config_digest_is_deterministic() -> None:
    assert Config().digest() == Config().digest()


def test_implicit_config_refuses_symlink_but_explicit_config_allows_it(tmp_path: Path) -> None:
    external = tmp_path / "external.toml"
    external.write_text("[scan]\nworkers = 3\n", encoding="utf-8")
    linked = tmp_path / ".ironveil.toml"
    linked.symlink_to(external)

    with pytest.raises(ConfigurationError, match="refusing implicit symlink"):
        load_config(tmp_path)

    config = load_config(tmp_path, linked)
    assert config.scan.workers == 3
    assert config.source == external.resolve()


def test_config_file_read_is_size_bounded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(config_module, "MAX_CONFIG_BYTES", 32)
    (tmp_path / ".ironveil.toml").write_text(
        "[scan]\nworkers = 2\n" + "#" * 64,
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="safety limit"):
        load_config(tmp_path)


def test_packaged_config_schema_matches_loader_bounds_and_exclusions() -> None:
    schema = json.loads(
        resources.files("ironveil").joinpath("schemas/config.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    valid = {
        "scan": {"max_size_mb": 0.001, "tracked_only": True, "all_files": False},
        "policy": {"fail_on": ["secret", "error"]},
        "history": {"max_commits": 1_000_000},
        "exclude": ["generated/**"],
    }

    assert list(validator.iter_errors(valid)) == []
    assert list(validator.iter_errors({"scan": {"max_size_mb": 0.0009}}))
    assert list(validator.iter_errors({"scan": {"tracked_only": True, "all_files": True}}))
    assert list(validator.iter_errors({"history": {"max_commits": 1_000_001}}))
