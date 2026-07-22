from __future__ import annotations

from dataclasses import replace

import pytest

from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import compile_rule, iter_regex_matches, rule_applies_to_path
from ironveil.rules.registry import (
    BUILTIN_RULES,
    RULE_PACKS,
    RuleRegistry,
    RuleValidationError,
    get_builtin_rules,
    load_declarative_rules,
    load_rules,
    rule_from_mapping,
    validate_rules,
)


def _custom_rule_data(**updates: object) -> dict[str, object]:
    data: dict[str, object] = {
        "id": "CUSTOM-SEC-001",
        "name": "Synthetic marker",
        "description": "Detect a non-secret marker used only by this unit test.",
        "category": "repository",
        "severity": "low",
        "confidence": "high",
        "message": "Synthetic marker found.",
        "remediation": "Remove the marker.",
        "pattern": r"SYNTHETIC_MARKER_[0-9]+",
        "references": ["https://example.invalid/custom-rule"],
        "file_globs": ["*.txt"],
        "tags": ["custom", "synthetic"],
    }
    data.update(updates)
    return data


def test_builtin_registry_is_unique_complete_and_compilable() -> None:
    ids = [rule.id for rule in BUILTIN_RULES]

    assert len(ids) == len(set(ids)) == 77
    assert sum(map(len, RULE_PACKS.values())) == len(BUILTIN_RULES)
    assert all(isinstance(rule, Rule) for rule in BUILTIN_RULES)
    for rule in BUILTIN_RULES:
        if rule.pattern:
            compile_rule(rule)


def test_registry_filters_by_pack_category_and_tag() -> None:
    secret_rules = get_builtin_rules(packs=["secrets"], categories=[Category.SECRET])
    github_rules = get_builtin_rules(tags=["github-actions"])

    assert len(secret_rules) == 27
    assert {rule.id for rule in github_rules} == {f"IV-GHA-{number:03d}" for number in range(1, 8)}


def test_path_globs_preserve_leading_dot_components() -> None:
    workflow_rule = next(rule for rule in BUILTIN_RULES if rule.id == "IV-GHA-001")
    env_rule = replace(next(rule for rule in BUILTIN_RULES if rule.id == "IV-FILE-001"), file_globs=(".env",))

    assert rule_applies_to_path(workflow_rule, "./.github/workflows/scan.yml")
    assert not rule_applies_to_path(workflow_rule, "github/workflows/scan.yml")
    assert rule_applies_to_path(env_rule, ".env")


def test_generic_regex_iterator_masks_named_secret_groups() -> None:
    credential_rule = next(rule for rule in BUILTIN_RULES if rule.id == "IV-TF-004")
    synthetic_value = "Q7m2N9p4R6t8V3w5"

    match = next(iter_regex_matches(credential_rule, f'secret_key = "{synthetic_value}"'))

    assert synthetic_value not in match.evidence
    assert "…" in match.evidence


def test_declarative_rule_is_strictly_typed() -> None:
    rule = rule_from_mapping(_custom_rule_data())

    assert rule.category is Category.REPOSITORY
    assert rule.severity is Severity.LOW
    assert rule.confidence is Confidence.HIGH
    assert compile_rule(rule).regex.search("SYNTHETIC_MARKER_42")


def test_declarative_document_and_registry_class() -> None:
    custom = load_declarative_rules({"rules": [_custom_rule_data()]})
    registry = RuleRegistry.with_custom(custom, packs=["files"])

    assert registry.get("CUSTOM-SEC-001") is not None
    assert len(registry.rules) == len(RULE_PACKS["files"]) + 1


def test_duplicate_and_builtin_override_ids_are_rejected() -> None:
    custom = rule_from_mapping(_custom_rule_data())
    with pytest.raises(RuleValidationError, match="Duplicate rule ID"):
        validate_rules([custom, custom])

    override = Rule(
        id="IV-SEC-001",
        name="Invalid override",
        description="A custom rule must not shadow a built-in.",
        category=Category.SECRET,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        message="Invalid.",
        remediation="Use a custom ID.",
        pattern="synthetic",
    )
    with pytest.raises(RuleValidationError, match="cannot override"):
        load_rules([override])


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"severity": "urgent"}, "Invalid severity"),
        ({"pattern": "("}, "invalid regular expression"),
        ({"detection_type": "python-callback"}, "regex.*only"),
        ({"unexpected": True}, "Unknown custom rule fields"),
        ({"file_globs": ["../outside"]}, "unsafe file glob"),
    ],
)
def test_invalid_declarative_rules_are_rejected(updates: dict[str, object], message: str) -> None:
    with pytest.raises(RuleValidationError, match=message):
        rule_from_mapping(_custom_rule_data(**updates))
