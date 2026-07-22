"""Validated registry for built-in and custom declarative rules."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, TypeVar

from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import compile_rule
from ironveil.rules.dependencies import DEPENDENCY_RULES
from ironveil.rules.docker import DOCKER_RULES
from ironveil.rules.files import FILE_RULES
from ironveil.rules.github_actions import GITHUB_ACTIONS_RULES
from ironveil.rules.kubernetes import KUBERNETES_RULES
from ironveil.rules.secrets import SECRET_RULES
from ironveil.rules.terraform import TERRAFORM_RULES


class RuleValidationError(ValueError):
    """Raised when a rule pack is ambiguous or unsafe to load."""


RULE_PACKS: Mapping[str, tuple[Rule, ...]] = MappingProxyType(
    {
        "secrets": SECRET_RULES,
        "files": FILE_RULES,
        "dependencies": DEPENDENCY_RULES,
        "docker": DOCKER_RULES,
        "github-actions": GITHUB_ACTIONS_RULES,
        "terraform": TERRAFORM_RULES,
        "kubernetes": KUBERNETES_RULES,
    }
)
_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,8}$")
_BUILTIN_ID = re.compile(r"^IV-(?:SEC|FILE|DEP|DOCKER|GHA|TF|K8S)-\d{3}$")
_REQUIRED_TEXT_FIELDS = ("id", "name", "description", "message", "remediation")
_DECLARATIVE_FIELDS = frozenset(
    {
        "id",
        "name",
        "description",
        "category",
        "severity",
        "confidence",
        "message",
        "remediation",
        "references",
        "pattern",
        "detection_type",
        "file_globs",
        "tags",
    }
)
_EnumT = TypeVar("_EnumT", Category, Severity, Confidence)


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise RuleValidationError(f"Custom rule field '{field}' must be an array of strings")
    items = tuple(value)
    if any(not isinstance(item, str) or not item.strip() for item in items):
        raise RuleValidationError(f"Custom rule field '{field}' must contain non-empty strings")
    return items


def _enum(enum_type: type[_EnumT], value: Any, field: str) -> _EnumT:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise RuleValidationError(f"Custom rule field '{field}' must be a string")
    try:
        return enum_type(value.strip().lower())
    except ValueError as exc:
        choices = ", ".join(item.value for item in enum_type)
        raise RuleValidationError(f"Invalid {field} '{value}'; expected one of: {choices}") from exc


def validate_rule(rule: Rule, *, builtin: bool = False) -> Rule:
    """Validate one typed rule and return it unchanged."""

    for field in _REQUIRED_TEXT_FIELDS:
        value = getattr(rule, field)
        if not isinstance(value, str) or not value.strip():
            raise RuleValidationError(f"Rule field '{field}' must be a non-empty string")
    if not _ID.fullmatch(rule.id):
        raise RuleValidationError(f"Invalid rule ID '{rule.id}'; use uppercase dash-separated components")
    if builtin and not _BUILTIN_ID.fullmatch(rule.id):
        raise RuleValidationError(
            f"Built-in rule ID '{rule.id}' does not follow the stable IronVeil namespace"
        )
    if not isinstance(rule.category, Category):
        raise RuleValidationError(f"Rule {rule.id} has an invalid category")
    if not isinstance(rule.severity, Severity):
        raise RuleValidationError(f"Rule {rule.id} has an invalid severity")
    if not isinstance(rule.confidence, Confidence):
        raise RuleValidationError(f"Rule {rule.id} has an invalid confidence")
    if not isinstance(rule.detection_type, str) or not rule.detection_type.strip():
        raise RuleValidationError(f"Rule {rule.id} must define a detection type")
    for field in ("references", "file_globs", "tags"):
        value = getattr(rule, field)
        if not isinstance(value, tuple) or any(not isinstance(item, str) or not item for item in value):
            raise RuleValidationError(f"Rule {rule.id} field '{field}' must be a tuple of non-empty strings")
    for reference in rule.references:
        if not reference.startswith(("https://", "http://")):
            raise RuleValidationError(f"Rule {rule.id} reference must be an HTTP(S) URL: {reference}")
    for glob in rule.file_globs:
        normalized = glob.replace("\\", "/")
        if "\x00" in glob or normalized.startswith("/") or ".." in normalized.split("/"):
            raise RuleValidationError(f"Rule {rule.id} has an unsafe file glob: {glob}")
    if rule.pattern is not None:
        if not isinstance(rule.pattern, str) or not rule.pattern:
            raise RuleValidationError(f"Rule {rule.id} pattern must be a non-empty string or null")
        if len(rule.pattern) > 16_384:
            raise RuleValidationError(f"Rule {rule.id} pattern exceeds the 16384-character limit")
        try:
            compile_rule(rule)
        except ValueError as exc:
            raise RuleValidationError(str(exc)) from exc
    elif rule.detection_type in {"regex", "regex-context"}:
        raise RuleValidationError(f"Rule {rule.id} uses {rule.detection_type} but has no pattern")
    return rule


def validate_rules(rules: Iterable[Rule], *, builtin: bool = False) -> tuple[Rule, ...]:
    """Validate a sequence and reject duplicate stable identifiers."""

    validated: list[Rule] = []
    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, Rule):
            raise RuleValidationError(f"Expected Rule, received {type(rule).__name__}")
        validate_rule(rule, builtin=builtin)
        if rule.id in seen:
            raise RuleValidationError(f"Duplicate rule ID: {rule.id}")
        seen.add(rule.id)
        validated.append(rule)
    return tuple(validated)


BUILTIN_RULES: tuple[Rule, ...] = validate_rules(
    (rule for pack in RULE_PACKS.values() for rule in pack),
    builtin=True,
)
_BUILTIN_BY_ID: Mapping[str, Rule] = MappingProxyType({rule.id: rule for rule in BUILTIN_RULES})


def rule_from_mapping(data: Mapping[str, Any]) -> Rule:
    """Build one regex-only custom rule from declarative configuration."""

    if not isinstance(data, Mapping):
        raise RuleValidationError("A custom rule must be an object")
    unknown = set(data) - _DECLARATIVE_FIELDS
    if unknown:
        raise RuleValidationError(f"Unknown custom rule fields: {', '.join(sorted(map(str, unknown)))}")
    missing = set(_REQUIRED_TEXT_FIELDS) - set(data)
    missing.update({"category", "severity", "confidence", "pattern"} - set(data))
    if missing:
        raise RuleValidationError(f"Missing custom rule fields: {', '.join(sorted(missing))}")
    detection_type = data.get("detection_type", "regex")
    if detection_type != "regex":
        raise RuleValidationError("Declarative custom rules currently support detection_type='regex' only")
    pattern = data.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise RuleValidationError("Custom rule field 'pattern' must be a non-empty string")

    text_values: dict[str, str] = {}
    for field in _REQUIRED_TEXT_FIELDS:
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            raise RuleValidationError(f"Custom rule field '{field}' must be a non-empty string")
        text_values[field] = value.strip()
    rule = Rule(
        **text_values,
        category=_enum(Category, data.get("category"), "category"),
        severity=_enum(Severity, data.get("severity"), "severity"),
        confidence=_enum(Confidence, data.get("confidence"), "confidence"),
        references=_strings(data.get("references"), "references"),
        pattern=pattern,
        detection_type=detection_type,
        file_globs=_strings(data.get("file_globs"), "file_globs"),
        tags=_strings(data.get("tags"), "tags"),
    )
    return validate_rule(rule)


def load_declarative_rules(data: Sequence[Mapping[str, Any]] | Mapping[str, Any]) -> tuple[Rule, ...]:
    """Load custom rule objects from a list or a ``{"rules": [...]}`` document."""

    values: Any = data.get("rules") if isinstance(data, Mapping) and "rules" in data else data
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise RuleValidationError("Custom rules must be an array or an object containing a 'rules' array")
    rules = tuple(rule_from_mapping(item) for item in values)
    return validate_rules(rules)


def get_builtin_rules(
    *,
    packs: Iterable[str] | None = None,
    categories: Iterable[Category | str] | None = None,
    tags: Iterable[str] | None = None,
) -> tuple[Rule, ...]:
    """Return a stable built-in sequence, optionally filtered by pack/category/tag."""

    if packs is None:
        selected = BUILTIN_RULES
    else:
        requested = tuple(packs)
        unknown = set(requested) - set(RULE_PACKS)
        if unknown:
            raise RuleValidationError(f"Unknown rule packs: {', '.join(sorted(unknown))}")
        selected = tuple(rule for pack in requested for rule in RULE_PACKS[pack])

    if categories is not None:
        category_values = {
            item if isinstance(item, Category) else _enum(Category, item, "category") for item in categories
        }
        selected = tuple(rule for rule in selected if rule.category in category_values)
    if tags is not None:
        required_tags = {tag.casefold() for tag in tags}
        selected = tuple(
            rule for rule in selected if required_tags.intersection(tag.casefold() for tag in rule.tags)
        )
    return selected


def load_rules(
    custom_rules: Iterable[Rule | Mapping[str, Any]] = (),
    *,
    packs: Iterable[str] | None = None,
) -> tuple[Rule, ...]:
    """Combine built-ins with typed or declarative custom rules safely."""

    builtins = get_builtin_rules(packs=packs)
    custom: list[Rule] = []
    for item in custom_rules:
        custom.append(item if isinstance(item, Rule) else rule_from_mapping(item))
    custom_validated = validate_rules(custom)
    builtin_ids = {rule.id for rule in BUILTIN_RULES}
    collisions = sorted(builtin_ids.intersection(rule.id for rule in custom_validated))
    if collisions:
        raise RuleValidationError(f"Custom rules cannot override built-in IDs: {', '.join(collisions)}")
    return validate_rules((*builtins, *custom_validated))


def get_rule(rule_id: str) -> Rule | None:
    """Look up one built-in rule by its stable identifier."""

    return _BUILTIN_BY_ID.get(rule_id)


@dataclass(frozen=True, slots=True)
class RuleRegistry:
    """Immutable registry useful to scanners and integrations."""

    rules: tuple[Rule, ...] = BUILTIN_RULES

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", validate_rules(self.rules))

    @classmethod
    def with_custom(
        cls,
        custom_rules: Iterable[Rule | Mapping[str, Any]],
        *,
        packs: Iterable[str] | None = None,
    ) -> RuleRegistry:
        return cls(load_rules(custom_rules, packs=packs))

    def get(self, rule_id: str) -> Rule | None:
        return next((rule for rule in self.rules if rule.id == rule_id), None)

    def by_category(self, category: Category | str) -> tuple[Rule, ...]:
        value = category if isinstance(category, Category) else _enum(Category, category, "category")
        return tuple(rule for rule in self.rules if rule.category is value)


def get_rules() -> tuple[Rule, ...]:
    """Compatibility alias for callers that do not need filters."""

    return BUILTIN_RULES
