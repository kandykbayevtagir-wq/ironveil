"""Helpers shared by declarative rule packs.

Rule packs deliberately return small, immutable :class:`RuleMatch` values.  The
scanner remains responsible for turning those values into public findings and
for applying policy, suppressions, and fingerprints.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePosixPath
from re import Pattern

from ironveil.models import Rule


@dataclass(frozen=True, slots=True)
class CompiledRule:
    rule: Rule
    regex: Pattern[str]


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A detector result without reporter- or policy-specific state."""

    rule: Rule
    line: int
    column: int = 1
    evidence: str = ""
    metadata: tuple[tuple[str, str | int | float | bool], ...] = ()


@lru_cache(maxsize=512)
def compile_rule(rule: Rule) -> CompiledRule:
    if not rule.pattern:
        raise ValueError(f"Rule {rule.id} does not define a regular expression")
    try:
        regex = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as exc:
        raise ValueError(f"Rule {rule.id} has an invalid regular expression: {exc}") from exc
    return CompiledRule(rule=rule, regex=regex)


def line_column(text: str, offset: int) -> tuple[int, int]:
    """Return one-based line and column numbers for *offset*."""

    line_start = text.rfind("\n", 0, offset) + 1
    return text.count("\n", 0, offset) + 1, offset - line_start + 1


def iter_regex_matches(rule: Rule, text: str) -> Iterator[RuleMatch]:
    """Yield safe, line-oriented matches for a regular-expression rule."""

    for match in compile_rule(rule).regex.finditer(text):
        line, column = line_column(text, match.start())
        evidence = text.splitlines()[line - 1].strip() if text else ""
        secret = match.groupdict().get("secret")
        if secret:
            masked = "*" * len(secret) if len(secret) <= 8 else f"{secret[:4]}…{secret[-4:]}"
            evidence = evidence.replace(secret, masked)
        yield RuleMatch(rule=rule, line=line, column=column, evidence=evidence)


def rule_applies_to_path(rule: Rule, path: str) -> bool:
    """Return whether a rule's glob constraints accept a repository path."""

    if not rule.file_globs:
        return True
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    candidate = PurePosixPath(normalized)
    return any(candidate.match(glob) or candidate.name == glob for glob in rule.file_globs)
