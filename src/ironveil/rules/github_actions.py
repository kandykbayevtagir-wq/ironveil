"""Context-aware GitHub Actions workflow rules without a YAML dependency."""

from __future__ import annotations

import re

from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import RuleMatch, compile_rule, line_column

_HARDENING = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"


def _gha_rule(
    number: int,
    name: str,
    description: str,
    pattern: str | None,
    *,
    severity: Severity,
    confidence: Confidence,
    detection_type: str = "workflow",
) -> Rule:
    return Rule(
        id=f"IV-GHA-{number:03d}",
        name=name,
        description=description,
        category=Category.IAC,
        severity=severity,
        confidence=confidence,
        message=f"GitHub Actions: {name.lower()}.",
        remediation=description,
        references=(_HARDENING,),
        pattern=pattern,
        detection_type=detection_type,
        file_globs=(".github/workflows/*.yml", ".github/workflows/*.yaml"),
        tags=("iac", "github-actions"),
    )


GITHUB_ACTIONS_RULES: tuple[Rule, ...] = (
    _gha_rule(
        1,
        "Repository permissions set to write-all",
        "Replace write-all with an explicit minimum permissions map, defaulting unspecified scopes to none.",
        r"^\s*permissions\s*:\s*[\"']?write-all[\"']?\s*(?:#.*)?$",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    ),
    _gha_rule(
        2,
        "Unsafe pull_request_target checkout",
        (
            "Do not check out or execute pull-request head code in pull_request_target; use "
            "pull_request or split privileged work into a trusted workflow."
        ),
        None,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detection_type="workflow-context",
    ),
    _gha_rule(
        3,
        "Secrets combined with untrusted pull-request data",
        (
            "Keep secrets out of jobs that interpolate attacker-controlled event fields, or pass "
            "validated values through a trusted boundary."
        ),
        None,
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        detection_type="workflow-context",
    ),
    _gha_rule(
        4,
        "Third-party action not pinned to a commit",
        (
            "Pin third-party actions and reusable workflows to a reviewed full 40-character commit "
            "SHA; retain the release tag in a comment."
        ),
        r"^\s*-?\s*uses\s*:\s*(?!(?:\./|docker://|actions/))[^\s@]+@(?!(?-i:[0-9a-f]{40})(?:\s|#|$))[^\s#]+",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        detection_type="workflow-context",
    ),
    _gha_rule(
        5,
        "Shell interpolation of untrusted event data",
        (
            "Pass event values through a quoted environment variable and validate them before use "
            "instead of placing expressions directly in shell source."
        ),
        r"\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref|head\.label)|issue\.(?:title|body)|comment\.body|review\.body|head_commit\.message)[^}]*\}\}",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        detection_type="workflow-context",
    ),
    _gha_rule(
        6,
        "Checkout persists the GitHub token",
        (
            "Set persist-credentials: false for checkout unless later authenticated Git operations "
            "are explicitly required."
        ),
        r"^\s*persist-credentials\s*:\s*[\"']?(?:true|yes|on)[\"']?\s*(?:#.*)?$",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        detection_type="workflow-context",
    ),
    _gha_rule(
        7,
        "Broad write permission",
        (
            "Grant write access only to the specific job that needs it and only for the required "
            "permission scope."
        ),
        r"^\s*(?:actions|checks|contents|deployments|issues|packages|pull-requests|security-events|statuses)\s*:\s*[\"']?write[\"']?\s*(?:#.*)?$",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        detection_type="workflow-context",
    ),
)

RULES = GITHUB_ACTIONS_RULES
_RULE = {rule.id: rule for rule in GITHUB_ACTIONS_RULES}
_USES = re.compile(r"^\s*-?\s*uses\s*:\s*([^\s@]+)@([^\s#]+)", re.IGNORECASE)
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_UNTRUSTED = re.compile(_RULE["IV-GHA-005"].pattern or "", re.IGNORECASE)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _line_match(rule: Rule, line_number: int, line: str, path: str, detail: str = "") -> RuleMatch:
    metadata: tuple[tuple[str, str | int | float | bool], ...] = (("path", path),)
    if detail:
        metadata += (("detail", detail),)
    return RuleMatch(rule=rule, line=line_number, evidence=line.strip()[:240], metadata=metadata)


def _has_trigger(lines: list[str], trigger: str) -> bool:
    expression = re.compile(rf"^\s*(?:on\s*:\s*)?{re.escape(trigger)}\s*:", re.IGNORECASE)
    inline = re.compile(
        rf"^\s*on\s*:\s*(?:{re.escape(trigger)}|\[[^]]*\b{re.escape(trigger)}\b[^]]*\])\s*$",
        re.IGNORECASE,
    )
    return any(
        expression.search(line.split("#", 1)[0]) or inline.search(line.split("#", 1)[0]) for line in lines
    )


def _run_blocks(lines: list[str]) -> list[tuple[int, str]]:
    blocks: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        parsed = re.match(r"^(\s*)(?:-\s*)?run\s*:\s*(.*)$", line, re.IGNORECASE)
        if not parsed:
            index += 1
            continue
        start = index + 1
        base_indent = len(parsed.group(1))
        parts = [parsed.group(2)]
        index += 1
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip() and _indent(candidate) <= base_indent:
                break
            parts.append(candidate.strip())
            index += 1
        blocks.append((start, "\n".join(parts)))
    return blocks


def _unsafe_target_checkout(lines: list[str]) -> tuple[int, str] | None:
    if not _has_trigger(lines, "pull_request_target"):
        return None
    for index, line in enumerate(lines):
        uses = _USES.match(line)
        if not uses or uses.group(1).casefold() != "actions/checkout":
            continue
        checkout_indent = _indent(line)
        for following in lines[index + 1 : index + 16]:
            if following.strip().startswith("-") and _indent(following) <= checkout_indent:
                break
            if re.search(
                r"github\.event\.pull_request\.(?:head\.(?:sha|ref|repo)|merge_commit_sha)",
                following,
                re.IGNORECASE,
            ):
                return index + 1, line
    return None


def _untrusted_secret_context(lines: list[str]) -> tuple[int, str] | None:
    if not _has_trigger(lines, "pull_request_target"):
        return None
    secret_lines = [
        index for index, line in enumerate(lines, 1) if re.search(r"\$\{\{\s*secrets\.", line, re.IGNORECASE)
    ]
    if not secret_lines:
        return None
    for line_number, block in _run_blocks(lines):
        if _UNTRUSTED.search(block):
            return line_number, lines[line_number - 1]
    return None


def _in_permissions_map(lines: list[str], line_index: int) -> bool:
    line = lines[line_index]
    current_indent = _indent(line)
    for previous in range(line_index - 1, -1, -1):
        candidate = lines[previous]
        if not candidate.strip() or candidate.lstrip().startswith("#"):
            continue
        candidate_indent = _indent(candidate)
        if candidate_indent >= current_indent:
            continue
        return bool(re.match(r"^\s*permissions\s*:\s*(?:#.*)?$", candidate, re.IGNORECASE))
    return False


def analyze_workflow(
    text: str,
    path: str = ".github/workflows/workflow.yml",
    *,
    partial: bool = False,
) -> tuple[RuleMatch, ...]:
    """Analyze a workflow, skipping whole-document correlations for Git fragments."""

    lines = text.splitlines()
    matches: list[RuleMatch] = []

    for rule in GITHUB_ACTIONS_RULES:
        if not rule.pattern:
            continue
        for regex_match in compile_rule(rule).regex.finditer(text):
            line_number, column = line_column(text, regex_match.start())
            line = lines[line_number - 1] if lines else ""
            if rule.id == "IV-GHA-004":
                uses = _USES.match(line)
                if not uses:
                    continue
                reference_path, ref = uses.groups()
                if reference_path.startswith(("./", "docker://")) or reference_path.casefold().startswith(
                    "actions/"
                ):
                    continue
                if _FULL_SHA.fullmatch(ref):
                    continue
            if rule.id == "IV-GHA-005" and not any(
                block_line <= line_number <= block_line + block.count("\n")
                for block_line, block in _run_blocks(lines)
            ):
                continue
            if rule.id == "IV-GHA-007" and not _in_permissions_map(lines, line_number - 1):
                continue
            matches.append(
                RuleMatch(
                    rule=rule,
                    line=line_number,
                    column=column,
                    evidence=line.strip()[:240],
                    metadata=(("path", path),),
                )
            )

    if not partial:
        target_checkout = _unsafe_target_checkout(lines)
        if target_checkout:
            matches.append(
                _line_match(
                    _RULE["IV-GHA-002"],
                    *target_checkout,
                    path,
                    "pull_request_target with PR head checkout",
                )
            )
        secret_context = _untrusted_secret_context(lines)
        if secret_context:
            matches.append(
                _line_match(
                    _RULE["IV-GHA-003"],
                    *secret_context,
                    path,
                    "privileged trigger combines secrets and untrusted expressions",
                )
            )

    deduplicated = {(match.rule.id, match.line, match.column): match for match in matches}
    return tuple(sorted(deduplicated.values(), key=lambda item: (item.line, item.column, item.rule.id)))


def get_rules() -> tuple[Rule, ...]:
    return GITHUB_ACTIONS_RULES
