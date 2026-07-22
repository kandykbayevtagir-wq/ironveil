"""Kubernetes manifest security checks with lightweight YAML context."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import RuleMatch, compile_rule, line_column

_POD_SECURITY = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"


def _kubernetes_rule(
    number: int,
    name: str,
    description: str,
    pattern: str | None,
    *,
    severity: Severity,
    confidence: Confidence,
    detection_type: str = "kubernetes",
) -> Rule:
    return Rule(
        id=f"IV-K8S-{number:03d}",
        name=name,
        description=description,
        category=Category.IAC,
        severity=severity,
        confidence=confidence,
        message=f"Kubernetes: {name.lower()}.",
        remediation=description,
        references=(_POD_SECURITY,),
        pattern=pattern,
        detection_type=detection_type,
        file_globs=("*.yaml", "*.yml", "k8s/*.yaml", "k8s/*.yml", "manifests/*.yaml", "manifests/*.yml"),
        tags=("iac", "kubernetes"),
    )


KUBERNETES_RULES: tuple[Rule, ...] = (
    _kubernetes_rule(
        1,
        "Privileged container",
        "Set privileged: false and grant only the individual capabilities the workload requires.",
        r"^\s*privileged\s*:\s*(?:true|yes|on)\s*(?:#.*)?$",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    ),
    _kubernetes_rule(
        2,
        "Host network namespace",
        "Remove hostNetwork or set it to false so the pod uses an isolated network namespace.",
        r"^\s*hostNetwork\s*:\s*(?:true|yes|on)\s*(?:#.*)?$",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _kubernetes_rule(
        3,
        "Host process namespace",
        "Remove hostPID or set it to false so the pod cannot inspect host processes.",
        r"^\s*hostPID\s*:\s*(?:true|yes|on)\s*(?:#.*)?$",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _kubernetes_rule(
        4,
        "hostPath volume",
        (
            "Replace hostPath with a scoped volume type, or tightly constrain and document the "
            "required host path."
        ),
        r"^\s*hostPath\s*:\s*(?:\{.*)?$",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _kubernetes_rule(
        5,
        "Container permitted to run as root",
        "Set runAsNonRoot: true and a non-zero runAsUser at pod or container scope.",
        r"^\s*(?:runAsNonRoot\s*:\s*(?:false|no|off)|runAsUser\s*:\s*0)\s*(?:#.*)?$",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _kubernetes_rule(
        6,
        "Privilege escalation allowed",
        "Set allowPrivilegeEscalation: false for every container.",
        r"^\s*allowPrivilegeEscalation\s*:\s*(?:true|yes|on)\s*(?:#.*)?$",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _kubernetes_rule(
        7,
        "Container resource limits missing",
        (
            "Define CPU and memory limits for each application container, with requests chosen from "
            "observed demand."
        ),
        None,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        detection_type="kubernetes-structural",
    ),
    _kubernetes_rule(
        8,
        "Floating container image",
        "Pin the container image to a reviewed digest or immutable version tag.",
        r"^\s*image\s*:\s*[\"']?[^\s\"']+:latest[\"']?\s*(?:#.*)?$",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        detection_type="kubernetes-context",
    ),
    _kubernetes_rule(
        9,
        "Unsafe Linux capability",
        (
            "Drop ALL capabilities and add back only a reviewed minimal set; avoid SYS_ADMIN, "
            "NET_ADMIN, and other host-level capabilities."
        ),
        r"^\s*add\s*:\s*\[[^]]*\b(?:ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH)\b[^]]*\]",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        detection_type="kubernetes-context",
    ),
)

RULES = KUBERNETES_RULES
_RULE = {rule.id: rule for rule in KUBERNETES_RULES}
_UNSAFE_CAPABILITY = re.compile(
    r"^(?:ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH)$", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class _ContainerBlock:
    line: int
    lines: tuple[str, ...]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _container_blocks(lines: list[str]) -> tuple[_ContainerBlock, ...]:
    blocks: list[_ContainerBlock] = []
    index = 0
    while index < len(lines):
        header = re.match(r"^(\s*)(?:initContainers|containers)\s*:\s*$", lines[index])
        if not header:
            index += 1
            continue
        header_indent = len(header.group(1))
        cursor = index + 1
        while cursor < len(lines) and (not lines[cursor].strip() or lines[cursor].lstrip().startswith("#")):
            cursor += 1
        if cursor >= len(lines) or _indent(lines[cursor]) <= header_indent:
            index = cursor
            continue
        item_indent = _indent(lines[cursor])
        while cursor < len(lines):
            if lines[cursor].strip() and _indent(lines[cursor]) <= header_indent:
                break
            if _indent(lines[cursor]) == item_indent and lines[cursor].lstrip().startswith("-"):
                start = cursor
                cursor += 1
                while cursor < len(lines):
                    candidate = lines[cursor]
                    if candidate.strip() and _indent(candidate) <= header_indent:
                        break
                    if _indent(candidate) == item_indent and candidate.lstrip().startswith("-"):
                        break
                    cursor += 1
                blocks.append(_ContainerBlock(start + 1, tuple(lines[start:cursor])))
                continue
            cursor += 1
        index = cursor
    return tuple(blocks)


def _result(rule_id: str, line: int, evidence: str, path: str, detail: str = "") -> RuleMatch:
    metadata: tuple[tuple[str, str | int | float | bool], ...] = (("path", path),)
    if detail:
        metadata += (("detail", detail),)
    return RuleMatch(rule=_RULE[rule_id], line=line, evidence=evidence.strip()[:240], metadata=metadata)


def _image_is_floating(value: str) -> bool:
    image = value.strip().strip("\"'")
    if "@sha256:" in image.casefold():
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.casefold().endswith(":latest")


def _unsafe_capability(block: _ContainerBlock) -> tuple[int, str] | None:
    lines = list(block.lines)
    for index, line in enumerate(lines):
        add = re.match(r"^(\s*)add\s*:\s*(.*)$", line)
        if not add:
            continue
        inline = add.group(2)
        for candidate in re.findall(r"[A-Za-z_]+", inline):
            if _UNSAFE_CAPABILITY.fullmatch(candidate):
                return block.line + index, candidate
        add_indent = len(add.group(1))
        for nested_index, nested in enumerate(lines[index + 1 :], index + 1):
            if nested.strip() and _indent(nested) <= add_indent:
                break
            candidate = nested.strip().lstrip("-").strip().strip("\"'")
            if _UNSAFE_CAPABILITY.fullmatch(candidate):
                return block.line + nested_index, candidate
    return None


def analyze_kubernetes(text: str, path: str = "manifest.yaml") -> tuple[RuleMatch, ...]:
    """Analyze a decoded Kubernetes YAML manifest without interpreting templates."""

    return _analyze_kubernetes(text, path, partial=False)


def _looks_like_kubernetes_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    name = normalized.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return any(
        marker in normalized.split("/")
        for marker in ("k8s", "kubernetes", "manifests", "helm", "charts", "templates")
    ) or any(marker in name for marker in ("deployment", "daemonset", "statefulset", "pod", "cronjob", "job"))


def analyze_kubernetes_fragment(text: str, path: str = "manifest.yaml") -> tuple[RuleMatch, ...]:
    """Analyze only high-signal added lines from a likely Kubernetes manifest."""

    return _analyze_kubernetes(text, path, partial=True)


def _analyze_kubernetes(text: str, path: str, *, partial: bool) -> tuple[RuleMatch, ...]:
    has_markers = bool(re.search(r"^\s*apiVersion\s*:", text, re.MULTILINE)) and bool(
        re.search(r"^\s*kind\s*:", text, re.MULTILINE)
    )

    if not has_markers and (not partial or not _looks_like_kubernetes_path(path)):
        return ()
    lines = text.splitlines()
    matches: list[RuleMatch] = []
    for rule in KUBERNETES_RULES:
        if not rule.pattern:
            continue
        for match in compile_rule(rule).regex.finditer(text):
            line, column = line_column(text, match.start())
            evidence = lines[line - 1].strip() if lines else ""
            matches.append(
                RuleMatch(
                    rule=rule,
                    line=line,
                    column=column,
                    evidence=evidence[:240],
                    metadata=(("path", path),),
                )
            )

    for block in () if partial else _container_blocks(lines):
        image_match = re.search(r"^\s*image\s*:\s*([^\s#]+)", block.text, re.IGNORECASE | re.MULTILINE)
        if image_match and _image_is_floating(image_match.group(1)):
            relative_line = block.text.count("\n", 0, image_match.start())
            line = block.line + relative_line
            if not any(item.rule.id == "IV-K8S-008" and item.line == line for item in matches):
                matches.append(
                    _result(
                        "IV-K8S-008",
                        line,
                        lines[line - 1],
                        path,
                        "image lacks an immutable digest or fixed tag",
                    )
                )

        resources = re.search(r"^\s*resources\s*:", block.text, re.IGNORECASE | re.MULTILINE)
        limits = re.search(r"^\s*limits\s*:", block.text, re.IGNORECASE | re.MULTILINE)
        inline_limits = re.search(r"resources\s*:\s*\{[^}]*\blimits\s*:", block.text, re.IGNORECASE)
        if not (resources and limits) and not inline_limits:
            evidence = next(
                (line.strip() for line in block.lines if re.search(r"\b(?:name|image)\s*:", line)),
                block.lines[0].strip(),
            )
            matches.append(_result("IV-K8S-007", block.line, evidence, path))

        capability = _unsafe_capability(block)
        if capability:
            line, name = capability
            if not any(item.rule.id == "IV-K8S-009" and item.line == line for item in matches):
                matches.append(_result("IV-K8S-009", line, lines[line - 1], path, name))

    deduplicated = {(match.rule.id, match.line, match.column): match for match in matches}
    return tuple(sorted(deduplicated.values(), key=lambda item: (item.line, item.column, item.rule.id)))


def get_rules() -> tuple[Rule, ...]:
    return KUBERNETES_RULES
