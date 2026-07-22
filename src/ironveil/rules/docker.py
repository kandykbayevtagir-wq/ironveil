"""Explainable Dockerfile security rules."""

from __future__ import annotations

import re

from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import RuleMatch, compile_rule, line_column

_DOCKER_BENCH = "https://docs.docker.com/build/building/best-practices/"


def _docker_rule(
    number: int,
    name: str,
    description: str,
    pattern: str | None,
    *,
    severity: Severity,
    confidence: Confidence,
    detection_type: str = "dockerfile",
) -> Rule:
    return Rule(
        id=f"IV-DOCKER-{number:03d}",
        name=name,
        description=description,
        category=Category.IAC,
        severity=severity,
        confidence=confidence,
        message=f"Dockerfile: {name.lower()}.",
        remediation=description,
        references=(_DOCKER_BENCH,),
        pattern=pattern,
        detection_type=detection_type,
        file_globs=("Dockerfile", "Dockerfile.*", "*.Dockerfile"),
        tags=("iac", "docker"),
    )


DOCKER_RULES: tuple[Rule, ...] = (
    _docker_rule(
        1,
        "Explicit root user",
        "Run the final image as a dedicated non-root UID and grant only required permissions.",
        r"^\s*USER\s+(?:root|0)(?::(?:root|0))?\s*(?:#.*)?$",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _docker_rule(
        2,
        "No USER instruction",
        "Add a USER instruction for a dedicated non-root identity in the final stage.",
        None,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        detection_type="dockerfile-structural",
    ),
    _docker_rule(
        3,
        "Floating base-image tag",
        "Pin the base image to a reviewed digest (and optionally retain a readable version tag).",
        r"^\s*FROM\s+(?:--platform=\S+\s+)?\S+:latest(?:@\S+)?(?:\s+AS\s+\S+)?\s*$",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        detection_type="dockerfile-context",
    ),
    _docker_rule(
        4,
        "Remote script piped to a shell",
        (
            "Download, verify, and execute trusted artifacts as separate build steps instead of "
            "piping network output to a shell."
        ),
        r"^\s*RUN\s+[^\n]*(?:curl|wget)\b[^\n]*\|\s*(?:/bin/)?(?:ba|z|da|k)?sh\b",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _docker_rule(
        5,
        "World-writable permissions",
        "Use the narrowest owner and mode needed; avoid chmod 777 or equivalent world-writable modes.",
        r"^\s*RUN\s+[^\n]*\bchmod\s+(?:-[A-Za-z]+\s+)*(?:0?777|a\+rwx)\b",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _docker_rule(
        6,
        "Sensitive file copied into image",
        (
            "Exclude credentials and private keys with .dockerignore and inject runtime secrets "
            "through the platform secret mechanism."
        ),
        r"^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*(?:\[\s*)?[\"']?[^\n]*(?:\.env(?:\.|[\"'\s,\]])|id_(?:rsa|dsa|ecdsa|ed25519)|credentials?\.json|service[-_]?account|\.pem\b|\.p12\b|\.pfx\b|\.key\b)",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    ),
    _docker_rule(
        7,
        "ADD used for a local source",
        "Use COPY for local files; reserve ADD for behavior that is explicitly required and documented.",
        r"^\s*ADD\s+(?:--\S+\s+)*(?!https?://)\S+\s+\S+",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
    ),
    _docker_rule(
        8,
        "No HEALTHCHECK instruction",
        "Define a HEALTHCHECK or document why the runtime platform supplies an equivalent probe.",
        None,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        detection_type="dockerfile-structural",
    ),
    _docker_rule(
        9,
        "Package-manager cache retained",
        "Install packages and clear package-manager indexes in the same RUN instruction.",
        None,
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        detection_type="dockerfile-context",
    ),
)

RULES = DOCKER_RULES
_RULE = {rule.id: rule for rule in DOCKER_RULES}


def _logical_lines(text: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    buffer: list[str] = []
    start = 1
    for line_number, raw in enumerate(text.splitlines(), 1):
        if not buffer:
            start = line_number
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1])
            continue
        buffer.append(stripped)
        logical.append((start, " ".join(part.strip() for part in buffer)))
        buffer = []
    if buffer:
        logical.append((start, " ".join(part.strip() for part in buffer)))
    return logical


def _match(rule: Rule, line: int, evidence: str, path: str, detail: str = "") -> RuleMatch:
    metadata: tuple[tuple[str, str | int | float | bool], ...] = (("path", path),)
    if detail:
        metadata += (("detail", detail),)
    return RuleMatch(rule=rule, line=line, evidence=evidence.strip()[:240], metadata=metadata)


def _floating_from(line: str) -> bool:
    parsed = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", line, re.IGNORECASE)
    if not parsed:
        return False
    image = parsed.group(1)
    if image.casefold() == "scratch" or "@sha256:" in image.casefold():
        return False
    last_component = image.rsplit("/", 1)[-1]
    return ":" not in last_component or last_component.casefold().endswith(":latest")


def _cache_retained(line: str) -> str | None:
    lower = line.casefold()
    if not re.match(r"^\s*run\b", lower):
        return None
    if re.search(r"\bapt-get\s+(?:[^;&|]+\s+)?install\b", lower) and not re.search(
        r"rm\s+-rf\s+/var/lib/apt/lists(?:/\*|/)?", lower
    ):
        return "apt indexes are not removed"
    if re.search(r"\bapk\s+add\b", lower) and "--no-cache" not in lower:
        return "apk --no-cache is not used"
    if re.search(r"\b(?:yum|dnf)\s+(?:[^;&|]+\s+)?install\b", lower) and not re.search(
        r"\b(?:yum|dnf)\s+clean\s+all\b", lower
    ):
        return "RPM package cache is not cleaned"
    return None


def analyze_dockerfile(
    text: str, path: str = "Dockerfile", *, partial: bool = False
) -> tuple[RuleMatch, ...]:
    """Analyze Dockerfile text, omitting absence checks for partial Git fragments."""

    matches: list[RuleMatch] = []
    for rule in DOCKER_RULES:
        if not rule.pattern:
            continue
        for regex_match in compile_rule(rule).regex.finditer(text):
            line, column = line_column(text, regex_match.start())
            evidence = text.splitlines()[line - 1].strip() if text.splitlines() else ""
            matches.append(
                RuleMatch(
                    rule=rule,
                    line=line,
                    column=column,
                    evidence=evidence[:240],
                    metadata=(("path", path),),
                )
            )

    logical = _logical_lines(text)
    instruction_lines = [
        (line, value) for line, value in logical if value and not value.lstrip().startswith("#")
    ]
    if not partial:
        if not any(re.match(r"^\s*USER\b", value, re.IGNORECASE) for _, value in instruction_lines):
            matches.append(_match(_RULE["IV-DOCKER-002"], 1, "No USER instruction", path))
        if not any(re.match(r"^\s*HEALTHCHECK\b", value, re.IGNORECASE) for _, value in instruction_lines):
            matches.append(_match(_RULE["IV-DOCKER-008"], 1, "No HEALTHCHECK instruction", path))
    for line, value in instruction_lines:
        for rule in DOCKER_RULES:
            if (
                rule.pattern
                and rule.id != "IV-DOCKER-003"
                and compile_rule(rule).regex.search(value)
                and not any(item.rule.id == rule.id and item.line == line for item in matches)
            ):
                matches.append(_match(rule, line, value, path))
        if _floating_from(value) and not any(
            item.rule.id == "IV-DOCKER-003" and item.line == line for item in matches
        ):
            matches.append(_match(_RULE["IV-DOCKER-003"], line, value, path, "missing immutable digest"))
        cache_detail = _cache_retained(value)
        if cache_detail:
            matches.append(_match(_RULE["IV-DOCKER-009"], line, value, path, cache_detail))

    deduplicated = {(match.rule.id, match.line, match.column): match for match in matches}
    return tuple(sorted(deduplicated.values(), key=lambda item: (item.line, item.column, item.rule.id)))


def get_rules() -> tuple[Rule, ...]:
    return DOCKER_RULES
