"""Conservative Terraform/HCL security checks."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import RuleMatch, compile_rule, line_column
from ironveil.rules.secrets import is_obvious_placeholder

_TF_SECURITY = (
    "https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables"
)


def _terraform_rule(
    number: int,
    name: str,
    description: str,
    pattern: str | None,
    *,
    severity: Severity,
    confidence: Confidence,
    detection_type: str = "terraform-context",
) -> Rule:
    return Rule(
        id=f"IV-TF-{number:03d}",
        name=name,
        description=description,
        category=Category.IAC,
        severity=severity,
        confidence=confidence,
        message=f"Terraform: {name.lower()}.",
        remediation=description,
        references=(_TF_SECURITY,),
        pattern=pattern,
        detection_type=detection_type,
        file_globs=("*.tf", "*.tf.json"),
        tags=("iac", "terraform"),
    )


TERRAFORM_RULES: tuple[Rule, ...] = (
    _terraform_rule(
        1,
        "Public CIDR exposes a sensitive port",
        "Restrict ingress on administrative and database ports to explicitly trusted networks.",
        None,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    ),
    _terraform_rule(
        2,
        "Public storage configuration",
        "Block anonymous storage access and grant access through narrowly scoped identities.",
        None,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    ),
    _terraform_rule(
        3,
        "Encryption explicitly disabled",
        "Enable provider-managed or customer-managed encryption for data at rest.",
        r"[\"']?(?:encrypted|storage_encrypted|enable_encryption|encryption_enabled)[\"']?\s*(?:=|:)\s*false\b",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    ),
    _terraform_rule(
        4,
        "Hardcoded provider credential",
        (
            "Load credentials from a secret manager or short-lived workload identity, not Terraform "
            "source or state inputs."
        ),
        r"[\"']?(?:access_key|secret_key|client_secret|account_key|password)[\"']?\s*(?:=|:)\s*[\"'](?P<secret>[^\"'\s$]{8,512})[\"']",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    ),
    _terraform_rule(
        5,
        "Overly permissive IAM policy",
        "Replace wildcard actions and resources with the minimum operations and resource ARNs required.",
        None,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    ),
    _terraform_rule(
        6,
        "Security group open to all traffic",
        "Limit protocols, port ranges, and source CIDRs; do not expose all traffic to the internet.",
        None,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    ),
)

RULES = TERRAFORM_RULES
_RULE = {rule.id: rule for rule in TERRAFORM_RULES}
_PUBLIC_CIDR = re.compile(r"(?:0\.0\.0\.0/0|::/0)")
_SENSITIVE_PORTS = {
    21,
    22,
    23,
    25,
    110,
    143,
    445,
    1433,
    1521,
    2049,
    2375,
    2376,
    3306,
    3389,
    5432,
    5601,
    6379,
    6443,
    8080,
    9200,
    11211,
    27017,
}


@dataclass(frozen=True, slots=True)
class _Block:
    kind: str
    label: str
    start: int
    text: str


def _blocks(text: str) -> tuple[_Block, ...]:
    """Extract labeled HCL blocks with a small quote-aware brace scanner."""

    header = re.compile(r"\b(resource|data)\s+[\"']([^\"']+)[\"']\s+[\"'][^\"']+[\"']\s*\{")
    blocks: list[_Block] = []
    for match in header.finditer(text):
        brace = text.find("{", match.start(), match.end())
        depth = 0
        quote = ""
        escaped = False
        index = brace
        while index < len(text):
            char = text[index]
            if escaped:
                escaped = False
            elif char == "\\" and quote:
                escaped = True
            elif quote:
                if char == quote:
                    quote = ""
            elif char in {'"', "'"}:
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(
                        _Block(match.group(1), match.group(2), match.start(), text[match.start() : index + 1])
                    )
                    break
            index += 1
    return tuple(blocks)


def _masked(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}…{value[-3:]}"


def _line_evidence(text: str, offset: int, secret: str = "") -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end < 0:
        end = len(text)
    evidence = text[start:end].strip()
    if secret:
        evidence = evidence.replace(secret, _masked(secret))
    return evidence[:240]


def _result(rule_id: str, text: str, offset: int, path: str, detail: str = "", secret: str = "") -> RuleMatch:
    line, column = line_column(text, offset)
    metadata: tuple[tuple[str, str | int | float | bool], ...] = (("path", path),)
    if detail:
        metadata += (("detail", detail),)
    return RuleMatch(
        rule=_RULE[rule_id],
        line=line,
        column=column,
        evidence=_line_evidence(text, offset, secret),
        metadata=metadata,
    )


def _integer(block: str, name: str) -> int | None:
    match = re.search(rf"\b{re.escape(name)}\s*=\s*(-?\d+)\b", block, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _public_network_issue(block: _Block) -> tuple[str, int, str] | None:
    cidr = _PUBLIC_CIDR.search(block.text)
    if not cidr:
        return None
    protocol_match = re.search(r"\bprotocol\s*=\s*[\"']?(-?1|all|tcp|udp)[\"']?", block.text, re.IGNORECASE)
    protocol = protocol_match.group(1).casefold() if protocol_match else ""
    from_port = _integer(block.text, "from_port")
    to_port = _integer(block.text, "to_port")
    if protocol in {"-1", "all"} or (from_port == 0 and to_port in {0, 65535}):
        return "IV-TF-006", block.start + cidr.start(), "all protocols or ports"
    if from_port is None:
        return None
    upper = to_port if to_port is not None else from_port
    exposed = sorted(port for port in _SENSITIVE_PORTS if from_port <= port <= upper)
    if exposed:
        return "IV-TF-001", block.start + cidr.start(), f"sensitive ports: {', '.join(map(str, exposed[:8]))}"
    return None


def _permissive_iam(block: _Block) -> bool:
    if "iam" not in block.label.casefold() and "policy" not in block.label.casefold():
        return False
    action_wildcard = bool(
        re.search(
            r"[\"']?(?:Action|actions?)[\"']?\s*(?:=|:)\s*(?:\[\s*)?[\"']\*[\"']", block.text, re.IGNORECASE
        )
    )
    resource_wildcard = bool(
        re.search(
            r"[\"']?(?:Resource|resources?)[\"']?\s*(?:=|:)\s*(?:\[\s*)?[\"']\*[\"']",
            block.text,
            re.IGNORECASE,
        )
    )
    return action_wildcard and resource_wildcard


def analyze_terraform(text: str, path: str = "main.tf") -> tuple[RuleMatch, ...]:
    """Analyze decoded Terraform while correlating values within resource blocks."""

    matches: list[RuleMatch] = []
    blocks = _blocks(text)

    # Direct, high-signal single-line rules.
    for rule in (TERRAFORM_RULES[2],):
        for match in compile_rule(rule).regex.finditer(text):
            matches.append(_result(rule.id, text, match.start(), path))

    credential_rule = _RULE["IV-TF-004"]
    for match in compile_rule(credential_rule).regex.finditer(text):
        secret = match.group("secret")
        if is_obvious_placeholder(secret):
            continue
        matches.append(_result(credential_rule.id, text, match.start("secret"), path, secret=secret))

    for block in blocks:
        network_issue = _public_network_issue(block)
        if network_issue:
            rule_id, offset, detail = network_issue
            matches.append(_result(rule_id, text, offset, path, detail))
        if _permissive_iam(block):
            wildcard = re.search(r"[\"']\*[\"']", block.text)
            offset = block.start + (wildcard.start() if wildcard else 0)
            matches.append(
                _result("IV-TF-005", text, offset, path, "wildcard action and resource in one policy block")
            )

        storage_public = re.search(
            r"\b(?:acl|access_type)\s*=\s*[\"'](?:public-read(?:-write)?|blob|container)[\"']"
            r"|\bmember\s*=\s*[\"'](?:allUsers|allAuthenticatedUsers)[\"']",
            block.text,
            re.IGNORECASE,
        )
        if storage_public and any(
            marker in block.label.casefold() for marker in ("storage", "bucket", "s3", "container", "object")
        ):
            matches.append(
                _result(
                    "IV-TF-002",
                    text,
                    block.start + storage_public.start(),
                    path,
                    "anonymous storage access",
                )
            )

        if block.label.casefold() in {"aws_s3_bucket_public_access_block", "aws_s3_bucket"}:
            disabled = re.search(
                r"\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b",
                block.text,
                re.IGNORECASE,
            )
            if disabled:
                matches.append(
                    _result(
                        "IV-TF-002",
                        text,
                        block.start + disabled.start(),
                        path,
                        "S3 public-access protection disabled",
                    )
                )

    deduplicated = {(match.rule.id, match.line, match.column): match for match in matches}
    return tuple(sorted(deduplicated.values(), key=lambda item: (item.line, item.column, item.rule.id)))


def get_rules() -> tuple[Rule, ...]:
    return TERRAFORM_RULES
