"""Local-first secret detection rules and context-aware candidate filtering."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import replace
from pathlib import PurePosixPath

from ironveil.core.entropy import shannon_entropy
from ironveil.core.fingerprint import material_digest
from ironveil.core.masking import mask_secret, redact_spans
from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import RuleMatch, compile_rule, line_column

_ROTATE = (
    "Revoke or rotate the credential, remove it from Git history, and store the "
    "replacement in a secret manager."
)
_OWASP = ("https://owasp.org/www-project-top-10-for-large-language-model-applications/",)
_GITHUB_SECRET_GUIDANCE = (
    "https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning",
)


def _secret_rule(
    number: int,
    name: str,
    description: str,
    pattern: str,
    *,
    severity: Severity = Severity.CRITICAL,
    confidence: Confidence = Confidence.HIGH,
    references: tuple[str, ...] = _GITHUB_SECRET_GUIDANCE,
    tags: tuple[str, ...] = (),
) -> Rule:
    return Rule(
        id=f"IV-SEC-{number:03d}",
        name=name,
        description=description,
        category=Category.SECRET,
        severity=severity,
        confidence=confidence,
        message=f"Possible {name.lower()} detected.",
        remediation=_ROTATE,
        references=references,
        pattern=pattern,
        detection_type="regex-context",
        tags=("secret", *tags),
    )


SECRET_RULES: tuple[Rule, ...] = (
    _secret_rule(
        1,
        "AWS access key ID",
        "An AWS access key identifier with a provider-specific prefix.",
        r"(?<![A-Z0-9])(?P<secret>(?-i:(?:AKIA|ASIA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}))(?![A-Z0-9])",
        references=("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",),
        tags=("aws",),
    ),
    _secret_rule(
        2,
        "GitHub classic token",
        "A GitHub token using a classic provider prefix.",
        r"(?<![A-Za-z0-9_])(?P<secret>(?-i:gh[opusr]_[A-Za-z0-9]{36,255}))(?![A-Za-z0-9_])",
        tags=("github",),
    ),
    _secret_rule(
        3,
        "GitHub fine-grained token",
        "A GitHub fine-grained personal access token.",
        r"(?<![A-Za-z0-9_])(?P<secret>(?-i:github_pat_[A-Za-z0-9_]{40,255}))(?![A-Za-z0-9_])",
        tags=("github",),
    ),
    _secret_rule(
        4,
        "GitLab personal access token",
        "A GitLab token using the glpat provider prefix.",
        r"(?<![A-Za-z0-9_-])(?P<secret>(?-i:glpat-[A-Za-z0-9_-]{20,255}))(?![A-Za-z0-9_-])",
        references=("https://docs.gitlab.com/user/profile/personal_access_tokens/",),
        tags=("gitlab",),
    ),
    _secret_rule(
        5,
        "Google API key",
        "A Google API key with the AIza prefix.",
        r"(?<![A-Za-z0-9_-])(?P<secret>(?-i:AIza[0-9A-Za-z_-]{35}))(?![A-Za-z0-9_-])",
        references=("https://cloud.google.com/docs/authentication/api-keys-best-practices",),
        tags=("google",),
    ),
    _secret_rule(
        6,
        "Google service-account private key",
        "A private key embedded in a Google service-account JSON field.",
        r"[\"']private_key[\"']\s*:\s*[\"'](?P<secret>-----BEGIN (?:RSA )?PRIVATE KEY-----)",
        references=("https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",),
        tags=("google", "private-key"),
    ),
    _secret_rule(
        7,
        "Azure Storage account key",
        "A base64 storage key assigned to an Azure account-key setting.",
        r"(?:AccountKey|AZURE(?:_STORAGE)?_ACCOUNT_KEY|azureStorageKey)\s*(?:=|:)\s*[\"']?(?P<secret>[A-Za-z0-9+/]{86}==)[\"']?",
        references=("https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage",),
        tags=("azure",),
    ),
    _secret_rule(
        8,
        "OpenAI API key",
        "An OpenAI API key with a provider-specific prefix.",
        r"(?<![A-Za-z0-9_-])(?P<secret>(?-i:sk-(?!live_|test_)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,255}))(?![A-Za-z0-9_-])",
        references=("https://platform.openai.com/docs/guides/production-best-practices/api-keys",),
        tags=("openai",),
    ),
    _secret_rule(
        9,
        "Anthropic API key",
        "An Anthropic API key with a provider-specific prefix.",
        r"(?<![A-Za-z0-9_-])(?P<secret>(?-i:sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,255}))(?![A-Za-z0-9_-])",
        references=("https://docs.anthropic.com/en/api/getting-started",),
        tags=("anthropic",),
    ),
    _secret_rule(
        10,
        "Stripe secret key",
        "A Stripe live or test secret key.",
        r"(?<![A-Za-z0-9_])(?P<secret>(?-i:sk_(?:live|test)_[A-Za-z0-9]{16,255}))(?![A-Za-z0-9])",
        references=("https://docs.stripe.com/keys-best-practices",),
        tags=("stripe",),
    ),
    _secret_rule(
        11,
        "Slack token",
        "A Slack workspace or application token.",
        r"(?<![A-Za-z0-9-])(?P<secret>(?-i:xox[baprs]-[A-Za-z0-9-]{10,255}))(?![A-Za-z0-9-])",
        references=("https://api.slack.com/authentication/best-practices",),
        tags=("slack",),
    ),
    _secret_rule(
        12,
        "Slack incoming webhook",
        "A complete Slack incoming-webhook URL.",
        r"(?P<secret>https://hooks\.slack\.com/services/[A-Z0-9]{8,16}/[A-Z0-9]{8,16}/[A-Za-z0-9]{20,64})",
        references=("https://api.slack.com/messaging/webhooks",),
        tags=("slack", "webhook"),
    ),
    _secret_rule(
        13,
        "Discord webhook",
        "A complete Discord webhook URL containing its token.",
        r"(?P<secret>https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d{15,22}/[A-Za-z0-9._-]{30,255})",
        references=("https://discord.com/developers/docs/resources/webhook",),
        tags=("discord", "webhook"),
    ),
    _secret_rule(
        14,
        "Telegram bot token",
        "A Telegram Bot API token.",
        r"(?<!\d)(?P<secret>\d{8,12}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])",
        references=("https://core.telegram.org/bots/features#botfather",),
        tags=("telegram",),
    ),
    _secret_rule(
        15,
        "Twilio auth token",
        "A Twilio authentication token in a Twilio-specific assignment.",
        r"(?:TWILIO_AUTH_TOKEN|twilio[_-]?(?:auth[_-]?)?token)\s*(?:=|:)\s*[\"']?(?P<secret>(?-i:[a-f0-9]{32}))[\"']?",
        references=("https://www.twilio.com/docs/usage/secure-credentials",),
        tags=("twilio",),
    ),
    _secret_rule(
        16,
        "SendGrid API key",
        "A SendGrid API key with its structured prefix.",
        r"(?<![A-Za-z0-9._-])(?P<secret>(?-i:SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}))(?![A-Za-z0-9._-])",
        references=("https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys",),
        tags=("sendgrid",),
    ),
    _secret_rule(
        17,
        "Firebase credential",
        "A Firebase CLI or legacy database credential in a contextual assignment.",
        r"(?:FIREBASE_(?:TOKEN|SECRET)|firebase[_-]?(?:token|secret)|databaseAuthVariableOverride)\s*(?:=|:)\s*[\"']?(?P<secret>[A-Za-z0-9._~-]{24,255})[\"']?",
        references=("https://firebase.google.com/docs/projects/api-keys",),
        tags=("firebase",),
    ),
    _secret_rule(
        18,
        "JSON Web Token",
        "A compact, signed JSON Web Token.",
        r"(?<![A-Za-z0-9_-])(?P<secret>(?-i:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}))(?![A-Za-z0-9_-])",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        references=("https://datatracker.ietf.org/doc/html/rfc8725",),
        tags=("jwt",),
    ),
    _secret_rule(
        19,
        "Bearer token",
        "A long bearer token in an authorization context.",
        r"\bBearer[ \t]+(?P<secret>[A-Za-z0-9._~+/-]{20,2048}=*)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        references=_OWASP,
        tags=("authorization",),
    ),
    _secret_rule(
        20,
        "Database URL with credentials",
        "A database connection URL containing a username and password.",
        r"(?P<secret>(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@]+:[^\s/@]+@[^\s\"']+)",
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",),
        tags=("database",),
    ),
    _secret_rule(
        21,
        "RSA private key",
        "A PEM-encoded RSA private-key boundary.",
        r"(?P<secret>-----BEGIN RSA PRIVATE KEY-----)",
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",),
        tags=("private-key",),
    ),
    _secret_rule(
        22,
        "OpenSSH private key",
        "An OpenSSH private-key boundary.",
        r"(?P<secret>-----BEGIN OPENSSH PRIVATE KEY-----)",
        references=("https://www.ssh.com/academy/ssh/keygen",),
        tags=("private-key", "ssh"),
    ),
    _secret_rule(
        23,
        "EC private key",
        "A PEM-encoded elliptic-curve private-key boundary.",
        r"(?P<secret>-----BEGIN EC PRIVATE KEY-----)",
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",),
        tags=("private-key",),
    ),
    _secret_rule(
        24,
        "PGP private key",
        "An ASCII-armored PGP private-key boundary.",
        r"(?P<secret>-----BEGIN PGP PRIVATE KEY BLOCK-----)",
        references=("https://www.gnupg.org/gph/en/manual.html",),
        tags=("private-key", "pgp"),
    ),
    _secret_rule(
        25,
        "Password assignment",
        "A non-placeholder value assigned to a password-like variable.",
        r"\b(?:password|passwd|pwd|passphrase|db_pass(?:word)?|client_secret)\b\s*(?:=|:)\s*(?P<quote>[\"']?)(?P<secret>[^\s\"']{8,512})(?P=quote)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        references=_OWASP,
        tags=("generic", "context"),
    ),
    _secret_rule(
        26,
        "API token assignment",
        "A non-placeholder token assigned to a secret-bearing variable.",
        r"\b(?:api[_-]?(?:key|token|secret)|access[_-]?token|auth[_-]?token|secret[_-]?key)\b\s*(?:=|:)\s*(?P<quote>[\"']?)(?P<secret>[A-Za-z0-9._~+/-]{16,2048}=*)(?P=quote)",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        references=_OWASP,
        tags=("generic", "context"),
    ),
    Rule(
        id="IV-SEC-027",
        name="High-entropy credential candidate",
        description="A long, random-looking value in a secret-bearing assignment.",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        message="Possible high-entropy credential detected.",
        remediation=_ROTATE,
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",),
        pattern=r"(?<![A-Za-z0-9_+/=-])(?P<secret>[A-Za-z0-9_+/=-]{24,512})(?![A-Za-z0-9_+/=-])",
        detection_type="entropy-context",
        tags=("secret", "entropy", "context"),
    ),
)

RULES = SECRET_RULES
_RULE_BY_ID = {rule.id: rule for rule in SECRET_RULES}
_GENERIC_RULE_IDS = {"IV-SEC-025", "IV-SEC-026"}
_PRIVATE_KEY_RULE_IDS = {
    "IV-SEC-006",
    "IV-SEC-021",
    "IV-SEC-022",
    "IV-SEC-023",
    "IV-SEC-024",
}
_MAX_PRIVATE_KEY_MATERIAL = 64 * 1024
_PLACEHOLDER_WORDS = {
    "example",
    "changeme",
    "yourtokenhere",
    "testtoken",
    "dummy",
    "placeholder",
    "redacted",
    "xxxxx",
    "syntheticfixture",
    "notasecret",
}
_SENSITIVE_NAMES = re.compile(
    r"(?:secret|token|api[_-]?key|access[_-]?key|account[_-]?key|password|passwd|pwd|credential|auth|private[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"[\"']?(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,100})[\"']?\s*(?:=|:)\s*(?P<quote>[\"']?)"
    r"(?P<secret>[^\s\"',;#}\]]{4,2048})(?P=quote)",
    re.IGNORECASE,
)
_ENTROPY_CANDIDATE = re.compile(_RULE_BY_ID["IV-SEC-027"].pattern or "")
_LOW_SIGNAL_SUFFIXES = {".md", ".rst", ".txt", ".csv", ".lock", ".map"}
_EMBEDDED_PROVIDER_SECRET = re.compile(
    r"(?-i:(?:AKIA|ASIA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}"
    r"|gh[opusr]_[A-Za-z0-9]{36,255}"
    r"|github_pat_[A-Za-z0-9_]{40,255}"
    r"|glpat-[A-Za-z0-9_-]{20,255}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|sk-(?!live_|test_)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,255}"
    r"|sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,255}"
    r"|sk_(?:live|test)_[A-Za-z0-9]{16,255}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,255}"
    r"|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"
    r"|eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,8192})"
)


def is_obvious_placeholder(value: str) -> bool:
    """Recognize explicit fixture markers without broad substring allowlisting."""

    candidate = value.strip().strip("\"'` ").lower()
    normalized = re.sub(r"[^a-z0-9]", "", candidate)
    if normalized in _PLACEHOLDER_WORDS:
        return True
    if re.fullmatch(r"(?:your|insert|replace|set)(?:[a-z0-9]*)(?:here|me)", normalized):
        return True
    if re.fullmatch(r"syntheticfixture\d*", normalized):
        return True
    if len(candidate) >= 8 and len(set(candidate)) == 1:
        return True
    return bool(re.fullmatch(r"x{5,}|\*{5,}|0{8,}", candidate))


def _masked(value: str) -> str:
    return mask_secret(value)


def _safe_evidence(text: str, start: int, secret: str) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    return line.replace(secret, _masked(secret))


def _overlaps(span: tuple[int, int], claimed: list[tuple[int, int]]) -> bool:
    return any(span[0] < end and start < span[1] for start, end in claimed)


def _secret_material(
    rule_id: str,
    text: str,
    match: re.Match[str],
) -> tuple[str, tuple[int, int]]:
    """Expand a private-key header to its bounded block for identity and redaction."""

    group = "secret" if "secret" in match.groupdict() else 0
    secret = match.group(group)
    span = match.span(group)
    if rule_id not in _PRIVATE_KEY_RULE_IDS:
        return secret, span
    footer = secret.replace("BEGIN", "END", 1)
    search_end = min(len(text), span[0] + _MAX_PRIVATE_KEY_MATERIAL)
    footer_start = text.find(footer, span[1], search_end)
    block_end = search_end if footer_start < 0 else footer_start + len(footer)
    return text[span[0] : block_end], (span[0], block_end)


def _regex_secret_matches(text: str, path: str) -> Iterator[tuple[RuleMatch, tuple[int, int]]]:
    claimed: list[tuple[int, int]] = []
    for rule in SECRET_RULES[:-1]:
        for match in compile_rule(rule).regex.finditer(text):
            secret, span = _secret_material(rule.id, text, match)
            placeholder_probe = secret
            if rule.id == "IV-SEC-020":
                password = re.search(r":([^\s/@]+)@", secret)
                if password:
                    placeholder_probe = password.group(1)
            if is_obvious_placeholder(placeholder_probe):
                continue
            if rule.id in _GENERIC_RULE_IDS and _overlaps(span, claimed):
                continue
            line, column = line_column(text, span[0])
            yield (
                RuleMatch(
                    rule=rule,
                    line=line,
                    column=column,
                    evidence=_safe_evidence(text, span[0], secret),
                    metadata=(
                        ("detector", "regex-context"),
                        ("path", path),
                        ("_fingerprint_digest", material_digest(secret)),
                    ),
                ),
                span,
            )
            if rule.id not in _GENERIC_RULE_IDS:
                claimed.append(span)


def _entropy_matches(
    text: str,
    path: str,
    claimed: list[tuple[int, int]],
) -> Iterator[RuleMatch]:
    rule = _RULE_BY_ID["IV-SEC-027"]
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.lower()
    for match in _ENTROPY_CANDIDATE.finditer(text):
        value = match.group("secret")
        span = match.span("secret")
        if _overlaps(span, claimed) or is_obvious_placeholder(value):
            continue
        if len(set(value)) < 8:
            continue
        line_start = text.rfind("\n", 0, span[0]) + 1
        prefix = text[line_start : span[0]]
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_.-]{1,80})\s*(?:=|:)\s*[\"']?$", prefix)
        if not name_match or not _SENSITIVE_NAMES.search(name_match.group(1)):
            continue
        threshold = 4.15 if suffix in _LOW_SIGNAL_SUFFIXES else 3.6
        entropy = shannon_entropy(value)
        if entropy < threshold:
            continue
        line, column = line_column(text, span[0])
        yield RuleMatch(
            rule=rule,
            line=line,
            column=column,
            evidence=_safe_evidence(text, span[0], value),
            metadata=(
                ("detector", "entropy-context"),
                ("entropy", round(entropy, 3)),
                ("variable", name_match.group(1)),
                ("path", path),
                ("_fingerprint_digest", material_digest(value)),
            ),
        )


def _redaction_spans(text: str, path: str) -> tuple[tuple[int, int], ...]:
    """Locate all credential material in a bounded evidence string."""

    spans: list[tuple[int, int]] = []
    claimed: list[tuple[int, int]] = []
    spans.extend(match.span() for match in _EMBEDDED_PROVIDER_SECRET.finditer(text))
    for match in _SENSITIVE_ASSIGNMENT.finditer(text):
        candidate = match.group("secret")
        if (
            _SENSITIVE_NAMES.search(match.group("name"))
            and "<redacted:" not in candidate.casefold()
            and not is_obvious_placeholder(candidate)
        ):
            spans.append(match.span("secret"))
    for rule in SECRET_RULES[:-1]:
        for match in compile_rule(rule).regex.finditer(text):
            secret, span = _secret_material(rule.id, text, match)
            placeholder_probe = secret
            if rule.id == "IV-SEC-020":
                password = re.search(r":([^\s/@]+)@", secret)
                if password:
                    placeholder_probe = password.group(1)
            if is_obvious_placeholder(placeholder_probe):
                continue
            spans.append(span)
            if rule.id not in _GENERIC_RULE_IDS:
                claimed.append(span)

    suffix = PurePosixPath(path.replace("\\", "/")).suffix.lower()
    for match in _ENTROPY_CANDIDATE.finditer(text):
        value = match.group("secret")
        span = match.span("secret")
        if _overlaps(span, claimed) or is_obvious_placeholder(value) or len(set(value)) < 8:
            continue
        line_start = text.rfind("\n", 0, span[0]) + 1
        prefix = text[line_start : span[0]]
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_.-]{1,80})\s*(?:=|:)\s*[\"']?$", prefix)
        if not name_match or not _SENSITIVE_NAMES.search(name_match.group(1)):
            continue
        threshold = 4.15 if suffix in _LOW_SIGNAL_SUFFIXES else 3.6
        if shannon_entropy(value) >= threshold:
            spans.append(span)
    return tuple(spans)


def redact_secrets(value: str, path: str = "") -> str:
    """Remove every detected secret from arbitrary detector or reporter evidence."""

    return redact_spans(value, _redaction_spans(value, path))


def secret_values_for_redaction(value: str, path: str = "") -> tuple[str, ...]:
    """Return in-memory values that a boundary should exact-redact across related fields."""

    return tuple(value[start:end] for start, end in _redaction_spans(value, path))


def detect_secret_matches(text: str, path: str = "") -> tuple[RuleMatch, ...]:
    """Detect secrets in decoded text while suppressing explicit placeholders.

    Returned evidence is masked here, before it reaches scanner or reporter code.
    """

    regex_matches = list(_regex_secret_matches(text, path))
    claimed = [span for match, span in regex_matches if match.rule.id not in _GENERIC_RULE_IDS]
    matches = [match for match, _ in regex_matches]
    matches.extend(_entropy_matches(text, path, claimed))
    sanitized = [replace(match, evidence=redact_secrets(match.evidence, path)[:240]) for match in matches]
    return tuple(sorted(sanitized, key=lambda item: (item.line, item.column, item.rule.id)))


def get_rules() -> tuple[Rule, ...]:
    """Return the stable secret rule pack."""

    return SECRET_RULES
