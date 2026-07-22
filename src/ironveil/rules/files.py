"""Repository path and file-metadata rules.

These detectors never open files. Discovery supplies the relative path and
metadata, which keeps size checks cheap and makes Git-ignore behavior explicit.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import RuleMatch, compile_rule


def _file_rule(
    number: int,
    name: str,
    description: str,
    pattern: str | None,
    *,
    severity: Severity,
    confidence: Confidence = Confidence.HIGH,
    category: Category = Category.SENSITIVE_FILE,
    detection_type: str = "path",
    tags: tuple[str, ...] = (),
    remediation: str | None = None,
) -> Rule:
    return Rule(
        id=f"IV-FILE-{number:03d}",
        name=name,
        description=description,
        category=category,
        severity=severity,
        confidence=confidence,
        message=f"{name} detected in the repository.",
        remediation=remediation
        or (
            "Remove the file from version control, rotate any exposed credentials, "
            "and add a narrowly scoped ignore rule where appropriate."
        ),
        references=(
            "https://docs.github.com/en/repositories/working-with-files/managing-files/ignoring-files",
        ),
        pattern=pattern,
        detection_type=detection_type,
        tags=("repository", *tags),
    )


FILE_RULES: tuple[Rule, ...] = (
    _file_rule(
        1,
        "Environment file",
        "An environment file commonly used to hold local secrets.",
        r"(?:^|/)\.env(?:$|\.(?![^/]*(?:example|sample|template|dist)$)[^/]+$)",
        severity=Severity.HIGH,
        tags=("environment",),
    ),
    _file_rule(
        2,
        "Credential document",
        "A credential or service-account document with a sensitive conventional name.",
        r"(?:^|/)(?:credentials?(?:\.[^/]+)?\.json|credentials?\.json|service[-_]?account(?:[-_.][^/]*)?\.json|application_default_credentials\.json)$",
        severity=Severity.CRITICAL,
        tags=("credential",),
    ),
    _file_rule(
        3,
        "SSH private-key file",
        "A conventional SSH private-key filename.",
        r"(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$",
        severity=Severity.CRITICAL,
        tags=("private-key", "ssh"),
    ),
    _file_rule(
        4,
        "Private-key or certificate container",
        "A file extension frequently used for private keys or certificate bundles.",
        r"(?:^|/)[^/]+\.(?:pem|key|p12|pfx|pkcs12)$",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        tags=("private-key", "certificate"),
    ),
    _file_rule(
        5,
        "Keystore file",
        "A Java or platform keystore that may contain private keys.",
        r"(?:^|/)[^/]+\.(?:jks|keystore|truststore|bks)$",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        tags=("keystore",),
    ),
    _file_rule(
        6,
        "Database dump",
        "A database dump or portable database file.",
        r"(?:^|/)(?:[^/]+\.(?:sql|dump|dmp|sqlite3?|db)|dump\.rdb)$",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        tags=("database", "backup"),
    ),
    _file_rule(
        7,
        "Backup archive",
        "A backup file or archive likely to bypass source-level controls.",
        r"(?:^|/)(?:[^/]+\.(?:bak|backup|old|orig|save|tar|tgz|zip|7z|rar)|[^/]+\.tar\.(?:gz|bz2|xz))$",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        tags=("backup",),
    ),
    _file_rule(
        8,
        "Debug log",
        "A debug or application log that may expose runtime data.",
        r"(?:^|/)(?:debug(?:[-_.][^/]*)?\.log|[^/]+\.debug\.log|npm-debug\.log|yarn-(?:debug|error)\.log)$",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        tags=("log",),
    ),
    _file_rule(
        9,
        "Local configuration file",
        "A developer-local configuration file likely to contain machine-specific values.",
        r"(?:^|/)(?:\.npmrc|\.pypirc|\.netrc|\.envrc|config\.local\.[^/]+|settings\.local\.[^/]+|application-local\.(?:ya?ml|properties))$",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        tags=("configuration",),
    ),
    _file_rule(
        10,
        "Oversized repository file",
        "A file exceeds the configured repository scanning size threshold.",
        None,
        severity=Severity.MEDIUM,
        category=Category.REPOSITORY,
        detection_type="metadata",
        tags=("size",),
        remediation=(
            "Move large artifacts to an artifact store or Git LFS, and keep scanner size limits bounded."
        ),
    ),
    _file_rule(
        11,
        "Generated or dependency directory",
        "A generated, cache, build, or vendored directory is present in scan scope.",
        r"(?:^|/)(?:node_modules|\.venv|venv|dist|build|__pycache__|\.cache|coverage|target|vendor|\.idea|\.vscode|\.vs)(?:/|$)",
        severity=Severity.LOW,
        category=Category.REPOSITORY,
        detection_type="path-metadata",
        tags=("junk",),
        remediation=(
            "Remove generated or dependency content from version control and add the directory to "
            "the appropriate ignore file."
        ),
    ),
)

RULES = FILE_RULES
_PATH_RULES = FILE_RULES[:9]
_LARGE_RULE = FILE_RULES[9]
_JUNK_RULE = FILE_RULES[10]


def _normalize(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


def _is_vendor_applicable(path: str, vendor_applicable: bool) -> bool:
    """Require ecosystem evidence before treating a generic vendor path as junk."""

    parts = PurePosixPath(path).parts
    if "vendor" not in parts:
        return True
    return vendor_applicable


def match_file_rules(
    path: str,
    *,
    size_bytes: int | None = None,
    tracked: bool | None = None,
    ignored: bool = False,
    all_files: bool = False,
    max_size_bytes: int = 10 * 1024 * 1024,
    contains_sensitive_data: bool | None = None,
    vendor_applicable: bool = False,
) -> tuple[RuleMatch, ...]:
    """Match path and metadata rules for a repository-relative path.

    Ignored junk directories are intentionally quiet unless ``all_files`` is
    enabled. Sensitive filenames remain reportable when a caller explicitly
    supplies them, because ignore state alone does not remove committed data.
    """

    normalized = _normalize(path)
    metadata: tuple[tuple[str, str | int | float | bool], ...] = (
        ("path", normalized),
        ("ignored", ignored),
        ("all_files", all_files),
        *((("tracked", tracked),) if tracked is not None else ()),
        *(
            (("contains_sensitive_data", contains_sensitive_data),)
            if contains_sensitive_data is not None
            else ()
        ),
    )
    matches: list[RuleMatch] = []
    for rule in _PATH_RULES:
        if compile_rule(rule).regex.search(normalized):
            matches.append(RuleMatch(rule=rule, line=1, evidence=normalized, metadata=metadata))

    if size_bytes is not None and max_size_bytes > 0 and size_bytes > max_size_bytes:
        matches.append(
            RuleMatch(
                rule=_LARGE_RULE,
                line=1,
                evidence=normalized,
                metadata=(*metadata, ("size_bytes", size_bytes), ("max_size_bytes", max_size_bytes)),
            )
        )

    if (
        (all_files or not ignored)
        and compile_rule(_JUNK_RULE).regex.search(normalized)
        and _is_vendor_applicable(normalized, vendor_applicable)
    ):
        matches.append(RuleMatch(rule=_JUNK_RULE, line=1, evidence=normalized, metadata=metadata))

    # Defensive de-duplication keeps path aliases from producing repeated rules.
    by_id = {match.rule.id: match for match in matches}
    return tuple(by_id[rule_id] for rule_id in sorted(by_id))


def get_rules() -> tuple[Rule, ...]:
    return FILE_RULES
