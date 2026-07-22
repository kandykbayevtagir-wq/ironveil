"""Configuration loading and validation for ``.ironveil.toml``."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tomllib
from dataclasses import asdict, dataclass, field
from datetime import date
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, TypeVar

from ironveil.exceptions import ConfigurationError
from ironveil.models import Category, Confidence, Severity

EnumValue = TypeVar("EnumValue", Severity, Confidence, Category)
MAX_CONFIG_BYTES = 1024 * 1024


@dataclass(slots=True)
class ScanConfig:
    max_size_mb: float = 10.0
    workers: int = max(1, min(32, (os.cpu_count() or 2) + 4))
    respect_gitignore: bool = True
    follow_symlinks: bool = False
    scan_binary: bool = False
    tracked_only: bool = False
    all_files: bool = False
    use_cache: bool = True
    exclude: list[str] = field(default_factory=list)

    @property
    def max_size_bytes(self) -> int:
        return int(self.max_size_mb * 1024 * 1024)


@dataclass(slots=True)
class PolicyConfig:
    fail_severity: Severity = Severity.HIGH
    minimum_confidence: Confidence = Confidence.MEDIUM
    fail_on: list[Category] = field(
        default_factory=lambda: [Category.SECRET, Category.DEPENDENCY, Category.IAC, Category.SCAN_ERROR]
    )
    no_fail: bool = False


@dataclass(slots=True)
class HistoryConfig:
    enabled: bool = False
    max_commits: int = 500


@dataclass(slots=True)
class DependencyConfig:
    online: bool = False
    timeout_seconds: float = 10.0
    retries: int = 1


@dataclass(slots=True)
class UIConfig:
    open_browser: bool = True
    host: str = "127.0.0.1"
    port: int = 8765


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    rule: str
    path: str
    reason: str
    expires: str | None = None

    def matches(self, rule_id: str, relative_path: str) -> bool:
        return (self.rule == "*" or self.rule == rule_id) and fnmatch(relative_path, self.path)


@dataclass(frozen=True, slots=True)
class CustomRuleConfig:
    id: str
    name: str
    category: Category
    severity: Severity
    confidence: Confidence
    regex: str
    message: str
    remediation: str
    description: str = "User-defined declarative rule"


@dataclass(slots=True)
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)
    dependencies: DependencyConfig = field(default_factory=DependencyConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    allowlist: list[AllowlistEntry] = field(default_factory=list)
    rules: list[CustomRuleConfig] = field(default_factory=list)
    source: Path | None = None

    def digest(self) -> str:
        value = asdict(self)
        value.pop("source", None)
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=_json_default)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _json_default(value: Any) -> str:
    if isinstance(value, (Path, Severity, Confidence, Category)):
        return str(value.value if isinstance(value, (Severity, Confidence, Category)) else value)
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def _mapping(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigurationError(f"{field_name}: expected a TOML table, got {value!r}")
    return value


def _enum(enum_type: type[EnumValue], value: Any, field_name: str) -> EnumValue:
    try:
        return enum_type(str(value))
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise ConfigurationError(
            f"{field_name}: invalid value {value!r}; expected one of: {allowed}"
        ) from exc


def _bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{field_name}: expected true or false, got {value!r}")
    return value


def _number(value: Any, field_name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
        raise ConfigurationError(
            f"{field_name}: expected a number from {minimum:g} to {maximum:g}, got {value!r}"
        )
    return float(value)


def _integer(value: Any, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigurationError(
            f"{field_name}: expected an integer from {minimum} to {maximum}, got {value!r}"
        )
    return value


def _unknown(table: dict[str, Any], allowed: set[str], prefix: str) -> None:
    extras = sorted(set(table) - allowed)
    if extras:
        raise ConfigurationError(f"{prefix}.{extras[0]}: unknown configuration field")


def load_config(root: Path, explicit: Path | None = None) -> Config:
    """Load and validate configuration, or return secure defaults."""

    root = root.expanduser().resolve()
    path = explicit or root / ".ironveil.toml"
    path = path.expanduser()
    if explicit is None and path.is_symlink():
        raise ConfigurationError(f"config: refusing implicit symlink: {path}")
    if not path.exists():
        if explicit:
            raise ConfigurationError(f"config: file does not exist: {path}")
        return Config()
    try:
        flags = os.O_RDONLY
        if explicit is None and hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise ConfigurationError(f"config: expected a regular file: {path}")
            if file_stat.st_size > MAX_CONFIG_BYTES:
                raise ConfigurationError(
                    f"config: file exceeds the {MAX_CONFIG_BYTES // 1024} KiB safety limit: {path}"
                )
            payload = handle.read(MAX_CONFIG_BYTES + 1)
        if len(payload) > MAX_CONFIG_BYTES:
            raise ConfigurationError(
                f"config: file exceeds the {MAX_CONFIG_BYTES // 1024} KiB safety limit: {path}"
            )
        raw = tomllib.loads(payload.decode("utf-8"))
    except ConfigurationError:
        raise
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"config: cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("config: top-level TOML value must be a table")
    allowed_root = {"scan", "policy", "history", "dependencies", "ui", "allowlist", "rules", "exclude"}
    _unknown(raw, allowed_root, "config")
    config = Config(source=path.resolve())
    _load_scan(config, _mapping(raw.get("scan"), "scan"), raw.get("exclude"))
    _load_policy(config, _mapping(raw.get("policy"), "policy"))
    _load_history(config, _mapping(raw.get("history"), "history"))
    _load_dependencies(config, _mapping(raw.get("dependencies"), "dependencies"))
    _load_ui(config, _mapping(raw.get("ui"), "ui"))
    config.allowlist = _load_allowlist(raw.get("allowlist", []))
    config.rules = _load_custom_rules(raw.get("rules", []))
    return config


def _load_scan(config: Config, table: dict[str, Any], root_exclude: Any) -> None:
    allowed = {
        "max_size_mb",
        "workers",
        "respect_gitignore",
        "follow_symlinks",
        "scan_binary",
        "tracked_only",
        "all_files",
        "use_cache",
        "exclude",
    }
    _unknown(table, allowed, "scan")
    if "max_size_mb" in table:
        config.scan.max_size_mb = _number(table["max_size_mb"], "scan.max_size_mb", 0.001, 1024)
    if "workers" in table:
        config.scan.workers = _integer(table["workers"], "scan.workers", 1, 256)
    for name in (
        "respect_gitignore",
        "follow_symlinks",
        "scan_binary",
        "tracked_only",
        "all_files",
        "use_cache",
    ):
        if name in table:
            setattr(config.scan, name, _bool(table[name], f"scan.{name}"))
    if config.scan.tracked_only and config.scan.all_files:
        raise ConfigurationError("scan.tracked_only and scan.all_files are mutually exclusive")
    excludes = table.get("exclude", root_exclude if root_exclude is not None else [])
    if not isinstance(excludes, list) or not all(isinstance(item, str) and item for item in excludes):
        raise ConfigurationError("scan.exclude: expected an array of non-empty glob strings")
    config.scan.exclude = list(excludes)


def _load_policy(config: Config, table: dict[str, Any]) -> None:
    _unknown(table, {"fail_severity", "minimum_confidence", "fail_on", "no_fail"}, "policy")
    if "fail_severity" in table:
        config.policy.fail_severity = _enum(Severity, table["fail_severity"], "policy.fail_severity")
    if "minimum_confidence" in table:
        config.policy.minimum_confidence = _enum(
            Confidence, table["minimum_confidence"], "policy.minimum_confidence"
        )
    if "fail_on" in table:
        values = table["fail_on"]
        if not isinstance(values, list):
            raise ConfigurationError("policy.fail_on: expected an array of categories")
        aliases = {"error": "scan-error", "file": "sensitive-file"}
        config.policy.fail_on = [
            _enum(Category, aliases.get(str(item), item), f"policy.fail_on[{index}]")
            for index, item in enumerate(values)
        ]
    if "no_fail" in table:
        config.policy.no_fail = _bool(table["no_fail"], "policy.no_fail")


def _load_history(config: Config, table: dict[str, Any]) -> None:
    _unknown(table, {"enabled", "max_commits"}, "history")
    if "enabled" in table:
        config.history.enabled = _bool(table["enabled"], "history.enabled")
    if "max_commits" in table:
        config.history.max_commits = _integer(table["max_commits"], "history.max_commits", 1, 1_000_000)


def _load_dependencies(config: Config, table: dict[str, Any]) -> None:
    _unknown(table, {"online", "timeout_seconds", "retries"}, "dependencies")
    if "online" in table:
        config.dependencies.online = _bool(table["online"], "dependencies.online")
    if "timeout_seconds" in table:
        config.dependencies.timeout_seconds = _number(
            table["timeout_seconds"], "dependencies.timeout_seconds", 0.1, 120
        )
    if "retries" in table:
        config.dependencies.retries = _integer(table["retries"], "dependencies.retries", 0, 5)


def _load_ui(config: Config, table: dict[str, Any]) -> None:
    _unknown(table, {"open_browser", "host", "port"}, "ui")
    if "open_browser" in table:
        config.ui.open_browser = _bool(table["open_browser"], "ui.open_browser")
    if "host" in table:
        if table["host"] != "127.0.0.1":
            raise ConfigurationError("ui.host: only 127.0.0.1 is allowed")
        config.ui.host = table["host"]
    if "port" in table:
        config.ui.port = _integer(table["port"], "ui.port", 1, 65535)


def _load_allowlist(value: Any) -> list[AllowlistEntry]:
    if not isinstance(value, list):
        raise ConfigurationError("allowlist: expected one or more [[allowlist]] tables")
    result: list[AllowlistEntry] = []
    for index, item in enumerate(value):
        table = _mapping(item, f"allowlist[{index}]")
        _unknown(table, {"rule", "path", "reason", "expires"}, f"allowlist[{index}]")
        for required in ("rule", "path", "reason"):
            if not isinstance(table.get(required), str) or not table[required].strip():
                raise ConfigurationError(f"allowlist[{index}].{required}: expected a non-empty string")
        expires = table.get("expires")
        if expires is not None:
            expires = str(expires)
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires):
                raise ConfigurationError(f"allowlist[{index}].expires: expected YYYY-MM-DD")
            try:
                date.fromisoformat(expires)
            except ValueError as exc:
                raise ConfigurationError(
                    f"allowlist[{index}].expires: invalid calendar date {expires!r}"
                ) from exc
        result.append(AllowlistEntry(table["rule"], table["path"], table["reason"], expires))
    return result


def _load_custom_rules(value: Any) -> list[CustomRuleConfig]:
    if not isinstance(value, list):
        raise ConfigurationError("rules: expected one or more [[rules]] tables")
    result: list[CustomRuleConfig] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        table = _mapping(item, f"rules[{index}]")
        required = {"id", "name", "category", "severity", "confidence", "regex", "message", "remediation"}
        _unknown(table, required | {"description"}, f"rules[{index}]")
        missing = [
            name
            for name in sorted(required)
            if not isinstance(table.get(name), str) or not table[name].strip()
        ]
        if missing:
            raise ConfigurationError(f"rules[{index}].{missing[0]}: expected a non-empty string")
        description = table.get("description", "User-defined declarative rule")
        if not isinstance(description, str):
            raise ConfigurationError(f"rules[{index}].description: expected a string")
        rule_id = table["id"]
        if rule_id in seen:
            raise ConfigurationError(f"rules[{index}].id: duplicate rule ID {rule_id!r}")
        try:
            re.compile(table["regex"])
        except re.error as exc:
            raise ConfigurationError(f"rules[{index}].regex: invalid expression: {exc}") from exc
        seen.add(rule_id)
        result.append(
            CustomRuleConfig(
                id=rule_id,
                name=table["name"],
                category=_enum(Category, table["category"], f"rules[{index}].category"),
                severity=_enum(Severity, table["severity"], f"rules[{index}].severity"),
                confidence=_enum(Confidence, table["confidence"], f"rules[{index}].confidence"),
                regex=table["regex"],
                message=table["message"],
                remediation=table["remediation"],
                description=description,
            )
        )
    return result


DEFAULT_CONFIG = """# IronVeil works without configuration. These are explicit defaults.\n\n[scan]\nmax_size_mb = 10\nworkers = 8\nrespect_gitignore = true\nfollow_symlinks = false\nscan_binary = false\nuse_cache = true\nexclude = []\n\n[policy]\nfail_severity = \"high\"\nminimum_confidence = \"medium\"\nfail_on = [\"secret\", \"dependency\", \"iac\", \"scan-error\"]\n\n[history]\nenabled = false\nmax_commits = 500\n\n[dependencies]\nonline = false\ntimeout_seconds = 10\nretries = 1\n\n[ui]\nopen_browser = true\nhost = \"127.0.0.1\"\nport = 8765\n"""
