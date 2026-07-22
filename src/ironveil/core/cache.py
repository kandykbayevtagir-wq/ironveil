"""Small, secret-safe metadata cache stored outside scanned repositories."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat as stat_module
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ironveil.core.masking import redact_values
from ironveil.rules.secrets import redact_secrets, secret_values_for_redaction

CACHE_SCHEMA = 2
RULE_PACK_VERSION = "1"
MAX_CACHE_ENTRY_BYTES = 32 * 1024 * 1024
MAX_CACHE_FINDINGS = 20_000


def default_cache_dir() -> Path:
    override = os.environ.get("IRONVEIL_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "ironveil"
    return Path.home() / ".cache" / "ironveil"


@dataclass(frozen=True, slots=True)
class CacheStats:
    entries: int
    bytes_used: int
    path: Path


class FileCache:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or default_cache_dir()
        self.enabled = True
        try:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            self.enabled = False

    def _key(self, root: Path, path: Path) -> str:
        identity = f"{root.resolve()}\0{path.relative_to(root).as_posix()}"
        return hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()

    def get(self, root: Path, path: Path, config_digest: str) -> list[dict[str, Any]] | None:
        if not self.enabled:
            return None
        try:
            cache_path = self.directory / f"{self._key(root, path)}.json"
            if cache_path.is_symlink():
                return None
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(cache_path, flags)
            with os.fdopen(descriptor, "rb") as handle:
                cache_stat = os.fstat(handle.fileno())
                if not stat_module.S_ISREG(cache_stat.st_mode) or cache_stat.st_size > MAX_CACHE_ENTRY_BYTES:
                    return None
                encoded = handle.read(MAX_CACHE_ENTRY_BYTES + 1)
            if len(encoded) > MAX_CACHE_ENTRY_BYTES:
                return None
            raw = json.loads(encoded.decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(raw, dict):
            return None
        cached_hash = raw.get("content_hash")
        try:
            stat = path.stat()
        except OSError:
            return None
        if (
            raw.get("schema") != CACHE_SCHEMA
            or raw.get("rule_pack_version") != RULE_PACK_VERSION
            or raw.get("config_digest") != config_digest
            or raw.get("size") != stat.st_size
            or raw.get("mtime_ns") != stat.st_mtime_ns
            or not isinstance(cached_hash, str)
        ):
            return None
        try:
            hashed_stat, content_hash = _content_snapshot(path)
        except (OSError, ValueError):
            return None
        if (
            hashed_stat.st_size != stat.st_size
            or hashed_stat.st_mtime_ns != stat.st_mtime_ns
            or not hmac.compare_digest(cached_hash, content_hash)
        ):
            return None
        findings = raw.get("findings")
        if not isinstance(findings, list) or len(findings) > MAX_CACHE_FINDINGS:
            return None
        return findings

    def put(
        self,
        root: Path,
        path: Path,
        config_digest: str,
        content_hash: str,
        findings: list[dict[str, Any]],
    ) -> None:
        if not self.enabled:
            return
        try:
            stat = path.stat()
            payload = {
                "schema": CACHE_SCHEMA,
                "rule_pack_version": RULE_PACK_VERSION,
                "config_digest": config_digest,
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "content_hash": content_hash,
                # Cache detector output, never time-sensitive policy decisions.
                # Suppressions are re-evaluated against today's date and the
                # current source whenever this entry is restored.
                "findings": [_policy_neutral_finding(item) for item in findings],
            }
            destination = self.directory / f"{self._key(root, path)}.json"
            descriptor, temporary_name = tempfile.mkstemp(prefix=".ironveil-", dir=self.directory)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                os.replace(temporary_name, destination)
            except BaseException:
                with suppress(OSError):
                    os.unlink(temporary_name)
                raise
        except OSError:
            self.enabled = False

    def stats(self) -> CacheStats:
        if not self.directory.exists():
            return CacheStats(0, 0, self.directory)
        entries = 0
        bytes_used = 0
        for path in self.directory.glob("*.json"):
            try:
                bytes_used += path.stat().st_size
                entries += 1
            except OSError:
                continue
        return CacheStats(entries, bytes_used, self.directory)

    def clear(self) -> int:
        """Remove only IronVeil JSON cache entries and return the count."""

        if not self.directory.exists():
            return 0
        removed = 0
        for path in self.directory.glob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed


def clear_cache_directory(directory: Path | None = None) -> int:
    return FileCache(directory).clear()


def _content_snapshot(path: Path) -> tuple[os.stat_result, str]:
    """Hash a stable file snapshot and return the descriptor metadata used."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    current = path.stat()
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in identity) or any(
        getattr(after, field) != getattr(current, field) for field in identity
    ):
        raise ValueError("file changed while its cache entry was validated")
    return after, digest.hexdigest()


def _policy_neutral_finding(value: dict[str, Any]) -> dict[str, Any]:
    """Copy a finding without policy state or reporter-visible credential text."""

    finding = dict(value)
    finding["baseline"] = False
    finding["suppressed"] = False
    finding["suppression_reason"] = None
    finding["suppression_expires"] = None
    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        finding["metadata"] = {
            str(key): item for key, item in metadata.items() if not str(key).startswith("_")
        }
    path = str(finding.get("path", ""))
    sensitive_values = tuple(sorted(_collect_secret_values(finding, path), key=len, reverse=True))
    sanitized = _cache_safe_value(finding, path, sensitive_values)
    return sanitized if isinstance(sanitized, dict) else {}


def _cache_safe_value(value: Any, path: str, sensitive_values: tuple[str, ...]) -> Any:
    """Recursively remove built-in credential material before cache serialization."""

    if isinstance(value, str):
        return redact_secrets(redact_values(value, sensitive_values), path)
    if isinstance(value, dict):
        return {
            redact_secrets(redact_values(str(key), sensitive_values), path): _cache_safe_value(
                item, path, sensitive_values
            )
            for key, item in value.items()
            if not str(key).startswith("_")
        }
    if isinstance(value, (list, tuple)):
        return [_cache_safe_value(item, path, sensitive_values) for item in value]
    return value


def _collect_secret_values(value: Any, path: str) -> set[str]:
    values: set[str] = set()
    if isinstance(value, str):
        values.update(secret_values_for_redaction(value, path))
    elif isinstance(value, dict):
        for key, item in value.items():
            values.update(secret_values_for_redaction(str(key), path))
            values.update(_collect_secret_values(item, path))
    elif isinstance(value, (list, tuple)):
        for item in value:
            values.update(_collect_secret_values(item, path))
    return values
