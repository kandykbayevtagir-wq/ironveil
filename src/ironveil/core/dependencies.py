"""Offline dependency inventory and explicit opt-in OSV lookups."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ironveil.config import DependencyConfig, ScanConfig
from ironveil.core.cache import default_cache_dir
from ironveil.core.discovery import discover_files
from ironveil.core.fingerprint import fingerprint
from ironveil.models import Category, Confidence, Finding, Severity

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
MAX_OSV_PACKAGES = 1_000
MAX_OSV_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_OSV_CACHE_BYTES = MAX_OSV_RESPONSE_BYTES
SUPPORTED_FILES = {
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}


@dataclass(frozen=True, order=True, slots=True)
class PackageCoordinate:
    ecosystem: str
    name: str
    version: str
    path: str
    line: int = 1


def _python_requirement(value: str, path: str, line: int) -> PackageCoordinate | None:
    stripped = value.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith(("-r", "--", "git+", "http:")):
        return None
    match = re.match(
        r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)[^=\n]*==(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)", stripped
    )
    if not match:
        return None
    return PackageCoordinate("PyPI", match.group("name"), match.group("version"), path, line)


def _from_toml(path: str, text: str) -> list[PackageCoordinate]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    result: list[PackageCoordinate] = []
    if Path(path).name == "pyproject.toml":
        dependencies = data.get("project", {}).get("dependencies", [])
        if isinstance(dependencies, list):
            for value in dependencies:
                if isinstance(value, str):
                    coordinate = _python_requirement(value, path, 1)
                    if coordinate:
                        result.append(coordinate)
    packages = data.get("package", [])
    if isinstance(packages, list):
        for package in packages:
            if (
                isinstance(package, dict)
                and isinstance(package.get("name"), str)
                and isinstance(package.get("version"), str)
            ):
                result.append(PackageCoordinate("PyPI", package["name"], package["version"], path))
    return result


def _from_npm_json(path: str, data: dict[str, Any]) -> list[PackageCoordinate]:
    result: list[PackageCoordinate] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, package in packages.items():
            if not package_path or not isinstance(package, dict):
                continue
            name = package.get("name")
            if not isinstance(name, str):
                name = str(package_path).rsplit("node_modules/", 1)[-1]
            version = package.get("version")
            if isinstance(version, str) and name:
                result.append(PackageCoordinate("npm", name, version, path))
    else:
        dependencies = data.get("dependencies", {})
        if isinstance(dependencies, dict):
            for name, package in dependencies.items():
                if isinstance(package, dict) and isinstance(package.get("version"), str):
                    result.append(PackageCoordinate("npm", name, package["version"], path))
    return result


def _from_pipfile(path: str, data: dict[str, Any]) -> list[PackageCoordinate]:
    result: list[PackageCoordinate] = []
    for section in ("default", "develop"):
        packages = data.get(section, {})
        if not isinstance(packages, dict):
            continue
        for name, metadata in packages.items():
            version = metadata.get("version") if isinstance(metadata, dict) else metadata
            if isinstance(version, str) and version.startswith("=="):
                result.append(PackageCoordinate("PyPI", name, version[2:], path))
    return result


def extract_packages(path: str, text: str) -> list[PackageCoordinate]:
    """Extract pinned package coordinates without executing package-manager code."""

    name = Path(path).name
    result: list[PackageCoordinate] = []
    if name == "requirements.txt":
        for line_number, line in enumerate(text.splitlines(), 1):
            coordinate = _python_requirement(line, path, line_number)
            if coordinate:
                result.append(coordinate)
    elif name in {"pyproject.toml", "poetry.lock", "uv.lock"}:
        result.extend(_from_toml(path, text))
    elif name in {"Pipfile.lock", "package-lock.json", "npm-shrinkwrap.json"}:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            if name == "Pipfile.lock":
                result.extend(_from_pipfile(path, data))
            else:
                result.extend(_from_npm_json(path, data))
    elif name == "yarn.lock":
        current_names: list[str] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                current_names = [
                    part.strip(' "').rsplit("@", 1)[0] for part in line[:-1].split(",") if "@" in part
                ]
            elif current_names and re.match(r"\s+version\s+\"[^\"]+\"", line):
                version = line.split('"', 2)[1]
                result.extend(
                    PackageCoordinate("npm", item, version, path, line_number) for item in current_names
                )
                current_names = []
    elif name == "pnpm-lock.yaml":
        for line_number, line in enumerate(text.splitlines(), 1):
            match = re.match(r"\s{2,}/?(?P<name>@?[^:\s]+(?:/[^:\s]+)?)/(?P<version>[^:\s(]+)", line)
            if match:
                result.append(
                    PackageCoordinate("npm", match.group("name"), match.group("version"), path, line_number)
                )
    return sorted(set(result))


def discover_dependency_files(root: Path, scan_config: ScanConfig | None = None) -> list[Path]:
    """Discover manifests through the same contained, ignore-aware path as a normal scan."""

    root = root.expanduser().resolve()
    discovery = discover_files(root, scan_config or ScanConfig())
    return [path for path in discovery.files if path.name in SUPPORTED_FILES]


def inventory(root: Path, scan_config: ScanConfig | None = None) -> tuple[list[PackageCoordinate], list[str]]:
    """Build a bounded inventory without following ignored or out-of-root symlinks."""

    root = root.expanduser().resolve()
    effective_config = scan_config or ScanConfig()
    discovery = discover_files(root, effective_config)
    packages: list[PackageCoordinate] = []
    warnings = [f"Cannot inspect dependency path {error.path}: {error.message}" for error in discovery.errors]
    for path in discovery.files:
        if path.name not in SUPPORTED_FILES:
            continue
        relative = path.name if root.is_file() and path == root else path.relative_to(root).as_posix()
        try:
            if path.stat().st_size > effective_config.max_size_bytes:
                warnings.append(
                    f"Skipping oversized dependency file {relative} "
                    f"(limit: {effective_config.max_size_bytes} bytes)"
                )
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            warnings.append(f"Cannot read dependency file {relative}: {exc}")
            continue
        packages.extend(extract_packages(relative, text))
    return sorted(set(packages)), warnings


def _cache_key(packages: list[PackageCoordinate]) -> str:
    payload = [(item.ecosystem, item.name, item.version) for item in packages]
    return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()


def _load_osv_cache(
    packages: list[PackageCoordinate], max_age_seconds: int = 86_400
) -> dict[str, Any] | None:
    path = default_cache_dir() / "osv" / f"{_cache_key(packages)}.json"
    try:
        if path.is_symlink():
            return None
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > MAX_OSV_CACHE_BYTES:
                return None
            if time.time() - file_stat.st_mtime > max_age_seconds:
                return None
            payload = handle.read(MAX_OSV_CACHE_BYTES + 1)
        if len(payload) > MAX_OSV_CACHE_BYTES:
            return None
        data = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _store_osv_cache(packages: list[PackageCoordinate], data: dict[str, Any]) -> None:
    directory = default_cache_dir() / "osv"
    temporary_name: str | None = None
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_OSV_CACHE_BYTES:
            return
        destination = directory / f"{_cache_key(packages)}.json"
        descriptor, temporary_name = tempfile.mkstemp(prefix=".ironveil-osv-", dir=directory)
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    except OSError:
        return
    finally:
        if temporary_name is not None:
            with suppress(OSError):
                os.unlink(temporary_name)


def query_osv(
    packages: list[PackageCoordinate],
    config: DependencyConfig,
) -> tuple[list[Finding], list[str]]:
    """Send only package ecosystem/name/version values to OSV when explicitly called."""

    if not packages:
        return [], []
    if len(packages) > MAX_OSV_PACKAGES:
        return [], [
            f"OSV lookup package count exceeds the bounded limit of {MAX_OSV_PACKAGES}; "
            "narrow the repository scope"
        ]
    cached = _load_osv_cache(packages)
    data: dict[str, Any] | None = cached
    warning: str | None = None
    if data is None:
        payload = {
            "queries": [
                {"package": {"ecosystem": item.ecosystem, "name": item.name}, "version": item.version}
                for item in packages
            ]
        }
        request = urllib.request.Request(  # noqa: S310 - fixed HTTPS OSV endpoint
            OSV_QUERY_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "IronVeil/0.1.0"},
            method="POST",
        )
        for attempt in range(config.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:  # noqa: S310
                    body = response.read(MAX_OSV_RESPONSE_BYTES + 1)
                if len(body) > MAX_OSV_RESPONSE_BYTES:
                    warning = "OSV response exceeded the 8 MiB safety limit"
                    break
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict):
                    data = parsed
                    _store_osv_cache(packages, data)
                    warning = None
                    break
            except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
                warning = f"OSV lookup unavailable: {exc}"
                if attempt < config.retries:
                    time.sleep(min(0.25 * (2**attempt), 1.0))
    if data is None:
        return [], [warning or "OSV lookup returned no usable result"]
    results = data.get("results", [])
    if not isinstance(results, list) or len(results) != len(packages):
        return [], ["OSV lookup returned an incomplete result set"]
    findings: list[Finding] = []
    for index, package in enumerate(packages):
        item = results[index]
        vulnerabilities = item.get("vulns", []) if isinstance(item, dict) else []
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            continue
        identifiers = sorted(
            str(vulnerability.get("id"))
            for vulnerability in vulnerabilities
            if isinstance(vulnerability, dict) and vulnerability.get("id")
        )
        joined = ", ".join(identifiers[:5])
        value = f"{package.name}@{package.version}"
        findings.append(
            Finding(
                rule_id="IV-DEP-100",
                rule_name="Known vulnerable dependency",
                category=Category.DEPENDENCY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                path=package.path,
                line=package.line,
                column=1,
                message=f"OSV reports known vulnerabilities for {value}: {joined}",
                remediation="Upgrade to a patched release and verify the resolved dependency graph.",
                fingerprint=fingerprint("IV-DEP-100", package.path, value, joined),
                evidence=value,
                references=tuple(f"https://osv.dev/vulnerability/{item}" for item in identifiers),
                source="dependency-osv",
                metadata={"osv_ids": identifiers, "ecosystem": package.ecosystem},
            )
        )
    return findings, ([warning] if warning else [])
