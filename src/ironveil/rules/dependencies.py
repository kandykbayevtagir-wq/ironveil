"""Offline dependency-manifest and lockfile security analysis.

The analyzer is intentionally network-free.  It identifies dependency hygiene
risks from repository files and leaves vulnerability lookups to the explicit
online dependency scanner.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from ironveil.models import Category, Confidence, Rule, Severity
from ironveil.rules.base import RuleMatch


def _dependency_rule(
    number: int,
    name: str,
    description: str,
    *,
    severity: Severity,
    confidence: Confidence,
    remediation: str,
    tags: tuple[str, ...],
) -> Rule:
    return Rule(
        id=f"IV-DEP-{number:03d}",
        name=name,
        description=description,
        category=Category.DEPENDENCY,
        severity=severity,
        confidence=confidence,
        message=f"{name} detected in a dependency file.",
        remediation=remediation,
        references=(
            "https://owasp.org/www-project-dependency-check/",
            "https://slsa.dev/spec/v1.0/threats-overview",
        ),
        pattern=None,
        detection_type="manifest",
        tags=("dependency", *tags),
    )


DEPENDENCY_RULES: tuple[Rule, ...] = (
    _dependency_rule(
        1,
        "Unpinned dependency",
        "A direct dependency has no version constraint or immutable reference.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        remediation="Pin direct dependencies and commit the ecosystem lockfile.",
        tags=("pinning",),
    ),
    _dependency_rule(
        2,
        "Wildcard or floating dependency",
        "A dependency accepts a wildcard, range, branch, or floating version.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        remediation="Use a reviewed exact version or lockfile-backed immutable resolution.",
        tags=("pinning", "floating"),
    ),
    _dependency_rule(
        3,
        "Git dependency",
        "A dependency is installed directly from a Git repository.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        remediation="Prefer a trusted registry release, or pin the Git dependency to a full commit SHA.",
        tags=("git", "supply-chain"),
    ),
    _dependency_rule(
        4,
        "Insecure dependency source",
        "A dependency or package index uses unencrypted HTTP or embeds credentials.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        remediation="Use HTTPS from a trusted registry and remove credentials from manifest URLs.",
        tags=("transport", "registry"),
    ),
    _dependency_rule(
        5,
        "Suspicious package name",
        "A package name uses non-ASCII characters or resembles a common package typo.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        remediation="Verify the exact package name, publisher, and provenance before installation.",
        tags=("typosquatting", "supply-chain"),
    ),
    _dependency_rule(
        6,
        "Install lifecycle script",
        "A package manifest defines a preinstall, install, or postinstall script.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        remediation="Review lifecycle scripts and disable them in CI when they are not required.",
        tags=("script", "supply-chain"),
    ),
    _dependency_rule(
        7,
        "Missing lockfile integrity",
        "A lockfile package resolved from a registry lacks a supported integrity hash.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Regenerate the lockfile with a current package manager and verify registry integrity metadata."
        ),
        tags=("integrity", "lockfile"),
    ),
    _dependency_rule(
        8,
        "Local or editable dependency",
        "A dependency resolves from a mutable local path or editable checkout.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        remediation=(
            "Avoid mutable local dependencies in release and CI builds, or document the trusted source."
        ),
        tags=("local", "reproducibility"),
    ),
)

RULES = DEPENDENCY_RULES
_RULE = {rule.id: rule for rule in DEPENDENCY_RULES}
SUPPORTED_DEPENDENCY_FILES = frozenset(
    {
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
    }
)
_SUSPICIOUS_NAMES = frozenset(
    {
        "reqeusts",
        "requsets",
        "requestes",
        "djagno",
        "flaks",
        "numpyy",
        "pandsa",
        "urllib4",
        "expresss",
        "lodahs",
        "reactt",
        "colorss",
    }
)
_EXACT_VERSION = re.compile(r"^(?:===?)?\s*v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")
_FULL_SHA = re.compile(r"(?:^|[#@])(?:[0-9a-f]{40})(?:$|[/?])", re.IGNORECASE)
_URL_CREDENTIALS = re.compile(r"(?P<scheme>https?://)(?P<userinfo>[^\s/@]+:[^\s/@]+)@", re.IGNORECASE)


def supports_dependency_file(path: str) -> bool:
    """Return whether the path is an initially supported dependency format."""

    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    return name in SUPPORTED_DEPENDENCY_FILES or (name.startswith("requirements") and name.endswith(".txt"))


def _line_for(text: str, needle: str, start: int = 0) -> int:
    offset = text.lower().find(needle.lower(), start)
    return text.count("\n", 0, max(offset, 0)) + 1


def _safe_source(value: str) -> str:
    value = _URL_CREDENTIALS.sub(r"\g<scheme>****:****@", value)
    return value[:200]


def _metadata(**values: str | int | bool) -> tuple[tuple[str, str | int | float | bool], ...]:
    return tuple((key, value) for key, value in values.items() if value != "")


def _add(
    matches: list[RuleMatch],
    seen: set[tuple[str, int, str]],
    rule_id: str,
    *,
    line: int,
    path: str,
    package: str = "",
    evidence: str = "",
    detail: str = "",
) -> None:
    key = (rule_id, line, package.casefold())
    if key in seen:
        return
    seen.add(key)
    matches.append(
        RuleMatch(
            rule=_RULE[rule_id],
            line=max(1, line),
            evidence=_safe_source(evidence),
            metadata=_metadata(path=path, package=package, detail=detail),
        )
    )


def _check_package_name(
    matches: list[RuleMatch],
    seen: set[tuple[str, int, str]],
    path: str,
    package: str,
    line: int,
) -> None:
    normalized = package.casefold().strip().lstrip("@").split("/", 1)[-1]
    if not package.isascii() or normalized in _SUSPICIOUS_NAMES:
        _add(
            matches,
            seen,
            "IV-DEP-005",
            line=line,
            path=path,
            package=package,
            evidence=f"dependency name: {package}",
        )


def _classify_spec(
    matches: list[RuleMatch],
    seen: set[tuple[str, int, str]],
    path: str,
    package: str,
    spec: str,
    line: int,
    *,
    locked: bool = False,
) -> None:
    value = spec.strip().strip("\"'")
    lower = value.lower()
    _check_package_name(matches, seen, path, package, line)

    if lower.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")) or re.search(
        r"(?:github|gitlab|bitbucket)\.com[/:]", lower
    ):
        detail = "full commit SHA" if _FULL_SHA.search(value) else "mutable or short Git reference"
        _add(
            matches,
            seen,
            "IV-DEP-003",
            line=line,
            path=path,
            package=package,
            evidence=f"{package}: Git dependency ({detail})",
            detail=detail,
        )
    if lower.startswith("http://") or _URL_CREDENTIALS.search(value):
        _add(
            matches,
            seen,
            "IV-DEP-004",
            line=line,
            path=path,
            package=package,
            evidence=f"{package}: {_safe_source(value)}",
        )
    if lower.startswith(("file:", "link:", "workspace:", "../", "./")) or lower == "editable":
        _add(
            matches,
            seen,
            "IV-DEP-008",
            line=line,
            path=path,
            package=package,
            evidence=f"{package}: local dependency",
        )

    if locked or lower.startswith(("git+", "git://", "http://", "https://", "file:", "link:", "workspace:")):
        return
    if not value or value in {"*", "latest"}:
        rule_id = "IV-DEP-002" if value else "IV-DEP-001"
        _add(
            matches,
            seen,
            rule_id,
            line=line,
            path=path,
            package=package,
            evidence=f"{package}: {value or 'unpinned'}",
        )
        return
    if not _EXACT_VERSION.fullmatch(value):
        _add(
            matches,
            seen,
            "IV-DEP-002",
            line=line,
            path=path,
            package=package,
            evidence=f"{package}: floating version {value[:80]}",
        )


def _analyze_requirements(
    path: str, text: str, matches: list[RuleMatch], seen: set[tuple[str, int, str]]
) -> None:
    for line_number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lowered = stripped.lower()
        if lowered.startswith(("--index-url", "--extra-index-url", "--find-links")):
            source = stripped.split(maxsplit=1)[1] if " " in stripped else ""
            if source.startswith("http://") or _URL_CREDENTIALS.search(source):
                _add(matches, seen, "IV-DEP-004", line=line_number, path=path, evidence=source)
            continue
        editable = lowered.startswith(("-e ", "--editable "))
        requirement = stripped.split(maxsplit=1)[1] if editable else stripped
        requirement = requirement.split(" #", 1)[0].split(";", 1)[0].strip()
        requirement = re.split(r"\s+--hash(?:=|\s)", requirement, maxsplit=1)[0]
        if editable:
            package = re.sub(r"^.*[#&]egg=", "", requirement) if "egg=" in requirement else requirement
            _classify_spec(matches, seen, path, package, "editable", line_number)
            if requirement.lower().startswith(("git+", "git://")):
                _classify_spec(matches, seen, path, package, requirement, line_number)
            continue
        direct = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*@\s*(.+)$", requirement)
        if direct:
            _classify_spec(matches, seen, path, direct.group(1), direct.group(2), line_number)
            continue
        parsed = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)$", requirement)
        if parsed:
            _classify_spec(matches, seen, path, parsed.group(1), parsed.group(2), line_number)


def _analyze_package_json(
    path: str,
    text: str,
    data: Mapping[str, Any],
    matches: list[RuleMatch],
    seen: set[tuple[str, int, str]],
) -> None:
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = data.get(section)
        if not isinstance(dependencies, Mapping):
            continue
        for package, spec in dependencies.items():
            if isinstance(package, str) and isinstance(spec, str):
                _classify_spec(matches, seen, path, package, spec, _line_for(text, f'"{package}"'))
    scripts = data.get("scripts")
    if isinstance(scripts, Mapping):
        for script_name in ("preinstall", "install", "postinstall"):
            if script_name in scripts:
                _add(
                    matches,
                    seen,
                    "IV-DEP-006",
                    line=_line_for(text, f'"{script_name}"'),
                    path=path,
                    evidence=f"lifecycle script '{script_name}' is defined",
                    detail=script_name,
                )


def _analyze_npm_lock(
    path: str,
    text: str,
    data: Mapping[str, Any],
    matches: list[RuleMatch],
    seen: set[tuple[str, int, str]],
) -> None:
    packages = data.get("packages")
    if isinstance(packages, Mapping):
        for package_path, record in packages.items():
            if not package_path or not isinstance(record, Mapping):
                continue
            package = str(record.get("name") or PurePosixPath(str(package_path)).name)
            line = _line_for(text, f'"{package_path}"')
            resolved = record.get("resolved")
            if isinstance(resolved, str):
                _classify_spec(matches, seen, path, package, resolved, line, locked=True)
            if (
                resolved
                and isinstance(resolved, str)
                and resolved.startswith(("http://", "https://"))
                and not record.get("integrity")
            ):
                _add(
                    matches,
                    seen,
                    "IV-DEP-007",
                    line=line,
                    path=path,
                    package=package,
                    evidence=f"{package}: missing integrity hash",
                )
            _check_package_name(matches, seen, path, package, line)
            if record.get("hasInstallScript") is True:
                _add(
                    matches,
                    seen,
                    "IV-DEP-006",
                    line=line,
                    path=path,
                    package=package,
                    evidence=f"{package}: lockfile marks an install script",
                )
        root = packages.get("")
        if isinstance(root, Mapping):
            scripts = root.get("scripts")
            if isinstance(scripts, Mapping):
                _analyze_package_json(path, text, {"scripts": scripts}, matches, seen)
        return

    dependencies = data.get("dependencies")
    if isinstance(dependencies, Mapping):
        for package, record in dependencies.items():
            if not isinstance(record, Mapping):
                continue
            line = _line_for(text, f'"{package}"')
            resolved = record.get("resolved")
            if isinstance(resolved, str):
                _classify_spec(matches, seen, path, str(package), resolved, line, locked=True)
                if resolved.startswith(("http://", "https://")) and not record.get("integrity"):
                    _add(
                        matches,
                        seen,
                        "IV-DEP-007",
                        line=line,
                        path=path,
                        package=str(package),
                        evidence=f"{package}: missing integrity hash",
                    )
            _check_package_name(matches, seen, path, str(package), line)
            if record.get("hasInstallScript") is True:
                _add(
                    matches,
                    seen,
                    "IV-DEP-006",
                    line=line,
                    path=path,
                    package=str(package),
                    evidence=f"{package}: lockfile marks an install script",
                )


def _analyze_pipfile_lock(
    path: str,
    text: str,
    data: Mapping[str, Any],
    matches: list[RuleMatch],
    seen: set[tuple[str, int, str]],
) -> None:
    for section in ("default", "develop"):
        dependencies = data.get(section)
        if not isinstance(dependencies, Mapping):
            continue
        for package, record in dependencies.items():
            line = _line_for(text, f'"{package}"')
            _check_package_name(matches, seen, path, str(package), line)
            if not isinstance(record, Mapping):
                continue
            git = record.get("git")
            if isinstance(git, str):
                ref = str(record.get("ref", ""))
                _classify_spec(matches, seen, path, str(package), f"git+{git}#{ref}", line, locked=True)
            version = record.get("version")
            if not version and not git and not record.get("path") and not record.get("file"):
                _add(
                    matches,
                    seen,
                    "IV-DEP-001",
                    line=line,
                    path=path,
                    package=str(package),
                    evidence=f"{package}: unpinned",
                )
            if record.get("path") or record.get("file"):
                _add(
                    matches,
                    seen,
                    "IV-DEP-008",
                    line=line,
                    path=path,
                    package=str(package),
                    evidence=f"{package}: local dependency",
                )
            if not record.get("hashes") and not git and not record.get("path") and not record.get("file"):
                _add(
                    matches,
                    seen,
                    "IV-DEP-007",
                    line=line,
                    path=path,
                    package=str(package),
                    evidence=f"{package}: missing hashes",
                )


def _analyze_pyproject(
    path: str,
    text: str,
    data: Mapping[str, Any],
    matches: list[RuleMatch],
    seen: set[tuple[str, int, str]],
) -> None:
    project = data.get("project")
    if isinstance(project, Mapping):
        dependencies = project.get("dependencies")
        if isinstance(dependencies, list):
            for requirement in dependencies:
                if not isinstance(requirement, str):
                    continue
                direct = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*@\s*(.+)$", requirement)
                if direct:
                    _classify_spec(
                        matches, seen, path, direct.group(1), direct.group(2), _line_for(text, requirement)
                    )
                else:
                    parsed = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)$", requirement)
                    if parsed:
                        _classify_spec(
                            matches,
                            seen,
                            path,
                            parsed.group(1),
                            parsed.group(2),
                            _line_for(text, requirement),
                        )

    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, Mapping) else None
    if isinstance(poetry, Mapping):
        dependencies = poetry.get("dependencies")
        if isinstance(dependencies, Mapping):
            for package, spec in dependencies.items():
                if str(package).lower() == "python":
                    continue
                line = _line_for(text, str(package))
                if isinstance(spec, str):
                    _classify_spec(matches, seen, path, str(package), spec, line)
                elif isinstance(spec, Mapping):
                    if isinstance(spec.get("git"), str):
                        ref = str(spec.get("rev") or spec.get("tag") or spec.get("branch") or "")
                        _classify_spec(matches, seen, path, str(package), f"git+{spec['git']}#{ref}", line)
                    elif spec.get("path"):
                        _classify_spec(matches, seen, path, str(package), f"file:{spec['path']}", line)
                    else:
                        _classify_spec(matches, seen, path, str(package), str(spec.get("version", "")), line)
        sources = poetry.get("source")
        if isinstance(sources, list):
            for source in sources:
                if isinstance(source, Mapping) and isinstance(source.get("url"), str):
                    url = source["url"]
                    if url.startswith("http://") or _URL_CREDENTIALS.search(url):
                        _add(matches, seen, "IV-DEP-004", line=_line_for(text, url), path=path, evidence=url)


def _analyze_toml_lock(
    path: str,
    text: str,
    data: Mapping[str, Any],
    matches: list[RuleMatch],
    seen: set[tuple[str, int, str]],
) -> None:
    packages = data.get("package")
    if not isinstance(packages, list):
        return
    for record in packages:
        if not isinstance(record, Mapping):
            continue
        package = str(record.get("name", ""))
        line = _line_for(text, f'name = "{package}"')
        _check_package_name(matches, seen, path, package, line)
        source = record.get("source")
        if isinstance(source, Mapping):
            source_type = str(source.get("type", ""))
            url = str(source.get("url", ""))
            uv_git = source.get("git")
            uv_local = source.get("editable") or source.get("directory") or source.get("path")
            uv_registry = source.get("registry")
            if isinstance(uv_git, str):
                _classify_spec(matches, seen, path, package, f"git+{uv_git}", line, locked=True)
            elif uv_local:
                _classify_spec(matches, seen, path, package, f"file:{uv_local}", line, locked=True)
            elif isinstance(uv_registry, str) and (
                uv_registry.startswith("http://") or _URL_CREDENTIALS.search(uv_registry)
            ):
                _add(
                    matches,
                    seen,
                    "IV-DEP-004",
                    line=line,
                    path=path,
                    package=package,
                    evidence=uv_registry,
                )
            elif source_type in {"git", "directory", "file"}:
                _classify_spec(
                    matches,
                    seen,
                    path,
                    package,
                    f"git+{url}" if source_type == "git" else f"file:{url}",
                    line,
                    locked=True,
                )
            elif url.startswith("http://") or _URL_CREDENTIALS.search(url):
                _add(matches, seen, "IV-DEP-004", line=line, path=path, package=package, evidence=url)


def _analyze_text_lock(
    path: str, text: str, matches: list[RuleMatch], seen: set[tuple[str, int, str]]
) -> None:
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        lower = line.lower()
        if "http://" in lower or _URL_CREDENTIALS.search(line):
            _add(matches, seen, "IV-DEP-004", line=line_number, path=path, evidence=line)
        if re.search(r"(?:git\+|git://|github\.com[/:]|gitlab\.com[/:]|bitbucket\.org[/:])", lower):
            _add(
                matches,
                seen,
                "IV-DEP-003",
                line=line_number,
                path=path,
                evidence="Git dependency in lockfile",
            )
        if re.search(r"\b(?:requiresBuild|hasInstallScript)\s*:\s*true\b", line, re.IGNORECASE):
            _add(
                matches,
                seen,
                "IV-DEP-006",
                line=line_number,
                path=path,
                evidence="lockfile marks a dependency as requiring an install/build script",
            )


def analyze_dependency_file(path: str, text: str) -> tuple[RuleMatch, ...]:
    """Analyze one decoded dependency file without network access."""

    normalized = path.replace("\\", "/")
    name = PurePosixPath(normalized).name.lower()
    if not supports_dependency_file(normalized):
        return ()
    matches: list[RuleMatch] = []
    seen: set[tuple[str, int, str]] = set()

    if name.startswith("requirements") and name.endswith(".txt"):
        _analyze_requirements(normalized, text, matches, seen)
    elif name in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pipfile.lock"}:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            data = None
        if isinstance(data, Mapping):
            if name == "package.json":
                _analyze_package_json(normalized, text, data, matches, seen)
            elif name == "pipfile.lock":
                _analyze_pipfile_lock(normalized, text, data, matches, seen)
            else:
                _analyze_npm_lock(normalized, text, data, matches, seen)
        else:
            _analyze_text_lock(normalized, text, matches, seen)
    elif name in {"pyproject.toml", "poetry.lock", "uv.lock"}:
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, TypeError):
            data = None
        if isinstance(data, Mapping):
            if name == "pyproject.toml":
                _analyze_pyproject(normalized, text, data, matches, seen)
            else:
                _analyze_toml_lock(normalized, text, data, matches, seen)
        else:
            _analyze_text_lock(normalized, text, matches, seen)
    else:
        _analyze_text_lock(normalized, text, matches, seen)

    return tuple(sorted(matches, key=lambda item: (item.line, item.rule.id, item.evidence)))


def get_rules() -> tuple[Rule, ...]:
    return DEPENDENCY_RULES
