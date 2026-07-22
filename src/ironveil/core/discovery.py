"""Bounded, Git-aware file discovery with symlink containment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from ironveil.config import ScanConfig
from ironveil.core.git import is_repository, run_git
from ironveil.exceptions import GitError
from ironveil.models import ScanError

MAX_GIT_FILE_COUNT = 1_000_000

DEFAULT_SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".cache",
}


@dataclass(slots=True)
class DiscoveryResult:
    files: list[Path] = field(default_factory=list)
    metadata_paths: list[str] = field(default_factory=list)
    skipped: int = 0
    errors: list[ScanError] = field(default_factory=list)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _excluded(relative: str, patterns: list[str]) -> bool:
    normalized = relative.replace(os.sep, "/")
    return any(fnmatch(normalized, pattern) or fnmatch(f"{normalized}/", pattern) for pattern in patterns)


def _git_files(root: Path, config: ScanConfig) -> tuple[list[Path] | None, ScanError | None]:
    if not is_repository(root):
        return None, None
    args = ["ls-files", "-z"]
    if not config.tracked_only:
        args.extend(["--cached", "--others"])
        if config.respect_gitignore and not config.all_files:
            args.append("--exclude-standard")
    try:
        raw = run_git(root, args, timeout=30)
    except GitError as exc:
        return None, ScanError(str(root), f"Cannot enumerate Git files safely: {exc}", fatal=True)
    names = [item for item in raw.split(b"\0") if item]
    if len(names) > MAX_GIT_FILE_COUNT:
        return None, ScanError(
            str(root),
            f"Git index exceeds the bounded limit of {MAX_GIT_FILE_COUNT} paths",
            fatal=True,
        )
    return [root / os.fsdecode(item) for item in names], None


def discover_files(root: Path, config: ScanConfig) -> DiscoveryResult:
    """Discover candidate files deterministically without escaping ``root``."""

    result = DiscoveryResult()
    root = root.resolve()
    if not root.exists():
        result.errors.append(ScanError(str(root), "Scan root does not exist", fatal=True))
        return result
    if root.is_file():
        result.files = [root]
        return result
    git_error: ScanError | None = None
    if config.all_files:
        candidates = None
    else:
        candidates, git_error = _git_files(root, config)
    if git_error is not None:
        result.errors.append(git_error)
        return result
    if candidates is None and config.tracked_only and not config.all_files:
        result.errors.append(
            ScanError(
                str(root),
                "--tracked-only requires an accessible Git repository and index",
                fatal=True,
            )
        )
        return result
    if candidates is None:
        candidates = []

        def record_walk_error(error: OSError) -> None:
            failed = Path(error.filename) if error.filename else root
            try:
                relative = failed.resolve(strict=False).relative_to(root).as_posix()
            except (OSError, ValueError):
                relative = failed.name or str(root)
            result.errors.append(
                ScanError(
                    relative,
                    f"Cannot traverse directory: {error}",
                    fatal=failed.absolute() == root.absolute(),
                )
            )

        for current, directories, names in os.walk(root, followlinks=False, onerror=record_walk_error):
            current_path = Path(current)
            relative_dir = current_path.relative_to(root).as_posix()
            kept_directories: list[str] = []
            for directory in sorted(directories):
                relative = (Path(relative_dir) / directory).as_posix() if relative_dir != "." else directory
                full = current_path / directory
                if directory == ".git":
                    result.skipped += 1
                    continue
                if not config.all_files and directory in DEFAULT_SKIPPED_DIRECTORIES:
                    if directory != ".git":
                        result.metadata_paths.append(relative)
                    result.skipped += 1
                    continue
                if _excluded(relative, config.exclude):
                    result.skipped += 1
                    continue
                if full.is_symlink() and (not config.follow_symlinks or not _is_within(full, root)):
                    result.skipped += 1
                    continue
                kept_directories.append(directory)
            directories[:] = kept_directories
            for name in sorted(names):
                candidates.append(current_path / name)
    seen: set[str] = set()
    for path in candidates:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            result.skipped += 1
            continue
        if relative in seen or _excluded(relative, config.exclude):
            result.skipped += 1
            continue
        seen.add(relative)
        try:
            if path.is_symlink() and (not config.follow_symlinks or not _is_within(path, root)):
                result.skipped += 1
                continue
            if not path.is_file():
                result.skipped += 1
                continue
        except OSError as exc:
            result.errors.append(ScanError(relative, f"Cannot inspect file: {exc}"))
            result.skipped += 1
            continue
        result.files.append(path)
    result.files.sort(key=lambda item: item.relative_to(root).as_posix().casefold())
    result.metadata_paths = sorted(set(result.metadata_paths), key=str.casefold)
    return result
