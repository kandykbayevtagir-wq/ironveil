"""Safe Git subprocess adapters and added-line diff parsing."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from ironveil.exceptions import GitError

REF_RE = re.compile(
    r"(?!-)[A-Za-z0-9][A-Za-z0-9._/@{}^~:+-]*(?:\.{2,3}[A-Za-z0-9][A-Za-z0-9._/@{}^~:+-]*)?\Z"
)
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<line>\d+)(?:,\d+)? @@")
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_GIT_ERROR_BYTES = 64 * 1024
MAX_HISTORY_BYTES = 128 * 1024 * 1024
MAX_HISTORY_LINES = 1_000_000
PATCH_OPTIONS = (
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--text",
    "--src-prefix=a/",
    "--dst-prefix=b/",
)


@dataclass(frozen=True, slots=True)
class GitLine:
    path: str
    line: int
    text: str
    source: str
    commit: str | None = None
    metadata_only: bool = False


@dataclass(frozen=True, slots=True)
class GitInfo:
    available: bool
    repository: bool
    history_available: bool
    branch: str | None
    commit: str | None


def _validate_ref(value: str, label: str = "Git ref") -> str:
    if not REF_RE.fullmatch(value):
        raise GitError(f"{label} contains unsupported characters: {value!r}")
    return value


def run_git(
    root: Path,
    arguments: Iterable[str],
    *,
    timeout: float = 60,
    check: bool = True,
    max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
) -> bytes:
    command = [
        "git",
        "-c",
        "core.quotepath=false",
        # A repository-local fsmonitor may be an executable hook. IronVeil
        # never needs it and must not execute target-repository code.
        "-c",
        "core.fsmonitor=false",
        # ``git show`` otherwise honors a repository-selected signature
        # verifier. A crafted signed commit plus ``gpg.program`` would execute
        # target-repository code while IronVeil scans history.
        "-c",
        "log.showSignature=false",
        "-C",
        str(root),
        *arguments,
    ]
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                env=environment,
            )
            stdout_size = stdout.tell()
            stderr_size = stderr.tell()
            if stdout_size > max_output_bytes:
                raise GitError(
                    f"Git output exceeded the {max_output_bytes // (1024 * 1024)} MiB safety limit"
                )
            stdout.seek(0)
            output = stdout.read(max_output_bytes + 1)
            stderr.seek(0)
            error_output = stderr.read(min(stderr_size, MAX_GIT_ERROR_BYTES))
    except FileNotFoundError as exc:
        raise GitError("Git is not installed or is not available on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"Git command timed out after {timeout:g} seconds") from exc
    if check and completed.returncode != 0:
        message = error_output.decode("utf-8", errors="replace").strip()
        if stderr_size > MAX_GIT_ERROR_BYTES:
            message = f"{message}\n[Git error output truncated]".strip()
        raise GitError(message or f"Git exited with status {completed.returncode}")
    return output


def _changed_paths(raw: bytes) -> list[str]:
    return sorted(
        {os.fsdecode(item) for item in raw.split(b"\0") if item},
        key=str.casefold,
    )


def _include_changed_paths(
    lines: list[GitLine], paths: Iterable[str], source: str, commit: str | None = None
) -> list[GitLine]:
    present = {line.path for line in lines}
    lines.extend(
        GitLine(path, 1, "", source, commit, metadata_only=True) for path in paths if path not in present
    )
    return sorted(lines, key=lambda item: (item.path.casefold(), item.line, item.metadata_only))


def is_repository(root: Path) -> bool:
    try:
        output = run_git(root, ["rev-parse", "--is-inside-work-tree"], timeout=10)
    except GitError:
        return False
    return output.strip() == b"true"


def git_info(root: Path) -> GitInfo:
    available = shutil.which("git") is not None
    if not available or not is_repository(root):
        return GitInfo(available, False, False, None, None)
    branch_raw = run_git(root, ["branch", "--show-current"], timeout=10, check=False)
    commit_raw = run_git(root, ["rev-parse", "HEAD"], timeout=10, check=False)
    commit = commit_raw.decode("ascii", errors="ignore").strip() or None
    branch = branch_raw.decode("utf-8", errors="replace").strip() or None
    return GitInfo(True, True, commit is not None, branch, commit)


def repository_root(root: Path) -> Path | None:
    """Return the containing Git work-tree root without executing repository hooks."""

    try:
        raw = run_git(root, ["rev-parse", "--show-toplevel"], timeout=10)
    except GitError:
        return None
    value = os.fsdecode(raw.rstrip(b"\r\n"))
    if not value:
        return None
    candidate = Path(value).resolve()
    return candidate if candidate.is_dir() else None


def parse_added_lines(patch: bytes, source: str, commit: str | None = None) -> list[GitLine]:
    """Parse added lines from a unified diff without retaining deleted content."""

    current_path: str | None = None
    current_line = 0
    in_hunk = False
    result: list[GitLine] = []
    for raw_line in patch.decode("utf-8", errors="replace").splitlines():
        if not in_hunk and raw_line.startswith("+++ "):
            value = raw_line[4:]
            current_path = None if value == "/dev/null" else value.removeprefix("b/")
            in_hunk = False
            continue
        hunk = HUNK_RE.match(raw_line)
        if hunk:
            current_line = int(hunk.group("line"))
            in_hunk = True
            continue
        if not in_hunk or current_path is None:
            continue
        if raw_line.startswith("+"):
            result.append(GitLine(current_path, current_line, raw_line[1:], source, commit))
            current_line += 1
        elif raw_line.startswith(" "):
            current_line += 1
        elif raw_line.startswith("-") or raw_line.startswith("\\"):
            continue
        else:
            in_hunk = False
    return result


def diff_lines(root: Path, commit_range: str) -> list[GitLine]:
    commit_range = _validate_ref(commit_range, "Commit range")
    source = f"diff:{commit_range}"
    patch = run_git(
        root,
        [
            "diff",
            *PATCH_OPTIONS,
            "--unified=0",
            "--diff-filter=ACMR",
            commit_range,
            "--",
        ],
    )
    paths = _changed_paths(
        run_git(
            root,
            [
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "-z",
                "--diff-filter=ACMR",
                commit_range,
                "--",
            ],
        )
    )
    return _include_changed_paths(parse_added_lines(patch, source), paths, source)


def staged_lines(root: Path) -> list[GitLine]:
    patch = run_git(
        root,
        [
            "diff",
            "--cached",
            *PATCH_OPTIONS,
            "--unified=0",
            "--diff-filter=ACMR",
            "--",
        ],
    )
    paths = _changed_paths(
        run_git(
            root,
            [
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "-z",
                "--diff-filter=ACMR",
                "--",
            ],
        )
    )
    return _include_changed_paths(parse_added_lines(patch, "staged"), paths, "staged")


def commit_lines(root: Path, commit: str) -> list[GitLine]:
    commit = _validate_ref(commit, "Commit")
    resolved = (
        run_git(root, ["rev-parse", "--verify", f"{commit}^{{commit}}"], timeout=15).decode("ascii").strip()
    )
    patch = run_git(
        root,
        [
            "show",
            "--root",
            "--format=",
            "--no-show-signature",
            *PATCH_OPTIONS,
            "--unified=0",
            "--diff-filter=ACMR",
            resolved,
            "--",
        ],
    )
    source = f"commit:{resolved}"
    paths = _changed_paths(
        run_git(
            root,
            [
                "show",
                "--root",
                "--format=",
                "--no-show-signature",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "-z",
                "--diff-filter=ACMR",
                resolved,
                "--",
            ],
        )
    )
    return _include_changed_paths(parse_added_lines(patch, source, resolved), paths, source, resolved)


def history_commits(
    root: Path,
    *,
    max_commits: int,
    since: str | None = None,
    until: str | None = None,
    branch: str | None = None,
    all_branches: bool = False,
) -> list[str]:
    arguments = ["rev-list", "--reverse", f"--max-count={max_commits}"]
    for label, value in (("since", since), ("until", until)):
        if value:
            if len(value) > 64 or "\0" in value or "\n" in value:
                raise GitError(f"Invalid --{label} value")
            arguments.append(f"--{label}={value}")
    if all_branches:
        arguments.append("--all")
    else:
        arguments.append(_validate_ref(branch or "HEAD", "Branch"))
    raw = run_git(root, arguments, timeout=30)
    return [line for line in raw.decode("ascii", errors="ignore").splitlines() if line]


def history_lines(
    root: Path,
    *,
    max_commits: int = 500,
    since: str | None = None,
    until: str | None = None,
    branch: str | None = None,
    all_branches: bool = False,
) -> list[GitLine]:
    result: list[GitLine] = []
    total_bytes = 0
    for commit in history_commits(
        root,
        max_commits=max_commits,
        since=since,
        until=until,
        branch=branch,
        all_branches=all_branches,
    ):
        additions = commit_lines(root, commit)
        total_bytes += sum(len(item.text.encode("utf-8", errors="replace")) for item in additions)
        if total_bytes > MAX_HISTORY_BYTES or len(result) + len(additions) > MAX_HISTORY_LINES:
            raise GitError(
                "Git history additions exceeded the bounded scan limit; narrow --max-commits, "
                "--since, --until, or --branch"
            )
        result.extend(additions)
    return result


HOOK_BODY = """#!/bin/sh\n# Installed by IronVeil\nexec ironveil pre-commit\n"""
MAX_HOOK_BYTES = 1024 * 1024


def install_pre_commit_hook(root: Path, *, backup_existing: bool = False) -> tuple[Path, Path | None]:
    if not is_repository(root):
        raise GitError(f"Not a Git repository: {root}")
    custom_hooks_path = (
        run_git(
            root,
            ["config", "--get", "core.hooksPath"],
            timeout=10,
            check=False,
            max_output_bytes=MAX_GIT_ERROR_BYTES,
        )
        .decode("utf-8", errors="replace")
        .strip()
    )
    if custom_hooks_path:
        raise GitError(
            "Refusing to install while core.hooksPath is configured; manage that hook path explicitly"
        )
    git_dir_raw = (
        run_git(root, ["rev-parse", "--git-dir"], timeout=10).decode("utf-8", errors="replace").strip()
    )
    git_dir = Path(git_dir_raw)
    if not git_dir.is_absolute():
        git_dir = root / git_dir
    resolved_git_dir = git_dir.resolve()
    hooks_dir = resolved_git_dir / "hooks"
    if hooks_dir.is_symlink():
        raise GitError(f"Refusing symlinked Git hooks directory: {hooks_dir}")
    resolved_hooks = hooks_dir.resolve()
    if not resolved_hooks.is_relative_to(resolved_git_dir):
        raise GitError(f"Git hooks directory escapes the repository metadata directory: {hooks_dir}")
    hooks_dir.mkdir(parents=True, exist_ok=True)
    if hooks_dir.is_symlink() or not hooks_dir.resolve().is_relative_to(resolved_git_dir):
        raise GitError(f"Refusing unsafe Git hooks directory: {hooks_dir}")
    hook = hooks_dir / "pre-commit"
    backup: Path | None = None
    if hook.is_symlink():
        raise GitError(f"Refusing symlinked pre-commit hook: {hook}")
    if hook.exists():
        hook_stat = hook.stat()
        if not hook.is_file() or hook_stat.st_size > MAX_HOOK_BYTES:
            raise GitError(f"Refusing non-regular or oversized pre-commit hook: {hook}")
        existing = hook.read_text(encoding="utf-8", errors="replace")
        if existing == HOOK_BODY and hook_stat.st_mode & 0o111:
            return hook, None
        if not backup_existing:
            raise GitError(
                f"A pre-commit hook already exists at {hook}. Re-run with --backup-existing to preserve and replace it."
            )
        backup = hook.with_name("pre-commit.ironveil-backup")
        if backup.is_symlink() or backup.exists():
            raise GitError(f"Refusing to overwrite existing backup: {backup}")
        os.replace(hook, backup)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ironveil-hook-", dir=hooks_dir)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(HOOK_BODY)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o755)
        os.replace(temporary_name, hook)
    except BaseException:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise
    return hook, backup
