"""Zero-config command-line interface for IronVeil."""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from ironveil import __version__
from ironveil.config import DEFAULT_CONFIG, Config, load_config
from ironveil.core.cache import FileCache
from ironveil.core.dependencies import inventory, query_osv
from ironveil.core.git import (
    commit_lines,
    diff_lines,
    git_info,
    history_lines,
    install_pre_commit_hook,
    repository_root,
    staged_lines,
)
from ironveil.core.scanner import Scanner
from ironveil.exceptions import ConfigurationError, GitError, IronVeilError, ReportError
from ironveil.models import Category, Confidence, ScanError, ScanResult, Severity, finding_sort_key
from ironveil.policy import (
    baseline_document,
    exit_code,
    load_baseline,
    mark_baseline,
)
from ironveil.reporters._common import terminal_safe
from ironveil.reporters.registry import available_reporters, render_report, write_report
from ironveil.ui.server import serve_report
from ironveil.ui.templates import render_report_page

COMMANDS = {
    "scan",
    "diff",
    "staged",
    "pre-commit",
    "commit",
    "history",
    "baseline",
    "dependencies",
    "ui",
    "init",
    "doctor",
    "install-hook",
    "cache",
}


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _add_policy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fail-severity", choices=[item.value for item in Severity])
    parser.add_argument("--minimum-confidence", choices=[item.value for item in Confidence])
    parser.add_argument("--fail-on", help="Comma-separated categories that may fail policy")
    parser.add_argument("--no-fail", action="store_true", help="Always return success for findings")


def _add_report_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=available_reporters(), default="text")
    parser.add_argument("--output", type=_path, help="Write the report to this file")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colors")


def _add_common_options(parser: argparse.ArgumentParser, *, path: bool = True) -> None:
    if path:
        parser.add_argument("path", nargs="?", default=Path("."), type=_path)
    parser.add_argument("--config", type=_path, help="Use an explicit TOML configuration file")
    parser.add_argument("--baseline", type=_path, help="Use an explicit baseline file")
    _add_policy_options(parser)
    _add_report_options(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironveil",
        description="Local-first repository security scanner.",
    )
    parser.add_argument("--version", action="version", version=f"IronVeil {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = subparsers.add_parser("scan", help="Scan the current repository tree")
    _add_common_options(scan)
    scan.add_argument("--workers", type=int)
    scan.add_argument("--max-size-mb", type=float)
    scan.add_argument("--tracked-only", action="store_true")
    scan.add_argument("--all-files", action="store_true")
    scan.add_argument("--no-cache", action="store_true")
    scan.add_argument("--scan-binary", action="store_true")

    diff = subparsers.add_parser("diff", help="Scan added lines in a Git commit range")
    diff.add_argument("range")
    diff.add_argument("--root", type=_path, default=Path("."))
    _add_common_options(diff, path=False)

    staged = subparsers.add_parser("staged", help="Scan staged added lines")
    staged.add_argument("--root", type=_path, default=Path("."))
    _add_common_options(staged, path=False)

    pre_commit = subparsers.add_parser("pre-commit", help="Fast alias for staged scanning")
    pre_commit.add_argument("--root", type=_path, default=Path("."))
    _add_common_options(pre_commit, path=False)

    commit = subparsers.add_parser("commit", help="Scan lines introduced by a commit")
    commit.add_argument("sha")
    commit.add_argument("--root", type=_path, default=Path("."))
    _add_common_options(commit, path=False)

    history = subparsers.add_parser("history", help="Scan secrets introduced throughout Git history")
    _add_common_options(history)
    history.add_argument("--max-commits", type=int)
    history.add_argument("--since")
    history.add_argument("--until")
    history.add_argument("--branch")
    history.add_argument("--all-branches", action="store_true")

    baseline = subparsers.add_parser("baseline", help="Create, update, or verify a finding baseline")
    baseline_actions = baseline.add_subparsers(dest="baseline_action", required=True)
    for action in ("create", "update", "verify"):
        command = baseline_actions.add_parser(action)
        command.add_argument("path", nargs="?", default=Path("."), type=_path)
        command.add_argument("--config", type=_path)
        command.add_argument("--file", type=_path)
        command.add_argument("--force", action="store_true")

    dependencies = subparsers.add_parser("dependencies", help="Inspect dependency files")
    _add_common_options(dependencies)
    dependencies.add_argument("--online", action="store_true", help="Send package names and versions to OSV")
    dependencies.add_argument("--no-cache", action="store_true")

    ui = subparsers.add_parser("ui", help="Scan and serve a local static HTML report")
    ui.add_argument("path", nargs="?", default=Path("."), type=_path)
    ui.add_argument("--config", type=_path)
    ui.add_argument("--baseline", type=_path)
    ui.add_argument("--port", type=int)
    ui.add_argument("--no-open", action="store_true")
    ui.add_argument("--history", action="store_true")
    ui.add_argument("--diff", dest="diff_range")

    init = subparsers.add_parser("init", help="Create a documented .ironveil.toml")
    init.add_argument("path", nargs="?", default=Path("."), type=_path)
    init.add_argument("--force", action="store_true")

    doctor = subparsers.add_parser("doctor", help="Check the local IronVeil environment")
    doctor.add_argument("path", nargs="?", default=Path("."), type=_path)
    doctor.add_argument("--config", type=_path)
    doctor.add_argument("--no-network", action="store_true")

    hook = subparsers.add_parser("install-hook", help="Install a guarded Git pre-commit hook")
    hook.add_argument("path", nargs="?", default=Path("."), type=_path)
    hook.add_argument("--backup-existing", action="store_true")

    cache = subparsers.add_parser("cache", help="Inspect or clear the local scan cache")
    cache_actions = cache.add_subparsers(dest="cache_action", required=True)
    cache_actions.add_parser("stats")
    cache_actions.add_parser("clear")
    return parser


def _normalize_argv(argv: Sequence[str]) -> list[str]:
    values = list(argv)
    if not values:
        return ["--help"]
    if values[0] in COMMANDS or values[0] in {"-h", "--help", "--version"}:
        return values
    return ["scan", *values]


def _root_for(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "path", getattr(args, "root", Path(".")))).expanduser().resolve()


def _repository_context(root: Path) -> Path:
    """Find repository-level configuration for a directly selected file."""

    if not root.is_file():
        return root
    start = root.parent
    git_root = repository_root(start)
    if git_root is None:
        return start
    current = start
    while True:
        config_path = current / ".ironveil.toml"
        if config_path.exists() or config_path.is_symlink():
            return current
        if current == git_root or current.parent == current:
            break
        current = current.parent
    return git_root or start


def _configured(args: argparse.Namespace, root: Path) -> Config:
    config = load_config(_repository_context(root), getattr(args, "config", None))
    scan = config.scan
    policy = config.policy
    if getattr(args, "workers", None) is not None:
        if args.workers < 1 or args.workers > 256:
            raise ConfigurationError("--workers must be between 1 and 256")
        scan.workers = args.workers
    if getattr(args, "max_size_mb", None) is not None:
        if not math.isfinite(args.max_size_mb) or not 0.001 <= args.max_size_mb <= 1024:
            raise ConfigurationError("--max-size-mb must be between 0.001 and 1024")
        scan.max_size_mb = args.max_size_mb
    for option in ("tracked_only", "all_files", "scan_binary"):
        if getattr(args, option, False):
            setattr(scan, option, True)
    if scan.tracked_only and scan.all_files:
        raise ConfigurationError("--tracked-only and --all-files are mutually exclusive")
    if getattr(args, "no_cache", False):
        scan.use_cache = False
    if getattr(args, "fail_severity", None):
        policy.fail_severity = Severity(args.fail_severity)
    if getattr(args, "minimum_confidence", None):
        policy.minimum_confidence = Confidence(args.minimum_confidence)
    if getattr(args, "fail_on", None):
        aliases = {"error": "scan-error", "file": "sensitive-file"}
        try:
            policy.fail_on = [
                Category(aliases.get(item.strip(), item.strip())) for item in args.fail_on.split(",")
            ]
        except ValueError as exc:
            raise ConfigurationError(f"--fail-on contains an invalid category: {exc}") from exc
    if getattr(args, "no_fail", False):
        policy.no_fail = True
    return config


def _apply_baseline(result: ScanResult, args: argparse.Namespace, root: Path) -> None:
    explicit = getattr(args, "baseline", None)
    path = explicit or _repository_context(root) / ".ironveil-baseline.json"
    if explicit is not None and not path.exists():
        raise ConfigurationError(f"baseline: explicit file does not exist: {path}")
    if path.exists() or path.is_symlink():
        mark_baseline(result, load_baseline(path))


def _emit(result: ScanResult, args: argparse.Namespace, config: Config) -> int:
    output = getattr(args, "output", None)
    format_name = getattr(args, "format", "text")
    options: dict[str, object] = {}
    if format_name == "text":
        options["color"] = bool(
            output is None and sys.stdout.isatty() and not getattr(args, "no_color", False)
        )
    if output:
        write_report(result, format_name, output, tool_version=__version__, **options)
        print(f"IronVeil wrote {format_name} report to {terminal_safe(output)}")
    else:
        rendered = render_report(result, format_name, tool_version=__version__, **options)
        print(rendered, end="" if rendered.endswith("\n") else "\n")
    return exit_code(result, config.policy)


def _run_scan(args: argparse.Namespace) -> int:
    root = _root_for(args)
    config = _configured(args, root)
    result = Scanner(config).scan(root)
    _apply_baseline(result, args, root)
    return _emit(result, args, config)


def _run_git_scan(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    config = _configured(args, root)
    scanner = Scanner(config)
    if args.command == "diff":
        lines = diff_lines(root, args.range)
        command = f"diff {args.range}"
    elif args.command in {"staged", "pre-commit"}:
        lines = staged_lines(root)
        command = args.command
    else:
        lines = commit_lines(root, args.sha)
        command = f"commit {args.sha}"
    result = scanner.scan_git_lines(root, lines, command=command)
    _apply_baseline(result, args, root)
    return _emit(result, args, config)


def _run_history(args: argparse.Namespace) -> int:
    root = _root_for(args)
    config = _configured(args, root)
    maximum = args.max_commits or config.history.max_commits
    if maximum < 1:
        raise ConfigurationError("--max-commits must be greater than zero")
    lines = history_lines(
        root,
        max_commits=maximum,
        since=args.since,
        until=args.until,
        branch=args.branch,
        all_branches=args.all_branches,
    )
    result = Scanner(config).scan_git_lines(root, lines, command="history")
    result.history_scanned = True
    if result.visible_findings():
        result.warnings.append(
            "Removing a secret from the current file does not remove it from Git history. "
            "Revoke or rotate every exposed credential."
        )
    _apply_baseline(result, args, root)
    return _emit(result, args, config)


def _run_baseline(args: argparse.Namespace) -> int:
    root = args.path.expanduser().resolve()
    context = _repository_context(root)
    config = load_config(context, args.config)
    result = Scanner(config).scan(root, command=f"baseline {args.baseline_action}")
    target = (args.file or context / ".ironveil-baseline.json").expanduser()
    if result.errors:
        detail = result.errors[0]
        raise IronVeilError(
            f"baseline scan is incomplete ({detail.path}: {detail.message}); no baseline was written"
        )
    if args.baseline_action == "verify":
        if not target.exists() or target.is_symlink():
            raise ConfigurationError(f"baseline: regular file does not exist: {target}")
        known = load_baseline(target)
        mark_baseline(result, known)
        new = result.new_findings()
        if new:
            print(f"Baseline verification failed: {len(new)} new finding(s).")
            return 1
        print(f"Baseline verified: {len(known)} fingerprint(s), no new findings.")
        return 0
    if args.baseline_action == "create" and (target.exists() or target.is_symlink()) and not args.force:
        raise ConfigurationError(f"baseline: {target} already exists; use --force or baseline update")
    _write_baseline(target, json.dumps(baseline_document(result), indent=2, sort_keys=True) + "\n")
    print(
        f"Baseline {args.baseline_action}d at {terminal_safe(target)} "
        f"with {len(result.visible_findings())} finding(s)."
    )
    return 0


def _write_baseline(target: Path, content: str) -> None:
    """Atomically replace a baseline without following a repository-controlled symlink."""

    _write_private_text(target, content, subject="baseline")


def _write_private_text(target: Path, content: str, *, subject: str) -> None:
    """Atomically write a private UTF-8 file without following the final path."""

    try:
        parent = target.parent.resolve(strict=True)
    except OSError as exc:
        raise ConfigurationError(f"{subject}: output directory does not exist: {target.parent}") from exc
    destination = parent / target.name
    if destination.exists() and destination.is_dir():
        raise ConfigurationError(f"{subject}: output is a directory: {destination}")
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=parent
        )
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise ConfigurationError(f"{subject}: cannot write {destination}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink()


def _run_dependencies(args: argparse.Namespace) -> int:
    root = _root_for(args)
    config = _configured(args, root)
    result = Scanner(config).scan(root, command="dependencies")
    result.findings = [item for item in result.findings if item.category == Category.DEPENDENCY]
    result.dependencies_scanned = True
    if args.online:
        print(
            "OSV online mode sends only dependency ecosystem, package name, and version; source code is not sent.",
            file=sys.stderr,
        )
        packages, warnings = inventory(root, config.scan)
        online, online_warnings = query_osv(packages, config.dependencies)
        result.findings.extend(online)
        result.warnings.extend(warnings)
        result.warnings.extend(online_warnings)
        result.errors.extend(
            ScanError("dependencies", warning, fatal=False) for warning in (*warnings, *online_warnings)
        )
        result.findings.sort(key=finding_sort_key)
    _apply_baseline(result, args, root)
    return _emit(result, args, config)


def _run_ui(args: argparse.Namespace) -> int:
    root = args.path.expanduser().resolve()
    config = load_config(_repository_context(root), args.config)
    scanner = Scanner(config)
    if args.diff_range:
        result = scanner.scan_git_lines(
            root, diff_lines(root, args.diff_range), command=f"diff {args.diff_range}"
        )
    elif args.history:
        result = scanner.scan_git_lines(
            root,
            history_lines(root, max_commits=config.history.max_commits),
            command="history",
        )
        result.history_scanned = True
    else:
        result = scanner.scan(root)
    _apply_baseline(result, args, root)
    directory = Path(tempfile.mkdtemp(prefix="ironveil-ui-"))
    report = directory / "ironveil-report.html"
    _write_private_text(
        report,
        render_report_page(result, tool_version=__version__),
        subject="ui report",
    )
    port = args.port or config.ui.port
    if not 1 <= port <= 65535:
        raise ConfigurationError("--port must be between 1 and 65535")
    print(f"IronVeil local report: http://127.0.0.1:{port}/")
    try:
        serve_report(report, port=port, open_browser=not args.no_open and config.ui.open_browser)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return 0


def _run_init(args: argparse.Namespace) -> int:
    destination = args.path.expanduser().resolve() / ".ironveil.toml"
    if (destination.exists() or destination.is_symlink()) and not args.force:
        raise ConfigurationError(f"init: {destination} already exists; use --force to replace it")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _write_private_text(destination, DEFAULT_CONFIG, subject="init")
    print(f"Created {terminal_safe(destination)}")
    return 0


def _osv_available() -> tuple[bool, str]:
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=b'{"queries":[]}',
        headers={"Content-Type": "application/json", "User-Agent": f"IronVeil/{__version__}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310
            return response.status == 200, f"HTTP {response.status}"
    except (OSError, urllib.error.URLError) as exc:
        return False, str(exc)


def _run_doctor(args: argparse.Namespace) -> int:
    root = args.path.expanduser().resolve()
    checks: list[tuple[str, bool, str]] = []
    checks.append(("Python", sys.version_info >= (3, 11), sys.version.split()[0]))
    info = git_info(root)
    checks.append(("Git installed", info.available, shutil.which("git") or "not found"))
    checks.append(("Git repository", info.repository, str(root)))
    checks.append(("Git history", info.history_available, info.commit or "unavailable"))
    try:
        config = load_config(_repository_context(root), args.config)
        Scanner(config)
    except ConfigurationError as exc:
        checks.append(("Configuration", False, str(exc)))
        config = Config()
    else:
        checks.append(("Configuration", True, str(config.source or "defaults")))
    active = 0
    expired = 0
    non_expiring = 0
    from datetime import date

    for entry in config.allowlist:
        if entry.expires is None:
            non_expiring += 1
        elif date.fromisoformat(entry.expires) < date.today():
            expired += 1
        else:
            active += 1
    checks.append(
        (
            "Suppressions",
            expired == 0,
            f"{active} active, {non_expiring} non-expiring, {expired} expired",
        )
    )
    try:
        probe = root / ".ironveil-write-probe"
        with probe.open("x", encoding="utf-8") as handle:
            handle.write("")
        probe.unlink()
    except OSError as exc:
        checks.append(("Report write", False, str(exc)))
    else:
        checks.append(("Report write", True, str(root)))
    if args.no_network:
        checks.append(("OSV online check", True, "skipped by --no-network"))
    else:
        available, detail = _osv_available()
        checks.append(("OSV online check", available, detail))
    for name, passed, detail in checks:
        print(f"{'PASS' if passed else 'FAIL':4}  {terminal_safe(name)}: {terminal_safe(detail)}")
    required = [item for item in checks if item[0] != "OSV online check"]
    return 0 if all(item[1] for item in required) else 2


def _run_hook(args: argparse.Namespace) -> int:
    hook, backup = install_pre_commit_hook(
        args.path.expanduser().resolve(), backup_existing=args.backup_existing
    )
    print(f"Installed IronVeil pre-commit hook at {terminal_safe(hook)}")
    if backup:
        print(f"Existing hook preserved at {terminal_safe(backup)}")
    return 0


def _run_cache(args: argparse.Namespace) -> int:
    cache = FileCache()
    if args.cache_action == "clear":
        print(f"Removed {cache.clear()} IronVeil cache entr{'y' if cache.stats().entries == 1 else 'ies'}.")
        return 0
    stats = cache.stats()
    print(f"Cache path: {terminal_safe(stats.path)}\nEntries: {stats.entries}\nBytes: {stats.bytes_used}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_normalize_argv(sys.argv[1:] if argv is None else argv))
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command in {"diff", "staged", "pre-commit", "commit"}:
            return _run_git_scan(args)
        if args.command == "history":
            return _run_history(args)
        if args.command == "baseline":
            return _run_baseline(args)
        if args.command == "dependencies":
            return _run_dependencies(args)
        if args.command == "ui":
            return _run_ui(args)
        if args.command == "init":
            return _run_init(args)
        if args.command == "doctor":
            return _run_doctor(args)
        if args.command == "install-hook":
            return _run_hook(args)
        if args.command == "cache":
            return _run_cache(args)
    except (ConfigurationError, GitError, ReportError, IronVeilError, OSError) as exc:
        print(f"ironveil: error: {terminal_safe(exc)}", file=sys.stderr)
        return 2
    parser.print_help()
    return 0
