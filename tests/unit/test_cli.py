from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

from ironveil.cli import main
from ironveil.core.dependencies import PackageCoordinate


def test_zero_config_path_is_scan(tmp_path: Path, capsys) -> None:
    (tmp_path / "safe.py").write_text("answer = 42\n", encoding="utf-8")

    code = main([str(tmp_path), "--no-fail", "--no-cache"])

    assert code == 0
    assert "IronVeil 0.1.0 scan report" in capsys.readouterr().out


def test_policy_exit_and_json_never_expose_secret(tmp_path: Path, capsys) -> None:
    value = "sk-" + "mN4pQ6rS8tV0xY2zA3bC5dE7fG9hJ1k"
    (tmp_path / "settings.py").write_text(f'OPENAI_API_KEY = "{value}"\n', encoding="utf-8")

    code = main(["scan", str(tmp_path), "--format", "json", "--no-cache"])
    output = capsys.readouterr().out

    assert code == 1
    assert value not in output
    document = json.loads(output)
    assert document["summary"]["total"] >= 1


def test_selected_nested_file_uses_repo_path_and_root_config(tmp_path: Path, capsys) -> None:
    _git(tmp_path, "init", "-b", "main")
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n  test:\n    steps:\n      - uses: outside/example-action@v1\n"
        "      - run: echo repo_context_marker\n",
        encoding="utf-8",
    )
    (tmp_path / ".ironveil.toml").write_text(
        """
[[rules]]
id = "CUSTOM-CONTEXT-001"
name = "Repository context marker"
category = "iac"
severity = "medium"
confidence = "high"
regex = "repo_context_marker"
message = "Repository-root configuration was applied"
remediation = "Remove the synthetic marker"
""",
        encoding="utf-8",
    )

    assert main(["scan", str(workflow), "--format", "json", "--no-cache", "--no-fail"]) == 0
    document = json.loads(capsys.readouterr().out)
    by_rule = {item["rule_id"]: item for item in document["findings"]}
    assert by_rule["IV-GHA-004"]["path"] == ".github/workflows/ci.yml"
    assert by_rule["CUSTOM-CONTEXT-001"]["path"] == ".github/workflows/ci.yml"


def test_selected_git_file_keeps_repo_path_with_external_explicit_config(tmp_path: Path, capsys) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-b", "main")
    workflow = root / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n  test:\n    steps:\n      - uses: outside/example-action@v1\n",
        encoding="utf-8",
    )
    external = tmp_path / "external.toml"
    external.write_text("[scan]\nworkers = 1\n", encoding="utf-8")

    assert (
        main(
            [
                "scan",
                str(workflow),
                "--config",
                str(external),
                "--format",
                "json",
                "--no-cache",
                "--no-fail",
            ]
        )
        == 0
    )
    document = json.loads(capsys.readouterr().out)
    finding = next(item for item in document["findings"] if item["rule_id"] == "IV-GHA-004")
    assert finding["path"] == ".github/workflows/ci.yml"


def test_selected_non_git_file_does_not_load_ancestor_config(tmp_path: Path, capsys) -> None:
    project = tmp_path / "project"
    project.mkdir()
    selected = project / "selected.py"
    selected.write_text("ancestor_marker\n", encoding="utf-8")
    (tmp_path / ".ironveil.toml").write_text(
        """
[[rules]]
id = "CUSTOM-ANCESTOR-001"
name = "Unsafe ancestor marker"
category = "iac"
severity = "high"
confidence = "high"
regex = "ancestor_marker"
message = "An unrelated ancestor config was loaded"
remediation = "Do not load it"
""",
        encoding="utf-8",
    )

    assert main(["scan", str(selected), "--format", "json", "--no-cache", "--no-fail"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert all(item["rule_id"] != "CUSTOM-ANCESTOR-001" for item in document["findings"])


def test_all_report_formats_write_files(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "safe.py").write_text("answer = 42\n", encoding="utf-8")
    suffixes = {"json": ".json", "sarif": ".sarif", "html": ".html", "junit": ".xml"}

    for format_name, suffix in suffixes.items():
        output = tmp_path / f"report{suffix}"
        code = main(
            [
                "scan",
                str(root),
                "--format",
                format_name,
                "--output",
                str(output),
                "--no-fail",
                "--no-cache",
            ]
        )
        assert code == 0
        assert output.stat().st_size > 0
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["schema_version"] == "1.0"
    assert json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "Content-Security-Policy" in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_baseline_create_and_verify(tmp_path: Path, capsys) -> None:
    value = "sk-" + "pQ6rS8tV0xY2zA4bC5dE7fG9hJ1kL3m"
    (tmp_path / "settings.py").write_text(f'OPENAI_API_KEY = "{value}"\n', encoding="utf-8")

    assert main(["baseline", "create", str(tmp_path)]) == 0
    assert (tmp_path / ".ironveil-baseline.json").exists()
    assert main(["baseline", "verify", str(tmp_path)]) == 0
    assert "Baseline verified" in capsys.readouterr().out

    second = "sk-" + "zA4bC6dE8fG0hJ2kL3mN5pQ7rS9tV1x"
    (tmp_path / "new.py").write_text(f'OPENAI_API_KEY = "{second}"\n', encoding="utf-8")
    assert main(["baseline", "verify", str(tmp_path)]) == 1


def test_init_refuses_silent_overwrite(tmp_path: Path, capsys) -> None:
    assert main(["init", str(tmp_path)]) == 0
    assert main(["init", str(tmp_path)]) == 2
    assert "already exists" in capsys.readouterr().err


def test_init_force_replaces_symlink_without_touching_its_target(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    external = tmp_path / "external.toml"
    external.write_text("do not overwrite\n", encoding="utf-8")
    destination = root / ".ironveil.toml"
    destination.symlink_to(external)

    assert main(["init", str(root), "--force"]) == 0

    assert not destination.is_symlink()
    assert "[scan]" in destination.read_text(encoding="utf-8")
    assert external.read_text(encoding="utf-8") == "do not overwrite\n"


def test_text_report_file_has_no_ansi_even_when_stdout_is_a_tty(tmp_path: Path, monkeypatch) -> None:
    class TTYBuffer(io.StringIO):
        def isatty(self) -> bool:
            return True

    root = tmp_path / "repo"
    root.mkdir()
    value = "sk-" + "Q6rS8tV0xY2zA4bC5dE7fG9hJ1kL3mN"
    (root / "settings.py").write_text(f'OPENAI_API_KEY = "{value}"\n', encoding="utf-8")
    destination = tmp_path / "report.txt"
    monkeypatch.setattr("ironveil.cli.sys.stdout", TTYBuffer())

    assert (
        main(
            [
                "scan",
                str(root),
                "--format",
                "text",
                "--output",
                str(destination),
                "--no-fail",
                "--no-cache",
            ]
        )
        == 0
    )
    assert "\x1b" not in destination.read_text(encoding="utf-8")


def test_ui_generates_report_and_uses_loopback_server(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "safe.py").write_text("answer = 42\n", encoding="utf-8")
    observed: dict[str, object] = {}

    def fake_serve(path: Path, *, port: int, open_browser: bool) -> None:
        observed["html"] = path.read_text(encoding="utf-8")
        observed["port"] = port
        observed["open_browser"] = open_browser

    monkeypatch.setattr("ironveil.cli.serve_report", fake_serve)

    assert main(["ui", str(tmp_path), "--port", "9876", "--no-open"]) == 0
    assert observed["port"] == 9876
    assert observed["open_browser"] is False
    assert "IronVeil" in str(observed["html"])


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_staged_and_diff_cli(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "IronVeil Test")
    _git(tmp_path, "config", "user.email", "ironveil@example.invalid")
    (tmp_path / "file.py").write_text("first = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "file.py")
    _git(tmp_path, "commit", "-m", "first")
    first = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "file.py").write_text("first = 1\nsecond = 2\n", encoding="utf-8")
    _git(tmp_path, "add", "file.py")

    assert main(["staged", "--root", str(tmp_path), "--no-fail"]) == 0

    _git(tmp_path, "commit", "-m", "second")
    second = _git(tmp_path, "rev-parse", "HEAD")
    assert main(["diff", f"{first}..{second}", "--root", str(tmp_path), "--no-fail"]) == 0


def test_doctor_reports_environment_without_network(tmp_path: Path, capsys) -> None:
    code = main(["doctor", str(tmp_path), "--no-network"])
    output = capsys.readouterr().out

    assert code == 2
    assert "Python" in output
    assert "OSV online check: skipped" in output


def test_history_and_commit_cli(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "IronVeil Test")
    _git(tmp_path, "config", "user.email", "ironveil@example.invalid")
    (tmp_path / "safe.py").write_text("value = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "safe.py")
    _git(tmp_path, "commit", "-m", "first")
    commit = _git(tmp_path, "rev-parse", "HEAD")

    assert main(["history", str(tmp_path), "--max-commits", "5", "--no-fail"]) == 0
    assert main(["commit", commit, "--root", str(tmp_path), "--no-fail"]) == 0


def test_dependency_command_offline_and_online(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "requirements.txt").write_text("example-package>=1\n", encoding="utf-8")
    coordinate = PackageCoordinate("PyPI", "example-package", "1.0", "requirements.txt")
    monkeypatch.setattr("ironveil.cli.inventory", lambda root, scan_config: ([coordinate], []))
    monkeypatch.setattr("ironveil.cli.query_osv", lambda packages, config: ([], []))

    assert main(["dependencies", str(tmp_path), "--no-fail", "--no-cache"]) == 0
    assert main(["dependencies", str(tmp_path), "--online", "--no-fail", "--no-cache"]) == 0

    monkeypatch.setattr("ironveil.cli.query_osv", lambda packages, config: ([], ["offline in test"]))
    assert main(["dependencies", str(tmp_path), "--online", "--no-fail", "--no-cache"]) == 3


def test_baseline_update_and_create_conflict(tmp_path: Path, capsys) -> None:
    (tmp_path / "safe.py").write_text("safe = True\n", encoding="utf-8")
    assert main(["baseline", "create", str(tmp_path)]) == 0
    assert main(["baseline", "create", str(tmp_path)]) == 2
    assert "already exists" in capsys.readouterr().err
    assert main(["baseline", "update", str(tmp_path)]) == 0


def test_scan_rejects_missing_explicit_baseline(tmp_path: Path, capsys) -> None:
    (tmp_path / "safe.py").write_text("safe = True\n", encoding="utf-8")
    missing = tmp_path / "missing-baseline.json"

    assert main(["scan", str(tmp_path), "--baseline", str(missing), "--no-fail"]) == 2
    assert "explicit file does not exist" in capsys.readouterr().err


def test_cli_diagnostics_and_confirmation_paths_never_expose_embedded_secret(tmp_path: Path, capsys) -> None:
    secret = "sk-proj-" + "Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St1Uv0Wx"
    (tmp_path / "safe.py").write_text("safe = True\n", encoding="utf-8")
    missing_config = tmp_path / f"missing-{secret}.toml"

    assert main(["scan", str(tmp_path), "--config", str(missing_config)]) == 2
    assert secret not in capsys.readouterr().err

    baseline = tmp_path / f"baseline-{secret}.json"
    assert main(["baseline", "create", str(tmp_path), "--file", str(baseline)]) == 0
    assert baseline.exists()
    assert secret not in capsys.readouterr().out


def test_baseline_refuses_incomplete_scan_and_replaces_symlink_safely(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing"
    assert main(["baseline", "create", str(missing)]) == 2
    assert not missing.exists()
    assert "scan is incomplete" in capsys.readouterr().err

    root = tmp_path / "repo"
    root.mkdir()
    (root / "safe.py").write_text("safe = True\n", encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text("do not overwrite\n", encoding="utf-8")
    baseline = root / ".ironveil-baseline.json"
    baseline.symlink_to(outside)

    assert main(["baseline", "update", str(root)]) == 0
    assert not baseline.is_symlink()
    assert outside.read_text(encoding="utf-8") == "do not overwrite\n"


def test_ui_diff_and_history_modes(tmp_path: Path, monkeypatch) -> None:
    served: list[Path] = []
    monkeypatch.setattr("ironveil.cli.diff_lines", lambda root, commit_range: [])
    monkeypatch.setattr("ironveil.cli.history_lines", lambda root, max_commits: [])
    monkeypatch.setattr(
        "ironveil.cli.serve_report",
        lambda path, *, port, open_browser: served.append(Path(path)),
    )

    assert main(["ui", str(tmp_path), "--diff", "main...HEAD", "--no-open"]) == 0
    assert main(["ui", str(tmp_path), "--history", "--no-open"]) == 0
    assert len(served) == 2


def test_doctor_passes_in_git_repository(tmp_path: Path, capsys) -> None:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "IronVeil Test")
    _git(tmp_path, "config", "user.email", "ironveil@example.invalid")
    (tmp_path / "safe.py").write_text("safe = True\n", encoding="utf-8")
    _git(tmp_path, "add", "safe.py")
    _git(tmp_path, "commit", "-m", "first")

    assert main(["doctor", str(tmp_path), "--no-network"]) == 0
    assert "Git history" in capsys.readouterr().out


def test_doctor_rejects_custom_rule_collision_like_scan(tmp_path: Path, capsys) -> None:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "IronVeil Test")
    _git(tmp_path, "config", "user.email", "ironveil@example.invalid")
    (tmp_path / "safe.py").write_text("safe = True\n", encoding="utf-8")
    _git(tmp_path, "add", "safe.py")
    _git(tmp_path, "commit", "-m", "first")
    (tmp_path / ".ironveil.toml").write_text(
        """
[[rules]]
id = "IV-SEC-001"
name = "Collision"
category = "secret"
severity = "high"
confidence = "high"
regex = "collision"
message = "collision"
remediation = "rename"
""",
        encoding="utf-8",
    )

    assert main(["doctor", str(tmp_path), "--no-network"]) == 2
    output = capsys.readouterr().out
    assert "FAIL  Configuration" in output
    assert "duplicates a built-in rule" in output


def test_install_hook_preserves_existing_only_on_explicit_request(tmp_path: Path, capsys) -> None:
    _git(tmp_path, "init", "-b", "main")
    assert main(["install-hook", str(tmp_path)]) == 0
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")

    assert main(["install-hook", str(tmp_path)]) == 2
    assert "already exists" in capsys.readouterr().err
    assert main(["install-hook", str(tmp_path), "--backup-existing"]) == 0
    assert (tmp_path / ".git" / "hooks" / "pre-commit.ironveil-backup").exists()


def test_install_hook_refuses_symlink_escape_and_custom_hook_path(tmp_path: Path, capsys) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-b", "main")
    hook = root / ".git" / "hooks" / "pre-commit"
    outside = tmp_path / "outside-hook"
    hook.symlink_to(outside)

    assert main(["install-hook", str(root)]) == 2
    assert hook.is_symlink()
    assert not outside.exists()
    assert "symlinked pre-commit hook" in capsys.readouterr().err

    hook.unlink()
    _git(root, "config", "core.hooksPath", "custom-hooks")
    assert main(["install-hook", str(root)]) == 2
    assert "core.hooksPath" in capsys.readouterr().err


def test_install_hook_refuses_symlinked_hooks_directory(tmp_path: Path, capsys) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-b", "main")
    hooks = root / ".git" / "hooks"
    preserved = root / ".git" / "hooks-preserved"
    hooks.rename(preserved)
    outside = tmp_path / "outside-hooks"
    outside.mkdir()
    hooks.symlink_to(outside, target_is_directory=True)

    assert main(["install-hook", str(root)]) == 2
    assert not (outside / "pre-commit").exists()
    assert "hooks directory" in capsys.readouterr().err


def test_install_hook_does_not_trust_marker_substring(tmp_path: Path, capsys) -> None:
    _git(tmp_path, "init", "-b", "main")
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\n# Installed by IronVeil\necho untrusted\n", encoding="utf-8")
    hook.chmod(0o755)

    assert main(["install-hook", str(tmp_path)]) == 2
    assert "already exists" in capsys.readouterr().err


def test_cache_commands_and_invalid_policy(tmp_path: Path, monkeypatch, capsys) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "one.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("IRONVEIL_CACHE_DIR", str(cache))

    assert main(["cache", "stats"]) == 0
    assert "Entries: 1" in capsys.readouterr().out
    assert main(["cache", "clear"]) == 0
    assert main(["scan", str(tmp_path), "--fail-on", "unknown"]) == 2


def test_report_write_error_and_missing_scan_root(tmp_path: Path, capsys) -> None:
    missing_parent = tmp_path / "missing" / "report.json"
    assert main(["scan", str(tmp_path), "--output", str(missing_parent), "--format", "json"]) == 2
    assert "directory does not exist" in capsys.readouterr().err
    assert main(["scan", str(tmp_path / "absent")]) == 2


def test_empty_argv_shows_help() -> None:
    with pytest.raises(SystemExit, match="0"):
        main([])


def test_scan_cli_overrides_and_validation(tmp_path: Path) -> None:
    (tmp_path / "safe.bin").write_bytes(b"safe\0binary")
    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--workers",
                "1",
                "--max-size-mb",
                "1",
                "--all-files",
                "--scan-binary",
                "--fail-severity",
                "low",
                "--minimum-confidence",
                "low",
                "--no-fail",
            ]
        )
        == 0
    )
    assert main(["scan", str(tmp_path), "--workers", "0"]) == 2
    assert main(["scan", str(tmp_path), "--max-size-mb", "0"]) == 2
    assert main(["scan", str(tmp_path), "--max-size-mb", "1e100"]) == 2
    assert main(["scan", str(tmp_path), "--max-size-mb", "nan"]) == 2
    assert main(["scan", str(tmp_path), "--tracked-only", "--all-files"]) == 2
