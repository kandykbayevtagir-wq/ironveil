from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import ironveil.core.git as git_module
from ironveil.config import Config, ScanConfig
from ironveil.core.discovery import discover_files
from ironveil.core.git import (
    GitError,
    commit_lines,
    diff_lines,
    history_lines,
    parse_added_lines,
    run_git,
    staged_lines,
)
from ironveil.core.scanner import Scanner


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "IronVeil Test")
    _git(root, "config", "user.email", "ironveil@example.invalid")
    (root / "app.py").write_text("print('first')\n", encoding="utf-8")
    _git(root, "add", "app.py")
    _git(root, "commit", "-m", "first")
    return root


def test_diff_staged_commit_and_history_added_lines(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    first = _git(root, "rev-parse", "HEAD")
    (root / "app.py").write_text("print('first')\nprint('second')\n", encoding="utf-8")
    _git(root, "add", "app.py")

    assert [item.text for item in staged_lines(root)] == ["print('second')"]

    _git(root, "commit", "-m", "second")
    second = _git(root, "rev-parse", "HEAD")

    assert [item.text for item in diff_lines(root, f"{first}..{second}")] == ["print('second')"]
    assert [item.text for item in commit_lines(root, second)] == ["print('second')"]
    historical = history_lines(root, max_commits=10)
    assert {item.text for item in historical} >= {"print('first')", "print('second')"}


def test_git_scans_preserve_metadata_only_paths_for_empty_files_and_renames(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "empty.env").write_text("", encoding="utf-8")
    _git(root, "add", "empty.env")

    empty = staged_lines(root)
    assert any(item.path == "empty.env" and item.metadata_only for item in empty)

    _git(root, "commit", "-m", "empty sensitive file")
    _git(root, "mv", "app.py", "credentials.json")
    renamed = staged_lines(root)
    assert any(item.path == "credentials.json" and item.metadata_only for item in renamed)
    assert all(item.path != "app.py" for item in renamed)


def test_git_output_and_history_are_bounded(tmp_path: Path, monkeypatch) -> None:
    root = _repository(tmp_path)
    with pytest.raises(GitError, match="safety limit"):
        run_git(root, ["rev-parse", "HEAD"], max_output_bytes=1)

    monkeypatch.setattr(git_module, "MAX_HISTORY_BYTES", 1)
    with pytest.raises(GitError, match="bounded scan limit"):
        history_lines(root, max_commits=1)


@pytest.mark.skipif(os.name == "nt", reason="POSIX textconv execution regression")
def test_git_scans_disable_repository_selected_textconv(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    marker = tmp_path / "textconv-ran"
    converter = tmp_path / "converter.sh"
    converter.write_text(
        f'#!/bin/sh\nprintf invoked > "{marker}"\ncat "$1"\n',
        encoding="utf-8",
    )
    converter.chmod(0o700)
    _git(root, "config", "diff.ironveil-test.textconv", str(converter))
    (root / ".gitattributes").write_text("*.fixture diff=ironveil-test\n", encoding="utf-8")
    (root / "data.fixture").write_text("before\n", encoding="utf-8")
    _git(root, "add", ".gitattributes", "data.fixture")
    _git(root, "commit", "-m", "add attributed fixture")
    (root / "data.fixture").write_text("after\n", encoding="utf-8")
    _git(root, "add", "data.fixture")

    assert [line.text for line in staged_lines(root)] == ["after"]
    assert not marker.exists()


def test_diff_parser_keeps_added_content_that_looks_like_a_file_header() -> None:
    patch = b"""diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1 @@
+++ synthetic_value = 1
"""

    lines = parse_added_lines(patch, "synthetic")

    assert [(line.path, line.line, line.text) for line in lines] == [("app.py", 1, "++ synthetic_value = 1")]


@pytest.mark.skipif(os.name == "nt", reason="POSIX fsmonitor execution regression")
def test_git_scans_disable_repository_selected_fsmonitor(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "app.py").write_text("print('changed')\n", encoding="utf-8")
    _git(root, "add", "app.py")
    marker = tmp_path / "fsmonitor-ran"
    monitor = tmp_path / "monitor.sh"
    monitor.write_text(f'#!/bin/sh\nprintf invoked > "{marker}"\n', encoding="utf-8")
    monitor.chmod(0o700)
    _git(root, "config", "core.fsmonitor", str(monitor))

    discovered = discover_files(root, ScanConfig())
    staged = staged_lines(root)

    assert not discovered.errors
    assert root / "app.py" in discovered.files
    assert [line.text for line in staged] == ["print('changed')"]
    assert not marker.exists()


def test_git_patch_paths_ignore_repository_mnemonic_prefixes(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    workflow = root / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: safe\non: push\njobs: {}\n", encoding="utf-8")
    _git(root, "add", ".github/workflows/ci.yml")
    _git(root, "commit", "-m", "add workflow")
    before = _git(root, "rev-parse", "HEAD")
    workflow.write_text(
        "name: risky\non: pull_request_target\npermissions: write-all\njobs: {}\n",
        encoding="utf-8",
    )
    _git(root, "add", ".github/workflows/ci.yml")
    _git(root, "config", "diff.mnemonicPrefix", "true")

    staged = staged_lines(root)
    staged_result = Scanner(Config()).scan_git_lines(root, staged, command="staged")

    assert {line.path for line in staged} == {".github/workflows/ci.yml"}
    assert "IV-GHA-001" in {finding.rule_id for finding in staged_result.findings}

    _git(root, "commit", "-m", "make workflow risky")
    after = _git(root, "rev-parse", "HEAD")
    changed = diff_lines(root, f"{before}..{after}")
    diff_result = Scanner(Config()).scan_git_lines(root, changed, command="diff")

    assert {line.path for line in changed} == {".github/workflows/ci.yml"}
    assert "IV-GHA-001" in {finding.rule_id for finding in diff_result.findings}


def test_git_patch_scans_ignore_binary_attributes(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    secret = "sk-proj-Ab3Cd5Ef7Gh9Z2Lm4Np6Qr8St1Uv0WxYz"
    (root / ".gitattributes").write_text("settings.py binary\n", encoding="utf-8")
    (root / "settings.py").write_text("safe = True\n", encoding="utf-8")
    _git(root, "add", ".gitattributes", "settings.py")
    _git(root, "commit", "-m", "add attributed file")
    (root / "settings.py").write_text(f'api_key = "{secret}"\n', encoding="utf-8")
    _git(root, "add", "settings.py")

    staged = staged_lines(root)
    result = Scanner(Config()).scan_git_lines(root, staged, command="staged")

    assert [line.text for line in staged] == [f'api_key = "{secret}"']
    assert any(finding.category.value == "secret" for finding in result.findings)


@pytest.mark.skipif(os.name == "nt", reason="POSIX signature verifier execution regression")
def test_git_show_disables_repository_selected_signature_verifier(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    original = _git(root, "cat-file", "commit", "HEAD")
    headers, message = original.split("\n\n", 1)
    signed_commit = (
        f"{headers}\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n"
        " synthetic fixture\n"
        " -----END PGP SIGNATURE-----\n\n"
        f"{message}\n"
    )
    completed = subprocess.run(
        ["git", "-C", str(root), "hash-object", "-t", "commit", "-w", "--stdin"],
        input=signed_commit,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    commit = completed.stdout.strip()
    _git(root, "update-ref", "HEAD", commit)
    marker = tmp_path / "signature-verifier-ran"
    verifier = tmp_path / "signature-verifier.sh"
    verifier.write_text(
        f'#!/bin/sh\nprintf invoked > "{marker}"\nexit 1\n',
        encoding="utf-8",
    )
    verifier.chmod(0o700)
    _git(root, "config", "log.showSignature", "true")
    _git(root, "config", "gpg.program", str(verifier))

    lines = commit_lines(root, commit)

    assert [line.text for line in lines] == ["print('first')"]
    assert not marker.exists()
