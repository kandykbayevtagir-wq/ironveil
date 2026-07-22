from __future__ import annotations

import os
from pathlib import Path

import pytest

from ironveil.config import ScanConfig
from ironveil.core.discovery import discover_files


def test_discovery_excludes_generated_and_cache_dirs(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("ok", encoding="utf-8")
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "skip.py").write_text("skip", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "skip.js").write_text("skip", encoding="utf-8")

    result = discover_files(tmp_path, ScanConfig(exclude=["generated/**"]))

    assert [item.name for item in result.files] == ["keep.py"]
    assert result.skipped >= 2


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink unavailable")
def test_symlink_cannot_escape_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    (root / "link.txt").symlink_to(outside)

    result = discover_files(root, ScanConfig(follow_symlinks=True))

    assert result.files == []
    assert result.skipped == 1


def test_tracked_only_requires_git_instead_of_broadening_scope(tmp_path: Path) -> None:
    (tmp_path / "untracked.py").write_text("value = 1\n", encoding="utf-8")

    result = discover_files(tmp_path, ScanConfig(tracked_only=True))

    assert result.files == []
    assert result.errors and result.errors[0].fatal
    assert "requires an accessible Git repository" in result.errors[0].message


def test_walk_error_marks_scan_incomplete(tmp_path: Path, monkeypatch) -> None:
    def failing_walk(root: Path, *, followlinks: bool, onerror):
        onerror(PermissionError(13, "permission denied", str(root)))
        return iter(())

    monkeypatch.setattr("ironveil.core.discovery.os.walk", failing_walk)

    result = discover_files(tmp_path, ScanConfig())

    assert result.files == []
    assert result.errors and result.errors[0].fatal
    assert "Cannot traverse directory" in result.errors[0].message
