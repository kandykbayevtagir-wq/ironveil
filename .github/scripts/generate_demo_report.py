"""Generate the Pages demo from an explicitly synthetic JSON fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ironveil.models import Category, Confidence, Finding, ScanResult, ScanStats, Severity
from ironveil.reporters import write_report


def _load_fixture(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise ValueError("Demo fixture must be an object with schema 1")
    return data


def _finding(raw: dict[str, Any]) -> Finding:
    evidence = str(raw["evidence"])
    if raw["category"] == "secret" and "••" not in evidence and "synthetic" not in evidence.casefold():
        raise ValueError("Demo evidence must be visibly masked or synthetic")
    return Finding(
        rule_id=str(raw["rule_id"]),
        rule_name=str(raw["rule_name"]),
        category=Category(str(raw["category"])),
        severity=Severity(str(raw["severity"])),
        confidence=Confidence(str(raw["confidence"])),
        path=str(raw["path"]),
        line=int(raw["line"]),
        column=int(raw["column"]),
        message=str(raw["message"]),
        remediation=str(raw["remediation"]),
        fingerprint=str(raw["fingerprint"]),
        evidence=evidence,
        source=str(raw.get("source", "synthetic-demo")),
        metadata={"synthetic": True},
    )


def generate(fixture_path: Path, output_path: Path) -> Path:
    raw = _load_fixture(fixture_path)
    stats = raw["stats"]
    result = ScanResult(
        root=Path(str(raw["root"])),
        command=str(raw["command"]),
        findings=[_finding(item) for item in raw["findings"]],
        warnings=["Synthetic demonstration: no repository was scanned and timing was not measured."],
        stats=ScanStats(
            files_discovered=int(stats["files_discovered"]),
            files_scanned=int(stats["files_scanned"]),
            files_skipped=int(stats["files_skipped"]),
            cache_hits=int(stats["cache_hits"]),
            bytes_scanned=int(stats["bytes_scanned"]),
            duration_seconds=float(stats["duration_seconds"]),
        ),
        config_digest="synthetic-demo-configuration",
        started_at=str(raw["started_at"]),
        git_branch=str(raw["git_branch"]),
        git_commit=str(raw["git_commit"]),
        history_scanned=False,
        dependencies_scanned=True,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return write_report(result, "html", output_path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    generate(args.fixture, args.output)


if __name__ == "__main__":
    main()
