from __future__ import annotations

import json
import runpy
from pathlib import Path


def test_action_summary_redacts_all_action_and_sarif_text(tmp_path: Path, monkeypatch) -> None:
    secret = "sk-proj-" + "Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St1Uv0Wx"
    sarif = tmp_path / "ironveil.sarif"
    summary = tmp_path / "summary.md"
    sarif.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": f"CUSTOM-{secret}",
                                        "properties": {"severity": "high"},
                                    }
                                ]
                            }
                        },
                        "results": [{"ruleId": f"CUSTOM-{secret}"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("IRONVEIL_SARIF", str(sarif))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("IRONVEIL_EXIT_CODE", "1")
    monkeypatch.setenv("IRONVEIL_TARGET", f"nested/bad-{secret}.py")
    monkeypatch.setenv("IRONVEIL_ARTIFACT_NAME", f"report-{secret}")
    monkeypatch.setenv("IRONVEIL_ARTIFACT_URL", f"https://github.com/example/repo/{secret}")

    script = Path(__file__).parents[2] / ".github" / "scripts" / "write_action_summary.py"
    namespace = runpy.run_path(str(script), run_name="ironveil_action_summary_test")
    namespace["main"]()

    rendered = summary.read_text(encoding="utf-8")
    assert secret not in rendered
    assert "redacted" in rendered
