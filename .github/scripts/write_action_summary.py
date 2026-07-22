"""Write IronVeil results to the GitHub Actions job summary.

The script only reads already-masked SARIF output. It deliberately avoids printing
messages, snippets, or matched values from findings.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ironveil.rules.secrets import redact_secrets


def _safe(value: object) -> str:
    """Escape text used in a Markdown table or inline code span."""

    text = redact_secrets(str(value), str(value))
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _artifact_url(value: str) -> str:
    """Accept only GitHub HTTPS artifact links without credentials or unsafe delimiters."""

    if redact_secrets(value, value) != value or any(character in value for character in "\r\n()<>`"):
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
    ):
        return ""
    return value


def _severity(result: dict[str, Any], rules: dict[str, dict[str, Any]]) -> str:
    rule_id = str(result.get("ruleId", "unknown"))
    rule = rules.get(rule_id, {})
    result_props = result.get("properties") or {}
    rule_props = rule.get("properties") or {}
    for source in (result_props, rule_props):
        value = source.get("severity")
        if isinstance(value, str):
            return value.lower()
    level = str(result.get("level", "note")).lower()
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "low")


def _read_results(path: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not path.is_file():
        return [], {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], {}
    runs = document.get("runs") or []
    if not runs:
        return [], {}
    run = runs[0]
    rules = {
        str(rule.get("id", "unknown")): rule
        for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules", [])
    }
    return list(run.get("results") or []), rules


def main() -> None:
    sarif_path = Path(os.environ["IRONVEIL_SARIF"])
    summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
    exit_code = int(os.environ.get("IRONVEIL_EXIT_CODE", "2"))
    results, rules = _read_results(sarif_path)
    active_results = [
        result for result in results if (result.get("properties") or {}).get("suppressed") is not True
    ]
    severities = Counter(_severity(result, rules) for result in active_results)
    rule_ids = Counter(str(result.get("ruleId", "unknown")) for result in active_results)

    status = {
        0: "Passed",
        1: "Policy findings detected",
        2: "Scan error",
        3: "Partial result",
    }.get(exit_code, f"Unexpected exit code {exit_code}")
    artifact_url = _artifact_url(os.environ.get("IRONVEIL_ARTIFACT_URL", ""))
    artifact_name = _safe(os.environ.get("IRONVEIL_ARTIFACT_NAME", "ironveil-html-report"))
    target = _safe(os.environ.get("IRONVEIL_TARGET", "."))
    fail_severity = _safe(os.environ.get("IRONVEIL_FAIL_SEVERITY", "high"))
    minimum_confidence = _safe(os.environ.get("IRONVEIL_MINIMUM_CONFIDENCE", "medium"))

    lines = [
        "## IronVeil security scan",
        "",
        f"**Status:** {status}",
        "",
        "| Findings | Critical | High | Medium |",
        "| ---: | ---: | ---: | ---: |",
        (
            f"| {len(active_results)} | {severities['critical']} | "
            f"{severities['high']} | {severities['medium']} |"
        ),
        "",
        "### Most frequent rules",
        "",
    ]
    if rule_ids:
        lines.extend(f"- `{_safe(rule_id)}`: {count}" for rule_id, count in rule_ids.most_common(5))
    else:
        lines.append("No findings were reported.")

    lines.extend(["", "### Report", ""])
    if artifact_url:
        lines.append(f"[{artifact_name}]({artifact_url})")
    else:
        lines.append(f"Artifact: `{artifact_name}`")
    lines.extend(
        [
            "",
            "### Reproduce locally",
            "",
            (
                f"`ironveil scan {target} --fail-severity {fail_severity} "
                f"--minimum-confidence {minimum_confidence}`"
            ),
            "",
            "> Finding messages and matched values are omitted from this summary by design.",
        ]
    )
    with summary_path.open("a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
