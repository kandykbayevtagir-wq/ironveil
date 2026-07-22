"""Self-contained, offline HTML security reports."""

from __future__ import annotations

import base64
import hashlib
import math
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from html import escape
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from ironveil import __version__
from ironveil.models import (
    SEVERITY_RANK,
    Category,
    Confidence,
    Finding,
    ScanResult,
    Severity,
)

from ._common import (
    TOOL_NAME,
    display_path,
    ordered_errors,
    ordered_findings,
    ordered_warnings,
    report_safe_evidence,
    report_safe_text,
    scan_reference_date,
    stable_fingerprint,
    suppression_expiry_status,
)

SECURITY_SCORE_WEIGHTS: Mapping[Severity, int] = MappingProxyType(
    {
        Severity.CRITICAL: 25,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }
)

_CSS = r"""
:root {
  color-scheme: light dark;
  --bg: #f4f7fb;
  --surface: #ffffff;
  --surface-soft: #edf2f8;
  --text: #152033;
  --muted: #5c6b7d;
  --border: #d6dee9;
  --accent: #2854c5;
  --accent-strong: #173b99;
  --critical: #a51426;
  --high: #c13b16;
  --medium: #996500;
  --low: #126b7a;
  --info: #526173;
  --good: #147a4b;
  --warning-bg: #fff4cf;
  --danger-bg: #ffe8eb;
  --shadow: 0 8px 28px rgba(25, 44, 79, 0.09);
  --radius: 14px;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b1120;
    --surface: #121b2d;
    --surface-soft: #19243a;
    --text: #e8edf6;
    --muted: #a9b5c7;
    --border: #2a3852;
    --accent: #8aa9ff;
    --accent-strong: #b7c9ff;
    --critical: #ff7686;
    --high: #ff946f;
    --medium: #f1c766;
    --low: #6ed0df;
    --info: #b6c0cf;
    --good: #69d6a4;
    --warning-bg: #3c3218;
    --danger-bg: #3b1d25;
    --shadow: 0 8px 30px rgba(0, 0, 0, 0.27);
  }
}

:root[data-theme="light"] {
  color-scheme: light;
  --bg: #f4f7fb;
  --surface: #ffffff;
  --surface-soft: #edf2f8;
  --text: #152033;
  --muted: #5c6b7d;
  --border: #d6dee9;
  --accent: #2854c5;
  --accent-strong: #173b99;
  --critical: #a51426;
  --high: #c13b16;
  --medium: #996500;
  --low: #126b7a;
  --info: #526173;
  --good: #147a4b;
  --warning-bg: #fff4cf;
  --danger-bg: #ffe8eb;
  --shadow: 0 8px 28px rgba(25, 44, 79, 0.09);
}

:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0b1120;
  --surface: #121b2d;
  --surface-soft: #19243a;
  --text: #e8edf6;
  --muted: #a9b5c7;
  --border: #2a3852;
  --accent: #8aa9ff;
  --accent-strong: #b7c9ff;
  --critical: #ff7686;
  --high: #ff946f;
  --medium: #f1c766;
  --low: #6ed0df;
  --info: #b6c0cf;
  --good: #69d6a4;
  --warning-bg: #3c3218;
  --danger-bg: #3b1d25;
  --shadow: 0 8px 30px rgba(0, 0, 0, 0.27);
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
}
a { color: var(--accent); }
a:hover { color: var(--accent-strong); }
button, input, select { font: inherit; }
button:focus-visible, input:focus-visible, select:focus-visible, a:focus-visible {
  outline: 3px solid color-mix(in srgb, var(--accent) 55%, transparent);
  outline-offset: 2px;
}
[hidden] { display: none !important; }
.skip-link {
  position: absolute;
  left: 1rem;
  top: -5rem;
  background: var(--surface);
  color: var(--text);
  padding: .7rem 1rem;
  z-index: 20;
  border-radius: .5rem;
}
.skip-link:focus { top: 1rem; }
.topbar {
  background: linear-gradient(120deg, #10255b, #263f8f 55%, #315bb7);
  color: #fff;
  padding: 2rem max(1rem, calc((100vw - 1180px) / 2));
}
.topbar-inner {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1.5rem;
}
.eyebrow {
  margin: 0 0 .35rem;
  text-transform: uppercase;
  letter-spacing: .12em;
  font-size: .75rem;
  font-weight: 800;
  opacity: .85;
}
h1 { margin: 0; font-size: clamp(1.7rem, 5vw, 2.6rem); line-height: 1.12; }
.subtitle { margin: .55rem 0 0; color: #dce5ff; max-width: 70ch; }
.theme-button {
  border: 1px solid rgba(255, 255, 255, .45);
  background: rgba(255, 255, 255, .12);
  color: #fff;
  border-radius: 999px;
  padding: .55rem .9rem;
  cursor: pointer;
  white-space: nowrap;
}
.container { width: min(1180px, calc(100% - 2rem)); margin: 1.5rem auto 4rem; }
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 1.15rem;
  margin: 0 0 1.2rem;
}
.panel h2 { margin: 0 0 .85rem; font-size: 1.25rem; }
.panel h3 { margin: 1.15rem 0 .55rem; font-size: 1rem; }
.muted { color: var(--muted); }
.meta-grid, .stats-grid, .summary-grid {
  display: grid;
  gap: .8rem;
}
.summary-grid { grid-template-columns: repeat(auto-fit, minmax(128px, 1fr)); }
.meta-grid, .stats-grid { grid-template-columns: repeat(auto-fit, minmax(205px, 1fr)); }
.metric {
  background: var(--surface-soft);
  border: 1px solid var(--border);
  border-radius: 11px;
  padding: .85rem;
  min-width: 0;
}
.metric-label {
  display: block;
  color: var(--muted);
  font-size: .76rem;
  font-weight: 750;
  letter-spacing: .04em;
  text-transform: uppercase;
}
.metric-value { display: block; font-size: 1.55rem; font-weight: 800; margin-top: .15rem; }
.metric-value.small { font-size: .95rem; overflow-wrap: anywhere; }
.score-layout {
  display: grid;
  grid-template-columns: minmax(180px, 240px) 1fr;
  gap: 1.2rem;
  align-items: stretch;
}
.score-card {
  display: grid;
  place-items: center;
  text-align: center;
  background: var(--surface-soft);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.2rem;
}
.score-number { font-size: 3.2rem; font-weight: 850; line-height: 1; }
.score-out-of { color: var(--muted); font-size: .85rem; margin-top: .25rem; }
.score-good { color: var(--good); }
.score-caution { color: var(--medium); }
.score-danger { color: var(--critical); }
.formula {
  background: var(--surface-soft);
  border-radius: 9px;
  border: 1px solid var(--border);
  padding: .75rem;
  overflow-wrap: anywhere;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.controls {
  display: grid;
  grid-template-columns: minmax(230px, 2fr) repeat(5, minmax(120px, 1fr)) auto;
  gap: .65rem;
  align-items: end;
}
.control label { display: block; color: var(--muted); font-size: .78rem; margin-bottom: .25rem; }
.control input, .control select {
  width: 100%;
  min-height: 2.55rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  color: var(--text);
  padding: .5rem .6rem;
}
.clear-button {
  min-height: 2.55rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-soft);
  color: var(--text);
  padding: .5rem .8rem;
  cursor: pointer;
}
.result-count { color: var(--muted); margin: .8rem 0 0; }
.finding-list { display: grid; gap: .85rem; }
.finding {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 5px solid var(--info);
  border-radius: 11px;
  padding: 1rem;
  box-shadow: 0 3px 12px rgba(12, 30, 58, .06);
}
.finding.severity-critical { border-left-color: var(--critical); }
.finding.severity-high { border-left-color: var(--high); }
.finding.severity-medium { border-left-color: var(--medium); }
.finding.severity-low { border-left-color: var(--low); }
.finding.severity-info { border-left-color: var(--info); }
.finding-header { display: flex; justify-content: space-between; gap: .8rem; align-items: flex-start; }
.finding h3 { margin: 0; font-size: 1.02rem; overflow-wrap: anywhere; }
.location { margin: .28rem 0 0; color: var(--muted); overflow-wrap: anywhere; }
.badges { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: .35rem; }
.badge {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--surface-soft);
  color: var(--text);
  padding: .2rem .52rem;
  font-size: .72rem;
  font-weight: 750;
  white-space: nowrap;
}
.badge.critical { color: var(--critical); }
.badge.high { color: var(--high); }
.badge.medium { color: var(--medium); }
.badge.low { color: var(--low); }
.badge.info { color: var(--info); }
.badge.new { color: var(--critical); }
.badge.baseline { color: var(--medium); }
.badge.suppressed { color: var(--good); }
.badge.expired { color: var(--critical); background: var(--danger-bg); }
.details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: .75rem;
  margin-top: .85rem;
}
.detail {
  background: var(--surface-soft);
  border-radius: 8px;
  border: 1px solid var(--border);
  padding: .7rem;
  min-width: 0;
}
.detail-title { display: block; font-weight: 760; font-size: .8rem; margin-bottom: .25rem; }
.detail p { margin: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .86em;
  overflow-wrap: anywhere;
}
.reference-list { margin: .35rem 0 0; padding-left: 1.2rem; }
.reference-list li { overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
th, td { text-align: left; padding: .65rem; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: .74rem; text-transform: uppercase; letter-spacing: .04em; }
td { overflow-wrap: anywhere; }
.notice {
  border: 1px solid var(--border);
  border-radius: 9px;
  background: var(--warning-bg);
  padding: .75rem;
  margin-top: .7rem;
}
.empty {
  text-align: center;
  border: 1px dashed var(--border);
  border-radius: 10px;
  padding: 2rem 1rem;
  color: var(--muted);
}
.footer { color: var(--muted); text-align: center; font-size: .82rem; margin-top: 1.5rem; }

@media (max-width: 1050px) {
  .controls { grid-template-columns: repeat(3, 1fr); }
  .control.search { grid-column: 1 / -1; }
}
@media (max-width: 700px) {
  .topbar { padding: 1.4rem 1rem; }
  .topbar-inner, .finding-header { flex-direction: column; }
  .badges { justify-content: flex-start; }
  .container { width: min(100% - 1rem, 1180px); margin-top: .5rem; }
  .panel { padding: .85rem; border-radius: 10px; }
  .score-layout { grid-template-columns: 1fr; }
  .controls { grid-template-columns: 1fr 1fr; }
  .control.search { grid-column: 1 / -1; }
  .clear-button { width: 100%; }
}
@media (max-width: 430px) {
  .controls { grid-template-columns: 1fr; }
  .control.search { grid-column: auto; }
  .summary-grid { grid-template-columns: 1fr 1fr; }
}
@media print {
  .theme-button, .controls, .result-count, .skip-link { display: none; }
  body { background: #fff; color: #111; }
  .panel, .finding { box-shadow: none; break-inside: avoid; }
}
"""

_JAVASCRIPT = r"""
(() => {
  "use strict";

  const cards = Array.from(document.querySelectorAll("[data-finding]"));
  const controls = Array.from(document.querySelectorAll("[data-filter]"));
  const resultCount = document.getElementById("result-count");
  const clearButton = document.getElementById("clear-filters");

  function filterValue(name) {
    const element = document.getElementById(name);
    return element ? element.value.trim().toLocaleLowerCase() : "";
  }

  function applyFilters() {
    const query = filterValue("path-search");
    const severity = filterValue("severity-filter");
    const confidence = filterValue("confidence-filter");
    const category = filterValue("category-filter");
    const rule = filterValue("rule-filter");
    const state = filterValue("state-filter");
    let visible = 0;

    cards.forEach((card) => {
      const matches =
        (!query || (card.dataset.path || "").includes(query)) &&
        (!severity || card.dataset.severity === severity) &&
        (!confidence || card.dataset.confidence === confidence) &&
        (!category || card.dataset.category === category) &&
        (!rule || card.dataset.rule === rule) &&
        (!state || card.dataset.state === state);
      card.hidden = !matches;
      if (matches) visible += 1;
    });

    if (resultCount) {
      resultCount.textContent = `${visible} of ${cards.length} findings shown`;
    }
  }

  controls.forEach((control) => {
    control.addEventListener("input", applyFilters);
    control.addEventListener("change", applyFilters);
  });

  if (clearButton) {
    clearButton.addEventListener("click", () => {
      controls.forEach((control) => { control.value = ""; });
      applyFilters();
      const search = document.getElementById("path-search");
      if (search) search.focus();
    });
  }

  const root = document.documentElement;
  const themeButton = document.getElementById("theme-toggle");
  let savedTheme = "";
  try {
    savedTheme = window.localStorage.getItem("ironveil-theme") || "";
  } catch (_error) {
    savedTheme = "";
  }
  if (savedTheme === "light" || savedTheme === "dark") {
    root.dataset.theme = savedTheme;
  }
  if (themeButton) {
    themeButton.addEventListener("click", () => {
      const current = root.dataset.theme ||
        (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      const next = current === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      themeButton.setAttribute("aria-label", `Use ${current} theme`);
      try {
        window.localStorage.setItem("ironveil-theme", next);
      } catch (_error) {
        // Theme persistence is optional; the report remains fully functional.
      }
    });
  }

  applyFilters();
})();
"""


def _csp_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    f"style-src 'sha256-{_csp_hash(_CSS)}'; "
    f"script-src 'sha256-{_csp_hash(_JAVASCRIPT)}'; "
    "img-src data:; font-src 'none'; connect-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


def calculate_security_score(result: ScanResult) -> int:
    """Return a transparent 0-100 score based on active finding counts."""

    deduction = sum(SECURITY_SCORE_WEIGHTS[finding.severity] for finding in result.visible_findings())
    return max(0, 100 - deduction)


def security_score_breakdown(result: ScanResult) -> dict[str, Any]:
    active = result.visible_findings()
    counts = Counter(finding.severity for finding in active)
    raw_deduction = sum(counts[severity] * weight for severity, weight in SECURITY_SCORE_WEIGHTS.items())
    return {
        "score": max(0, 100 - raw_deduction),
        "deduction": min(100, raw_deduction),
        "raw_deduction": raw_deduction,
        "counts": {severity.value: counts[severity] for severity in Severity},
        "weights": {severity.value: SECURITY_SCORE_WEIGHTS[severity] for severity in Severity},
    }


def _h(value: object) -> str:
    return escape(report_safe_text(value), quote=True)


def _human_bytes(value: int) -> str:
    amount = float(max(0, value))
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or suffix == "TiB":
            return f"{int(amount)} {suffix}" if suffix == "B" else f"{amount:.1f} {suffix}"
        amount /= 1024
    return f"{amount:.1f} TiB"


def _finite_number(value: float, *, digits: int = 2) -> str:
    return f"{value:.{digits}f}" if math.isfinite(value) else "Unavailable"


def _metric(label: str, value: object, *, small: bool = False) -> str:
    value_class = "metric-value small" if small else "metric-value"
    return (
        '<div class="metric">'
        f'<span class="metric-label">{_h(label)}</span>'
        f'<span class="{value_class}">{_h(value)}</span>'
        "</div>"
    )


def _option(value: str, label: str) -> str:
    return f'<option value="{_h(value)}">{_h(label)}</option>'


def _safe_reference(reference: str) -> str | None:
    parsed = urlsplit(reference)
    if (
        parsed.scheme in {"https", "http"}
        and parsed.netloc
        and parsed.username is None
        and parsed.password is None
    ):
        return reference
    return None


def _references(finding: Finding) -> str:
    if not finding.references:
        return ""
    items: list[str] = []
    for reference in finding.references:
        safe_reference = _safe_reference(reference)
        if safe_reference:
            items.append(
                '<li><a target="_blank" rel="noopener noreferrer" '
                f'href="{_h(safe_reference)}">{_h(reference)}</a></li>'
            )
        else:
            items.append("<li>Unsupported reference</li>")
    return (
        '<div class="detail"><span class="detail-title">References</span>'
        f'<ul class="reference-list">{"".join(items)}</ul></div>'
    )


def _finding_card(finding: Finding, result: ScanResult) -> str:
    state = "suppressed" if finding.suppressed else "baseline" if finding.baseline else "new"
    state_label = state.capitalize()
    path = display_path(finding.path)
    suppression_status, suppression_label = suppression_expiry_status(
        finding, reference_date=scan_reference_date(result)
    )
    suppression_badge = ""
    suppression_detail = ""
    if finding.suppressed:
        status_class = "expired" if suppression_status in {"expired", "invalid"} else "suppressed"
        suppression_badge = f'<span class="badge {status_class}">{_h(suppression_label)}</span>'
        reason = finding.suppression_reason or "No reason supplied"
        suppression_detail = (
            '<div class="detail"><span class="detail-title">Suppression</span>'
            f"<p>{_h(reason)} — {_h(suppression_label)}</p></div>"
        )
    commit = ""
    if finding.commit:
        commit = (
            '<div class="detail"><span class="detail-title">Commit</span>'
            f"<p><code>{_h(finding.commit)}</code></p></div>"
        )
    evidence = ""
    if finding.evidence:
        evidence = (
            '<div class="detail"><span class="detail-title">Masked evidence</span>'
            f"<p><code>{_h(report_safe_evidence(finding))}</code></p></div>"
        )
    return "".join(
        (
            (
                f'<article class="finding severity-{finding.severity.value}" '
                "data-finding "
                f'data-path="{_h(path.casefold())}" '
                f'data-severity="{finding.severity.value}" '
                f'data-confidence="{finding.confidence.value}" '
                f'data-category="{finding.category.value}" '
                f'data-rule="{_h(finding.rule_id.casefold())}" '
                f'data-state="{state}">'
            ),
            '<div class="finding-header"><div>',
            f"<h3>{_h(finding.rule_id)} · {_h(finding.rule_name)}</h3>",
            (
                f'<p class="location"><code>{_h(path)}:{max(1, finding.line)}:'
                f"{max(1, finding.column)}</code></p>"
            ),
            '</div><div class="badges">',
            f'<span class="badge {finding.severity.value}">{_h(finding.severity.value.upper())}</span>',
            f'<span class="badge">{_h(finding.confidence.value)} confidence</span>',
            f'<span class="badge">{_h(finding.category.value)}</span>',
            f'<span class="badge {state}">{_h(state_label)}</span>',
            suppression_badge,
            "</div></div>",
            f"<p>{_h(finding.message)}</p>",
            '<div class="details-grid">',
            '<div class="detail"><span class="detail-title">Remediation</span>',
            f"<p>{_h(finding.remediation)}</p></div>",
            evidence,
            suppression_detail,
            commit,
            _references(finding),
            "</div>",
            (
                '<p class="muted"><small>Source: '
                f"{_h(finding.source)} · Fingerprint: "
                f"<code>{_h(stable_fingerprint(finding))}</code></small></p>"
            ),
            "</article>",
        )
    )


def _summary_section(result: ScanResult) -> str:
    summary = result.summary()
    metrics = [
        _metric("Active findings", summary["total"]),
        _metric("New", summary["new"]),
        _metric("Baseline", summary["baseline"]),
        _metric("Suppressed", summary["suppressed"]),
    ]
    metrics.extend(
        _metric(severity.value.capitalize(), summary["by_severity"][severity.value])
        for severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        )
    )
    return (
        '<section class="panel" aria-labelledby="summary-title">'
        '<h2 id="summary-title">Summary</h2>'
        f'<div class="summary-grid">{"".join(metrics)}</div></section>'
    )


def _score_section(result: ScanResult) -> str:
    breakdown = security_score_breakdown(result)
    score = breakdown["score"]
    score_class = "score-good" if score >= 80 else "score-caution" if score >= 50 else "score-danger"
    counts = breakdown["counts"]
    weights = breakdown["weights"]
    formula = (
        "100 - ("
        f"{weights['critical']} x {counts['critical']} critical + "
        f"{weights['high']} x {counts['high']} high + "
        f"{weights['medium']} x {counts['medium']} medium + "
        f"{weights['low']} x {counts['low']} low)"
    )
    return "".join(
        (
            '<section class="panel" aria-labelledby="score-title">',
            '<h2 id="score-title">Security score</h2>',
            '<div class="score-layout">',
            '<div class="score-card">',
            f'<div class="score-number {score_class}">{score}</div>',
            '<div class="score-out-of">out of 100</div>',
            f'<div class="muted">Deduction: {_h(breakdown["deduction"])}</div>',
            "</div><div>",
            (
                "<p>The score starts at 100 and subtracts fixed points for every "
                "active, unsuppressed finding. Baseline findings remain in the score "
                "because they are still unresolved. Info findings subtract zero points.</p>"
            ),
            f'<div class="formula">{_h(formula)}</div>',
            (
                '<p class="muted">The result is floored at zero. This is a simple '
                "prioritisation aid, not a probability, compliance grade, or substitute "
                "for reviewing the findings.</p>"
            ),
            "</div></div></section>",
        )
    )


def _metadata_section(result: ScanResult) -> str:
    commit = result.git_commit or "Not available"
    branch = result.git_branch or "Not available"
    metrics = (
        _metric("Scan time", result.started_at or "Not recorded", small=True),
        _metric("Root", result.root, small=True),
        _metric("Command", result.command or "scan", small=True),
        _metric("Git branch", branch, small=True),
        _metric("Git commit", commit, small=True),
        _metric("History scan", "Completed" if result.history_scanned else "Not run", small=True),
        _metric(
            "Dependency scan",
            "Completed" if result.dependencies_scanned else "Not run",
            small=True,
        ),
        _metric("Config digest", result.config_digest or "Default configuration", small=True),
    )
    return (
        '<section class="panel" aria-labelledby="metadata-title">'
        '<h2 id="metadata-title">Scan context</h2>'
        f'<div class="meta-grid">{"".join(metrics)}</div></section>'
    )


def _statistics_section(result: ScanResult) -> str:
    stats = result.stats
    metrics = (
        _metric("Files discovered", stats.files_discovered),
        _metric("Files scanned", stats.files_scanned),
        _metric("Files skipped", stats.files_skipped),
        _metric("Cache hits", stats.cache_hits),
        _metric("Bytes scanned", _human_bytes(stats.bytes_scanned)),
        _metric("Duration", f"{_finite_number(stats.duration_seconds, digits=3)} s"),
        _metric(
            "Scan rate",
            f"{_human_bytes(int(stats.scan_rate))}/s" if math.isfinite(stats.scan_rate) else "Unavailable",
        ),
        _metric("Scan errors", len(result.errors)),
    )
    return (
        '<section class="panel" aria-labelledby="statistics-title">'
        '<h2 id="statistics-title">Scan statistics</h2>'
        f'<div class="stats-grid">{"".join(metrics)}</div></section>'
    )


def _controls(result: ScanResult) -> str:
    rules = sorted({finding.rule_id for finding in result.findings}, key=str.casefold)
    severity_options = "".join(_option(severity.value, severity.value.capitalize()) for severity in Severity)
    confidence_options = "".join(
        _option(confidence.value, confidence.value.capitalize()) for confidence in Confidence
    )
    category_options = "".join(
        _option(category.value, category.value.replace("-", " ").title()) for category in Category
    )
    rule_options = "".join(_option(rule.casefold(), rule) for rule in rules)
    state_options = "".join(
        _option(value, label)
        for value, label in (
            ("new", "New"),
            ("baseline", "Baseline"),
            ("suppressed", "Suppressed"),
        )
    )
    return f"""
<section class="panel" aria-labelledby="filters-title">
  <h2 id="filters-title">Findings</h2>
  <div class="controls">
    <div class="control search">
      <label for="path-search">Search path</label>
      <input id="path-search" data-filter type="search" placeholder="src/settings.py"
             autocomplete="off" spellcheck="false">
    </div>
    <div class="control">
      <label for="severity-filter">Severity</label>
      <select id="severity-filter" data-filter><option value="">All</option>{severity_options}</select>
    </div>
    <div class="control">
      <label for="confidence-filter">Confidence</label>
      <select id="confidence-filter" data-filter><option value="">All</option>{confidence_options}</select>
    </div>
    <div class="control">
      <label for="category-filter">Category</label>
      <select id="category-filter" data-filter><option value="">All</option>{category_options}</select>
    </div>
    <div class="control">
      <label for="rule-filter">Rule</label>
      <select id="rule-filter" data-filter><option value="">All</option>{rule_options}</select>
    </div>
    <div class="control">
      <label for="state-filter">State</label>
      <select id="state-filter" data-filter><option value="">All</option>{state_options}</select>
    </div>
    <button class="clear-button" id="clear-filters" type="button">Clear</button>
  </div>
  <p class="result-count" id="result-count" aria-live="polite"></p>
</section>
"""


def _findings_section(result: ScanResult) -> str:
    findings = ordered_findings(result)
    if not findings:
        content = (
            '<div class="empty"><strong>No findings.</strong><br>'
            "The scan did not report any active, baseline, or suppressed findings.</div>"
        )
    else:
        content = (
            '<div class="finding-list">'
            + "".join(_finding_card(finding, result) for finding in findings)
            + "</div>"
        )
    return _controls(result) + content


def _baseline_section(result: ScanResult) -> str:
    summary = result.summary()
    return "".join(
        (
            '<section class="panel" aria-labelledby="baseline-title">',
            '<h2 id="baseline-title">Baseline and gating</h2>',
            '<div class="summary-grid">',
            _metric("New findings", summary["new"]),
            _metric("Baseline findings", summary["baseline"]),
            _metric("Suppressed findings", summary["suppressed"]),
            "</div>",
            (
                '<p class="muted">Baseline findings are existing, unsuppressed issues. '
                "They remain visible and count toward the security score, while CI can "
                "gate only on new findings. Suppressed findings are excluded from the "
                "active totals and score.</p>"
            ),
            "</section>",
        )
    )


def _suppressions_section(result: ScanResult) -> str:
    suppressed = [finding for finding in ordered_findings(result) if finding.suppressed]
    reference_date = scan_reference_date(result)
    rows: list[str] = []
    expired = 0
    for finding in suppressed:
        status, label = suppression_expiry_status(finding, reference_date=reference_date)
        if status in {"expired", "invalid"}:
            expired += 1
        status_class = "expired" if status in {"expired", "invalid"} else "suppressed"
        rows.append(
            "<tr>"
            f"<td><code>{_h(finding.rule_id)}</code></td>"
            f"<td><code>{_h(display_path(finding.path))}:{max(1, finding.line)}</code></td>"
            f"<td>{_h(finding.suppression_reason or 'No reason supplied')}</td>"
            f'<td><span class="badge {status_class}">{_h(label)}</span></td>'
            "</tr>"
        )
    if rows:
        content = (
            '<div class="table-wrap"><table><thead><tr>'
            "<th>Rule</th><th>Location</th><th>Reason</th><th>Status</th>"
            f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        )
    else:
        content = '<div class="empty">No suppressions were applied.</div>'
    notice = (
        f'<div class="notice"><strong>{expired} expired or invalid suppression'
        f"{'' if expired == 1 else 's'}.</strong> Review these exclusions.</div>"
        if expired
        else ""
    )
    return (
        '<section class="panel" aria-labelledby="suppressions-title">'
        '<h2 id="suppressions-title">Suppressions</h2>'
        f"{content}{notice}</section>"
    )


def _category_and_files_section(result: ScanResult) -> str:
    active = result.visible_findings()
    categories = Counter(finding.category for finding in active)
    category_rows = "".join(
        f"<tr><td>{_h(category.value.replace('-', ' ').title())}</td><td>{categories[category]}</td></tr>"
        for category in Category
    )
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for finding in active:
        by_file[display_path(finding.path)].append(finding)
    file_rows: list[str] = []
    for path, findings in sorted(by_file.items(), key=lambda pair: (-len(pair[1]), pair[0].casefold())):
        highest = max(findings, key=lambda finding: SEVERITY_RANK[finding.severity])
        file_rows.append(
            f"<tr><td><code>{_h(path)}</code></td><td>{len(findings)}</td>"
            f'<td><span class="badge {highest.severity.value}">'
            f"{_h(highest.severity.value.upper())}</span></td></tr>"
        )
    files_body = (
        "".join(file_rows) if file_rows else '<tr><td colspan="3">No files with active findings.</td></tr>'
    )
    return f"""
<section class="panel" aria-labelledby="distribution-title">
  <h2 id="distribution-title">Distribution</h2>
  <div class="details-grid">
    <div class="detail">
      <span class="detail-title">Active findings by category</span>
      <div class="table-wrap"><table><thead><tr><th>Category</th><th>Count</th></tr>
      </thead><tbody>{category_rows}</tbody></table></div>
    </div>
    <div class="detail">
      <span class="detail-title">Files with active findings</span>
      <div class="table-wrap"><table><thead><tr><th>File</th><th>Count</th><th>Highest</th></tr>
      </thead><tbody>{files_body}</tbody></table></div>
    </div>
  </div>
</section>
"""


def _diagnostics_section(result: ScanResult) -> str:
    warnings = ordered_warnings(result)
    errors = ordered_errors(result)
    if not warnings and not errors:
        return ""
    rows: list[str] = []
    rows.extend(f"<tr><td>Warning</td><td>—</td><td>{_h(warning)}</td></tr>" for warning in warnings)
    rows.extend(
        f"<tr><td>{'Fatal error' if error.fatal else 'Scan error'}</td>"
        f"<td><code>{_h(display_path(error.path))}</code></td>"
        f"<td>{_h(error.message)}</td></tr>"
        for error in errors
    )
    return (
        '<section class="panel" aria-labelledby="diagnostics-title">'
        '<h2 id="diagnostics-title">Warnings and scan errors</h2>'
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Type</th><th>Path</th><th>Message</th></tr></thead><tbody>"
        f"{''.join(rows)}</tbody></table></div></section>"
    )


@dataclass(frozen=True, slots=True)
class HTMLReporter:
    """Render a portable report with no network or build-time dependencies."""

    name: str = "html"
    suffix: str = ".html"
    media_type: str = "text/html; charset=utf-8"

    def render(self, result: ScanResult, *, tool_version: str = __version__) -> str:
        head = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="{_h(CONTENT_SECURITY_POLICY)}">
  <title>{TOOL_NAME} security report</title>
  <style>{_CSS}</style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to report</a>
<header class="topbar">
  <div class="topbar-inner">
    <div>
      <p class="eyebrow">{TOOL_NAME} {_h(tool_version)}</p>
      <h1>Repository security report</h1>
      <p class="subtitle">Local-first scan results. Evidence is rendered only from the
      scanner's masked finding model.</p>
    </div>
    <button class="theme-button" id="theme-toggle" type="button"
            aria-label="Toggle light and dark theme">Theme</button>
  </div>
</header>
<main class="container" id="main-content">
"""
        body = "".join(
            (
                _summary_section(result),
                _score_section(result),
                _metadata_section(result),
                _statistics_section(result),
                _baseline_section(result),
                _suppressions_section(result),
                _category_and_files_section(result),
                _diagnostics_section(result),
                _findings_section(result),
            )
        )
        footer = f"""
  <p class="footer">Generated locally by {TOOL_NAME} {_h(tool_version)}.
  No report assets require an internet connection.</p>
</main>
<script>{_JAVASCRIPT}</script>
</body>
</html>
"""
        return head + body + footer


def render(result: ScanResult, *, tool_version: str = __version__) -> str:
    return HTMLReporter().render(result, tool_version=tool_version)


render_html = render

__all__ = [
    "CONTENT_SECURITY_POLICY",
    "SECURITY_SCORE_WEIGHTS",
    "HTMLReporter",
    "calculate_security_score",
    "render",
    "render_html",
    "security_score_breakdown",
]
