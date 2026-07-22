"""HTML report template entrypoint used by the local UI."""

from __future__ import annotations

from ironveil import __version__
from ironveil.models import ScanResult
from ironveil.reporters.html import (
    CONTENT_SECURITY_POLICY,
    calculate_security_score,
    render_html,
)


def render_report_page(result: ScanResult, *, tool_version: str = __version__) -> str:
    return render_html(result, tool_version=tool_version)


__all__ = [
    "CONTENT_SECURITY_POLICY",
    "calculate_security_score",
    "render_report_page",
]
