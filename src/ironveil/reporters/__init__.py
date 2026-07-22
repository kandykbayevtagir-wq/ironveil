"""Stable report formats and the CLI-facing reporter registry."""

from .html import HTMLReporter, calculate_security_score, render_html
from .json import REPORT_SCHEMA_V1, JSONReporter, render_json
from .junit import JUnitReporter, render_junit
from .registry import (
    REPORTERS,
    Reporter,
    ReporterRegistry,
    available_reporters,
    default_output_filename,
    get_reporter,
    register_reporter,
    render_report,
    write_report,
)
from .sarif import SARIFReporter, render_sarif
from .text import TextReporter, render_text

__all__ = [
    "REPORTERS",
    "REPORT_SCHEMA_V1",
    "HTMLReporter",
    "JSONReporter",
    "JUnitReporter",
    "Reporter",
    "ReporterRegistry",
    "SARIFReporter",
    "TextReporter",
    "available_reporters",
    "calculate_security_score",
    "default_output_filename",
    "get_reporter",
    "register_reporter",
    "render_html",
    "render_json",
    "render_junit",
    "render_report",
    "render_sarif",
    "render_text",
    "write_report",
]
