"""Reporter discovery and rendering API used by the CLI."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast, runtime_checkable

from ironveil import __version__
from ironveil.exceptions import ReportError
from ironveil.models import ScanResult

from .html import HTMLReporter
from .json import JSONReporter
from .junit import JUnitReporter
from .sarif import SARIFReporter
from .text import TextReporter


@runtime_checkable
class Reporter(Protocol):
    """Minimal interface implemented by built-in and third-party reporters."""

    @property
    def name(self) -> str: ...

    @property
    def suffix(self) -> str: ...

    @property
    def media_type(self) -> str: ...

    def render(self, result: ScanResult, *, tool_version: str = __version__) -> str: ...


class ReporterRegistry:
    """Validated, case-insensitive reporter registry."""

    def __init__(self, reporters: Iterable[Reporter] = ()) -> None:
        self._reporters: dict[str, Reporter] = {}
        for reporter in reporters:
            self.register(reporter)

    @staticmethod
    def _normalize(name: str) -> str:
        normalized = name.strip().casefold()
        if not normalized:
            raise ReportError("Report format cannot be empty")
        return normalized

    def register(self, reporter: Reporter, *, replace: bool = False) -> None:
        if not isinstance(reporter, Reporter):
            raise TypeError("Reporter must define name, suffix, media_type, and render()")
        name = self._normalize(reporter.name)
        if name in self._reporters and not replace:
            raise ReportError(f"Reporter format already registered: {name}")
        if not reporter.suffix.startswith("."):
            raise ReportError(f"Reporter suffix must start with '.': {reporter.suffix}")
        self._reporters[name] = reporter

    def get(self, name: str) -> Reporter:
        normalized = self._normalize(name)
        aliases = {"console": "text", "sarif2": "sarif", "xml": "junit"}
        normalized = aliases.get(normalized, normalized)
        try:
            return self._reporters[normalized]
        except KeyError as error:
            choices = ", ".join(self.names())
            raise ReportError(f"Unknown report format '{name}'. Choose one of: {choices}") from error

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._reporters))

    @property
    def reporters(self) -> Mapping[str, Reporter]:
        return MappingProxyType(self._reporters)

    def render(
        self,
        result: ScanResult,
        format_name: str,
        *,
        tool_version: str = __version__,
        **options: Any,
    ) -> str:
        renderer = cast(Callable[..., str], self.get(format_name).render)
        return renderer(result, tool_version=tool_version, **options)


registry = ReporterRegistry(
    (TextReporter(), JSONReporter(), SARIFReporter(), HTMLReporter(), JUnitReporter())
)
REPORTERS = registry.reporters


def available_reporters() -> tuple[str, ...]:
    return registry.names()


def get_reporter(name: str) -> Reporter:
    return registry.get(name)


def register_reporter(reporter: Reporter, *, replace: bool = False) -> None:
    registry.register(reporter, replace=replace)


def render_report(
    result: ScanResult,
    format_name: str,
    *,
    tool_version: str = __version__,
    **options: Any,
) -> str:
    return registry.render(result, format_name, tool_version=tool_version, **options)


def default_output_filename(format_name: str) -> str:
    reporter = get_reporter(format_name)
    names = {
        "text": "ironveil-report.txt",
        "json": "ironveil-report.json",
        "sarif": "ironveil.sarif",
        "html": "ironveil-report.html",
        "junit": "ironveil-junit.xml",
    }
    return names.get(reporter.name, f"ironveil-report{reporter.suffix}")


def write_report(
    result: ScanResult,
    format_name: str,
    output: str | Path | None = None,
    *,
    tool_version: str = __version__,
    **options: Any,
) -> Path:
    """Render and atomically write a UTF-8 report with private permissions."""

    content = render_report(result, format_name, tool_version=tool_version, **options)
    requested = Path(output or default_output_filename(format_name)).expanduser()
    try:
        parent = requested.parent.resolve(strict=True)
    except OSError as error:
        raise ReportError(f"Report output directory does not exist: {requested.parent}") from error
    target = parent / requested.name
    if target.exists() and target.is_dir():
        raise ReportError(f"Report output is a directory: {target}")

    temporary: Path | None = None
    descriptor: int | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=parent)
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o600)
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            errors="backslashreplace",
            newline="\n",
        ) as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
    except OSError as error:
        raise ReportError(f"Could not write report to {target}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise ReportError(f"Could not clean up temporary report {temporary}: {error}") from error
    return target


__all__ = [
    "REPORTERS",
    "Reporter",
    "ReporterRegistry",
    "available_reporters",
    "default_output_filename",
    "get_reporter",
    "register_reporter",
    "registry",
    "render_report",
    "write_report",
]
