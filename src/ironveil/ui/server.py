"""Minimal HTTP server for viewing a generated report on loopback only."""

from __future__ import annotations

import os
import stat
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from ironveil.exceptions import IronVeilError
from ironveil.reporters.html import CONTENT_SECURITY_POLICY

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_REPORT_BYTES = 256 * 1024 * 1024


class UIServerError(IronVeilError):
    """Raised when the local report server cannot start safely."""


@dataclass(frozen=True, slots=True)
class ServerReady:
    url: str
    browser_opened: bool | None


class LocalReportServer(ThreadingHTTPServer):
    """Threaded HTTP server carrying one immutable in-memory document."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, document: bytes, *, port: int = DEFAULT_PORT) -> None:
        validated_port = _validate_port(port)
        self.report_document = document
        try:
            super().__init__((LOOPBACK_HOST, validated_port), ReportRequestHandler)
        except OSError as error:
            raise UIServerError(
                f"Could not bind the IronVeil UI to {LOOPBACK_HOST}:{validated_port}: {error}"
            ) from error
        bound_host = cast(tuple[str, int], self.server_address)[0]
        if bound_host != LOOPBACK_HOST:
            self.server_close()
            raise UIServerError(f"Refusing non-loopback UI binding: {bound_host!r}")


class ReportRequestHandler(BaseHTTPRequestHandler):
    """Serve only the report, a health probe, and an empty favicon."""

    server: LocalReportServer
    protocol_version = "HTTP/1.1"
    server_version = "IronVeilLocalUI/1"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: object) -> None:
        return

    def _valid_host_header(self) -> bool:
        host_header = self.headers.get("Host")
        if host_header is None:
            return self.request_version == "HTTP/1.0"
        try:
            parsed = urlsplit(f"//{host_header}")
            port = parsed.port
        except ValueError:
            return False
        expected_port = cast(tuple[str, int], self.server.server_address)[1]
        return parsed.hostname == LOOPBACK_HOST and (port is None or port == expected_port)

    def _security_headers(self, *, content_type: str, length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        self.send_header("Connection", "close")

    def _send(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str,
        include_body: bool,
        allow: str | None = None,
    ) -> None:
        self.send_response(status)
        self._security_headers(content_type=content_type, length=len(body))
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        if include_body and body:
            self.wfile.write(body)

    def _handle(self, *, include_body: bool) -> None:
        if not self._valid_host_header():
            self._send(
                421,
                b"Misdirected request\n",
                content_type="text/plain; charset=utf-8",
                include_body=include_body,
            )
            return
        try:
            path = urlsplit(self.path).path
        except ValueError:
            self._send(
                400,
                b"Bad request\n",
                content_type="text/plain; charset=utf-8",
                include_body=include_body,
            )
            return
        if path in {"/", "/index.html"}:
            self._send(
                200,
                self.server.report_document,
                content_type="text/html; charset=utf-8",
                include_body=include_body,
            )
        elif path == "/healthz":
            self._send(
                200,
                b"ok\n",
                content_type="text/plain; charset=utf-8",
                include_body=include_body,
            )
        elif path == "/favicon.ico":
            self._send(
                204,
                b"",
                content_type="image/x-icon",
                include_body=False,
            )
        else:
            self._send(
                404,
                b"Not found\n",
                content_type="text/plain; charset=utf-8",
                include_body=include_body,
            )

    def do_GET(self) -> None:
        self._handle(include_body=True)

    def do_HEAD(self) -> None:
        self._handle(include_body=False)

    def _method_not_allowed(self) -> None:
        if not self._valid_host_header():
            self._send(
                421,
                b"Misdirected request\n",
                content_type="text/plain; charset=utf-8",
                include_body=True,
            )
            return
        self._send(
            405,
            b"Method not allowed\n",
            content_type="text/plain; charset=utf-8",
            include_body=True,
            allow="GET, HEAD",
        )

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_OPTIONS = _method_not_allowed


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int):
        raise UIServerError("UI port must be an integer between 0 and 65535")
    if port < 0 or port > 65535:
        raise UIServerError("UI port must be between 0 and 65535")
    return port


def _read_report(path: str | os.PathLike[str]) -> bytes:
    requested = Path(path).expanduser()
    try:
        resolved = requested.resolve(strict=True)
    except OSError as error:
        raise UIServerError(f"Could not read HTML report {requested}: {error}") from error
    try:
        with resolved.open("rb") as stream:
            file_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise UIServerError(f"HTML report is not a regular file: {resolved}")
            if file_stat.st_size > MAX_REPORT_BYTES:
                raise UIServerError(
                    f"HTML report exceeds the {MAX_REPORT_BYTES // (1024 * 1024)} MiB UI limit"
                )
            document = stream.read(MAX_REPORT_BYTES + 1)
    except OSError as error:
        raise UIServerError(f"Could not read HTML report {resolved}: {error}") from error
    if len(document) > MAX_REPORT_BYTES:
        raise UIServerError(f"HTML report exceeds the {MAX_REPORT_BYTES // (1024 * 1024)} MiB UI limit")
    return document


def create_html_server(html: str | bytes, *, port: int = DEFAULT_PORT) -> LocalReportServer:
    document = html.encode("utf-8", errors="backslashreplace") if isinstance(html, str) else bytes(html)
    if len(document) > MAX_REPORT_BYTES:
        raise UIServerError(f"HTML report exceeds the {MAX_REPORT_BYTES // (1024 * 1024)} MiB UI limit")
    return LocalReportServer(document, port=port)


def create_server(report_path: str | os.PathLike[str], *, port: int = DEFAULT_PORT) -> LocalReportServer:
    return LocalReportServer(_read_report(report_path), port=port)


def server_url(server: LocalReportServer) -> str:
    host, port = cast(tuple[str, int], server.server_address)
    if host != LOOPBACK_HOST:
        raise UIServerError(f"Refusing non-loopback UI address: {host!r}")
    return f"http://{LOOPBACK_HOST}:{port}/"


def open_report_browser(url: str) -> bool:
    """Open only a constructed loopback HTTP URL, never a user-provided scheme."""

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise UIServerError(f"Invalid local report URL: {url!r}") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname != LOOPBACK_HOST
        or port is None
        or parsed.path != "/"
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise UIServerError(f"Refusing to open non-loopback report URL: {url!r}")
    return bool(webbrowser.open(url, new=2, autoraise=True))


def serve(
    server: LocalReportServer,
    *,
    open_browser: bool = True,
    on_ready: Callable[[ServerReady], None] | None = None,
) -> None:
    """Serve until interrupted, closing the listening socket on every exit."""

    try:
        url = server_url(server)
        browser_opened = open_report_browser(url) if open_browser else None
        if on_ready:
            on_ready(ServerReady(url=url, browser_opened=browser_opened))
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def serve_report(
    report_path: str | os.PathLike[str],
    *,
    port: int = DEFAULT_PORT,
    open_browser: bool = True,
    on_ready: Callable[[ServerReady], None] | None = None,
) -> None:
    serve(
        create_server(report_path, port=port),
        open_browser=open_browser,
        on_ready=on_ready,
    )


def serve_html(
    html: str | bytes,
    *,
    port: int = DEFAULT_PORT,
    open_browser: bool = True,
    on_ready: Callable[[ServerReady], None] | None = None,
) -> None:
    serve(
        create_html_server(html, port=port),
        open_browser=open_browser,
        on_ready=on_ready,
    )


run_server = serve_report

__all__ = [
    "DEFAULT_PORT",
    "LOOPBACK_HOST",
    "LocalReportServer",
    "ReportRequestHandler",
    "ServerReady",
    "UIServerError",
    "create_html_server",
    "create_server",
    "open_report_browser",
    "run_server",
    "serve",
    "serve_html",
    "serve_report",
    "server_url",
]
