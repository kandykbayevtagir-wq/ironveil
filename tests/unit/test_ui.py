from __future__ import annotations

import http.client
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from ironveil.reporters.html import CONTENT_SECURITY_POLICY
from ironveil.ui.server import (
    LOOPBACK_HOST,
    LocalReportServer,
    UIServerError,
    create_html_server,
    create_server,
    open_report_browser,
    server_url,
)


@pytest.fixture
def running_server() -> Iterator[LocalReportServer]:
    server = create_html_server("<!doctype html><title>Masked report</title>", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _connection(server: LocalReportServer) -> http.client.HTTPConnection:
    _, port = cast(tuple[str, int], server.server_address)
    return http.client.HTTPConnection(LOOPBACK_HOST, port, timeout=2)


def test_server_binds_only_ipv4_loopback_and_serves_report(
    running_server: LocalReportServer,
) -> None:
    host, port = cast(tuple[str, int], running_server.server_address)
    assert host == LOOPBACK_HOST
    assert server_url(running_server) == f"http://{LOOPBACK_HOST}:{port}/"

    connection = _connection(running_server)
    connection.request("GET", "/")
    response = connection.getresponse()
    assert response.status == 200
    assert response.read() == b"<!doctype html><title>Masked report</title>"
    assert response.getheader("Content-Security-Policy") == CONTENT_SECURITY_POLICY
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    assert response.getheader("Cache-Control") == "no-store, max-age=0"
    connection.close()


def test_server_rejects_dns_rebinding_host_header(
    running_server: LocalReportServer,
) -> None:
    connection = _connection(running_server)
    connection.putrequest("GET", "/", skip_host=True)
    connection.putheader("Host", "attacker.invalid")
    connection.endheaders()
    response = connection.getresponse()
    assert response.status == 421
    assert response.read() == b"Misdirected request\n"
    connection.close()


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    (("GET", "/../../etc/passwd", 404), ("POST", "/", 405)),
)
def test_server_exposes_no_files_or_write_methods(
    running_server: LocalReportServer, method: str, path: str, expected: int
) -> None:
    connection = _connection(running_server)
    connection.request(method, path)
    response = connection.getresponse()
    assert response.status == expected
    response.read()
    connection.close()


def test_head_and_health_endpoints(running_server: LocalReportServer) -> None:
    connection = _connection(running_server)
    connection.request("HEAD", "/index.html")
    response = connection.getresponse()
    assert response.status == 200
    assert response.read() == b""
    connection.close()

    connection = _connection(running_server)
    connection.request("GET", "/healthz")
    response = connection.getresponse()
    assert response.status == 200
    assert response.read() == b"ok\n"
    connection.close()


def test_create_server_reads_one_explicit_report(tmp_path: Path) -> None:
    report = tmp_path / "report.html"
    report.write_text("<!doctype html><title>Report</title>", encoding="utf-8")
    server = create_server(report, port=0)
    try:
        assert server.report_document.endswith(b"<title>Report</title>")
        assert server.server_address[0] == LOOPBACK_HOST
    finally:
        server.server_close()

    with pytest.raises(UIServerError, match="Could not read HTML report"):
        create_server(tmp_path / "missing.html", port=0)


@pytest.mark.parametrize("port", (-1, 65536, True, "8765"))
def test_invalid_ports_are_rejected(port: object) -> None:
    with pytest.raises(UIServerError, match="port"):
        create_html_server("report", port=port)  # type: ignore[arg-type]


def test_browser_opening_accepts_only_constructed_loopback_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[tuple[str, int, bool]] = []

    def fake_open(url: str, *, new: int, autoraise: bool) -> bool:
        opened.append((url, new, autoraise))
        return True

    monkeypatch.setattr("ironveil.ui.server.webbrowser.open", fake_open)
    assert open_report_browser("http://127.0.0.1:8765/") is True
    assert opened == [("http://127.0.0.1:8765/", 2, True)]

    for unsafe in (
        "https://127.0.0.1:8765/",
        "http://localhost:8765/",
        "file:///tmp/report.html",
        "http://user@127.0.0.1:8765/",
    ):
        with pytest.raises(UIServerError, match="Refusing"):
            open_report_browser(unsafe)
