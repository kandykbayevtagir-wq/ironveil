from pathlib import Path
from urllib.error import URLError

import ironveil.core.dependencies as dependency_module
from ironveil.config import DependencyConfig, ScanConfig
from ironveil.core.dependencies import PackageCoordinate, extract_packages, inventory, query_osv


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.read_size: int | None = None

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        self.read_size = size
        return self.body


def _coordinate() -> PackageCoordinate:
    return PackageCoordinate("PyPI", "example-package", "1.2.3", "requirements.txt", 1)


def _disable_osv_cache(monkeypatch) -> None:
    monkeypatch.setattr(dependency_module, "_load_osv_cache", lambda packages: None)
    monkeypatch.setattr(dependency_module, "_store_osv_cache", lambda packages, data: None)


def test_extract_pinned_python_requirements() -> None:
    packages = extract_packages(
        "requirements.txt",
        "alpha==1.2.3\nunpinned>=2\n-r other.txt\n",
    )

    assert [(item.ecosystem, item.name, item.version) for item in packages] == [("PyPI", "alpha", "1.2.3")]


def test_extract_package_lock() -> None:
    packages = extract_packages(
        "package-lock.json",
        '{"packages":{"node_modules/pkg":{"name":"pkg","version":"2.0.0"}}}',
    )

    assert packages[0].ecosystem == "npm"
    assert packages[0].name == "pkg"
    assert packages[0].version == "2.0.0"


def test_inventory_does_not_follow_symlink_or_scan_ignored_environment(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside-requirements.txt"
    outside.write_text("external-package==9.9.9\n", encoding="utf-8")
    (tmp_path / "requirements.txt").symlink_to(outside)
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "requirements.txt").write_text("ignored-package==1.0.0\n", encoding="utf-8")

    packages, warnings = inventory(tmp_path)

    assert packages == []
    assert warnings == []


def test_inventory_bounds_manifest_reads(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("package==1.0.0\n" * 200, encoding="utf-8")
    config = ScanConfig(max_size_mb=0.001)

    packages, warnings = inventory(tmp_path, config)

    assert packages == []
    assert any("oversized dependency file" in warning for warning in warnings)


def test_query_osv_network_unavailable_returns_warning_after_retries(monkeypatch) -> None:
    _disable_osv_cache(monkeypatch)
    attempts: list[float] = []
    delays: list[float] = []

    def unavailable(request, *, timeout: float):
        attempts.append(timeout)
        raise URLError("network unavailable")

    monkeypatch.setattr(dependency_module.urllib.request, "urlopen", unavailable)
    monkeypatch.setattr(dependency_module.time, "sleep", delays.append)

    findings, warnings = query_osv([_coordinate()], DependencyConfig(timeout_seconds=0.25, retries=2))

    assert findings == []
    assert len(attempts) == 3
    assert attempts == [0.25, 0.25, 0.25]
    assert delays == [0.25, 0.5]
    assert len(warnings) == 1
    assert "OSV lookup unavailable" in warnings[0]
    assert "network unavailable" in warnings[0]


def test_query_osv_retries_timeout_then_clears_warning_on_success(monkeypatch) -> None:
    _disable_osv_cache(monkeypatch)
    response = _Response(b'{"results":[{}]}')
    calls = 0
    delays: list[float] = []

    def timeout_then_success(request, *, timeout: float):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("timed out")
        return response

    monkeypatch.setattr(dependency_module.urllib.request, "urlopen", timeout_then_success)
    monkeypatch.setattr(dependency_module.time, "sleep", delays.append)

    findings, warnings = query_osv([_coordinate()], DependencyConfig(timeout_seconds=0.1, retries=1))

    assert calls == 2
    assert delays == [0.25]
    assert findings == []
    assert warnings == []
    assert response.read_size == dependency_module.MAX_OSV_RESPONSE_BYTES + 1


def test_query_osv_bounds_response_body(monkeypatch) -> None:
    _disable_osv_cache(monkeypatch)
    monkeypatch.setattr(dependency_module, "MAX_OSV_RESPONSE_BYTES", 32)
    response = _Response(b"x" * 33)
    monkeypatch.setattr(
        dependency_module.urllib.request,
        "urlopen",
        lambda request, *, timeout: response,
    )

    findings, warnings = query_osv([_coordinate()], DependencyConfig(timeout_seconds=0.1, retries=0))

    assert findings == []
    assert warnings == ["OSV response exceeded the 8 MiB safety limit"]
    assert response.read_size == 33
