from __future__ import annotations

import pytest

from ironveil.rules.dependencies import analyze_dependency_file, supports_dependency_file
from ironveil.rules.files import match_file_rules


def _ids(matches: object) -> set[str]:
    return {match.rule.id for match in matches}  # type: ignore[attr-defined]


def test_sensitive_paths_large_files_and_junk_directories() -> None:
    sensitive = match_file_rules("config/.env.local", tracked=True)
    key = match_file_rules("deploy/id_ed25519", tracked=True)
    large = match_file_rules("assets/video.bin", size_bytes=11, max_size_bytes=10)
    junk = match_file_rules("node_modules/pkg/index.js", ignored=False)

    assert _ids(sensitive) == {"IV-FILE-001"}
    assert _ids(key) == {"IV-FILE-003"}
    assert _ids(large) == {"IV-FILE-010"}
    assert _ids(junk) == {"IV-FILE-011"}


@pytest.mark.parametrize(
    "path,rule_id",
    [
        ("config/.env.local", "IV-FILE-001"),
        ("secrets/service-account.json", "IV-FILE-002"),
        ("deploy/id_ed25519", "IV-FILE-003"),
        ("certs/server.p12", "IV-FILE-004"),
        ("android/release.keystore", "IV-FILE-005"),
        ("backups/production.sqlite3", "IV-FILE-006"),
        ("backups/source.tar.gz", "IV-FILE-007"),
        ("logs/npm-debug.log", "IV-FILE-008"),
        ("config/.pypirc", "IV-FILE-009"),
    ],
)
def test_every_sensitive_path_rule_has_a_positive_case(path: str, rule_id: str) -> None:
    assert rule_id in _ids(match_file_rules(path))


@pytest.mark.parametrize(
    "path,rule_id",
    [
        (".env.example", "IV-FILE-001"),
        ("docs/service-account.example.txt", "IV-FILE-002"),
        ("ssh/id_rsa.pub", "IV-FILE-003"),
        ("certs/server.crt", "IV-FILE-004"),
        ("android/keystore.txt", "IV-FILE-005"),
        ("docs/schema.sql.txt", "IV-FILE-006"),
        ("docs/archive.txt", "IV-FILE-007"),
        ("logs/application.log", "IV-FILE-008"),
        ("config/config.production.yml", "IV-FILE-009"),
    ],
)
def test_every_sensitive_path_rule_has_a_negative_case(path: str, rule_id: str) -> None:
    assert rule_id not in _ids(match_file_rules(path))


def test_ignored_junk_is_quiet_unless_all_files_is_requested() -> None:
    default = match_file_rules("build/output.js", ignored=True)
    exhaustive = match_file_rules("build/output.js", ignored=True, all_files=True)

    assert "IV-FILE-011" not in _ids(default)
    assert "IV-FILE-011" in _ids(exhaustive)


def test_templates_and_ambiguous_vendor_directories_avoid_noise() -> None:
    assert "IV-FILE-001" not in _ids(match_file_rules(".env.example"))
    assert "IV-FILE-011" not in _ids(match_file_rules("src/vendor/library.py"))
    assert "IV-FILE-011" in _ids(match_file_rules("src/vendor/library.py", vendor_applicable=True))


def test_offline_requirements_analysis_finds_source_and_pinning_risks() -> None:
    # The credential-looking URL is an explicit synthetic fixture and must never
    # be returned verbatim in detector evidence.
    text = """\
requests
flask>=2
demo-lib @ git+https://github.com/example/demo-lib.git@main
--index-url http://synthetic-user:SYNTHETIC-ONLY@packages.invalid/simple
-e ../shared-library
"""

    matches = analyze_dependency_file("requirements.txt", text)

    assert _ids(matches) >= {"IV-DEP-001", "IV-DEP-002", "IV-DEP-003", "IV-DEP-004", "IV-DEP-008"}
    assert all("SYNTHETIC-ONLY" not in match.evidence for match in matches)


def test_package_manifest_detects_lifecycle_script_and_suspicious_name() -> None:
    text = """{
      "dependencies": {"reqeusts": "*", "safe-package": "1.2.3"},
      "scripts": {"postinstall": "node ./scripts/setup.js"}
    }"""

    matches = analyze_dependency_file("package.json", text)

    assert _ids(matches) >= {"IV-DEP-002", "IV-DEP-005", "IV-DEP-006"}


def test_lockfile_without_integrity_is_reported() -> None:
    text = """{
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "synthetic-project"},
        "node_modules/safe-package": {
          "name": "safe-package",
          "version": "1.2.3",
          "resolved": "https://registry.npmjs.org/safe-package/-/safe-package-1.2.3.tgz"
        }
      }
    }"""

    matches = analyze_dependency_file("package-lock.json", text)

    assert _ids(matches) == {"IV-DEP-007"}


def test_dependency_file_support_is_explicit() -> None:
    assert supports_dependency_file("backend/requirements-dev.txt")
    assert supports_dependency_file("frontend/pnpm-lock.yaml")
    assert not supports_dependency_file("src/application.py")


def test_hash_pinned_requirement_is_exact_but_compatible_release_is_floating() -> None:
    text = """\
safe-package==1.2.3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
floating-package~=2.4
"""

    matches = analyze_dependency_file("requirements.txt", text)

    floating_packages = {
        dict(match.metadata).get("package") for match in matches if match.rule.id == "IV-DEP-002"
    }
    assert floating_packages == {"floating-package"}


def test_uv_lock_sources_are_analyzed_offline() -> None:
    text = """\
version = 1

[[package]]
name = "git-package"
version = "1.0.0"
source = { git = "https://github.com/example/git-package.git?branch=main" }

[[package]]
name = "registry-package"
version = "2.0.0"
source = { registry = "http://packages.invalid/simple" }

[[package]]
name = "local-package"
version = "0.1.0"
source = { editable = "../local-package" }
"""

    matches = analyze_dependency_file("uv.lock", text)

    assert _ids(matches) >= {"IV-DEP-003", "IV-DEP-004", "IV-DEP-008"}


def test_npm_lock_install_script_metadata_is_reported() -> None:
    text = """{
      "lockfileVersion": 3,
      "packages": {
        "node_modules/native-package": {
          "name": "native-package",
          "version": "1.0.0",
          "hasInstallScript": true
        }
      }
    }"""

    assert "IV-DEP-006" in _ids(analyze_dependency_file("package-lock.json", text))
