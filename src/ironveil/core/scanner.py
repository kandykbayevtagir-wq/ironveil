"""Parallel, bounded repository scanning orchestration."""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from ironveil.config import Config, CustomRuleConfig
from ironveil.core.cache import FileCache
from ironveil.core.discovery import discover_files
from ironveil.core.fingerprint import fingerprint, fingerprint_from_digest, material_digest
from ironveil.core.git import GitLine, git_info, repository_root
from ironveil.core.masking import redact_values, safe_line_evidence
from ironveil.exceptions import ConfigurationError
from ironveil.models import (
    Category,
    Confidence,
    Finding,
    Rule,
    ScanError,
    ScanResult,
    Severity,
    finding_sort_key,
)
from ironveil.policy import apply_suppressions
from ironveil.rules.base import RuleMatch, line_column, rule_applies_to_path
from ironveil.rules.dependencies import analyze_dependency_file
from ironveil.rules.docker import analyze_dockerfile
from ironveil.rules.files import match_file_rules
from ironveil.rules.github_actions import analyze_workflow
from ironveil.rules.kubernetes import analyze_kubernetes, analyze_kubernetes_fragment
from ironveil.rules.registry import get_builtin_rules
from ironveil.rules.secrets import detect_secret_matches, redact_secrets
from ironveil.rules.terraform import analyze_terraform


@dataclass(slots=True)
class FileScanOutput:
    findings: list[Finding]
    warnings: list[str]
    bytes_scanned: int
    skipped: bool = False
    content_hash: str | None = None


def _finding_from_dict(value: dict[str, Any]) -> Finding:
    return Finding(
        rule_id=str(value["rule_id"]),
        rule_name=str(value["rule_name"]),
        category=Category(str(value["category"])),
        severity=Severity(str(value["severity"])),
        confidence=Confidence(str(value["confidence"])),
        path=str(value["path"]),
        line=int(value["line"]),
        column=int(value["column"]),
        message=str(value["message"]),
        remediation=str(value["remediation"]),
        fingerprint=str(value["fingerprint"]),
        evidence=str(value["evidence"]),
        references=tuple(str(item) for item in value.get("references", [])),
        source=str(value.get("source", "working-tree")),
        commit=str(value["commit"]) if value.get("commit") is not None else None,
        # Policy state is deliberately reconstructed for every scan.  Trusting
        # cached values could keep an expired suppression or a stale baseline.
        baseline=False,
        suppressed=False,
        suppression_reason=None,
        suppression_expires=None,
        metadata=dict(value.get("metadata", {})),
    )


def _custom_rule(value: CustomRuleConfig) -> Rule:
    return Rule(
        id=value.id,
        name=value.name,
        description=value.description,
        category=value.category,
        severity=value.severity,
        confidence=value.confidence,
        message=value.message,
        remediation=value.remediation,
        pattern=value.regex,
        detection_type="custom-regex",
        tags=("custom",),
    )


class Scanner:
    """Scan files and Git-provided text without executing repository content."""

    def __init__(self, config: Config, *, cache: FileCache | None = None) -> None:
        self.config = config
        self.cache = cache or FileCache()
        self.builtin_rules = get_builtin_rules()
        ids = {rule.id for rule in self.builtin_rules}
        duplicates = sorted(ids.intersection(item.id for item in config.rules))
        if duplicates:
            raise ConfigurationError(f"rules: custom rule ID duplicates a built-in rule: {duplicates[0]}")
        self.custom_rules = tuple(_custom_rule(item) for item in config.rules)

    def scan(self, root: Path, *, command: str = "scan") -> ScanResult:
        started = time.perf_counter()
        root = root.expanduser().resolve()
        relative_root = _selected_file_context(root, self.config) if root.is_file() else root
        result = self._new_result(root, command)
        result.dependencies_scanned = True
        discovery = discover_files(root, self.config.scan)
        result.errors.extend(discovery.errors)
        result.stats.files_discovered = len(discovery.files)
        result.stats.files_skipped = discovery.skipped
        if any(error.fatal for error in discovery.errors):
            result.stats.duration_seconds = time.perf_counter() - started
            return result
        for metadata_path in discovery.metadata_paths:
            matches = match_file_rules(
                metadata_path,
                all_files=self.config.scan.all_files,
                max_size_bytes=self.config.scan.max_size_bytes,
            )
            result.findings.extend(
                self._matches_without_text(
                    metadata_path,
                    matches,
                    "working-tree",
                    warnings=result.warnings,
                )
            )
        futures: dict[Future[FileScanOutput], tuple[Path, bool]] = {}
        with ThreadPoolExecutor(max_workers=self.config.scan.workers, thread_name_prefix="ironveil") as pool:
            for path in discovery.files:
                cached = None
                cache_candidate = False
                if self.config.scan.use_cache:
                    # The worker converts an inaccessible file to a scan error.
                    with suppress(OSError):
                        cache_candidate = path.stat().st_size <= self.config.scan.max_size_bytes
                if cache_candidate:
                    cached = self.cache.get(relative_root, path, result.config_digest)
                if cached is not None:
                    try:
                        cached_findings = [_finding_from_dict(item) for item in cached]
                        source_text = path.read_text(encoding="utf-8", errors="replace")
                        source_lines = source_text.splitlines()
                        relative_path = _relative(path, relative_root)
                        _, custom_secret_values = self._custom_matches(relative_path, source_text)
                        cache_warnings: list[str] = []
                        for finding in cached_findings:
                            # The discovery result, not cache-controlled JSON, is
                            # authoritative for path-based policy evaluation.
                            finding.path = relative_path
                            apply_suppressions(
                                finding,
                                source_lines,
                                self.config.allowlist,
                                cache_warnings,
                            )
                            _sanitize_finding(finding, relative_path, custom_secret_values)
                    except (KeyError, OSError, TypeError, ValueError):
                        cached = None
                    else:
                        result.findings.extend(cached_findings)
                        result.warnings.extend(
                            _safe_public_text(item, relative_path, custom_secret_values)
                            for item in cache_warnings
                        )
                        result.stats.cache_hits += 1
                        result.stats.files_scanned += 1
                        continue
                futures[pool.submit(self._scan_file, relative_root, path, "working-tree")] = (
                    path,
                    cached is not None,
                )
            for future in as_completed(futures):
                path, _ = futures[future]
                relative = _relative(path, relative_root)
                try:
                    output = future.result()
                except OSError as exc:
                    result.errors.append(ScanError(relative, f"Cannot scan file: {exc}"))
                    result.stats.files_skipped += 1
                    continue
                result.findings.extend(output.findings)
                result.warnings.extend(output.warnings)
                result.stats.bytes_scanned += output.bytes_scanned
                if output.skipped:
                    result.stats.files_skipped += 1
                else:
                    result.stats.files_scanned += 1
                if self.config.scan.use_cache and not output.skipped and output.content_hash is not None:
                    self.cache.put(
                        relative_root,
                        path,
                        result.config_digest,
                        output.content_hash,
                        [item.to_dict() for item in output.findings],
                    )
        _finalize(result, started)
        return result

    def scan_git_lines(self, root: Path, lines: Iterable[GitLine], *, command: str) -> ScanResult:
        started = time.perf_counter()
        root = root.expanduser().resolve()
        result = self._new_result(root, command)
        grouped: dict[tuple[str, str, str | None], list[GitLine]] = {}
        for item in lines:
            grouped.setdefault((item.path, item.source, item.commit), []).append(item)
        result.stats.files_discovered = len({key[0] for key in grouped})
        for (path, source, commit), items in sorted(grouped.items()):
            ordered = sorted(
                (item for item in items if not item.metadata_only),
                key=lambda item: item.line,
            )
            text = "\n".join(item.text for item in ordered)
            line_map = [item.line for item in ordered]
            output = self.scan_text(
                path,
                text,
                source=source,
                commit=commit,
                line_map=line_map,
                partial=True,
            )
            result.findings.extend(output.findings)
            result.warnings.extend(output.warnings)
            result.stats.bytes_scanned += output.bytes_scanned
            result.stats.files_scanned += 1
        _finalize(result, started)
        return result

    def scan_text(
        self,
        path: str,
        text: str,
        *,
        source: str = "memory",
        commit: str | None = None,
        line_map: list[int] | None = None,
        size_bytes: int | None = None,
        partial: bool = False,
    ) -> FileScanOutput:
        normalized = path.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        source_lines = text.splitlines()
        matches: list[RuleMatch] = list(
            match_file_rules(
                normalized,
                size_bytes=size_bytes,
                all_files=self.config.scan.all_files,
                max_size_bytes=self.config.scan.max_size_bytes,
            )
        )
        matches.extend(detect_secret_matches(text, normalized))
        matches.extend(analyze_dependency_file(normalized, text))
        file_name = PurePosixPath(normalized).name.casefold()
        suffix = PurePosixPath(normalized).suffix.casefold()
        if (
            file_name == "dockerfile"
            or file_name.startswith("dockerfile.")
            or file_name.endswith(".dockerfile")
        ):
            matches.extend(analyze_dockerfile(text, normalized, partial=partial))
        if normalized.casefold().startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
            matches.extend(analyze_workflow(text, normalized, partial=partial))
        if suffix == ".tf" or normalized.casefold().endswith(".tf.json"):
            matches.extend(analyze_terraform(text, normalized))
        if suffix in {".yml", ".yaml"}:
            if partial:
                matches.extend(analyze_kubernetes_fragment(text, normalized))
            elif re.search(r"(?im)^\s*apiVersion\s*:", text) and re.search(r"(?im)^\s*kind\s*:", text):
                matches.extend(analyze_kubernetes(text, normalized))
        custom_matches, custom_secret_values = self._custom_matches(normalized, text)
        matches.extend(custom_matches)
        findings: list[Finding] = []
        warnings: list[str] = []
        seen: set[str] = set()
        for match in matches:
            mapped_line = match.line
            if line_map and 1 <= match.line <= len(line_map):
                mapped_line = line_map[match.line - 1]
            raw_evidence = match.evidence.strip()[:240] or normalized
            custom_safe_evidence = redact_values(raw_evidence, custom_secret_values)
            evidence = redact_secrets(custom_safe_evidence, normalized).strip()[:240] or normalized
            metadata = dict(match.metadata)
            supplied_digest = metadata.pop("_fingerprint_digest", None)
            metadata = _safe_metadata(metadata, normalized, custom_secret_values)
            if isinstance(supplied_digest, str):
                value_digest = supplied_digest
            elif 1 <= match.line <= len(source_lines):
                value_digest = material_digest(source_lines[match.line - 1])
            else:
                value_digest = material_digest(raw_evidence)
            safe_message = _safe_public_text(match.rule.message, normalized, custom_secret_values)
            stable = fingerprint_from_digest(
                match.rule.id,
                normalized,
                value_digest,
                f"{safe_message}\0{evidence}",
            )
            if stable in seen:
                continue
            seen.add(stable)
            finding = Finding(
                rule_id=match.rule.id,
                rule_name=_safe_public_text(match.rule.name, normalized, custom_secret_values),
                category=match.rule.category,
                severity=match.rule.severity,
                confidence=match.rule.confidence,
                path=normalized,
                line=mapped_line,
                column=match.column,
                message=safe_message,
                remediation=_safe_public_text(match.rule.remediation, normalized, custom_secret_values),
                fingerprint=stable,
                evidence=evidence,
                references=tuple(
                    _safe_public_text(item, normalized, custom_secret_values)
                    for item in match.rule.references
                ),
                source=_safe_public_text(source, normalized, custom_secret_values),
                commit=(_safe_public_text(commit, normalized, custom_secret_values) if commit else None),
                metadata=metadata,
            )
            # Suppression indexes operate on the compact diff text before line remapping.
            suppression_line = finding.line
            finding.line = match.line
            apply_suppressions(finding, source_lines, self.config.allowlist, warnings)
            finding.line = suppression_line
            _sanitize_finding(finding, normalized, custom_secret_values)
            findings.append(finding)
        findings.sort(key=finding_sort_key)
        return FileScanOutput(
            findings=findings,
            warnings=sorted({_safe_public_text(item, normalized, custom_secret_values) for item in warnings}),
            bytes_scanned=len(text.encode("utf-8", errors="replace")),
            content_hash=hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        )

    def _custom_matches(self, path: str, text: str) -> tuple[list[RuleMatch], tuple[str, ...]]:
        matches: list[RuleMatch] = []
        secret_values: set[str] = set()
        for rule in self.custom_rules:
            if not rule_applies_to_path(rule, path) or not rule.pattern:
                continue
            regex = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            for found in regex.finditer(text):
                secret_group = found.re.groupindex.get("secret")
                if secret_group is not None and found.start(secret_group) >= 0:
                    start, end = found.span(secret_group)
                    fingerprint_value = found.group(secret_group)
                else:
                    # Positional groups commonly describe structure, not the
                    # sensitive value.  Masking group 1 can expose the rest.
                    start, end = found.span()
                    fingerprint_value = found.group()
                line, column = line_column(text, start)
                line_start = text.rfind("\n", 0, start) + 1
                line_end = text.find("\n", end)
                if line_end < 0:
                    line_end = len(text)
                source_line = text[line_start:line_end]
                evidence = safe_line_evidence(source_line, start - line_start, end - line_start)
                metadata: tuple[tuple[str, str | int | float | bool], ...] = (("detector", "custom-regex"),)
                if rule.category is Category.SECRET:
                    secret_values.add(fingerprint_value)
                    secret_values.update(
                        fragment for fragment in re.split(r"\r?\n", fingerprint_value) if fragment
                    )
                    secret_values.update(
                        fragment.strip()
                        for fragment in re.split(r"\r?\n", fingerprint_value)
                        if fragment.strip()
                    )
                    metadata += (
                        (
                            "_fingerprint_digest",
                            material_digest(fingerprint_value),
                        ),
                    )
                matches.append(
                    RuleMatch(
                        rule=rule,
                        line=line,
                        column=column,
                        evidence=evidence,
                        metadata=metadata,
                    )
                )
        return matches, tuple(sorted(secret_values, key=lambda item: (-len(item), item)))

    def _scan_file(self, root: Path, path: Path, source: str) -> FileScanOutput:
        relative = _relative(path, root)
        stat = path.stat()
        path_matches = match_file_rules(
            relative,
            size_bytes=stat.st_size,
            all_files=self.config.scan.all_files,
            max_size_bytes=self.config.scan.max_size_bytes,
        )
        if stat.st_size > self.config.scan.max_size_bytes:
            warnings: list[str] = []
            findings = self._matches_without_text(relative, path_matches, source, warnings=warnings)
            return FileScanOutput(findings, warnings, 0, skipped=True)
        with path.open("rb") as handle:
            data = handle.read(self.config.scan.max_size_bytes + 1)
        if len(data) > self.config.scan.max_size_bytes:
            warnings = []
            findings = self._matches_without_text(relative, path_matches, source, warnings=warnings)
            return FileScanOutput(findings, warnings, 0, skipped=True)
        content_hash = hashlib.sha256(data).hexdigest()
        if not self.config.scan.scan_binary and b"\0" in data[:8192]:
            warnings = []
            findings = self._matches_without_text(relative, path_matches, source, warnings=warnings)
            return FileScanOutput(findings, warnings, 0, skipped=True, content_hash=content_hash)
        text = data.decode("utf-8", errors="replace")
        output = self.scan_text(relative, text, source=source, size_bytes=stat.st_size)
        output.bytes_scanned = len(data)
        output.content_hash = content_hash
        return output

    def _matches_without_text(
        self,
        path: str,
        matches: Iterable[RuleMatch],
        source: str,
        *,
        warnings: list[str] | None = None,
    ) -> list[Finding]:
        result: list[Finding] = []
        local_warnings = warnings if warnings is not None else []
        for match in matches:
            evidence = redact_secrets(match.evidence[:240] or path, path)
            metadata = {key: value for key, value in match.metadata if not str(key).startswith("_")}
            finding = Finding(
                rule_id=match.rule.id,
                rule_name=match.rule.name,
                category=match.rule.category,
                severity=match.rule.severity,
                confidence=match.rule.confidence,
                path=path,
                line=match.line,
                column=match.column,
                message=match.rule.message,
                remediation=match.rule.remediation,
                fingerprint=fingerprint(match.rule.id, path, evidence, match.rule.message),
                evidence=evidence,
                references=match.rule.references,
                source=source,
                metadata=metadata,
            )
            apply_suppressions(finding, [], self.config.allowlist, local_warnings)
            _sanitize_finding(finding, path, ())
            result.append(finding)
        if warnings is not None:
            warnings[:] = sorted({_safe_public_text(item, path, ()) for item in warnings})
        return sorted(result, key=finding_sort_key)

    def _new_result(self, root: Path, command: str) -> ScanResult:
        info = git_info(root.parent if root.is_file() else root)
        return ScanResult(
            root=root,
            command=command,
            config_digest=self.config.digest(),
            started_at=datetime.now(UTC).isoformat(),
            git_branch=info.branch,
            git_commit=info.commit,
        )


def _relative(path: Path, root: Path) -> str:
    if root.is_file() and path == root:
        return path.name
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return PurePosixPath(path.name).as_posix()


def _selected_file_context(path: Path, config: Config) -> Path:
    """Choose a stable repository-relative path base for a selected file."""

    git_root = repository_root(path.parent)
    if git_root is not None:
        return git_root
    if config.source is not None:
        config_root = config.source.parent.resolve()
        if path.is_relative_to(config_root):
            return config_root
    return path.parent


def _safe_metadata(value: Any, path: str, custom_secret_values: tuple[str, ...]) -> Any:
    """Redact custom-secret material from public detector metadata."""

    if isinstance(value, str):
        return redact_secrets(redact_values(value, custom_secret_values), path)
    if isinstance(value, dict):
        return {
            str(key): _safe_metadata(item, path, custom_secret_values)
            for key, item in value.items()
            if not str(key).startswith("_")
        }
    if isinstance(value, list):
        return [_safe_metadata(item, path, custom_secret_values) for item in value]
    if isinstance(value, tuple):
        return tuple(_safe_metadata(item, path, custom_secret_values) for item in value)
    return value


def _safe_public_text(value: str, path: str, custom_secret_values: tuple[str, ...]) -> str:
    return redact_secrets(redact_values(value, custom_secret_values), path)


def _sanitize_finding(
    finding: Finding,
    path: str,
    custom_secret_values: tuple[str, ...],
) -> None:
    """Enforce the scanner's no-credential public-field boundary."""

    finding.rule_name = _safe_public_text(finding.rule_name, path, custom_secret_values)
    finding.path = _safe_public_text(finding.path, path, custom_secret_values)
    finding.message = _safe_public_text(finding.message, path, custom_secret_values)
    finding.remediation = _safe_public_text(finding.remediation, path, custom_secret_values)
    finding.evidence = _safe_public_text(finding.evidence, path, custom_secret_values)[:240]
    finding.references = tuple(
        _safe_public_text(item, path, custom_secret_values) for item in finding.references
    )
    finding.source = _safe_public_text(finding.source, path, custom_secret_values)
    if finding.commit is not None:
        finding.commit = _safe_public_text(finding.commit, path, custom_secret_values)
    if finding.suppression_reason is not None:
        finding.suppression_reason = _safe_public_text(finding.suppression_reason, path, custom_secret_values)
    finding.metadata = _safe_metadata(finding.metadata, path, custom_secret_values)


def _finalize(result: ScanResult, started: float) -> None:
    result.findings.sort(key=finding_sort_key)
    result.warnings = sorted(set(result.warnings))
    result.stats.duration_seconds = time.perf_counter() - started
