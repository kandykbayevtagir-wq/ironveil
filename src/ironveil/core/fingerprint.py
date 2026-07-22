"""Stable finding fingerprints that do not disclose matched values."""

from __future__ import annotations

import hashlib
import re

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def material_digest(value: str) -> str:
    """Return domain-separated digest material safe to pass between layers."""

    digest = hashlib.sha256()
    digest.update(b"ironveil-secret-material-v1\0")
    digest.update(value.encode("utf-8", errors="replace"))
    return digest.hexdigest()


def fingerprint_from_digest(
    rule_id: str,
    path: str,
    matched_value_digest: str,
    context: str = "",
) -> str:
    """Build a fingerprint from material that has already been irreversibly digested."""

    if not _DIGEST_RE.fullmatch(matched_value_digest):
        raise ValueError("matched_value_digest must be a lowercase SHA-256 digest")
    return _normalized_fingerprint(rule_id, path, matched_value_digest, context)


def fingerprint(rule_id: str, path: str, matched_value: str, context: str = "") -> str:
    """Build a fingerprint without retaining the matched value."""

    return fingerprint_from_digest(rule_id, path, material_digest(matched_value), context)


def _normalized_fingerprint(
    rule_id: str,
    path: str,
    matched_value_digest: str,
    context: str,
) -> str:
    normalized_path = path.replace("\\", "/")
    while normalized_path.startswith("./"):
        normalized_path = normalized_path[2:]
    normalized_context = re.sub(r"\s+", " ", context.strip().casefold())[:160]
    digest = hashlib.sha256()
    for part in (
        "ironveil-v1",
        rule_id,
        # Preserve case because Git can track Foo.py and foo.py as distinct
        # paths even when the scanner runs on a case-insensitive workstation.
        normalized_path,
        matched_value_digest,
        normalized_context,
    ):
        digest.update(part.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return f"iv1:{digest.hexdigest()}"
