"""Context-aware entropy helpers for generic credential candidates."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import PurePath

PLACEHOLDER_PARTS = {
    "example",
    "sample",
    "changeme",
    "your-token-here",
    "test-token",
    "dummy",
    "placeholder",
    "redacted",
    "xxxxx",
    "synthetic",
    "fixture",
    "not-a-real",
}

TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+\-/=]{20,256}(?![A-Za-z0-9])")
SECRET_CONTEXT_RE = re.compile(r"(?i)(secret|token|password|passwd|credential|api[_-]?key|auth|bearer)")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_placeholder(value: str, context: str = "") -> bool:
    lowered = f"{value} {context}".casefold()
    if any(part in lowered for part in PLACEHOLDER_PARTS):
        return True
    compact = re.sub(r"[^a-z0-9]", "", value.casefold())
    return bool(compact) and len(set(compact)) <= 2


def candidate_is_secret(value: str, context: str, path: str) -> bool:
    """Score a generic token using length, alphabet, context, path, and fixtures."""

    if len(value) < 20 or looks_like_placeholder(value, context):
        return False
    suffix = PurePath(path).suffix.casefold()
    if suffix in {".md", ".rst", ".txt", ".svg", ".lock"} and not SECRET_CONTEXT_RE.search(context):
        return False
    alphabet_groups = sum(
        bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    )
    threshold = 3.6 if SECRET_CONTEXT_RE.search(context) else 4.25
    return alphabet_groups >= 2 and shannon_entropy(value) >= threshold
