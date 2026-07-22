"""Secret-safe evidence rendering."""

from __future__ import annotations

import re
from collections.abc import Iterable
from difflib import SequenceMatcher


def mask_secret(value: str) -> str:
    """Mask a value without retaining any characters from the value.

    Evidence is routinely copied into machine-readable reports.  Keeping even
    a prefix and suffix is unnecessary disclosure and can also reveal a second
    credential when multiple values share a source line.
    """

    cleaned = value.strip()
    length = len(cleaned)
    if not cleaned:
        return "<redacted:empty>"
    return f"…<redacted:{length}>…"


def redact_spans(value: str, spans: Iterable[tuple[int, int]]) -> str:
    """Replace bounded spans in *value* without exposing overlapping values."""

    bounded: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        start = max(0, min(len(value), start))
        end = max(start, min(len(value), end))
        if start == end:
            continue
        if bounded and start <= bounded[-1][1]:
            bounded[-1] = (bounded[-1][0], max(bounded[-1][1], end))
        else:
            bounded.append((start, end))

    rendered = value
    for start, end in reversed(bounded):
        rendered = f"{rendered[:start]}{mask_secret(value[start:end])}{rendered[end:]}"
    return rendered


def redact_values(value: str, sensitive_values: Iterable[str]) -> str:
    """Redact in-memory custom-secret values from arbitrary detector evidence.

    Exact occurrences are preferred.  A detector may already have bounded or
    normalized its evidence, so a sufficiently long remaining fragment is
    also removed.  The supplied values never leave the scan orchestration.
    """

    spans: list[tuple[int, int]] = []
    for sensitive in {item for item in sensitive_values if item}:
        cursor = 0
        found_exact = False
        while True:
            start = value.find(sensitive, cursor)
            if start < 0:
                break
            spans.append((start, start + len(sensitive)))
            cursor = start + max(1, len(sensitive))
            found_exact = True
        if found_exact or len(sensitive) < 4:
            continue
        overlap = SequenceMatcher(None, value, sensitive, autojunk=False).find_longest_match()
        if overlap.size >= 8:
            spans.append((overlap.a, overlap.a + overlap.size))
    return redact_spans(value, spans)


def safe_line_evidence(line: str, start: int, end: int) -> str:
    """Return a bounded source line with the matched span replaced by a mask."""

    prefix = line[:start][-80:]
    suffix = line[end:][:80]
    rendered = f"{prefix}{mask_secret(line[start:end])}{suffix}".strip()
    return re.sub(r"[\r\n\t]+", " ", rendered)[:240]
