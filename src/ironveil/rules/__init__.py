"""Built-in IronVeil rule packs."""

from __future__ import annotations

from typing import Any

from ironveil.models import Rule


def get_builtin_rules(**filters: Any) -> tuple[Rule, ...]:
    """Lazily expose the validated built-in registry without import cycles."""

    from ironveil.rules.registry import get_builtin_rules as _get_builtin_rules

    return _get_builtin_rules(**filters)


__all__ = ["get_builtin_rules"]
