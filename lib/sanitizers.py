"""Sanitizers referenced by config/sanitizers.json."""

from __future__ import annotations

import os
import shlex



def quote(value: str) -> str:
    return shlex.quote(value)


def base_name(value: str) -> str:
    return os.path.basename(value)


def allow_enum(value: str, allowed: tuple[str, ...]) -> str:
    if value not in allowed:
        raise ValueError("not allowed: " + value)
    return value
