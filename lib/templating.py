"""Render command templates from templates/ (str.format)."""

from __future__ import annotations

import os

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")



def render_cmd(name: str, **values: str) -> str:
    """Render templates/<name> with the given values."""
    with open(os.path.join(TEMPLATE_DIR, name), encoding="utf-8") as fh:
        return fh.read().format(**values)


def render_inline(template: str, **values: str) -> str:
    return template.format(**values)
