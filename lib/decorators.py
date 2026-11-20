"""Audit / role decorators (they forward *args and **kwargs)."""

from __future__ import annotations

import functools
import logging

LOG = logging.getLogger(__name__)



def audited(name: str):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            LOG.info("audit %s", name)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def require_role(role: str):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper
    return deco
