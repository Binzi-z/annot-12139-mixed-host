"""Celery application used by background jobs."""

from __future__ import annotations

from celery import Celery

app = Celery("annot")
