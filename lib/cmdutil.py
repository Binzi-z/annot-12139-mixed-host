"""Critical command helpers (fail fast, capture output)."""

from __future__ import annotations

import subprocess



def critical_run(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True).decode()


def safe_run(argv: list[str]) -> str:
    return subprocess.run(argv, shell=False, capture_output=True).stdout.decode()
