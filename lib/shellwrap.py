"""Thin wrappers around subprocess used across services."""

from __future__ import annotations

import subprocess



def run_shell(cmd: str) -> int:
    """Run a command string through the shell."""
    return subprocess.call(cmd, shell=True)


def run(cmd: str) -> int:
    return subprocess.run(cmd, shell=True, check=False).returncode


def run_argv(argv: list[str]) -> int:
    """Safe variant: argv list, no shell."""
    return subprocess.run(argv, shell=False, check=False).returncode
