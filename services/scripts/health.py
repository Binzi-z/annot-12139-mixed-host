"""Cron-driven health scripts. Constant argv, no shell."""

from __future__ import annotations

import os
import subprocess

from lib import shellwrap



def check_load():
    return subprocess.run(["cat", "/proc/loadavg"], capture_output=True).stdout


def check_services(names):
    for name in names:
        subprocess.run(["/usr/bin/systemctl", "restart", name], check=False)


def check_tmp_size():
    out = subprocess.run("du -sh /tmp", shell=True, capture_output=True)
    return out.stdout.decode()


def check_clock():
    return os.popen("date -u").read()


def check_archive():
    return shellwrap.run_argv(["tar", "-tzf", "/backup/latest.tgz"])


def check_dns():
    return subprocess.run(["getent", "hosts", "localhost"],
                          capture_output=True).returncode
