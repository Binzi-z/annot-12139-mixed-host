"""Monitoring endpoints. All command usage here is constant or sanitized."""

from __future__ import annotations

import os
import shlex
import subprocess

from flask import Blueprint, request

from lib import cmdutil, shellwrap
from lib.decorators import audited

bp = Blueprint("monitor", __name__, url_prefix="/monitor")



ALLOWED_SERVICES = {"nginx": "nginx", "app": "app", "redis": "redis"}


@bp.route("/uptime")
def monitor_uptime():
    return subprocess.run(["/usr/bin/uptime"], capture_output=True).stdout.decode()


@bp.route("/service")
def monitor_service():
    name = request.args.get("name", "app")
    svc = ALLOWED_SERVICES[name]
    return subprocess.run(["systemctl", "is-active", svc],
                          capture_output=True).stdout.decode()


@bp.route("/disk")
def monitor_disk():
    return subprocess.run("df -h", shell=True, capture_output=True).stdout.decode()


@bp.route("/hostname")
def monitor_hostname():
    return subprocess.run("cat /etc/hostname", shell=True,
                          capture_output=True).stdout.decode()


@bp.route("/date")
def monitor_date():
    return subprocess.run(["date", "-u"], capture_output=True).stdout.decode()


@bp.route("/pkg")
def monitor_pkg():
    name = request.args.get("name", "")
    safe = os.path.basename(name)
    return subprocess.run("dpkg -s " + shlex.quote(safe), shell=True,
                          capture_output=True).stdout.decode()


@bp.route("/tail")
def monitor_tail():
    path = request.args.get("path", "/var/log/syslog")
    return shellwrap.run_argv(["tail", "-n", "20", path])


@bp.route("/sha")
def monitor_sha():
    path = request.args.get("path", "/etc/hosts")
    return cmdutil.safe_run(["sha256sum", path])


@bp.route("/sleep")
def monitor_sleep():
    seconds = int(request.args.get("n", "0"))
    return subprocess.run(["sleep", str(seconds)], check=False).returncode


@bp.route("/ping-once")
def monitor_ping_once():
    return subprocess.run(["ping", "-c", "1", "127.0.0.1"],
                          capture_output=True).returncode
