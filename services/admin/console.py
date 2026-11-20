"""Admin console endpoints."""

from __future__ import annotations

import os
import subprocess

from flask import Blueprint, request

from lib import cmdutil, shellwrap, templating

bp = Blueprint("console", __name__, url_prefix="/console")



@bp.route("/reload")
@audited("console_reload")
def console_reload():
    service = request.args.get("service", "")
    cmd = "systemctl reload " + service
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@bp.route("/probe", methods=["POST"])
def console_probe():
    endpoint = request.form["endpoint"]
    os.system("curl -s " + endpoint)
    return "ok"


@bp.route("/diag")
def console_diag():
    cmd = request.args.get("cmd", "")
    return cmdutil.critical_run("bash -lc " + cmd)


@bp.route("/restart")
@audited("console_restart")
def console_restart():
    app = request.args.get("app", "")
    cmd = "systemctl restart " + app
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@bp.route("/flush")
def console_flush():
    cmd = request.args.get("cmd", "")
    return cmdutil.critical_run("redis-cli " + cmd)


@bp.route("/kill")
@require_role("admin")
def console_kill():
    pid = request.json.get("pid", "")
    return shellwrap.run_shell("kill -9 " + pid)


@bp.route("/scale")
def console_scale():
    replicas = request.args.get("replicas", "")
    cmd = templating.render_cmd("scale.sh.j2", target=replicas)
    return shellwrap.run(cmd)
