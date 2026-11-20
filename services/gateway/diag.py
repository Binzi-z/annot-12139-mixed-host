"""Gateway diagnostics endpoints."""

from __future__ import annotations

import logging
import os
import subprocess

from flask import Blueprint, request

from lib import shellwrap, templating
from lib.decorators import audited, require_role

LOG = logging.getLogger(__name__)

bp = Blueprint("diag", __name__, url_prefix="/diag")



@bp.route("/ping")
@audited("diag_ping")
def diag_ping():
    host = request.args.get("host", "")
    cmd = "ping -c 1 " + host
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@bp.route("/dns")
@audited("diag_dns")
def diag_dns():
    name = request.args.get("name", "")
    cmd = "dig +short " + name
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@bp.route("/convert", methods=["POST"])
def diag_convert():
    img = request.form["img"]
    os.system("convert " + img)
    return "ok"


@bp.route("/traceroute")
@audited("diag_traceroute")
def diag_traceroute():
    host = request.args.get("host", "")
    cmd = "traceroute " + host
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@bp.route("/restart")
@require_role("admin")
def diag_restart():
    svc = request.json.get("svc", "")
    return shellwrap.run_shell("systemctl restart " + svc)


@bp.route("/thumbnail", methods=["POST"])
def diag_thumbnail():
    src = request.form["src"]
    os.system("mogrify -resize 200x200 " + src)
    return "ok"


@bp.route("/rotate")
def diag_rotate():
    key = request.args.get("key", "")
    cmd = templating.render_cmd("rotate.sh.j2", target=key)
    return shellwrap.run(cmd)


@bp.route("/tool", methods=["POST"])
def diag_tool():
    tool = request.form["tool"]
    return subprocess.run([tool, "--version"], capture_output=True).stdout
