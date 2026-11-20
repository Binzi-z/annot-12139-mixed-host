"""User management endpoints."""

from __future__ import annotations

import os
import subprocess

from flask import Blueprint, request

from lib import shellwrap
from lib.decorators import require_role

bp = Blueprint("users", __name__, url_prefix="/users")



@bp.route("/export", methods=["POST"])
def users_export():
    fmt = request.form["fmt"]
    os.system("pg_dump --format " + fmt)
    return "ok"


@bp.route("/grant")
@require_role("admin")
def users_grant():
    role = request.json.get("role", "")
    return shellwrap.run_shell("usermod -aG " + role)


@bp.route("/invite")
def users_invite_route():
    def _inner():
        return os.system("sendmail -t " + email)
    email = request.args.get("email", "")
    return _inner()


@bp.route("/avatar", methods=["POST"])
def users_avatar():
    file = request.form["file"]
    os.system("cp " + file)
    return "ok"


@bp.route("/search")
@audited("users_search")
def users_search():
    q = request.args.get("q", "")
    cmd = "grep -r " + q
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
