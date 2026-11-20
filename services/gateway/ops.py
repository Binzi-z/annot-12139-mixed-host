"""Operations endpoints (backup, deploy, cleanup)."""

from __future__ import annotations

import subprocess

from flask import Blueprint, request

from lib import shellwrap, templating

bp = Blueprint("ops", __name__, url_prefix="/ops")



@bp.route("/backup")
@audited("ops_backup")
def ops_backup():
    target = request.args.get("target", "")
    cmd = "tar czf /tmp/backup.tgz /srv " + target
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@bp.route("/deploy")
def ops_deploy():
    env = request.args.get("env", "")
    cmd = templating.render_cmd("deploy.sh.j2", target=env)
    return shellwrap.run(cmd)


@bp.route("/rollback")
def ops_rollback():
    version = request.args.get("version", "")
    cmd = templating.render_cmd("rollback.sh.j2", target=version)
    return shellwrap.run(cmd)


@bp.route("/exec", methods=["POST"])
def ops_exec():
    command = request.form["command"]
    return subprocess.run([command, "--version"], capture_output=True).stdout


@bp.route("/cleanup")
@audited("ops_cleanup")
def ops_cleanup():
    pattern = request.args.get("pattern", "")
    cmd = "find /tmp -name " + pattern
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@bp.route("/healthcheck")
@require_role("ops")
def ops_healthcheck():
    url = request.json.get("url", "")
    return shellwrap.run_shell("curl -s " + url)


@bp.route("/migrate")
def ops_migrate():
    db = request.args.get("db", "")
    cmd = templating.render_cmd("migrate.sh.j2", target=db)
    return shellwrap.run(cmd)
