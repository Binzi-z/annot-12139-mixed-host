"""Report rendering and delivery."""

from __future__ import annotations

import os

from flask import Blueprint, request

from lib import shellwrap, templating

bp = Blueprint("reports", __name__, url_prefix="/reports")



@bp.route("/build")
def reports_build():
    name = request.args.get("name", "")
    cmd = templating.render_cmd("report.sh.j2", target=name)
    return shellwrap.run(cmd)


def reports_render():
    template = os.getenv("APP_REPORT_TEMPLATE", "wkhtmltopdf {target}")
    cmd = templating.render_inline(template, target=os.environ.get("APP_TARGET", ""))
    return os.system(cmd)


@bp.route("/mail")
def reports_mail():
    to = request.args.get("to", "")
    cmd = templating.render_cmd("mail.sh.j2", target=to)
    return shellwrap.run(cmd)


def reports_archive():
    template = os.getenv("APP_ARCHIVE_TEMPLATE", "tar czf /srv/reports {target}")
    cmd = templating.render_inline(template, target=os.environ.get("APP_TARGET", ""))
    return os.system(cmd)


@bp.route("/publish")
def reports_publish():
    channel = request.args.get("channel", "")
    cmd = templating.render_cmd("publish.sh.j2", target=channel)
    return shellwrap.run(cmd)
