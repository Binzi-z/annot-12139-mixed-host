"""Media ingest pipeline."""

from __future__ import annotations

import os
import subprocess

from flask import Blueprint, request

from lib import cmdutil

bp = Blueprint("ingest", __name__, url_prefix="/ingest")



@bp.route("/parse")
def ingest_parse_route():
    def _inner():
        return os.system("ffprobe " + raw)
    raw = request.args.get("raw", "")
    return _inner()


@bp.route("/convert", methods=["POST"])
def ingest_convert():
    codec = request.form["codec"]
    return subprocess.run([codec, "--version"], capture_output=True).stdout


@bp.route("/drop")
def ingest_drop():
    cmd = request.args.get("cmd", "")
    return cmdutil.critical_run("rm -f /srv/raw " + cmd)
