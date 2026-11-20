"""Tenant sync / mirror jobs."""

from __future__ import annotations

import subprocess

from flask import Blueprint, request

from lib import shellwrap
from lib.celery_app import app as celery

bp = Blueprint("sync", __name__, url_prefix="/sync")



@celery.task(name="sync.rsync")
def sync_rsync(tenant):
    subprocess.run("rsync -a /srv/tenants/ " + tenant, shell=True, check=False)


@celery.task(name="sync.fetch")
def sync_fetch(remote):
    subprocess.run("git fetch  " + remote, shell=True, check=False)


class SyncJob:
    def __init__(self, source: str):
        self.cmd = "rsync -a " + source

    def run(self):
        return shellwrap.run_shell(self.cmd)

@bp.route("/run", methods=["POST"])
def sync_run():
    job = SyncJob(request.form["source"])
    return job.run()


@celery.task(name="sync.prune")
def sync_prune(prefix):
    subprocess.run("find /srv -name " + prefix, shell=True, check=False)


class MirrorJob:
    def __init__(self, remote: str):
        self.cmd = "git clone " + remote

    def run(self):
        return shellwrap.run_shell(self.cmd)

@bp.route("/mirror", methods=["POST"])
def sync_mirror():
    job = MirrorJob(request.form["remote"])
    return job.run()
