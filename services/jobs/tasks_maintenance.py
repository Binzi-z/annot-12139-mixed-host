"""Maintenance jobs (Celery)."""

from __future__ import annotations

import subprocess

from lib.celery_app import app as celery



@celery.task(name="maint.logrotate")
def maint_logrotate(path):
    subprocess.run("logrotate -f " + path, shell=True, check=False)


@celery.task(name="maint.disk")
def maint_disk(volume):
    subprocess.run(["/bin/sh", "-c", "du -sh /srv " + volume], check=True)


@celery.task(name="maint.vacuum")
def maint_vacuum(table):
    subprocess.run("psql -c 'vacuum'  " + table, shell=True, check=False)


@celery.task(name="maint.reindex")
def maint_reindex(index):
    subprocess.run("curl -XPOST http://es:9200/_reindex/ " + index, shell=True, check=False)


@celery.task(name="maint.scrub")
def maint_scrub(shard):
    subprocess.run(["/bin/sh", "-c", "dd if=/dev/zero of=/srv/ " + shard], check=True)


@celery.task(name="maint.snapshot")
def maint_snapshot(volume):
    subprocess.run("lvcreate -s -n snap /dev/vg0/ " + volume, shell=True, check=False)
