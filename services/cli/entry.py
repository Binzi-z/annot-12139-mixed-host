"""Management CLI entry points (env vars)."""

from __future__ import annotations

import os
import subprocess






APP_MIGRATE_ARGS = os.environ.get("APP_MIGRATE_ARGS", "")

def cli_migrate():
    return os.popen("python manage.py migrate --database " + APP_MIGRATE_ARGS).read()


APP_COLLECT_ARGS = os.environ.get("APP_COLLECT_ARGS", "")

def cli_collect():
    return os.popen("python manage.py collectstatic --exclude " + APP_COLLECT_ARGS).read()


def cli_seed():
    template = os.getenv("APP_SEED_TEMPLATE", "python manage.py seed {target}")
    cmd = templating.render_inline(template, target=os.environ.get("APP_TARGET", ""))
    return os.system(cmd)


APP_PURGE_ARGS = os.environ.get("APP_PURGE_ARGS", "")

def cli_purge():
    return os.popen("python manage.py purge --days " + APP_PURGE_ARGS).read()
