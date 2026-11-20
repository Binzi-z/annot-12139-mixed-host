#!/usr/bin/env python3
"""Regenerate the 12139 corpus (services/ + lib/ + filler/ + labels.json).

    python tools/make_corpus.py

The corpus is a Python monorepo (~20 万行):

  services/    Flask 路由 / Celery 任务 / CLI 入口，含 50 条真实命令注入链路
  lib/         命令包装、模板渲染、装饰器、净化器配置（被 services 跨模块调用）
  templates/   命令模板（模板渲染出的命令）
  config/      sanitizer 白名单
  filler/      约 36 万行……不，约 19 万行业务占位代码（无 sink）

Every label's file/line is computed from the lines written here.
"""
from __future__ import annotations

import ast
import json
import os
import random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RND = random.Random(20261139)

PACKAGES: dict[str, "Mod"] = {}
LABELS: list[dict] = []
COUNTER = {"n": 0}


def next_id() -> str:
    COUNTER["n"] += 1
    return f"C{COUNTER['n']:02d}"


class Mod:
    def __init__(self, rel: str, doc: str, imports: list[str], preamble: list[str] | None = None):
        self.rel = rel
        self.lines: list[str] = [f'"""{doc}"""', "", "from __future__ import annotations", ""]
        self.lines.extend(imports)
        if imports:
            self.lines.append("")
        if preamble:
            self.lines.extend(preamble)
            self.lines.append("")

    def add_block(self, block: list[str], sink_idx: int) -> int:
        self.lines.extend(["", ""])
        start = len(self.lines) + 1
        self.lines.extend(block)
        return start + sink_idx

    def write(self) -> None:
        text = "\n".join(self.lines).rstrip() + "\n"
        ast.parse(text)  # fail loudly if a template produced broken code
        path = os.path.join(ROOT, self.rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


def mod(key: str, rel: str, doc: str, imports: list[str],
        preamble: list[str] | None = None) -> "Mod":
    m = Mod(rel, doc, imports, preamble)
    PACKAGES[key] = m
    return m


def record(m: Mod, line: int, *, variant: str, source: str, entry: str,
           path: list[str], evidence: str, sink: str = "command_injection") -> None:
    LABELS.append({
        "id": next_id(),
        "sink": sink,
        "rule": sink,
        "variant": variant,
        "source": source,
        "entry": entry,
        "file": m.rel,
        "line": line,
        "path": path,
        "evidence": evidence,
    })


# ---------------------------------------------------------------------------
# Block templates. Each returns (lines, sink_index).
# ---------------------------------------------------------------------------
def t_concat(route: str, fn: str, param: str, prefix: str):
    return [
        f'@bp.route("/{route}")',
        f'@audited("{fn}")',
        f'def {fn}():',
        f'    {param} = request.args.get("{param}", "")',
        f'    cmd = "{prefix} " + {param}',
        f'    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()',
    ], 5


def t_os_system(route: str, fn: str, param: str, prefix: str):
    return [
        f'@bp.route("/{route}", methods=["POST"])',
        f'def {fn}():',
        f'    {param} = request.form["{param}"]',
        f'    os.system("{prefix} " + {param})',
        f'    return "ok"',
    ], 3


def t_celery(route: str, fn: str, arg: str, task: str, command: str):
    return [
        f'@celery.task(name="{task}")',
        f'def {fn}({arg}):',
        f'    subprocess.run("{command} " + {arg}, shell=True, check=False)',
    ], 2


def t_env(prefix: str, fn: str, var: str):
    return [
        f'{var} = os.environ.get("{var}", "")',
        "",
        f'def {fn}():',
        f'    return os.popen("{prefix} " + {var}).read()',
    ], 3


def t_wrapper(route: str, fn: str, param: str, prefix: str, role: str):
    return [
        f'@bp.route("/{route}")',
        f'@require_role("{role}")',
        f'def {fn}():',
        f'    {param} = request.json.get("{param}", "")',
        f'    return shellwrap.run_shell("{prefix} " + {param})',
    ], 4


def t_template(route: str, fn: str, param: str, tpl: str):
    return [
        f'@bp.route("/{route}")',
        f'def {fn}():',
        f'    {param} = request.args.get("{param}", "")',
        f'    cmd = templating.render_cmd("{tpl}", target={param})',
        f'    return shellwrap.run(cmd)',
    ], 4


def t_closure(route: str, fn: str, param: str, prefix: str):
    return [
        f'@bp.route("/{route}")',
        f'def {fn}_route():',
        f'    def _inner():',
        f'        return os.system("{prefix} " + {param})',
        f'    {param} = request.args.get("{param}", "")',
        f'    return _inner()',
    ], 3


def t_class(route: str, fn: str, param: str, cls: str, prefix: str):
    return [
        f'class {cls}:',
        f'    def __init__(self, {param}: str):',
        f'        self.cmd = "{prefix} " + {param}',
        "",
        f'    def run(self):',
        f'        return shellwrap.run_shell(self.cmd)',
        "",
        f'@bp.route("/{route}", methods=["POST"])',
        f'def {fn}():',
        f'    job = {cls}(request.form["{param}"])',
        f'    return job.run()',
    ], 5


def t_program(route: str, fn: str, param: str):
    return [
        f'@bp.route("/{route}", methods=["POST"])',
        f'def {fn}():',
        f'    {param} = request.form["{param}"]',
        f'    return subprocess.run([{param}, "--version"], capture_output=True).stdout',
    ], 3


def t_shell_c(route: str, fn: str, arg: str, task: str, command: str):
    return [
        f'@celery.task(name="{task}")',
        f'def {fn}({arg}):',
        f'    subprocess.run(["/bin/sh", "-c", "{command} " + {arg}], check=True)',
    ], 2


def t_env_template(fn: str, var: str, prefix: str):
    return [
        f'def {fn}():',
        f'    template = os.getenv("{var}_TEMPLATE", "{prefix} {{target}}")',
        f'    cmd = templating.render_inline(template, target=os.environ.get("APP_TARGET", ""))',
        f'    return os.system(cmd)',
    ], 3


def t_cmdutil(route: str, fn: str, param: str, prefix: str):
    return [
        f'@bp.route("/{route}")',
        f'def {fn}():',
        f'    {param} = request.args.get("{param}", "")',
        f'    return cmdutil.critical_run("{prefix} " + {param})',
    ], 3


# ---------------------------------------------------------------------------
# lib/ — cross-module helpers (the propagation surface)
# ---------------------------------------------------------------------------
def build_lib() -> None:
    shellwrap = mod("shellwrap", "lib/shellwrap.py",
                    "Thin wrappers around subprocess used across services.",
                    ["import subprocess", ""])
    shellwrap.lines.extend([
        "",
        "def run_shell(cmd: str) -> int:",
        '    """Run a command string through the shell."""',
        "    return subprocess.call(cmd, shell=True)",
        "",
        "",
        "def run(cmd: str) -> int:",
        "    return subprocess.run(cmd, shell=True, check=False).returncode",
        "",
        "",
        "def run_argv(argv: list[str]) -> int:",
        '    """Safe variant: argv list, no shell."""',
        "    return subprocess.run(argv, shell=False, check=False).returncode",
    ])
    shellwrap.write()

    cmdutil = mod("cmdutil", "lib/cmdutil.py",
                  "Critical command helpers (fail fast, capture output).",
                  ["import subprocess", ""])
    cmdutil.lines.extend([
        "",
        "def critical_run(cmd: str) -> str:",
        "    return subprocess.check_output(cmd, shell=True).decode()",
        "",
        "",
        "def safe_run(argv: list[str]) -> str:",
        "    return subprocess.run(argv, shell=False, capture_output=True).stdout.decode()",
    ])
    cmdutil.write()

    templating = mod("templating", "lib/templating.py",
                     "Render command templates from templates/ (str.format).",
                     ["import os", "", "TEMPLATE_DIR = os.path.join("
                      'os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")'])
    templating.lines.extend([
        "",
        "",
        "def render_cmd(name: str, **values: str) -> str:",
        '    """Render templates/<name> with the given values."""',
        '    with open(os.path.join(TEMPLATE_DIR, name), encoding="utf-8") as fh:',
        "        return fh.read().format(**values)",
        "",
        "",
        "def render_inline(template: str, **values: str) -> str:",
        "    return template.format(**values)",
    ])
    templating.write()

    decorators = mod("decorators", "lib/decorators.py",
                     "Audit / role decorators (they forward *args and **kwargs).",
                     ["import functools", "import logging", "", "LOG = logging.getLogger(__name__)"])
    decorators.lines.extend([
        "",
        "",
        "def audited(name: str):",
        "    def deco(fn):",
        "        @functools.wraps(fn)",
        "        def wrapper(*args, **kwargs):",
        '            LOG.info("audit %s", name)',
        "            return fn(*args, **kwargs)",
        "        return wrapper",
        "    return deco",
        "",
        "",
        "def require_role(role: str):",
        "    def deco(fn):",
        "        @functools.wraps(fn)",
        "        def wrapper(*args, **kwargs):",
        "            return fn(*args, **kwargs)",
        "        return wrapper",
        "    return deco",
    ])
    decorators.write()

    celery_app = mod("celery_app", "lib/celery_app.py",
                     "Celery application used by background jobs.",
                     ["from celery import Celery", "", 'app = Celery("annot")'])
    celery_app.write()

    sanitizers = mod("sanitizers", "lib/sanitizers.py",
                     "Sanitizers referenced by config/sanitizers.json.",
                     ["import os", "import shlex"])
    sanitizers.lines.extend([
        "",
        "",
        "def quote(value: str) -> str:",
        "    return shlex.quote(value)",
        "",
        "",
        "def base_name(value: str) -> str:",
        "    return os.path.basename(value)",
        "",
        "",
        "def allow_enum(value: str, allowed: tuple[str, ...]) -> str:",
        "    if value not in allowed:",
        '        raise ValueError("not allowed: " + value)',
        "    return value",
    ])
    sanitizers.write()


def build_templates() -> None:
    templates = {
        "deploy.sh.j2": "deploy --env {target} --force\n",
        "rollback.sh.j2": "rollback --version {target}\n",
        "migrate.sh.j2": "migrate --db {target}\n",
        "scale.sh.j2": "scale --replicas {target}\n",
        "report.sh.j2": "report --name {target} --format pdf\n",
        "mail.sh.j2": "mail --to {target}\n",
        "publish.sh.j2": "publish --channel {target}\n",
        "rotate.sh.j2": "logrotate -f {target}\n",
    }
    for name, body in templates.items():
        path = os.path.join(ROOT, "templates", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)


# ---------------------------------------------------------------------------
# services/
# ---------------------------------------------------------------------------
def build_diag() -> None:
    m = mod("diag", "services/gateway/diag.py",
            "Gateway diagnostics endpoints.",
            ["import logging", "import os", "import subprocess", "",
             "from flask import Blueprint, request", "",
             "from lib import shellwrap, templating", "from lib.decorators import audited, require_role",
             "", 'LOG = logging.getLogger(__name__)', "",
             'bp = Blueprint("diag", __name__, url_prefix="/diag")'])
    block, idx = t_concat("ping", "diag_ping", "host", "ping -c 1")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_arg", entry="request.args['host']",
           path=["request.args['host']", "cmd", "subprocess.run(shell=True)"],
           evidence="query 参数 host 拼进命令行后 subprocess.run(shell=True)")
    block, idx = t_concat("dns", "diag_dns", "name", "dig +short")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_arg", entry="request.args['name']",
           path=["request.args['name']", "cmd", "subprocess.run(shell=True)"],
           evidence="query 参数 name 拼进 dig 命令并 shell=True")
    block, idx = t_os_system("convert", "diag_convert", "img", "convert")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_form", entry="request.form['img']",
           path=["request.form['img']", "os.system"],
           evidence="表单字段 img 直接进 os.system")
    block, idx = t_concat("traceroute", "diag_traceroute", "host", "traceroute")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_arg", entry="request.args['host']",
           path=["request.args['host']", "cmd", "subprocess.run(shell=True)"],
           evidence="traceroute 目标来自 query 参数，shell=True")
    block, idx = t_wrapper("restart", "diag_restart", "svc", "systemctl restart", "admin")
    line = m.add_block(block, idx)
    record(m, line, variant="shell_wrapper", source="flask_json", entry="request.json['svc']",
           path=["request.json['svc']", "shellwrap.run_shell", "subprocess.call(shell=True)"],
           evidence="JSON 字段经 shellwrap.run_shell 进 subprocess.call(shell=True)")
    block, idx = t_os_system("thumbnail", "diag_thumbnail", "src", "mogrify -resize 200x200")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_form", entry="request.form['src']",
           path=["request.form['src']", "os.system"],
           evidence="表单 src 拼进 mogrify 命令")
    block, idx = t_template("rotate", "diag_rotate", "key", "rotate.sh.j2")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="flask_arg", entry="request.args['key']",
           path=["request.args['key']", "templating.render_cmd", "shellwrap.run"],
           evidence="模板 rotate.sh.j2 用 key 渲染后交给 shellwrap.run")
    block, idx = t_program("tool", "diag_tool", "tool")
    line = m.add_block(block, idx)
    record(m, line, variant="arglist_misuse", source="flask_form", entry="request.form['tool']",
           path=["request.form['tool']", "subprocess.run(argv)"],
           evidence="表单字段被当成 argv[0] 直接执行")
    m.write()


def build_ops() -> None:
    m = mod("ops", "services/gateway/ops.py",
            "Operations endpoints (backup, deploy, cleanup).",
            ["import subprocess", "",
             "from flask import Blueprint, request", "",
             "from lib import shellwrap, templating", "",
             'bp = Blueprint("ops", __name__, url_prefix="/ops")'])
    block, idx = t_concat("backup", "ops_backup", "target", "tar czf /tmp/backup.tgz /srv")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_arg", entry="request.args['target']",
           path=["request.args['target']", "cmd", "subprocess.run(shell=True)"],
           evidence="备份目标目录来自 query 参数，shell=True")
    block, idx = t_template("deploy", "ops_deploy", "env", "deploy.sh.j2")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="flask_arg", entry="request.args['env']",
           path=["request.args['env']", "templating.render_cmd", "shellwrap.run"],
           evidence="部署模板 deploy.sh.j2 用 env 渲染出命令后执行")
    block, idx = t_template("rollback", "ops_rollback", "version", "rollback.sh.j2")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="flask_arg", entry="request.args['version']",
           path=["request.args['version']", "templating.render_cmd", "shellwrap.run"],
           evidence="回滚版本号进模板渲染出的命令")
    block, idx = t_program("exec", "ops_exec", "command")
    line = m.add_block(block, idx)
    record(m, line, variant="arglist_misuse", source="flask_form", entry="request.form['command']",
           path=["request.form['command']", "subprocess.run(argv)"],
           evidence="任意程序名作为 argv[0] 执行（参数列表误用）")
    block, idx = t_concat("cleanup", "ops_cleanup", "pattern", "find /tmp -name")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_arg", entry="request.args['pattern']",
           path=["request.args['pattern']", "cmd", "subprocess.run(shell=True)"],
           evidence="清理表达式来自 query 参数并拼进 find 命令")
    block, idx = t_wrapper("healthcheck", "ops_healthcheck", "url", "curl -s", "ops")
    line = m.add_block(block, idx)
    record(m, line, variant="shell_wrapper", source="flask_json", entry="request.json['url']",
           path=["request.json['url']", "shellwrap.run_shell", "subprocess.call(shell=True)"],
           evidence="健康检查 URL 经 shellwrap.run_shell 执行，可注入 ; 命令")
    block, idx = t_template("migrate", "ops_migrate", "db", "migrate.sh.j2")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="flask_arg", entry="request.args['db']",
           path=["request.args['db']", "templating.render_cmd", "shellwrap.run"],
           evidence="migrate.sh.j2 用 db 参数渲染后执行")
    m.write()


def build_users() -> None:
    m = mod("users", "services/gateway/users.py",
            "User management endpoints.",
            ["import os", "import subprocess", "",
             "from flask import Blueprint, request", "",
             "from lib import shellwrap", "from lib.decorators import require_role", "",
             'bp = Blueprint("users", __name__, url_prefix="/users")'])
    block, idx = t_os_system("export", "users_export", "fmt", "pg_dump --format")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_form", entry="request.form['fmt']",
           path=["request.form['fmt']", "os.system"],
           evidence="导出格式来自表单，直接拼进 pg_dump 命令")
    block, idx = t_wrapper("grant", "users_grant", "role", "usermod -aG", "admin")
    line = m.add_block(block, idx)
    record(m, line, variant="shell_wrapper", source="flask_json", entry="request.json['role']",
           path=["request.json['role']", "shellwrap.run_shell", "subprocess.call(shell=True)"],
           evidence="授权角色名经 shellwrap.run_shell 进入 shell")
    block, idx = t_closure("invite", "users_invite", "email", "sendmail -t")
    line = m.add_block(block, idx)
    record(m, line, variant="closure", source="flask_arg", entry="request.args['email']",
           path=["request.args['email']", "closure _inner", "os.system"],
           evidence="query 参数被闭包 _inner 捕获后进 os.system")
    block, idx = t_os_system("avatar", "users_avatar", "file", "cp")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_form", entry="request.form['file']",
           path=["request.form['file']", "os.system"],
           evidence="头像文件名拼进 cp 命令")
    block, idx = t_concat("search", "users_search", "q", "grep -r")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_arg", entry="request.args['q']",
           path=["request.args['q']", "cmd", "subprocess.run(shell=True)"],
           evidence="搜索词拼进 grep 命令，shell=True")
    m.write()


def build_maintenance() -> None:
    m = mod("maintenance", "services/jobs/tasks_maintenance.py",
            "Maintenance jobs (Celery).",
            ["import subprocess", "",
             "from lib.celery_app import app as celery"])
    block, idx = t_celery("logrotate", "maint_logrotate", "path", "maint.logrotate",
                          "logrotate -f")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="celery_arg", entry="task arg path",
           path=["task arg path", "subprocess.run(shell=True)"],
           evidence="Celery 任务参数 path 拼进 logrotate 命令，shell=True")
    block, idx = t_shell_c("disk", "maint_disk", "volume", "maint.disk", "du -sh /srv")
    line = m.add_block(block, idx)
    record(m, line, variant="arglist_misuse", source="celery_arg", entry="task arg volume",
           path=["task arg volume", "subprocess.run(['/bin/sh','-c',...])"],
           evidence="任务参数拼进 /bin/sh -c 的字符串（参数列表误用）")
    block, idx = t_celery("vacuum", "maint_vacuum", "table", "maint.vacuum",
                          "psql -c 'vacuum' ")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="celery_arg", entry="task arg table",
           path=["task arg table", "subprocess.run(shell=True)"],
           evidence="表名来自任务参数并拼进 psql 命令")
    block, idx = t_celery("reindex", "maint_reindex", "index", "maint.reindex",
                          "curl -XPOST http://es:9200/_reindex/")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="celery_arg", entry="task arg index",
           path=["task arg index", "subprocess.run(shell=True)"],
           evidence="索引名来自任务参数并拼进 curl 命令")
    block, idx = t_shell_c("scrub", "maint_scrub", "shard", "maint.scrub", "dd if=/dev/zero of=/srv/")
    line = m.add_block(block, idx)
    record(m, line, variant="arglist_misuse", source="celery_arg", entry="task arg shard",
           path=["task arg shard", "subprocess.run(['/bin/sh','-c',...])"],
           evidence="分片名拼进 sh -c 字符串")
    block, idx = t_celery("snapshot", "maint_snapshot", "volume", "maint.snapshot",
                          "lvcreate -s -n snap /dev/vg0/")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="celery_arg", entry="task arg volume",
           path=["task arg volume", "subprocess.run(shell=True)"],
           evidence="卷名来自任务参数并拼进 lvcreate 命令")
    m.write()


def build_sync() -> None:
    m = mod("sync", "services/jobs/tasks_sync.py",
            "Tenant sync / mirror jobs.",
            ["import subprocess", "",
             "from flask import Blueprint, request", "",
             "from lib import shellwrap", "from lib.celery_app import app as celery", "",
             'bp = Blueprint("sync", __name__, url_prefix="/sync")'])
    block, idx = t_celery("rsync", "sync_rsync", "tenant", "sync.rsync",
                          "rsync -a /srv/tenants/")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="celery_arg", entry="task arg tenant",
           path=["task arg tenant", "subprocess.run(shell=True)"],
           evidence="租户 ID 来自任务参数并拼进 rsync 命令")
    block, idx = t_celery("fetch", "sync_fetch", "remote", "sync.fetch", "git fetch ")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="celery_arg", entry="task arg remote",
           path=["task arg remote", "subprocess.run(shell=True)"],
           evidence="远端地址来自任务参数并拼进 git fetch")
    block, idx = t_class("run", "sync_run", "source", "SyncJob", "rsync -a")
    line = m.add_block(block, idx)
    record(m, line, variant="class_attr", source="flask_form", entry="request.form['source']",
           path=["request.form['source']", "SyncJob.cmd", "shellwrap.run_shell"],
           evidence="表单字段存进实例属性 self.cmd，run() 时进 shell")
    block, idx = t_celery("prune", "sync_prune", "prefix", "sync.prune", "find /srv -name")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="celery_arg", entry="task arg prefix",
           path=["task arg prefix", "subprocess.run(shell=True)"],
           evidence="前缀来自任务参数并拼进 find -delete 命令")
    block, idx = t_class("mirror", "sync_mirror", "remote", "MirrorJob", "git clone")
    line = m.add_block(block, idx)
    record(m, line, variant="class_attr", source="flask_form", entry="request.form['remote']",
           path=["request.form['remote']", "MirrorJob.cmd", "shellwrap.run_shell"],
           evidence="远端地址存进实例属性后经 shellwrap.run_shell 执行")
    m.write()


def build_console() -> None:
    m = mod("console", "services/admin/console.py",
            "Admin console endpoints.",
            ["import os", "import subprocess", "",
             "from flask import Blueprint, request", "",
             "from lib import cmdutil, shellwrap, templating", "",
             'bp = Blueprint("console", __name__, url_prefix="/console")'])
    block, idx = t_concat("reload", "console_reload", "service", "systemctl reload")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_arg", entry="request.args['service']",
           path=["request.args['service']", "cmd", "subprocess.run(shell=True)"],
           evidence="服务名来自 query 参数并拼进 systemctl")
    block, idx = t_os_system("probe", "console_probe", "endpoint", "curl -s")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_form", entry="request.form['endpoint']",
           path=["request.form['endpoint']", "os.system"],
           evidence="探测地址来自表单并进 os.system")
    block, idx = t_cmdutil("diag", "console_diag", "cmd", "bash -lc")
    line = m.add_block(block, idx)
    record(m, line, variant="shell_wrapper", source="flask_arg", entry="request.args['cmd']",
           path=["request.args['cmd']", "cmdutil.critical_run", "subprocess.check_output(shell=True)"],
           evidence="query 参数经 cmdutil.critical_run 进 check_output(shell=True)")
    block, idx = t_concat("restart", "console_restart", "app", "systemctl restart")
    line = m.add_block(block, idx)
    record(m, line, variant="concat_shell", source="flask_arg", entry="request.args['app']",
           path=["request.args['app']", "cmd", "subprocess.run(shell=True)"],
           evidence="应用名来自 query 参数并拼进 systemctl restart")
    block, idx = t_cmdutil("flush", "console_flush", "cmd", "redis-cli")
    line = m.add_block(block, idx)
    record(m, line, variant="shell_wrapper", source="flask_arg", entry="request.args['cmd']",
           path=["request.args['cmd']", "cmdutil.critical_run", "subprocess.check_output(shell=True)"],
           evidence="query 参数经 cmdutil.critical_run 执行 redis-cli 子命令")
    block, idx = t_wrapper("kill", "console_kill", "pid", "kill -9", "admin")
    line = m.add_block(block, idx)
    record(m, line, variant="shell_wrapper", source="flask_json", entry="request.json['pid']",
           path=["request.json['pid']", "shellwrap.run_shell", "subprocess.call(shell=True)"],
           evidence="pid 来自 JSON 并经 shellwrap.run_shell 进 shell")
    block, idx = t_template("scale", "console_scale", "replicas", "scale.sh.j2")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="flask_arg", entry="request.args['replicas']",
           path=["request.args['replicas']", "templating.render_cmd", "shellwrap.run"],
           evidence="副本数经 scale.sh.j2 渲染出命令后执行")
    m.write()


def build_cli() -> None:
    m = mod("cli", "services/cli/entry.py",
            "Management CLI entry points (env vars).",
            ["import os", "import subprocess", ""])
    m.lines.extend(["", ""])
    # 4 env-var flows; t_env already includes the module-level assignment.
    block, idx = t_env("python manage.py migrate --database", "cli_migrate", "APP_MIGRATE_ARGS")
    m.lines.extend(["", ""])
    start = len(m.lines) + 1
    m.lines.extend(block)
    record(m, start + idx, variant="concat_shell", source="env_var", entry="APP_MIGRATE_ARGS",
           path=["os.environ['APP_MIGRATE_ARGS']", "os.popen"],
           evidence="环境变量拼进 os.popen 的 manage.py 命令")
    block, idx = t_env("python manage.py collectstatic --exclude", "cli_collect",
                       "APP_COLLECT_ARGS")
    m.lines.extend(["", ""])
    start = len(m.lines) + 1
    m.lines.extend(block)
    record(m, start + idx, variant="concat_shell", source="env_var", entry="APP_COLLECT_ARGS",
           path=["os.environ['APP_COLLECT_ARGS']", "os.popen"],
           evidence="环境变量拼进 collectstatic 命令")
    block, idx = t_env_template("cli_seed", "APP_SEED", "python manage.py seed")
    m.lines.extend(["", ""])
    start = len(m.lines) + 1
    m.lines.extend(block)
    record(m, start + idx, variant="template_rendered", source="env_var", entry="APP_TARGET",
           path=["os.environ['APP_TARGET']", "templating.render_inline", "os.system"],
           evidence="APP_TARGET 经 render_inline 渲染后进 os.system")
    block, idx = t_env("python manage.py purge --days", "cli_purge", "APP_PURGE_ARGS")
    m.lines.extend(["", ""])
    start = len(m.lines) + 1
    m.lines.extend(block)
    record(m, start + idx, variant="concat_shell", source="env_var", entry="APP_PURGE_ARGS",
           path=["os.environ['APP_PURGE_ARGS']", "os.popen"],
           evidence="环境变量拼进 purge 命令并 os.popen 执行")
    m.write()


def build_reports() -> None:
    m = mod("reports", "services/reports/render.py",
            "Report rendering and delivery.",
            ["import os", "",
             "from flask import Blueprint, request", "",
             "from lib import shellwrap, templating", "",
             'bp = Blueprint("reports", __name__, url_prefix="/reports")'])
    block, idx = t_template("build", "reports_build", "name", "report.sh.j2")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="flask_arg", entry="request.args['name']",
           path=["request.args['name']", "templating.render_cmd", "shellwrap.run"],
           evidence="报表名经 report.sh.j2 渲染成命令后执行")
    block, idx = t_env_template("reports_render", "APP_REPORT", "wkhtmltopdf")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="env_var", entry="APP_TARGET",
           path=["os.environ['APP_TARGET']", "templating.render_inline", "os.system"],
           evidence="环境变量 APP_TARGET 经模板渲染进 os.system")
    block, idx = t_template("mail", "reports_mail", "to", "mail.sh.j2")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="flask_arg", entry="request.args['to']",
           path=["request.args['to']", "templating.render_cmd", "shellwrap.run"],
           evidence="收件人经 mail.sh.j2 渲染出 mail 命令后执行")
    block, idx = t_env_template("reports_archive", "APP_ARCHIVE", "tar czf /srv/reports")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="env_var", entry="APP_TARGET",
           path=["os.environ['APP_TARGET']", "templating.render_inline", "os.system"],
           evidence="归档路径来自环境变量并经 render_inline 进 os.system")
    block, idx = t_template("publish", "reports_publish", "channel", "publish.sh.j2")
    line = m.add_block(block, idx)
    record(m, line, variant="template_rendered", source="flask_arg", entry="request.args['channel']",
           path=["request.args['channel']", "templating.render_cmd", "shellwrap.run"],
           evidence="发布渠道经 publish.sh.j2 渲染成命令后执行")
    m.write()


def build_ingest() -> None:
    m = mod("ingest", "services/ingest/pipeline.py",
            "Media ingest pipeline.",
            ["import os", "import subprocess", "",
             "from flask import Blueprint, request", "",
             "from lib import cmdutil", "",
             'bp = Blueprint("ingest", __name__, url_prefix="/ingest")'])
    block, idx = t_closure("parse", "ingest_parse", "raw", "ffprobe")
    line = m.add_block(block, idx)
    record(m, line, variant="closure", source="flask_arg", entry="request.args['raw']",
           path=["request.args['raw']", "closure _inner", "os.system"],
           evidence="query 参数被闭包捕获后进 os.system")
    block, idx = t_program("convert", "ingest_convert", "codec")
    line = m.add_block(block, idx)
    record(m, line, variant="arglist_misuse", source="flask_form", entry="request.form['codec']",
           path=["request.form['codec']", "subprocess.run(argv)"],
           evidence="编解码器名被当成 argv[0] 直接执行")
    block, idx = t_cmdutil("drop", "ingest_drop", "cmd", "rm -f /srv/raw")
    line = m.add_block(block, idx)
    record(m, line, variant="shell_wrapper", source="flask_arg", entry="request.args['cmd']",
           path=["request.args['cmd']", "cmdutil.critical_run", "subprocess.check_output(shell=True)"],
           evidence="query 参数经 cmdutil.critical_run 进 check_output(shell=True)")
    m.write()


def build_benign() -> None:
    """Benign sink sites: they must NOT be reported (precision fodder)."""
    monitor = mod("monitor", "services/gateway/monitor.py",
                  "Monitoring endpoints. All command usage here is constant or sanitized.",
                  ["import os", "import shlex", "import subprocess", "",
                   "from flask import Blueprint, request", "",
                   "from lib import cmdutil, shellwrap", "from lib.decorators import audited", "",
                   'bp = Blueprint("monitor", __name__, url_prefix="/monitor")'])
    monitor.lines.extend([
        "", "",
        "ALLOWED_SERVICES = {\"nginx\": \"nginx\", \"app\": \"app\", \"redis\": \"redis\"}",
        "", "",
        "@bp.route(\"/uptime\")",
        "def monitor_uptime():",
        "    return subprocess.run([\"/usr/bin/uptime\"], capture_output=True).stdout.decode()",
        "", "",
        "@bp.route(\"/service\")",
        "def monitor_service():",
        "    name = request.args.get(\"name\", \"app\")",
        "    svc = ALLOWED_SERVICES[name]",
        "    return subprocess.run([\"systemctl\", \"is-active\", svc],",
        "                          capture_output=True).stdout.decode()",
        "", "",
        "@bp.route(\"/disk\")",
        "def monitor_disk():",
        "    return subprocess.run(\"df -h\", shell=True, capture_output=True).stdout.decode()",
        "", "",
        "@bp.route(\"/hostname\")",
        "def monitor_hostname():",
        "    return subprocess.run(\"cat /etc/hostname\", shell=True,",
        "                          capture_output=True).stdout.decode()",
        "", "",
        "@bp.route(\"/date\")",
        "def monitor_date():",
        "    return subprocess.run([\"date\", \"-u\"], capture_output=True).stdout.decode()",
        "", "",
        "@bp.route(\"/pkg\")",
        "def monitor_pkg():",
        "    name = request.args.get(\"name\", \"\")",
        "    safe = os.path.basename(name)",
        "    return subprocess.run(\"dpkg -s \" + shlex.quote(safe), shell=True,",
        "                          capture_output=True).stdout.decode()",
        "", "",
        "@bp.route(\"/tail\")",
        "def monitor_tail():",
        "    path = request.args.get(\"path\", \"/var/log/syslog\")",
        "    return shellwrap.run_argv([\"tail\", \"-n\", \"20\", path])",
        "", "",
        "@bp.route(\"/sha\")",
        "def monitor_sha():",
        "    path = request.args.get(\"path\", \"/etc/hosts\")",
        "    return cmdutil.safe_run([\"sha256sum\", path])",
        "", "",
        "@bp.route(\"/sleep\")",
        "def monitor_sleep():",
        "    seconds = int(request.args.get(\"n\", \"0\"))",
        "    return subprocess.run([\"sleep\", str(seconds)], check=False).returncode",
        "", "",
        "@bp.route(\"/ping-once\")",
        "def monitor_ping_once():",
        "    return subprocess.run([\"ping\", \"-c\", \"1\", \"127.0.0.1\"],",
        "                          capture_output=True).returncode",
    ])
    try:
        ast.parse("\n".join(monitor.lines) + "\n")
    except SyntaxError as exc:
        raise SystemExit(f"monitor.py template broke: {exc}")
    monitor.write()

    health = mod("health", "services/scripts/health.py",
                 "Cron-driven health scripts. Constant argv, no shell.",
                 ["import os", "import subprocess", "", "from lib import shellwrap"])
    health.lines.extend([
        "", "",
        "def check_load():",
        "    return subprocess.run([\"cat\", \"/proc/loadavg\"], capture_output=True).stdout",
        "", "",
        "def check_services(names):",
        "    for name in names:",
        "        subprocess.run([\"/usr/bin/systemctl\", \"restart\", name], check=False)",
        "", "",
        "def check_tmp_size():",
        "    out = subprocess.run(\"du -sh /tmp\", shell=True, capture_output=True)",
        "    return out.stdout.decode()",
        "", "",
        "def check_clock():",
        "    return os.popen(\"date -u\").read()",
        "", "",
        "def check_archive():",
        "    return shellwrap.run_argv([\"tar\", \"-tzf\", \"/backup/latest.tgz\"])",
        "", "",
        "def check_dns():",
        "    return subprocess.run([\"getent\", \"hosts\", \"localhost\"],",
        "                          capture_output=True).returncode",
    ])
    try:
        ast.parse("\n".join(health.lines) + "\n")
    except SyntaxError as exc:
        raise SystemExit(f"health.py template broke: {exc}")
    health.write()


# ---------------------------------------------------------------------------
# filler — the 20 万行 backdrop of ordinary business code
# ---------------------------------------------------------------------------
def build_filler() -> None:
    total_files = 380
    lines_per_file = 530
    for idx in range(total_files):
        pkg = f"pkg_{idx // 12:03d}"
        lines = [
            f'"""Business helper {pkg}/mod_{idx:03d}: pure data transforms (no side effects)."""',
            "",
            "from __future__ import annotations",
            "",
            "import hashlib",
            "import json",
            "import math",
            "from dataclasses import dataclass",
            "",
        ]
        if idx % 40 == 7:
            lines += ["import subprocess", ""]
        lines += [""]

        def block(k: int, probe: bool = False) -> list[str]:
            out = [
                "",
                "@dataclass",
                f"class Rec{k:02d}:",
                "    key: str",
                "    weight: float = 1.0",
                "    tags: tuple[str, ...] = ()",
                "",
                "",
                f"def transform_{k:02d}(rec: Rec{k:02d}, factor: float = 1.0) -> dict:",
                f'    """Scale record {k} by factor and serialise it."""',
                "    total = 0.0",
                "    for tag in rec.tags:",
                "        total += (len(tag) * factor) % 7",
                "    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]",
                "    return {",
                '        "key": rec.key,',
                '        "total": round(total + rec.weight * factor, 6),',
                '        "digest": digest,',
                '        "json": json.dumps({"k": rec.key}, sort_keys=True),',
                "    }",
                "",
                "",
                f"def aggregate_{k:02d}(recs: list[Rec{k:02d}], factor: float = 1.0) -> float:",
                f'    """Aggregate a batch of Rec{k:02d}."""',
                "    if not recs:",
                "        return 0.0",
                "    values = [math.log1p(abs(r.weight)) for r in recs]",
                "    return sum(values) * factor / len(values)",
            ]
            if probe:
                out += [
                    "",
                    "",
                    "def _probe_static_binary() -> int:",
                    f'    """Constant probe used by the {pkg} health check."""',
                    '    return subprocess.run(["/usr/bin/true"], check=False).returncode',
                ]
            return out

        k = 0
        while True:
            probe = idx % 40 == 7 and k == 3
            chunk = block(k, probe)
            if len(lines) + len(chunk) > lines_per_file:
                break
            lines.extend(chunk)
            k += 1

        text = "\n".join(lines).rstrip() + "\n"
        ast.parse(text)
        path = os.path.join(ROOT, "filler", pkg, f"mod_{idx:03d}.py")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


# ---------------------------------------------------------------------------
# config + main
# ---------------------------------------------------------------------------
def build_config() -> None:
    doc = {
        "note": "可配置的 sanitizer 白名单：这些函数/方法的返回值视为已净化。",
        "sanitizers": [
            {"name": "shlex.quote", "kind": "function"},
            {"name": "lib.sanitizers.quote", "kind": "function"},
            {"name": "os.path.basename", "kind": "function"},
            {"name": "lib.sanitizers.base_name", "kind": "function"},
            {"name": "lib.sanitizers.allow_enum", "kind": "function"},
            {"name": "int", "kind": "builtin"},
        ],
        "shell_wrappers": [
            "lib.shellwrap.run_shell", "lib.shellwrap.run", "lib.cmdutil.critical_run",
        ],
        "safe_wrappers": ["lib.shellwrap.run_argv", "lib.cmdutil.safe_run"],
        "template_renderers": ["lib.templating.render_cmd", "lib.templating.render_inline"],
    }
    path = os.path.join(ROOT, "config", "sanitizers.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def main() -> int:
    build_lib()
    build_templates()
    build_config()
    build_diag()
    build_ops()
    build_users()
    build_maintenance()
    build_sync()
    build_console()
    build_cli()
    build_reports()
    build_ingest()
    build_benign()
    build_filler()
    for m in PACKAGES.values():
        if m.rel != "lib/templating.py":
            m.write()

    labels = sorted(LABELS, key=lambda v: v["id"])
    doc = {
        "topic": "12139",
        "note": ("50 条命令注入链路：源为 Flask 路由参数 / Celery 任务参数 / 环境变量，"
                 "落点覆盖 subprocess/os.system 的字符串拼接、参数列表误用、shell 包装函数、"
                 "模板渲染出的命令；传播跨模块并穿过装饰器与闭包。"
                 "良性注入点（常量命令、argv 列表、shlex.quote/basename/allow_enum 净化后）"
                 "一律不算。finding 的 file/line 指向污点实际到达的执行调用行。"),
        "total": len(labels),
        "vulns": labels,
    }
    with open(os.path.join(ROOT, "labels.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    total_lines = 0
    total_files = 0
    for dirpath, _dirnames, names in os.walk(ROOT):
        if ".git" in dirpath or "tools" in dirpath or "tests" in dirpath or "baseline" in dirpath:
            continue
        for name in names:
            if name.endswith(".py"):
                total_files += 1
                with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                    total_lines += sum(1 for _ in fh)
    print(f"wrote {total_files} .py files / {total_lines} lines / {len(labels)} labels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
