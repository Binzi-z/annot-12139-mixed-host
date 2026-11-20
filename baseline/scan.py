#!/usr/bin/env python3
"""baseline/scan.py —— 12139 的现有基线：正则扫「命令执行 API」。

现状就是题面第一句说的那件事：只看调用点，不看参数是不是用户可控的。
只要一行里出现 subprocess / os.system / os.popen / shellwrap / cmdutil 的调用就报，
于是常量命令、argv 列表、shlex.quote 净化过的调用全被报成漏洞（误报），
而真正跨模块、经装饰器/闭包/模板传播的链路也只是「报在调用行」，没有任何污点证据。

用法::

    python baseline/scan.py > findings.json
    python eval.py findings.json

只依赖标准库；扫描 services/ 与 lib/（baseline/、tools/、tests/ 不参与）。
"""
from __future__ import annotations

import json
import os
import re
import sys

SCAN_ROOTS = ("services", "lib", "filler")
SKIP_DIRS = {"__pycache__", ".git", "baseline", "tools", "tests"}

SINK = re.compile(
    r"\b(?:"
    r"subprocess\.(?:run|call|Popen|check_output|check_call)"
    r"|os\.system"
    r"|os\.popen"
    r"|shellwrap\.\w+"
    r"|cmdutil\.\w+"
    r")\s*\("
)


def scan_file(rel: str) -> list[dict]:
    out = []
    with open(rel, encoding="utf-8", errors="ignore") as fh:
        for no, line in enumerate(fh, start=1):
            if line.lstrip().startswith("#"):
                continue
            if SINK.search(line):
                out.append({
                    "rule": "command_injection",
                    "sink": "command_injection",
                    "file": rel.replace("\\", "/"),
                    "line": no,
                    "evidence": line.strip()[:200],
                })
    return out


def main() -> int:
    findings: list[dict] = []
    for root in SCAN_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, names in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(names):
                if name.endswith(".py"):
                    findings.extend(scan_file(os.path.join(dirpath, name)))
    json.dump({"findings": findings}, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
    print(f"[baseline] {len(findings)} sink hits (regex on execution APIs, no taint)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
