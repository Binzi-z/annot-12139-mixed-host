"""SARIF 2.1.0 序列化（静态结果格式，OASIS 标准）。

CI 系统（GitHub Code Scanning / 各平台 SARIF 接入）直接消费该文件；
同时保留 findings.json 出口供 ``eval.py`` 与人工审阅。
"""
from __future__ import annotations

import json
from typing import Iterable

from . import RULE_ID
from .model import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

RULE_DESCRIPTIONS = {
    "concat_shell": "外部输入经字符串拼接进入 shell=True 的命令执行",
    "arglist_misuse": "外部输入成为 argv[0] 或 /bin/sh -c 的命令字符串",
    "shell_wrapper": "外部输入经配置登记的 shell 包装函数进入 shell",
    "template_rendered": "外部输入经模板渲染生成命令字符串后被执行",
    "closure": "外部输入被闭包捕获后到达命令执行点",
    "class_attr": "外部输入存入实例属性，稍后被 shell 执行",
}


def to_sarif(findings: Iterable[Finding], tool_name: str = "taint_sa",
             root_uri: str = "") -> dict:
    results = []
    for f in findings:
        results.append({
            "ruleId": RULE_ID,
            "level": "error",
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file.replace("\\", "/"),
                        **({"uriBaseId": root_uri} if root_uri else {}),
                    },
                    "region": {"startLine": f.line,
                               "snippet": {"text": f.sink_call}},
                }
            }],
            "properties": {
                "variant": f.variant,
                "sources": list(f.sources),
                "taint_path": list(f.path),
                "security-severity": "8.8",   # CVSS 风格分值，供平台排序
                "cwe": "CWE-78",
            },
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": "1.0.0",
                "informationUri": "https://example.invalid/taint_sa",
                "rules": [{
                    "id": RULE_ID,
                    "name": "PythonCommandInjection",
                    "shortDescription": {"text": "Python 命令注入（污点到 sink 可达）"},
                    "fullDescription": {"text": (
                        "基于自建 CFG 与污点状态的跨过程分析：Flask/Celery/环境变量 "
                        "源经拼接、参数列表误用、shell 包装、模板渲染、闭包/实例属性 "
                        "传播到达 subprocess/os.system/os.popen 等执行点。")},
                    "defaultConfiguration": {"level": "error"},
                    "helpUri": "https://cwe.mitre.org/data/definitions/78.html",
                    "messageStrings": {
                        v: {"text": d} for v, d in RULE_DESCRIPTIONS.items()
                    },
                }],
            }},
            "results": results,
        }],
    }


def to_findings_json(findings: Iterable[Finding]) -> dict:
    return {"findings": [{
        "rule": RULE_ID,
        "sink": RULE_ID,
        "file": f.file.replace("\\", "/"),
        "line": f.line,
        "variant": f.variant,
        "sources": list(f.sources),
        "path": list(f.path),
        "evidence": f.message,
    } for f in findings]}


def dump_sarif(findings: Iterable[Finding], path: str) -> None:
    doc = to_sarif(findings)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
