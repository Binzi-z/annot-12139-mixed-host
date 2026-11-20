"""可配置白名单与 sink 定义。

``config/sanitizers.json`` 是唯一的策略入口，可在不改代码的情况下增删：

- ``sanitizers``         返回值视为已净化（污点失活，不删 source 证据）
- ``shell_wrappers``     配置出的 shell 包装函数：首参当 shell 字符串处理
- ``safe_wrappers``      安全包装（``shell=False``）：永不产生告警
- ``template_renderers`` 模板渲染器：任一渲染入参带污点则渲染结果带污点

sink 本身（``subprocess.run`` 等）是语言级事实，不放进配置——配置只描述
项目自身代码的语义，避免把「什么是危险 API」也变成可调参数。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

# ---- 语言级 sink ----------------------------------------------------------

# subprocess 族：(属性名集合, 是否由 shell=True 决定危险性)
SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_call", "check_output"}
OS_SHELL_FUNCS = {"system", "popen"}          # os.system / os.popen 恒为 shell
# 参数列表误用：argv[0]（程序名）可控即可执行任意程序
ARGV0_SHELL_TOKENS = {"/bin/sh", "/bin/bash", "sh", "bash"}
SHELL0_FLAGS = {"-c", "-lc", "-ec"}

# Flask / Celery / 环境变量 source 的识别模式
FLASK_REQUEST = "request"
REQUEST_ARGS_ATTRS = {"args", "form", "json", "values", "cookies", "headers"}
ENV_MODULE = "os"
ENV_NAMES = {"environ", "getenv"}
CELERY_DECORATORS = {"task"}


@dataclass
class AnalyzerConfig:
    sanitizers: dict[str, str] = field(default_factory=dict)     # fqname -> kind
    shell_wrappers: set[str] = field(default_factory=set)
    safe_wrappers: set[str] = field(default_factory=set)
    template_renderers: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: Optional[str]) -> "AnalyzerConfig":
        if not path:
            return cls()
        with open(path, "rb") as fh:
            data = fh.read()
        doc = json.loads(data.decode("utf-8-sig"))
        return cls(
            sanitizers={s["name"]: s.get("kind", "function")
                        for s in doc.get("sanitizers", [])},
            shell_wrappers=set(doc.get("shell_wrappers", [])),
            safe_wrappers=set(doc.get("safe_wrappers", [])),
            template_renderers=set(doc.get("template_renderers", [])),
        )

    # 名称在配置里可能写成 fqname（lib.sanitizers.quote）或短名（int / shlex.quote），
    # 调用点解析出的两种形式都查一遍。
    def is_sanitizer(self, fqname: str, short: str) -> Optional[str]:
        for cand in (fqname, short):
            if cand in self.sanitizers:
                return cand
        return None

    def classify_wrapper(self, fqname: str, short: str) -> Optional[str]:
        def hit(group: set[str]) -> bool:
            if fqname in group or short in group:
                return True
            # 短名容错：templating.render_inline 匹配 lib.templating.render_inline
            tail2 = ".".join(short.split(".")[-2:])
            return any(".".join(name.split(".")[-2:]) == tail2 for name in group)
        for group, label in ((self.shell_wrappers, "shell"),
                             (self.safe_wrappers, "safe"),
                             (self.template_renderers, "template")):
            if hit(group):
                return label
        return None
