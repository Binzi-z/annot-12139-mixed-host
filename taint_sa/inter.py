"""跨过程分析：函数摘要、调用解析、入口驱动。

摘要模型（核心抽象）
====================
每个函数只分析一次，分析时给每个形参灌一个唯一的 **marker 污点**
（``param:<qualname>#<argname>``），得到 :class:`FunctionSummary`：

- ``ret_masks``：返回值污点由哪些形参 marker 构成、是否被 sanitizer 灭活
- ``self_writes`` / ``global_writes``：对 ``self.x``、模块全局的副作用掩码
- ``sinks``：函数体内命中的 sink，记录「哪些形参 marker 可达」与变体

调用点用实参污点 **实例化掩码**：marker 命中的形参在本次调用带污点，
就把对应实参的真实污点取出来合并。这样既不需要上下文敏感的多次重分析，
又能把 ``lib/shellwrap.py`` 里包装实现的 sink 归到 **调用点行号**——
label 锚点要求报在「污点实际到达的执行调用行」，而不是共用包装的实现行。

装饰器
======
``@audited`` / ````@require_role`` 是纯转发包装（``fn(*args, **kwargs)``），
分析时直接穿透；``@celery.task`` 标记的函数把形参灌为 celery source。
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional

from .config import AnalyzerConfig, CELERY_DECORATORS
from .impres import ModuleInfo, ModuleRepo
from .model import Taint

MARKER_PREFIX = "param:"


def marker(qual: str, arg: str) -> str:
    return f"{MARKER_PREFIX}{qual}#{arg}"


@dataclass
class SinkRecord:
    line: int
    variant: str
    arg_masks: tuple[str, ...]          # 可达该 sink 的形参 marker
    extra_source: bool = False          # 函数内部自带 source（request/env）
    sink_text: str = ""


@dataclass
class FunctionSummary:
    qualname: str
    params: tuple[str, ...]
    ret_masks: tuple[str, ...] = ()
    ret_sanitized: bool = False
    ret_extra_sources: tuple[str, ...] = ()
    self_writes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    self_write_sanitized: dict[str, bool] = field(default_factory=dict)
    global_writes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    sinks: list[SinkRecord] = field(default_factory=list)
    is_celery_task: bool = False
    analyzed: bool = False


@dataclass
class FunctionUnit:
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module: ModuleInfo
    parent_qual: Optional[str] = None
    class_name: Optional[str] = None
    is_module_entry: bool = False       # 模块级 body（伪函数）
    is_celery_task: bool = False


class FunctionRegistry:
    """从所有模块里收集函数单元（含方法、嵌套函数），按全限定名索引。"""

    def __init__(self, repo: ModuleRepo):
        self.repo = repo
        self.units: dict[str, FunctionUnit] = {}
        self.by_module: dict[str, list[str]] = {}
        self.classes: dict[str, ast.ClassDef] = {}       # qualname -> ClassDef
        self.class_methods: dict[str, dict[str, str]] = {}  # class qual -> method map

    def discover(self) -> None:
        for fqname, info in self.repo.modules.items():
            self.by_module[fqname] = []
            for node in info.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._register(fqname, info, node, parent=None, class_name=None)
                elif isinstance(node, ast.ClassDef):
                    cq = f"{fqname}.{node.name}"
                    self.classes[cq] = node
                    self.class_methods[cq] = {}
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self.class_methods[cq][sub.name] = f"{cq}.{sub.name}"
                            self._register(fqname, info, sub, parent=None,
                                           class_name=node.name)

    def _register(self, module_fq: str, info: ModuleInfo,
                  node: ast.FunctionDef, parent: Optional[str],
                  class_name: Optional[str]) -> None:
        qual = f"{module_fq}.{node.name}" if class_name is None \
            else f"{module_fq}.{class_name}.{node.name}"
        if parent:
            qual = f"{parent}.{node.name}"
        is_task = self._is_celery_task(node)
        unit = FunctionUnit(qualname=qual, node=node, module=info,
                            parent_qual=parent, class_name=class_name,
                            is_celery_task=is_task)
        self.units[qual] = unit
        self.by_module.setdefault(module_fq, []).append(qual)
        for sub in self._nested_funcs(node):
            self._register_nested(info, sub, qual)

    def _register_nested(self, info: ModuleInfo, node: ast.FunctionDef,
                         parent_qual: str) -> None:
        qual = f"{parent_qual}.{node.name}"
        unit = FunctionUnit(qualname=qual, node=node, module=info,
                            parent_qual=parent_qual,
                            is_celery_task=self._is_celery_task(node))
        self.units[qual] = unit
        for sub in self._nested_funcs(node):
            self._register_nested(info, sub, qual)

    @staticmethod
    def _nested_funcs(node: ast.AST) -> list[ast.FunctionDef]:
        out: list[ast.FunctionDef] = []
        for sub in ast.walk(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub is not node:
                # 只收直接/间接嵌套；walk 会重复进入，靠 qualname 注册去重
                if not any(sub is x for x in out):
                    out.append(sub)
        return out

    @staticmethod
    def _is_celery_task(node: ast.FunctionDef) -> bool:
        for dec in node.decorator_list:
            target = dec
            if isinstance(dec, ast.Call):
                target = dec.func
            if isinstance(target, ast.Attribute) and target.attr in CELERY_DECORATORS:
                return True
            if isinstance(target, ast.Name) and target.id in CELERY_DECORATORS:
                return True
        return False

    def lookup(self, qualname: str) -> Optional[FunctionUnit]:
        return self.units.get(qualname)


@dataclass
class ResolvedCall:
    fqname: Optional[str]              # 仓库内可解析的函数全限定名
    short: str                         # 点分短名（查配置/内建用）
    is_method: bool = False
    class_qual: Optional[str] = None
    method_name: Optional[str] = None


class CallResolver:
    def __init__(self, repo: ModuleRepo, registry: FunctionRegistry):
        self.repo = repo
        self.registry = registry

    def resolve(self, info: ModuleInfo, func: ast.AST) -> ResolvedCall:
        # 方法调用 obj.method(...)
        if isinstance(func, ast.Attribute):
            dotted = self._dotted(func)
            if dotted:
                fq, short = self.repo.resolve(info, dotted)
                if fq and fq in self.registry.units:
                    unit = self.registry.units[fq]
                    return ResolvedCall(fq, short, is_method=unit.class_name is not None,
                                        class_qual=(f"{info.fqname}.{unit.class_name}"
                                                    if unit.class_name else None),
                                        method_name=func.attr)
                return ResolvedCall(fq, short, method_name=func.attr)
            return ResolvedCall(None, self._attr_text(func))
        # 直接名字 f(...)
        if isinstance(func, ast.Name):
            fq, short = self.repo.resolve(info, [func.id])
            if fq and fq in self.registry.units:
                return ResolvedCall(fq, short)
            return ResolvedCall(fq, short)
        return ResolvedCall(None, "<call>")

    def resolve_class_of(self, info: ModuleInfo, class_name: str) -> Optional[str]:
        fq, _ = self.repo.resolve(info, [class_name])
        return fq if fq in self.registry.classes else None

    @staticmethod
    def _dotted(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            base = CallResolver._dotted(node.value)
            return base + [node.attr] if base else []
        return []

    @staticmethod
    def _attr_text(node: ast.Attribute) -> str:
        parts = CallResolver._dotted(node)
        return ".".join(parts) if parts else "?"
