"""污点状态的核心数据结构。

设计要点
========
1. 污点「值」用 :class:`Taint` 表示：携带 source 描述与传播路径（用于报告里给出
   完整链路证据），并记录 ``sanitized`` 标记——被配置白名单里的 sanitizer 处理后
   污点不消失但失活，失活污点再参与拼接也不会复活。
2. 变量状态按 *槽位（slot）* 组织：普通局部变量、实例属性 ``self.x``、闭包单元、
   模块级全局。槽位是字符串，前缀区分命名空间，避免 ``self.cmd`` 与局部 ``cmd``
   互相污染。
3. 状态对象不可变（:class:`State` 每次 update 返回新对象），CFG 分支合流时做
   保守合并：任一支路带污点，合流后该槽位仍带污点（may-analysis）。
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Iterable, Optional

# ---- 槽位前缀 -------------------------------------------------------------

SLOT_LOCAL = "L:"      # 函数局部变量（含参数）
SLOT_SELF = "S:"       # self.<attr> 实例属性
SLOT_CLOSURE = "C:"    # 嵌套函数共享的闭包单元
SLOT_GLOBAL = "G:"     # 模块级全局

SELF_TOKEN = "<self>"


def local(name: str) -> str:
    return SLOT_LOCAL + name


def self_attr(attr: str) -> str:
    return SLOT_SELF + attr


def closure(name: str) -> str:
    return SLOT_CLOSURE + name


def global_slot(name: str) -> str:
    return SLOT_GLOBAL + name


@dataclass(frozen=True)
class Taint:
    """一个污点值。``sources`` 非空即表示该值受外部输入影响。"""

    sources: tuple[str, ...] = ()
    path: tuple[str, ...] = ()
    sanitized: bool = False

    def is_tainted(self) -> bool:
        return bool(self.sources) and not self.sanitized

    def with_step(self, step: str) -> "Taint":
        return replace(self, path=self.path + (step,))

    def sanitize(self, sanitizer_name: str) -> "Taint":
        return replace(self, sanitized=True,
                       path=self.path + (f"sanitized:{sanitizer_name}",))

    @staticmethod
    def merge(a: Optional["Taint"], b: Optional["Taint"]) -> Optional["Taint"]:
        """may 合并：两边都有污点时合并 source；任一边未净化则合流后未净化。"""
        if a is None:
            return b
        if b is None:
            return a
        sources = tuple(dict.fromkeys(a.sources + b.sources))
        path = a.path if len(a.path) >= len(b.path) else b.path
        return Taint(sources=sources, path=path,
                     sanitized=a.sanitized and b.sanitized)


# 不可变映射的极简实现（避免第三方依赖，也避免 dict 别名导致分支状态互相串改）
class _FrozenMap:
    __slots__ = ("_d",)

    def __init__(self, d: Optional[dict[str, Taint]] = None):
        self._d = dict(d or {})

    def get(self, key: str) -> Optional[Taint]:
        return self._d.get(key)

    def update(self, *pairs: tuple[str, Optional[Taint]]) -> "_FrozenMap":
        new = dict(self._d)
        for key, val in pairs:
            if val is None:
                new.pop(key, None)
            else:
                new[key] = val
        return _FrozenMap(new)

    def items(self) -> Iterable[tuple[str, Taint]]:
        return self._d.items()

    def __contains__(self, key: str) -> bool:
        return key in self._d


@dataclass(frozen=True)
class _TypeTag:
    """局部变量的静态对象类型（构造调用推断），与污点值分开存放。"""
    class_fq: str


@dataclass(frozen=True)
class State:
    """CFG 节点上的污点环境。"""

    slots: _FrozenMap = field(default_factory=_FrozenMap)
    # 局部变量 -> 类全限定名（构造调用推断出的对象类型，方法调用解析用）
    types: _FrozenMap = field(default_factory=_FrozenMap)
    # 已触发过 finding 的 (node-id, sink-key)，防止同一 sink 在循环里重复上报
    reported: frozenset[tuple[int, str]] = frozenset()

    def get(self, slot: str) -> Optional[Taint]:
        return self.slots.get(slot)

    def get_type(self, name: str) -> Optional[str]:
        t = self.types.get(name)
        return t.class_fq if isinstance(t, _TypeTag) else None

    def put(self, slot: str, taint: Optional[Taint]) -> "State":
        if taint is None:
            if slot not in self.slots:
                return self
            return State(self.slots.update((slot, None)), self.types, self.reported)
        return State(self.slots.update((slot, taint)), self.types, self.reported)

    def put_type(self, name: str, class_fq: Optional[str]) -> "State":
        if class_fq is None:
            return State(self.slots, self.types.update((name, None)), self.reported)
        tag = _TypeTag(class_fq)
        return State(self.slots, self.types.update((name, tag)), self.reported)

    def mark_reported(self, key: tuple[int, str]) -> "State":
        if key in self.reported:
            return self
        return State(self.slots, self.types, self.reported | {key})

    @staticmethod
    def merge(s1: "State", s2: "State") -> "State":
        keys = {k for k, _ in s1.slots.items()} | {k for k, _ in s2.slots.items()}
        merged: dict[str, Taint] = {}
        for key in keys:
            t = Taint.merge(s1.slots.get(key), s2.slots.get(key))
            if t is not None:
                merged[key] = t
        tkeys = {k for k, _ in s1.types.items()} | {k for k, _ in s2.types.items()}
        tmerged: dict[str, "_TypeTag"] = {}
        for key in tkeys:
            a, b = s1.types.get(key), s2.types.get(key)
            if a is not None and b is not None and a.class_fq == b.class_fq:
                tmerged[key] = a
            elif a is not None:
                tmerged[key] = a
            elif b is not None:
                tmerged[key] = b
        return State(_FrozenMap(merged), _FrozenMap(tmerged),
                     s1.reported & s2.reported)


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    variant: str
    sources: tuple[str, ...]
    path: tuple[str, ...]
    sink_call: str
    message: str

    def identity(self) -> tuple[str, int, str]:
        # eval.py 对重复同点告警算 FP，故全引擎按 文件+行+变体 去重
        return (self.file, self.line, self.variant)
