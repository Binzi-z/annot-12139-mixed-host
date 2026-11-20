"""表达式级污点求值。

:class:`Evaluator` 把一个 AST 表达式求值成 :class:`Value`——同时携带：

- ``taint``：污点（可能为空）
- ``literal``：是否为纯常量字面量（常量字符串 / 常量 argv 列表据此放行）
- ``kind``：str / list / dict / other，用于参数列表误用（argv[0]）的判定
- ``const_value``：能静态确定时保存 Python 原值（dict 白名单下标、shell=True 判定）

所有传播规则集中在本模块，过程内引擎只负责按 CFG 顺序调用它。
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

from .config import (ARGV0_SHELL_TOKENS, ENV_MODULE, ENV_NAMES, REQUEST_ARGS_ATTRS,
                     FLASK_REQUEST, SHELL0_FLAGS, SUBPROCESS_FUNCS, AnalyzerConfig)
from .impres import ModuleInfo, ModuleRepo
from .model import (SELF_TOKEN, Taint, closure, global_slot, local, self_attr)

TAINT_SRC_REQUEST = "flask"
TAINT_SRC_CELERY = "celery"
TAINT_SRC_ENV = "env"
TAINT_SRC_EXCEPT = "exception"
TAINT_SRC_UNKNOWN = "unknown"


@dataclass
class Value:
    taint: Optional[Taint] = None
    literal: bool = True
    kind: str = "other"           # str | list | dict | other
    const_value: object = None
    # list/dict 的逐元素污点（下标精确判定 argv[0] 用）
    elems: tuple["Value", ...] = ()
    keys: tuple[object, ...] = ()
    # 调用副作用（self/global 写）产生的后继状态，引擎语句层负责合并
    state_after: object = None

    def is_tainted(self) -> bool:
        return self.taint is not None and self.taint.is_tainted()

    @staticmethod
    def clean_const(node_repr: str = "<const>") -> "Value":
        return Value(literal=True, kind="str", const_value=node_repr)

    @staticmethod
    def merge(a: "Value", b: "Value") -> "Value":
        return Value(
            taint=Taint.merge(a.taint, b.taint),
            literal=a.literal and b.literal,
            kind=a.kind if a.kind == b.kind else "other",
            elems=tuple(_merge_elems(a.elems, b.elems)),
        )


def _merge_elems(a: tuple[Value, ...], b: tuple[Value, ...]) -> list[Value]:
    out: list[Value] = []
    for i in range(max(len(a), len(b))):
        if i < len(a) and i < len(b):
            out.append(Value.merge(a[i], b[i]))
        elif i < len(a):
            out.append(a[i])
        else:
            out.append(b[i])
    return out


class Evaluator:
    def __init__(self, repo: ModuleRepo, config: AnalyzerConfig,
                 inter, info: ModuleInfo):
        self.repo = repo
        self.config = config
        self.inter = inter          # InterproceduralAnalyzer（延迟传，避免循环导入）
        self.info = info

    # -- 入口 ----------------------------------------------------------------

    def eval(self, node: ast.AST, state, frame: "Frame") -> Value:
        method = getattr(self, f"_eval_{type(node).__name__}", None)
        if method is None:
            return self._unknown(node, state, frame)
        return method(node, state, frame)

    def _unknown(self, node: ast.AST, state, frame) -> Value:
        # 无法识别的表达式：不带污点，但绝不当常量
        return Value(literal=False)

    # -- 字面量 --------------------------------------------------------------

    def _eval_Constant(self, node: ast.Constant, state, frame) -> Value:
        val = node.value
        if isinstance(val, str):
            return Value(literal=True, kind="str", const_value=val)
        if isinstance(val, bool):
            return Value(literal=True, kind="other", const_value=val)
        if isinstance(val, (int, float)):
            return Value(literal=True, kind="other", const_value=val)
        if val is None:
            return Value(literal=True, kind="other", const_value=None)
        if isinstance(val, bytes):
            return Value(literal=True, kind="other", const_value=val)
        return Value(literal=True, kind="other")

    def _eval_Tuple(self, node: ast.Tuple, state, frame) -> Value:
        elems = tuple(self.eval(e, state, frame) for e in node.elts)
        return Value(literal=all(e.literal for e in elems), kind="list",
                     elems=elems, const_value=tuple(e.const_value for e in elems
                                                    if e.literal))

    def _eval_List(self, node: ast.List, state, frame) -> Value:
        elems = tuple(self.eval(e, state, frame) for e in node.elts)
        return Value(literal=all(e.literal for e in elems), kind="list",
                     elems=elems, const_value=[e.const_value for e in elems
                                               if e.literal])

    def _eval_Dict(self, node: ast.Dict, state, frame) -> Value:
        elems = tuple(self.eval(v, state, frame) for v in node.values)
        const: dict[object, object] = {}
        keys: list[object] = []
        for k_node, v in zip(node.keys, elems):
            if k_node is None:
                keys.append(None)
                continue
            kv = self.eval(k_node, state, frame)
            keys.append(kv.const_value if kv.literal else None)
            if kv.literal and v.literal:
                const[kv.const_value] = v.const_value
        return Value(literal=all(e.literal for e in elems), kind="dict",
                     elems=elems, keys=tuple(keys), const_value=const or None)

    def _eval_Set(self, node: ast.Set, state, frame) -> Value:
        elems = tuple(self.eval(e, state, frame) for e in node.elts)
        return Value(literal=all(e.literal for e in elems), kind="other", elems=elems)

    def _eval_FormattedValue(self, node: ast.FormattedValue, state, frame) -> Value:
        return self.eval(node.value, state, frame)

    def _eval_JoinedStr(self, node: ast.JoinedStr, state, frame) -> Value:
        parts = [self.eval(v, state, frame) for v in node.values]
        taint = None
        for p in parts:
            taint = Taint.merge(taint, p.taint)
        return Value(taint=taint, literal=all(p.literal for p in parts), kind="str")

    # -- 名字 / 下标 / 属性 ---------------------------------------------------

    def _eval_Name(self, node: ast.Name, state, frame) -> Value:
        name = node.id
        # 方法内的 self：本身不携带值污点，属性访问在 _eval_Attribute 处理
        if name == frame.self_name:
            return Value(literal=False, kind="other", const_value=SELF_TOKEN)
        slot = frame.resolve_name(name)
        taint = state.get(slot) if slot else None
        if taint is not None:
            return Value(taint=taint, literal=False, kind="str")
        return Value(literal=False)

    def _eval_Attribute(self, node: ast.Attribute, state, frame) -> Value:
        owner = self.eval(node.value, state, frame)
        # request.args / request.form / request.json ... 的后续下标在 Subscript 处理
        if self._is_request_root(node.value):
            return Value(literal=False, kind="other",
                         const_value=("request_attr", node.attr))
        # self.x -> 实例属性槽位
        if isinstance(node.value, ast.Name) and node.value.id == frame.self_name:
            taint = state.get(self_attr(node.attr))
            if taint is not None:
                return Value(taint=taint, literal=False, kind="str")
            return Value(literal=False)
        # os.environ（不带下标时本身就是环境源容器）
        if owner.const_value and isinstance(owner.const_value, tuple) \
                and owner.const_value[0] == "request_attr":
            return owner
        return Value(taint=owner.taint, literal=False)

    def _eval_Subscript(self, node: ast.Subscript, state, frame) -> Value:
        owner = self.eval(node.value, state, frame)
        index = self.eval(node.slice, state, frame)
        # request.args["x"] / request.form["x"] / request.json.get(...) 之外的下标形式
        if owner.const_value and isinstance(owner.const_value, tuple) \
                and owner.const_value[0] == "request_attr":
            attr = owner.const_value[1]
            if attr in REQUEST_ARGS_ATTRS:
                src = f"{TAINT_SRC_REQUEST}.{attr}"
                return Value(taint=Taint(sources=(src,),
                                         path=(f"request.{attr}[...]",)),
                             literal=False, kind="str")
        # os.environ["X"]
        if self._is_os_environ(node.value):
            return Value(taint=Taint(sources=(f"{TAINT_SRC_ENV}.{self._slice_text(node.slice)}",),
                                     path=("os.environ[...]",)),
                         literal=False, kind="str")
        # 常量 dict 白名单下标：ALLOWED_SERVICES[name] -> 干净
        if owner.kind == "dict" and owner.literal and isinstance(owner.const_value, dict):
            return Value(literal=True, kind="str",
                         const_value=owner.const_value.get(index.const_value))
        # 逐元素下标：argv[0] 判定需要
        if owner.elems and index.literal and isinstance(index.const_value, int):
            i = index.const_value
            if 0 <= i < len(owner.elems):
                return owner.elems[i]
        # 非常量下标：容器任一元素有污点则结果有污点（保守）
        taint = owner.taint
        for e in owner.elems:
            taint = Taint.merge(taint, e.taint)
        return Value(taint=taint, literal=False,
                     kind=owner.elems[0].kind if owner.elems else "other")

    # -- 运算 ----------------------------------------------------------------

    def _eval_BinOp(self, node: ast.BinOp, state, frame) -> Value:
        left = self.eval(node.left, state, frame)
        right = self.eval(node.right, state, frame)
        if isinstance(node.op, ast.Add):
            taint = Taint.merge(left.taint, right.taint)
            kind = "str" if left.kind == "str" or right.kind == "str" else "other"
            if taint is not None and taint.is_tainted():
                taint = taint.with_step("concat")
            return Value(taint=taint,
                         literal=left.literal and right.literal, kind=kind)
        # 其他运算：数值运算不产生可注入字符串；但污点保留（可能再被 str() 化）
        return Value(taint=Taint.merge(left.taint, right.taint), literal=False)

    def _eval_UnaryOp(self, node: ast.UnaryOp, state, frame) -> Value:
        return self.eval(node.operand, state, frame)

    def _eval_BoolOp(self, node: ast.BoolOp, state, frame) -> Value:
        vals = [self.eval(v, state, frame) for v in node.values]
        taint = None
        for v in vals:
            taint = Taint.merge(taint, v.taint)
        return Value(taint=taint, literal=all(v.literal for v in vals))

    def _eval_Compare(self, node: ast.Compare, state, frame) -> Value:
        taint = self.eval(node.left, state, frame).taint
        for comp in node.comparators:
            taint = Taint.merge(taint, self.eval(comp, state, frame).taint)
        return Value(taint=taint, literal=False, kind="other")

    def _eval_IfExp(self, node: ast.IfExp, state, frame) -> Value:
        a = self.eval(node.body, state, frame)
        b = self.eval(node.orelse, state, frame)
        return Value.merge(a, b)

    def _eval_Starred(self, node: ast.Starred, state, frame) -> Value:
        return self.eval(node.value, state, frame)

    def _eval_Slice(self, node: ast.Slice, state, frame) -> Value:
        taint = None
        for part in (node.lower, node.upper, node.step):
            if part is not None:
                taint = Taint.merge(taint, self.eval(part, state, frame).taint)
        return Value(taint=taint, literal=False)

    def _eval_Lambda(self, node: ast.Lambda, state, frame) -> Value:
        return Value(literal=False)  # 闭包对象本身不携带值污点

    # -- 调用：source / sanitizer / wrapper / 跨过程 / sink 全在这里 ----------

    def _eval_Call(self, node: ast.Call, state, frame) -> Value:
        return self.inter.eval_call(node, state, frame, self)

    # -- 辅助 ----------------------------------------------------------------

    def _is_request_root(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id == FLASK_REQUEST

    def _is_os_environ(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Attribute):
            return False
        return isinstance(node.value, ast.Name) and node.value.id == ENV_MODULE \
            and node.attr == "environ"

    def _slice_text(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant):
            return str(node.value)
        return "?"

    def dotted_of(self, node: ast.AST) -> list[str]:
        """把 ``a.b.c`` 形式拆成属性链；不可拆返回 []。"""
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            base = self.dotted_of(node.value)
            return base + [node.attr] if base else []
        return []

    # ---- source 识别（供 inter 复用） --------------------------------------

    def source_taint_for(self, node: ast.Call) -> Optional[Taint]:
        """识别 request.args.get(...) / os.getenv(...) 等 source 调用。"""
        func = node.func
        # os.getenv(...) / os.environ.get(...)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                and func.value.id == ENV_MODULE and func.attr == "getenv":
            key = self._arg0_text(node)
            return Taint(sources=(f"{TAINT_SRC_ENV}.{key}",),
                         path=("os.getenv(...)",))
        if isinstance(func, ast.Attribute) and func.attr == "get":
            # os.environ.get(...)
            if self._is_os_environ(func.value):
                key = self._arg0_text(node)
                return Taint(sources=(f"{TAINT_SRC_ENV}.{key}",),
                             path=("os.environ.get(...)",))
            # request.args.get / request.form.get / request.json.get ...
            root = func.value
            if isinstance(root, ast.Attribute) and isinstance(root.value, ast.Name) \
                    and root.value.id == FLASK_REQUEST and root.attr in REQUEST_ARGS_ATTRS:
                return Taint(sources=(f"{TAINT_SRC_REQUEST}.{root.attr}",),
                             path=(f"request.{root.attr}.get(...)",))
        return None

    def _arg0_text(self, node: ast.Call) -> str:
        if node.args and isinstance(node.args[0], ast.Constant):
            return str(node.args[0].value)
        return "?"
