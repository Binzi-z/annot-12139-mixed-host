"""过程内 CFG 求值 + 跨过程摘要实例化（引擎核心）。

角色划分
========
- :class:`Frame`       一次函数分析的词法作用域（参数槽、self 名、闭包名集合）
- :class:`FunctionAnalyzer`  单个函数单元：建 CFG、worklist 不动点、产摘要
- :class:`InterAnalyzer`     仓库级协调器：模块装载、摘要缓存、调用点分类与
  sink 上报、``eval_call``（被 :class:`~taint_sa.expr.Evaluator` 回调）

摘要实例化（跨过程传播的关键）
==============================
函数分析时给每个形参灌唯一 marker 污点 ``param:<qual>#<arg>``；摘要里所有
sink / 返回值 / self 写都只记录 marker 掩码。调用点用实参真实污点替换 marker，
于是 ``lib`` 包装函数内部的 sink 可以报在 **services 调用点行号** 上，
且包装函数只需分析一次，与调用点数量无关。
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Optional

from .cfg import CFG, CFGBuilder
from .config import (ARGV0_SHELL_TOKENS, OS_SHELL_FUNCS, SHELL0_FLAGS,
                     SUBPROCESS_FUNCS, AnalyzerConfig)
from .expr import (TAINT_SRC_CELERY, TAINT_SRC_ENV, TAINT_SRC_EXCEPT,
                   TAINT_SRC_REQUEST, TAINT_SRC_UNKNOWN, Evaluator, Value)
from .impres import ModuleInfo, ModuleRepo
from .inter import (FunctionRegistry, FunctionSummary, FunctionUnit, MARKER_PREFIX,
                    SinkRecord, marker)
from .model import Finding, State, Taint, closure, global_slot, local, self_attr

MODULE_UNIT_PREFIX = "<module>:"

# 保持字符串语义、原样传递污点的 str 方法
_STR_PASSTHROUGH = {
    "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize",
    "swapcase", "encode", "decode", "casefold", "zfill", "ljust", "rjust",
    "center", "expandtabs", "replace", "removeprefix", "removesuffix",
}
# 返回容器/元素但仍应继承接收者污点的方法
_STR_ELEM_METHODS = {"split", "splitlines", "rsplit", "partition", "rpartition"}


@dataclass
class Frame:
    unit: FunctionUnit
    param_slots: dict[str, str] = field(default_factory=dict)
    self_name: Optional[str] = None
    closure_names: set[str] = field(default_factory=set)
    nested_qual: Optional[str] = None

    def resolve_name(self, name: str) -> Optional[str]:
        if self.unit.is_module_entry:
            return global_slot(name)
        if name in self.param_slots:
            return self.param_slots[name]
        # 模块全局（环境变量源等）优先于闭包槽：全局槽有真实值时直接用全局
        if self._has_global(name):
            return global_slot(name)
        if name in self.closure_names:
            return closure(name)
        return local(name)

    def _has_global(self, name: str) -> bool:
        holder = getattr(self, "_state_holder", None)
        if not holder:
            return False
        return holder[0].get(global_slot(name)) is not None


class InterAnalyzer:
    def __init__(self, repo: ModuleRepo, config: AnalyzerConfig,
                 max_iterations: int = 200, max_call_depth: int = 40):
        self.repo = repo
        self.config = config
        self.registry = FunctionRegistry(repo)
        self.registry.discover()
        self.summaries: dict[str, FunctionSummary] = {}
        self.module_states: dict[str, State] = {}
        self.findings: list[Finding] = []
        self.truncated: list[str] = []
        self.max_iterations = max_iterations
        self.max_call_depth = max_call_depth
        self._active: set[str] = set()
        self._depth = 0
        self._module_units: dict[str, FunctionUnit] = {}

    # ================================================================ 驱动

    def run(self) -> list[Finding]:
        self._build_module_units()
        # 1) 模块级状态（环境变量源 -> 全局槽）
        for fqname, info in self.repo.modules.items():
            unit = self._module_units[fqname]
            self._analyze_module_body(unit)
        # 2) 第一轮：建全部摘要（marker 探针，实现行不上报），lib 包装/类方法
        #    先于调用点就绪。缓存复用的摘要（incremental 模式）直接命中，但
        #    未缓存模块仍需现场分析。
        for qual, unit in self.registry.units.items():
            self.analyze_unit(unit)
        # 3) 第二轮：摘要已稳定，重跑入口函数的 CFG，让调用点用真实污点实例化
        #    掩码并在「执行调用行」上报。
        #    增量模式下部分摘要来自缓存、没有经过本进程的 CFG 求值，因此入口
        #    函数一律重跑（其 CFG 很小，成本可忽略），保证全量/增量同口径。
        entry_units = [u for q, u in self.registry.units.items()
                       if self._is_entry_unit(u)]
        for unit in entry_units:
            self._rerun_for_findings(unit)
        # 4) 去重（同 文件+行+变体 只保留一条，证据取 source 更丰富的）
        return self._dedupe()

    def _is_entry_unit(self, unit: FunctionUnit) -> bool:
        # 独立语料（无根目录 services/）里的函数都视作潜在入口，保证测试探针
        # 与任意第三方布局不被入口过滤漏掉
        standard_roots = any(
            os.path.isdir(os.path.join(self.repo.root, r))
            for r in ("services", "lib", "filler"))
        if not standard_roots:
            return unit.parent_qual is None
        # 只把 services/ 下的函数视作可达入口；filler 无 sink、无外部源，
        # 其摘要在第一轮建好即可，不需要第二轮 CFG 重放
        if not unit.module.fqname.startswith("services."):
            return False
        if unit.is_celery_task:
            return True
        node = unit.node
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            dotted = self._dotted(target)
            if not dotted:
                continue
            fq, _ = self.repo.resolve(unit.module, dotted)
            if fq and ("route" in dotted or "flask" in fq):
                return True
        # 模块级普通函数（CLI 入口、reports 的无装饰函数）
        return unit.parent_qual is None and unit.class_name is None

    @staticmethod
    def _dotted(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            base = InterAnalyzer._dotted(node.value)
            return base + [node.attr] if base else []
        return []

    def _rerun_for_findings(self, unit: FunctionUnit) -> None:
        """用已缓存摘要重跑入口函数的 CFG，产出调用行 findings。"""
        from .cfg import CFGBuilder
        fa = FunctionAnalyzer(self)
        module_state = self.module_states.get(unit.module.fqname, State())
        cfg = CFGBuilder().build(unit.node)
        frame = fa._build_frame(unit, cfg)
        seed = fa._seed(unit, frame, module_state, cfg)
        frame._state_holder = [seed]
        fa._fixpoint(unit, cfg, frame, seed, seeding="function")

    def _build_module_units(self) -> None:
        for fqname, info in self.repo.modules.items():
            node = ast.FunctionDef(name="<module>", args=ast.arguments(
                posonlyargs=[], args=[], vararg=None, kwonlyargs=[],
                kw_defaults=[], kwarg=None, defaults=[]),
                body=list(info.tree.body), decorator_list=[], returns=None,
                type_comment=None)
            unit = FunctionUnit(qualname=MODULE_UNIT_PREFIX + fqname, node=node,
                                module=info, is_module_entry=True)
            self._module_units[fqname] = unit

    def _analyze_module_body(self, unit: FunctionUnit) -> None:
        fa = FunctionAnalyzer(self)
        state, summary = fa.analyze_module(unit)
        self.module_states[unit.module.fqname] = state
        self.summaries[unit.qualname] = summary

    def analyze_unit(self, unit: FunctionUnit) -> FunctionSummary:
        cached = self.summaries.get(unit.qualname)
        if cached is not None and cached.analyzed:
            return cached
        if unit.qualname in self._active:
            # 递归环：截断。返回保守空摘要（详见 README「截断策略」）
            stub = FunctionSummary(
                qualname=unit.qualname,
                params=FunctionAnalyzer.param_names(unit),
                is_celery_task=unit.is_celery_task)
            self.summaries[unit.qualname] = stub
            self.truncated.append(f"递归环截断: {unit.qualname}")
            return stub
        if self._depth >= self.max_call_depth:
            stub = FunctionSummary(
                qualname=unit.qualname,
                params=FunctionAnalyzer.param_names(unit),
                is_celery_task=unit.is_celery_task)
            self.truncated.append(f"调用深度截断(>{self.max_call_depth}): {unit.qualname}")
            return stub
        self._active.add(unit.qualname)
        self._depth += 1
        try:
            fa = FunctionAnalyzer(self)
            summary = fa.analyze(unit, self.module_states.get(unit.module.fqname, State()))
            self.summaries[unit.qualname] = summary
            return summary
        finally:
            self._depth -= 1
            self._active.discard(unit.qualname)

    def _dedupe(self) -> list[Finding]:
        best: dict[tuple[str, int, str], Finding] = {}
        for f in self.findings:
            key = f.identity()
            old = best.get(key)
            if old is None or len(f.sources) > len(old.sources):
                best[key] = f
        return sorted(best.values(), key=lambda f: (f.file, f.line, f.variant))

    # ================================================================ 调用点

    def eval_call(self, call: ast.Call, state: State, frame: Frame,
                  ev: Evaluator) -> Value:
        # 1) 语言级 source：request.* / os.getenv / os.environ.get
        src = ev.source_taint_for(call)
        if src is not None:
            return Value(taint=src, literal=False, kind="str")

        resolved = self._resolve(frame.unit.module, call.func, state, frame)

        # 2) 语言级 sink：subprocess.* / os.system / os.popen
        direct = self._direct_sink(call, state, frame, ev, resolved)
        if direct is not None:
            return direct

        fq = resolved.fqname if resolved else None
        short = resolved.short if resolved else ""

        # 容错：目标代码缺 import（运行时即 NameError 的坏代码）时，按属性链尾部
        # 匹配配置里的短名（如 templating.render_inline），保证策略仍可生效
        if fq is None and isinstance(call.func, ast.Attribute):
            tail = self._resolver._attr_text(call.func)
            tail2 = ".".join(tail.split(".")[-2:])
            for group in (self.config.template_renderers, self.config.shell_wrappers,
                          self.config.safe_wrappers):
                if any(".".join(name.split(".")[-2:]) == tail2 for name in group):
                    short = tail
                    break

        # 3) 配置白名单：sanitizer / safe_wrapper / renderer 直接按配置语义处理；
        #    shell_wrappers 优先走仓库内摘要实例化（需要 callee 的 sink 掩码与
        #    行号归属），仅当仓库内找不到实现时才退回配置直判
        san = self.config.is_sanitizer(fq or "", short)
        if san is not None:
            return self._apply_sanitizer(call, state, frame, ev, san)
        cfg_hit = self.config.classify_wrapper(fq or "", short)
        if cfg_hit == "safe":
            return Value(literal=False)
        if cfg_hit == "template":
            return self._renderer_call(call, state, frame, ev)
        if cfg_hit == "shell" and not (fq and fq in self.registry.units):
            self._configured_shell_sink(call, state, frame, ev, short)
            return Value(literal=False, kind="str")

        # 4) 仓库内函数/方法：摘要实例化
        if fq and fq in self.registry.units:
            value = self._instantiate_call(call, state, frame, ev, fq,
                                           is_method=resolved.is_method,
                                           method_name=resolved.method_name)
            return self._sync_state(value, state, frame)
        # 4b) 嵌套函数的局部名字调用：_inner() —— import 表里没有，但函数
        #     注册表能按 当前模块+外层限定名 找到
        if fq is None and isinstance(call.func, ast.Name):
            nested_fq = self._lookup_nested(frame.unit, call.func.id)
            if nested_fq is not None:
                value = self._instantiate_call(call, state, frame, ev, nested_fq,
                                               is_method=False, method_name=None)
                return self._sync_state(value, state, frame)
        # 5) 类构造：ClassName(...) -> __init__ 摘要的 self 写
        if fq and fq in self.registry.classes:
            value = self._instantiate_constructor(call, state, frame, ev, fq)
            return self._sync_state(value, state, frame)

        # 6) 内建/str 方法等语言语义
        builtin = self._builtin_call(call, state, frame, ev, short)
        if builtin is not None:
            return builtin
        # 7) 未知外部函数：默认不臆造污点；但参数里的污点必须保留（可能是
        #    纯转发包装），否则会把未配置 sanitizer 的净化函数误当成「清洗器」
        arg_taint = self._arg_taint(call, state, frame, ev)
        if arg_taint is not None:
            return Value(taint=arg_taint, literal=False)
        return Value(literal=False)

    # ---- 解析 -------------------------------------------------------------

    def _lookup_nested(self, unit: FunctionUnit, name: str) -> Optional[str]:
        """从当前函数向外逐层找同名嵌套函数的全限定名。"""
        qual = unit.qualname
        while qual:
            candidate = f"{qual}.{name}"
            if candidate in self.registry.units:
                return candidate
            parent = self.registry.units.get(qual)
            if parent is None or parent.parent_qual is None:
                break
            qual = parent.parent_qual
        # 同模块顶层函数
        top = f"{unit.module.fqname}.{name}"
        return top if top in self.registry.units else None

    def _resolve(self, info: ModuleInfo, func: ast.AST, state: Optional[State] = None,
                 frame: Optional[Frame] = None):
        from .inter import CallResolver
        if not hasattr(self, "_resolver"):
            self._resolver = CallResolver(self.repo, self.registry)
        resolved = self._resolver.resolve(info, func)
        # 局部对象的方法调用：job.run() —— 用构造时记录的类型补全全限定名
        if resolved.fqname is None and isinstance(func, ast.Attribute) \
                and isinstance(func.value, ast.Name) and state is not None \
                and frame is not None:
            class_fq = state.get_type(func.value.id)
            if class_fq:
                method_qual = f"{class_fq}.{func.attr}"
                if method_qual in self.registry.units:
                    resolved.fqname = method_qual
                    resolved.short = method_qual
                    resolved.is_method = True
                    resolved.class_qual = class_fq
                    resolved.method_name = func.attr
        return resolved

    # ---- 直接 sink --------------------------------------------------------

    def _direct_sink(self, call: ast.Call, state: State, frame: Frame,
                     ev: Evaluator, resolved) -> Optional[Value]:
        func = call.func
        if not isinstance(func, ast.Attribute):
            return None
        owner = func.value
        # subprocess.<fn>(...)
        if isinstance(owner, ast.Name) and owner.id == "subprocess" \
                and func.attr in SUBPROCESS_FUNCS:
            self._check_subprocess(call, state, frame, ev, func.attr)
            return Value(literal=False)
        # os.system / os.popen
        if isinstance(owner, ast.Name) and owner.id == "os" \
                and func.attr in OS_SHELL_FUNCS:
            self._check_os_shell(call, state, frame, ev, func.attr)
            return Value(literal=False)
        return None

    def _check_subprocess(self, call: ast.Call, state: State, frame: Frame,
                          ev: Evaluator, fn_name: str) -> None:
        shell_true = self._kw_bool(call, "shell") is True
        args = [ev.eval(a, state, frame) for a in call.args]
        kwargs = {kw.arg: ev.eval(kw.value, state, frame)
                  for kw in call.keywords if kw.arg}
        line = call.lineno
        # 形态 A：shell=True + 字符串命令
        if shell_true and args:
            cmd = args[0]
            if cmd.is_tainted():
                self._emit(state, frame, line, "concat_shell",
                           f"subprocess.{fn_name}(shell=True)",
                           cmd.taint, call)
            return
        # 形态 B：argv 列表
        if args and args[0].kind == "list":
            argv = args[0]
            # B1: ["/bin/sh","-c", tainted] —— 等价 shell 字符串
            sh_idx = self._shell_c_index(argv)
            if sh_idx is not None and sh_idx + 2 < len(argv.elems):
                payload = argv.elems[sh_idx + 2]
                if payload.is_tainted():
                    self._emit(state, frame, line, "arglist_misuse",
                               'subprocess argv ["/bin/sh","-c", ...]',
                               payload.taint, call)
                return
            # B2: argv[0]（程序名）可控
            if argv.elems and argv.elems[0].is_tainted():
                self._emit(state, frame, line, "arglist_misuse",
                           "subprocess argv[0] 可控", argv.elems[0].taint, call)
                return
            # B3: 列表中任意元素污点 + shell=False：仍可能参数注入，但本题口径
            #     只认 argv[0] 与 sh -c；其余不报（monitor/health 的良性场景）
            return
        # 形态 C：shell 默认 False 但传了污点字符串变量（无列表包裹）
        if args and args[0].is_tainted() and not args[0].literal:
            if not shell_true and fn_name in {"Popen"}:
                # Popen 带字符串且 shell=False 会被当作单程序名，等价 argv0
                self._emit(state, frame, line, "arglist_misuse",
                           "Popen 污点程序名", args[0].taint, call)

    def _check_os_shell(self, call: ast.Call, state: State, frame: Frame,
                        ev: Evaluator, fn_name: str) -> None:
        if not call.args:
            return
        cmd = ev.eval(call.args[0], state, frame)
        if cmd.is_tainted():
            self._emit(state, frame, call.lineno, "concat_shell",
                       f"os.{fn_name}", cmd.taint, call)

    @staticmethod
    def _shell_c_index(argv: Value) -> Optional[int]:
        for i, elem in enumerate(argv.elems):
            if elem.kind == "str" and elem.const_value in ARGV0_SHELL_TOKENS:
                if i + 1 < len(argv.elems):
                    flag = argv.elems[i + 1]
                    if flag.kind == "str" and flag.const_value in SHELL0_FLAGS:
                        return i
        return None

    @staticmethod
    def _kw_bool(call: ast.Call, name: str) -> Optional[bool]:
        for kw in call.keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant) \
                    and isinstance(kw.value.value, bool):
                return kw.value.value
        return None

    # ---- 配置化包装 -------------------------------------------------------

    def _apply_sanitizer(self, call: ast.Call, state: State, frame: Frame,
                         ev: Evaluator, name: str) -> Value:
        taint = None
        for a in call.args:
            taint = Taint.merge(taint, ev.eval(a, state, frame).taint)
        for kw in call.keywords:
            taint = Taint.merge(taint, ev.eval(kw.value, state, frame).taint)
        if taint is None:
            return Value(literal=all(isinstance(a, ast.Constant) for a in call.args),
                         kind="str")
        return Value(taint=taint.sanitize(name), literal=False, kind="str")

    def _configured_shell_sink(self, call: ast.Call, state: State, frame: Frame,
                               ev: Evaluator, name: str) -> None:
        taint = None
        for a in call.args:
            taint = Taint.merge(taint, ev.eval(a, state, frame).taint)
        for kw in call.keywords:
            taint = Taint.merge(taint, ev.eval(kw.value, state, frame).taint)
        if taint is not None and taint.is_tainted():
            self._emit(state, frame, call.lineno, "shell_wrapper",
                       f"shell 包装 {name}", taint, call)

    def _renderer_call(self, call: ast.Call, state: State, frame: Frame,
                       ev: Evaluator) -> Value:
        taint = None
        # 模板串本身可控（render_inline 的 template 形参）也是污染源
        for a in call.args:
            taint = Taint.merge(taint, ev.eval(a, state, frame).taint)
        for kw in call.keywords:
            taint = Taint.merge(taint, ev.eval(kw.value, state, frame).taint)
        if taint is None:
            return Value(literal=False, kind="str")
        if taint.is_tainted():
            taint = taint.with_step("template.render")
        return Value(taint=taint, literal=False, kind="str")

    # ---- 摘要实例化 -------------------------------------------------------

    def _instantiate_call(self, call: ast.Call, state: State, frame: Frame,
                          ev: Evaluator, fq: str, *, is_method: bool,
                          method_name: Optional[str]) -> Value:
        unit = self.registry.units[fq]
        summary = self.analyze_unit(unit)
        arg_map = self._bind_arguments(call, state, frame, ev, summary, unit,
                                       is_method=is_method)
        if is_method:
            # self:<attr> marker <- 调用者视角下接收者对象的实例属性槽
            receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
            for rec in summary.sinks:
                for mask in rec.arg_masks:
                    if "#self:" in mask:
                        attr = mask.split("#self:", 1)[1]
                        taint = self._receiver_attr_taint(receiver, attr, state, frame)
                        if taint is not None:
                            arg_map[mask] = taint
            for attr, masks in summary.self_writes.items():
                for mask in masks:
                    if "#self:" in mask:
                        taint = self._receiver_attr_taint(receiver, attr, state, frame)
                        if taint is not None:
                            arg_map[mask] = taint
        closure_map = self._closure_arguments(summary, state, frame)
        self._fire_summary_sinks(summary, arg_map, closure_map, call, frame)
        state = self._apply_self_writes(summary, arg_map, state, frame)
        state = self._apply_global_writes(summary, arg_map, state, unit)
        return self._materialize_return(summary, arg_map, closure_map)

    def _receiver_attr_taint(self, receiver: Optional[ast.AST], attr: str,
                             state: State, frame: Frame) -> Optional[Taint]:
        if receiver is None:
            return None
        # job.run()：接收者是局部变量，实例属性存在 self 槽（构造时写入）
        if isinstance(receiver, ast.Name):
            # 同一帧内所有实例共享 S: 槽（无对象敏感性，may 分析保守合并）
            return state.get(self_attr(attr))
        if isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name) \
                and receiver.value.id == frame.self_name:
            return state.get(self_attr(attr))
        return None

    def _sync_state(self, value: Value, state: State, frame: Frame) -> Value:
        """调用产生的 self/global 副作用已写入 frame 持有状态；把最新状态挂到
        Value 上，由引擎语句层在赋值后合并回当前 state。"""
        holder = self._frame_state_holder(frame)
        if holder is not None and holder[0] is not state:
            value.state_after = holder[0]  # type: ignore[attr-defined]
        return value

    def _instantiate_constructor(self, call: ast.Call, state: State, frame: Frame,
                                 ev: Evaluator, class_fq: str) -> Value:
        methods = self.registry.class_methods.get(class_fq, {})
        init_qual = methods.get("__init__")
        if init_qual and init_qual in self.registry.units:
            unit = self.registry.units[init_qual]
            summary = self.analyze_unit(unit)
            # __init__(self, ...)：调用实参对应 self 之后的形参
            arg_map = self._bind_arguments(call, state, frame, ev, summary, unit,
                                           is_method=True)
            new_state = self._apply_self_writes(summary, arg_map, state, frame)
            state = new_state
            self._fire_summary_sinks(summary, arg_map, {}, call, frame)
        return Value(literal=False, kind="other", const_value=("instance", class_fq))

    def _bind_arguments(self, call: ast.Call, state: State, frame: Frame,
                        ev: Evaluator, summary: FunctionSummary,
                        unit: FunctionUnit, *, is_method: bool) -> dict[str, Taint]:
        params = list(summary.params)
        if is_method and params and params[0] == "self":
            params = params[1:]
        arg_map: dict[str, Taint] = {}
        positional = list(call.args)
        # 关键字参数
        kw_values: dict[str, Value] = {}
        star_kw: Optional[Value] = None
        for kw in call.keywords:
            if kw.arg is None:
                star_kw = ev.eval(kw.value, state, frame)
            else:
                kw_values[kw.arg] = ev.eval(kw.value, state, frame)
        vararg_name = unit.node.args.vararg.arg if unit.node.args.vararg else None
        own_qual = unit.qualname
        for i, p in enumerate(params):
            if p == vararg_name:
                elems = [ev.eval(a, state, frame) for a in positional[i:]]
                t = None
                for v in elems:
                    t = Taint.merge(t, v.taint)
                if t:
                    arg_map[marker(own_qual, p)] = t
                positional = positional[i:]
                break
            if i < len(positional):
                v = ev.eval(positional[i], state, frame)
                if v.taint is not None:
                    arg_map[marker(own_qual, p)] = v.taint
            elif p in kw_values and kw_values[p].taint is not None:
                arg_map[marker(own_qual, p)] = kw_values[p].taint
        if vararg_name and marker(own_qual, vararg_name) not in arg_map:
            t = None
            for a in positional[len(params):]:
                t = Taint.merge(t, ev.eval(a, state, frame).taint)
            if t:
                arg_map[marker(own_qual, vararg_name)] = t
        kwarg_name = unit.node.args.kwarg.arg if unit.node.args.kwarg else None
        if kwarg_name:
            t = star_kw.taint if star_kw else None
            for v in kw_values.values():
                t = Taint.merge(t, v.taint)
            if t:
                arg_map[marker(own_qual, kwarg_name)] = t
            # 关键字实参同时保留逐名字映射：摘要掩码可能来自 **kwargs 整体，
            # 也可能来自具体形参名，两个键都写入可覆盖两种摘要形态
            for pname, v in kw_values.items():
                if v.taint is not None:
                    arg_map[marker(own_qual, pname)] = v.taint
        else:
            # 无 **kwargs 形参时，具名关键字实参仍按形参名映射
            for pname, v in kw_values.items():
                if v.taint is not None and pname in summary.params:
                    arg_map[marker(own_qual, pname)] = v.taint
        return arg_map

    def _closure_arguments(self, summary: FunctionSummary, state: State,
                           frame: Frame) -> dict[str, Taint]:
        out: dict[str, Taint] = {}
        prefix = MARKER_PREFIX + summary.qualname + "#closure:"
        for key, taint in state.slots.items():
            if not key.startswith("C:"):
                continue
            name = key[2:]
            # 嵌套函数摘要里的闭包掩码 marker 与当前帧闭包槽的真实污点对齐
            out[prefix + name] = taint
        return out

    def _fire_summary_sinks(self, summary: FunctionSummary,
                            arg_map: dict[str, Taint], closure_map: dict[str, Taint],
                            call: ast.Call, frame: Frame) -> None:
        # 若本次调用本身命中配置化 shell 包装，变体按调用点语义归类，
        # 而不是沿用包装实现内部的 concat_shell
        resolved = self._resolve(frame.unit.module, call.func, None, frame)
        wrapper_kind = self.config.classify_wrapper(resolved.fqname or "",
                                                     resolved.short)
        for rec in summary.sinks:
            taint = None
            for mask in rec.arg_masks:
                if mask in arg_map:
                    taint = Taint.merge(taint, arg_map[mask])
                elif mask in closure_map:
                    taint = Taint.merge(taint, closure_map[mask])
            if rec.extra_source:
                taint = Taint.merge(
                    taint, Taint(sources=("internal-source",),
                                 path=("callee 内部 source",)))
            if taint is None or not taint.is_tainted():
                continue
            variant = "shell_wrapper" if wrapper_kind == "shell" else rec.variant
            # label 锚点是「污点实际到达的执行调用行」：优先用摘要里记录的
            # callee 内部 sink 行（如 SyncJob.run 内的 shellwrap 调用行），
            # 库包装（lib/*）实现行被题面明确排除，才退回调用点行号。
            callee_module = self.registry.lookup(summary.qualname)
            in_lib = bool(callee_module and callee_module.module.fqname.startswith("lib."))
            line = call.lineno if in_lib else rec.line
            override_file = None if in_lib else callee_module.module.rel_path
            self._emit(state=None, frame=frame, line=line,
                       variant=variant, sink_text=rec.sink_text,
                       taint=taint, call=call, override_file=override_file)

    def _apply_self_writes(self, summary: FunctionSummary, arg_map: dict[str, Taint],
                           state: State, frame: Frame) -> State:
        new_state = state
        for attr, masks in summary.self_writes.items():
            taint = None
            for m in masks:
                taint = Taint.merge(taint, arg_map.get(m))
            if taint is None:
                continue
            slot = self_attr(attr)
            new_state = new_state.put(slot, Taint.merge(new_state.get(slot), taint))
        holder = self._frame_state_holder(frame)
        if holder is not None:
            holder[0] = new_state
        return new_state

    def _apply_global_writes(self, summary: FunctionSummary,
                             arg_map: dict[str, Taint], state: State,
                             unit: FunctionUnit) -> State:
        """函数对模块全局的副作用：写入当前帧的 G: 槽（may 合并）。"""
        for gname, masks in summary.global_writes.items():
            taint = None
            for m in masks:
                taint = Taint.merge(taint, arg_map.get(m))
            if taint is None:
                continue
            slot = global_slot(gname)
            state = state.put(slot, Taint.merge(state.get(slot), taint))
        return state

    def _materialize_return(self, summary: FunctionSummary,
                            arg_map: dict[str, Taint],
                            closure_map: dict[str, Taint]) -> Value:
        taint: Optional[Taint] = None
        for mask in summary.ret_masks:
            t = arg_map.get(mask) or closure_map.get(mask)
            if t is not None:
                taint = Taint.merge(taint, t)
        for src in summary.ret_extra_sources:
            taint = Taint.merge(taint, Taint(sources=(src,), path=("callee source",)))
        if taint is None:
            return Value(literal=False)
        if summary.ret_sanitized:
            taint = taint.sanitize(summary.qualname)
        return Value(taint=taint, literal=False, kind="str")

    # ---- 内建/字符串语义 ---------------------------------------------------

    def _builtin_call(self, call: ast.Call, state: State, frame: Frame,
                      ev: Evaluator, short: str) -> Optional[Value]:
        func = call.func
        # 类型构造
        if isinstance(func, ast.Name):
            if func.id in {"str", "bytes", "format"}:
                t = self._arg_taint(call, state, frame, ev)
                return Value(taint=t, literal=False, kind="str")
            if func.id in {"list", "tuple", "set", "dict", "frozenset"}:
                t = self._arg_taint(call, state, frame, ev)
                return Value(taint=t, literal=False, kind="list")
            if func.id in {"bool", "float", "len", "abs", "round", "sum", "min", "max"}:
                return Value(taint=self._arg_taint(call, state, frame, ev),
                             literal=False)
            if func.id == "isinstance":
                return Value(literal=True, kind="other", const_value=None)
        if isinstance(func, ast.Attribute):
            recv = ev.eval(func.value, state, frame)
            name = func.attr
            if name == "format":
                t = recv.taint
                for a in call.args:
                    t = Taint.merge(t, ev.eval(a, state, frame).taint)
                for kw in call.keywords:
                    t = Taint.merge(t, ev.eval(kw.value, state, frame).taint)
                if t is not None and t.is_tainted():
                    t = t.with_step("str.format")
                return Value(taint=t, literal=False, kind="str")
            if name == "join":
                t = recv.taint
                if call.args:
                    arg = ev.eval(call.args[0], state, frame)
                    t = Taint.merge(t, arg.taint)
                    for e in arg.elems:
                        t = Taint.merge(t, e.taint)
                return Value(taint=t, literal=False, kind="str")
            if name in _STR_PASSTHROUGH:
                t = recv.taint
                for a in call.args:
                    t = Taint.merge(t, ev.eval(a, state, frame).taint)
                return Value(taint=t, literal=False,
                             kind="str" if recv.kind == "str" else recv.kind)
            if name in _STR_ELEM_METHODS:
                t = recv.taint
                for a in call.args:
                    t = Taint.merge(t, ev.eval(a, state, frame).taint)
                return Value(taint=t, literal=False, kind="list",
                             elems=(Value(taint=t, literal=False, kind="str"),))
            if name in {"get", "copy", "setdefault"}:
                t = recv.taint
                for a in call.args:
                    t = Taint.merge(t, ev.eval(a, state, frame).taint)
                return Value(taint=t, literal=False)
            if name in {"append", "extend", "insert", "update", "add", "pop",
                        "clear", "remove", "discard", "sort", "reverse"}:
                # 原地修改：返回 None，污点通过容器槽位已在赋值/下标处理覆盖
                return Value(literal=False)
            if name in {"encode", "decode"}:
                return Value(taint=recv.taint, literal=False)
            # 未知方法：接收者或参数带污点时保守传播（未登记为 sanitizer 的
            # 函数不能享受「净化」待遇），否则改为纯常量返回
            t = recv.taint
            for a in call.args:
                t = Taint.merge(t, ev.eval(a, state, frame).taint)
            for kw in call.keywords:
                t = Taint.merge(t, ev.eval(kw.value, state, frame).taint)
            return Value(taint=t, literal=False)
        return None

    def _arg_taint(self, call: ast.Call, state: State, frame: Frame,
                   ev: Evaluator) -> Optional[Taint]:
        t = None
        for a in call.args:
            t = Taint.merge(t, ev.eval(a, state, frame).taint)
        for kw in call.keywords:
            t = Taint.merge(t, ev.eval(kw.value, state, frame).taint)
        return t

    # ---- 上报 -------------------------------------------------------------

    def _emit(self, state, frame: Frame, line: int, variant: str,
              sink_text: str, taint: Taint, call: ast.Call,
              override_file: Optional[str] = None) -> None:
        # 只有 marker 污点说明该 sink 位于被调函数内部、真实输入尚未经调用点流入：
        # 不报在实现行（label 口径明确排除 lib/ 包装实现行），改由摘要实例化在
        # 调用点行号上报。
        if all(s.startswith(MARKER_PREFIX) for s in taint.sources):
            return
        rel = override_file or frame.unit.module.rel_path
        sources = tuple(dict.fromkeys(
            s for s in taint.sources if not s.startswith(MARKER_PREFIX)))
        if not sources:
            sources = taint.sources
        msg = self._message(variant, sources, taint.path)
        self.findings.append(Finding(
            file=rel, line=line, rule="command_injection", variant=variant,
            sources=sources, path=taint.path, sink_call=sink_text, message=msg))

    @staticmethod
    def _message(variant: str, sources: tuple[str, ...], path: tuple[str, ...]) -> str:
        chain = " -> ".join(dict.fromkeys(path)) if path else "直连"
        return (f"[command_injection/{variant}] 污点源 {', '.join(sources)} "
                f"经 {chain} 到达命令执行点")

    # ---- 状态回写钩子 -----------------------------------------------------

    def _frame_state_holder(self, frame: Frame):
        return getattr(frame, "_state_holder", None)


class FunctionAnalyzer:
    """单函数：CFG 构建 + worklist 不动点 + 摘要抽取。"""

    def __init__(self, inter: InterAnalyzer):
        self.inter = inter
        self.repo = inter.repo
        self.config = inter.config
        self.last_states: dict[int, State] = {}

    @staticmethod
    def param_names(unit: FunctionUnit) -> tuple[str, ...]:
        a = unit.node.args
        names = [p.arg for p in a.posonlyargs + a.args]
        if a.vararg:
            names.append(a.vararg.arg)
        if a.kwarg:
            names.append(a.kwarg.arg)
        names += [p.arg for p in a.kwonlyargs]
        return tuple(names)

    # -- 模块级 body --------------------------------------------------------

    def analyze_module(self, unit: FunctionUnit) -> tuple[State, FunctionSummary]:
        cfg = CFGBuilder().build(unit.node)
        frame = Frame(unit=unit)
        holder = [State()]
        frame._state_holder = holder  # type: ignore[attr-defined]
        states = self._fixpoint(unit, cfg, frame, holder[0], seeding="module")
        final = State()
        for st in states.values():
            final = State.merge(final, st)
        # 只保留全局槽作为模块对外状态
        global_only = State()
        for key, taint in final.slots.items():
            if key.startswith("G:"):
                global_only = global_only.put(key, taint)
        summary = FunctionSummary(qualname=unit.qualname, params=(), analyzed=True)
        return global_only, summary

    # -- 普通函数 -----------------------------------------------------------

    def analyze(self, unit: FunctionUnit, module_state: State) -> FunctionSummary:
        cfg = CFGBuilder().build(unit.node)
        frame = self._build_frame(unit, cfg)
        seed = self._seed(unit, frame, module_state, cfg)
        holder = [seed]
        frame._state_holder = holder  # type: ignore[attr-defined]
        states = self._fixpoint(unit, cfg, frame, seed, seeding="function")
        summary = self._summarize(unit, cfg, frame, states)
        return summary

    def _build_frame(self, unit: FunctionUnit, cfg: CFG) -> Frame:
        frame = Frame(unit=unit)
        args = unit.node.args
        all_args = args.posonlyargs + args.args + args.kwonlyargs
        if unit.class_name and all_args and all_args[0].arg == "self":
            frame.self_name = "self"
        for p in all_args:
            frame.param_slots[p.arg] = local(p.arg)
        if args.vararg:
            frame.param_slots[args.vararg.arg] = local(args.vararg.arg)
        if args.kwarg:
            frame.param_slots[args.kwarg.arg] = local(args.kwarg.arg)
        for refs in cfg.closure_refs.values():
            frame.closure_names.update(refs)
        # 嵌套函数自身引用的外层变量：CFG 的 free-var 分析结果直接作为本帧闭包名
        if unit.parent_qual is not None:
            own_free = cfg.closure_refs.get(unit.node.name, set())
            frame.closure_names.update(own_free)
        return frame

    def _seed(self, unit: FunctionUnit, frame: Frame, module_state: State,
              cfg: CFG) -> State:
        # 模块全局槽通过同一套 L:/S:/G: 槽位继承；函数内对全局名的读写都落在 G: 槽
        state = State()
        for key, taint in module_state.slots.items():
            state = state.put(key, taint)
        for name, slot in frame.param_slots.items():
            if name == frame.self_name:
                continue
            if unit.is_celery_task:
                t = Taint(sources=(f"{TAINT_SRC_CELERY}.{name}",),
                          path=(f"celery 任务参数 {name}",))
            else:
                t = Taint(sources=(marker(unit.qualname, name),),
                          path=(f"形参 {name}",))
            state = state.put(slot, t)
        # 嵌套函数引用的外层变量：预置闭包 marker，摘要里以 closure: 掩码出现
        for cname in frame.closure_names:
            state = state.put(closure(cname),
                              Taint(sources=(marker(unit.qualname, "closure:" + cname),),
                                    path=(f"闭包捕获 {cname}",)))
        # 方法内 self.<attr> 预置实例属性 marker：使 self.cmd 进 sink 的传播能在
        # 摘要里留下掩码，调用点（构造器 self 写）再实例化真实污点
        if frame.self_name:
            existing = {k[2:] for k, _ in state.slots.items() if k.startswith("S:")}
            for attr in self._self_attrs_used(unit.node, frame.self_name) - existing:
                state = state.put(
                    self_attr(attr),
                    Taint(sources=(marker(unit.qualname, "self:" + attr),),
                          path=(f"实例属性 self.{attr}",)))
        return state

    @staticmethod
    def _self_attrs_used(node: ast.AST, self_name: str) -> set[str]:
        out: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                    and sub.value.id == self_name:
                out.add(sub.attr)
        return out

    def _fixpoint(self, unit: FunctionUnit, cfg: CFG, frame: Frame,
                  initial: State, seeding: str) -> dict[int, State]:
        states: dict[int, State] = {cfg.entry: initial}
        # 广度优先的 FIFO 队列：pop(0) 保证块按 CFG 拓扑序处理，避免后继块
        # 在前驱完成前被空状态调度（虽会再次收敛，但会漏掉仅在完整状态下
        # 才能触发的 sink 上报）
        work = [cfg.entry]
        guard = 0
        while work:
            guard += 1
            if guard > self.inter.max_iterations * max(1, len(cfg.blocks)):
                self.inter.truncated.append(
                    f"{unit.qualname}: CFG 不动点迭代上限截断")
                break
            bid = work.pop(0)
            block = cfg.blocks[bid]
            state = states[bid]
            holder = frame._state_holder  # type: ignore[attr-defined]
            holder[0] = state
            ev = Evaluator(self.repo, self.config, self.inter, unit.module)
            for stmt in block.stmts:
                state = self._exec(stmt, state, frame, ev, unit, cfg, block)
                holder[0] = state
            if block.kind == "header" and block.stmts and isinstance(block.stmts[0], ast.For):
                state = self._bind_for(block.stmts[0], state, frame, ev)
                holder[0] = state
            for succ in block.succ:
                old = states.get(succ)
                merged = state if old is None else State.merge(old, state)
                if old is None or not _state_equal(old, merged):
                    states[succ] = merged
                    if succ not in work:
                        work.append(succ)
        self.last_states = states
        return states

    # -- 语句语义 -----------------------------------------------------------

    def _absorb(self, val: Value, state: State) -> State:
        if getattr(val, "state_after", None) is not None:
            return State.merge(state, val.state_after)
        return state

    def _exec(self, stmt: ast.stmt, state: State, frame: Frame, ev: Evaluator,
              unit: FunctionUnit, cfg: CFG, block) -> State:
        if isinstance(stmt, ast.Assign):
            val = ev.eval(stmt.value, state, frame)
            state = self._absorb(val, state)
            for target in stmt.targets:
                state = self._store(target, val, state, frame, ev)
            return state
        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                val = ev.eval(stmt.value, state, frame)
                state = self._absorb(val, state)
                state = self._store(stmt.target, val, state, frame, ev)
            return state
        if isinstance(stmt, ast.AugAssign):
            before = ev.eval(stmt.target, state, frame)
            rhs = ev.eval(stmt.value, state, frame)
            t = Taint.merge(before.taint, rhs.taint)
            if t is not None and t.is_tainted():
                t = t.with_step("拼接赋值")
            state = self._store(stmt.target,
                                Value(taint=t, literal=False, kind="str"),
                                state, frame, ev)
            return state
        if isinstance(stmt, ast.Expr):
            val = ev.eval(stmt.value, state, frame)
            state = self._absorb(val, state)
            return state
        if isinstance(stmt, (ast.If, ast.While)):
            ev.eval(stmt.test, state, frame)
            return state
        if isinstance(stmt, ast.For):
            ev.eval(stmt.iter, state, frame)
            return state
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # 嵌套函数：惰性分析；此处仅保证闭包槽存在
            for cname in cfg.closure_refs.get(stmt.name, set()):
                if state.get(closure(cname)) is None:
                    state = state.put(
                        closure(cname),
                        Taint(sources=(marker(unit.qualname, "closure:" + cname),),
                              path=(f"闭包捕获 {cname}",)))
            return state
        if isinstance(stmt, ast.ClassDef):
            return state
        if isinstance(stmt, ast.Return):
            # 返回表达式必须在 fixpoint 内求值：调用本身（如 shellwrap.run(cmd)）
            # 携带 sink，跳过求值会漏掉 return 语句上的执行调用行
            if stmt.value is not None:
                val = ev.eval(stmt.value, state, frame)
                state = self._absorb(val, state)
            return state
        if isinstance(stmt, ast.ExceptHandler):
            if stmt.name:
                slot = frame.resolve_name(stmt.name) or local(stmt.name)
                state = state.put(slot, Taint(
                    sources=(f"{TAINT_SRC_EXCEPT}.{stmt.name}",),
                    path=("异常绑定",)))
            return state
        if isinstance(stmt, ast.With):
            for item in stmt.items:
                ev.eval(item.context_expr, state, frame)
            return state
        if isinstance(stmt, ast.Assert):
            ev.eval(stmt.test, state, frame)
            return state
        if isinstance(stmt, ast.Raise):
            if stmt.exc is not None:
                ev.eval(stmt.exc, state, frame)
            return state
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass, ast.Global,
                              ast.Nonlocal, ast.Delete, ast.Try)):
            return state
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call):
                ev.eval(sub, state, frame)
        return state

    def _bind_for(self, stmt: ast.For, state: State, frame: Frame,
                  ev: Evaluator) -> State:
        iter_val = ev.eval(stmt.iter, state, frame)
        taint = iter_val.taint
        for e in iter_val.elems:
            taint = Taint.merge(taint, e.taint)
        return self._store(stmt.target, Value(taint=taint, literal=False),
                           state, frame, ev)

    def _store(self, target: ast.AST, val: Value, state: State,
               frame: Frame, ev: Evaluator) -> State:
        if isinstance(target, ast.Name):
            if frame.unit.is_module_entry:
                state = state.put(global_slot(target.id), val.taint)
            elif frame.nested_qual and target.id in frame.closure_names:
                state = state.put(closure(target.id), val.taint)
            else:
                slot = frame.resolve_name(target.id) or local(target.id)
                state = state.put(slot, val.taint)
            # 记录对象类型，供 x.method() 解析
            if isinstance(val.const_value, tuple) \
                    and val.const_value and val.const_value[0] == "instance":
                state = state.put_type(target.id, val.const_value[1])
            return state
        if isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name) and target.value.id == frame.self_name:
                return state.put(self_attr(target.attr), val.taint)
            return state
        if isinstance(target, (ast.Tuple, ast.List)):
            for i, elt in enumerate(target.elts):
                elem = val.elems[i] if i < len(val.elems) else Value(
                    taint=val.taint, literal=False)
                state = self._store(elt, elem, state, frame, ev)
            return state
        if isinstance(target, ast.Starred):
            return self._store(target.value, val, state, frame, ev)
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            slot = frame.resolve_name(target.value.id)
            if slot:
                return state.put(slot, Taint.merge(state.get(slot), val.taint))
        return state

    # -- 摘要 ---------------------------------------------------------------

    def _summarize(self, unit: FunctionUnit, cfg: CFG, frame: Frame,
                   states: dict[int, State]) -> FunctionSummary:
        summary = FunctionSummary(
            qualname=unit.qualname, params=self.param_names(unit),
            is_celery_task=unit.is_celery_task, analyzed=True)
        final = State()
        for st in states.values():
            final = State.merge(final, st)
        # 返回值掩码：重新扫描 return 节点（用最终态近似，may 分析下只会更保守）
        for ret in [n for n in ast.walk(unit.node) if isinstance(n, ast.Return) and n.value]:
            ev = Evaluator(self.repo, self.config, self.inter, unit.module)
            val = ev.eval(ret.value, final, frame)
            if val.taint is not None:
                for src in val.taint.sources:
                    if src.startswith(MARKER_PREFIX):
                        if src not in summary.ret_masks:
                            summary.ret_masks += (src,)
                    elif src not in summary.ret_extra_sources:
                        summary.ret_extra_sources += (src,)
                summary.ret_sanitized = summary.ret_sanitized or val.taint.sanitized
        # sink 记录在分析过程中已写入 inter.findings（带真实行号）；摘要需要
        # 掩码形式供跨过程实例化，故从本函数 findings 反推不可行——改为扫描
        # 本单元 CFG 内调用点并以 marker 态重新判定。
        summary.sinks = self._collect_sink_masks(unit, cfg, frame, final)
        # self / global 写掩码
        for key, taint in final.slots.items():
            masks = tuple(s for s in taint.sources if s.startswith(MARKER_PREFIX))
            if not masks:
                continue
            if key.startswith("S:"):
                attr = key[2:]
                # self:<attr> 是方法自身的实例探针，不参与跨调用掩码；只保留
                # 真正由形参/闭包流入该属性的掩码
                masks = tuple(m for m in masks if "#self:" not in m)
                if not masks:
                    continue
                summary.self_writes[attr] = tuple(dict.fromkeys(
                    summary.self_writes.get(attr, ()) + masks))
                summary.self_write_sanitized[attr] = taint.sanitized
            elif key.startswith("G:"):
                gname = key[2:]
                summary.global_writes[gname] = tuple(dict.fromkeys(
                    summary.global_writes.get(gname, ()) + masks))
        return summary

    def _collect_sink_masks(self, unit: FunctionUnit, cfg: CFG, frame: Frame,
                            final: State) -> list[SinkRecord]:
        """用最终 may-态重新过一遍 sink 调用，抽取 marker 掩码。"""
        records: list[SinkRecord] = []
        ev = Evaluator(self.repo, self.config, self.inter, unit.module)
        for node in ast.walk(unit.node):
            if not isinstance(node, ast.Call):
                continue
            variant, taint = self._classify_sink(node, final, frame, ev)
            if variant is None or taint is None:
                continue
            masks = tuple(s for s in taint.sources if s.startswith(MARKER_PREFIX))
            extra = any(not s.startswith(MARKER_PREFIX) for s in taint.sources)
            if not masks and not extra:
                continue
            records.append(SinkRecord(
                line=node.lineno, variant=variant, arg_masks=masks,
                extra_source=extra, sink_text=_call_text(node)))
        return records

    def _classify_sink(self, node: ast.Call, state: State, frame: Frame,
                       ev: Evaluator) -> tuple[Optional[str], Optional[Taint]]:
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "subprocess" \
                    and func.attr in SUBPROCESS_FUNCS:
                shell_true = InterAnalyzer._kw_bool(node, "shell") is True
                args = [ev.eval(a, state, frame) for a in node.args]
                if shell_true and args and args[0].is_tainted():
                    return "concat_shell", args[0].taint
                if args and args[0].kind == "list":
                    argv = args[0]
                    idx = InterAnalyzer._shell_c_index(argv)
                    if idx is not None and idx + 2 < len(argv.elems) \
                            and argv.elems[idx + 2].is_tainted():
                        return "arglist_misuse", argv.elems[idx + 2].taint
                    if argv.elems and argv.elems[0].is_tainted():
                        return "arglist_misuse", argv.elems[0].taint
                return None, None
            if isinstance(func.value, ast.Name) and func.value.id == "os" \
                    and func.attr in OS_SHELL_FUNCS and node.args:
                v = ev.eval(node.args[0], state, frame)
                if v.is_tainted():
                    return "concat_shell", v.taint
                return None, None
        # 配置化包装的掩码记录
        resolved = self.inter._resolve(frame.unit.module, func, state, frame)
        hit = self.config.classify_wrapper(resolved.fqname or "", resolved.short)
        if hit == "shell":
            t = None
            for a in node.args:
                t = Taint.merge(t, ev.eval(a, state, frame).taint)
            for kw in node.keywords:
                t = Taint.merge(t, ev.eval(kw.value, state, frame).taint)
            if t is not None and t.is_tainted():
                return "shell_wrapper", t
        if hit == "template":
            t = None
            for a in node.args:
                t = Taint.merge(t, ev.eval(a, state, frame).taint)
            for kw in node.keywords:
                t = Taint.merge(t, ev.eval(kw.value, state, frame).taint)
            if t is not None and t.is_tainted():
                # 渲染器本身不是 sink；记录由后续 shell 调用承接
                return None, None
        return None, None


def _call_text(node: ast.Call) -> str:
    try:
        return ast.unparse(node.func)
    except Exception:
        return "<call>"


def _state_equal(a: State, b: State) -> bool:
    ka = {k for k, _ in a.slots.items()}
    kb = {k for k, _ in b.slots.items()}
    if ka != kb:
        return False
    for k in ka:
        ta, tb = a.slots.get(k), b.slots.get(k)
        if ta is None or tb is None:
            if ta is not tb:
                return False
            continue
        if ta.sources != tb.sources or ta.sanitized != tb.sanitized:
            return False
    ta_keys = {k for k, _ in a.types.items()}
    tb_keys = {k for k, _ in b.types.items()}
    if ta_keys != tb_keys:
        return False
    for k in ta_keys:
        if a.get_type(k) != b.get_type(k):
            return False
    return True
