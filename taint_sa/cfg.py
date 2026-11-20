"""自建控制流图（仅依赖 ``ast``）。

粒度选择：**基本块 = 直线语句序列**，块间用显式边连接分支/循环/异常。
语句级而不是 SSA/三地址码，是因为污点状态在 :class:`~taint_sa.model.State`
里按槽位维护，直线序列逐条求值即可，过度降低粒度只会拖慢 20 万行全量扫描。

支持的控制结构
==============
- ``if/elif/else``：条件块 -> (true 块, false 块)，两支在合流点 may-merge
- ``while``：带循环回边，状态迭代到不动点
- ``for``：迭代对象的元素污点灌进循环变量；break/continue 用专用边汇总
- ``try/except/else/finally``：try 体每条语句后都可能跳到 handler（保守做法，
  牺牲一点精度换实现简单与可终止性）
- ``with``、``raise``、``return``：终结边
- 嵌套函数：作为**词法作用域单元**整体登记，不在父函数 CFG 里内联展开；
  它通过闭包槽位（``C:`` 前缀）与外层交换污点。
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class Block:
    bid: int
    stmts: list[ast.stmt] = field(default_factory=list)
    succ: list[int] = field(default_factory=list)          # 普通后继
    true_succ: int | None = None
    false_succ: int | None = None
    # 循环专用
    loop_header: bool = False
    loop_exit: int | None = None
    kind: str = "plain"                                    # plain/header/exit/handler/finally


@dataclass
class CFG:
    entry: int
    blocks: dict[int, Block]
    # 函数内嵌套定义的函数（名字 -> 节点），闭包分析用
    nested_funcs: dict[str, ast.FunctionDef] = field(default_factory=dict)
    # 嵌套函数中引用的外层变量（ast 静态分析得出）
    closure_refs: dict[str, set[str]] = field(default_factory=dict)
    # 参数节点
    args: ast.arguments | None = None
    is_async: bool = False


class CFGBuilder:
    def __init__(self) -> None:
        self._seq = 0

    def _new_block(self, kind: str = "plain") -> Block:
        bid = self._seq
        self._seq += 1
        return Block(bid=bid, kind=kind)

    def build(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> CFG:
        cfg = CFG(entry=-1, blocks={}, args=func.args,
                  is_async=isinstance(func, ast.AsyncFunctionDef))
        self._collect_nested(func, cfg)
        # 顶层函数自身也可能是嵌套单元：直接计算它的自由变量（闭包捕获）
        own_free = self._free_vars(func)
        if own_free:
            cfg.closure_refs[func.name] = own_free
        entry = self._new_block()
        cfg.entry = entry.bid
        cfg.blocks[entry.bid] = entry
        tail = self._emit_body(func.body, entry, cfg, break_to=None, continue_to=None)
        exit_block = self._new_block(kind="exit")
        cfg.blocks[exit_block.bid] = exit_block
        for bid in tail:
            cfg.blocks[bid].succ.append(exit_block.bid)
        return cfg

    # -- 嵌套函数登记 --------------------------------------------------------

    def _collect_nested(self, func: ast.AST, cfg: CFG) -> None:
        for node in ast.walk(func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not func:
                cfg.nested_funcs[node.name] = node
                cfg.closure_refs[node.name] = self._free_vars(node)

    # 模块级导入名/内建不算闭包捕获：它们走 import 解析与全局槽，不是外层局部变量
    _NON_LOCAL_NAMES = {
        "os", "sys", "subprocess", "ast", "json", "re", "shlex", "logging",
        "functools", "hashlib", "math", "dataclass", "self", "cls", "print",
        "len", "str", "int", "dict", "list", "tuple", "set", "range", "enumerate",
        "isinstance", "getattr", "setattr", "hasattr", "open", "super", "Exception",
        "ValueError", "RuntimeError", "True", "False", "None",
    }

    def _free_vars(self, node: ast.AST) -> set[str]:
        """嵌套函数引用但未在本地绑定的名字（真正的外层局部变量才是闭包）。"""
        assigned: set[str] = set()
        loaded: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                    and sub is not node:
                assigned.add(sub.name)
            elif isinstance(sub, ast.Name):
                if isinstance(sub.ctx, ast.Store):
                    assigned.add(sub.id)
                else:
                    loaded.add(sub.id)
            elif isinstance(sub, ast.arg):
                assigned.add(sub.arg)
            elif isinstance(sub, ast.ExceptHandler) and sub.name:
                assigned.add(sub.name)
        free = loaded - assigned
        return {name for name in free if name not in self._NON_LOCAL_NAMES}

    # -- body 发射：返回「活着的」块 id 列表（可能因为分支而有多个） ----------

    def _emit_body(self, body: list[ast.stmt], start: Block, cfg: CFG,
                   break_to: int | None, continue_to: int | None) -> list[int]:
        fronts = [start.bid]
        for stmt in body:
            next_fronts: list[int] = []
            for bid in fronts:
                next_fronts.extend(
                    self._emit_stmt(stmt, cfg.blocks[bid], cfg, break_to, continue_to))
            fronts = list(dict.fromkeys(next_fronts))
        return fronts

    def _emit_stmt(self, stmt: ast.stmt, block: Block, cfg: CFG,
                   break_to: int | None, continue_to: int | None) -> list[int]:
        # 终结语句：块到此为止
        if isinstance(stmt, ast.Return):
            block.stmts.append(stmt)
            term = self._new_block(kind="exit")
            cfg.blocks[term.bid] = term
            block.succ.append(term.bid)
            return []
        if isinstance(stmt, (ast.Break, ast.Continue)):
            block.stmts.append(stmt)
            target = break_to if isinstance(stmt, ast.Break) else continue_to
            if target is not None:
                block.succ.append(target)
            return []
        if isinstance(stmt, ast.Raise):
            block.stmts.append(stmt)
            return []
        if isinstance(stmt, ast.If):
            return self._emit_if(stmt, block, cfg, break_to, continue_to)
        if isinstance(stmt, ast.While):
            return self._emit_while(stmt, block, cfg, break_to, continue_to)
        if isinstance(stmt, ast.For):
            return self._emit_for(stmt, block, cfg, break_to, continue_to)
        if isinstance(stmt, ast.Try):
            return self._emit_try(stmt, block, cfg, break_to, continue_to)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # 词法单元登记即可；定义语句本身保留，分析阶段处理装饰器/默认值
            block.stmts.append(stmt)
            return [block.bid]
        # 普通直线语句
        block.stmts.append(stmt)
        return [block.bid]

    def _fresh_chain(self, cfg: CFG, body: list[ast.stmt],
                     break_to: int | None, continue_to: int | None) -> tuple[int, list[int]]:
        head = self._new_block()
        cfg.blocks[head.bid] = head
        tails = self._emit_body(body, head, cfg, break_to, continue_to)
        return head.bid, tails

    def _emit_if(self, stmt: ast.If, block: Block, cfg: CFG,
                 break_to: int | None, continue_to: int | None) -> list[int]:
        block.stmts.append(stmt)  # 条件表达式随节点保留，分析阶段求值
        true_head, true_tails = self._fresh_chain(cfg, stmt.body, break_to, continue_to)
        block.true_succ = true_head
        block.succ.append(true_head)
        if stmt.orelse:
            false_head, false_tails = self._fresh_chain(cfg, stmt.orelse,
                                                        break_to, continue_to)
        else:
            false_block = self._new_block()
            cfg.blocks[false_block.bid] = false_block
            false_head = false_block.bid
            false_tails = [false_head]
        block.false_succ = false_head
        block.succ.append(false_head)
        merge = self._new_block()
        cfg.blocks[merge.bid] = merge
        for bid in true_tails + false_tails:
            cfg.blocks[bid].succ.append(merge.bid)
        return [merge.bid]

    def _emit_while(self, stmt: ast.While, block: Block, cfg: CFG,
                    break_to: int | None, continue_to: int | None) -> list[int]:
        header = self._new_block(kind="header")
        header.loop_header = True
        cfg.blocks[header.bid] = header
        header.stmts.append(stmt)
        block.succ.append(header.bid)
        exit_block = self._new_block(kind="exit")
        cfg.blocks[exit_block.bid] = exit_block
        header.loop_exit = exit_block.bid
        header.false_succ = exit_block.bid
        header.succ.append(exit_block.bid)
        body_head, body_tails = self._fresh_chain(cfg, stmt.body,
                                                  break_to=exit_block.bid,
                                                  continue_to=header.bid)
        header.true_succ = body_head
        header.succ.append(body_head)
        for bid in body_tails:
            cfg.blocks[bid].succ.append(header.bid)  # 回边
        if stmt.orelse:  # while-else：正常退出（非 break）走 else
            else_head, else_tails = self._fresh_chain(cfg, stmt.orelse,
                                                      break_to, continue_to)
            cfg.blocks[exit_block.bid].succ.append(else_head.bid)
            return else_tails
        return [exit_block.bid]

    def _emit_for(self, stmt: ast.For, block: Block, cfg: CFG,
                  break_to: int | None, continue_to: int | None) -> list[int]:
        # for 节点挂在 header 上，迭代对象的求值在分析阶段做
        header = self._new_block(kind="header")
        header.loop_header = True
        header.stmts.append(stmt)
        cfg.blocks[header.bid] = header
        exit_block = self._new_block(kind="exit")
        cfg.blocks[exit_block.bid] = exit_block
        header.loop_exit = exit_block.bid
        header.succ.append(exit_block.bid)
        body_head, body_tails = self._fresh_chain(cfg, stmt.body,
                                                  break_to=exit_block.bid,
                                                  continue_to=header.bid)
        header.true_succ = body_head
        header.succ.append(body_head)
        for bid in body_tails:
            cfg.blocks[bid].succ.append(header.bid)
        if stmt.orelse:
            else_head, else_tails = self._fresh_chain(cfg, stmt.orelse,
                                                      break_to, continue_to)
            cfg.blocks[exit_block.bid].succ.append(else_head.bid)
            return else_tails
        return [exit_block.bid]

    def _emit_try(self, stmt: ast.Try, block: Block, cfg: CFG,
                  break_to: int | None, continue_to: int | None) -> list[int]:
        block.stmts.append(stmt)
        # try 体：每条语句的块都额外连向所有 handler（异常可能在任意点抛出）
        try_head = self._new_block()
        cfg.blocks[try_head.bid] = try_head
        block.succ.append(try_head.bid)
        fronts = [try_head.bid]
        handler_heads: list[int] = []
        handlers = list(stmt.handlers)
        for sub in stmt.body:
            new_fronts: list[int] = []
            for bid in fronts:
                tails = self._emit_stmt(sub, cfg.blocks[bid], cfg,
                                        break_to, continue_to)
                for t in tails:
                    for h in handlers:
                        hb = self._handler_chain(h, cfg, break_to, continue_to)
                        cfg.blocks[t].succ.append(hb)
                        handler_heads.append(hb)
                new_fronts.extend(tails)
            fronts = list(dict.fromkeys(new_fronts))
        handler_tails: list[int] = []
        for hb in dict.fromkeys(handler_heads):
            handler_tails.extend(self._chain_tails(hb, cfg))
        # else 仅在 try 无异常时执行
        else_tails: list[int] = []
        if stmt.orelse:
            else_head, else_tails = self._fresh_chain(cfg, stmt.orelse,
                                                      break_to, continue_to)
            for bid in fronts:
                cfg.blocks[bid].succ.append(else_head.bid)
        else:
            else_tails = fronts
        merge = self._new_block()
        cfg.blocks[merge.bid] = merge
        for bid in else_tails + handler_tails:
            cfg.blocks[bid].succ.append(merge.bid)
        # finally：合流后再走一遍，异常路径同样汇入（语料无 finally，保守连通）
        if stmt.finalbody:
            fin_head, fin_tails = self._fresh_chain(cfg, stmt.finalbody,
                                                    break_to, continue_to)
            cfg.blocks[merge.bid].succ.append(fin_head.bid)
            return fin_tails
        return [merge.bid]

    def _handler_chain(self, handler: ast.ExceptHandler, cfg: CFG,
                       break_to: int | None, continue_to: int | None) -> int:
        head = self._new_block(kind="handler")
        cfg.blocks[head.bid] = head
        head.stmts.append(handler)  # 分析阶段把 handler.name 绑定为不可信外部值
        tails = self._emit_body(handler.body, head, cfg, break_to, continue_to)
        for bid in tails:
            cfg.blocks[bid].kind = cfg.blocks[bid].kind
        return head.bid

    def _chain_tails(self, head_bid: int, cfg: CFG) -> list[int]:
        """从一个链头找到所有没有普通后继的块。"""
        seen: set[int] = set()
        tails: list[int] = []
        stack = [head_bid]
        while stack:
            bid = stack.pop()
            if bid in seen:
                continue
            seen.add(bid)
            block = cfg.blocks[bid]
            if not block.succ:
                tails.append(bid)
            else:
                stack.extend(block.succ)
        return tails
