"""import 解析与模块仓库。

仓库布局是「源码根目录即 sys.path 根」的扁平包结构（``lib/``、``services/``、
``filler/`` 都在根下），所以模块的全限定名就是相对仓库根的点分路径，例如
``services/gateway/diag.py`` -> ``services.gateway.diag``。

本模块只做**静态**名字解析，绝不 import 目标代码（flask/celery 未安装也能跑）。
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field

SCAN_ROOTS = ("services", "lib", "filler")
SKIP_DIRS = {"__pycache__", ".git", "baseline", "tools", "tests", ".ci", "taint_sa"}
PY_EXT = ".py"


def module_name_of(rel_path: str) -> str:
    rel = rel_path.replace("\\", "/")
    if rel.endswith(PY_EXT):
        rel = rel[: -len(PY_EXT)]
    parts = rel.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


@dataclass
class ImportBinding:
    """一个本地名字 -> 全限定目标 的绑定。"""

    local_name: str
    fq_target: str           # 模块名 或 模块.属性
    kind: str                # "module" | "name"
    dotted_alias: bool = False  # ``import a.b.c`` 后本地名是 a，需要保留 a.b.c 链


@dataclass
class ModuleInfo:
    rel_path: str
    fqname: str
    tree: ast.AST
    source: str
    imports: dict[str, ImportBinding] = field(default_factory=dict)
    # 本模块定义的顶层函数/类名
    top_defs: set[str] = field(default_factory=set)
    parse_error: str | None = None


class ModuleRepo:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.modules: dict[str, ModuleInfo] = {}          # fqname -> info
        self.path_index: dict[str, ModuleInfo] = {}       # rel path -> info
        self._all_fqnames: set[str] = set()

    # -- 装载 ---------------------------------------------------------------

    def load(self) -> None:
        roots = [r for r in SCAN_ROOTS if os.path.isdir(os.path.join(self.root, r))]
        # 测试/独立语料场景：仓库根下没有标准目录时，直接扫描根目录
        if not roots:
            roots = ["."]
        for scan_root in roots:
            base = os.path.join(self.root, scan_root)
            if not os.path.isdir(base):
                continue
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
                for name in sorted(filenames):
                    if not name.endswith(PY_EXT):
                        continue
                    abs_path = os.path.join(dirpath, name)
                    rel = os.path.relpath(abs_path, self.root).replace("\\", "/")
                    self._load_one(rel, abs_path)
        self._all_fqnames = set(self.modules)

    def _load_one(self, rel: str, abs_path: str) -> None:
        fqname = module_name_of(rel)
        with open(abs_path, "rb") as fh:
            source = fh.read().decode("utf-8-sig", errors="replace")
        try:
            tree = ast.parse(source, filename=rel)
            err = None
        except SyntaxError as exc:  # 语料里有坏文件也不能让整仓扫描挂掉
            tree = ast.Module(body=[], type_ignores=[])
            err = f"{type(exc).__name__}: {exc.msg}"
        info = ModuleInfo(rel_path=rel, fqname=fqname, tree=tree,
                          source=source, parse_error=err)
        if err is None:
            self._collect_imports(info, tree)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    info.top_defs.add(node.name)
        self.modules[fqname] = info
        self.path_index[rel] = info

    def _collect_imports(self, info: ModuleInfo, tree: ast.Module) -> None:
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    info.imports[local] = ImportBinding(
                        local_name=local, fq_target=alias.name,
                        kind="module", dotted_alias=alias.asname is None and "." in alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                # 相对导入在本语料里不存在；出现时按无信息处理
                if node.level:
                    continue
                for alias in node.names:
                    local = alias.asname or alias.name
                    if alias.name == "*":
                        continue
                    info.imports[local] = ImportBinding(
                        local_name=local,
                        fq_target=f"{module}.{alias.name}" if module else alias.name,
                        kind="name")

    # -- 名字解析 ------------------------------------------------------------

    def resolve(self, info: ModuleInfo, dotted: list[str]) -> tuple[str | None, str]:
        """把模块内的属性链根名解析成 (fqname, 短名)。

        返回 ``(fqname, short)``：``fqname`` 指向仓库内模块/函数时非空；
        ``short`` 始终给出配置白名单可用的点分短名（如 ``shlex.quote``、``int``）。
        """
        if not dotted:
            return None, ""
        root_name = dotted[0]
        rest = dotted[1:]
        binding = info.imports.get(root_name)
        if binding is None:
            # 内建/未导入名字（int、len ...）或本模块内定义
            if root_name in info.top_defs:
                return ".".join([info.fqname] + dotted), ".".join(dotted)
            return None, ".".join(dotted)
        if binding.kind == "name":
            # from a.b import c -> c 可能是子模块也可能是 a.b 里的属性
            target = binding.fq_target
            target_with_rest = ".".join([target] + rest)
            if target_with_rest in self._all_fqnames:
                return target_with_rest, ".".join(dotted)
            if target in self._all_fqnames and rest:
                # c 是模块，rest 是其内部属性
                return target_with_rest, ".".join(dotted)
            return target_with_rest, ".".join(dotted)
        # import a.b / import x as y
        base = binding.fq_target
        full = ".".join([base] + rest)
        return full, ".".join(dotted)

    def get_module(self, fqname: str) -> ModuleInfo | None:
        return self.modules.get(fqname)

    def relpaths(self) -> list[str]:
        return sorted(self.path_index)
