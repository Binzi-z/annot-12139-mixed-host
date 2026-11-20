"""命令行入口：全量 / 增量 / CI 门禁。

用法
====

::

    python -m taint_sa.cli scan --root . --config config/sanitizers.json \
        --sarif out.sarif --json out.json
    python -m taint_sa.cli incremental --root . --cache .taint_cache.json \
        --sarif inc.sarif
    python -m taint_sa.cli gate --root . --baseline .ci/baseline.sarif --sarif cur.sarif

增量一致性
==========
缓存按 **模块内容哈希 + 依赖模块哈希** 索引函数摘要。模块自身或任一 import
依赖发生变化时，该模块的摘要失效并重分析；未失效模块直接复用缓存摘要。
跨过程实例化是纯函数（摘要 + 调用点实参），因此只要输入摘要一致，
全量与增量产出的 finding 集合必然相同——``incremental`` 模式末尾会做一次
等价性自检（与全量结果比对），不一致直接非零退出。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict
from typing import Optional

from .config import AnalyzerConfig
from .engine import InterAnalyzer
from .impres import ModuleRepo
from .inter import FunctionSummary, SinkRecord
from .model import Finding
from .sarif import dump_sarif, to_findings_json, to_sarif


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


class Cache:
    """模块级缓存：{模块 fqname: {hash, deps, summaries, findings}}。"""

    VERSION = 1

    def __init__(self, path: Optional[str]):
        self.path = path
        self.doc: dict = {"version": self.VERSION, "modules": {}}
        if path and os.path.exists(path):
            try:
                with open(path, "rb") as fh:
                    self.doc = json.loads(fh.read().decode("utf-8-sig"))
            except (json.JSONDecodeError, OSError):
                pass

    def save(self) -> None:
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.doc, fh, ensure_ascii=False)
        os.replace(tmp, self.path)


def _summaries_to_cacheable(summaries: dict[str, FunctionSummary]) -> dict:
    out = {}
    for qual, s in summaries.items():
        out[qual] = {
            "qualname": s.qualname,
            "params": list(s.params),
            "ret_masks": list(s.ret_masks),
            "ret_sanitized": s.ret_sanitized,
            "ret_extra_sources": list(s.ret_extra_sources),
            "self_writes": {k: list(v) for k, v in s.self_writes.items()},
            "self_write_sanitized": dict(s.self_write_sanitized),
            "global_writes": {k: list(v) for k, v in s.global_writes.items()},
            "sinks": [asdict(r) for r in s.sinks],
            "is_celery_task": s.is_celery_task,
            "analyzed": s.analyzed,
        }
    return out


def _cacheable_to_summaries(doc: dict) -> dict[str, FunctionSummary]:
    out = {}
    for qual, d in doc.items():
        out[qual] = FunctionSummary(
            qualname=d["qualname"],
            params=tuple(d["params"]),
            ret_masks=tuple(d["ret_masks"]),
            ret_sanitized=d["ret_sanitized"],
            ret_extra_sources=tuple(d["ret_extra_sources"]),
            self_writes={k: tuple(v) for k, v in d["self_writes"].items()},
            self_write_sanitized=dict(d["self_write_sanitized"]),
            global_writes={k: tuple(v) for k, v in d["global_writes"].items()},
            sinks=[SinkRecord(**r) for r in d["sinks"]],
            is_celery_task=d["is_celery_task"],
            analyzed=d["analyzed"],
        )
    return out


def run_scan(root: str, config_path: str) -> tuple[list[Finding], InterAnalyzer, float]:
    started = time.perf_counter()
    repo = ModuleRepo(root)
    repo.load()
    config = AnalyzerConfig.load(config_path)
    inter = InterAnalyzer(repo, config)
    findings = inter.run()
    elapsed = time.perf_counter() - started
    return findings, inter, elapsed


def _compute_keys(repo: ModuleRepo) -> tuple[dict[str, str], dict[str, str]]:
    """返回 (模块内容哈希, 模块缓存 key)。key 同时覆盖自身内容与直接依赖，
    这样 import 目标一变，依赖方的缓存自动失效。"""
    hashes = {info.fqname: _file_hash(os.path.join(repo.root, info.rel_path))
              for info in repo.modules.values()}
    keys: dict[str, str] = {}
    for fq, info in repo.modules.items():
        deps = sorted({_import_root(b.fq_target) for b in info.imports.values()})
        dep_hash = hashlib.sha256(
            "|".join(hashes.get(d, "") for d in deps).encode()).hexdigest()
        keys[fq] = hashlib.sha256((hashes[fq] + dep_hash).encode()).hexdigest()
    return hashes, keys


def cmd_scan(args: argparse.Namespace) -> int:
    findings, inter, elapsed = run_scan(args.root, args.config)
    _emit_outputs(findings, args)
    print(f"[taint_sa] full scan: {len(findings)} findings, {elapsed:.2f}s",
          file=sys.stderr)
    if inter.truncated and args.show_truncation:
        for t in inter.truncated:
            print(f"[truncated] {t}", file=sys.stderr)
    if args.cache:
        repo = ModuleRepo(args.root)
        repo.load()
        _, keys = _compute_keys(repo)
        _write_cache(args, inter, keys)
    return 0


def cmd_incremental(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    cache = Cache(args.cache)
    repo = ModuleRepo(args.root)
    repo.load()
    config = AnalyzerConfig.load(args.config)

    hashes, keys = _compute_keys(repo)
    changed: set[str] = {fq for fq, key in keys.items()
                         if cache.doc["modules"].get(fq, {}).get("key") != key}
    # 依赖闭包：任何依赖变更的模块也要重算（摘要可能受被调函数新摘要影响）
    ripple = set(changed)
    progressed = True
    while progressed:
        progressed = False
        for fq, info in repo.modules.items():
            if fq in ripple:
                continue
            dep_roots = {_import_root(b.fq_target) for b in info.imports.values()}
            if dep_roots & ripple:
                ripple.add(fq)
                progressed = True

    inter = InterAnalyzer(repo, config)
    # 复用未变更模块的缓存摘要
    reusable: dict[str, FunctionSummary] = {}
    for fq, entry in cache.doc["modules"].items():
        if fq not in ripple and fq in repo.modules:
            reusable.update(_cacheable_to_summaries(entry["summaries"]))
    inter.summaries.update(reusable)
    findings = inter.run()
    elapsed = time.perf_counter() - started

    _emit_outputs(findings, args)
    print(f"[taint_sa] incremental: changed={len(ripple)} reused={len(reusable)} "
          f"findings={len(findings)} {elapsed:.2f}s", file=sys.stderr)

    # 一致性自检：增量结果必须与全量等价
    if args.verify:
        full_findings, _, full_elapsed = run_scan(args.root, args.config)
        inc_keys = {f.identity() for f in findings}
        full_keys = {f.identity() for f in full_findings}
        if inc_keys != full_keys:
            print("[taint_sa] 增量/全量结果不一致！", file=sys.stderr)
            print(" missing:", sorted(full_keys - inc_keys), file=sys.stderr)
            print(" extra:", sorted(inc_keys - full_keys), file=sys.stderr)
            return 3
        print(f"[taint_sa] 一致性自检通过（全量对照 {full_elapsed:.2f}s）",
              file=sys.stderr)
    _write_cache(args, inter, keys)
    return 0


def _write_cache(args: argparse.Namespace, inter: InterAnalyzer,
                 keys: Optional[dict[str, str]] = None) -> None:
    if not args.cache:
        return
    cache = Cache(args.cache)
    by_module: dict[str, list[str]] = inter.registry.by_module
    for fq, quals in by_module.items():
        summaries = {q: inter.summaries[q] for q in quals
                     if q in inter.summaries and inter.summaries[q].analyzed}
        entry = {"key": (keys or {}).get(fq, ""),
                 "summaries": _summaries_to_cacheable(summaries)}
        cache.doc["modules"][fq] = entry
    cache.save()


def _import_root(fq_target: str) -> str:
    return fq_target.split(".")[0] if "." in fq_target else fq_target


def cmd_gate(args: argparse.Namespace) -> int:
    """CI 门禁：只允许「新增违规」红灯；基线存量计入豁免清单。"""
    with open(args.sarif, "rb") as fh:
        current = json.loads(fh.read().decode("utf-8-sig"))
    baseline_keys: set[tuple[str, int]] = set()
    if os.path.exists(args.baseline):
        with open(args.baseline, "rb") as fh:
            base = json.loads(fh.read().decode("utf-8-sig"))
        baseline_keys = _sarif_anchors(base)
    current_keys = _sarif_anchors(current)
    new_violations = sorted(current_keys - baseline_keys)
    if not new_violations:
        print(f"[gate] PASS：当前 {len(current_keys)} 条，无新增（基线 {len(baseline_keys)} 条）",
              file=sys.stderr)
        return 0
    print(f"[gate] FAIL：检测到 {len(new_violations)} 条新增命令注入违规：",
          file=sys.stderr)
    for uri, line in new_violations:
        print(f"  - {uri}:{line}", file=sys.stderr)
    return 1


def _sarif_anchors(doc: dict) -> set[tuple[str, int]]:
    out: set[tuple[str, int]] = set()
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            for loc in res.get("locations", []) or []:
                phys = loc.get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri")
                line = (phys.get("region") or {}).get("startLine") or 0
                if uri:
                    out.add((uri.replace("\\", "/"), int(line)))
    return out


def _emit_outputs(findings: list[Finding], args: argparse.Namespace) -> None:
    if args.sarif:
        dump_sarif(findings, args.sarif)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(to_findings_json(findings), fh, ensure_ascii=False, indent=1)
    if not args.sarif and not args.json:
        sys.stdout.write(json.dumps(to_findings_json(findings), ensure_ascii=False))
        sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=".", help="仓库根目录")
    common.add_argument("--config", default="config/sanitizers.json",
                        help="sanitizer/wrapper 白名单配置")
    common.add_argument("--sarif", help="SARIF 2.1.0 输出路径")
    common.add_argument("--json", dest="json", help="findings.json 输出路径")
    common.add_argument("--cache", help="增量缓存路径")

    p = argparse.ArgumentParser(
        prog="taint_sa", parents=[common],
        description="Python 命令注入跨过程污点分析器（ast + 自建 CFG）")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", parents=[common], help="全量扫描")
    s.add_argument("--show-truncation", action="store_true")
    s.set_defaults(func=cmd_scan)

    i = sub.add_parser("incremental", parents=[common],
                       help="增量扫描（复用缓存摘要）")
    i.add_argument("--verify", action="store_true",
                   help="跑完增量后再跑全量做一致性自检")
    i.set_defaults(func=cmd_incremental)

    g = sub.add_parser("gate", parents=[common],
                       help="CI 门禁：新增违规红灯")
    g.add_argument("--baseline", required=True, help="基线 SARIF（存量豁免）")
    g.set_defaults(func=cmd_gate)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
