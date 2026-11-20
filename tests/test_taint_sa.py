"""taint_sa 分析器自身的测试：召回/误报指标、SARIF 合规、sanitizer 配置、
增量一致性、CI 门禁。全部使用标准库，不依赖 flask/celery。"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "config", "sanitizers.json")
CACHE = os.path.join(ROOT, ".taint_cache_test.json")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", os.path.join(ROOT, "analyze.py"), *args],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")


@pytest.fixture(scope="module")
def full_scan(tmp_path_factory):
    out_json = tmp_path_factory.mktemp("sa") / "findings.json"
    out_sarif = tmp_path_factory.mktemp("sa") / "findings.sarif"
    proc = run("scan", "--root", ROOT, "--config", CONFIG,
               "--json", str(out_json), "--sarif", str(out_sarif))
    assert proc.returncode == 0, proc.stderr
    return out_json, out_sarif


def _eval(findings_path):
    proc = subprocess.run(
        [sys.executable, "-I", os.path.join(ROOT, "eval.py"), str(findings_path)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_recall_and_false_positive_targets(full_scan):
    """题面硬指标：50 条样本召回 ≥85%、误报率 ≤15%。"""
    out_json, _ = full_scan
    report = _eval(out_json)
    assert "recall=100.0%" in report
    assert "false_positive_rate=0.0%" in report
    assert "FP=0" in report and "FN=0" in report


def test_no_findings_in_benign_dirs(full_scan):
    """monitor/health/lib 实现/filler 探针全部是良性，一条都不能报。"""
    out_json, _ = full_scan
    findings = json.loads(out_json.read_text(encoding="utf-8"))["findings"]
    assert findings
    for f in findings:
        assert not f["file"].startswith(("lib/", "filler/"))
        assert "monitor.py" not in f["file"]
        assert "health.py" not in f["file"]


def test_all_variants_and_sources_covered(full_scan):
    """50 条标注覆盖全部传播形态；finding 按 sink 形态归类（closure/class_attr
    传播到的 sink 仍是 concat_shell/shell_wrapper），故这里按 label 反查覆盖。"""
    out_json, _ = full_scan
    findings = json.loads(out_json.read_text(encoding="utf-8"))["findings"]
    anchors = {(f["file"], f["line"]) for f in findings}
    labels = json.loads(open(os.path.join(ROOT, "labels.json"),
                             encoding="utf-8").read())["vulns"]
    label_variants = {v["variant"] for v in labels}
    assert label_variants == {
        "concat_shell", "arglist_misuse", "shell_wrapper", "template_rendered",
        "closure", "class_attr"}
    # 每种变体至少有一条标注被 finding 锚点覆盖（行号容差 2）
    for variant in label_variants:
        assert any(any(abs(f_line - v["line"]) <= 2 and f_file == v["file"]
                       for f_file, f_line in anchors)
                   for v in labels if v["variant"] == variant), variant
    source_kinds = {s.split(".", 1)[0] for f in findings for s in f["sources"]}
    assert {"flask", "celery", "env"} <= source_kinds


def test_sarif_2_1_0_shape(full_scan):
    _, out_sarif = full_scan
    doc = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    run0 = doc["runs"][0]
    assert run0["tool"]["driver"]["rules"][0]["id"] == "command_injection"
    for res in run0["results"]:
        assert res["level"] == "error"
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].endswith(".py")
        assert loc["region"]["startLine"] > 0
        assert res["properties"]["cwe"] == "CWE-78"


def test_sanitizer_config_is_effective(tmp_path):
    """把 shlex.quote 从配置白名单移除后，构造一个仅依赖该 sanitizer 的
    最小污点链路，验证它不再被灭活而产生告警——证明白名单可配置而非写死。"""
    cfg_doc = json.loads(open(CONFIG, encoding="utf-8").read())
    cfg_doc["sanitizers"] = [s for s in cfg_doc["sanitizers"]
                             if s["name"] != "shlex.quote"]
    cfg_path = tmp_path / "sanitizers.json"
    cfg_path.write_text(json.dumps(cfg_doc), encoding="utf-8")
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    (probe_dir / "svc_probe.py").write_text(
        "import os, shlex\n"
        "from flask import request\n\n"
        "def probe():\n"
        "    name = request.args.get('name', '')\n"
        "    os.system('dpkg -s ' + shlex.quote(name))\n",
        encoding="utf-8")
    out = tmp_path / "out.json"
    proc = run("scan", "--root", str(tmp_path), "--config", str(cfg_path),
               "--json", str(out))
    assert proc.returncode == 0, proc.stderr
    findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
    assert any("svc_probe.py" in f["file"] for f in findings)

    # 同样的探针在默认配置下必须干净（shlex.quote 生效）
    out2 = tmp_path / "out2.json"
    proc2 = run("scan", "--root", str(tmp_path), "--config", CONFIG,
                "--json", str(out2))
    assert proc2.returncode == 0, proc2.stderr
    clean = json.loads(out2.read_text(encoding="utf-8"))["findings"]
    assert not any("svc_probe.py" in f["file"] for f in clean)


def test_incremental_matches_full(full_scan, tmp_path):
    out_json, _ = full_scan
    full_keys = {
        (f["file"], f["line"], f["variant"])
        for f in json.loads(out_json.read_text(encoding="utf-8"))["findings"]}
    # 全量建缓存
    proc = run("scan", "--root", ROOT, "--config", CONFIG,
               "--cache", CACHE, "--json", str(tmp_path / "warm.json"))
    assert proc.returncode == 0, proc.stderr
    inc = tmp_path / "inc.json"
    proc = run("incremental", "--root", ROOT, "--config", CONFIG,
               "--cache", CACHE, "--json", str(inc))
    assert proc.returncode == 0, proc.stderr
    assert "changed=0" in proc.stderr
    inc_keys = {
        (f["file"], f["line"], f["variant"])
        for f in json.loads(inc.read_text(encoding="utf-8"))["findings"]}
    assert inc_keys == full_keys


def test_gate_blocks_new_violation(full_scan, tmp_path):
    _, sarif = full_scan
    baseline = tmp_path / "baseline.sarif"
    baseline.write_text(sarif.read_text(encoding="utf-8"), encoding="utf-8")
    # 构造一条新增违规的 SARIF（复制一条并改锚点）
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    extra = json.loads(json.dumps(doc["runs"][0]["results"][0]))
    extra["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = \
        "services/gateway/monitor.py"
    extra["locations"][0]["physicalLocation"]["region"]["startLine"] = 99
    doc["runs"][0]["results"].append(extra)
    current = tmp_path / "current.sarif"
    current.write_text(json.dumps(doc), encoding="utf-8")
    proc = run("gate", "--root", ROOT, "--baseline", str(baseline),
               "--sarif", str(current))
    assert proc.returncode == 1
    assert "monitor.py:99" in proc.stderr


def test_only_ast_dependency():
    """实现约束：只准用语法解析库。扫描 taint_sa 全部 import，禁止第三方库。"""
    allowed_roots = {
        "ast", "os", "sys", "json", "argparse", "hashlib", "time",
        "dataclasses", "typing", "__future__", "taint_sa"}
    pkg = os.path.join(ROOT, "taint_sa")
    for name in os.listdir(pkg):
        if not name.endswith(".py"):
            continue
        ns = {}
        tree = ast_parse(os.path.join(pkg, name))
        for node in tree.body:
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name.split(".")[0] in allowed_roots, (name, a.name)
            elif isinstance(node, ast.ImportFrom):
                # 包内相对导入（from .config import ...）module 为短名
                if node.level:
                    continue
                root = node.module.split(".")[0] if node.module else None
                assert root in allowed_roots or node.module and \
                    node.module.startswith("taint_sa"), (name, node.module)


def ast_parse(path):
    import ast
    return ast.parse(open(path, encoding="utf-8").read())
