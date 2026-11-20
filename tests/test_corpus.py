import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEC_API = re.compile(
    r"subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen"
    r"|shellwrap\.\w+|cmdutil\.\w+")


def load_json(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return json.load(fh)


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def test_labels_anchor_real_lines():
    doc = load_json("labels.json")
    vulns = doc["vulns"]
    assert len(vulns) == 50
    assert {v["sink"] for v in vulns} == {"command_injection"}
    for v in vulns:
        lines = open(os.path.join(ROOT, v["file"]), encoding="utf-8").read().splitlines()
        assert 1 <= v["line"] <= len(lines), (v["id"], v["line"])
        assert EXEC_API.search(lines[v["line"] - 1]), (v["id"], lines[v["line"] - 1])
        assert v["variant"] and v["source"] and v["path"]


def test_label_coverage():
    vulns = load_json("labels.json")["vulns"]
    assert {v["variant"] for v in vulns} == {
        "concat_shell", "arglist_misuse", "shell_wrapper", "template_rendered",
        "closure", "class_attr"}
    assert {v["source"] for v in vulns} == {
        "flask_arg", "flask_form", "flask_json", "celery_arg", "env_var"}


def test_sanitizer_config():
    cfg = load_json("config/sanitizers.json")
    names = {s["name"] for s in cfg["sanitizers"]}
    assert "shlex.quote" in names and "os.path.basename" in names
    assert "lib.shellwrap.run_shell" in cfg["shell_wrappers"]
    assert "lib.shellwrap.run_argv" in cfg["safe_wrappers"]


def test_baseline_emits_required_fields():
    proc = run([sys.executable, os.path.join(ROOT, "baseline", "scan.py")])
    assert proc.returncode == 0, proc.stderr
    findings = json.loads(proc.stdout)["findings"]
    assert findings
    for f in findings:
        assert f["file"].endswith(".py") and f["line"] > 0
        assert f["sink"] == "command_injection"


def test_baseline_is_a_noisy_starting_point(tmp_path):
    proc = run([sys.executable, os.path.join(ROOT, "baseline", "scan.py")])
    assert proc.returncode == 0, proc.stderr
    out = tmp_path / "o.json"
    out.write_text(proc.stdout, encoding="utf-8")
    ev = run([sys.executable, os.path.join(ROOT, "eval.py"), str(out)])
    assert ev.returncode == 0, ev.stderr
    m = re.search(r"recall=([\d.]+)%.*false_positive_rate=([\d.]+)%", ev.stdout)
    assert m, ev.stdout
    assert float(m.group(1)) >= 90.0
    assert float(m.group(2)) > 20.0


def test_eval_accepts_sarif(tmp_path):
    vulns = load_json("labels.json")["vulns"][:3]
    results = [{
        "ruleId": "command_injection",
        "message": {"text": v["evidence"]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": v["file"]},
            "region": {"startLine": v["line"]},
        }}],
    } for v in vulns]
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": results}]}
    path = tmp_path / "out.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    ev = run([sys.executable, os.path.join(ROOT, "eval.py"), str(path)])
    assert ev.returncode == 0, ev.stderr
    assert "TP=3" in ev.stdout, ev.stdout
