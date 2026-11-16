import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")
DETECTOR = os.path.join(ROOT, "detector", "detector.py")


def run(tmp_path, log=LOG):
    out = tmp_path / "out.json"
    r = subprocess.run(
        [sys.executable, DETECTOR, log, str(out)],
        capture_output=True, text=True,
    )
    return r, out


def _scan_text(tmp_path, text):
    log = tmp_path / "case.log"
    log.write_text(text, encoding="utf-8")
    r, out = run(tmp_path, str(log))
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Skeleton / contract tests
# --------------------------------------------------------------------------

def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data["events"]) == 3


def test_detector_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "findings" in payload
    assert "needs_review" in payload


def test_findings_have_required_fields(tmp_path):
    _, out = run(tmp_path)
    for f in json.loads(out.read_text(encoding="utf-8"))["findings"]:
        assert f.get("rule") and f.get("line") and f.get("ip")
        # prompt-mandated schema
        for key in ("rule", "first_seen", "last_seen", "entities", "evidence"):
            assert key in f, key
        assert isinstance(f["evidence"], list) and f["evidence"]
        assert f["first_seen"] <= f["last_seen"]


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    r, out = run(tmp_path, str(empty))
    assert r.returncode == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["needs_review"] == []


# --------------------------------------------------------------------------
# Label coverage: every labelled event is hit, nothing else
# --------------------------------------------------------------------------

def test_all_three_labelled_events_detected(tmp_path):
    _, out = run(tmp_path)
    findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
    rules = {f["rule"] for f in findings}
    assert rules == {"privilege_escalation", "dns_tunnel", "webshell"}

    by_rule = {f["rule"]: f for f in findings}

    pe = by_rule["privilege_escalation"]
    assert pe["entities"]["user"] == "deploy"
    assert pe["entities"]["target_user"] == "root"
    kinds = [e["event"] for e in pe["evidence"]]
    assert kinds == ["ssh_accept", "sudo", "ssh_accept"]

    dns = by_rule["dns_tunnel"]
    assert dns["entities"]["ip"] == "10.20.1.51"
    assert dns["entities"]["tunnel_zone"] == "exfil.example.com"
    assert dns["entities"]["query_count"] >= 12
    assert len({e["query"] for e in dns["evidence"]}) == 12

    web = by_rule["webshell"]
    assert web["entities"]["ip"] == "10.20.1.51"
    paths = [e["path"] for e in web["evidence"]]
    assert paths[0] == "/upload.php"
    assert paths[1].startswith("/uploads/shell.php")
    assert "cmd=" in paths[1]


def test_benign_lookalikes_zero_false_positives(tmp_path):
    _, out = run(tmp_path)
    payload = json.loads(out.read_text(encoding="utf-8"))
    # 3 failed ops logins then a success, and two 403 probes must not alert
    for f in payload["findings"]:
        assert f["ip"] not in {"10.20.1.77", "10.20.1.88"}
        for e in f["evidence"]:
            assert e.get("ip") not in {"10.20.1.77", "10.20.1.88"}
    # and no review noise either: the benign patterns are fully explainable
    for r in payload["needs_review"]:
        assert r.get("ip") not in {"10.20.1.77", "10.20.1.88"}


def test_exactly_three_findings_on_corpus(tmp_path):
    _, out = run(tmp_path)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert len(payload["findings"]) == 3
    assert payload["needs_review"] == []


# --------------------------------------------------------------------------
# Format-dialect compatibility: the same attacks in different feed shapes
# must still align and alert
# --------------------------------------------------------------------------

def test_mixed_format_dialects_are_aligned(tmp_path):
    # one event per rule, each in a different timestamp/program dialect,
    # spread over two hosts
    text = (
        # RFC5424 timestamp, no PID bracket (year intentionally matches BSD pin
        # so cross-dialect correlation windows overlap)
        "2024-10-01T06:35:29+00:00 web02 sudo: bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/sh\n"
        # single-digit BSD day, PID present
        "Oct  1 06:35:40 web02 sshd[4242]: Accepted publickey for root from 198.51.100.7 port 22 ssh2\n"
        # BIND-style DNS instead of dnsmasq, different column layout (8 encoded labels)
        "Oct  1 06:40:00 web02 named[99]: client 198.51.100.7#53 (xq7mz2kv9wpa4rdh8nbt.evil.test): query: xq7mz2kv9wpa4rdh8nbt.evil.test IN A +E (10.0.0.1)\n"
        "Oct  1 06:40:05 web02 named[99]: client 198.51.100.7#53 (jf3k8sla6dgv2cxp5erh.evil.test): query: jf3k8sla6dgv2cxp5erh.evil.test IN A +E (10.0.0.1)\n"
        "Oct  1 06:40:10 web02 named[99]: client 198.51.100.7#53 (pw9bn4mk7vza2qxd8lcf.evil.test): query: pw9bn4mk7vza2qxd8lcf.evil.test IN A +E (10.0.0.1)\n"
        "Oct  1 06:40:15 web02 named[99]: client 198.51.100.7#53 (ht6gr3ke9mnx2vbw7qaz.evil.test): query: ht6gr3ke9mnx2vbw7qaz.evil.test IN A +E (10.0.0.1)\n"
        "Oct  1 06:40:20 web02 named[99]: client 198.51.100.7#53 (dk8fx2mp5svz3nqa6wer.evil.test): query: dk8fx2mp5svz3nqa6wer.evil.test IN A +E (10.0.0.1)\n"
        "Oct  1 06:40:25 web02 named[99]: client 198.51.100.7#53 (bv4cw7hn2klx9qgm8paz.evil.test): query: bv4cw7hn2klx9qgm8paz.evil.test IN A +E (10.0.0.1)\n"
        "Oct  1 06:40:30 web02 named[99]: client 198.51.100.7#53 (mr5sd8gk3xfw2vbn9qle.evil.test): query: mr5sd8gk3xfw2vbn9qle.evil.test IN A +E (10.0.0.1)\n"
        "Oct  1 06:40:35 web02 named[99]: client 198.51.100.7#53 (nz6lf3ht8xqw4kdv2mga.evil.test): query: nz6lf3ht8xqw4kdv2mga.evil.test IN A +E (10.0.0.1)\n"
        # nginx with extra spaces inside the quoted UA and a different host
        'Oct  1 06:50:00 web02 nginx: 198.51.100.7 - - "POST /upload.php HTTP/1.1" 200 12 "curl/8.0  custom"\n'
        'Oct  1 06:50:10 web02 nginx: 198.51.100.7 - - "GET /uploads/x.jsp?exec=whoami HTTP/1.1" 200 9 "curl/8.0  custom"\n'
    )
    payload = _scan_text(tmp_path, text)
    rules = {f["rule"] for f in payload["findings"]}
    assert {"privilege_escalation", "dns_tunnel", "webshell"} <= rules
    assert payload["needs_review"] == []


def test_nginx_spaces_in_request_do_not_shift_fields(tmp_path):
    text = (
        'Oct 01 06:50:00 web01 nginx: 10.20.1.51 - - "POST /upload.php HTTP/1.1" 200 3828 "Mozilla/5.0 (Windows NT 10.0)"\n'
        'Oct 01 06:50:05 web01 nginx: 10.20.1.51 - - "GET /uploads/s.php?cmd=uname HTTP/1.1" 200 17 "Mozilla/5.0 (Windows NT 10.0)"\n'
    )
    payload = _scan_text(tmp_path, text)
    web = next(f for f in payload["findings"] if f["rule"] == "webshell")
    # status must be parsed as 200 even though the UA string contains spaces
    assert all(e.get("status") == 200 for e in web["evidence"])
    assert web["evidence"][0]["method"] == "POST"
    assert web["evidence"][1]["method"] == "GET"


# --------------------------------------------------------------------------
# needs_review: ambiguity must be escalated, never silently alerted/dropped
# --------------------------------------------------------------------------

def test_sudo_without_followup_root_goes_to_review(tmp_path):
    text = (
        "Oct 01 06:35:29 web01 sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash\n"
    )
    payload = _scan_text(tmp_path, text)
    assert payload["findings"] == []
    assert len(payload["needs_review"]) == 1
    item = payload["needs_review"][0]
    assert item["rule"] == "privilege_escalation"
    assert item["reason"] == "inconclusive"
    assert "missing" in item and item["missing"]


def test_upload_without_execution_goes_to_review(tmp_path):
    text = (
        'Oct 01 06:50:00 web01 nginx: 10.20.1.51 - - "POST /upload.php HTTP/1.1" 200 10 "-"\n'
    )
    payload = _scan_text(tmp_path, text)
    assert payload["findings"] == []
    assert len(payload["needs_review"]) == 1
    assert payload["needs_review"][0]["rule"] == "webshell"


def test_failed_upload_is_not_even_reviewed(tmp_path):
    text = (
        'Oct 01 06:50:00 web01 nginx: 10.20.1.51 - - "POST /upload.php HTTP/1.1" 403 0 "-"\n'
    )
    payload = _scan_text(tmp_path, text)
    assert payload["findings"] == []
    assert payload["needs_review"] == []


def test_subthreshold_dns_burst_goes_to_review(tmp_path):
    rows = []
    for i in range(4):  # below the 8-query alert threshold, above review floor
        rows.append(
            f"Oct 01 06:40:{i:02d} web01 dnsmasq[1]: query[A] "
            f"aaaa1111bbbb2222cccc333{i}.evil.test from 10.20.1.51"
        )
    payload = _scan_text(tmp_path, "\n".join(rows) + "\n")
    assert payload["findings"] == []
    assert len(payload["needs_review"]) == 1
    assert payload["needs_review"][0]["rule"] == "dns_tunnel"


def test_ordinary_low_entropy_dns_is_ignored(tmp_path):
    names = ["www.example.com", "mail.example.com", "api.example.com",
             "cdn.example.com", "auth.example.com"]
    text = "".join(
        f"Oct 01 06:40:{i:02d} web01 dnsmasq[1]: query[A] {n} from 10.20.1.9\n"
        for i, n in enumerate(names)
    )
    payload = _scan_text(tmp_path, text)
    assert payload["findings"] == []
    assert payload["needs_review"] == []


def test_high_entropy_lookups_across_distinct_subdomains_are_ignored(tmp_path):
    # CDN-style: random-looking names under *different* subdomains of one
    # registrar domain must not be treated as one tunnel endpoint
    text = "".join(
        f"Oct 01 06:40:{i:02d} web01 dnsmasq[1]: query[A] "
        f"xq7mz2kv9wpa4rdh8nbt{i}.cdn-{i}.example.net from 10.20.1.9\n"
        for i in range(10)
    )
    payload = _scan_text(tmp_path, text)
    assert payload["findings"] == []
    assert payload["needs_review"] == []


def test_two_label_tunnel_shape_is_detected(tmp_path):
    # classic <encoded-blob>.evil.io with no extra zone component
    text = "".join(
        f"Oct 01 06:40:{i:02d} web01 dnsmasq[1]: query[A] "
        f"xq7mz2kv9wpa4rdh8nb{i}.evil.io from 10.20.1.9\n"
        for i in range(10)
    )
    payload = _scan_text(tmp_path, text)
    assert any(f["rule"] == "dns_tunnel" for f in payload["findings"])


def test_plain_root_login_without_sudo_is_not_escalation(tmp_path):
    text = ("Oct 01 06:35:32 web01 sshd[1]: Accepted publickey for root "
            "from 10.20.1.51 port 1 ssh2\n")
    payload = _scan_text(tmp_path, text)
    assert payload["findings"] == []
    assert payload["needs_review"] == []


def test_unknown_feed_format_is_reviewed_not_misaligned(tmp_path):
    text = "Oct 01 06:50:00 web01 mysteryservice: something unrecognizable happened\n"
    payload = _scan_text(tmp_path, text)
    assert payload["findings"] == []
    assert len(payload["needs_review"]) == 1
    assert payload["needs_review"][0]["reason"] == "unparsed"
    assert "missing" in payload["needs_review"][0]


# --------------------------------------------------------------------------
# Unit-level checks on the normalization helpers
# ---------------------------------------------------------------------------

def test_parser_normalizes_across_dialects(tmp_path):
    sys.path.insert(0, os.path.join(ROOT, "detector"))
    import detector  # noqa: E402

    ev, problem = detector.parse_line(
        "Oct 01 06:35:29 web01 sudo: deploy : TTY=pts/0 ; PWD=/tmp ; "
        "USER=root ; COMMAND=/bin/bash", 1)
    assert problem is None and ev.etype == "sudo"
    assert ev.user == "deploy" and ev.sudo_user == "root"

    ev, problem = detector.parse_line(
        "2026-10-01T06:35:29+00:00 web02 sshd[9]: Failed password for ops "
        "from 10.20.1.77 port 1 ssh2", 2)
    assert problem is None and ev.etype == "ssh_fail"
    assert ev.user == "ops" and ev.ip == "10.20.1.77" and ev.host == "web02"

    assert detector.parent_domain("a.b.exfil.example.com") == "example.com"
    assert detector.parent_domain("x.example.co.uk") == "example.co.uk"
    assert detector.shannon_entropy("abcdefghijklmnopqrstuvwx") > 3.0


def test_crlf_input_is_handled(tmp_path):
    text = (
        'Oct 01 06:50:00 web01 nginx: 10.20.1.51 - - "POST /upload.php HTTP/1.1" 200 1 "-"\r\n'
        'Oct 01 06:50:02 web01 nginx: 10.20.1.51 - - "GET /uploads/s.php?cmd=id HTTP/1.1" 200 1 "-"\r\n'
    )
    payload = _scan_text(tmp_path, text)
    assert any(f["rule"] == "webshell" for f in payload["findings"])
