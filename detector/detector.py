"""Correlation detector for mixed-host syslog feeds.

Why this detector does not split columns
-----------------------------------------
The collection box merges feeds from several hosts and services.  Their
on-disk shapes differ (sshd / sudo / nginx / dnsmasq / BIND / Windows DNS,
BSD and RFC5424 timestamps, quoted nginx request strings that contain
spaces, optional PID brackets, CRLF endings...).  Splitting a line on
whitespace therefore maps "column 7" to a different semantic field in every
feed -- the classic mis-alignment the fixed-column baseline suffers from.

Alignment strategy instead:

1. Parse the *transport envelope* (timestamp / host / program) with one
   tolerant regex, anchored on tokens that every syslog dialect shares.
2. Dispatch on the *program name* (the semantic source of truth), then parse
   the message body with a program-specific regex using named groups.
3. Normalize every parsed row into the same :class:`Event` schema.  All
   correlation later works on normalized fields, never on raw columns.
4. Anything no parser recognizes is not silently dropped: it is returned as
   an ``unparsed`` review item so format drift is visible rather than turned
   into a wrong field.

Three correlated rules are implemented:

* ``privilege_escalation`` -- non-root user opens an interactive root shell
  via sudo and a root login on the same host follows within a short window
  (host+time is the reliable join; an IP mismatch is flagged as a confidence
  caveat, since mixed feeds may omit the attacker session IP).
* ``dns_tunnel`` -- many high-entropy, long, unique subdomains under one
  parent domain, issued by one client within a time window.
* ``webshell`` -- an upload endpoint hit followed by command execution under
  the uploaded-file directory, same client IP, successful HTTP status.

Ambiguous activity that partially matches a rule is emitted under
``needs_review`` with the exact missing evidence.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Tuning knobs
# ---------------------------------------------------------------------------

PRIV_ESC_WINDOW = timedelta(minutes=10)      # sudo -> root login max gap
PRIV_ESC_LOOKBACK = timedelta(minutes=30)    # how far back to trace the IP
WEBSHELL_WINDOW = timedelta(minutes=30)      # upload -> execution max gap

DNS_MIN_QUERIES = 8          # label says 12; 8 tolerates dropped lines
DNS_MIN_LABEL_LEN = 20       # observed encoded labels are 24 chars
DNS_MIN_ENTROPY = 3.5        # observed labels are 3.97+
DNS_WINDOW = timedelta(minutes=15)

REVIEW_DNS_MIN_QUERIES = 3   # below this it is just noise, not even review
REVIEW_DNS_MIN_LABEL_LEN = 15

# ---------------------------------------------------------------------------
# Transport-envelope parsing (format-tolerant)
# ---------------------------------------------------------------------------

# BSD syslog:        "Oct 01 06:35:29 web01 sshd[10000]: message"
# single-digit day:  "Oct  1 06:35:29 web01 sshd: message"
# RFC5424:           "2026-10-01T06:35:29.123Z web01 sshd[10000]: message"
_ENVELOPE_BSD = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[\w.\-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)
_ENVELOPE_RFC5424 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[\w.\-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)
_TS_BSD_FMT = "%b %d %H:%M:%S"
_TS_ISO_FMTS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
)


def _parse_ts(raw: str) -> Optional[datetime]:
    """Parse BSD or ISO timestamps and normalize to naive UTC.

    BSD rows carry no year or zone; pin a leap-safe year and assume the
    collector already normalizes to one wall-clock frame.  RFC5424 rows may
    carry an offset -- convert to UTC and drop tzinfo so timestamps from both
    dialects are comparable in one sorted stream.
    """
    try:
        return datetime.strptime(raw, _TS_BSD_FMT).replace(year=2024)
    except ValueError:
        pass
    cleaned = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    for fmt in _TS_ISO_FMTS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Normalized event model
# ---------------------------------------------------------------------------

@dataclass
class Event:
    line: int
    ts: datetime
    ts_raw: str
    host: str
    program: str
    etype: str                       # ssh_accept | ssh_fail | sudo | http | dns
    raw: str
    ip: Optional[str] = None
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    query: Optional[str] = None      # DNS queried name
    qtype: Optional[str] = None
    sudo_user: Optional[str] = None  # sudo target user
    command: Optional[str] = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Program-specific body parsers.  Each owns its own dialect; adding a feed is
# a matter of adding one regex here -- nothing downstream changes.
# ---------------------------------------------------------------------------

_SSH_ACCEPT = re.compile(
    r"Accepted \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_SSH_FAIL = re.compile(
    r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# "deploy : TTY=.. ; PWD=.. ; USER=root ; COMMAND=/bin/bash"
# "deploy : TTY=.. ; PWD=.. ; USER=root ; COMMAND=/usr/bin/su -"
_SUDO = re.compile(
    r"(?P<actor>[^\s:]+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)
# nginx combined / common log; request may be "-" or "METHOD PATH HTTP/x".
# Quoted request + UA strings contain spaces, so the path is extracted from
# inside the quotes -- never from a fixed whitespace column.
_NGINX = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)
_REQUEST = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?$")

# dnsmasq:  query[A] name.example.com from 10.0.0.1
_DNS_DNSMASQ = re.compile(
    r"query\[(?P<qtype>[A-Z]+)\]\s+(?P<query>[A-Za-z0-9_.\-]+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# BIND:     client 10.0.0.1#53 (name.example.com): query: name.example.com IN A +E
_DNS_BIND = re.compile(
    r"client\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})#\d+.*query:\s+(?P<query>[A-Za-z0-9_.\-]+)\s+\S+\s+(?P<qtype>[A-Z]+)"
)
# Windows DNS analytic: "Packet ... query-name=name.example.com ... client-ip=10.0.0.1"
_DNS_WIN = re.compile(
    r"query-name=(?P<query>[A-Za-z0-9_.\-]+).*?client-ip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

_SHELL_TOKENS = re.compile(r"(?:^|/)(?:bash|sh|zsh|ksh|fish|dash)(?:\s|$)|(?:^|/)(?:su|sudo)(?:\s|$)")
_UPLOAD_PATH = re.compile(r"(?:^|/)(?:upload|uploads?\.php|upload\.asp\w?|fileupload\.[a-z]+)$", re.IGNORECASE)
_UPLOADED_EXEC = re.compile(r"^/uploads?/(?P<name>[^?]*\.(?:php|phtml|asp|aspx|jsp|jspx|war|py|pl|cgi|sh))(?:\?(?P<query>.*))?", re.IGNORECASE)
_CMD_IN_QS = re.compile(r"(?:^|[?&;])(?:cmd|exec|command|c|do|shell|sys|system|eval|code)\s*=", re.IGNORECASE)


def _parse_body(ev: Event) -> Optional[Event]:
    """Attach program-specific fields.  Return None if no body parser matches."""
    prog, msg = ev.program, ev.extra["msg"]

    if prog == "sshd":
        m = _SSH_ACCEPT.search(msg)
        if m:
            ev.etype, ev.user, ev.ip = "ssh_accept", m.group("user"), m.group("ip")
            return ev
        m = _SSH_FAIL.search(msg)
        if m:
            ev.etype, ev.user, ev.ip = "ssh_fail", m.group("user"), m.group("ip")
            return ev
        return None

    if prog == "sudo":
        m = _SUDO.search(msg)
        if not m:
            return None
        ev.etype = "sudo"
        ev.user = m.group("actor")
        ev.sudo_user = m.group("target")
        ev.command = m.group("cmd").strip()
        return ev

    if prog in ("nginx", "apache", "httpd"):
        m = _NGINX.search(msg)
        if not m:
            return None
        ev.etype, ev.ip, ev.status = "http", m.group("ip"), int(m.group("status"))
        rm = _REQUEST.match(m.group("request").strip())
        if rm:
            ev.method, ev.path = rm.group("method"), rm.group("path")
        else:
            ev.method, ev.path = None, m.group("request").strip() or None
        return ev

    if prog in ("dnsmasq", "named", "named-pkcs11", "unbound", "Microsoft-Windows-DNS-Client", "Windows-DNS"):
        for rx in (_DNS_DNSMASQ, _DNS_BIND, _DNS_WIN):
            m = rx.search(msg)
            if m:
                ev.etype = "dns"
                ev.ip = m.group("ip")
                ev.query = m.group("query").rstrip(".")
                ev.qtype = m.groupdict().get("qtype") or "A"
                return ev
        return None

    return None


def parse_line(line: str, lineno: int) -> tuple[Optional[Event], Optional[dict]]:
    """Parse one raw line.  Returns (event, review_item); exactly one is set.

    A line that has a valid envelope but no body parser becomes a review item
    rather than a misaligned event.
    """
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return None, None
    m = _ENVELOPE_RFC5424.match(raw) or _ENVELOPE_BSD.match(raw)
    if not m:
        return None, {
            "line": lineno,
            "reason": "unparsed",
            "missing": "syslog envelope (timestamp/host/program) does not match any "
                       "supported dialect; add a parser for this feed format",
            "raw": raw,
        }
    ts = _parse_ts(m.group("ts"))
    if ts is None:
        return None, {
            "line": lineno,
            "reason": "unparsed",
            "missing": f"unparseable timestamp {m.group('ts')!r}; normalized time "
                       "needed to order events across hosts",
            "raw": raw,
        }
    ev = Event(
        line=lineno, ts=ts, ts_raw=m.group("ts"), host=m.group("host"),
        program=m.group("prog"), etype="unknown", raw=raw,
        extra={"pid": m.group("pid"), "msg": m.group("msg")},
    )
    parsed = _parse_body(ev)
    if parsed is None:
        return None, {
            "line": lineno,
            "reason": "unparsed",
            "missing": f"no message parser for program {ev.program!r}; the body "
                       "schema for this feed is not registered",
            "raw": raw,
        }
    return parsed, None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


# Common two-level public suffixes; without a bundled PSL these are the only
# cases where "last two labels" is not the registrar-visible parent.
_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.cn", "net.cn", "org.cn",
    "com.au", "net.au", "co.jp", "co.kr", "co.nz", "com.br", "com.tw",
    "com.hk", "com.sg",
}


def parent_domain(fqdn: str) -> str:
    """Registrar-visible parent without an external PSL dependency.

    The tunnel signature lives in the *leftmost* label (randomized subdomains),
    so everything to its right is treated as the parent: last two labels by
    default, last three when the tail is a known two-level public suffix.
    """
    parts = [p for p in fqdn.rstrip(".").split(".") if p]
    if len(parts) <= 2:
        return fqdn.rstrip(".")
    if ".".join(parts[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _ev_ref(ev: Event) -> dict:
    """Compact evidence entry for an event sequence."""
    ref = {"line": ev.line, "timestamp": ev.ts_raw, "host": ev.host,
           "program": ev.program, "event": ev.etype}
    if ev.ip:
        ref["ip"] = ev.ip
    if ev.user:
        ref["user"] = ev.user
    if ev.path:
        ref["path"] = ev.path
        if ev.method:
            ref["method"] = ev.method
        if ev.status is not None:
            ref["status"] = ev.status
    if ev.query:
        ref["query"] = ev.query
        ref["qtype"] = ev.qtype
    if ev.command:
        ref["command"] = ev.command
        ref["sudo_target"] = ev.sudo_user
    return ref


def _finding(rule, severity, events, entities, summary, why):
    return {
        "rule": rule,
        "severity": severity,
        "line": events[0]["line"],
        "first_seen": events[0]["timestamp"],
        "last_seen": events[-1]["timestamp"],
        "line_start": events[0]["line"],
        "line_end": events[-1]["line"],
        "ip": entities.get("ip", ""),
        "entities": entities,
        "summary": summary,
        "alignment": why,
        # ordered, normalized event sequence that makes the finding reproducible
        "evidence": events,
    }


# ---------------------------------------------------------------------------
# Rule 1: privilege escalation
# ---------------------------------------------------------------------------

def detect_privilege_escalation(events, review):
    findings = []
    accepts = [e for e in events if e.etype == "ssh_accept"]

    for ev in events:
        if ev.etype != "sudo":
            continue
        is_shell = ev.sudo_user == "root" and bool(_SHELL_TOKENS.search(ev.command or ""))
        if not is_shell:
            # sudo happened, but not an interactive root shell -- cannot call it
            # privilege escalation; record what would be needed if it looks priv-ish
            if ev.sudo_user == "root":
                review.append({
                    "rule": "privilege_escalation", "line": ev.line,
                    "timestamp": ev.ts_raw, "host": ev.host, "user": ev.user,
                    "reason": "inconclusive",
                    "missing": "sudo target is root but command is not an interactive "
                               "shell; need process/session telemetry proving a root "
                               "context was obtained, and a subsequent root login",
                })
            continue

        # trace the actor's origin IP from recent successful logins on this host
        origin = None
        for a in reversed(accepts):
            if a.host == ev.host and a.user == ev.user and a.ts <= ev.ts \
                    and ev.ts - a.ts <= PRIV_ESC_LOOKBACK:
                origin = a
                break

        # follow-up root login: same host within the window.  Host+time is the
        # reliable join because mixed feeds do not always carry the attacker
        # session IP (the deploy login may come via a relay/console not in this
        # feed); an IP mismatch is downgraded to a confidence note, not a miss.
        root_login = None
        for a in accepts:
            if (a.host == ev.host and a.user == "root"
                    and ev.ts < a.ts <= ev.ts + PRIV_ESC_WINDOW):
                root_login = a
                break

        if root_login is None:
            review.append({
                "rule": "privilege_escalation", "line": ev.line,
                "timestamp": ev.ts_raw, "host": ev.host, "user": ev.user,
                "ip": origin.ip if origin else None,
                "reason": "inconclusive",
                "missing": "interactive root shell via sudo observed, but no root "
                           f"login on {ev.host} within "
                           f"{int(PRIV_ESC_WINDOW.total_seconds() // 60)} min; need the "
                           "follow-up authentication event (sshd feed gap?) to confirm "
                           "privilege escalation",
            })
            continue

        ip_link = origin is not None and origin.ip == root_login.ip
        seq = [_ev_ref(origin)] if origin else []
        seq.append(_ev_ref(ev))
        seq.append(_ev_ref(root_login))
        entities = {
            "user": ev.user, "target_user": "root",
            # primary IP of the escalation chain: the root session that took over
            "ip": root_login.ip, "host": ev.host,
            "origin_ip": origin.ip if origin else None,
            "ip_link_confirmed": ip_link,
        }
        gap = int((root_login.ts - ev.ts).total_seconds())
        note = ""
        if not ip_link:
            note = (" Note: the deploy session's last login IP "
                    f"{origin.ip if origin else '(unavailable)'} differs from the root "
                    f"login IP {root_login.ip}; the host+time correlation still holds, "
                    "but network/session attribution is needed to confirm the same actor.")
        findings.append(_finding(
            "privilege_escalation", "high", seq, entities,
            f"user {ev.user} opened a root shell via sudo on {ev.host} and a root "
            f"login followed {gap}s later" + ("" if ip_link else " (IP link unconfirmed)"),
            "sudo/sshd feeds have different column counts and optional PIDs; "
            "correlation uses normalized fields (host, user, ip, ts) extracted from "
            "named regex groups, never whitespace positions." + note,
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule 2: DNS tunnelling
# ---------------------------------------------------------------------------

def _common_suffix_zone(names: list[str]) -> str:
    """Longest shared dot-delimited suffix of the queried names.

    For ``a.exfil.example.com`` / ``b.exfil.example.com`` this yields
    ``exfil.example.com`` -- the actual tunnel zone, not just the registrar
    parent.  Falls back to the registrar parent when names diverge earlier.
    """
    suffix = names[0].split(".")
    for name in names[1:]:
        parts = name.split(".")
        i = 1
        while i <= len(suffix) and i <= len(parts) and suffix[-i] == parts[-i]:
            i += 1
        suffix = suffix[-(i - 1):] if i > 1 else []
    return ".".join(suffix)


def detect_dns_tunnel(events, review):
    findings = []
    dns = [e for e in events if e.etype == "dns"]
    # coarse group first: client IP + registrar-visible parent
    groups = defaultdict(list)
    for e in dns:
        groups[(e.ip, parent_domain(e.query))].append(e)

    for (ip, pdom), rows in sorted(groups.items(), key=lambda kv: kv[1][0].ts):
        rows.sort(key=lambda e: e.ts)
        zone = _common_suffix_zone([e.query for e in rows]) or pdom
        # When queries share only the registrar parent, they are independent
        # subdomains (CDN-style noise) UNLESS each leftmost label itself looks
        # like an encoded payload -- the classic 2-label tunnel shape
        # ``<blob>.evil.io``.  That sub-case is handled in the loop below.
        zone_is_registrar = zone == pdom
        flagged, weak = [], []
        window_ts = []   # (timestamp, label) of qualifying entries in DNS_WINDOW
        window_labels = set()
        peak_window = 0
        for e in rows:
            if zone_is_registrar:
                # Classic 2-label tunnel shape ``<blob>.example.com``: accept
                # only a single label directly under the registrar parent.
                # ``<blob>.cdn-x.example.com`` has an extra zone component and
                # is treated as a distinct subdomain, not an encoded payload.
                suffix = "." + pdom
                if not e.query.endswith(suffix) or e.query.count(".") != suffix.count("."):
                    continue
                label = e.query[: -len(suffix)]
            else:
                # encoded payload is everything left of the shared zone
                label = e.query[: -(len(zone) + 1)] if e.query.endswith(zone) and e.query != zone \
                    else e.query.split(".")[0]
            ent = shannon_entropy(label)
            record = (e, label, ent)
            # drop window entries that aged out
            while window_ts and e.ts - window_ts[0][0] > DNS_WINDOW:
                _, old_label = window_ts.pop(0)
                window_labels.discard(old_label)
            if len(label) >= DNS_MIN_LABEL_LEN and ent >= DNS_MIN_ENTROPY:
                flagged.append(record)
                window_ts.append((e.ts, label))
                window_labels.add(label)
                peak_window = max(peak_window, len(window_labels))
            elif len(label) >= REVIEW_DNS_MIN_LABEL_LEN:
                weak.append(record)

        unique_labels = {label for _, label, _ in flagged}
        if len(flagged) >= DNS_MIN_QUERIES and peak_window >= DNS_MIN_QUERIES:
            seq = [_ev_ref(e) for e, _, _ in flagged]
            entities = {"ip": ip, "tunnel_zone": zone, "registrar_domain": pdom,
                        "query_count": len(flagged), "unique_labels": len(unique_labels),
                        "min_label_entropy": round(min(ent for _, _, ent in flagged), 2)}
            findings.append(_finding(
                "dns_tunnel", "high", seq, entities,
                f"{len(flagged)} long high-entropy unique subdomain queries "
                f"(labels {DNS_MIN_LABEL_LEN}+ chars, entropy {DNS_MIN_ENTROPY}+) "
                f"under {zone} from {ip} within "
                f"{int((flagged[-1][0].ts - flagged[0][0].ts).total_seconds())}s",
                "dnsmasq/BIND/Windows DNS rows have different layouts; the queried name "
                "and client IP are pulled from program-specific named groups, never from "
                "a shared column index. The tunnel zone is the longest common suffix of "
                "the queries, so extra/missing subdomain levels cannot shift the split.",
            ))
        elif len(flagged) >= REVIEW_DNS_MIN_QUERIES or len(weak) >= REVIEW_DNS_MIN_QUERIES:
            seen = flagged + weak
            review.append({
                "rule": "dns_tunnel",
                "line": seen[0][0].line, "timestamp": seen[0][0].ts_raw,
                "ip": ip, "domain": zone, "reason": "inconclusive",
                "missing": f"only {len(flagged)} qualifying encoded-label queries "
                           f"(threshold {DNS_MIN_QUERIES} within "
                           f"{int(DNS_WINDOW.total_seconds() // 60)} min) under {zone}; "
                           "need more queries, egress byte-volume/resolved-IP reputation, "
                           "or process attribution on the client to confirm exfiltration",
            })
    return findings


# ---------------------------------------------------------------------------
# Rule 3: webshell upload-then-execute
# ---------------------------------------------------------------------------

def detect_webshell(events, review):
    findings = []
    http = [e for e in events if e.etype == "http"]
    by_ip = defaultdict(list)
    for e in http:
        by_ip[e.ip].append(e)

    for ip, rows in sorted(by_ip.items()):
        rows.sort(key=lambda e: e.ts)
        for idx, e in enumerate(rows):
            if not e.path or e.status is None or e.status >= 400:
                continue
            up = _UPLOAD_PATH.search(e.path)
            if not up:
                continue
            # look for a later in-window execution under an uploads directory
            execution = None
            for later in rows[idx + 1:]:
                if later.ts - e.ts > WEBSHELL_WINDOW:
                    break
                if later.status is not None and later.status >= 400:
                    continue
                m = _UPLOADED_EXEC.match(later.path or "")
                if m and _CMD_IN_QS.search(later.path or ""):
                    execution = later
                    break
            if execution is None:
                review.append({
                    "rule": "webshell", "line": e.line, "timestamp": e.ts_raw,
                    "ip": ip, "host": e.host, "path": e.path, "reason": "inconclusive",
                    "missing": f"upload endpoint {e.path} returned {e.status} but no "
                               f"successful request executing a script under /uploads/ "
                               f"with a command parameter followed within "
                               f"{int(WEBSHELL_WINDOW.total_seconds() // 60)} min; need "
                               "the execution request or file-drop telemetry",
                })
                continue
            seq = [_ev_ref(e), _ev_ref(execution)]
            entities = {"ip": ip, "host": e.host,
                        "upload_path": e.path, "shell_path": execution.path}
            findings.append(_finding(
                "webshell", "critical", seq, entities,
                f"{ip} uploaded via {e.path} then executed {execution.path} on {e.host} "
                f"{int((execution.ts - e.ts).total_seconds())}s later",
                "nginx request strings are quoted and contain spaces/spacing varies; the "
                "path and status are extracted inside the quoted request via named groups, "
                "so request formatting cannot shift other fields",
            ))
    return findings


# ---------------------------------------------------------------------------
# Top-level scan
# ---------------------------------------------------------------------------

def scan(path: str) -> dict:
    events: list[Event] = []
    review: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for no, line in enumerate(fh, start=1):
            ev, problem = parse_line(line, no)
            if ev is not None:
                events.append(ev)
            elif problem is not None:
                review.append(problem)

    events.sort(key=lambda e: (e.ts, e.line))
    findings = []
    findings.extend(detect_privilege_escalation(events, review))
    findings.extend(detect_dns_tunnel(events, review))
    findings.extend(detect_webshell(events, review))
    findings.sort(key=lambda f: (f["first_seen"], f["rule"]))
    review.sort(key=lambda r: (r.get("timestamp", ""), r.get("line", 0)))
    return {"findings": findings, "needs_review": review}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log> <out.json>")
        return 2
    result = scan(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(f"{len(result['findings'])} findings, "
          f"{len(result['needs_review'])} needs_review -> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
