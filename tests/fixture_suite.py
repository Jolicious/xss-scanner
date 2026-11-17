#!/usr/bin/env python3
"""Acceptance suite for the browser confirmation contract.

Runs the real Nuclei headless verifier against fixtures that reflect a payload
into executable and non-executable contexts, then asserts:

  * executable contexts yield the exec-proof token (real Chromium execution)
  * inert contexts never yield a token
  * a redirect to an out-of-scope host is refused before navigation

Requires: nuclei (>=3.11) and chromium on PATH, or CHROME_PATH set.
Exit codes: 0 pass, 1 failure, 77 skipped (tools missing).

    python3 tests/fixture_suite.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TPL = os.path.join(ROOT, "xss-headless-verify.yaml")
SERVER = os.path.join(HERE, "fixtures", "server.py")
Q = os.path.join(ROOT, "xss-queue.py")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def js_string(tok):
    return "String.fromCharCode(%s)" % ",".join(str(ord(c)) for c in tok)


def payload_variant(variant, tok):
    js = js_string(tok)
    return {
        0: '"><svg/onload=document.body.dataset.pwn=%s>' % js,
        1: "'><svg/onload=document.body.dataset.pwn=%s>" % js,
        2: '";document.body.dataset.pwn=%s//' % js,
    }[variant]


def wait_up(url, tries=50):
    for _ in range(tries):
        try:
            urllib.request.urlopen(url, timeout=1).read(64)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def token_for(name):
    # deterministic, 12 hex chars as required by the template regex
    import hashlib
    return "XSS_CONFIRMED_" + hashlib.sha1(name.encode()).hexdigest()[:12]


def queue_checks(port):
    """Scope and evidence gates, exercised against the live fixture server."""
    import importlib.util
    out = []
    spec = importlib.util.spec_from_file_location("xss_queue", Q)
    q = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(q)
    d = tempfile.mkdtemp()
    db = os.path.join(d, "q.db")
    scope = os.path.join(d, "hosts.txt")
    with open(scope, "w") as fh:
        fh.write("127.0.0.1:%d\n" % port)
    os.environ["XSS_SCOPE_HOSTS"] = scope
    q.SCOPE_FILE = scope
    c = q.connect(db)
    q.ensure(c)
    osc = "http://127.0.0.1:%d/landing" % (port + 1)   # never in scope
    cand = "http://127.0.0.1:%d/redirect/out/%d?q=1" % (port, port + 1)
    c.execute("INSERT INTO findings(template_id,url,param,sig,json,created,config_id,context)"
              " VALUES('reflected-param-all-xss',?,'q','s','{}','now','cfg','html')", (cand,))
    c.commit()
    q.cmd_verify_plan(db, "50")
    lst = os.path.join(d, "a.txt")
    ids = os.path.join(d, "a.ids")
    n = q.cmd_verify_batch(db, "10", lst, ids)
    emitted = len([l for l in open(lst) if l.strip()])
    rows = q.connect(db).execute(
        "SELECT state, COALESCE(evidence,'') FROM attempts").fetchall()
    out.append(("out-of-scope redirect never reaches browser",
                n == 0 and emitted == 0
                and all(st == "error" and "out_of_scope" in ev for st, ev in rows)))

    # wrong extractor: a dom-context hit is not execution proof
    d2 = tempfile.mkdtemp()
    db2 = os.path.join(d2, "q.db")
    c2 = q.connect(db2)
    q.ensure(c2)
    q.SCOPE_FILE = scope
    tok = "XSS_CONFIRMED_" + "a" * 12
    inj = "http://127.0.0.1:%d/pos/echo?q=1" % port
    c2.execute("INSERT INTO attempts(candidate,param_index,param_name,variant,injected,"
               "token,state) VALUES(?,0,'q',0,?,?,'running')", (inj, inj, tok))
    c2.commit()
    rid = c2.execute("SELECT id FROM attempts").fetchone()[0]
    ids2 = os.path.join(d2, "b.ids")
    open(ids2, "w").write("%d\n" % rid)
    jl = os.path.join(d2, "b.jsonl")
    rec = {"template-id": "xss-headless-verify", "type": "headless",
           "extractor-name": "dom-context", "matched-at": inj, "url": inj,
           "extracted-results": [tok]}
    open(jl, "w").write(json.dumps(rec) + "\n")
    q.cmd_verify_commit(db2, jl, ids2, "0")
    st = q.connect(db2).execute("SELECT state FROM attempts WHERE id=?", (rid,)).fetchone()[0]
    out.append(("wrong extractor rejected", st == "not_confirmed"))
    return out


def main():
    nuclei = shutil.which("nuclei")
    chrome = os.environ.get("CHROME_PATH") or shutil.which("chromium") \
        or shutil.which("chromium-browser") or shutil.which("google-chrome")
    if not nuclei or not chrome:
        print("SKIP: nuclei=%r chrome=%r" % (nuclei, chrome))
        return 77

    port = free_port()
    srv = subprocess.Popen([sys.executable, SERVER, "--port", str(port)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    fails = []
    try:
        if not wait_up(base + "/pos/echo?q=1"):
            print("FAIL: fixture server did not start")
            return 1

        cases = [
            # name, path, variant, expect_execution
            ("pos-echo-html", "/pos/echo", 0, True),
            ("pos-attr-double-quote", "/pos/attr", 0, True),
            ("pos-js-string-breakout", "/pos/jsbreak", 2, True),
            ("neg-escaped", "/neg/escaped", 0, False),
            ("neg-json-script", "/neg/json", 0, False),
            ("neg-comment", "/neg/comment", 0, False),
            ("neg-textarea", "/neg/textarea", 0, False),
            ("neg-template", "/neg/template", 0, False),
            ("neg-js-string-escaped", "/neg/jsstring", 2, False),
            ("neg-attr-no-handler", "/neg/wrongtoken", 0, False),
        ]

        urls, tokens = [], {}
        for name, path, variant, _ in cases:
            tok = token_for(name)
            tokens[name] = tok
            inj = base + path + "?q=" + urllib.parse.quote(payload_variant(variant, tok), safe="")
            urls.append((name, inj))

        wd = tempfile.mkdtemp()
        listf = os.path.join(wd, "urls.txt")
        out = os.path.join(wd, "out.jsonl")
        with open(listf, "w") as fh:
            for _, u in urls:
                fh.write(u + "\n")

        env = dict(os.environ)
        env.setdefault("CHROME_PATH", chrome)
        cmd = [nuclei, "-l", listf, "-headless", "-t", TPL, "-silent", "-jsonl",
               "-o", out, "-timeout", "3", "-retries", "0"]
        print("running: " + " ".join(cmd))
        rc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=900).returncode
        if rc != 0:
            print("note: nuclei rc=%d" % rc)

        got = {}
        if os.path.exists(out):
            for line in open(out, encoding="utf-8", errors="replace"):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                url = rec.get("matched-at") or rec.get("url") or ""
                # one match emits several extractor records; only exec-proof counts
                if (rec.get("extractor-name") or "") != "exec-proof":
                    continue
                for v in (rec.get("extracted-results") or []):
                    got.setdefault(url, set()).add(str(v).strip())

        for name, inj in urls:
            tok = tokens[name]
            proven = tok in got.get(inj, set())
            want = dict((n, e) for n, _, _, e in cases)[name]
            ok = proven == want
            print("%s %s: proven=%s want=%s" % ("PASS" if ok else "FAIL", name, proven, want))
            if not ok:
                fails.append(name)

        for name, ok in queue_checks(port):
            print("%s %s" % ("PASS" if ok else "FAIL", name))
            if not ok:
                fails.append(name)
        return 1 if fails else 0
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except Exception:
            srv.kill()


if __name__ == "__main__":
    sys.exit(main())
