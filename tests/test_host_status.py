#!/usr/bin/env python3
"""Queue-completion regressions (no network, no browser).

Covers the completion-accounting rules that production review kept breaking:
  * a host with an unplanned reportable finding is not complete
  * a host completes once that finding has a terminal attempt
  * historical attempts are ignored when verification was not requested
  * an SQL error in the unplanned-verification query blocks, not completes
  * api-reflect classifies reflection context instead of matching alert(1)

Run: python3 tests/test_host_status.py
"""
import importlib.util
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
Q = os.path.join(HERE, "..", "xss-queue.py")
if not os.path.exists(Q):
    Q = os.path.join(HERE, "..", "..", "xss-queue.py")

spec = importlib.util.spec_from_file_location("xss_queue", Q)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)

FAILS = []


def check(name, got, want):
    ok = got == want
    print("%s %s: got=%r want=%r" % ("PASS" if ok else "FAIL", name, got, want))
    if not ok:
        FAILS.append(name)


def fresh():
    d = tempfile.mkdtemp()
    db = os.path.join(d, "queue.db")
    hosts = os.path.join(d, "hosts.txt")
    with open(hosts, "w") as fh:
        fh.write("example.test\n")
    c = q.connect(db)
    q.ensure(c)
    c.execute("INSERT INTO urls(url,state) VALUES('https://example.test/?x=1','done')")
    c.execute("INSERT INTO discovery(source,key,status,rc,ts)"
              " VALUES('httpx','all','done',0,'now')")
    c.commit()
    os.environ["XSS_SCOPE_HOSTS"] = hosts
    q.SCOPE_FILE = hosts
    return d, db, hosts, c


def done_hosts(d, db, hosts):
    out = os.path.join(d, "hosts-done.txt")
    q.cmd_host_status(db, hosts, out, "", "")
    with open(out) as fh:
        return fh.read().strip()


def add_finding(c, url, context, template="reflected-param-all-xss"):
    c.execute("INSERT INTO findings(template_id,url,param,sig,json,created,config_id,context)"
              " VALUES(?,?,'q','s','{}','now','cfg',?)", (template, url, context))
    return c.execute("SELECT last_insert_rowid()").fetchone()[0]


# 1. verification requested + no attempt yet -> host incomplete
d, db, hosts, c = fresh()
add_finding(c, "https://example.test/a?q=1", "html")
c.commit()
q.meta_set(c, "verify_requested", 1)
check("unplanned reportable blocks completion", done_hosts(d, db, hosts), "")

# 2. terminal attempt -> host completes
c.execute("INSERT INTO attempts(finding_id,candidate,param_index,param_name,variant,"
          "injected,token,state,evidence)"
          " SELECT id,url,0,'q',0,url,'tok','confirmed','exec-proof' FROM findings")
c.commit()
check("terminal attempt completes host", done_hosts(d, db, hosts), "example.test")

# 3. verification disabled: leftover pending attempt must not block
d, db, hosts, c = fresh()
fid = add_finding(c, "https://example.test/a?q=1", "html")
c.execute("INSERT INTO attempts(finding_id,candidate,param_index,param_name,variant,"
          "injected,token,state) VALUES(?,?,0,'q',0,?,'tok','pending')",
          (fid, "https://example.test/a?q=1", "https://example.test/a?q=1"))
c.commit()
check("verify not requested ignores attempts", done_hosts(d, db, hosts), "example.test")

# 4. filtered historical attempt must not block when verification is requested
d, db, hosts, c = fresh()
fid = add_finding(c, "https://example.test/a?q=1", "escaped")
c.execute("INSERT INTO attempts(finding_id,candidate,param_index,param_name,variant,"
          "injected,token,state) VALUES(?,?,0,'q',0,?,'tok','pending')",
          (fid, "https://example.test/a?q=1", "https://example.test/a?q=1"))
c.commit()
q.meta_set(c, "verify_requested", 1)
check("non-reportable attempt ignored", done_hosts(d, db, hosts), "example.test")

# 5. SQL failure in the unplanned-query must block, never complete
d, db, hosts, c = fresh()
add_finding(c, "https://example.test/a?q=1", "html")
c.commit()
q.meta_set(c, "verify_requested", 1)
real_connect = q.connect


class _Cur(object):
    def __init__(self, cur):
        self._c = cur

    def execute(self, sql, *a):
        if "LEFT JOIN attempts" in sql:
            raise sqlite3.OperationalError("simulated failure")
        return self._c.execute(sql, *a)

    def __getattr__(self, n):
        return getattr(self._c, n)


class _Conn(object):
    def __init__(self, con):
        self._con = con

    def cursor(self):
        return _Cur(self._con.cursor())

    def execute(self, sql, *a):
        return _Cur(self._con.cursor()).execute(sql, *a)

    def __getattr__(self, n):
        return getattr(self._con, n)


q.connect = lambda path: _Conn(real_connect(path))
try:
    check("SQL error fails closed", done_hosts(d, db, hosts), "")
finally:
    q.connect = real_connect

# 6. api-reflect context classifier (comment echo must not become html)
d, db, hosts, c = fresh()
q.SCOPE_FILE = hosts
c.execute("INSERT INTO urls(url,state) VALUES('https://example.test/api/x?q=1','done')")
c.commit()
os.environ["XSS_NO_NET"] = "1"   # no requests: classifier is exercised below
from urllib.parse import urlencode  # noqa: E402

payload = "<script>alert(1)</script>"
inert = "<html><!-- %s --></html>" % payload
live = "<html><div>%s</div></html>" % payload
check("classifier rejects comment echo", q._executable_reflection(inert, payload), False)
check("classifier accepts element echo", q._executable_reflection(live, payload), True)
check("classifier rejects json script echo",
      q._executable_reflection('<script type="application/json">{"q":"%s"}</script>' % payload,
                               payload), False)

print("FAILURES: %s" % (FAILS or "none"))
sys.exit(1 if FAILS else 0)
