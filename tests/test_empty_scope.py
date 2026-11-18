import importlib.util, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
Q = os.path.join(HERE, "..", "xss-queue.py")
spec = importlib.util.spec_from_file_location("q", Q)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)

d = tempfile.mkdtemp()
db = os.path.join(d, "q.db")
scope = os.path.join(d, "h.txt")
open(scope, "w").write("empty.test\n")
os.environ["XSS_SCOPE_HOSTS"] = scope
q.SCOPE_FILE = scope
c = q.connect(db)
q.ensure(c)
out = os.path.join(d, "cov.json")

q.cmd_coverage(db, out)
import json
cov = json.load(open(out))
print("empty host  : complete=%s nothing_to_test=%s"
      % (cov["complete"], cov.get("nothing_to_test")))
assert cov["complete"] is True, "empty host must be terminal complete"
assert cov.get("nothing_to_test") is True

c.execute("insert into urls(url,state) values('https://empty.test/a?x=1','pending')")
c.commit()
q.cmd_coverage(db, out)
cov = json.load(open(out))
print("pending url : complete=%s query_complete=%s"
      % (cov["complete"], cov["query_complete"]))
assert cov["complete"] is False, "pending work must block completion"
print("PASS empty-scope completion")
