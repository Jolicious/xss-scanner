#!/usr/bin/env python3
"""xss-report.py - human-readable, colour-coded report for an xss-scan run.

Usage:
  xss-report.py [RUN_DIR] [--all] [--no-body] [--no-color] [--limit N]

  RUN_DIR     run directory (default: newest xss-scan-*/ or ./out)
  --all       also list refuted (not_confirmed) endpoints
  --no-body   hide manual body/form/JSON reflection candidates
  --no-color  disable ANSI colour (auto-disabled when piped or NO_COLOR set)
  --limit N   max rows per section (default 40; 0 = all)

Exit: 0 always (report only).
"""

import glob
import json
import os
import sys
from urllib.parse import urlsplit

ALL = False
SHOW_BODY = True
LIMIT = 40
USE_COLOR = sys.stdout.isatty()
pos = []

argv = sys.argv[1:]
i = 0
while i < len(argv):
    a = argv[i]
    if a == "--all":
        ALL = True
    elif a == "--no-color":
        USE_COLOR = False
    elif a == "--no-body":
        SHOW_BODY = False
    elif a == "--limit":
        i += 1
        try:
            LIMIT = int(argv[i])
        except (IndexError, ValueError):
            LIMIT = 40
    elif a in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    else:
        pos.append(a)
    i += 1

if os.environ.get("NO_COLOR"):
    USE_COLOR = False


def c(code, text):
    return "\033[%sm%s\033[0m" % (code, text) if USE_COLOR else str(text)


GREEN = lambda s: c("1;32", s)
RED = lambda s: c("1;31", s)
YELLOW = lambda s: c("1;33", s)
DIM = lambda s: c("2", s)
BOLD = lambda s: c("1", s)


def pick_dir(arg):
    if arg:
        return arg
    for cand in ("out", "run1", "xss-scan"):
        if os.path.isdir(cand):
            return cand
    hits = sorted(glob.glob("xss-scan-*"), key=os.path.getmtime)
    return hits[-1] if hits else "."


RUN = pick_dir(pos[0] if pos else None)
if not os.path.isdir(RUN):
    print(RED("no such run directory: %s" % RUN))
    sys.exit(1)


def load_jsonl(name):
    p = os.path.join(RUN, name)
    out = []
    if os.path.exists(p):
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    return out


cov = {}
cov_p = os.path.join(RUN, "coverage.json")
if os.path.exists(cov_p):
    try:
        cov = json.load(open(cov_p, encoding="utf-8"))
    except Exception:
        cov = {}

verify = load_jsonl("verify-report.jsonl")
results = load_jsonl("results.jsonl")

confirmed = [d for d in verify if d.get("status") == "confirmed"]
manual = [r for r in results if r.get("template-id") == "reflected-body-xss"]
refuted = [d for d in verify if d.get("status") == "not_confirmed"]
problems = [d for d in verify if d.get("status") in
            ("verification_error", "inconclusive_heuristic", "inconclusive")]


def route(url):
    """endpoint identity: scheme://host[:port]/path (no payload query)."""
    try:
        sp = urlsplit(url)
        return "%s://%s%s" % (sp.scheme, sp.netloc, sp.path)
    except ValueError:
        return url


def group_confirmed(rows):
    groups = {}
    for d in rows:
        att = [a for a in d.get("attempts", []) if a.get("status") == "confirmed"]
        if not att:
            continue
        param = att[0].get("param") or "-"
        key = (route(d.get("url", "")), param)
        g = groups.setdefault(key, {"url": key[0], "param": param, "hits": 0,
                                    "proofs": [], "strategy": att[0].get("strategy") or "query"})
        g["hits"] += 1
        p = att[0].get("proof") or att[0].get("evidence")
        if p and p not in g["proofs"]:
            g["proofs"].append(p)
    return sorted(groups.values(), key=lambda g: (g["url"], g["param"]))


def row_limit(rows):
    return rows if LIMIT <= 0 else rows[:LIMIT]


print()
print(BOLD("xss-scan report") + DIM("  " + os.path.abspath(RUN)))
if cov:
    flags = [("complete", cov.get("complete")),
             ("discovery", cov.get("discovery_complete")),
             ("query", cov.get("query_complete")),
             ("path", cov.get("path_complete")),
             ("body", cov.get("body_complete")),
             ("verification", cov.get("verification_complete"))]
    print("  ".join(GREEN("%s ✓" % k) if v else
                    (DIM("%s –" % k) if v is None else RED("%s ✗" % k))
                    for k, v in flags))
    if cov.get("verification_skipped"):
        print("  " + YELLOW("verification not requested — candidates are unproven (re-run with --verify)"))
    if cov.get("verification_capped"):
        print("  " + YELLOW("verification capped: %s candidate(s) not verified" % cov["verification_capped"]))
    if cov.get("verification_unplanned"):
        print("  " + YELLOW("unplanned candidates: %s" % cov["verification_unplanned"]))
    if cov.get("urls_capped"):
        print("  " + YELLOW("deferred URLs: %s" % cov["urls_capped"]))
    if cov.get("jobs_capped"):
        print("  " + YELLOW("deferred jobs: %s" % cov["jobs_capped"]))
    print("  " + DIM("findings=%s  confirmed=%s  manual=%s"
                     % (cov.get("findings", "?"), cov.get("confirmed_candidates", "?"),
                        cov.get("manual_confirmation_required", "?"))))
print()

groups = group_confirmed(confirmed)
print(GREEN("CONFIRMED XSS") + (DIM("  (%d endpoint/param, %d proven request%s)"
                                    % (len(groups), len(confirmed),
                                       "" if len(confirmed) == 1 else "s")))
      if groups else GREEN("CONFIRMED XSS") + DIM("  (0)"))
if groups:
    for g in row_limit(groups):
        extra = ""
        if len(g["proofs"]) > 1:
            extra = DIM("  +%d more payload(s)" % (len(g["proofs"]) - 1))
        print("  " + GREEN("✓") + " " + g["url"])
        print("    " + DIM("param=") + BOLD(g["param"]) +
              DIM("  strategy=") + str(g["strategy"]) +
              DIM("  proof=") + str(g["proofs"][0] if g["proofs"] else "-") + extra)
    if LIMIT > 0 and len(groups) > LIMIT:
        print(DIM("  ... %d more (use --limit 0)" % (len(groups) - LIMIT)))
elif not cov.get("verification_requested"):
    print(DIM("  verification was not requested for this run"))
print()

if manual and SHOW_BODY:
    mg = {}
    for r in manual:
        key = (route(r.get("url") or r.get("matched-at") or ""), r.get("param") or "-")
        g = mg.setdefault(key, {"url": key[0], "param": key[1],
                                "method": r.get("method") or "?",
                                "evidence": r.get("evidence"), "hits": 0,
                                "req_file": r.get("request_file") or "",
                                "payload": r.get("payload") or "",
                                "raw_url": r.get("url") or ""})
        g["hits"] += 1
        if not g["req_file"] and r.get("request_file"):
            g["req_file"] = r["request_file"]
    print(YELLOW("MANUAL CONFIRMATION NEEDED — body/form/JSON reflection  (%d)" % len(mg)))
    for g in row_limit(sorted(mg.values(), key=lambda x: x["url"])):
        print("  " + YELLOW("⚠") + " " + g["method"] + " " + g["url"])
        print("    " + DIM("param=") + BOLD(g["param"]) +
              DIM("  reflected=") + str(g["evidence"]) +
              (DIM("  +%d more" % (g["hits"] - 1)) if g["hits"] > 1 else ""))
        if g["req_file"]:
            print("    " + DIM("request: ") + g["req_file"] + DIM("  (raw HTTP, paste into Burp Repeater)"))
    print()

if problems:
    print(RED("VERIFICATION PROBLEMS  (%d)" % len(problems)))
    for d in row_limit(sorted(problems, key=lambda x: x.get("url", ""))):
        print("  " + RED("!") + " " + d.get("url", "?")[:140] +
              DIM("  " + str(d.get("status"))))
    print()

if ALL and refuted:
    print(DIM("REFUTED — verified, no execution  (%d)" % len(refuted)))
    for d in row_limit(sorted(refuted, key=lambda x: x.get("url", ""))):
        print(DIM("  ✗ " + d.get("url", "?")[:140]))
    print()

if not groups and not manual:
    if cov.get("verification_requested"):
        print(DIM("no confirmed findings and no manual candidates in this run"))
    else:
        cand = [r for r in results if r.get("template-id") != "reflected-body-xss"]
        print(YELLOW("CANDIDATES ONLY  (%d)" % len(cand)))
        seen = set()
        shown = 0
        for r in cand:
            u = r.get("matched-at") or r.get("url") or ""
            base = route(u)
            if base in seen:
                continue
            seen.add(base)
            print("  " + DIM("• ") + base + DIM("  via " + str(r.get("template-id"))))
            shown += 1
            if LIMIT > 0 and shown >= LIMIT:
                print(DIM("  ... %d more (use --limit 0)" % (len(cand) - shown)))
                break
        print(DIM("  these are reflections, not proven XSS — run with --verify"))
    print()

print(DIM("files: results.jsonl  verify-report.jsonl  confirmed.jsonl  coverage.json"))
