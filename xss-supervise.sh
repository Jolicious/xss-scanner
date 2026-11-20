#!/usr/bin/env bash
# xss-supervise.sh - keep a scan alive until it actually finishes.
#
#   xss-supervise.sh -i list.txt -o out --per-host --per-host-jobs 3 ...
#
# The scanner resumes from its own queue, so a dropped ssh session, a killed
# child, an OOM or a Ctrl+C only costs a restart: this loop re-runs the same
# command with --continue until coverage.complete=true, the STOP file appears,
# or MAX_TRIES unrelated failures pile up.
#
# stop conditions:
#   exit 0                     -> run complete
#   $OUT/STOP exists           -> operator asked to stop
#   $OUT/coverage.json true    -> complete even if exit code was odd
set -uo pipefail

SCAN="${XSS_SCAN_BIN:-xss-scan}"
MAX_TRIES="${MAX_TRIES:-50}"          # consecutive non-progress restarts
SLEEP_SECS="${SLEEP_SECS:-60}"
OUT=""; HAVE_CONTINUE=0
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out)   OUT="${2:-}"; ARGS+=("$1" "$2"); shift 2;;
    --continue) HAVE_CONTINUE=1; ARGS+=("$1"); shift;;
    --no-resume) ARGS+=("--continue"); shift;;   # a supervisor always resumes
    *) ARGS+=("$1"); shift;;
  esac
done
# no -o: nothing to supervise (the scanner would invent a timestamped dir and
# a restart would create a second one), so run once and pass the exit code on
if [ -z "$OUT" ]; then
  exec "$SCAN" "${ARGS[@]}"
fi
[ "$HAVE_CONTINUE" = 1 ] || ARGS+=("--continue")

log() { printf '[supervise %s] %s\n' "$(date +%H:%M:%S)" "$*"; }

stamp() {  # progress signal: queue + result counters, not just exit code
  local q="$OUT/queue.db" f
  f="$OUT/queue.db"
  [ -f "$f" ] || f=$(ls "$OUT"/.parts/*/queue.db 2>/dev/null | head -1)
  {
    [ -f "$OUT/results.jsonl" ] && wc -l < "$OUT/results.jsonl" || echo 0
    [ -n "${f:-}" ] && [ -f "$f" ] && python3 - "$f" <<'PY' 2>/dev/null || true
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
u = c.execute("SELECT COUNT(*) FROM urls WHERE state='done'").fetchone()[0]
j = c.execute("SELECT COUNT(*) FROM jobs WHERE state='done'").fetchone()[0]
print(j + u)
PY
  } | tr '\n' ' '
}

complete() {
  python3 - "$OUT/coverage.json" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if d.get("complete") else 1)
PY
}

TRY=0; SAME=0; LAST=""
while :; do
  if [ -f "$OUT/STOP" ]; then log "STOP file present: exiting"; exit 0; fi
  if complete; then log "coverage.complete=true: done"; exit 0; fi
  TRY=$((TRY + 1))
  log "attempt $TRY (same-progress restarts: $SAME/$MAX_TRIES)"
  "$SCAN" "${ARGS[@]}"
  RC=$?
  if [ "$RC" -eq 0 ]; then
    if complete; then log "finished (rc=0)"; exit 0; fi
    log "rc=0 but coverage incomplete; will resume"
  else
    log "scanner exited rc=$RC"
  fi
  if [ -f "$OUT/STOP" ]; then log "STOP file present: exiting"; exit 0; fi
  if complete; then log "coverage.complete=true after rc=$RC: done"; exit 0; fi
  NOW=$(stamp)
  if [ "$NOW" = "$LAST" ]; then SAME=$((SAME + 1)); else SAME=0; LAST="$NOW"; fi
  if [ "$SAME" -ge "$MAX_TRIES" ]; then
    log "no progress across $SAME restarts; giving up"
    exit 3
  fi
  log "restarting in ${SLEEP_SECS}s (progress marker: ${NOW:-none})"
  sleep "$SLEEP_SECS"
done
