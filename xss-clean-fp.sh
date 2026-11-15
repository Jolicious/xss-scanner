#!/usr/bin/env bash
# xss-clean-fp.sh - re-run the context filter on finished run dirs and re-export.
# Drops findings whose payload only appears inside JSON data blobs
# (__NEXT_DATA__, <script type="application/json">) - those are not XSS.
#
# usage: xss-clean-fp.sh RUN_DIR [RUN_DIR...]
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QHELPER="${QHELPER:-$HERE/xss-queue.py}"
[ $# -gt 0 ] || { echo "usage: $0 RUN_DIR [RUN_DIR...]" >&2; exit 1; }
for d in "$@"; do
  d="${d%/}"
  [ -f "$d/queue.db" ] || { echo "[-] skip $d (no queue.db)"; continue; }
  [ -f "$d/hosts.txt" ] || { echo "[-] skip $d (no hosts.txt for scope)"; continue; }
  echo "[*] $d"
  XSS_SCOPE_HOSTS="$d/hosts.txt" python3 "$QHELPER" ctxfilter "$d/queue.db" 2>&1 | tail -1
  python3 "$QHELPER" export "$d/queue.db" "$d/results.jsonl" 2>/dev/null || true
  python3 "$QHELPER" coverage "$d/queue.db" "$d/coverage.json" 2>/dev/null >/dev/null || true
  [ -x "$HERE/xss-report.py" ] && python3 "$HERE/xss-report.py" "$d" --no-color | sed -n '1,12p'
done
