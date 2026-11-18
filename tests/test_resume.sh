#!/bin/bash
# Regression: SIGTERM mid-scan must not lose work; --continue finishes it.
#
# Run: bash tests/test_resume.sh
set +e
HERE=$(cd "$(dirname "$0")" && pwd)
SCAN="$HERE/../xss-scan.sh"
W=$(mktemp -d)
PORT=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)
python3 "$HERE/fixtures/server.py" --port "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$W"' EXIT
sleep 1

cat > "$W/list.txt" <<EOF
http://127.0.0.1:$PORT/pos/echo?q=1
http://127.0.0.1:$PORT/pos/attr?q=1
http://127.0.0.1:$PORT/pos/jsbreak?q=1
http://127.0.0.1:$PORT/neg/escaped?q=1
EOF

setsid "$SCAN" -i "$W/list.txt" -o "$W/out" --per-host --no-notify --no-forms-post --no-gau \
  > "$W/first.log" 2>&1 &
PID=$!
sleep 12
kill -TERM -"$PID" 2>/dev/null || kill -TERM "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
echo "interrupted (signal sent)"

"$SCAN" -i "$W/list.txt" -o "$W/out" --per-host --no-notify --no-forms-post --no-gau --continue \
  > "$W/second.log" 2>&1
RC=$?
echo "resume rc=$RC"

python3 - "$W/out/coverage.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as exc:
    print("FAIL: no coverage.json (%s)" % exc)
    raise SystemExit(1)
ok = bool(d.get("complete"))
print(("PASS" if ok else "FAIL") + ": coverage.complete=%s work_complete=%s verification=%s"
      % (d.get("complete"), d.get("work_complete"), d.get("verification_complete")))
raise SystemExit(0 if ok else 1)
PY
