#!/bin/bash
# Regression: an explicit --no-notify must survive per-host provider
# auto-discovery, including with a real-looking notify provider config and a
# mocked notify binary on PATH.
#
# Run: bash tests/test_notify.sh
set +e
HERE=$(cd "$(dirname "$0")" && pwd)
SCAN="$HERE/../xss-scan.sh"
W=$(mktemp -d)
PORT=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)
mkdir -p "$W/site" "$W/bin"
printf '<html><body><form method="post" action="/f"><input name="q"></form></body></html>' > "$W/site/index.html"
( cd "$W/site" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$W"' EXIT
sleep 1

printf 'http://127.0.0.1:%s/index.html\n' "$PORT" > "$W/list.txt"
cat > "$W/bin/notify" <<'EOF'
#!/bin/bash
echo "CALLED $*" >> "$NOTIFY_MARKER"
exit 0
EOF
chmod +x "$W/bin/notify"
cat > "$W/provider-config.yaml" <<'EOF'
slack:
  - id: "mock-provider"
    channel: "#test"
    username: "xss-scanner"
    webhook-url: "https://example.invalid/hook"
EOF

PATH="$W/bin:$PATH" NOTIFY_CONFIG="$W/provider-config.yaml" \
  NOTIFY_MARKER="$W/notify-called.txt" \
  timeout 300 "$SCAN" -i "$W/list.txt" -o "$W/out" --per-host --no-notify \
  > "$W/run.log" 2>&1
RC=$?
[ "$RC" -eq 0 ] || echo "note: scanner rc=$RC (log: $W/run.log)"

FAIL=0
if [ -s "$W/notify-called.txt" ]; then
  echo "FAIL: notify invoked despite --no-notify"
  cat "$W/notify-called.txt"
  FAIL=1
fi
if grep -q "auto: notify enabled" "$W/run.log"; then
  echo "FAIL: provider auto-enabled despite --no-notify"
  FAIL=1
fi
if ! grep -q "tls: verify=on" "$W/run.log"; then
  echo "FAIL: TLS verification not reported as on by default"
  FAIL=1
fi
[ "$FAIL" -eq 0 ] && echo "PASS: --no-notify held in per-host mode; TLS verify on by default"
exit "$FAIL"
