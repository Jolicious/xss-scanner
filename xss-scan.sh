#!/usr/bin/env bash
# xss-scan.sh v18 - coloured report, human-readable notify messages.
# xss-scan.sh v12 - queue-driven XSS scan; fail-closed scope, path-bound verification.
# xss-scan.sh v11 - queue-driven XSS scan; deferred caps, path verification.
#
# Input: one subdomain/URL per line, scheme optional.
#   example.com
#   example.com:8443
#   https://example.com/app?x=1
#
# Usage: ./xss-scan.sh -i list.txt [options]
#
#   -i, --input FILE      input list (required)
#   -o, --out DIR         work dir; reusing it resumes (default xss-scan-<ts>)
#   -t, --templates DIR   nuclei template dir (default: script dir)
#   -r, --rate N          nuclei req/sec (default 150)
#   -c, --conc N          nuclei concurrency (default 25)
#   -H, --header 'K: V'   extra header, repeatable (httpx/katana/nuclei/probe)
#   -b, --cookie STRING   Cookie header
#   -T, --token STRING    bearer token (adds Authorization: Bearer <token>)
#       --token-file FILE read bearer token from a file (keeps it off argv)
#   env XSS_TOKEN / XSS_COOKIE are also honoured
#       --crawl           add katana discovery
#       --no-gau          skip gau
#       --rediscover      redo discovery sources marked done
#       --batch-size N    urls per query batch (default 10000)
#       --path-batch N    path targets per batch (default 5000)
#       --max-urls N      alias for --batch-size
#       --max-total N     global unique-URL cap (0 = all)
#       --max-jobs N      global cap on path+body jobs (0 = all)
#       --max-disk-mb N   pause before a batch above N MB (default 2048)
#       --forms           discover HTML forms and probe GET forms
#       --forms-post      probe POST forms (default on; state-changing risk)
#       --no-forms-post   disable POST form probing for read-only engagements
#       --form-max N      max pages parsed for forms (default 200)
#       --json-file F     JSON body targets, one JSON spec per line
#       --body-batch N    body targets per batch (default 100)
#       --verify          headless confirmation (query params)
#       --reverify        clear attempts and verify again
#       --verify-max N    max candidate URLs to verify (default 200)
#       --verify-batch N  attempts per headless run (default 100)
#       --no-resume       archive the previous run, start clean
#       --retry-failed    requeue failed urls/jobs/attempts
#       --force-config    continue even if scope/templates differ from the run
#       --amend-limits    update stored max-total/max-jobs without full override
#       --strict          exit on scanner error (default)
#       --lenient         continue after scanner errors
#       --compact         delete queue.db + logs once coverage is complete
#       --report          print the coloured summary at the end (default on)
#       --no-report       skip the summary
#       --notify          send confirmed findings via ProjectDiscovery notify
#       --notify-id ID    notify provider id, repeatable (e.g. discord, slack)
#       --notify-config F notify provider-config path
#       --notify-summary  also send a run summary (including 0 findings)
#   -h, --help
#
# Evidence model: a verification attempt is "confirmed" only when the headless
# run reports its exact random token inside the rendered DOM (data-pwn="<token>")
# or as an exact extracted-results entry. The payload builds that token with
# String.fromCharCode, so a reflected URL/response can never contain it.
# Scope model: forms, JSON specs, and every outbound body probe are checked
# against the same host:port allowlist; redirects are never followed.
#
# Requires: ProjectDiscovery httpx, ProjectDiscovery nuclei, python3.
#   xss-queue.py must sit next to this script.
# Optional: gau, katana, jq.

set -uo pipefail
exec 3>&1
ORIG_ARGS=("$@")

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TPL_DIR="${TPL_DIR:-$SELF_DIR}"
QHELPER="${QHELPER:-$SELF_DIR/xss-queue.py}"

# ---------- stop handling (Ctrl+C / SIGTERM / STOP file) ----------
STOP_REQUESTED=0
stop_children() {
  local child
  for child in $(pgrep -P $$ 2>/dev/null); do
    kill -TERM "$child" 2>/dev/null
  done
  sleep 1
  for child in $(pgrep -P $$ 2>/dev/null); do
    kill -KILL "$child" 2>/dev/null
  done
}
on_stop() {
  [ "$STOP_REQUESTED" = 1 ] && exit 130
  STOP_REQUESTED=1
  trap - INT TERM
  echo "" >&2
  warn "stopping: killing running stages"
  stop_children
  if [ -n "${OUT:-}" ] && [ -f "${Q:-}" ] && [ -f "$QHELPER" ]; then
    python3 "$QHELPER" reset "$Q" >/dev/null 2>&1 || true
    warn "in-progress work returned to the queue"
  fi
  [ -n "${OUT:-}" ] && echo "[*] resume later with: $0 -i ${IN:-<list>} -o $OUT $*" >&2
  echo "[*] stopped (exit 130)" >&2
  exit 130
}
trap on_stop INT TERM

IN=""; OUT=""
RATE_ENV="${RATE:+1}"; CONC_ENV="${CONC:+1}"
RATE="${RATE:-150}"; CONC="${CONC:-25}"; THREADS="${THREADS:-50}"
BATCH_SIZE="${BATCH_SIZE:-10000}"
PATH_BATCH="${PATH_BATCH:-2000}"
BODY_BATCH="${BODY_BATCH:-100}"
MAX_TOTAL="${MAX_TOTAL:-0}"
MAX_JOBS="${MAX_JOBS:-0}"
MAX_DISK_MB="${MAX_DISK_MB:-2048}"
VERIFY_MAX="${VERIFY_MAX:-200}"
VERIFY_BATCH="${VERIFY_BATCH:-100}"
FORM_MAX="${FORM_MAX:-0}"
STEP_TIMEOUT="${STEP_TIMEOUT:-1800}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-3600}"
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-900}"
DO_GAU=1; DO_CRAWL=1; DO_VERIFY=0; DO_FORMS=1; FORMS_POST=1; DO_JS=1
VERIFY_EXPLICIT=0; RATE_SET=0; CONC_SET=0; DISK_SET=0; NOTIFY_EXPLICIT=0
COMPACT=0; RESUME=1; RETRY_FAILED=0; STRICT=1; REDISCOVER=0
SILENT=0; PER_HOST=0; PER_HOST_CHUNK=1; DO_SITEMAP=1
REVERIFY=0; FORCE_CONFIG=0; AMEND_LIMITS=0; DO_REPORT=1
NOTIFY=0; NOTIFY_SUMMARY=0; NOTIFY_LIVE=1; NOTIFY_SENT_ANY=0; NOTIFY_IDS=(); NOTIFY_CANDIDATES=1
NOTIFY_CONFIG="${NOTIFY_CONFIG:-$HOME/.config/notify/provider-config.yaml}"
JSON_FILE=""
HDRS=(); COOKIE=""; TOKEN=""; TOKEN_FILE=""

die() { echo "[-] $*" >&2; [ "${SILENT:-0}" = 1 ] && echo "[-] $*" >&3; exit 1; }
warn() { echo "[!] $*" >&2; }
# findings go to the terminal even when chatter is redirected
emit() { if [ "$SILENT" = 1 ]; then cat >&3; else cat; fi; }
say()  { [ "${PER_HOST_CHILD:-0}" = 1 ] && return 0
         if [ "$SILENT" = 1 ]; then echo "[*] $*" >&3; else echo "[*] $*"; fi; }
usage() { awk 'NR>1 && /^set -uo/{exit} NR>1 {sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -i|--input)       IN="${2:-}"; shift 2;;
    -o|--out)         OUT="${2:-}"; shift 2;;
    -t|--templates)   TPL_DIR="${2:-}"; shift 2;;
    -r|--rate)        RATE="${2:-}"; RATE_SET=1; shift 2;;
    -c|--conc)        CONC="${2:-}"; CONC_SET=1; shift 2;;
    -H|--header)      HDRS+=("${2:-}"); shift 2;;
    -b|--cookie)      COOKIE="${2:-}"; shift 2;;
    -T|--token)       TOKEN="${2:-}"; shift 2;;
    --token-file)     TOKEN_FILE="${2:-}"; shift 2;;
    --crawl)          DO_CRAWL=1; shift;;
    --no-crawl)       DO_CRAWL=0; shift;;
    --no-gau)         DO_GAU=0; shift;;
    --no-js)          DO_JS=0; shift;;
    --no-sitemap)     DO_SITEMAP=0; shift;;
    -q|--silent|--quiet) SILENT=1; shift;;
    --per-host)       PER_HOST=1; shift;;
    --per-host-chunk) PER_HOST=1; PER_HOST_CHUNK="${2:-1}"; shift 2;;
    --rediscover)     REDISCOVER=1; shift;;
    --batch-size)     BATCH_SIZE="${2:-}"; shift 2;;
    --path-batch)     PATH_BATCH="${2:-}"; shift 2;;
    --body-batch)     BODY_BATCH="${2:-}"; shift 2;;
    --max-urls)       BATCH_SIZE="${2:-}"; warn "--max-urls is per-batch now (alias of --batch-size)"; shift 2;;
    --max-total)      MAX_TOTAL="${2:-}"; shift 2;;
    --max-jobs)       MAX_JOBS="${2:-}"; shift 2;;
    --max-disk-mb)    MAX_DISK_MB="${2:-}"; DISK_SET=1; shift 2;;
    --forms)          DO_FORMS=1; shift;;
    --forms-post)     DO_FORMS=1; FORMS_POST=1; shift;;
    --no-forms-post)  FORMS_POST=0; shift;;
    --form-max)       FORM_MAX="${2:-}"; shift 2;;
    --json-file)      JSON_FILE="${2:-}"; shift 2;;
    --verify)         DO_VERIFY=1; VERIFY_EXPLICIT=1; shift;;
    --no-verify)      DO_VERIFY=0; VERIFY_EXPLICIT=1; shift;;
    --no-forms)       DO_FORMS=0; shift;;
    --reverify)       DO_VERIFY=1; VERIFY_EXPLICIT=1; REVERIFY=1; shift;;
    --verify-max)     VERIFY_MAX="${2:-}"; shift 2;;
    --verify-batch)   VERIFY_BATCH="${2:-}"; shift 2;;
    --no-resume)      RESUME=0; shift;;
    --retry-failed)   RETRY_FAILED=1; shift;;
    --force-config)   FORCE_CONFIG=1; shift;;
    --amend-limits)   AMEND_LIMITS=1; shift;;
    --strict)         STRICT=1; shift;;
    --lenient)        STRICT=0; shift;;
    --compact)        COMPACT=1; shift;;
    --report)         DO_REPORT=1; shift;;
    --no-report)      DO_REPORT=0; shift;;
    --notify)         NOTIFY=1; NOTIFY_EXPLICIT=1; shift;;
    --no-notify)      NOTIFY=0; NOTIFY_EXPLICIT=1; shift;;
    --notify-id)      NOTIFY_IDS+=("${2:-}"); NOTIFY_EXPLICIT=1; shift 2;;
    --notify-config)  NOTIFY_CONFIG="${2:-}"; shift 2;;
    --notify-summary) NOTIFY=1; NOTIFY_SUMMARY=1; shift;;
    --notify-live)    NOTIFY=1; NOTIFY_LIVE=1; shift;;
    --no-notify-live) NOTIFY_LIVE=0; shift;;
    --notify-candidates) NOTIFY_CANDIDATES=1; shift;;
    --no-notify-candidates) NOTIFY_CANDIDATES=0; shift;;
    -h|--help)        usage; exit 0;;
    *) die "unknown arg: $1 (use -h)";;
  esac
done

[ -n "$IN" ] || { usage; die "need -i <file>"; }
[ -f "$IN" ] || die "input not found: $IN"
[ -d "$TPL_DIR" ] || die "templates dir not found: $TPL_DIR"
[ -f "$QHELPER" ] || die "helper not found: $QHELPER (must sit next to this script)"
for n in "$RATE" "$CONC" "$THREADS" "$BATCH_SIZE" "$PATH_BATCH" "$BODY_BATCH" \
         "$MAX_TOTAL" "$MAX_JOBS" "$MAX_DISK_MB" "$VERIFY_MAX" "$VERIFY_BATCH" "$FORM_MAX"; do
  case "$n" in ''|*[!0-9]*) die "numeric option expected, got '$n'";; esac
done
[ "$BATCH_SIZE" -gt 0 ] || die "--batch-size must be > 0"
command -v python3 >/dev/null 2>&1 || die "missing python3"

pick_bin() {
  local want="$2" c
  if [ -n "${1:-}" ]; then printf '%s' "$1"; return 0; fi
  for c in "$HOME/go/bin/$want" "$(command -v "$want" 2>/dev/null || true)" /usr/local/bin/"$want" /usr/bin/"$want"; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    if "$c" -version 2>&1 | grep -qiE 'projectdiscovery|nuclei engine'; then
      printf '%s' "$c"; return 0
    fi
  done
  return 1
}
HTTPX_BIN="$(pick_bin "${HTTPX_BIN:-}" httpx)"  || die "no ProjectDiscovery httpx (pip httpx does not count). Set HTTPX_BIN="
NUCLEI_BIN="$(pick_bin "${NUCLEI_BIN:-}" nuclei)" || die "no ProjectDiscovery nuclei. Set NUCLEI_BIN="
[ "$SILENT" = 0 ] && echo "[*] httpx:  $HTTPX_BIN"
[ "$SILENT" = 0 ] && echo "[*] nuclei: $NUCLEI_BIN"

HAVE_GAU=0;    command -v gau    >/dev/null 2>&1 && HAVE_GAU=1
HAVE_CURL=0;   command -v curl   >/dev/null 2>&1 && HAVE_CURL=1
HAVE_KATANA=0; command -v katana >/dev/null 2>&1 && HAVE_KATANA=1
HAVE_JQ=0;     command -v jq     >/dev/null 2>&1 && HAVE_JQ=1
[ "$HAVE_GAU" = 1 ] || DO_GAU=0
[ "$HAVE_CURL" = 1 ] || DO_JS=0
[ "$DO_GAU" = 1 ] || [ "$SILENT" = 1 ] || warn "gau disabled/unavailable - seed + crawl URLs only"
if [ "$DO_CRAWL" = 1 ] && [ "$HAVE_KATANA" = 0 ]; then
  warn "katana not found - crawl skipped"; DO_CRAWL=0
fi
[ -n "$JSON_FILE" ] && [ ! -f "$JSON_FILE" ] && die "--json-file not found: $JSON_FILE"

OUT="${OUT:-xss-scan-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT" || die "cannot create $OUT"
LOGS="$OUT/logs"; mkdir -p "$LOGS"

# single reusable buffer for tool URL output: tools write with ">", the buffer
# is truncated right after ingest, so it never grows across hosts or chunks
RUN_START=$(date +%s)
URLTMP="$OUT/.tool-urls.tmp"
: > "$URLTMP"

# keep per-stage logs bounded on multi-day runs
trim_log() {
  local f="${1:-}" cap="${2:-5242880}" sz
  [ -n "$f" ] && [ -f "$f" ] || return 0
  sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
  case "$sz" in ''|*[!0-9]*) return 0;; esac
  if [ "$sz" -gt "$cap" ]; then
    tail -c "$cap" "$f" > "$f.trim" 2>/dev/null && mv -f "$f.trim" "$f"
  fi
  return 0
}
Q="$OUT/queue.db"
rm -rf "$OUT/.gau-work" "$OUT/.js-dl" 2>/dev/null || true

# ---------- per-host pipeline mode ----------
run_per_host() {
  local hostf="$OUT/.per-host" parts="$OUT/.parts" cf part idx total chunk
  chunk="${PER_HOST_CHUNK:-1}"
  case "$chunk" in ''|*[!0-9]*) chunk=1;; esac
  [ "$chunk" -ge 1 ] || chunk=1
  mkdir -p "$hostf" "$parts"
  # the parent exits before the normal auto-notify block, so resolve it here
  if [ "$NOTIFY" = 0 ] && [ -f "$NOTIFY_CONFIG" ]; then
    FIRST_ID=$(grep -oE 'id:[[:space:]]*"?[A-Za-z0-9_.-]+"?' "$NOTIFY_CONFIG" 2>/dev/null \
               | head -1 | sed -E 's/id:[[:space:]]*"?//; s/"$//')
    if [ -n "$FIRST_ID" ]; then
      NOTIFY=1
      [ ${#NOTIFY_IDS[@]} -eq 0 ] && NOTIFY_IDS+=("$FIRST_ID")
    fi
  fi
  awk 'NF && $1 !~ /^#/' "$IN" | tr 'A-Z' 'a-z' \
    | sed -E 's#^[a-z][a-z0-9+.-]*://##; s#[/?#].*$##; s#[.]+$##' \
    | awk 'NF' | sort -u > "$hostf/hosts.txt"
  total=$(wc -l < "$hostf/hosts.txt" | tr -d ' ')
  [ "$total" -gt 0 ] || die "per-host: no hosts in $IN"
  cp "$hostf/hosts.txt" "$OUT/hosts.txt"
  # never wipe aggregates: a rerun must keep what earlier parts already produced
  for f in results.jsonl confirmed.jsonl hosts-done.txt hosts-completed.log urls-done.txt; do
    [ -f "$OUT/$f" ] || : > "$OUT/$f"
  done
  echo "[*] per-host mode: $total host(s), $chunk per batch, one run dir reused"
  split -l "$chunk" -d -a 5 "$hostf/hosts.txt" "$hostf/h."
  idx=0
  for cf in "$hostf"/h.*; do
    [ -s "$cf" ] || { rm -f "$cf"; continue; }
    idx=$((idx + 1))
    part="$parts/p$idx"
    if [ -f "$OUT/hosts-done.txt" ] && grep -qxF "$(head -1 "$cf")" "$OUT/hosts-done.txt"; then
      say "skip (already complete): $(tr '\n' ' ' < "$cf")"
      rm -f "$cf"
      continue
    fi
    # a leftover part directory is resumed, never wiped
    PTMO="${PER_HOST_TIMEOUT:-0}"
    if [ "$PTMO" -gt 0 ]; then
      timeout --foreground "$PTMO" \
        env PER_HOST_CHILD=1 bash "$0" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"} -i "$cf" -o "$part" \
        >&3 2>>"$OUT/logs/per-host.log"
      prc=$?
      [ "$prc" -eq 124 ] && warn "per-host: $(tr '\n' ' ' < "$cf") hit ${PTMO}s budget; partial results kept"
    else
      env PER_HOST_CHILD=1 bash "$0" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"} -i "$cf" -o "$part" \
        >&3 2>>"$OUT/logs/per-host.log"
      prc=$?
    fi
    if [ -d "$part" ]; then
      if python3 "$QHELPER" merge-run "$part" "$OUT" >/dev/null 2>>"$OUT/logs/merge.log"; then
        rm -rf "$part"
      else
        # never throw away a finished scan because the merge step failed
        mkdir -p "$OUT/.failed-parts"
        mv -f "$part" "$OUT/.failed-parts/p$idx" 2>/dev/null || true
        warn "merge failed for $(tr '\n' ' ' < "$cf"); kept at $OUT/.failed-parts/p$idx"
      fi
    fi
    say "hosts complete: $(wc -l < "$OUT/hosts-done.txt" | tr -d ' ')/$total ($(tr '\n' ' ' < "$cf"))"
    rm -f "$cf"
  done
  rm -rf "$hostf" "$parts"
  echo "[*] per-host done: $(wc -l < "$OUT/hosts-done.txt" | tr -d ' ')/$total host(s) complete" >&3
  echo "[*] findings: $(wc -l < "$OUT/results.jsonl" | tr -d ' ')  confirmed: $(wc -l < "$OUT/confirmed.jsonl" | tr -d ' ')" >&3
  if [ "$NOTIFY" = 1 ] && [ "$(wc -l < "$OUT/results.jsonl" 2>/dev/null || echo 0)" -gt 0 ] \
     && command -v notify >/dev/null 2>&1; then
    local dn fn cn el sum nid nargs=()
    dn=$(wc -l < "$OUT/hosts-done.txt" | tr -d ' ')
    fn=$(wc -l < "$OUT/results.jsonl" 2>/dev/null | tr -d ' ')
    cn=$(wc -l < "$OUT/confirmed.jsonl" 2>/dev/null | tr -d ' ')
    el=$(( ($(date +%s) - ${RUN_START:-$(date +%s)}) / 60 ))
    sum="$OUT/notify-complete.txt"
    {
      printf 'xss-scan finished (per-host): %s\n' "$(basename "$OUT")"
      printf 'hosts complete: %s/%s\n' "${dn:-0}" "$total"
      printf 'findings=%s confirmed=%s\n' "${fn:-0}" "${cn:-0}"
      printf 'elapsed: %sm\n' "$el"
    } > "$sum"
    nargs=(-data "$sum" -pc "$NOTIFY_CONFIG" -silent)
    for nid in ${NOTIFY_IDS[@]+"${NOTIFY_IDS[@]}"}; do nargs+=(-id "$nid"); done
    timeout --foreground 120 notify "${nargs[@]}" >>"$OUT/logs/notify.log" 2>&1 \
      && echo "[*] notify: completion sent" >&3 || warn "completion notify failed"
  fi
  return 0
}

if [ "$PER_HOST" = 1 ] && [ "${PER_HOST_CHILD:-0}" != "1" ]; then
  run_per_host
  exit $?
fi

# ---------- live notify helper (called after each batch with hits) ----------
notify_file() { # $1 = message file, $2 = label
  [ "$NOTIFY" = 1 ] || return 0
  [ -s "$1" ] || return 0
  command -v notify >/dev/null 2>&1 || { warn "notify binary missing"; return 0; }
  local -a args=(-data "$1" -pc "$NOTIFY_CONFIG" -silent)
  local nid
  for nid in ${NOTIFY_IDS[@]+"${NOTIFY_IDS[@]}"}; do args+=(-id "$nid"); done
  if timeout --foreground 120 notify "${args[@]}" >>"$LOGS/notify.log" 2>&1; then
    NOTIFY_SENT_ANY=1
    echo "[*] notify: sent $2"
  else
    warn "notify send failed for $2 (see logs/notify.log)"
  fi
}

# build a readable message from a nuclei-style jsonl batch
notify_from_jsonl() { # $1=jsonl $2=out-file $3=header [$4=sent-file] [$5=scope]
  python3 - "$1" "$2" "$3" "${4:-}" "${5:-conf}" <<'PY'
import json, sys
from urllib.parse import urlsplit, unquote

MARKERS = ("<", "alert(", "onerror", "onmouseover", "svg", "script", "javascript:")

src, dst, header = sys.argv[1], sys.argv[2], sys.argv[3]
sent_file = sys.argv[4] if len(sys.argv) > 4 else ""
SCOPE = (sys.argv[5] if len(sys.argv) > 5 else "conf")

def norm(url):
    """(host, path-key). Payload segments are collapsed so the same injected
    path position is notified once, no matter which payload hit it."""
    try:
        sp = urlsplit(url.split("#")[0])
        host = sp.netloc.lower()
        segs = [x for x in (sp.path or "/").split("/")]
        keep = []
        for seg in segs:
            low = unquote(seg).lower()
            if any(m in low for m in MARKERS):
                break
            keep.append(seg)
        path = "/".join(keep) or "/"
        if keep and keep[-1] == "" and path != "/":
            pass
        if len(keep) < len(segs):
            path = path.rstrip("/") + "/*"
        return (host, path)
    except Exception:
        return (url, "")

def param_of(d, url):
    p = d.get("param") or ""
    if not p:
        meta = d.get("meta") or {}
        if isinstance(meta, dict):
            p = str(meta.get("param") or "")
    if not p and "#" in url:
        tail = url.split("#", 1)[1]
        p = tail.split(":", 1)[1] if ":" in tail else tail
    if not p:
        # URL hits: the injected parameter is the one carrying the payload
        try:
            from urllib.parse import urlsplit, parse_qsl, unquote
            q = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            for k, v in q.items():
                lv = unquote(v).lower()
                if any(m in lv for m in MARKERS):
                    return k
            if q:
                return next(iter(q))
        except Exception:
            pass
    return str(p)

seen_file = set()
if sent_file:
    try:
        with open(sent_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    seen_file.add(line)
    except OSError:
        pass

lines, keys = [], []
for line in open(src, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    tid = d.get("template-id", "xss")
    url = d.get("matched-at") or d.get("url") or ""
    host, path = norm(url)
    param = param_of(d, url)
    # one notification per endpoint+parameter, regardless of payload variant
    key = "%s|%s|%s|%s|%s" % (SCOPE, host, path, param, "body" if (d.get("type") == "body"
                                                       or tid == "reflected-body-xss") else "url")
    if key in seen_file or key in keys:
        continue
    keys.append(key)
    if d.get("type") == "body" or tid == "reflected-body-xss":
        lines.append("POST %s" % url.split("#")[0])
        if param:
            lines.append("    param=%s" % param)
    else:
        lines.append("GET %s" % url.split("#")[0])
        if param:
            lines.append("    param=%s" % param)

if not keys:
    raise SystemExit

with open(dst, "w", encoding="utf-8") as fh:
    fh.write("%s (%d)\n\n" % (header, len(keys)))
    fh.write("\n".join(lines[:60]) + "\n")
    if len(lines) > 60:
        fh.write("... %d more\n" % (len(lines) - 60))

if sent_file:
    try:
        with open(sent_file, "a", encoding="utf-8") as fh:
            for k in keys:
                fh.write(k + "\n")
    except OSError:
        pass
PY
}

# ---- run isolation: --no-resume moves the whole previous run aside ----
if [ "$RESUME" = 0 ]; then
  if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null | grep -v '^archive-' || true)" ]; then
    ARCH="$OUT/archive-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$ARCH"
    shopt -s dotglob nullglob
    for f in "$OUT"/*; do
      case "$(basename "$f")" in archive-*) continue;; esac
      mv -f "$f" "$ARCH/" 2>/dev/null || true
    done
    shopt -u dotglob nullglob
    warn "--no-resume: previous run archived to $ARCH"
  fi
  mkdir -p "$LOGS"
fi
[ "$SILENT" = 0 ] && echo "[*] workdir: $OUT"
if [ "$SILENT" = 1 ]; then
  exec >>"$LOGS/run.log" 2>&1
fi

# ---- per-domain completion tracking ----
HOSTS_DONE_LAST=""
host_progress() {
  local cnt
  if [ "$SILENT" = 1 ]; then
    cnt=$(python3 "$QHELPER" host-status "$Q" "$OUT/hosts.txt" \
          "$OUT/hosts-done.txt" "$OUT/hosts-completed.log" "$OUT/urls-done.txt" \
          2>>"$LOGS/hosts.log")
    [ "${PER_HOST_CHILD:-0}" = 1 ] && return 0
    if [ -n "$cnt" ] && [ "$cnt" != "$HOSTS_DONE_LAST" ]; then
      HOSTS_DONE_LAST="$cnt"
      echo "[*] hosts complete: $cnt" >&3
    fi
  else
    python3 "$QHELPER" host-status "$Q" "$OUT/hosts.txt" \
      "$OUT/hosts-done.txt" "$OUT/hosts-completed.log" "$OUT/urls-done.txt" \
      2>>"$LOGS/hosts.log" >/dev/null
  fi
  return 0
}

# ---- canonical auth headers: single source for every tool ----
AUTH_HDRS=()
[ -n "$COOKIE" ] && AUTH_HDRS+=("Cookie: $COOKIE")

# credential precedence: env > file > argv, and conflicting Authorization is fatal
if [ -n "${XSS_TOKEN:-}" ]; then TOKEN="$XSS_TOKEN"; fi
if [ -n "${XSS_COOKIE:-}" ] && [ -z "$COOKIE" ]; then COOKIE="$XSS_COOKIE"; AUTH_HDRS+=("Cookie: $COOKIE"); fi
if [ -n "$TOKEN_FILE" ]; then
  [ -r "$TOKEN_FILE" ] || die "--token-file not readable: $TOKEN_FILE"
  TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
fi
if [ -n "$TOKEN" ]; then
  for h in ${HDRS[@]+"${HDRS[@]}"}; do
    if printf '%s' "$h" | grep -qiE '^authorization:'; then
      die "conflicting Authorization: both --token and -H Authorization given"
    fi
  done
  AUTH_HDRS+=("Authorization: Bearer $TOKEN")
fi
for h in ${HDRS[@]+"${HDRS[@]}"}; do [ -n "$h" ] && AUTH_HDRS+=("$h"); done

# normalize: reject duplicate names with different values, then sort for hashing
if [ "${#AUTH_HDRS[@]}" -gt 0 ]; then
  HDRNORM=$(python3 - "${AUTH_HDRS[@]}" <<'PY'
import sys
seen = {}
out = []
for raw in sys.argv[1:]:
    if ":" not in raw:
        continue
    name, value = raw.split(":", 1)
    name, value = name.strip(), value.strip()
    key = name.lower()
    if key in seen:
        if seen[key] != value:
            sys.stderr.write("conflicting values for header %s\n" % name)
            sys.exit(9)
        continue
    seen[key] = value
    out.append("%s: %s" % (name, value))
print("\n".join(out))
PY
)
  HDRC=$?
  [ "$HDRC" -eq 0 ] || die "conflicting header values (same name, different value); pass one value per header"
  mapfile -t AUTH_HDRS <<< "$HDRNORM"
fi

NHDR=()
for h in ${AUTH_HDRS[@]+"${AUTH_HDRS[@]}"}; do NHDR+=(-H "$h"); done
# canonical fingerprint: lowercase names, exact values, order-insensitive
AUTH_SHA=$(python3 - "${AUTH_HDRS[@]}" <<'PY'
import hashlib, sys
lines = []
for raw in sys.argv[1:]:
    if ":" not in raw:
        continue
    name, value = raw.split(":", 1)
    lines.append("%s:%s" % (name.strip().lower(), value.strip()))
print(hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest())
PY
)
echo "[*] auth: cookie=$([ -n "$COOKIE" ] && echo yes || echo no) token=$([ -n "$TOKEN" ] && echo yes || echo no) headers=${#AUTH_HDRS[@]} auth_sha=${AUTH_SHA:0:12}"

# ---- 1. normalize input ----
: > "$OUT/hosts.txt"; : > "$OUT/seed-urls.txt"
while IFS= read -r raw || [ -n "$raw" ]; do
  line="$(printf '%s' "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  case "$line" in ''|'#'*) continue;; esac
  if printf '%s' "$line" | grep -qiE '^[a-z][a-z0-9+.-]*://'; then
    printf '%s\n' "$line" >> "$OUT/seed-urls.txt"
    h="$(printf '%s' "$line" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[/?#].*$##')"
  else
    h="$(printf '%s' "$line" | sed -E 's#[/?#].*$##')"
  fi
  printf '%s\n' "$h" | tr 'A-Z' 'a-z'
done < "$IN" | sort -u > "$OUT/hosts.txt"
sort -u -o "$OUT/seed-urls.txt" "$OUT/seed-urls.txt" 2>/dev/null || true
N_HOSTS=$(wc -l < "$OUT/hosts.txt" | tr -d ' ')
[ "$N_HOSTS" -gt 0 ] || die "no usable hosts in $IN"
[ "$SILENT" = 0 ] && echo "[*] hosts: $N_HOSTS  seed-urls: $(wc -l < "$OUT/seed-urls.txt" | tr -d ' ')"
sed -E 's#:[0-9]+$##' "$OUT/hosts.txt" | sort -u > "$OUT/gau-hosts.txt"
export XSS_SCOPE_HOSTS="$OUT/hosts.txt"

# ---- auto tuning: size the run to the scope and the disk, no flags needed ----
if [ "$RATE_SET" = 0 ]; then
  if [ "${PER_HOST_CHILD:-0}" = 1 ]; then
    # single-domain crawl+scan: slower on purpose, aggressive rates make sites
    # throttle and the crawl then returns almost nothing
    [ -z "${RATE_ENV:-}" ] && RATE=10
    [ -z "${CONC_ENV:-}" ] && CONC=3
    THREADS=20
  elif [ "$N_HOSTS" -ge 1000 ]; then RATE=25; CONC=8;  THREADS=60
  elif [ "$N_HOSTS" -ge 200 ]; then RATE=40; CONC=10; THREADS=80
  else                              RATE=60; CONC=12; THREADS=50
  fi
fi
if [ "$CONC_SET" = 1 ]; then :; fi
[ "$N_HOSTS" -ge 500 ] && BODY_BATCH="${BODY_BATCH_AUTO:-20}"
if [ "$DISK_SET" = 0 ]; then
  FREE_MB=$(df -Pm "$OUT" 2>/dev/null | awk 'NR==2 {print $4}')
  case "${FREE_MB:-0}" in ''|*[!0-9]*) FREE_MB=0;; esac
  if [ "$FREE_MB" -gt 4000 ]; then
    MAX_DISK_MB=$(( FREE_MB - 3000 ))
    [ "$MAX_DISK_MB" -gt 8000 ] && MAX_DISK_MB=8000
  elif [ "$FREE_MB" -gt 1500 ]; then
    MAX_DISK_MB=$(( FREE_MB - 1000 ))
  else
    MAX_DISK_MB=1024
  fi
fi
if [ "$VERIFY_EXPLICIT" = 0 ]; then
  if [ -n "${CHROME_PATH:-}" ] && [ -x "${CHROME_PATH:-}" ]; then DO_VERIFY=1
  elif command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 \
       || command -v google-chrome >/dev/null 2>&1; then DO_VERIFY=1
  else DO_VERIFY=0; warn "no browser found: verification disabled (candidates only)"; fi
fi
if [ "$NOTIFY_EXPLICIT" = 0 ] && [ -f "$NOTIFY_CONFIG" ]; then
  FIRST_ID=$(grep -oE 'id:[[:space:]]*"?[A-Za-z0-9_.-]+"?' "$NOTIFY_CONFIG" 2>/dev/null \
             | head -1 | sed -E 's/id:[[:space:]]*"?//; s/"$//')
  if [ -n "$FIRST_ID" ]; then
    NOTIFY=1
    [ ${#NOTIFY_IDS[@]} -eq 0 ] && NOTIFY_IDS+=("$FIRST_ID")
    [ "$SILENT" = 0 ] && echo "[*] auto: notify enabled (id=$FIRST_ID)"
  fi
fi
[ "$SILENT" = 0 ] && echo "[*] auto: rate=$RATE conc=$CONC threads=$THREADS disk_cap=${MAX_DISK_MB}MB verify=$DO_VERIFY forms=$DO_FORMS post=$FORMS_POST body_batch=$BODY_BATCH"
export MAX_BODY_PARAMS="${MAX_BODY_PARAMS:-40}"

# ---- 2. immutable config fingerprint ----
SCOPE_SHA=$( { sha256sum "$OUT/hosts.txt"; sha256sum "$IN"; } 2>/dev/null | sha256sum | cut -d' ' -f1 )
TMPL_SHA=$(find "$TPL_DIR" -maxdepth 1 -name '*.yaml' -print0 2>/dev/null | sort -z \
  | xargs -0 -r sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1)
COOKIE_SHA=$(printf '%s' "$COOKIE" | sha256sum | cut -d' ' -f1)
HDR_SHA=$(printf '%s\n' ${HDRS[@]+"${HDRS[@]}"} | sha256sum | cut -d' ' -f1)
# canonical authentication fingerprint (names lowercased, values exact, sorted)
AUTH_SHA=$(python3 - "${AUTH_HDRS[@]}" <<'PY'
import hashlib, sys
lines = []
for raw in sys.argv[1:]:
    if ":" not in raw:
        continue
    name, value = raw.split(":", 1)
    lines.append("%s:%s" % (name.strip().lower(), value.strip()))
print(hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest())
PY
)

JSON_SHA=$( [ -n "$JSON_FILE" ] && sha256sum "$JSON_FILE" 2>/dev/null | cut -d' ' -f1 || echo none )
CONFIG="$OUT/config.json"
if [ -s "$CONFIG" ]; then
  PREV_SCOPE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("scope_sha",""))' "$CONFIG" 2>/dev/null)
  PREV_TMPL=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("template_sha",""))' "$CONFIG" 2>/dev/null)
  PREV_COOKIE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("cookie_sha",""))' "$CONFIG" 2>/dev/null)
  PREV_HDR=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("header_sha",""))' "$CONFIG" 2>/dev/null)
  PREV_AUTH=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("auth_sha",""))' "$CONFIG" 2>/dev/null)
  LEGACY_CONFIG=0
  if [ -z "$PREV_AUTH" ]; then
    # legacy run: no canonical fingerprint; fall back to the old per-field hashes
    LEGACY_CONFIG=1
    warn "legacy config without auth_sha: resume uses old hashes; prefer a new -o dir"
  fi
  PREV_JSON=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("json_spec_sha",""))' "$CONFIG" 2>/dev/null)
  PREV_FPOST=$(python3 -c 'import json,sys;print(1 if json.load(open(sys.argv[1])).get("forms_post") else 0)' "$CONFIG" 2>/dev/null)
  PREV_MJOBS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("max_jobs",0))' "$CONFIG" 2>/dev/null)
  PREV_MTOTAL=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("max_total",0))' "$CONFIG" 2>/dev/null)
  NEED_AMEND=0
  LIMITS_CHANGED=0
  [ "${PREV_MJOBS:-0}" != "$MAX_JOBS" ] && LIMITS_CHANGED=1
  [ "${PREV_MTOTAL:-0}" != "$MAX_TOTAL" ] && LIMITS_CHANGED=1
  if [ "$LIMITS_CHANGED" = 1 ]; then
    if [ "$AMEND_LIMITS" = 1 ]; then
      NEED_AMEND=1
      PREV_MJOBS="$MAX_JOBS"   # limits are amendable; other fields still validated
      PREV_MTOTAL="$MAX_TOTAL"
    else
      die "resource limits differ from this run (max_jobs ${PREV_MJOBS:-0}->$MAX_JOBS, max_total ${PREV_MTOTAL:-0}->$MAX_TOTAL); re-run with --amend-limits"
    fi
  fi
  AUTH_MISMATCH=0
  if [ "$LEGACY_CONFIG" = 0 ]; then
    # canonical auth identity: cookie/token/header set compared as one fingerprint
    [ "$PREV_AUTH" != "$AUTH_SHA" ] && AUTH_MISMATCH=1
  else
    # legacy config: compare the older per-field hashes
    [ "$PREV_COOKIE" != "$COOKIE_SHA" ] && AUTH_MISMATCH=1
    [ "$PREV_HDR" != "$HDR_SHA" ] && AUTH_MISMATCH=1
  fi
  if [ "$PREV_SCOPE" != "$SCOPE_SHA" ] || [ "$PREV_TMPL" != "$TMPL_SHA" ] \
     || [ "$AUTH_MISMATCH" = 1 ] \
     || [ "$PREV_JSON" != "$JSON_SHA" ] || [ "${PREV_FPOST:-0}" != "$FORMS_POST" ] \
     || [ "${PREV_MJOBS:-0}" != "$MAX_JOBS" ]; then
    if [ "$FORCE_CONFIG" = 1 ]; then
      warn "config changed (scope/templates/auth/specs/forms-post); continuing with --force-config"
      cp -f "$CONFIG" "$CONFIG.previous" 2>/dev/null || true
    else
      die "scope, templates, auth, forms-post or json specs changed since this run started; use a new -o dir, --no-resume, or --force-config"
    fi
  fi
  if [ "$NEED_AMEND" = 1 ]; then
    # non-amendable fields validated above; now amend atomically
    python3 - "$CONFIG" "$MAX_JOBS" "$MAX_TOTAL" <<'PY'
import json, os, sys, time
p, mj, mt = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
d = json.load(open(p))
old = {"max_jobs": d.get("max_jobs", 0), "max_total": d.get("max_total", 0)}
d.setdefault("amendments", []).append({
    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "old": old, "new": {"max_jobs": mj, "max_total": mt},
})
d["max_jobs"] = mj
d["max_total"] = mt
tmp = p + ".tmp"
json.dump(d, open(tmp, "w"), indent=2, sort_keys=True)
os.replace(tmp, p)
PY
    warn "limits amended: max_jobs=$MAX_JOBS max_total=$MAX_TOTAL"
  fi
else
  python3 - "$CONFIG" "$IN" "$TPL_DIR" "$SCOPE_SHA" "$TMPL_SHA" \
    "$BATCH_SIZE" "$PATH_BATCH" "$BODY_BATCH" "$MAX_TOTAL" "$RATE" "$CONC" \
    "$DO_VERIFY" "$VERIFY_MAX" "$DO_FORMS" "$(printf '%s' "${#NHDR[@]}")" \
    "$([ -n "$COOKIE" ] && echo yes || echo no)" \
    "$("$HTTPX_BIN" -version 2>&1 | head -1)" \
    "$("$NUCLEI_BIN" -version 2>&1 | head -1)" \
    "$COOKIE_SHA" "$HDR_SHA" "$JSON_SHA" "$FORMS_POST" "$MAX_JOBS" "$AUTH_SHA" <<'PY'
import json, sys, time
(p, inp, tpl, scope, tmpl_sha, bs, pb, bb, mt, rate, conc,
 verify, vmax, forms, hdrs, cookie, httpx_v, nuclei_v,
 cookie_sha, hdr_sha, json_sha, forms_post, max_jobs, auth_sha) = sys.argv[1:25]
cfg = {
    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "input": inp, "templates": tpl, "scope_sha": scope, "template_sha": tmpl_sha,
    "batch_size": int(bs), "path_batch": int(pb), "body_batch": int(bb),
    "max_total": int(mt), "max_jobs": int(max_jobs),
    "rate": int(rate), "concurrency": int(conc),
    "verify": verify == "1", "verify_max": int(vmax), "forms": forms == "1",
    "forms_post": forms_post == "1",
    "header_count": int(hdrs), "cookie": cookie,
    "cookie_sha": cookie_sha, "header_sha": hdr_sha, "json_spec_sha": json_sha,
    "auth_sha": auth_sha,
    "httpx": httpx_v.strip(), "nuclei": nuclei_v.strip(),
}
json.dump(cfg, open(p, "w"), indent=2, sort_keys=True)
PY
  [ -s "$CONFIG" ] || die "could not write config fingerprint: $CONFIG"
  echo "[*] config: $CONFIG"
fi
CONFIG_ID=$( { printf '%s\n' "$SCOPE_SHA" "$TMPL_SHA" "$AUTH_SHA" \
  "$JSON_SHA" "$FORMS_POST"; } | sha256sum | cut -d' ' -f1 )

# ---- 3. queue init / recovery ----
python3 "$QHELPER" init "$Q" || die "queue init failed"
python3 "$QHELPER" meta-set "$Q" verify_requested "$DO_VERIFY" 2>/dev/null || true
python3 "$QHELPER" meta-set "$Q" jobs_cap "$MAX_JOBS" 2>/dev/null || true
python3 "$QHELPER" meta-set "$Q" url_cap "$MAX_TOTAL" 2>/dev/null || true
python3 "$QHELPER" meta-set "$Q" config_id "$CONFIG_ID" 2>/dev/null || true
[ "$FORCE_CONFIG" = 1 ] && python3 "$QHELPER" meta-set "$Q" config_forced 1 2>/dev/null || true
[ "$RESUME" = 1 ] && python3 "$QHELPER" reset "$Q"
[ "$RETRY_FAILED" = 1 ] && python3 "$QHELPER" retry "$Q"

# ---- 4. alive probe ----
DISC=$(python3 "$QHELPER" discovery-status "$Q" httpx all 2>/dev/null)
if [ "$REDISCOVER" = 1 ] || [ "$DISC" != "done" ]; then
  echo "[*] alive probe (httpx)"
  timeout --foreground "$STEP_TIMEOUT" "$HTTPX_BIN" -l "$OUT/hosts.txt" -silent -threads "$THREADS" \
    ${NHDR[@]+"${NHDR[@]}"} -o "$OUT/alive.txt" 2>>"$LOGS/httpx.log"
  RC=$?
  if [ "$RC" -ne 0 ]; then
    warn "httpx rc=$RC (timeout=$([ "$RC" = 124 ] && echo yes || echo no))"
    python3 "$QHELPER" discovery-set "$Q" httpx all failed "$RC"
    [ "$STRICT" = 1 ] && die "alive probe failed; host coverage incomplete"
  else
    python3 "$QHELPER" discovery-set "$Q" httpx all done 0
  fi
fi
ALIVE=$( [ -s "$OUT/alive.txt" ] && wc -l < "$OUT/alive.txt" | tr -d ' ' || echo 0 )
echo "[*] alive: $ALIVE"
[ "$ALIVE" -gt 0 ] || die "no alive hosts (see $LOGS/httpx.log)"

awk -F/ 'NF>=3 {print $1"//"$3}' "$OUT/alive.txt" | sort -u > "$OUT/origins.txt"
sed -E 's#[?#].*$##' "$OUT/alive.txt" | sort -u > "$OUT/path-targets.txt"
grep -Ei '^https?://[^ ]+$' "$OUT/alive.txt" > "$OUT/pages.txt" 2>/dev/null || cp "$OUT/alive.txt" "$OUT/pages.txt"
cat "$OUT/seed-urls.txt" >> "$OUT/pages.txt" 2>/dev/null || true
sort -u -o "$OUT/pages.txt" "$OUT/pages.txt"
# add discovered in-scope paths so forms on crawled pages are found too
if [ "$DO_FORMS" = 1 ]; then
  python3 "$QHELPER" list-targets "$Q" "$OUT/.targets.txt" >/dev/null 2>&1 || true
  cat "$OUT/.targets.txt" >> "$OUT/pages.txt" 2>/dev/null || true
  grep -vEi '\.(js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|gz|mp4|webp|avif)$' \
    "$OUT/pages.txt" 2>/dev/null | sort -u > "$OUT/pages2.txt" || cp "$OUT/pages.txt" "$OUT/pages2.txt"
  mv -f "$OUT/pages2.txt" "$OUT/pages.txt"
  rm -f "$OUT/.targets.txt"
fi

# ---- 5. discovery -> queue ----
echo "[*] discovery -> queue (batch $BATCH_SIZE, cap $MAX_TOTAL)"
ingest() { python3 "$QHELPER" ingest "$Q" "$OUT/hosts.txt" "$MAX_TOTAL"; }
PRODUCER_RC=0

{ cat "$OUT/seed-urls.txt" 2>/dev/null || true; sed 's#$#/?x=1#' "$OUT/origins.txt"; } | ingest
PS=("${PIPESTATUS[@]}")
[ "${PS[0]:-0}" -eq 0 ] || warn "seed/origin producer rc=${PS[0]} (missing optional seed data)"
[ "${PS[1]:-1}" -eq 0 ] || die "ingest failed for seeds/origins"

if [ "$DO_GAU" = 1 ]; then
  GAU_CONC="${GAU_CONC:-6}"
  GAU_TIMEOUT="${GAU_TIMEOUT:-120}"
  GAU_THREADS="${GAU_THREADS:-5}"
  python3 "$QHELPER" discovery-done "$Q" gau > "$OUT/.gau-done.txt" 2>/dev/null || : > "$OUT/.gau-done.txt"
  if [ "$REDISCOVER" = 0 ] && [ -s "$OUT/.gau-done.txt" ]; then
    grep -vxF -f "$OUT/.gau-done.txt" "$OUT/gau-hosts.txt" > "$OUT/.gau-todo.txt" 2>/dev/null \
      || cp "$OUT/gau-hosts.txt" "$OUT/.gau-todo.txt"
  else
    cp "$OUT/gau-hosts.txt" "$OUT/.gau-todo.txt"
  fi
  GAU_TODO=$(wc -l < "$OUT/.gau-todo.txt" | tr -d ' ')
  if [ "$GAU_TODO" -gt 0 ]; then
    echo "[*] gau: $GAU_TODO host(s), conc=$GAU_CONC timeout=${GAU_TIMEOUT}s"
    cat > "$OUT/.gau-worker.sh" <<'EOS'
#!/bin/bash
gh="$1"; workdir="$2"; log="$3"; thr="$4"; tmo="$5"
safe=$(printf '%s' "$gh" | tr '/: ' '___')
timeout --foreground "$tmo" gau "$gh" --threads "$thr" > "$workdir/$safe.txt" 2>>"$log"
echo "$? $gh $safe" >> "$workdir/rc.txt"
EOS
    chmod +x "$OUT/.gau-worker.sh"
    GAU_WAVE=$(( GAU_CONC * 10 ))
    split -l "$GAU_WAVE" -d -a 3 "$OUT/.gau-todo.txt" "$OUT/.gau-wave."
    for wf in "$OUT"/.gau-wave.*; do
      [ -s "$wf" ] || { rm -f "$wf"; continue; }
      rm -rf "$OUT/.gau-work"; mkdir -p "$OUT/.gau-work"
      WC=$(wc -l < "$wf" | tr -d ' ')
      echo "[*] gau wave: $WC host(s)"
      xargs -P "$GAU_CONC" -I{} bash "$OUT/.gau-worker.sh" {} "$OUT/.gau-work" "$LOGS/gau.log" "$GAU_THREADS" "$GAU_TIMEOUT" < "$wf"
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        grc=${line%% *}; grest=${line#* }
        gsafe=${grest##* }; ggh=${grest% *}
        if [ -s "$OUT/.gau-work/$gsafe.txt" ]; then
          ingest < "$OUT/.gau-work/$gsafe.txt"
          irc=$?
          rm -f "$OUT/.gau-work/$gsafe.txt"   # free space at once
        else
          irc=0
        fi
        if [ "$grc" = 0 ] && [ "$irc" = 0 ]; then
          python3 "$QHELPER" discovery-set "$Q" gau "$ggh" done 0
        elif [ "$grc" = 124 ]; then
          warn "gau timed out for $ggh (partial results kept)"
          python3 "$QHELPER" discovery-set "$Q" gau "$ggh" partial 124
        else
          warn "gau rc=$grc ingest rc=$irc for $ggh"
          python3 "$QHELPER" discovery-set "$Q" gau "$ggh" failed "$grc"
          PRODUCER_RC=$([ "$grc" -ne 0 ] && echo "$grc" || echo "$irc")
        fi
      done < "$OUT/.gau-work/rc.txt"
      rm -f "$wf"
      trim_log "$LOGS/gau.log" 5242880
    done
    rm -rf "$OUT/.gau-work" "$OUT/.gau-worker.sh"
  fi
  rm -f "$OUT/.gau-done.txt" "$OUT/.gau-todo.txt"
fi

# ---- sitemap/robots harvest: cheap, exact URLs before the crawler ----
if [ "$DO_SITEMAP" = 1 ] && [ "$HAVE_CURL" = 1 ]; then
  SD=$(python3 "$QHELPER" discovery-status "$Q" sitemap pages 2>/dev/null)
  if [ "$REDISCOVER" = 1 ] || [ "$SD" != "done" ]; then
    SM_TMP="$OUT/.sitemap.tmp"
    SM_CNT=0
    while IFS= read -r sh; do
      [ -n "$sh" ] || continue
      : > "$SM_TMP"
      for scheme in https http; do
        curl -sk --max-time 15 -A "Mozilla/5.0" \
          ${NHDR[@]+"${NHDR[@]}"} "$scheme://$sh/robots.txt" >> "$SM_TMP" 2>/dev/null || true
        curl -sk --max-time 15 -A "Mozilla/5.0" \
          ${NHDR[@]+"${NHDR[@]}"} "$scheme://$sh/sitemap.xml" >> "$SM_TMP" 2>/dev/null || true
      done
      if [ -s "$SM_TMP" ]; then
        python3 "$QHELPER" sitemap-parse "$SM_TMP" > "$URLTMP" 2>>"$LOGS/sitemap.log"
        if [ -s "$URLTMP" ]; then
          N=$(wc -l < "$URLTMP" | tr -d ' ')
          SM_CNT=$((SM_CNT + N))
          ingest < "$URLTMP" 2>>"$LOGS/sitemap.log" || true
        fi
        : > "$URLTMP"
      fi
      trim_log "$LOGS/sitemap.log" 1048576
    done < "$OUT/hosts.txt"
    rm -f "$SM_TMP"
    python3 "$QHELPER" discovery-set "$Q" sitemap pages done 0
    echo "[*] sitemap/robots: $SM_CNT url(s) harvested"
  fi
fi

DISC=$(python3 "$QHELPER" discovery-status "$Q" katana pages 2>/dev/null)
if [ "$DO_CRAWL" = 1 ] && { [ "$REDISCOVER" = 1 ] || [ "$DISC" != "done" ]; }; then
  # Resumable crawl: every host ends up in exactly one chunk file that is deleted
  # only after a successful katana run. A timeout keeps the file for the next pass,
  # so crawling is complete eventually instead of silently truncated.
  if [ "$N_HOSTS" -ge 1000 ]; then K_CHUNK=25
  elif [ "$N_HOSTS" -ge 200 ]; then K_CHUNK=50
  else K_CHUNK=100
  fi
  if [ "$N_HOSTS" -ge 200 ]; then K_DEPTH=2; else K_DEPTH=3; fi
  [ "${PER_HOST_CHILD:-0}" = 1 ] && K_DEPTH=3
  KMARK="$OUT/.crawl-inited"
  if [ ! -f "$KMARK" ]; then
    rm -rf "$OUT/.crawl-pending" "$OUT/.crawl-failed"
    mkdir -p "$OUT/.crawl-pending" "$OUT/.crawl-failed" "$OUT/.crawl-tries"
    split -l "$K_CHUNK" -d -a 3 "$OUT/alive.txt" "$OUT/.crawl-pending/c"
    touch "$KMARK"
  fi
  K_PASS=0
  while [ "$K_PASS" -lt 6 ]; do
    K_PASS=$((K_PASS + 1))
    shopt -s nullglob
    KFILES=("$OUT"/.crawl-pending/c*)
    shopt -u nullglob
    [ "${#KFILES[@]}" -gt 0 ] || break
    for kf in "${KFILES[@]}"; do
      [ -s "$kf" ] || { rm -f "$kf"; continue; }
      KC=$(wc -l < "$kf" | tr -d ' ')
      K_TIMEOUT=$(( KC * 20 )); [ "$K_TIMEOUT" -lt 600 ] && K_TIMEOUT=600
      [ "$K_TIMEOUT" -gt 1800 ] && K_TIMEOUT=1800
      # let katana stop itself before the wrapper kills it: a self-stop returns 0
      # and counts as done, instead of burning 3 retry passes on rc=124
      K_CT=$(( K_TIMEOUT - 60 )); [ "$K_CT" -lt 120 ] && K_CT=120
      # per-host runs must stay quick: crawling one domain for 9 minutes each
      # does not scale to thousands of hosts
      if [ "${PER_HOST_CHILD:-0}" = 1 ]; then
        K_CAP="${PER_HOST_CRAWL_SECS:-900}"
        [ "$K_CT" -gt "$K_CAP" ] && K_CT="$K_CAP"
      fi
      echo "[*] crawl pass $K_PASS at $(date +%H:%M:%S): $KC host(s) ($(basename "$kf"))"
      timeout --foreground "$K_TIMEOUT" katana -list "$kf" -d "$K_DEPTH" -jc -fs fqdn \
        -ct "${K_CT}s" -kf robotstxt -kf sitemapxml -fsu -rl "$RATE" -c "$CONC" -timeout 10 -silent \
        ${NHDR[@]+"${NHDR[@]}"} > "$URLTMP" 2>>"$LOGS/katana.log"
      prc=$?
      irc=0
      if [ -s "$URLTMP" ]; then ingest < "$URLTMP"; irc=$?; fi
      : > "$URLTMP"
      trim_log "$LOGS/katana.log" 5242880
      # a single-host crawl that returns almost nothing is usually throttling,
      # not an empty site: wait, slow down, and try the same host once more
      if [ "$prc" -eq 0 ] && [ "$irc" -eq 0 ] && [ "${PER_HOST_CHILD:-0}" = 1 ] \
         && [ "${K_RETRY_DONE:-0}" -lt 2 ]; then
        UC=$(python3 "$QHELPER" url-count "$Q" 2>/dev/null || echo 999)
        case "$UC" in ''|*[!0-9]*) UC=999;; esac
        if [ "$UC" -lt "${THIN_CRAWL_MIN:-50}" ]; then
          K_RETRY_DONE=$(( ${K_RETRY_DONE:-0} + 1 ))
          K_WAIT=$(( 45 * K_RETRY_DONE ))
          warn "crawl returned only $UC url(s) for this host; retry $K_RETRY_DONE/2 in ${K_WAIT}s at half rate"
          sleep "$K_WAIT"
          KR=$(( RATE / 2 )); [ "$KR" -lt 5 ] && KR=5
          PC=$(( CONC / 2 )); [ "$PC" -lt 2 ] && PC=2
          timeout --foreground "$K_TIMEOUT" katana -list "$kf" -d "$K_DEPTH" -jc -fs fqdn \
            -ct "${K_CT}s" -kf robotstxt -kf sitemapxml -fsu -rl "$KR" -c "$PC" -timeout 10 -silent \
            ${NHDR[@]+"${NHDR[@]}"} > "$URLTMP" 2>>"$LOGS/katana.log"
          if [ -s "$URLTMP" ]; then ingest < "$URLTMP"; fi
          : > "$URLTMP"
          trim_log "$LOGS/katana.log" 5242880
        fi
      fi
      if [ "$prc" -eq 0 ] && [ "$irc" -eq 0 ]; then
        rm -f "$kf" "$OUT/.crawl-tries/$(basename "$kf")"
        python3 "$QHELPER" discovery-set "$Q" katana "$(basename "$kf")" done 0
      else
        KBASE=$(basename "$kf")
        KTRY="$OUT/.crawl-tries/$KBASE"
        TRY=$(( $(cat "$KTRY" 2>/dev/null || echo 0) + 1 ))
        echo "$TRY" > "$KTRY"
        if [ "$TRY" -ge 3 ]; then
          warn "crawl chunk $(basename "$kf") failed $TRY times; parked in .crawl-failed"
          mv -f "$kf" "$OUT/.crawl-failed/" 2>/dev/null || true
          rm -f "$KTRY"
          python3 "$QHELPER" discovery-set "$Q" katana "$(basename "$kf")" failed "$prc"
        else
          warn "crawl chunk $(basename "$kf") rc=$prc, deferred to pass $((K_PASS + 1)) (try $TRY/3)"
          python3 "$QHELPER" discovery-set "$Q" katana "$(basename "$kf")" partial "$prc"
        fi
      fi
      # katana damping fallback: harvest the site ourselves, one request/second
      if [ "${PER_HOST_CHILD:-0}" = 1 ] && [ "${K_HARVESTED:-0}" = 0 ]; then
        UC=$(python3 "$QHELPER" url-count "$Q" 2>/dev/null || echo 999)
        case "$UC" in ''|*[!0-9]*) UC=999;; esac
        if [ "$UC" -lt "${HARVEST_MIN_URLS:-500}" ]; then
          K_HARVESTED=1
          HOSTONE=$(head -1 "$OUT/hosts.txt" | sed -E 's#^[a-z]+://##' | cut -d/ -f1)
          echo "[*] crawl starved ($UC urls); harvesting $HOSTONE links directly"
          python3 "$QHELPER" harvest "$HOSTONE" "${HARVEST_DEPTH:-2}" \
            "${HARVEST_MAX:-150}" > "$URLTMP" 2>>"$LOGS/harvest.log"
          if [ -s "$URLTMP" ]; then ingest < "$URLTMP"; fi
          : > "$URLTMP"
          trim_log "$LOGS/harvest.log" 1048576
        fi
      fi
    done
  done
  shopt -s nullglob
  LEFT=("$OUT"/.crawl-pending/c*)
  shopt -u nullglob
  if [ "${#LEFT[@]}" -eq 0 ]; then
    python3 "$QHELPER" discovery-set "$Q" katana pages done 0
  else
    warn "${#LEFT[@]} crawl chunk(s) still pending; re-run with -o $OUT to continue"
    python3 "$QHELPER" discovery-set "$Q" katana pages partial 0
  fi
fi

if [ "$DO_JS" = 1 ]; then
  # JS bundles hide endpoints that no crawler follows: fetch what discovery
  # already found and mine URL/API literals out of it.
  JSD=$(python3 "$QHELPER" discovery-status "$Q" js pages 2>/dev/null)
  if [ "$REDISCOVER" = 1 ] || [ "$JSD" != "done" ]; then
    python3 "$QHELPER" list-js "$Q" "$OUT/.js-urls.txt" > "$OUT/.js-count" 2>/dev/null \
      || echo 0 > "$OUT/.js-count"
    JSN=$(cat "$OUT/.js-count" 2>/dev/null || echo 0)
    case "${JSN:-0}" in ''|*[!0-9]*) JSN=0;; esac
    if [ "$JSN" -gt 0 ]; then
      JS_CONC="${JS_CONC:-8}"
      MAX_JS="${MAX_JS:-4000}"
      JS_LIST="$OUT/.js-urls.txt"
      if [ "$JSN" -gt "$MAX_JS" ]; then
        warn "js mining: capping at $MAX_JS of $JSN bundle(s)"
        head -n "$MAX_JS" "$JS_LIST" > "$OUT/.js-urls.lim.txt"
        JS_LIST="$OUT/.js-urls.lim.txt"
      fi
      echo "[*] js mining: $(wc -l < "$JS_LIST" | tr -d ' ') bundle(s), conc=$JS_CONC"
      rm -rf "$OUT/.js-dl"; mkdir -p "$OUT/.js-dl"
      { :; } > "$OUT/.js-hdrs.txt"
      i=0
      while [ "$i" -lt "${#NHDR[@]}" ]; do
        printf '%s\n' "${NHDR[$((i+1))]}" >> "$OUT/.js-hdrs.txt"
        i=$((i + 2))
      done
      cat > "$OUT/.js-fetch.sh" <<'EOS'
#!/bin/bash
outdir="$1"; url="$2"; hdrfile="$3"
safe=$(printf '%s' "$url" | sha1sum | cut -c1-16)
args=()
if [ -s "$hdrfile" ]; then
  while IFS= read -r h; do [ -n "$h" ] && args+=(-H "$h"); done < "$hdrfile"
fi
{ printf '#SRC %s\n' "$url"; curl -sk --max-time 15 -A "Mozilla/5.0" ${args[@]+"${args[@]}"} "$url"; } \
  > "$outdir/$safe.txt" 2>/dev/null
echo "$?" >> "$outdir/rc.txt"
EOS
      chmod +x "$OUT/.js-fetch.sh"
      xargs -P "$JS_CONC" -I{} bash "$OUT/.js-fetch.sh" "$OUT/.js-dl" {} "$OUT/.js-hdrs.txt" < "$JS_LIST"
      MAX_JS_URLS="${MAX_JS_URLS:-50000}"
      python3 "$QHELPER" js-extract "$OUT/.js-dl" "$MAX_JS_URLS" > "$URLTMP" 2>>"$LOGS/js.log"
      JRC=$?
      irc=0
      if [ -s "$URLTMP" ]; then ingest < "$URLTMP"; irc=$?; fi
      : > "$URLTMP"
      trim_log "$LOGS/js.log" 2097152
      [ "$JRC" -eq 0 ] && python3 "$QHELPER" discovery-set "$Q" js pages done 0 \
        || { warn "js-extract rc=$JRC"; python3 "$QHELPER" discovery-set "$Q" js pages failed "$JRC"; }
      rm -rf "$OUT/.js-dl" "$OUT/.js-fetch.sh"
    else
      python3 "$QHELPER" discovery-set "$Q" js pages done 0
    fi
  fi
fi

if [ "$PRODUCER_RC" -ne 0 ] && [ "$STRICT" = 1 ]; then
  die "discovery source failed (rc=$PRODUCER_RC); fix it or use --lenient"
fi

host_progress

# crawl is done: raise the scan rate (the damping that needs 10 rps applies to
# crawling, not to the batch scanner)
if [ "${PER_HOST_CHILD:-0}" = 1 ] && [ -z "${RATE_ENV:-}" ] && [ "$RATE" -lt 25 ]; then
  RATE=25
  echo "[*] scan rate raised to 25 rps after crawl"
fi

# ---- 6. plan work queues ----
python3 "$QHELPER" path-plan "$Q" "$OUT/path-targets.txt" 2>/dev/null
PROBE_HDRS=("${AUTH_HDRS[@]}")
export PROBE_HEADERS=$(python3 -c 'import json,sys
print(json.dumps([a for a in sys.argv[1:] if ":" in a]))' ${PROBE_HDRS[@]+"${PROBE_HDRS[@]}"})
if [ "${XSS_DEBUG_HEADERS:-0}" = "1" ]; then
  echo "[debug] probe header names: $(printf '%s\n' ${PROBE_HDRS[@]+"${PROBE_HDRS[@]}"} | cut -d: -f1 | tr '\n' ' ')"
fi
if [ "${PER_HOST_CHILD:-0}" = 1 ]; then
  export PROBE_TIMEOUT="${PROBE_TIMEOUT:-12}"
else
  export PROBE_TIMEOUT="${PROBE_TIMEOUT:-8}"
fi
# body probing is best-effort: a slow CGI must not stall the stage forever
export PROBE_BUDGET="${PROBE_BUDGET:-3600}"
if [ "${PER_HOST_CHILD:-0}" = 1 ]; then
  export BODY_CONC="${BODY_CONC:-4}"
else
  export BODY_CONC="${BODY_CONC:-6}"
fi
export BODY_PAYLOAD_MAX="${BODY_PAYLOAD_MAX:-4}"
export FORMS_POST="$FORMS_POST"
export FORMS_REDISCOVER="$REDISCOVER"
export JOBS_CAP="$MAX_JOBS"
export XSS_REQUEST_DIR="$OUT/requests"
# gives form-plan a budget below the outer timeout so it can stop cleanly
if [ "${STEP_TIMEOUT:-1800}" -gt 600 ]; then
  export FORMS_BUDGET="${FORMS_BUDGET:-$(( STEP_TIMEOUT - 240 ))}"
else
  export FORMS_BUDGET="${FORMS_BUDGET:-$(( STEP_TIMEOUT > 300 ? STEP_TIMEOUT - 60 : 240 ))}"
fi


if [ "$DO_FORMS" = 1 ]; then
  # crawl results exist only after discovery: refresh the page list now
  { grep -Ei '^https?://[^ ]+$' "$OUT/alive.txt" 2>/dev/null || cat "$OUT/alive.txt";
    cat "$OUT/seed-urls.txt" 2>/dev/null;
    python3 "$QHELPER" list-targets "$Q" "$OUT/.targets.txt" >/dev/null 2>&1 && cat "$OUT/.targets.txt";
  } | grep -vEi '\.(js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|gz|mp4|webp|avif)$' \
    | awk '
      {
        u=$0; path=u;
        sub(/^[a-z]+:\/\/[^\/]+/, "", path);
        sub(/[?#].*$/, "", path);
        if (path == "") path="/";
        n=split(path, a, "/");
        last=a[n];
        if (last ~ /\./ && last !~ /\.(html?|php|aspx?|jsp|cgi|do|action|shtml)$/) next;
        if (n > 6) next;
        print n "\t" length(u) "\t" u;
      }' \
    | sort -n -k1,1 -k2,2 | cut -f3 \
    | awk '!seen[$0]++' > "$OUT/pages.txt" || true
  # FORM_PAGE_CAP=0 (default) keeps every page; the resume queue makes a long
  # list safe because unfinished pages are deferred, never dropped
  if [ "${FORM_PAGE_CAP:-0}" -gt 0 ]; then
    head -n "$FORM_PAGE_CAP" "$OUT/pages.txt" > "$OUT/pages.cap" 2>/dev/null \
      && mv -f "$OUT/pages.cap" "$OUT/pages.txt"
  fi
  rm -f "$OUT/.targets.txt"
  export FORMS_QUEUE_FILE="$OUT/.forms-queue.txt"
  echo "[*] form stage at $(date +%H:%M:%S)"
  echo "[*] form discovery from $(wc -l < "$OUT/pages.txt") candidate page(s) (shallow pages first, cap ${FORM_PAGE_CAP:-0}=all)"
  FI=0
  while [ "$FI" -lt "${FORM_LOOP_MAX:-100}" ]; do
    FI=$((FI + 1))
    timeout --foreground "$STEP_TIMEOUT" python3 "$QHELPER" form-plan "$Q" "$OUT/pages.txt" "$FORM_MAX" \
      2>>"$LOGS/forms.log"
    rc=$?
    if [ "$rc" = 2 ]; then
      die "form discovery: scope policy missing/empty"
    fi
    if [ -s "$FORMS_QUEUE_FILE" ]; then
      echo "[*] form discovery: pass $FI done, $(wc -l < "$FORMS_QUEUE_FILE") page(s) queued, continuing"
      continue
    fi
    break
  done
  if [ -s "$FORMS_QUEUE_FILE" ]; then
    warn "form discovery: $(wc -l < "$FORMS_QUEUE_FILE") page(s) still queued; re-run -o $OUT to continue"
  fi
  [ "$rc" -ne 0 ] && warn "form-plan rc=$rc (see logs/forms.log), continuing"
fi
if [ -n "$JSON_FILE" ]; then
  python3 "$QHELPER" json-plan "$Q" "$JSON_FILE" 2>>"$LOGS/forms.log"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    warn "json-plan rc=$rc (see logs/forms.log); malformed or out-of-scope spec"
    [ "$STRICT" = 1 ] && die "json plan rejected entries rc=$rc; fix the spec or use --lenient"
  fi
fi

disk_ok() {
  local used free
  used=$(du -sm "$OUT" 2>/dev/null | cut -f1); used=${used:-0}
  free=$(df -Pm "$OUT" 2>/dev/null | awk 'NR==2 {print $4}'); free=${free:-0}
  if [ "$used" -ge "$MAX_DISK_MB" ]; then warn "disk guard: ${used}MB >= ${MAX_DISK_MB}MB"; return 1; fi
  if [ "$free" -gt 0 ] && [ "$free" -lt 200 ]; then warn "free space ${free}MB is low"; return 1; fi
  return 0
}

# ---- 7. query batches ----
BATCH_IDX=0; FAILED_BATCHES=0
python3 "$QHELPER" promote-urls "$Q" 2>/dev/null || true
while :; do
  if [ -f "$OUT/STOP" ]; then
    warn "STOP file present: finishing after current batch"
    break
  fi
  disk_ok || { warn "stopping before next query batch; work stays queued"; break; }
  COUNT=$(python3 "$QHELPER" batch "$Q" "$BATCH_SIZE" "$OUT/.batch.$$.txt")
  case "$COUNT" in ''|*[!0-9]*) die "queue batch failed";; esac
  [ "$COUNT" -gt 0 ] || break
  BATCH_IDX=$((BATCH_IDX + 1))
  BJ="$OUT/.batch.$BATCH_IDX.$$.jsonl"
  echo "[*] query batch $BATCH_IDX at $(date +%H:%M:%S): $COUNT url(s)"
  rm -f "$OUT/.live-off.$$"
  python3 "$QHELPER" live-watch "$Q" "$BJ" "$OUT/.live-off.$$" "hit" $$ \
    >&3 2>>"$LOGS/live.log" &
  LW_PID=$!
  timeout --foreground "$NUCLEI_TIMEOUT" "$NUCLEI_BIN" -l "$OUT/.batch.$$.txt" -dast -t "$TPL_DIR" \
    -tags candidate -c "$CONC" -rl "$RATE" -timeout 10 -retries 1 \
    ${NHDR[@]+"${NHDR[@]}"} -silent -jsonl -ot -or -o "$BJ" \
    >/dev/null 2>>"$LOGS/nuclei-batch-$BATCH_IDX.log"
  RC=$?
  kill "$LW_PID" 2>/dev/null
  wait "$LW_PID" 2>/dev/null
  [ -s "$BJ" ] && python3 "$QHELPER" live-watch "$Q" "$BJ" "$OUT/.live-off.$$" "hit" 0 \
    >&3 2>>"$LOGS/live.log"
  if [ "$RC" -eq 0 ]; then
    if ! python3 "$QHELPER" commit-batch "$Q" "$OUT/.batch.$$.txt" "$BJ" 2>>"$LOGS/commit.log"; then
      FAILED_BATCHES=$((FAILED_BATCHES + 1))
      warn "batch $BATCH_IDX commit rejected (missing/invalid output); urls kept for retry"
      [ -s "$BJ" ] && cp -f "$BJ" "$OUT/kept-batch-$BATCH_IDX.jsonl"
      python3 "$QHELPER" abort-batch "$Q" "$OUT/.batch.$$.txt" 2>/dev/null || true
      mv -f "$OUT/.batch.$$.txt" "$OUT/failed-batch-$BATCH_IDX.txt" 2>/dev/null || true
      [ "$STRICT" = 1 ] && die "batch commit rejected; state retained (re-run -o $OUT)"
    else
      python3 "$QHELPER" ctxfilter "$Q" 2>>"$LOGS/context.log" || true
      [ "$SILENT" = 1 ] && python3 "$QHELPER" show-findings "$Q" "query batch $BATCH_IDX" | emit
      host_progress
      if [ "$NOTIFY" = 1 ] && [ "$NOTIFY_LIVE" = 1 ] && [ -s "$BJ" ] \
         && { [ "$DO_VERIFY" = 0 ] || [ "${NOTIFY_CANDIDATES:-0}" = 1 ]; }; then
        if notify_from_jsonl "$BJ" "$OUT/.notify-live.txt" \
             "XSS CANDIDATES — not confirmed, verify manually (batch $BATCH_IDX)" \
             "$OUT/.notify-pending.txt" cand \
           && notify_file "$OUT/.notify-live.txt" "query batch $BATCH_IDX"; then
          cat "$OUT/.notify-pending.txt" >> "$OUT/.notify-sent.txt" 2>/dev/null || true
        fi
        rm -f "$OUT/.notify-pending.txt"
        rm -f "$OUT/.notify-live.txt"
      fi
      rm -f "$OUT/.batch.$$.txt" "$BJ"
      trim_log "$LOGS/nuclei-batch-$BATCH_IDX.log" 4194304
    fi
  else
    FAILED_BATCHES=$((FAILED_BATCHES + 1))
    warn "nuclei batch $BATCH_IDX rc=$RC (timeout=$([ "$RC" = 124 ] && echo yes || echo no))"
    python3 "$QHELPER" abort-batch "$Q" "$OUT/.batch.$$.txt" "$RC" 2>/dev/null || true
    mv -f "$OUT/.batch.$$.txt" "$OUT/failed-batch-$BATCH_IDX.txt" 2>/dev/null || true
    [ -s "$BJ" ] && mv -f "$BJ" "$OUT/failed-batch-$BATCH_IDX.jsonl"
    if [ "$RC" -eq 124 ]; then
      NEW=$(( BATCH_SIZE / 2 )); [ "$NEW" -lt 500 ] && NEW=500
      if [ "$NEW" -lt "$BATCH_SIZE" ]; then
        warn "auto-tune: query batch too slow ($BATCH_SIZE -> $NEW urls per batch)"
        BATCH_SIZE=$NEW
      fi
      if [ "${TIMEOUT_RETRIES:-0}" -lt 3 ]; then
        TIMEOUT_RETRIES=$(( ${TIMEOUT_RETRIES:-0} + 1 ))
        python3 "$QHELPER" retry "$Q" 2>/dev/null || true
        warn "query batch $BATCH_IDX timed out; requeued for retry with smaller batch ($TIMEOUT_RETRIES/3)"
      else
        warn "query batch $BATCH_IDX timed out repeatedly; left failed for --retry-failed"
      fi
    else
      [ "$STRICT" = 1 ] && die "batch $BATCH_IDX failed rc=$RC; re-run -o $OUT --retry-failed"
    fi
  fi
done

# ---- 8. path batches ----
PIDX=0
python3 "$QHELPER" promote-jobs "$Q" 2>/dev/null || true
while :; do
  if [ -f "$OUT/STOP" ]; then
    warn "STOP file present: finishing after current batch"
    break
  fi
  disk_ok || { warn "stopping before next path batch"; break; }
  COUNT=$(python3 "$QHELPER" path-batch "$Q" "$PATH_BATCH" "$OUT/.path.$$.txt")
  case "$COUNT" in ''|*[!0-9]*) warn "path-batch failed"; break;; esac
  [ "$COUNT" -gt 0 ] || break
  PIDX=$((PIDX + 1))
  PJ="$OUT/.path.$PIDX.$$.jsonl"
  echo "[*] path batch $PIDX: $COUNT target(s)"
  rm -f "$OUT/.live-off.p.$$"
  python3 "$QHELPER" live-watch "$Q" "$PJ" "$OUT/.live-off.p.$$" "hit (path)" $$ \
    >&3 2>>"$LOGS/live.log" &
  LWP_PID=$!
  timeout --foreground "$NUCLEI_TIMEOUT" "$NUCLEI_BIN" -l "$OUT/.path.$$.txt" \
    -t "$TPL_DIR/reflected-path-xss.yaml" -c "$CONC" -rl "$RATE" -timeout 10 -retries 1 \
    ${NHDR[@]+"${NHDR[@]}"} -silent -jsonl -ot -or -o "$PJ" \
    >/dev/null 2>>"$LOGS/nuclei-path-$PIDX.log"
  RC=$?
  kill "$LWP_PID" 2>/dev/null
  wait "$LWP_PID" 2>/dev/null
  [ -s "$PJ" ] && python3 "$QHELPER" live-watch "$Q" "$PJ" "$OUT/.live-off.p.$$" "hit (path)" 0 \
    >&3 2>>"$LOGS/live.log"
  if [ "$RC" -eq 0 ] && python3 "$QHELPER" path-commit "$Q" "$OUT/.path.$$.txt.ids" "$PJ" 2>>"$LOGS/commit.log"; then
    python3 "$QHELPER" ctxfilter "$Q" 2>>"$LOGS/context.log" || true
    [ "$SILENT" = 1 ] && python3 "$QHELPER" show-findings "$Q" "path batch $PIDX" | emit
    host_progress
    if [ "$NOTIFY" = 1 ] && [ "$NOTIFY_LIVE" = 1 ] && [ -s "$PJ" ] \
       && { [ "$DO_VERIFY" = 0 ] || [ "${NOTIFY_CANDIDATES:-0}" = 1 ]; }; then
      if notify_from_jsonl "$PJ" "$OUT/.notify-live.txt" \
           "XSS CANDIDATES — not confirmed, verify manually (path batch $PIDX)" \
           "$OUT/.notify-pending.txt" cand \
         && notify_file "$OUT/.notify-live.txt" "path batch $PIDX"; then
        cat "$OUT/.notify-pending.txt" >> "$OUT/.notify-sent.txt" 2>/dev/null || true
      fi
      rm -f "$OUT/.notify-pending.txt"
      rm -f "$OUT/.notify-live.txt"
    fi
    rm -f "$OUT/.path.$$.txt" "$OUT/.path.$$.txt.ids" "$PJ"
    trim_log "$LOGS/nuclei-path-$PIDX.log" 4194304
  else
    warn "path batch $PIDX rc=$RC; jobs kept for retry"
    python3 "$QHELPER" path-abort "$Q" "$OUT/.path.$$.txt.ids" 2>/dev/null || true
    rm -f "$OUT/.path.$$.txt" "$OUT/.path.$$.txt.ids"
    if [ "$RC" -eq 124 ]; then
      NEW=$(( PATH_BATCH / 2 )); [ "$NEW" -lt 200 ] && NEW=200
      if [ "$NEW" -lt "$PATH_BATCH" ]; then
        warn "auto-tune: path batch too slow ($PATH_BATCH -> $NEW targets per batch)"
        PATH_BATCH=$NEW
      fi
      if [ "${PATH_TIMEOUT_RETRIES:-0}" -lt 3 ]; then
        PATH_TIMEOUT_RETRIES=$(( ${PATH_TIMEOUT_RETRIES:-0} + 1 ))
        python3 "$QHELPER" retry "$Q" 2>/dev/null || true
        warn "path batch $PIDX timed out; requeued for retry with smaller batch ($PATH_TIMEOUT_RETRIES/3)"
      else
        warn "path batch $PIDX timed out repeatedly; left failed for --retry-failed"
      fi
    else
      [ "$STRICT" = 1 ] && die "path batch $PIDX failed; re-run -o $OUT --retry-failed"
    fi
  fi
done

# ---- 9. body (form / JSON) batches ----
BIDX=0
python3 "$QHELPER" promote-jobs "$Q" 2>/dev/null || true
while :; do
  if [ -f "$OUT/STOP" ]; then
    warn "STOP file present: finishing after current batch"
    break
  fi
  disk_ok || { warn "stopping before next body batch; jobs stay queued"; break; }
  COUNT=$(python3 "$QHELPER" body-batch "$Q" "$BODY_BATCH" "$OUT/.body.$$.txt")
  case "$COUNT" in ''|*[!0-9]*) warn "body-batch failed"; break;; esac
  [ "$COUNT" -gt 0 ] || break
  BIDX=$((BIDX + 1))
  BODYJ="$OUT/.body.$BIDX.$$.jsonl"
  echo "[*] body batch $BIDX at $(date +%H:%M:%S): $COUNT target(s)"
  timeout --foreground "${BODY_TIMEOUT:-1800}" python3 "$QHELPER" probe-body "$OUT/.body.$$.txt" "$BODYJ" \
    2>>"$LOGS/body.log"
  RC=$?
  if [ "$RC" -eq 0 ] && python3 "$QHELPER" body-commit "$Q" "$OUT/.body.$$.txt.ids" "$BODYJ" "$RC" 2>>"$LOGS/commit.log"; then
    if [ "$NOTIFY" = 1 ] && [ "$NOTIFY_LIVE" = 1 ] && [ -s "$BODYJ" ]; then
      if notify_from_jsonl "$BODYJ" "$OUT/.notify-live.txt" \
           "MANUAL POST XSS — not confirmed, verify manually (batch $BIDX)" \
           "$OUT/.notify-pending.txt" cand \
         && notify_file "$OUT/.notify-live.txt" "body batch $BIDX"; then
        cat "$OUT/.notify-pending.txt" >> "$OUT/.notify-sent.txt" 2>/dev/null || true
      fi
      rm -f "$OUT/.notify-pending.txt"
      rm -f "$OUT/.notify-live.txt"
    fi
    rm -f "$OUT/.body.$$.txt" "$OUT/.body.$$.txt.ids" "$BODYJ"
    trim_log "$LOGS/live.log" 4194304
  else
    warn "body batch $BIDX rc=$RC; slow/timed-out targets kept for retry (scan continues)"
    python3 "$QHELPER" body-abort "$Q" "$OUT/.body.$$.txt.ids" "${RC:-1}" 2>/dev/null || true
    rm -f "$OUT/.body.$$.txt" "$OUT/.body.$$.txt.ids"
    # body probing is best-effort: never abort the whole scan on it
  fi
done

# ---- 10. findings export ----
python3 "$QHELPER" ctxfilter "$Q" 2>>"$LOGS/context.log" || true
[ "$SILENT" = 1 ] && python3 "$QHELPER" show-findings "$Q" "body batch" | emit
host_progress
python3 "$QHELPER" export "$Q" "$OUT/results.jsonl" || die "export failed"
TOTAL=$( [ -s "$OUT/results.jsonl" ] && wc -l < "$OUT/results.jsonl" | tr -d ' ' || echo 0 )
echo "[+] unique candidates (queue.db): $TOTAL"
if [ "$TOTAL" -gt 0 ]; then
  if [ "$HAVE_JQ" = 1 ]; then
    jq -r '[.info.name, (."matched-at" // .url // .host)] | @tsv' "$OUT/results.jsonl" \
      | sort -u > "$OUT/summary.txt" 2>/dev/null || true
  else
    grep -oE '"(matched-at|url)":"[^"]+"' "$OUT/results.jsonl" | sort -u > "$OUT/summary.txt" || true
  fi
  sed 's/^/    /' "$OUT/summary.txt" | head -12
fi

# ---- 11. verification (token evidence only) ----
if [ "$DO_VERIFY" = 1 ] && [ "$TOTAL" -gt 0 ]; then
  echo "[*] verification at $(date +%H:%M:%S): planning"
  [ "$REVERIFY" = 1 ] && python3 "$QHELPER" verify-reset "$Q" 2>>"$LOGS/verify.log"
  python3 "$QHELPER" verify-plan "$Q" "$VERIFY_MAX" 2>>"$LOGS/verify.log" \
    || die "verify-plan failed"
  VC=0; VMETA_ERR=0
  while :; do
  if [ -f "$OUT/STOP" ]; then
    warn "STOP file present: finishing after current batch"
    break
  fi
    N=$(python3 "$QHELPER" verify-batch "$Q" "$VERIFY_BATCH" "$OUT/.va.$$.txt" "$OUT/.va.$$.ids")
    VBRC=$?
    if [ "$VBRC" -eq 2 ]; then
      die "verification scope policy missing or empty; refusing to navigate (check XSS_SCOPE_HOSTS)"
    fi
    case "$N" in ''|*[!0-9]*) die "verify-batch failed";; esac
    [ "$VBRC" -eq 0 ] || die "verify-batch failed rc=$VBRC"
    [ "$N" -gt 0 ] || break
    VC=$((VC + 1))
    VJ="$OUT/.va.$VC.$$.jsonl"
    timeout --foreground "$VERIFY_TIMEOUT" "$NUCLEI_BIN" -l "$OUT/.va.$$.txt" -headless \
      -t "$TPL_DIR/xss-headless-verify.yaml" ${NHDR[@]+"${NHDR[@]}"} \
      -silent -jsonl -ot -o "$VJ" >/dev/null 2>>"$LOGS/verify.log"
    RC=$?
    python3 "$QHELPER" verify-commit "$Q" "$VJ" "$OUT/.va.$$.ids" "$RC" 2>>"$LOGS/verify.log"
    VRC=$?
    [ "$SILENT" = 1 ] && python3 "$QHELPER" show-confirmed "$Q" "verified" | emit || true
    if [ "$VRC" -ne 0 ]; then
      VMETA_ERR=$((VMETA_ERR + 1))
      warn "verify batch $VC: output unusable or scanner rc=$RC (positives kept, rest error)"
    fi
    if [ "$NOTIFY" = 1 ] && [ "$NOTIFY_LIVE" = 1 ]; then
      NEWC=$(python3 "$QHELPER" confirmed-new "$Q" "$OUT/.notify-live.txt" \
               "$OUT/.confirmed-notified.id" "$OUT/.notify-confirmed.keys" \
               2>>"$LOGS/notify.log" || echo 0)
      case "${NEWC:-0}" in ''|*[!0-9]*) NEWC=0;; esac
      if [ "$NEWC" -gt 0 ]; then
        if notify_file "$OUT/.notify-live.txt" "confirmed batch $VC"; then
          cat "$OUT/.notify-confirmed.keys.pending" >> "$OUT/.notify-confirmed.keys" 2>/dev/null || true
        else
          warn "confirmed notify failed (see logs/notify.log)"
        fi
        rm -f "$OUT/.notify-confirmed.keys.pending"
      fi
      rm -f "$OUT/.notify-live.txt"
    fi
    rm -f "$OUT/.va.$$.txt" "$OUT/.va.$$.ids" "$VJ"
    echo "[*] verify batch $VC: $N attempt(s) nuclei_rc=$RC"
  done
  [ "$VMETA_ERR" -gt 0 ] && python3 "$QHELPER" meta-set "$Q" verify_batch_errors "$VMETA_ERR" 2>/dev/null || true
  python3 "$QHELPER" verify-report "$Q" "$OUT/verify-report.jsonl"
  python3 "$QHELPER" export-confirmed "$Q" "$OUT/confirmed.jsonl"
fi

host_progress

# ---- 12. coverage / cleanup ----
python3 "$QHELPER" coverage "$Q" "$OUT/coverage.json" || warn "coverage export failed"
echo "[*] queue: $(python3 "$QHELPER" stats "$Q")"
[ "$FAILED_BATCHES" -gt 0 ] && warn "$FAILED_BATCHES failed batch(es); re-run -o $OUT --retry-failed"

if [ "$COMPACT" = 1 ]; then
  COMPLETE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["complete"])' \
    "$OUT/coverage.json" 2>/dev/null || echo False)
  if [ "$COMPLETE" = "True" ]; then
    rm -f "$Q" "$Q"-wal "$Q"-shm; rm -rf "$LOGS"
    echo "[*] compact: queue.db + logs removed (coverage.complete=true)"
  else
    warn "compact skipped: coverage.complete is not true"
  fi
fi
echo "[*] disk used: $(du -sh "$OUT" 2>/dev/null | cut -f1)  files: $(find "$OUT" -type f | wc -l | tr -d ' ')"
rm -f "$OUT"/.batch.* "$OUT"/.path.* "$OUT"/.body.* "$OUT"/.va.* 2>/dev/null

COMPLETE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["complete"])' \
  "$OUT/coverage.json" 2>/dev/null || echo False)
SKIPPED=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("verification_skipped"))' \
  "$OUT/coverage.json" 2>/dev/null || echo None)
WORK=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["work_complete"])' \
  "$OUT/coverage.json" 2>/dev/null || echo False)
CONF_N=$( [ -s "$OUT/confirmed.jsonl" ] && wc -l < "$OUT/confirmed.jsonl" | tr -d ' ' || echo 0 )
MAN_N=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("manual_confirmation_required",0))' "$OUT/coverage.json" 2>/dev/null || echo 0)
CONF_N=${CONF_N:-0}
MAN_N=${MAN_N:-0}
STATUS=3
if [ "$COMPLETE" = "True" ]; then
  say "done: $OUT (coverage.complete=true)"
  STATUS=0
elif [ "$WORK" = "True" ] && [ "$SKIPPED" = "True" ]; then
  say "done: $OUT (discovery-only: work_complete=true, verification not requested)"
  echo "[*] add --verify to confirm execution before reporting XSS" >&2
  STATUS=0
elif [ "$(( CONF_N + MAN_N ))" -gt 0 ]; then
  say "partial: $OUT (findings kept: confirmed=$CONF_N manual=$MAN_N, coverage incomplete)"
  warn "coverage incomplete (see $OUT/coverage.json); findings valid, run not finished"
  STATUS=3
else
  warn "run incomplete: coverage.complete is false (see $OUT/coverage.json)"
  echo "[*] partial: $OUT" >&2; [ "$SILENT" = 1 ] && echo "[!] partial: $OUT" >&3
fi

if [ "$NOTIFY" = 1 ]; then
  if ! command -v notify >/dev/null 2>&1; then
    warn "notify requested but binary not found (go install github.com/projectdiscovery/notify/cmd/notify@latest)"
  else
    NOTIFY_DATA="$OUT/notify-findings.jsonl"
    NOTIFY_TEXT="$OUT/notify-message.txt"
    python3 - "$OUT" "$NOTIFY_DATA" "$NOTIFY_TEXT" <<'PY'
import json, os, sys, time
from urllib.parse import urlsplit

run, dst, txt = sys.argv[1], sys.argv[2], sys.argv[3]


def route(url):
    sp = urlsplit(url)
    return "%s://%s%s" % (sp.scheme, sp.netloc, sp.path)


confirmed = []
p = os.path.join(run, "confirmed.jsonl")
if os.path.exists(p):
    for line in open(p, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            confirmed.append(json.loads(line))
        except Exception:
            pass

manual = []
p = os.path.join(run, "results.jsonl")
if os.path.exists(p):
    for line in open(p, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("template-id") == "reflected-body-xss":
            manual.append(d)

groups = {}
for d in confirmed:
    url = d.get("url", "")
    params = d.get("params") or ["-"]
    key = (route(url), params[0] if params else "-")
    g = groups.setdefault(key, {"url": key[0], "param": key[1], "payloads": 0,
                                "proofs": [], "sample": url})
    g["payloads"] += 1
    for pr in d.get("proofs") or []:
        if pr not in g["proofs"]:
            g["proofs"].append(pr)

cov = {}
cp = os.path.join(run, "coverage.json")
if os.path.exists(cp):
    try:
        cov = json.load(open(cp, encoding="utf-8"))
    except Exception:
        cov = {}

lines = []
if groups:
    lines.append("XSS CONFIRMED (%d)" % len(groups))
    lines.append("")
    for g in sorted(groups.values(), key=lambda x: x["url"]):
        lines.append("GET %s" % g["sample"][:300])
else:
    lines.append("no XSS confirmed")

if manual:
    lines.append("")
    lines.append("MANUAL POST XSS (reflection, verify in browser): %d" % len(manual))
    seen_m = set()
    for d in manual:
        key = (d.get("url"), d.get("param"))
        if key in seen_m:
            continue
        seen_m.add(key)
        lines.append("%s %s" % (d.get("method", "POST"), d.get("url", "?")))
        lines.append("    param=%s" % d.get("param", "?"))

open(txt, "w", encoding="utf-8").write("\n".join(lines) + "\n")

rows = []
for d in confirmed:
    url = d.get("url", "")
    rows.append({
        "template-id": "confirmed-xss", "template": "confirmed-xss",
        "info": {"name": "Confirmed XSS", "severity": "high",
                 "description": "Execution confirmed by headless browser (exec-proof)"},
        "host": urlsplit(url).netloc, "matched-at": url, "url": url,
        "params": d.get("params", []), "proofs": d.get("proofs", []),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
with open(dst, "w", encoding="utf-8") as fh:
    for r in rows:
        fh.write(json.dumps(r, separators=(",", ":")) + "\n")
PY
    NOTIFY_ARGS=(-data "$NOTIFY_TEXT" -pc "$NOTIFY_CONFIG" -silent)
    NOTIFY_ID_ARGS=()
    for nid in ${NOTIFY_IDS[@]+"${NOTIFY_IDS[@]}"}; do NOTIFY_ID_ARGS+=(-id "$nid"); done
    if { [ "$CONF_N" -gt 0 ] || [ "${MAN_N:-0}" -gt 0 ]; } \
       && { [ "$NOTIFY_SENT_ANY" = 0 ] || [ "$NOTIFY_SUMMARY" = 1 ]; }; then
      echo "[*] notify: sending findings (confirmed=$CONF_N manual=$MAN_N)"
      timeout --foreground 120 notify "${NOTIFY_ARGS[@]}" >>"$LOGS/notify.log" 2>&1 \
        || warn "notify send failed (see logs/notify.log)"
    elif [ "$NOTIFY_SUMMARY" = 1 ]; then
      SUM="$OUT/notify-summary.txt"
      {
        printf 'xss-scan finished: %s\n' "$(basename "$OUT")"
        printf 'confirmed=%s manual=%s findings=%s\n' "$CONF_N" \
          "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("manual_confirmation_required",0))' "$OUT/coverage.json" 2>/dev/null || echo 0)" \
          "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("findings",0))' "$OUT/coverage.json" 2>/dev/null || echo 0)"
        printf 'complete=%s\n' "$COMPLETE"
      } > "$SUM"
      timeout --foreground 120 notify -data "$SUM" -pc "$NOTIFY_CONFIG" -silent \
        ${NOTIFY_ID_ARGS[@]+"${NOTIFY_ID_ARGS[@]}"} >>"$LOGS/notify.log" 2>&1 \
        || warn "notify summary failed (see logs/notify.log)"
    else
      if [ "$NOTIFY_SENT_ANY" = 1 ]; then
        echo "[*] notify: findings already sent live (see logs/notify.log)"
      else
        echo "[*] notify: no findings, no ping sent"
      fi
    fi
  fi
fi

if [ "$NOTIFY" = 1 ] && [ "$PER_HOST" = 0 ] && [ "${TOTAL:-0}" -gt 0 ] \
   && command -v notify >/dev/null 2>&1; then
  DN=$(wc -l < "$OUT/hosts-done.txt" 2>/dev/null | tr -d ' ')
  EL=$(( ($(date +%s) - ${RUN_START:-$(date +%s)}) / 60 ))
  SUMC="$OUT/notify-complete.txt"
  {
    printf 'xss-scan finished: %s\n' "$(basename "$OUT")"
    printf 'hosts complete: %s/%s\n' "${DN:-0}" "$N_HOSTS"
    printf 'findings=%s confirmed=%s complete=%s\n' "${TOTAL:-0}" "${CONF_N:-0}" "${COMPLETE:-unknown}"
    printf 'elapsed: %sm\n' "$EL"
  } > "$SUMC"
  NARGS=(-data "$SUMC" -pc "$NOTIFY_CONFIG" -silent)
  for nid in ${NOTIFY_IDS[@]+"${NOTIFY_IDS[@]}"}; do NARGS+=(-id "$nid"); done
  timeout --foreground 120 notify "${NARGS[@]}" >>"$LOGS/notify.log" 2>&1 \
    || warn "completion notify failed (see logs/notify.log)"
fi

if [ "$DO_REPORT" = 1 ] && [ -x "$SELF_DIR/xss-report.py" ]; then
  python3 "$SELF_DIR/xss-report.py" "$OUT" || true
fi
exit "$STATUS"
