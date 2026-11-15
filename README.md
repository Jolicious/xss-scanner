# XSS nuclei templates — corrected

Fixes the old templates that reported **encoded reflections as high-severity XSS**
(e.g. `map.sonysonpo.co.jp` and `ps-support.playstation.com`, both false positives).

## Why the old templates failed

1. **Sent raw request bytes.** The fuzzing engine inserted raw `"` `<` `>`, which no
   browser ever sends (browsers percent-encode them). Targets that reflected only the
   raw-char request were flagged even though a real victim cannot trigger them.
2. **Matched a reflection, not execution.** `"><meow>` / `"><{-+(.;:)'}>` are not
   executable payloads. A raw reflection in a double-quoted attribute, JSON string, or
   text node produced a "high" finding with zero real impact.
3. **Ignored context.** 302 bodies, `text/javascript`/JSON responses, HTML-entity
   (`&quot;`), percent (`%22`) and backslash (`\"`) echoes were all treated as XSS.
4. **No escaped-quote handling.** `"x":"\"><svg..."` (JSON) matched `"><svg` because of
   the escaped quote — not a breakout.

## What the new templates do

- Send **browser-encoded** payloads (`%22%3E%3Csvg...`) — the exact form a browser sends.
- Alert only on the **raw, decoded, executable** token (`"><svg/onload=...`,
  `</script><svg/onload=...`, `"><img src=x onerror=...`).
- Exclude:
  - 3xx redirects (browser never executes a redirect body),
  - non-`text/html` responses,
  - percent / HTML-entity / `\u003c` / backslash-escaped quote echoes.
- Split HTML context from JS-string context (JS needs quote-type to match).

## Two-stage pipeline

1. **Candidates** (medium severity, tag `candidate`, run with `-dast` for the
   `http.fuzzing` templates):
   - `reflected-param-all-xss.yaml`   — replace each query param (HTML context)
   - `reflected-param-char-probe.yaml` — attribute breakout + script-tag contexts
   - `query-param-append-reflection.yaml` — add a new `&xss=` param
   - `reflected-append-param-query.yaml`  — append payload onto existing value
   - `reflected-path-xss.yaml` — path injection (**regular** template: run WITHOUT `-dast`)
   - `xss-js-string-candidate.yaml` — JS string context (needs `<script` + raw quote breakout)

2. **Confirmation** (`xss-headless-verify.yaml`, high severity):
   Load a candidate URL whose payload mutates the DOM in a real headless browser and
   alert only if it executed. Example payload:
   ```
   "><svg/onload=document.body.dataset.pwn='XSS_CONFIRMED'>
   ```
   ```
   nuclei -headless -u '<candidate-url-with-marker-payload>' -t xss-headless-verify.yaml
   ```

## Usage

```bash
# candidates (fuzzing templates need -dast)
nuclei -l urls.txt -dast -t xss/ -tags candidate

# path template is regular (no fuzzing) — run without -dast
nuclei -l urls.txt -t xss/reflected-path-xss.yaml

# confirm a candidate manually in a browser, or in headless mode
nuclei -headless -u 'http://target/page?q=%22%3E%3Csvg%2Fonload%3Ddocument.body.dataset.pwn%3D%27XSS_CONFIRMED%27%3E' \
       -t xss/xss-headless-verify.yaml
```

## Test results (local vulnerable vs safe fixtures)

| case | expected | result |
|------|----------|--------|
| raw double-quote attribute reflection | HIT | PASS |
| HTML-escaped attribute (`&quot;`) | MISS | PASS |
| percent-encoded echo | MISS | PASS |
| JS string breakout (quote raw, `<>` escaped) | HIT | PASS |
| JS string, quote escaped (`\"`) | MISS | PASS |
| unquoted/attribute-breakout payload on quoted safe page | MISS | PASS |
| path reflection | HIT | PASS |
| path safe | MISS | PASS |
| append new param (vulnerable) | HIT | PASS |
| append onto value (vulnerable) | HIT | PASS |
| **real: map.sonysonpo.co.jp** | MISS | PASS |
| **real: ps-support.playstation.com** | MISS | PASS |
| headless execution confirmation | HIT | PASS |

Backups of the originals: `xss.bak.*` (sibling directory).

## xss-scan.sh + xss-queue.py + xss-headless-verify.yaml — v16 (frozen)

Give it a subdomain/URL list; it discovers, scans, and (with `--verify`) confirms
execution. Unauthenticated unless credentials are supplied.

```bash
# discovery + candidate scan only -> exit 0, verification_skipped=true
xss-scan.sh -i subs.txt -o run1

# full workflow: candidates then headless execution confirmation
xss-scan.sh -i subs.txt -o run1 --verify

# authenticated variants (all reach httpx, katana, nuclei and python probes)
xss-scan.sh -i subs.txt -o run1 -b 'session=abc' --verify
xss-scan.sh -i subs.txt -o run1 -T 'eyJ...' --verify
xss-scan.sh -i subs.txt -o run1 --token-file ./token.txt --verify
xss-scan.sh -i subs.txt -o run1 -H 'X-Api-Key: abc' --verify

# resume: repeat the SAME mode and credentials as the original run
xss-scan.sh -i subs.txt -o run1 --token-file ./token.txt --verify --retry-failed

# resource-limit change on an existing run
xss-scan.sh -i subs.txt -o run1 --max-jobs 20000 --amend-limits --verify
```

Resuming without `--verify` leaves results as candidates (that is a valid
discovery-only outcome, exit 0); resuming with a different credential is refused
with a message unless `--force-config` is used.

### Exit codes

| result | meaning |
|---|---|
| 0 | full workflow complete (`complete=true`), or discovery-only run with all work done |
| 3 | unfinished, capped, unplanned or failed work — see `coverage.json` |

### Confirmation semantics

A finding is `confirmed` only when the headless template's `exec-proof` extractor
returns the exact per-attempt token after the browser ran the payload. Generated
tokens look like:

```
XSS_CONFIRMED_4f3a91c7b2de        # XSS_CONFIRMED_ + 12 lowercase hex chars
```

Manual confirmation command (token is generated by the scanner; you cannot
hand-write one that matches a planned attempt):

```bash
xss-scan.sh -i list.txt -o run1 --verify      # plans attempts, then verifies
# or inspect the exact request/evidence of an attempt:
jq -r 'select(.status=="confirmed") | .attempts[] | select(.status=="confirmed") | .injected' \
  run1/verify-report.jsonl
jq -r '.proofs[]' run1/confirmed.jsonl
```

`confirmed.jsonl` — one record per confirmed finding, with proofs.
`verify-report.jsonl` — per finding, per attempt, with `evidence` (`exec-proof`),
`proof` (the token) and `strategy`.

Body / form / JSON reflections are stored as `reflected-body-xss` and reported
`manual_confirmation_required`; they are never called execution-confirmed.

### Migration note

v16 stores `auth_sha` (canonical, order- and case-insensitive). Runs created by
older versions lack it; those fall back to the old per-field hashes and print a
warning. Prefer a fresh `-o` directory when upgrading an old database rather than
reusing it.

### Operational boundaries

- `complete: true` = modelled workflow finished, not exhaustive XSS coverage
- DOM-based, stored, and session-state XSS are out of scope
- the scope preflight covers the initial injected URL only; a headless page can
  still redirect or fetch third-party resources — run behind an egress allowlist
  for unattended use
- tokens reach child-process arguments; use `--token-file` plus a restricted
  account on shared hosts

## Reading results without JSON (v17)

```bash
xss-report.py run1                 # colour-coded summary
xss-report.py run1 --all           # also list refuted endpoints
xss-report.py run1 --no-body       # hide manual reflections
xss-report.py run1 --limit 0       # no row cap
```
Green `✓` = confirmed by headless execution (`exec-proof`), yellow `⚠` = body /
form / JSON reflection needing manual check, red `!` = verification problems,
`✗` section (with `--all`) = verified but no execution.

The scan prints this report automatically at the end; `--no-report` disables it.

## Notifications via ProjectDiscovery notify (v17)

```bash
xss-scan.sh -i subs.txt -o run1 --token-file ./token.txt --verify \
  --notify --notify-id xss-alerts                # one message per confirmed finding
xss-scan.sh ... --notify --notify-summary        # also send a summary (0 findings too)
```

- provider config: `--notify-config ~/.config/notify/provider-config.yaml` (default)
- `--notify-id` repeatable (discord / slack / smtp / telegram ids from that file)
- only `confirmed` findings are sent; body reflections stay local
- payload: `run1/notify-findings.jsonl`; notify stdout/stderr: `run1/logs/notify.log`
- if `notify` is missing, the scan warns and continues

Deployment recipe (VPS, systemd timer, notify config, disk/egress notes):
see `DEPLOY.md`.

### Notification message format (v18)

Notifications are plain text, not JSON. Example of what lands in Discord/Slack:

```
CONFIRMED XSS: 1 endpoint/param (12 proven requests)

1. https://shop.example.com/search
   param: q
   proof: XSS_CONFIRMED_3b689b836932
   payloads that executed: 3
   request: https://shop.example.com/search?q=%22%3E%3Csvg/onload=...

Needs manual check (body/form/JSON reflection): 1
 - POST https://shop.example.com/feedback (param message)

run: run-2026-11-13
workflow complete: True | findings=26 confirmed=24 manual=2
checked: 2026-11-13 02:10:44Z
```

Files per run:

- `notify-message.txt` — exactly what gets sent (read this instead of JSON)
- `notify-findings.jsonl` — machine format, for other tooling
- `logs/notify.log` — notify stdout/stderr

`--notify` sends only this message when confirmations exist; `--notify-summary` also
sends a short summary for runs with zero findings.

### Minimal notification (current)

`--notify` now sends only what matters — one line per confirmed finding:

```
XSS CONFIRMED (2)

GET https://shop.example.com/search?q=%22%3E%3Csvg/onload=alert(1)%3E
GET https://shop.example.com/product?id=1%27%3E%3Csvg/onload=alert(1)%3E
```

- one line per endpoint+param, using the exact request that executed
- method is shown (`GET` for query/path findings; `POST` when body confirmation is
  added in future)
- body/form/JSON reflections are summarised as a count only, never listed as XSS
- full text is also saved as `run1/notify-message.txt` (readable without JSON)

### Stopping a run

- **Ctrl+C** (or `kill -TERM <pid>`) stops immediately: running `nuclei`/`httpx`/
  `katana`/`gau`/python probes are terminated, in-progress URLs/jobs/attempts are
  returned to the queue, and the script exits 130 with a resume hint.
  (`timeout --foreground` is used so signals reach the tools.)
- **Graceful stop**: `touch <run>/STOP` → the current batch finishes, then the run
  stops cleanly and prints the same resume hint.
- **From another terminal**:
  ```bash
  pkill -TERM -f "xss-scan.sh.*-o out"   # or kill the printed PID
  ```
- Resume afterwards with the same command plus `-o <same dir>` (add
  `--retry-failed` if any batch was interrupted).

### Live notifications (per batch)

Notifications are sent **as soon as a batch with hits is committed**, not only at
the end. On a multi-host run you get a ping the moment host #3 yields something,
while the rest keeps scanning.

```
[*] notify: sent body batch 1
... scan continues ...
[*] notify: findings already sent live
```

- default: live on when `--notify` is used
- `--no-notify-live` → single summary message at the end only
- `--notify-summary` → also send the final recap even after live pings
- each live message lists up to 60 findings (template/URL/param), rest counted
- messages are also stored as `run/.notify-live.txt` before sending; send log is
  `run/logs/notify.log`

### Auto-tuning (no numbers required)

You don't need to size batches or timeouts. Defaults adapt at runtime:

| setting | auto behaviour |
|---|---|
| form discovery | no page cap; runs until a time budget (20s + 0.5s/page, capped 1800s), remaining pages marked `partial`, never fatal |
| step timeout | 1800s per stage |
| query batch | 10000 urls; on timeout it halves (min 500) and requeues the batch, up to 3 auto-retries |
| path batch | 2000 targets; on timeout it halves (min 200) and requeues, up to 3 auto-retries |
| body batch | 100 targets; probe failures requeue without aborting |
| verification | unchanged (batch of 100 attempts) |

Timeouts no longer abort the run; work is requeued and retried with a smaller batch.
Only genuine errors (scope/config/output corruption) stop it.

Overrides still work if you want them (`--form-max`, `--batch-size`, `--path-batch`,
`STEP_TIMEOUT`, `FORMS_BUDGET`), but they are optional.

### Zero-flag operation (v19)

Defaults size themselves; the only required flag is `-i`:

```bash
xss-scan -i subs.txt -o run1 -t /opt/xss-scan
```

What happens automatically:

| decision | rule |
|---|---|
| rate / concurrency | <200 hosts: 60 rps, 12 conc; 200–999: 40 rps, 10; ≥1000: 25 rps, 8 |
| disk cap | free space − 3 GB, clamped to 1–8 GB |
| verification | on when chromium/chrome/CHROME_PATH exists, off with a warning otherwise |
| forms | on by default (GET); POST only with `--forms-post` |
| form page budget | time-based, no page cap |
| batch sizes | 10k urls / 2k path targets, auto-halve + requeue on timeout (3 tries) |
| notify | on if `~/.config/notify/provider-config.yaml` exists, using its first `id:` |
| crawl | on if katana exists (`-rl` limited to the same rate) |
| gau | on if installed, 2 threads |

Disable anything explicitly when needed: `--no-verify`, `--no-forms`,
`--no-notify`, `--no-crawl`, `--no-gau`, `--lenient`.

### Why "katana timed out" happened

The old crawl ran **one** katana process over the whole alive list with a single
1800s budget. With thousands of hosts (plus depth 2 and WAF rate limiting) it
always ran out of time and produced a partial, unordered result set.

Fixed in v20: crawl is chunked.

- 2000+ hosts -> 25 hosts per chunk, depth 1
- 200-999 -> 50 per chunk, depth 1
- <200 -> 100 per chunk, depth 2
- per-chunk budget = chunk size x 6s, clamped to 300-1800s
- each chunk is ingested separately and recorded as `katana/chunk-N`
  (done / partial / failed)
- a chunk timeout never aborts the run; the next chunk continues
- katana is rate-limited to the same `-rl` / `-c` as nuclei

Same pattern already applies to query/path/body batches (halve and requeue).

### Resumable crawl and form discovery (v21)

Neither stage drops work when a timeout hits. Both hold a queue on disk and
continue on the next pass or the next run.

Crawl:

- `alive.txt` is split once into `$OUT/.crawl-pending/cNNN` (25 hosts/chunk at
  >=1000 hosts, 50 at >=200, 100 below that), depth 2 for large scopes, 3 for small
- katana runs per chunk with `-kf robotstxt,sitemapxml` and the same `-rl`/`-c`
  as nuclei
- a chunk file is deleted only when katana exits 0; a failed chunk stays and is
  retried up to 3 times across passes
- after 3 failures the chunk moves to `$OUT/.crawl-failed/` (never silently lost)
- per-chunk try counters live in `$OUT/.crawl-tries/` so they are never mistaken
  for chunk files
- `katana/pages` is marked `done` only when `.crawl-pending/` is empty, otherwise
  `partial` with a re-run hint

Forms:

- pages that do not fit the time budget are written to `$OUT/.forms-queue.txt`
- the driver loops `form-plan` up to 20 passes while that file is non-empty
- the queue file is deleted when it drains, so a re-run starts clean
- `FORMS_BUDGET` defaults to `STEP_TIMEOUT - 240`, so python stops itself before
  the outer `timeout` kills it (no more `rc=124`)

Every other stage keeps its existing behaviour: query/path batches halve and
requeue on timeout (3 tries), body jobs requeue, verification records errors.

To continue an interrupted run, re-run with the same `-o` directory. Add
`--retry-failed` to requeue failed urls/jobs/attempts.

### Endpoint discovery beyond the crawl (v22)

Three more sources feed the queue, all resumable:

**sitemap + robots** — katana runs with `-kf robotstxt -kf sitemapxml` on every
crawl chunk, so sitemap-only routes are found without a wordlist.

**JS bundle mining** — new `js` stage:

1. every in-scope `.js`/`.mjs` URL discovered so far is collected into `jsurls`
2. up to `MAX_JS` bundles (default 4000) are fetched with `curl`, 8 at a time,
   reusing the same auth headers as httpx/katana/nuclei
3. `js-extract` resolves absolute URLs and quoted `/path?query` literals against
   the bundle's origin, drops asset extensions, and prints candidates
4. candidates go through `ingest`, so scope/static/query filtering applies
5. progress is `js/pages` in the discovery table (`done` / `failed`)

`MAX_JS_URLS` (default 50000) caps how many mined URLs enter the queue.
Disable with `--no-js`.

**Parallel gau** — `GAU_CONC` hosts at a time (default 6), `GAU_TIMEOUT` per host
(default 120s), `GAU_THREADS` per process (default 5). Hosts run in waves of
`GAU_CONC * 10`, each wave's output is ingested after it returns, and every host
is recorded `done`/`partial`/`failed` individually. Re-runs skip hosts already
marked `done`, so a 3000-host gau pass resumes instead of restarting.

Extra tuning knobs, all optional:

| var | default | meaning |
|---|---|---|
| `GAU_CONC` | 6 | parallel gau processes |
| `GAU_TIMEOUT` | 120 | seconds per host |
| `GAU_THREADS` | 5 | gau internal workers |
| `JS_CONC` | 8 | parallel curl fetches for bundles |
| `MAX_JS` | 4000 | bundles fetched per run |
| `MAX_JS_URLS` | 50000 | mined URLs accepted per run |

### Silent mode

```bash
xss-scan -i subs.txt -o run1 --silent      # same as -q / --quiet
```

Only XSS hits and the final status reach the terminal:

```
[+] XSS query batch 1: https://shop.example.com/search?q=... param=q  [reflected-param-all-xss]
[+] XSS verified: https://shop.example.com/search?q=... param=q  [exec-proof ok]
[*] done: out (coverage.complete=true)
```

Everything else — httpx alive counts, katana chunks, gau waves, ingest stats,
form passes, batch progress — goes to `run/logs/run.log`. Nothing is skipped:
the scan keeps running after each hit and prints the next one when found.

Findings are emitted per batch right after `ctxfilter`, so a confirmed false
positive never appears. Verified hits are printed per verify batch with the
`exec-proof ok` marker. Errors and fatal messages still show on the terminal.

Tail the log while it runs:

```bash
tail -f run1/logs/run.log
```

Notes:

- notify still works in silent mode (independent of terminal output)
- `--silent` only changes display, not rates, coverage, or work queues
- wrapper scripts and systemd units should keep stdout captured; findings then
  appear in the journal only, so use `--notify` there

### Domain-level progress

Two files in the run directory, updated after every batch and at the end:

| file | contents |
|---|---|
| `hosts-done.txt` | one hostname per line, fully scanned (no pending/running/failed work) |
| `hosts-completed.log` | `timestamp host` for each domain the first time it finished |

A host counts as complete only when every URL and every job that resolves to it
is `done`. Any deferred, retrying, or failed item keeps it out of the list, so
the file never overstates coverage.

Check progress while running:

```bash
wc -l run1/hosts-done.txt        # domains finished
tail run1/hosts-completed.log    # when each one finished
```

With `--silent` a progress line is printed only when the count changes:

```
[*] hosts complete: 0/3252
[*] hosts complete: 7/3252
```

Without `--silent` the same line appears after each query/path/body batch:

```
[*] hosts complete: 128/3252 (in progress 41, not started 3083)
```

Re-runs keep both files and only append domains newly finished.

### Per-host mode (space-saving)

```bash
xss-scan -i subs.txt -o run1 --per-host --silent
xss-scan -i subs.txt -o run1 --per-host-chunk 5   # 5 domains per slice
```

Instead of "all hosts through every stage", each domain runs the full pipeline
alone: gau -> crawl -> JS -> forms -> query/path/body -> verify. Then its temp
run dir is merged into `run1/` and deleted.

Why: a 2000-host run otherwise keeps every discovered URL for every host at
once. Here the working set is one domain, so `queue.db`, crawl chunks, gau
output, and JS downloads are freed after each domain.

What is kept in `run1/` (aggregates only):

| file | meaning |
|---|---|
| `results.jsonl` | all findings, deduped |
| `confirmed.jsonl` | exec-proof confirmed findings |
| `verify-report.jsonl` | per-attempt verification detail |
| `requests/` | raw HTTP dumps (`pN-<name>.txt`, unique per part) |
| `hosts-done.txt` | completed domains |
| `hosts-completed.log` | timestamp per finished domain |
| `urls-done.txt` | every scanned URL (state=done) |
| `coverage.json` | `mode: per-host`, per-part status, totals |
| `logs/per-host.log` | child run output |

Per-host temp dirs live at `run1/.parts/pN` and are removed right after merge,
so disk stays near one domain's footprint plus the aggregates.

Progress:

```
[*] per-host mode: 2000 host(s), 1 per batch, one run dir reused
[+] XSS hit: https://shop.example.com/search?q=... param=q  [reflected-param-all-xss]
[*] hosts complete: 1/2000 (shop.example.com)
[*] per-host done: 2000/2000 host(s) complete
```

`urls-done.txt` is rewritten only when the completed-URL count changes, and is
written to a `.tmp` then renamed so a reader never sees a partial file.

Resume: re-run the same command with the same `-o`. Domains already listed in
`hosts-done.txt` are still re-scanned (their temp dirs are gone), so trim the
input first if you only want the remainder:

```bash
grep -vxF -f run1/hosts-done.txt subs.txt > todo.txt
xss-scan -i todo.txt -o run1 --per-host --silent
```

Note on logs in per-host mode: each domain's `logs/run.log` is appended to
`run1/logs/run.log` under a `===== part pN log =====` header before the temp
directory is deleted, so the full history stays readable:

```bash
grep -n "===== part" run1/logs/run.log
tail -f run1/logs/run.log
```

### Disk hygiene: tool output overwrites, never accumulates

Tool URL output no longer grows across hosts or batches.

- katana writes to one buffer with `>` (`run/.tool-urls.tmp`), the buffer is
  ingested, then truncated with `: >` before the next chunk
- gau writes per host with `>`, and the file is deleted immediately after ingest
- JS extraction writes the same buffer with `>`, ingest, truncate
- `run/.tool-urls.tmp` is reused for every stage; transient copies of URLs never
  sit on disk waiting for something else
- stale `.gau-work/` and `.js-dl/` from an interrupted run are removed at startup

Logs are capped instead of deleted, so recent errors survive:

| log | cap |
|---|---|
| `logs/katana.log` | 5 MB |
| `logs/gau.log` | 5 MB |
| `logs/js.log` | 2 MB |
| `logs/nuclei-batch-*.log` | 4 MB |
| `logs/nuclei-path-*.log` | 4 MB |
| `logs/live.log` | 4 MB |

When a log passes its cap, the last `cap` bytes are kept (`tail -c`) and the
older part is dropped. Nothing else is truncated.
