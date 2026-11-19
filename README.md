# xss-scan

Queue-driven reflected XSS scanner for authorized targets. Discovery → scan →
headless verification → report/notify, with resumable state in SQLite.

Authorized testing only.

> [!NOTE]
> **Disclaimer:** This tool does not guarantee the detection of all Cross-Site Scripting (XSS) vulnerabilities. A clean scan result does not necessarily mean the target is free from XSS. Manual testing and additional security assessments are recommended.

## Requirements

```
python3  curl  jq(optional)
httpx     (ProjectDiscovery)
nuclei    (ProjectDiscovery)
notify    (ProjectDiscovery, optional)
katana    (optional, crawl)
gau       (optional, archive URLs)
chromium / chrome-headless-shell (optional, execution proof)
```

## Install

```bash
sudo mkdir -p /opt/xss-scan
git clone https://github.com/Jolicious/xss-scanner.git /tmp/xss-src
sudo cp /tmp/xss-src/*.sh /tmp/xss-src/*.py /tmp/xss-src/*.yaml /opt/xss-scan/
sudo chmod +x /opt/xss-scan/xss-scan.sh /opt/xss-scan/xss-queue.py \
  /opt/xss-scan/xss-report.py /opt/xss-scan/xss-clean-fp.sh
sudo sed -i 's/\r$//' /opt/xss-scan/*.sh /opt/xss-scan/*.py
```

Keep every file in one directory: the script loads `xss-queue.py` and the
templates from its own folder.

## Make the command global

Wrapper script, not a symlink (a symlink breaks the self-directory lookup):

```bash
printf '#!/usr/bin/env bash\nexec /opt/xss-scan/xss-scan.sh "$@"\n' \
  | sudo tee /usr/local/bin/xss-scan
sudo chmod 755 /usr/local/bin/xss-scan
```

No-sudo alternative:

```bash
mkdir -p ~/.local/bin
printf '#!/usr/bin/env bash\nexec /opt/xss-scan/xss-scan.sh "$@"\n' > ~/.local/bin/xss-scan
chmod +x ~/.local/bin/xss-scan
grep -q '.local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Check:

```bash
xss-scan -h | head -3
```

## Usage

```bash
xss-scan -i subs.txt -o run1 --per-host --silent
```

Input: subdomains or URLs, one per line, scheme optional.

Output directory (`-o`, created in the current directory):

```
run1/
├── results.jsonl          # all candidates
├── confirmed.jsonl        # headless-proven XSS
├── verify-report.jsonl
├── coverage.json          # complete, failure counters
├── hosts-done.txt         # finished domains
├── hosts-completed.log
├── urls-done.txt          # scanned URLs
├── requests/              # raw HTTP for manual replay
└── logs/                  # run.log, notify.log, per-stage logs
```

## Modes

`--per-host` (recommended for large lists) runs the full pipeline per domain:
gau → sitemap/robots → crawl → JS mining → forms → query/path/body → verify.
Temp state is merged into `-o` and deleted after each host, so disk stays flat.

Without `--per-host` one pipeline covers the whole list.

## Defaults

| setting | value |
|---|---|
| per-host rate / concurrency | 10 rps / 3 |
| scan rate after crawl | 25 rps |
| crawl | depth 3, 900s budget, retries + link harvest when damped |
| POST forms | **disabled** (opt in with `--forms-post`) |
| body probing | parallel, 3600s budget |
| verification | on when a browser is present |
| notify | on when `~/.config/notify/provider-config.yaml` exists |

## Useful flags

```
--per-host --per-host-jobs N    run N hosts in parallel (default 3)
--cookie-file PATH              cookie from file (handles quotes/CRLF)
--verify / --no-verify          headless execution proof
--api-reflections               report JSON/text API echoes as information
--forms-post                    enable POST/JSON body probing (state-changing)
--retry-failed                  requeue failures on resume
--insecure-tls                  disable TLS certificate verification (opt-in)
--no-notify                     never notify, even if a provider config exists
```

TLS is verified by default. `--insecure-tls` (or `XSS_INSECURE_TLS=1`) is the
only way to turn verification off, and the resolved mode is printed at start
(`[*] tls: verify=on ...`). A private CA can be added without weakening
verification: `XSS_CA_BUNDLE=/path/to/ca.pem`.

Per-host mode runs one httpx pass over the whole list first, then only alive
hosts get a pipeline; dead hosts are skipped.

## Tests

```
bash tests/run.sh                   # full local release gate
python3 tests/test_host_status.py   # queue completion + reflection classifier
bash    tests/test_notify.sh        # --no-notify vs provider auto-discovery
bash    tests/test_resume.sh        # SIGTERM mid-scan + --continue recovery
python3 tests/fixture_suite.py      # real nuclei + chromium execution proof
```

`fixture_suite.py` starts the fixture server, injects a token-bearing payload
into executable and inert contexts, and asserts that only real browser
execution produces an `exec-proof` extractor hit. It also checks that a
redirect to an out-of-scope host never reaches the browser and that a wrong
extractor name cannot confirm an attempt. Exit code 77 means nuclei/chromium
were not found (skipped).

`run.sh` is what CI runs (`.github/workflows/ci.yml`), with pinned
nuclei/httpx versions.

## Coverage fields

`coverage.json` reports the declared plan, not "everything was tested":

- `discovery_caps` — JS bundle/extraction caps, discovered vs processed bundles,
  crawl rounds, URL/job caps
- `body_params_tested` / `body_params_by_outcome` — per-parameter body-probe
  ledger (`{method, endpoint, parameter, payload family, outcome}`)
- `tool_versions` — nuclei/httpx/katana/chromium versions used for the run
- `body_probing_requested` — whether POST/JSON probing was authorized

Tested with: nuclei 3.11.1, httpx 1.9.0, Chromium 150.

## Notification accuracy

Candidates are notified only after context filtering:

| reflection | context | reported |
|---|---|---|
| raw payload in HTML `<script>`/markup | `html` | candidate -> headless confirm |
| entity/JS-escaped (`&#x27;`, `\u0027`) | `escaped` | `escaped.txt` only |
| inside `__NEXT_DATA__` / JSON script | `json_data` | dropped |
| `text/plain` / JSON API echo | `non_html` | dropped (see `--api-reflections`) |
| 429 / 503 | `blocked` | retried next pass |

## Notifications

Per batch, deduplicated per endpoint + parameter:

```
XSS CANDIDATES — not confirmed, verify manually (batch 1) (5)
MANUAL POST XSS — not confirmed, verify manually (batch 1) (3)
XSS CONFIRMED — execution proven (exec-proof) (4)
```

One `xss-scan finished` message at the end, only when findings exist.

## Exit codes

```
0  complete, no outstanding work
3  partial: findings kept, coverage incomplete
1  error / strict failure
130 interrupted (Ctrl+C)
```

Re-run with the same `-o` to resume; add `--retry-failed` to requeue failures.

## Limits

- POST/JSON findings are manual candidates; headless proof covers URL execution only
- no DOM-XSS, stored XSS, or blind XSS
- discovery is crawl/sitemap/archive/JS-literal based: no directory brute force
- pages the crawler cannot reach (offline, login-walled, client-rendered) are not tested
