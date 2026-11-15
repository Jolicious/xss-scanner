# xss-scan on a VPS

Everything below assumes a Debian/Ubuntu VPS and an authorized target.

## 1. Install

```bash
sudo apt update && sudo apt install -y python3 jq unzip curl
sudo apt install -y golang-go || true

export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/gau/v2/cmd/gau@latest        # optional
go install -v github.com/projectdiscovery/katana/cmd/katana@latest    # optional
```

Headless verification needs a browser:

```bash
sudo apt install -y chromium || sudo apt install -y chromium-browser
# nuclei finds it automatically; if not:
export CHROME_PATH=$(command -v chromium || command -v chromium-browser)
```

Copy the templates:

```bash
mkdir -p ~/xss
scp -r user@workstation:~/learn/custom-nuclei-templates/xss ~/xss-templates
chmod +x ~/xss-templates/xss-scan.sh ~/xss-templates/xss-queue.py ~/xss-templates/xss-report.py
~/xss-templates/xss-scan.sh -h | head -3
```

## 2. Target list + token

```bash
mkdir -p ~/scans
cat > ~/scans/subs.txt <<'EOF'
app.example.com
api.example.com
shop.example.com:8443
EOF

# bearer token, readable only by you
install -m 600 /dev/null ~/scans/token.txt
printf '%s' 'eyJhbGciOi...' > ~/scans/token.txt
```

## 3. notify provider config

```bash
mkdir -p ~/.config/notify
cat > ~/.config/notify/provider-config.yaml <<'EOF'
discord:
  - id: xss-alerts
    discord:
      - "https://discord.com/api/webhooks/XXXX/YYYY"
      - "{{data}}"          # message body
    discord-format: markdown

slack:
  - id: xss-slack
    slack:
      - "https://hooks.slack.com/services/AAA/BBB/CCC"
    slack-format: markdown

# mail (optional)
smtp:
  - id: xss-mail
    smtp:
      - "smtp.gmail.com"
      - "587"
      - "you@gmail.com"
      - "app-password"
      - "you@gmail.com"
EOF
chmod 600 ~/.config/notify/provider-config.yaml

notify -pc ~/.config/notify/provider-config.yaml -id xss-alerts -data /dev/stdin <<< "notify test"
```

## 4. Run with alerts

```bash
~/xss-templates/xss-scan.sh \
  -i ~/scans/subs.txt \
  -o ~/scans/run-$(date +%F) \
  --token-file ~/scans/token.txt \
  --verify \
  --notify --notify-id xss-alerts \
  --notify-summary
```

What gets sent:

- one message per **confirmed** finding (`exec-proof`), with URL, param, proof token
- `--notify-summary` sends a short run summary even when nothing is found
- body/form/JSON reflections are never sent as confirmed; they stay local as
  `manual_confirmation_required`

No findings, no spam: without `--notify-summary`, a clean run sends nothing.

## 5. Long runs (tmux / systemd)

tmux:

```bash
tmux new -s xss
~/xss-templates/xss-scan.sh -i ~/scans/subs.txt -o ~/scans/run1 --token-file ~/scans/token.txt --verify --notify --notify-id xss-alerts
# detach: Ctrl-b d ; reattach: tmux a -t xss
```

systemd unit (`/etc/systemd/system/xss-scan.service`):

```ini
[Unit]
Description=xss-scan
After=network-online.target

[Service]
Type=oneshot
User=scanner
WorkingDirectory=/home/scanner/scans
Environment=HOME=/home/scanner
Environment=CHROME_PATH=/usr/bin/chromium
ExecStart=/home/scanner/xss-templates/xss-scan.sh \
  -i /home/scanner/scans/subs.txt \
  -o /home/scanner/scans/run-%Y%m%d \
  --token-file /home/scanner/scans/token.txt \
  --verify \
  --notify --notify-id xss-alerts --notify-summary
TimeoutStartSec=0
Nice=10
IOSchedulingClass=idle
```

Weekly timer (`/etc/systemd/system/xss-scan.timer`):

```ini
[Unit]
Description=weekly xss scan

[Timer]
OnCalendar=Mon 02:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now xss-scan.timer
journalctl -u xss-scan -f
```

## 6. Disk + resume behaviour

- one run dir holds `queue.db` (~60-100 bytes/URL), `results.jsonl`,
  `verify-report.jsonl`, `confirmed.jsonl`, `notify-findings.jsonl`, `logs/`
- 5k URLs with verification ≈ 300 KB; 200k URLs ≈ tens of MB
- interrupted run: re-run the same command with `-o <same dir>`; it resumes
- `--max-disk-mb 2048` stops before the volume fills, leaving work queued
- changing token/scope/templates on an old dir is refused; use a new dir or
  `--force-config`

## 7. Egress

Headless verification loads pages in a real browser. If your authorization is
strictly host-scoped, run the scanner where outbound traffic is limited to the
approved hosts (security group / nftables), because redirects and subresources
are not blocked by the tool itself.

## 8. Reading results on the VPS

```bash
~/xss-templates/xss-report.py ~/scans/run1
```

Green = confirmed by headless execution, yellow = manual body reflection,
red = verification problems or incomplete stages. Add `--all` to see refuted
endpoints, `--no-color` for logs.
