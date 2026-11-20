#!/usr/bin/env bash
# Install the scanner's external tools. Debian/Ubuntu, run as root or with sudo.
# Go puts binaries in $HOME/go/bin, which xss-scan.sh already searches first.
set -uo pipefail

say() { printf '[*] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

say "apt packages"
apt-get update -qq
apt-get install -y -qq git curl wget jq unzip python3 ca-certificates \
  build-essential libpcap-dev fonts-liberation >/dev/null

if ! have go; then
  say "go toolchain"
  GOVER="${GOVER:-1.24.4}"
  cd /tmp || exit 1
  wget -q "https://go.dev/dl/go${GOVER}.linux-amd64.tar.gz" -O go.tgz
  rm -rf /usr/local/go && tar -C /usr/local -xzf go.tgz && rm -f go.tgz
fi
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
mount | grep -q ' /usr/local/go ' || true
go version || { echo "[-] go missing" >&2; exit 1; }

export GOBIN="$HOME/go/bin"
mkdir -p "$GOBIN"

# each module must be installed by its own go install invocation
for mod in \
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
  "github.com/projectdiscovery/httpx/cmd/httpx@latest" \
  "github.com/projectdiscovery/katana/cmd/katana@latest" \
  "github.com/projectdiscovery/notify/cmd/notify@latest" \
  "github.com/lc/gau/v2/cmd/gau@latest"
do
  say "go install ${mod%@*}"
  GOTOOLCHAIN=auto go install "$mod" || echo "[!] failed: $mod" >&2
done

say "nuclei templates"
"$GOBIN/nuclei" -update-templates >/dev/null 2>&1 || true

if ! have chromium && ! have chromium-browser && ! have google-chrome; then
  say "chrome (needed for --verify headless)"
  cd /tmp || exit 1
  if wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O chrome.deb; then
    apt-get install -y -qq ./chrome.deb >/dev/null 2>&1 || echo "[!] chrome install failed" >&2
    rm -f chrome.deb
  fi
fi

say "optional param miners (arjun, x8)"
if have pip3; then
  pip3 install --quiet --break-system-packages arjun >/dev/null 2>&1 || true
fi
if have cargo; then
  cargo install --quiet x8 >/dev/null 2>&1 || true
fi

say "versions"
for t in nuclei httpx katana gau notify; do
  p="$GOBIN/$t"
  if [ -x "$p" ]; then
    printf '  %-8s %s\n' "$t" "$("$p" -version 2>&1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  else
    printf '  %-8s MISSING\n' "$t"
  fi
done
for b in chromium chromium-browser google-chrome; do
  command -v "$b" >/dev/null 2>&1 && echo "  $b $(command -v "$b")"
done

say "done. add to your shell rc if missing:"
echo '  export PATH=$HOME/go/bin:$PATH'
