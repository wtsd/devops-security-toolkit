#!/usr/bin/env bash
set -euo pipefail

# Defensive: only run on authorized hosts
if [[ "${AUTH_OK:-}" != "1" ]]; then
  echo "Refusing to proceed: set AUTH_OK=1 to confirm you are authorized."
  exit 1
fi

echo "[*] Detecting package manager..."
PM=""
if command -v apt-get >/dev/null 2>&1; then PM="apt"
elif command -v yum >/dev/null 2>&1; then PM="yum"
elif command -v dnf >/dev/null 2>&1; then PM="dnf"
elif command -v apk >/dev/null 2>&1; then PM="apk"
elif command -v brew >/dev/null 2>&1; then PM="brew"
else
  echo "No supported package manager found. Install dependencies manually: nmap jq python3 php-cli"
  exit 1
fi

echo "[*] Using: $PM"
case "$PM" in
  apt)
    sudo apt-get update
    sudo apt-get install -y nmap jq python3 python3-pip php-cli php-xml php-mbstring git
    ;;
  yum|dnf)
    sudo $PM install -y nmap jq python3 python3-pip php-cli git
    ;;
  apk)
    sudo apk add --no-cache nmap jq python3 py3-pip php81 php81-xml php81-mbstring git
    ;;
  brew)
    brew install nmap jq python php git
    ;;
esac

echo "[*] Installing Python deps..."
python3 -m pip install --user -r docker/requirements.txt || true

echo "[*] (Optional) Install gitleaks:"
echo "    https://github.com/gitleaks/gitleaks#install"
echo "[*] (Optional) Install trufflehog:"
echo "    https://github.com/trufflesecurity/trufflehog#install"

echo "[*] Done."
