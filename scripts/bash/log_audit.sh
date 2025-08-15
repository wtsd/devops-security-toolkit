#!/usr/bin/env bash
set -euo pipefail

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="results/reports"
mkdir -p "$OUTDIR"

AUTH_LOG="${1:-/var/log/auth.log}"
echo "[*] Analyzing auth log: $AUTH_LOG"
python3 scripts/python/log_analyzer.py --auth-log "$AUTH_LOG" --out "$OUTDIR/auth_report_${TS}.json"

if [[ -f "/var/log/syslog" ]]; then
  echo "[*] Checking syslog for suspicious commands..."
  grep -E "sudo:|COMMAND=|sudoers|password" /var/log/syslog || true
fi
