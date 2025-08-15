#!/usr/bin/env bash
set -euo pipefail

if [[ "${AUTH_OK:-}" != "1" ]]; then
  echo "Refusing to run without AUTH_OK=1 (authorization confirmation)."
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target> [nmap_args]"
  echo "Example: $0 example.com --script vuln,ssl-enum-ciphers"
  exit 1
fi

TARGET="$1"; shift || true
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="results/nmap"
mkdir -p "$OUTDIR"

SCRIPTS="vuln,ssl-enum-ciphers,ssl-cert,http-security-headers"
nmap -Pn -sV --script "$SCRIPTS" -oA "$OUTDIR/vuln_${TS}" "$@" "$TARGET"

echo "[*] Vuln script run complete. Files in $OUTDIR/vuln_${TS}.*"
