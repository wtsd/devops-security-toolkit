#!/usr/bin/env bash
set -euo pipefail

if [[ "${AUTH_OK:-}" != "1" ]]; then
  echo "Refusing to run without AUTH_OK=1 (authorization confirmation)."
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target> [nmap_args]"
  echo "Example: $0 192.168.1.0/24 -sV --top-ports 200"
  exit 1
fi

TARGET="$1"; shift || true
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="results/nmap"
mkdir -p "$OUTDIR"

PROFILE_ARGS=( -Pn -sV --top-ports 200 --reason --defeat-rst-ratelimit -oA "$OUTDIR/scan_${TS}" )
# Allow override/extension
nmap "${PROFILE_ARGS[@]}" "$@" "$TARGET"

echo "[*] Scan complete. Files in $OUTDIR/scan_${TS}.*"
