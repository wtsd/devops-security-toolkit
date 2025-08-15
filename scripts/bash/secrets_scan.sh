#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <directory_or_repo_url>"
  exit 1
fi

TARGET="$1"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="results/reports"
mkdir -p "$OUTDIR"

if [[ -d "$TARGET/.git" || -d "$TARGET" ]]; then
  echo "[*] Scanning directory: $TARGET"
  if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --no-banner -v -s "$TARGET" --report-format json --report-path "$OUTDIR/gitleaks_${TS}.json" || true
  fi
  if command -v trufflehog >/dev/null 2>&1; then
    trufflehog filesystem --json "$TARGET" > "$OUTDIR/trufflehog_${TS}.json" || true
  fi
  # Fallback to internal regex scanner
  python3 scripts/python/secret_patterns.py --path "$TARGET" --out "$OUTDIR/regex_secrets_${TS}.json"
else
  echo "Target not a directory. If it's a repo URL, clone it first."
  exit 1
fi

echo "[*] Secret scan complete. See $OUTDIR/*_${TS}.json"
