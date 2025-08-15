#!/usr/bin/env bash
set -euo pipefail

if [[ "${AUTH_OK:-}" != "1" ]]; then
  echo "Refusing to run without AUTH_OK=1 (authorization confirmation)."
  exit 1
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="results/reports"
mkdir -p "$OUTDIR"

REPORT="$OUTDIR/backdoor_detection_${TS}.txt"
echo "[*] Writing: $REPORT"

{
  echo "== Suspicious listening ports (non-standard) =="
  ss -lntu | awk 'NR>1 {print $1,$5}' | sort -u

  echo -e "\n== Unowned files in PATH =="
  IFS=':' read -ra P <<< "$PATH"
  for d in "${P[@]}"; do
    [[ -d "$d" ]] || continue
    find "$d" -maxdepth 1 -type f -perm -4000 -printf "%m %u %g %p\n" 2>/dev/null || true
  done

  echo -e "\n== New/odd SUID files =="
  find / -xdev -perm -4000 -type f -printf "%u %g %m %p\n" 2>/dev/null | sort || true

  echo -e "\n== World-writable directories in sensitive paths =="
  find /etc /usr /var /opt -xdev -type d -perm -0002 -printf "%m %p\n" 2>/dev/null || true

  echo -e "\n== Cron jobs =="
  crontab -l 2>/dev/null || true
  ls -la /etc/cron* 2>/dev/null || true

  echo -e "\n== SSH authorized_keys with commands/agents =="
  while IFS= read -r f; do
    echo "-- $f"
    grep -nE 'command=|from=' "$f" || true
  done < <(find /home /root -maxdepth 3 -name authorized_keys 2>/dev/null)

  echo -e "\n== Recent /tmp executables =="
  find /tmp -type f -executable -mtime -7 -printf "%TY-%Tm-%Td %TH:%TM %p\n" 2>/dev/null || true

  echo -e "\n== Systemd user services and suspicious names =="
  systemctl list-units --type=service --all 2>/dev/null | grep -Ei "reverse|shell|nc|socat|backdoor" || true

} | tee "$REPORT"

echo "[*] Backdoor detection sweep complete."
