#!/usr/bin/env bash
set -euo pipefail

if [[ "${AUTH_OK:-}" != "1" ]]; then
  echo "Refusing to run without AUTH_OK=1 (authorization confirmation)."
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root for complete results." >&2
fi
umask 077
trap 'echo "[!] Aborted (signal)"; exit 2' INT TERM

need() { command -v "$1" >/dev/null 2>&1 || echo "[!] Missing: $1"; }

for c in ss awk sort grep find systemctl stat getcap sed cut xargs; do need "$c"; done

TS="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname -f 2>/dev/null || hostname)"

OUTDIR="results/reports"
mkdir -p "$OUTDIR"

REPORT="$OUTDIR/backdoor_detection_${TS}.txt"
# For json formatted report:
JSON="$OUTDIR/backdoor_detection_${TS}.json"
BASE_SUID="${BASE_SUID:-results/baselines/suid.list}"

echo "[*] Writing: $REPORT"

{
  echo "== Host =="
  echo "Host: $HOST"
  echo "Date (UTC): $TS"
  uname -a 2>/dev/null || true

  echo 

  # Sus software listening ports except the common ones
  echo "== Suspicious listening ports (with processes) =="
  COMMON=':22|:80|:443|:53|:25|:110|:143|:587|:993|:995|:3306|:5432|:6379|:27017|:3000|:5000|:8080|:8443'
  if ss -lntup 2>/dev/null | tail -n +2 | awk '{print $1,$5,$7}' | grep -vE "$COMMON" | sort -u; then :; else echo "(none or ss unavailable)"; fi
  echo


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

# For json summary
{
  printf '{\n'
  printf '  "hostname": %q,\n' "$HOST"
  printf '  "timestamp_utc": %q,\n' "$TS"

  # Count a few signals
  suspicious_ports=$(ss -lntup 2>/dev/null | tail -n +2 | grep -vE "$COMMON" | wc -l || echo 0)
  ww_dirs=$(find /etc /usr /var /opt -xdev -type d -perm -0002 2>/dev/null | wc -l || echo 0)
  caps=$( (getcap -r / 2>/dev/null | wc -l) || echo 0 )
  tmp_execs=$(find /tmp /var/tmp -xdev -type f -mtime -7 -executable 2>/dev/null | wc -l || echo 0)
  printf '  "suspicious_listeners": %s,\n' "$suspicious_ports"
  printf '  "world_writable_dirs": %s,\n' "$ww_dirs"
  printf '  "files_with_capabilities": %s,\n' "$caps"
  printf '  "recent_tmp_execs": %s\n' "$tmp_execs"
  printf '}\n'
} > "$JSON" 2>/dev/null || true


echo "[*] Backdoor detection sweep complete."
