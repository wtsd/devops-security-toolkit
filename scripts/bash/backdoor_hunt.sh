#!/usr/bin/env bash

# Read more about rootkit hunting: https://rkhunter.sourceforge.net/

set -euo pipefail

if [[ "${AUTH_OK:-}" != "1" ]]; then
  echo "Refusing to run without AUTH_OK=1 (authorization confirmation)."
  echo "Usage: sudo AUTH_OK=1 ./backdoor_hunt.sh"
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root for complete results." >&2
fi
umask 077
trap 'echo "[!] Aborted (signal)"; exit 2' INT TERM

need() { command -v "$1" >/dev/null 2>&1 || echo "[!] Missing: $1"; }


for c in ss awk sort grep find systemctl stat getcap sed cut xargs; do need "$c"; done

###

TS="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname -f 2>/dev/null || hostname)"

OUTDIR="results/reports"
mkdir -p "$OUTDIR"

REPORT="$OUTDIR/backdoor_detection_${TS}.txt"
# For json formatted report:
JSON="$OUTDIR/backdoor_detection_${TS}.json"
BASE_SUID="${BASE_SUID:-results/baselines/suid.list}"

###

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


  # PATH hygiene
  echo "== PATH hygiene (world/group writable dirs, non-root owners) =="
  IFS=':' read -ra P <<< "${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
  
  for d in "${P[@]}"; do
    [[ -d "$d" ]] || continue
  
    perms="$(stat -c '%A %U:%G' "$d" 2>/dev/null || true)"
    sticky="$(stat -c '%a' "$d" 2>/dev/null || echo '')"
    printf "%s  %s\n" "$d" "$perms"

    # flag if writable by group/other
    if [[ -w "$d" && ( $(stat -c '%A' "$d") =~ .{7}w|.{8}w ) ]]; then
      echo "  [!] Writable by non-owner"
    fi

    # sticky bit absence for world-writable dirs
    if [[ "$sticky" =~ ^[0-7]??7$ ]] && [[ ! -k "$d" ]]; then
      echo "  [!] World-writable without sticky bit"
    fi
  
    # files in PATH not owned by root
    find "$d" -maxdepth 1 -type f ! -user root -printf "  [!] Non-root file: %u:%g %m %p\n" 2>/dev/null || true
  done
  echo

  # SUID/SGID
  echo "== SUID/SGID files (new/odd) =="
  mapfile -t suids < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%u %g %m %p\n" 2>/dev/null | sort -u || true)
  if [[ -s "$BASE_SUID" ]]; then
    echo "-- Baseline diff vs $BASE_SUID"
    # Normalize to path list for diff
    printf "%s\n" "${suids[@]}" | awk '{print $NF}' | sort -u > /tmp/suid_now.$$ || true
    comm -13 <(sort -u "$BASE_SUID") /tmp/suid_now.$$ | sed 's/^/[NEW] /' || true
    rm -f /tmp/suid_now.$$
  fi
  printf "%s\n" "${suids[@]}"
  echo

  # Capabilities
  echo "== Files with Linux capabilities =="
  if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null | sed 's/^/[cap] /' || true
  else
    echo "(getcap not available)"
  fi
  echo


  # World-writavle in sensitive paths
  echo "== World-writable files/dirs in sensitive paths =="
  find /etc /usr /var /opt -xdev \( -type d -o -type f \) -perm -0002 -printf "%m %p\n" 2>/dev/null || true
  echo


  # JOBS:

  # Jobs: Cronjobs
  echo "== Cron jobs =="
  crontab -l 2>/dev/null || echo "(no user crontab)"

  ls -la /etc/cron* 2>/dev/null || true

  for f in /etc/crontab /etc/cron.d/*; do [[ -e "$f" ]] && \
    { echo "-- $f"; sed -n '1,200p' "$f"; echo; }; done
  echo

  # Jobs: at jobs
  echo "== at jobs =="
  (atq 2>/dev/null || echo "(no at)") && echo
  echo

  # Startup & daemons: systemd
  # Startup & daemons: rc.local
  echo "== Systemd services & timers (system) =="
  systemctl list-units --type=service --all 2>/dev/null | awk 'NR==1 || /loaded/ {print}' || true
  systemctl list-timers --all 2>/dev/null || true
 
  echo "-- Suspicious names (reverse|shell|nc|socat|backdoor|tty|hidden)"
  (systemctl list-units --type=service --all 2>/dev/null | grep -Ei "reverse|shell|nc|socat|backdoor|tty|hidden" || true)
 
  echo "-- Unit file ExecStart for enabled services"
  while IFS= read -r u; do
    systemctl show "$u" -p FragmentPath,ExecStart 2>/dev/null | sed "s/^/[unit] $u /"
  done < <(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | awk 'NR>1{print $1}' | sed 's/@.*//g' | sort -u)
  echo

  # systemd (per user)
  echo "== Systemd user services (per user) =="
  while IFS=: read -r name _ uid gid home shell; do
    [[ "$uid" -ge 1000 && -d "$home" ]] || continue
    echo "-- user: $name ($uid) home: $home"

    sudo -u "$name" XDG_RUNTIME_DIR=/run/user/"$uid" systemctl --user list-units --type=service --all 2>/dev/null || true
    sudo -u "$name" XDG_RUNTIME_DIR=/run/user/"$uid" systemctl --user list-timers --all 2>/dev/null || true
  done < /etc/passwd
  echo
 

  # SSH
  echo "== SSH authorized_keys with options =="
  while IFS= read -r f; do
    echo "-- $f"
    grep -nE '^(command=|from=|environment=|permitopen=|tunnel=|agent-forwarding|port-forwarding)' "$f" || echo "(no options)"
  
    # permissions
    perms="$(stat -c '%A %U:%G' "$f" 2>/dev/null || true)"
    echo "   perms: $perms"
  done < <(find /home /root -maxdepth 3 -name authorized_keys 2>/dev/null)
  echo

  echo "== SSHD config deltas =="
  if [[ -f /etc/ssh/sshd_config ]]; then
    # Make sure nothing is enabled in sshd
    #egrep -i '^(PermitRootLogin|PasswordAuthentication|AuthorizedKeysCommand|[A-Za-z+]Root[A-Za-z+])\b' /etc/ssh/sshd_config || true 
    egrep -i '^(PermitRootLogin|PasswordAuthentication|AuthorizedKeysCommand|AllowUsers|AllowGroups|GatewayPorts|PermitTunnel)\b' /etc/ssh/sshd_config || true
  fi
  echo


  # Shell startup files
  echo "== Shells (curls, nc, reverse shells) =="
  GREP='(curl|wget).*(sh|bash)|bash -i|nc -e|socat|mkfifo .* /dev/tcp|/dev/tcp/'
  while IFS= read -r f; do
    echo "-- $f"
    grep -nE "$GREP" "$f" || echo "(clean)"

  done < <(find /etc/profile.d -type f -maxdepth 1 2>/dev/null; \
    find /root /home -maxdepth 2 -type f \( -name ".bashrc" -o \
    -name ".bash_profile" -o -name ".profile" \) 2>/dev/null)
  echo


  # /tmp, /var/tmp
  echo "== Recent executables in /tmp and /var/tmp (last 7 days) =="
  for d in /tmp /var/tmp; do
    echo "-- $d"
    find "$d" -xdev -type f -mtime -7 \( -executable -o -name '*.so' -o -name '*.bin' \) -printf "%TY-%Tm-%Td %TH:%TM %M %u:%g %p\n" 2>/dev/null || true
  done
  echo



  # ld.so.preload
  # Read more: https://www.defensive-security.com/blog/preventing-modification-of-etcldsopreload-with-selinux
  echo "== /etc/ld.so.preload (if present) =="
  if [[ -s /etc/ld.so.preload ]]; then
    cat /etc/ld.so.preload
    echo "[!] WARNING: ld.so.preload in use; ensure libraries are legitimate"
  else
    echo "(absent)"
  fi
  echo

  
  # sudoers:
  echo "== Users with login shells (UID >= 1000) =="
  awk -F: '($3>=1000)&&($7~/bash|zsh|sh/){print $1":"$3":"$6":"$7}' /etc/passwd || true
  
  echo "-- /etc/passwd mtime: $(stat -c %y /etc/passwd 2>/dev/null || echo n/a)"
  echo "-- /etc/shadow mtime: $(stat -c %y /etc/shadow 2>/dev/null || echo n/a)"
  
  echo


  # users and password changes
  echo "== Users with login shells (UID >= 1000) =="
  awk -F: '($3>=1000)&&($7~/bash|zsh|sh/){print $1":"$3":"$6":"$7}' /etc/passwd || true
  
  echo "-- /etc/passwd mtime: $(stat -c %y /etc/passwd 2>/dev/null || echo n/a)"
  echo "-- /etc/shadow mtime: $(stat -c %y /etc/shadow 2>/dev/null || echo n/a)"
  
  echo

  # Kernel modules
  echo "== Kernel modules not under /lib/modules (if any) =="
  if command -v lsmod >/dev/null 2>&1 && command -v modinfo >/dev/null 2>&1; then
    while read -r m; do
      p="$(modinfo -n "$m" 2>/dev/null || true)"
    
      [[ -n "$p" && "$p" != /lib/modules/* ]] && echo "$m -> $p"
    
    done < <(lsmod | awk 'NR>1{print $1}')
  fi

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
