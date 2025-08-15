#!/usr/bin/env bash
set -euo pipefail

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="results/reports"
mkdir -p "$OUTDIR"
REPORT="$OUTDIR/hardening_${TS}.txt"

{
  echo "== SSH config checks =="
  if [[ -f /etc/ssh/sshd_config ]]; then
    grep -E '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication)' /etc/ssh/sshd_config || true
  fi

  echo -e "\n== Firewall presence =="
  command -v ufw >/dev/null && sudo ufw status || true
  command -v firewall-cmd >/dev/null && sudo firewall-cmd --state || true

  echo -e "\n== Accounts without passwords =="
  awk -F: '($2=="!" || $2=="*" || $2=="x"){next} $2==""{print $1}' /etc/shadow 2>/dev/null || true

  echo -e "\n== World-writable files in /etc =="
  find /etc -xdev -type f -perm -0002 -print 2>/dev/null || true

  echo -e "\n== Kernel hardening flags (sysctl) =="
  sysctl kernel.kptr_restrict net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects 2>/dev/null || true

  echo -e "\n== Packages with known issues (if deb-based) =="
  command -v apt >/dev/null && apt list --upgradable 2>/dev/null | head -n 50 || true

  echo -e "\n== Optional: Lynis =="
  command -v lynis >/dev/null && sudo lynis audit system --quick || echo "Lynis not found."
} | tee "$REPORT"

echo "[*] Hardening report written to $REPORT"
