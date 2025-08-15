# Security Toolkit (Defensive) 🛡️

**Version:** 2025-08-15T21:16:05Z

A defensive, automation-friendly toolkit to help you **scan your own infrastructure** for common risks:
- Asset & network mapping (nmap)
- Vulnerability-oriented nmap scripts (safe profiles)
- Secret/credential leak detection (gitleaks/trufflehog fallback to regex)
- Linux log analysis & auth anomaly detection
- Backdoor **detection** (not creation): suspicious ports, SUID, cron, SSH keys, persistence
- Basic hardening checks and baseline reports
- Webroot source inspection for risky PHP patterns
- Containerized runtime for consistent results

> **Strict use policy**: This toolkit is for **authorized security analysis only** on systems you **own or are explicitly permitted to assess**. It does **not** include backdoors or password brute‑force tools. Do not use it against third parties. You are responsible for compliance with your local laws, contracts, and policies.

## Quick start (Docker)

```bash
# 1) Build the container
docker build -t security-toolkit ./docker

# 2) Run the container, mounting a target directory (code/logs/etc.) at /workspace
docker run --rm -it -v "$PWD:/workspace" --net=host \
  -e AUTH_OK=1 \
  security-toolkit bash

# 3) Inside the container, try a secrets scan and a log analysis:
scripts/bash/secrets_scan.sh /workspace
python3 scripts/python/log_analyzer.py --auth-log /var/log/auth.log --out results/reports/auth_report.json
```

> **Note**: `--net=host` is convenient for local nmap scans; remove if not needed. `AUTH_OK=1` is required for scans to run.

## Local install (Linux)

```bash
scripts/bash/install_tools.sh
export AUTH_OK=1
scripts/bash/net_scan.sh 127.0.0.1
```

## Structure

```
security-toolkit/
├─ scripts/
│  ├─ bash/
│  ├─ python/
│  └─ php/
├─ config/
├─ results/
│  ├─ nmap/
│  └─ reports/
├─ use-cases/
└─ docker/
```

## Tools used

- **nmap** for network/service discovery with safe profiles
- **gitleaks**/**trufflehog** if available (fallback to internal regex)
- **jq**, **php-cli**, **python3**, **pip** packages in Docker
- Optional: **lynis** for deeper hardening checks (if present)

## Legal & Ethical

This repo intentionally excludes backdoor creation and password brute‑force code. It focuses on **detection**, **policy** and **defense**. For password security, prefer **offline** audits of hashes you control (e.g., via enterprise-approved workflows) and policy checks rather than live brute forcing.

See **use-cases/09-legal-ethics.md** for guidance.
