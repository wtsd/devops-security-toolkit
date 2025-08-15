#!/usr/bin/env python3
import argparse, re, json, os, sys
from collections import Counter, defaultdict
from datetime import datetime

SSH_FAIL_RE = re.compile(r'Failed password for (invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})')
SSH_ACCEPT_RE = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})')
SUDO_RE = re.compile(r'sudo: +(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.*)')

def parse_auth_log(path):
    fails = Counter()
    accepts = Counter()
    users = Counter()
    sudo_cmds = Counter()
    lines = 0
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            lines += 1
            m = SSH_FAIL_RE.search(line)
            if m:
                user = m.group(2)
                ip = m.group(3)
                fails[(user, ip)] += 1
                continue
            m = SSH_ACCEPT_RE.search(line)
            if m:
                user = m.group(1)
                ip = m.group(2)
                accepts[(user, ip)] += 1
                users[user] += 1
                continue
            m = SUDO_RE.search(line)
            if m:
                cmd = m.group(5).strip()
                sudo_cmds[cmd] += 1
    return {
        "lines": lines,
        "failed_logins": [{"user": u, "ip": ip, "count": c} for (u, ip), c in fails.most_common(25)],
        "accepted_logins": [{"user": u, "ip": ip, "count": c} for (u, ip), c in accepts.most_common(25)],
        "sudo_commands": [{"command": cmd, "count": c} for cmd, c in sudo_cmds.most_common(25)],
    }

def main():
    ap = argparse.ArgumentParser(description="Analyze Linux auth logs for anomalies.")
    ap.add_argument("--auth-log", default="/var/log/auth.log")
    ap.add_argument("--out", default="results/reports/auth_report.json")
    args = ap.parse_args()

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "auth_log": os.path.abspath(args.auth_log),
        "summary": parse_auth_log(args.auth_log)
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Wrote {args.out}")

if __name__ == "__main__":
    main()
