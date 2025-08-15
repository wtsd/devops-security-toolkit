#!/usr/bin/env python3
import argparse, os, re, json, hashlib, sys
from datetime import datetime

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|sk|access).{0,3}([0-9a-zA-Z/+]{40})",
    "GitHub Token": r"ghp_[0-9A-Za-z]{36}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Live Key": r"sk_live_[0-9A-Za-z]{24}",
    "Heroku API Key": r"[hH]eroku(.{0,20})?[0-9a-fA-F]{32}",
    "Private Key Block": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
}

def scan_path(path):
    findings = []
    for root, dirs, files in os.walk(path):
        # Skip common noise
        dirs[:] = [d for d in dirs if d not in (".git", ".svn", "node_modules", ".venv", "venv", "__pycache__")]
        for name in files:
            fpath = os.path.join(root, name)
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    text = fh.read()
                for label, regex in PATTERNS.items():
                    for m in re.finditer(regex, text):
                        snippet = text[max(0, m.start()-20):m.end()+20]
                        sha = hashlib.sha256(snippet.encode("utf-8")).hexdigest()[:10]
                        findings.append({
                            "file": fpath,
                            "label": label,
                            "match_hash": sha,
                            "offset": m.start(),
                        })
            except Exception as e:
                # skip binaries or unreadable
                continue
    return findings

def main():
    ap = argparse.ArgumentParser(description="Regex-based secret scanner (fallback).")
    ap.add_argument("--path", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    report = {
        "generated_at": datetime.utcnow().isoformat()+"Z",
        "path": os.path.abspath(args.path),
        "findings": scan_path(args.path)
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Wrote {args.out}")

if __name__ == "__main__":
    main()
