# 04 — Linux Auth Log Analysis

**Goal:** Identify brute-force attempts (by others), compromised accounts, and risky sudo usage.

```bash
scripts/bash/log_audit.sh /var/log/auth.log
```

**Output:** `results/reports/auth_report*.json` with top failed/accepted logins and sudo command frequency.
