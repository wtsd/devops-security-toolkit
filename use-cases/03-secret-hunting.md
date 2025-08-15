# 03 — Secret Hunting

**Goal:** Detect leaked tokens/keys in repos, workspaces, images, or logs.

```bash
scripts/bash/secrets_scan.sh /workspace
```

**Tools:** Uses gitleaks/trufflehog if found, with fallback regex. Extend patterns in `config/secret_patterns.yaml`.
