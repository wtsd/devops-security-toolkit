# 02 — Network Mapping (nmap)

**Goal:** Find reachable services and their versions in your authorized scope.

```bash
export AUTH_OK=1
scripts/bash/net_scan.sh 10.0.0.0/24 -sV --top-ports 200
scripts/bash/vuln_scan.sh 10.0.0.5 --script-args="ssl-enum-ciphers.min-rsa=2048"
```

**Tip:** Start with small scopes, record outputs in `results/nmap/`, and review services against your approved exposure policy.
