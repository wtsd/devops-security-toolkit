# 01 — Asset & Process Inventory

**Goal:** Capture a point-in-time snapshot of processes and network connections for incident triage or baseline creation.

**Steps:**

```bash
python3 scripts/python/inventory.py --out results/reports/inventory.json
```

**Output:** JSON with processes, listening ports, and connections. Feed to your SIEM, or diff over time for drift detection.
