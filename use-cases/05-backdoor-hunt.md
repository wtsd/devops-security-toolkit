# 05 — Backdoor Detection (Indicators)

**Goal:** Hunt for common persistence and covert access indicators **without** executing payloads.

```bash
export AUTH_OK=1
scripts/bash/backdoor_hunt.sh
```

**Checks:** suspicious listening ports, SUID binaries, world-writable dirs, cron jobs, SSH key options, /tmp executables, suspicious unit names.
