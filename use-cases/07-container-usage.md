# 07 — Container Usage

**Goal:** Run consistently across environments via Docker.

```bash
docker build -t security-toolkit ./docker
docker run --rm -it -v "$PWD:/workspace" --net=host -e AUTH_OK=1 security-toolkit bash
```
