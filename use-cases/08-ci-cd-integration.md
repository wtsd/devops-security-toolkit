# 08 — CI/CD Integration

**Idea:** Add a pipeline job to scan repos and images before deploy.

- Run `secrets_scan.sh` on each PR
- Keep `results/` as artifacts
- Fail build if high-risk patterns are found
