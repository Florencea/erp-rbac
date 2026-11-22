---
trigger: glob
globs: ".github/workflows/**"
description: GitHub Actions workflow standards, actionlint checks, and exact SemVer pinning.
---

# CI and GitHub Actions Standards

## Local Validation

- Run `actionlint` locally after modifying any file under `.github/workflows/` and resolve all errors and warnings before staging.
- Do not invoke `actionlint` inside remote workflow YAML files.

## Workflow Baseline

- Pin every action to an exact stable SemVer tag (`@vX.Y.Z`) verified against upstream tags (`actions/checkout@v7.0.1`, `actions/setup-go@v7.1.0`, `golang/govulncheck-action@v1.1.0`).
- Declare top-level `permissions: contents: read` and `concurrency` with `cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}`.
- Set explicit `timeout-minutes: 15` on every job.
- Keep `gofmt`, `go vet ./...`, `go test -race -count=1 ./...`, `govulncheck ./...`, and `CGO_ENABLED=0 go build` in the gatekeeper job.
