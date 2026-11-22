# erp-rbac

Self-contained internal ERP Role-Based Access Control (RBAC) server compiled to a single static Go binary (`CGO_ENABLED=0`), serving pure HTML5 forms styled exclusively with embedded Bootstrap 5.3.9 CSS (zero JavaScript, zero custom CSS) and persisted across two isolated SQLite files (`app.sqlite` and `audit.sqlite`).

## Architecture Overview

- Single Static Executable: Embeds HTML templates, Bootstrap 5.3.9 CSS, favicon, and SQL migrations via `embed.FS`. Deployment requires only the binary and the SQLite database directory.
- Pure Bootstrap 5 CSS and Zero JavaScript: Uses standard HTML5 `<form method="POST">` workflows with Post-Redirect-Get (`303 See Other`). Enforces `script-src 'none'` via HTTP `Content-Security-Policy` and verifies every rendered CSS class against `web/static/bootstrap.min.css` in automated tests.
- Dual SQLite Separation: Stores domain state and sessions in `app.sqlite` and immutable security audit records in `audit.sqlite`, both running in WAL mode with foreign keys enabled and separate read/write connection pools.
- Database-Backed Sessions: Stores only SHA-256 hashes of 256-bit random session tokens in SQLite (`sessions`) and invalidates active sessions immediately on logout, password reset, or account deactivation.
- Fail-Closed RBAC and Data Scopes: Enforces explicit route declarations (`Public`, `Authenticated`, `RequirePerm`), `net/http.CrossOriginProtection` CSRF checks, and row-level Data Scopes (`ALL`, `DEPT_AND_CHILD`, `DEPT`, `SELF`, `CUSTOM`).

## Prerequisites

- Go 1.25 or newer (`go.mod` targets `go 1.27.4`) for building from source.
- No Node.js, C compiler (`CGO_ENABLED=0`), Docker, or external database server required at build or runtime.

## Build and Run

Build the static single binary:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/erp-rbac ./cmd/erp-rbac
```

Run in local HTTP development (sets non-Secure cookies via `--insecure-cookie`):

```bash
./bin/erp-rbac serve --addr 127.0.0.1:8080 --app-db data/app.sqlite --audit-db data/audit.sqlite --insecure-cookie
```

Run behind a TLS-terminating reverse proxy in production (`Secure` cookies enabled by default):

```bash
ADMIN_INIT_PASSWORD="change-this-strong-password" ./bin/erp-rbac serve --addr 127.0.0.1:8080 --app-db /var/lib/erp-rbac/app.sqlite --audit-db /var/lib/erp-rbac/audit.sqlite
```

## Initial Administrator Password Policy

- On first startup or `seed`, if the `admin` account does not exist yet:
  - When `ADMIN_INIT_PASSWORD` (or `--admin-password` on `seed`) is set, the server hashes and stores that password (minimum 8 characters).
  - When `ADMIN_INIT_PASSWORD` is unset, the server generates a cryptographically random password via `crypto/rand`, stores its bcrypt hash, and logs `generated_password` once to standard error.
- Record the generated password from startup logs, sign in as `admin`, and update the password immediately in User Management.
- To reset the `admin` password and revoke active `admin` sessions manually:

```bash
./bin/erp-rbac seed --app-db data/app.sqlite --audit-db data/audit.sqlite --reset-admin --admin-password "new-strong-password"
```

## Configuration Reference

Environment variables and matching CLI flags for `serve`:

- `ADDR` / `--addr`: HTTP bind address (default `127.0.0.1:8080`).
- `APP_DB_PATH` / `--app-db`: Path to application SQLite file (default `data/app.sqlite`).
- `AUDIT_DB_PATH` / `--audit-db`: Path to audit log SQLite file (default `data/audit.sqlite`). Must differ from `APP_DB_PATH`.
- `SESSION_TTL`: Go duration string for session lifetime (default `168h`, 7 days).
- `INSECURE_COOKIE` / `--insecure-cookie`: Allow non-HTTPS session and locale cookies (default `false`). Enable only for local HTTP development.
- `ADMIN_INIT_PASSWORD`: Optional initial password used when creating `admin` on first bootstrap.
- `DEFAULT_LOCALE` / `--locale`: Default UI language (`zh-TW` or `en-US`, default `zh-TW`).

## Backup and Restore

Create atomic online hot backups of both `app.sqlite` and `audit.sqlite` while the server is running via SQLite `VACUUM INTO`:

```bash
./bin/erp-rbac backup --app-db data/app.sqlite --audit-db data/audit.sqlite --out backups
```

Verify snapshot integrity:

```bash
sqlite3 backups/app-*.sqlite "PRAGMA integrity_check;"
sqlite3 backups/audit-*.sqlite "PRAGMA integrity_check;"
```

Restore procedure:

1. Stop the running `erp-rbac` server.
2. Remove stale `-wal` and `-shm` files adjacent to target `app.sqlite` and `audit.sqlite`.
3. Copy the verified backup files into place (`chmod 0640`).
4. Start `./erp-rbac serve`.

## Verification and Quality Gate

Run formatting, static analysis, race-enabled unit/contract/DOM-lint tests, vulnerability scanning, and static build:

```bash
test -z "$(gofmt -l .)"
go vet ./...
go test -race -count=1 ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/erp-rbac ./cmd/erp-rbac
actionlint
```

## Licensing

- Project license: MIT (`LICENSE`).
- Third-party notices and full license texts are included under `NOTICE` and `THIRD_PARTY_LICENSES/` (Bootstrap 5.3.9 MIT, `modernc.org/sqlite` BSD-3-Clause and SQLite Public Domain, `golang.org/x/crypto` BSD-3-Clause).
