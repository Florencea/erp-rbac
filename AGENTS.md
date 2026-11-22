# Agent Development Guidelines

Architecture and engineering invariants for `erp-rbac`.

## Architecture Map

- `cmd/erp-rbac/main.go`: Single CLI entrypoint (`serve`, `seed`, `backup`, `version`) with graceful shutdown.
- `internal/config/`: Runtime configuration loading and boundary validation.
- `internal/db/`: Dual SQLite connection management (`app.sqlite` and `audit.sqlite`), embedded SQL migrations, WAL pooling, seeding, and online `VACUUM INTO` hot backups.
- `internal/audit/`: Append-only audit writer and read-only query layer against `audit.sqlite`.
- `internal/auth/`: Bcrypt password hashing and SQLite-backed hashed session tokens with one-time flash messages.
- `internal/rbac/`: Fail-closed route registry (`Public`, `Authenticated`, `RequirePerm`), `net/http.CrossOriginProtection` CSRF middleware, strict `script-src 'none'` CSP, and row-level Data Scope builder.
- `internal/domain/`: Business services for `department`, `role`, and `user`.
- `internal/i18n/`: Compile-time checked `zh-TW` and `en-US` message catalogs.
- `internal/web/`: Server-side HTML handlers (PRG pattern) and embedded template renderer.
- `web/`: Embedded static Bootstrap 5.3.9 CSS (`web/static/bootstrap.min.css`), favicon, and HTML5 templates (`web/templates/*.html`).
- `.agents/rules/`: Domain rules for Bootstrap CSS-only UI, fail-closed Go RBAC routing, dual SQLite persistence, and GitHub Actions CI.
- `.agents/skills/`: Operational runbooks for database backup/restore and adding RBAC modules.

## Core Invariants

- Single Static Binary (`CGO_ENABLED=0`): Compile with pure Go (`modernc.org/sqlite`, `golang.org/x/crypto`) and embedded assets via `web/embed.go`. Do not introduce Node.js, npm, CGo, Docker, or Cloudflare tooling.
- Strict Bootstrap 5 CSS-Only UI and Zero JS: Never add `<script>`, `<style>`, `style=`, `on*=` attributes, `javascript:` URIs, `data-bs-*` JS attributes, or custom CSS files. Only class names present in `web/static/bootstrap.min.css` are permitted, enforced by `internal/web/lint_test.go`.
- Standard HTML Forms and PRG: All state mutations must use standard HTML `<form method="POST">` submissions followed by `303 See Other` redirects.
- Fail-Closed RBAC Routing: Never expose raw `http.ServeMux`. Every route must be registered via `rbac.Router` using `Public`, `Authenticated`, or `RequirePerm`.
- Data Scope and Anti-IDOR: Enforce `ALL`, `DEPT_AND_CHILD`, `DEPT`, `SELF`, and `CUSTOM` boundaries on list queries as well as single-record read, update, and delete paths.
- Dual SQLite Separation: Keep application state (`app.sqlite`) and immutable audit logs (`audit.sqlite`) in separate database files. Never expose update or delete operations on `audit_logs`.
- Session Security: Store only SHA-256 hashes of random session tokens in `sessions`. Check `status = 'active'` on every request and immediately revoke sessions on password change or user deactivation.
- Third-Party Licensing: Preserve `NOTICE` and `THIRD_PARTY_LICENSES/`. Do not add dependencies with copyleft licenses.

## Verification Commands

Run the full local gate after changes:

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/erp-rbac ./cmd/erp-rbac
actionlint
```

## Git Workflow Restrictions

- Never execute `git commit` directly because local commits rely on interactive SSH signing.
- Stage changes with `git add` and output the suggested `git commit -m "..."` command in English for the user to execute.

## Language Standards

- Write all dialogue, walkthroughs, and plans in Traditional Chinese (Taiwan usage).
- Write all source code, comments, templates, tests, standalone documentation, and commit messages in concise English (except localized UI strings in `zh-TW` catalogs and seed data).
