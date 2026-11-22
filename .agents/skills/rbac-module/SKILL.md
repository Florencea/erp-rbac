---
name: rbac-module
description: Add a new RBAC-protected ERP module using Go domain services, Bootstrap 5 HTML5 templates, PRG handlers, and contract tests.
---

# Adding an RBAC Module

1. Add schema tables in a new numbered SQL migration under `internal/db/migrations/app/000N_<name>.sql` and add permission codes in `internal/db/seed.go`.
2. Add localized UI strings to both `zhTW` and `enUS` inside `internal/i18n/i18n.go`.
3. Create domain logic under `internal/domain/<module>/service.go` using explicit transactions and `rbac.BuildUserScopeSQL` if row-level Data Scope applies.
4. Create HTML templates under `web/templates/` using strictly Bootstrap 5.3.9 classes from `web/static/bootstrap.min.css`, zero `<script>`, zero `style=`, and valid `<label for>` bindings; register template names in `internal/web/templates.go`.
5. Implement GET/POST PRG handlers in `internal/web/handlers_<module>.go`, record audit events via `s.recordAudit`, and mount routes on `s.router.RequirePerm(...)` inside `internal/web/server.go`.
6. Run `go vet ./...` and `go test -race -count=1 ./...` to validate RBAC Canary contracts and Bootstrap 5 / zero-JS / accessibility compliance.
