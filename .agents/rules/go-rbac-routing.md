---
trigger: glob
globs: "internal/rbac/**, internal/domain/**, internal/web/**"
description: Fail-closed route registration, CSRF protection, Data Scope enforcement, and anti-escalation rules.
---

# Fail-Closed RBAC Routing and Domain Rules

## Route Registration

- Keep `http.ServeMux` private inside `rbac.Router`.
- Every HTTP endpoint must explicitly call `router.Public`, `router.Authenticated`, or `router.RequirePerm`.
- Protect all state-changing `POST` endpoints using `http.NewCrossOriginProtection()`.
- Keep `internal/web/rbac_contract_test.go` passing for every newly added route.

## Authentication and Session Invariants

- Verify `user.status == "active"` during both login and per-request principal resolution.
- Immediately revoke all rows in `sessions` for a user whenever their password is changed or their status becomes non-active.
- Validate redirect parameters (`next`, `Referer`) with `SafeRedirectPath` to block open redirects.

## Data Scope and Privilege Controls

- Apply `rbac.BuildUserScopeSQL` to scoped list queries (`ALL`, `DEPT_AND_CHILD`, `DEPT`, `SELF`, `CUSTOM`).
- Enforce `rbac.CanAccessUser` on single-record `GET`, `POST` update, and `POST` delete operations to prevent IDOR.
- Reject non-`super_admin` attempts to modify `is_system = 1` records, assign `super_admin` roles, or move users outside allowed departments.
- Reject cyclic parent assignments in `department.Service.Update`.
