---
trigger: glob
globs: "internal/db/**, internal/audit/**, internal/auth/**"
description: Dual SQLite separation, WAL pooling, pure SQL migrations, hashed sessions, and immutable audit logs.
---

# Dual SQLite Persistence and Audit Rules

## Database Separation

- Keep `app.sqlite` (users, departments, roles, permissions, sessions) strictly separate from `audit.sqlite` (audit logs).
- Validate on startup that `AppDBPath` and `AuditDBPath` resolve to distinct file paths.
- Never allow `UPDATE` or `DELETE` operations on `audit_logs`.

## Driver and Connection Pooling

- Use pure Go `modernc.org/sqlite` (`CGO_ENABLED=0`) with `_foreign_keys=1`, `_journal_mode=WAL`, `_synchronous=NORMAL`, and `_busy_timeout=5000`.
- Restrict write pools (`AppWrite` and `Audit`) to `SetMaxOpenConns(1)` and `_txlock=immediate`.
- Restrict `AppRead` to `_query_only=1` with concurrent connection capacity.
- Checkpoint WAL files (`PRAGMA wal_checkpoint(TRUNCATE)`) on shutdown.

## Schema, Seed, and Backups

- Place forward-only SQL migrations in `internal/db/migrations/app/` and `internal/db/migrations/audit/`.
- Wrap multi-step domain mutations in single SQLite transactions.
- Never store plaintext session tokens in SQLite; store only SHA-256 digests (`auth.HashToken`).
- Perform online hot backups exclusively via `VACUUM INTO ?` (`Store.Backup`).
