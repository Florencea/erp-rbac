---
name: db-backup-restore
description: Perform online hot backups and offline file restores for dual SQLite databases (app.sqlite and audit.sqlite).
---

# Dual SQLite Backup and Restore

## Online Hot Backup

Run the `backup` subcommand while the server is running or stopped to produce consistent single-file snapshots via SQLite `VACUUM INTO`:

```bash
./erp-rbac backup --app-db data/app.sqlite --audit-db data/audit.sqlite --out backups
```

Verify both generated snapshots using `sqlite3`:

```bash
sqlite3 backups/app-*.sqlite "PRAGMA integrity_check;"
sqlite3 backups/audit-*.sqlite "PRAGMA integrity_check;"
```

## File Restore

1. Stop the running `erp-rbac` process so WAL files are checkpointed and locks released.
2. Remove stale `-wal` and `-shm` sidecar files alongside target `app.sqlite` and `audit.sqlite` if replacing files.
3. Copy the verified backup snapshots back to the target `APP_DB_PATH` and `AUDIT_DB_PATH` with `0640` permissions.
4. Start `./erp-rbac serve`.
