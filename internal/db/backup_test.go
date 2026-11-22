package db_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Florencea/erp-rbac/internal/db"
)

func TestDualDBSeedAndHotBackup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appPath := filepath.Join(dir, "app.sqlite")
	auditPath := filepath.Join(dir, "audit.sqlite")

	ctx := context.Background()
	store, err := db.Open(ctx, appPath, auditPath)
	if err != nil {
		t.Fatalf("open dual store: %v", err)
	}
	defer func() { _ = store.Close() }()

	// First seed without ADMIN_INIT_PASSWORD should generate a random one-time password.
	res1, err := db.EnsureSeeded(ctx, store, db.SeedOptions{})
	if err != nil {
		t.Fatalf("initial seed: %v", err)
	}
	if !res1.AdminCreated || res1.GeneratedPassword == "" {
		t.Fatalf("expected generated password on first seed, got %+v", res1)
	}

	// Second EnsureSeeded should be a no-op and not regenerate password.
	res2, err := db.EnsureSeeded(ctx, store, db.SeedOptions{})
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if res2.AdminCreated || res2.GeneratedPassword != "" {
		t.Fatalf("expected idempotent no-op on second seed, got %+v", res2)
	}

	// Verify WAL mode is active.
	var mode string
	if err := store.AppWrite.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("expected wal mode, got %q", mode)
	}

	// Write an audit record to audit.sqlite to ensure backup captures live data.
	if _, err := store.Audit.ExecContext(
		ctx,
		`INSERT INTO audit_logs (occurred_at, actor_account, action, resource_type, outcome) VALUES (1, 'admin', 'test.event', 'system', 'success')`,
	); err != nil {
		t.Fatalf("insert audit test record: %v", err)
	}

	backupDir := filepath.Join(dir, "backups")
	bk, err := store.Backup(ctx, backupDir)
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	for _, path := range []string{bk.AppBackupPath, bk.AuditBackupPath} {
		conn, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
		if err != nil {
			t.Fatalf("open backup %s: %v", path, err)
		}
		var check string
		err = conn.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&check)
		_ = conn.Close()
		if err != nil || check != "ok" {
			t.Fatalf("integrity_check failed for %s: err=%v res=%q", path, err, check)
		}
	}

	auditConn, err := sql.Open("sqlite", "file:"+filepath.ToSlash(bk.AuditBackupPath))
	if err != nil {
		t.Fatalf("open audit backup: %v", err)
	}
	defer func() { _ = auditConn.Close() }()
	var count int
	if err := auditConn.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE action = 'test.event'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected 1 audit row in backup, got count=%d err=%v", count, err)
	}
}
