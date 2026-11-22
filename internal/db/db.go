package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/app/*.sql migrations/audit/*.sql
var migrationFS embed.FS

// Store holds separated SQLite connection pools for application state and immutable audit logs.
type Store struct {
	AppWrite    *sql.DB
	AppRead     *sql.DB
	Audit       *sql.DB
	AppDBPath   string
	AuditDBPath string
}

// Open initializes both SQLite databases, applies pending migrations, and configures WAL pools.
func Open(ctx context.Context, appDBPath, auditDBPath string) (*Store, error) {
	appAbs, err := filepath.Abs(filepath.Clean(appDBPath))
	if err != nil {
		return nil, fmt.Errorf("resolve app db path: %w", err)
	}
	auditAbs, err := filepath.Abs(filepath.Clean(auditDBPath))
	if err != nil {
		return nil, fmt.Errorf("resolve audit db path: %w", err)
	}
	if appAbs == auditAbs {
		return nil, errors.New("app database and audit database paths must differ")
	}

	if err := os.MkdirAll(filepath.Dir(appAbs), 0o750); err != nil {
		return nil, fmt.Errorf("create app db directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(auditAbs), 0o750); err != nil {
		return nil, fmt.Errorf("create audit db directory: %w", err)
	}

	appWrite, err := openWritePool(ctx, appAbs)
	if err != nil {
		return nil, fmt.Errorf("open app write pool: %w", err)
	}

	if err := runMigrations(ctx, appWrite, "migrations/app"); err != nil {
		_ = appWrite.Close()
		return nil, fmt.Errorf("migrate app database: %w", err)
	}

	appRead, err := openReadPool(ctx, appAbs)
	if err != nil {
		_ = appWrite.Close()
		return nil, fmt.Errorf("open app read pool: %w", err)
	}

	auditDB, err := openWritePool(ctx, auditAbs)
	if err != nil {
		_ = appRead.Close()
		_ = appWrite.Close()
		return nil, fmt.Errorf("open audit db pool: %w", err)
	}

	if err := runMigrations(ctx, auditDB, "migrations/audit"); err != nil {
		_ = auditDB.Close()
		_ = appRead.Close()
		_ = appWrite.Close()
		return nil, fmt.Errorf("migrate audit database: %w", err)
	}

	return &Store{
		AppWrite:    appWrite,
		AppRead:     appRead,
		Audit:       auditDB,
		AppDBPath:   appAbs,
		AuditDBPath: auditAbs,
	}, nil
}

func openWritePool(ctx context.Context, absPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"file:%s?_busy_timeout=5000&_foreign_keys=1&_journal_mode=WAL&_synchronous=NORMAL&_txlock=immediate",
		filepath.ToSlash(absPath),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func openReadPool(ctx context.Context, absPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"file:%s?_busy_timeout=5000&_foreign_keys=1&_query_only=1",
		filepath.ToSlash(absPath),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	maxConns := max(4, runtime.NumCPU())
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(max(2, runtime.NumCPU()))
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func runMigrations(ctx context.Context, db *sql.DB, dir string) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrationFS, dir)
	if err != nil {
		return err
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			continue
		}

		raw, err := fs.ReadFile(migrationFS, dir+"/"+name)
		if err != nil {
			return err
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(raw)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			name, time.Now().Unix(),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Ping verifies connectivity to both application and audit SQLite databases.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.AppRead.PingContext(ctx); err != nil {
		return fmt.Errorf("app db ping: %w", err)
	}
	if err := s.Audit.PingContext(ctx); err != nil {
		return fmt.Errorf("audit db ping: %w", err)
	}
	return nil
}

// Close checkpoints WAL files and closes all SQLite connection pools cleanly.
func (s *Store) Close() error {
	var errs []error
	if s.AppRead != nil {
		if err := s.AppRead.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.AppWrite != nil {
		_, _ = s.AppWrite.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		if err := s.AppWrite.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.Audit != nil {
		_, _ = s.Audit.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		if err := s.Audit.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
