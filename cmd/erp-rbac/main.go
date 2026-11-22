package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Florencea/erp-rbac/internal/config"
	"github.com/Florencea/erp-rbac/internal/db"
	"github.com/Florencea/erp-rbac/internal/web"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	subcmd := "serve"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		subcmd = args[0]
		args = args[1:]
	}

	switch subcmd {
	case "serve":
		return runServe(args)
	case "seed":
		return runSeed(args)
	case "backup":
		return runBackup(args)
	case "version":
		fmt.Printf("erp-rbac %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q (supported: serve, seed, backup, version)\n", subcmd)
		return 2
	}
}

func runServe(args []string) int {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("configuration error", "error", err)
		return 1
	}

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.StringVar(&cfg.Addr, "addr", cfg.Addr, "HTTP listen address")
	fs.StringVar(&cfg.AppDBPath, "app-db", cfg.AppDBPath, "Application SQLite database path")
	fs.StringVar(&cfg.AuditDBPath, "audit-db", cfg.AuditDBPath, "Audit SQLite database path")
	fs.BoolVar(&cfg.InsecureCookie, "insecure-cookie", cfg.InsecureCookie, "Allow non-HTTPS cookies for local HTTP development")
	fs.StringVar(&cfg.DefaultLocale, "locale", cfg.DefaultLocale, "Default locale (zh-TW or en-US)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("configuration validation failed", "error", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := db.Open(ctx, cfg.AppDBPath, cfg.AuditDBPath)
	if err != nil {
		slog.Error("failed to open databases", "error", err)
		return 1
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			slog.Error("failed to close databases cleanly", "error", closeErr)
		}
	}()

	seedRes, err := db.EnsureSeeded(ctx, store, db.SeedOptions{
		AdminPassword: cfg.AdminInitPassword,
	})
	if err != nil {
		slog.Error("failed to ensure initial RBAC seed", "error", err)
		return 1
	}
	if seedRes.AdminCreated {
		if seedRes.GeneratedPassword != "" {
			slog.Warn("initialized default admin account with generated one-time password; change immediately after login",
				"account", db.DefaultAdminAccount,
				"generated_password", seedRes.GeneratedPassword,
			)
		} else {
			slog.Info("initialized default admin account from ADMIN_INIT_PASSWORD",
				"account", db.DefaultAdminAccount,
			)
		}
	}

	srv, err := web.NewServer(cfg, store)
	if err != nil {
		slog.Error("failed to initialize web server", "error", err)
		return 1
	}

	gcCtx, cancelGC := context.WithCancel(ctx)
	defer cancelGC()
	go srv.Sessions().StartGC(gcCtx, 15*time.Minute)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("erp-rbac server listening",
			"addr", cfg.Addr,
			"app_db", store.AppDBPath,
			"audit_db", store.AuditDBPath,
			"insecure_cookie", cfg.InsecureCookie,
		)
		if listenErr := httpSrv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			errCh <- listenErr
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received, draining connections")
		cancelGC()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		if shutErr := httpSrv.Shutdown(shutdownCtx); shutErr != nil {
			slog.Error("http shutdown error", "error", shutErr)
			return 1
		}
		return 0
	case listenErr := <-errCh:
		if listenErr != nil {
			slog.Error("server listen error", "error", listenErr)
			return 1
		}
		return 0
	}
}

func runSeed(args []string) int {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("configuration error", "error", err)
		return 1
	}

	var resetAdmin bool
	adminPass := cfg.AdminInitPassword

	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	fs.StringVar(&cfg.AppDBPath, "app-db", cfg.AppDBPath, "Application SQLite database path")
	fs.StringVar(&cfg.AuditDBPath, "audit-db", cfg.AuditDBPath, "Audit SQLite database path")
	fs.StringVar(&adminPass, "admin-password", adminPass, "Explicit initial or reset password for admin")
	fs.BoolVar(&resetAdmin, "reset-admin", false, "Reset admin password and revoke active admin sessions")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("configuration validation failed", "error", err)
		return 1
	}

	ctx := context.Background()
	store, err := db.Open(ctx, cfg.AppDBPath, cfg.AuditDBPath)
	if err != nil {
		slog.Error("failed to open databases", "error", err)
		return 1
	}
	defer func() { _ = store.Close() }()

	res, err := db.Seed(ctx, store, db.SeedOptions{
		AdminPassword:      adminPass,
		ResetAdminPassword: resetAdmin,
	})
	if err != nil {
		slog.Error("seed failed", "error", err)
		return 1
	}

	if res.GeneratedPassword != "" {
		slog.Warn("admin password generated during seed",
			"account", db.DefaultAdminAccount,
			"generated_password", res.GeneratedPassword,
		)
	} else {
		slog.Info("database seed completed", "admin_created", res.AdminCreated, "admin_reset", resetAdmin)
	}
	return 0
}

func runBackup(args []string) int {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("configuration error", "error", err)
		return 1
	}

	outDir := "backups"
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.StringVar(&cfg.AppDBPath, "app-db", cfg.AppDBPath, "Application SQLite database path")
	fs.StringVar(&cfg.AuditDBPath, "audit-db", cfg.AuditDBPath, "Audit SQLite database path")
	fs.StringVar(&outDir, "out", outDir, "Backup destination directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("configuration validation failed", "error", err)
		return 1
	}

	ctx := context.Background()
	store, err := db.Open(ctx, cfg.AppDBPath, cfg.AuditDBPath)
	if err != nil {
		slog.Error("failed to open databases", "error", err)
		return 1
	}
	defer func() { _ = store.Close() }()

	res, err := store.Backup(ctx, outDir)
	if err != nil {
		slog.Error("backup failed", "error", err)
		return 1
	}
	slog.Info("online SQLite backup completed",
		"app_backup", res.AppBackupPath,
		"audit_backup", res.AuditBackupPath,
	)
	return 0
}
