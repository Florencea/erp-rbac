package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAddr          = "127.0.0.1:8080"
	DefaultAppDBPath     = "data/app.sqlite"
	DefaultAuditDBPath   = "data/audit.sqlite"
	DefaultSessionTTL    = 7 * 24 * time.Hour
	DefaultDefaultLocale = "zh-TW"
)

// Config defines runtime configuration for the erp-rbac server and CLI.
type Config struct {
	Addr              string
	AppDBPath         string
	AuditDBPath       string
	SessionTTL        time.Duration
	InsecureCookie    bool
	AdminInitPassword string
	DefaultLocale     string
}

// Default returns a Config populated with baseline production-safe defaults.
func Default() Config {
	return Config{
		Addr:          DefaultAddr,
		AppDBPath:     DefaultAppDBPath,
		AuditDBPath:   DefaultAuditDBPath,
		SessionTTL:    DefaultSessionTTL,
		DefaultLocale: DefaultDefaultLocale,
	}
}

// LoadFromEnv constructs a Config from environment variables layered over defaults.
func LoadFromEnv() (Config, error) {
	cfg := Default()

	if v := strings.TrimSpace(os.Getenv("ADDR")); v != "" {
		cfg.Addr = v
	}
	if v := strings.TrimSpace(os.Getenv("APP_DB_PATH")); v != "" {
		cfg.AppDBPath = v
	}
	if v := strings.TrimSpace(os.Getenv("AUDIT_DB_PATH")); v != "" {
		cfg.AuditDBPath = v
	}
	if v := strings.TrimSpace(os.Getenv("SESSION_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid SESSION_TTL %q: %w", v, err)
		}
		cfg.SessionTTL = d
	}
	if v := strings.TrimSpace(os.Getenv("INSECURE_COOKIE")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid INSECURE_COOKIE %q: %w", v, err)
		}
		cfg.InsecureCookie = b
	}
	if v := os.Getenv("ADMIN_INIT_PASSWORD"); v != "" {
		cfg.AdminInitPassword = v
	}
	if v := strings.TrimSpace(os.Getenv("DEFAULT_LOCALE")); v != "" {
		cfg.DefaultLocale = v
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces invariants on address, database paths, TTL, and locale.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Addr) == "" {
		return errors.New("addr must not be empty")
	}
	host, portStr, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return fmt.Errorf("invalid addr %q: %w", c.Addr, err)
	}
	_ = host
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port in addr %q", c.Addr)
	}

	appClean := filepath.Clean(strings.TrimSpace(c.AppDBPath))
	auditClean := filepath.Clean(strings.TrimSpace(c.AuditDBPath))
	if appClean == "" || appClean == "." {
		return errors.New("app database path must not be empty")
	}
	if auditClean == "" || auditClean == "." {
		return errors.New("audit database path must not be empty")
	}
	appAbs, errApp := filepath.Abs(appClean)
	auditAbs, errAudit := filepath.Abs(auditClean)
	if errApp == nil && errAudit == nil && appAbs == auditAbs {
		return errors.New("app and audit databases must be separate files")
	}

	if c.SessionTTL <= 0 {
		return errors.New("session TTL must be positive")
	}
	if c.DefaultLocale != "zh-TW" && c.DefaultLocale != "en-US" {
		return fmt.Errorf("unsupported default locale %q", c.DefaultLocale)
	}
	return nil
}
