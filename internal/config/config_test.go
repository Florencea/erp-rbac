package config

import (
	"path/filepath"
	"testing"
)

func TestValidateRejectsSameDBPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := Default()
	cfg.AppDBPath = filepath.Join(dir, "shared.sqlite")
	cfg.AuditDBPath = filepath.Join(dir, "shared.sqlite")
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when AppDBPath and AuditDBPath point to the same file")
	}
}

func TestValidateDefaultsPass(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default config to be valid, got: %v", err)
	}
}
