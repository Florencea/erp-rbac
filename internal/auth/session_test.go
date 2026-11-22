package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Florencea/erp-rbac/internal/auth"
	"github.com/Florencea/erp-rbac/internal/db"
)

func TestSessionLifecycleAndHashedStorage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(dir, "app.sqlite"), filepath.Join(dir, "audit.sqlite"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = store.Close() }()

	if _, err := db.Seed(ctx, store, db.SeedOptions{AdminPassword: "AdminPass123!"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var adminID int64
	if err := store.AppRead.QueryRowContext(ctx, `SELECT id FROM users WHERE account = 'admin'`).Scan(&adminID); err != nil {
		t.Fatalf("query admin id: %v", err)
	}

	mgr := auth.NewManager(store.AppWrite, store.AppRead, time.Hour, true)
	rec := httptest.NewRecorder()
	tokenHash, err := mgr.Create(ctx, rec, adminID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie to be set")
	}
	rawCookie := cookies[0]
	if rawCookie.Value == tokenHash {
		t.Fatal("database token_hash must not equal plaintext cookie token")
	}
	if !rawCookie.HttpOnly || rawCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected cookie attributes: %+v", rawCookie)
	}

	// Verify DB only stores hash.
	var rawMatch int
	if err := store.AppRead.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, rawCookie.Value).Scan(&rawMatch); err != nil {
		t.Fatalf("query raw match: %v", err)
	}
	if rawMatch != 0 {
		t.Fatal("plaintext token must never be stored in sessions table")
	}

	// Load via cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(rawCookie)
	sess, err := mgr.Load(ctx, req)
	if err != nil || sess == nil || sess.UserID != adminID {
		t.Fatalf("expected loaded session for admin, got sess=%+v err=%v", sess, err)
	}

	// Flash roundtrip
	if err := mgr.SetFlash(ctx, sess.TokenHash, "success", "saved ok"); err != nil {
		t.Fatalf("set flash: %v", err)
	}
	kind, msg, err := mgr.PopFlash(ctx, sess.TokenHash)
	if err != nil || kind != "success" || msg != "saved ok" {
		t.Fatalf("unexpected flash pop: kind=%q msg=%q err=%v", kind, msg, err)
	}
	kind2, msg2, _ := mgr.PopFlash(ctx, sess.TokenHash)
	if kind2 != "" || msg2 != "" {
		t.Fatalf("expected flash cleared after pop, got kind=%q msg=%q", kind2, msg2)
	}

	// RevokeUserSessions invalidates session immediately
	if err := mgr.RevokeUserSessions(ctx, adminID); err != nil {
		t.Fatalf("revoke user sessions: %v", err)
	}
	sessAfter, err := mgr.Load(ctx, req)
	if err != nil || sessAfter != nil {
		t.Fatalf("expected nil session after revoke, got %+v err=%v", sessAfter, err)
	}
}

func TestPasswordHashing(t *testing.T) {
	t.Parallel()
	hash, err := auth.HashPassword("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !auth.VerifyPassword(hash, "StrongPass123!") {
		t.Fatal("expected password verification to succeed")
	}
	if auth.VerifyPassword(hash, "WrongPass") {
		t.Fatal("expected password verification to fail for wrong password")
	}
}
