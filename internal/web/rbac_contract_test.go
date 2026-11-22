package web_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Florencea/erp-rbac/internal/audit"
	"github.com/Florencea/erp-rbac/internal/config"
	"github.com/Florencea/erp-rbac/internal/db"
	"github.com/Florencea/erp-rbac/internal/domain/user"
	"github.com/Florencea/erp-rbac/internal/rbac"
	"github.com/Florencea/erp-rbac/internal/web"
)

type testHarness struct {
	srv     *web.Server
	store   *db.Store
	handler http.Handler
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.AppDBPath = filepath.Join(dir, "app.sqlite")
	cfg.AuditDBPath = filepath.Join(dir, "audit.sqlite")
	cfg.InsecureCookie = true
	cfg.AdminInitPassword = "AdminPass123!"

	ctx := context.Background()
	store, err := db.Open(ctx, cfg.AppDBPath, cfg.AuditDBPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := db.Seed(ctx, store, db.SeedOptions{AdminPassword: cfg.AdminInitPassword}); err != nil {
		t.Fatalf("seed db: %v", err)
	}

	srv, err := web.NewServer(cfg, store)
	if err != nil {
		t.Fatalf("new web server: %v", err)
	}

	return &testHarness{
		srv:     srv,
		store:   store,
		handler: srv.Handler(),
	}
}

func loginClient(t *testing.T, ts *httptest.Server, account, password string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	form := url.Values{}
	form.Set("account", account)
	form.Set("password", password)
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after login for %s, got %d", account, resp.StatusCode)
	}
	return client
}

func TestCanaryRBACRouteAuditAndSecurityHeaders(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	ts := httptest.NewServer(h.handler)
	defer ts.Close()

	routes := h.srv.Router().Routes()
	if len(routes) == 0 {
		t.Fatal("expected registered routes")
	}

	noRedirectClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Every route must have an explicit access level; protected GET routes must redirect unauthenticated callers to /login.
	for _, rt := range routes {
		if rt.Level == 0 {
			t.Fatalf("route %q has undeclared access level", rt.Pattern)
		}
		if rt.Level == rbac.AccessPermission && rt.Permission == "" {
			t.Fatalf("route %q uses AccessPermission without permission code", rt.Pattern)
		}
		if strings.HasPrefix(rt.Pattern, "GET ") && rt.Level != rbac.AccessPublic {
			path := strings.TrimPrefix(rt.Pattern, "GET ")
			path = strings.ReplaceAll(path, "{$}", "")
			path = strings.ReplaceAll(path, "{id}", "1")
			if path == "" {
				path = "/"
			}
			resp, err := noRedirectClient.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("unauth GET %s: %v", path, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("expected 303 redirect to /login for unauthenticated GET %s, got %d", path, resp.StatusCode)
			}
			if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
				t.Fatalf("expected redirect to /login for %s, got %q", path, loc)
			}
			if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'none'") {
				t.Fatalf("expected CSP script-src 'none' on %s, got %q", path, csp)
			}
		}
	}

	// 2. Employee role without department/role/audit permissions receives 403 and writes audit.sqlite entry.
	ctx := context.Background()
	var empRoleID int64
	if err := h.store.AppRead.QueryRowContext(ctx, `SELECT id FROM roles WHERE code = 'employee'`).Scan(&empRoleID); err != nil {
		t.Fatalf("load employee role: %v", err)
	}
	var adminID int64
	_ = h.store.AppRead.QueryRowContext(ctx, `SELECT id FROM users WHERE account = 'admin'`).Scan(&adminID)
	adminPrincipal, _ := rbac.LoadPrincipal(ctx, h.store.AppRead, adminID)
	userSvc := user.NewService(h.store.AppWrite, h.store.AppRead, h.srv.Sessions())
	if _, err := userSvc.Create(ctx, adminPrincipal, user.Input{
		Account: "emp_canary", Password: "EmpPassword123!", Name: "Emp Canary", Status: "active",
		RoleIDs: []int64{empRoleID},
	}); err != nil {
		t.Fatalf("create emp_canary: %v", err)
	}

	empClient := loginClient(t, ts, "emp_canary", "EmpPassword123!")
	for _, forbiddenPath := range []string{"/departments", "/roles", "/audit-logs", "/users/new"} {
		resp, err := empClient.Get(ts.URL + forbiddenPath)
		if err != nil {
			t.Fatalf("emp GET %s: %v", forbiddenPath, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for employee on %s, got %d", forbiddenPath, resp.StatusCode)
		}
	}

	auditLogger := audit.NewLogger(h.store.Audit)
	auditRes, err := auditLogger.List(ctx, audit.Filter{Account: "emp_canary", Action: "rbac.forbidden", Outcome: audit.OutcomeDenied})
	if err != nil || auditRes.Total < 4 {
		t.Fatalf("expected >=4 rbac.forbidden audit records in audit.sqlite, got total=%d err=%v", auditRes.Total, err)
	}

	// 3. Cross-origin POST must be rejected by http.NewCrossOriginProtection.
	csrfReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/departments", strings.NewReader("name=EvilDept"))
	csrfReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	csrfReq.Header.Set("Sec-Fetch-Site", "cross-site")
	csrfReq.Header.Set("Origin", "https://evil.example")
	csrfResp, err := empClient.Do(csrfReq)
	if err != nil {
		t.Fatalf("csrf request failed: %v", err)
	}
	_ = csrfResp.Body.Close()
	if csrfResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-site POST, got %d", csrfResp.StatusCode)
	}
}
