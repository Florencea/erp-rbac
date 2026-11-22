package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Florencea/erp-rbac/internal/audit"
)

func TestEndToEndFormCRUDLocaleAndAuditFlow(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	ts := httptest.NewServer(h.handler)
	defer ts.Close()

	client := loginClient(t, ts, "admin", "AdminPass123!")

	// 1. Switch locale to en-US and verify rendered home page switches language.
	locForm := url.Values{}
	locForm.Set("locale", "en-US")
	locResp, err := client.PostForm(ts.URL+"/locale", locForm)
	if err != nil {
		t.Fatalf("POST /locale: %v", err)
	}
	_ = locResp.Body.Close()

	homeResp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	homeHTML := readBody(t, homeResp)
	if !strings.Contains(homeHTML, `<html lang="en-US">`) || !strings.Contains(homeHTML, "ERP RBAC Administration") {
		t.Fatalf("expected en-US home page, got snippet: %s", homeHTML[:min(300, len(homeHTML))])
	}

	// Switch back to zh-TW
	locForm.Set("locale", "zh-TW")
	respBack, _ := client.PostForm(ts.URL+"/locale", locForm)
	_ = respBack.Body.Close()

	// 2. Department CRUD
	deptForm := url.Values{}
	deptForm.Set("name", "資訊安全部")
	deptForm.Set("parent_id", "1")
	deptForm.Set("sort", "10")
	dCreateResp, err := client.PostForm(ts.URL+"/departments", deptForm)
	if err != nil {
		t.Fatalf("POST /departments: %v", err)
	}
	_ = dCreateResp.Body.Close()
	if dCreateResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 on dept create, got %d", dCreateResp.StatusCode)
	}

	deptListResp, _ := client.Get(ts.URL + "/departments")
	deptListHTML := readBody(t, deptListResp)
	if !strings.Contains(deptListHTML, "資訊安全部") {
		t.Fatal("expected newly created department in /departments list")
	}

	// 3. Role CRUD with CUSTOM scope
	roleForm := url.Values{}
	roleForm.Set("code", "sec_auditor")
	roleForm.Set("name", "資安稽核員")
	roleForm.Set("data_scope", "CUSTOM")
	roleForm.Set("sort", "5")
	roleForm.Add("permission_ids", "1")
	roleForm.Add("department_ids", "4")
	rCreateResp, err := client.PostForm(ts.URL+"/roles", roleForm)
	if err != nil {
		t.Fatalf("POST /roles: %v", err)
	}
	_ = rCreateResp.Body.Close()
	if rCreateResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 on role create, got %d", rCreateResp.StatusCode)
	}

	// System role deletion must be refused
	rDelSysResp, _ := client.PostForm(ts.URL+"/roles/1/delete", url.Values{})
	_ = rDelSysResp.Body.Close()
	if rDelSysResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when attempting to delete super_admin role, got %d", rDelSysResp.StatusCode)
	}

	// 4. User CRUD + search + session invalidation on status change
	userForm := url.Values{}
	userForm.Set("account", "alice_sec")
	userForm.Set("password", "AliceSecret123!")
	userForm.Set("name", "愛麗絲")
	userForm.Set("employee_no", "EMP-900")
	userForm.Set("title", "資安工程師")
	userForm.Set("department_id", "4")
	userForm.Set("status", "active")
	userForm.Add("role_ids", "4")
	uCreateResp, err := client.PostForm(ts.URL+"/users", userForm)
	if err != nil {
		t.Fatalf("POST /users: %v", err)
	}
	_ = uCreateResp.Body.Close()
	if uCreateResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 on user create, got %d", uCreateResp.StatusCode)
	}

	// Verify alice_sec can log in
	aliceClient := loginClient(t, ts, "alice_sec", "AliceSecret123!")
	aliceHome, _ := aliceClient.Get(ts.URL + "/")
	_ = aliceHome.Body.Close()
	if aliceHome.StatusCode != http.StatusOK {
		t.Fatalf("expected alice_sec home 200, got %d", aliceHome.StatusCode)
	}

	// Admin suspends alice_sec -> alice_sec's session is revoked immediately
	var aliceID string
	_ = h.store.AppRead.QueryRowContext(context.Background(), `SELECT id FROM users WHERE account = 'alice_sec'`).Scan(&aliceID)
	uEditForm := url.Values{}
	uEditForm.Set("name", "愛麗絲")
	uEditForm.Set("department_id", "4")
	uEditForm.Set("status", "suspended")
	uEditForm.Add("role_ids", "4")
	uUpdResp, _ := client.PostForm(ts.URL+"/users/"+aliceID, uEditForm)
	_ = uUpdResp.Body.Close()

	aliceAfterResp, _ := aliceClient.Get(ts.URL + "/")
	_ = aliceAfterResp.Body.Close()
	if aliceAfterResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected suspended alice_sec redirected to /login, got %d", aliceAfterResp.StatusCode)
	}

	// 5. Audit logs page displays recorded mutations
	auditResp, err := client.Get(ts.URL + "/audit-logs?account=admin")
	if err != nil {
		t.Fatalf("GET /audit-logs: %v", err)
	}
	auditHTML := readBody(t, auditResp)
	for _, action := range []string{"auth.login", "department.create", "role.create", "user.create", "user.update"} {
		if !strings.Contains(auditHTML, action) {
			t.Errorf("expected audit action %q on /audit-logs page", action)
		}
	}

	auditLogger := audit.NewLogger(h.store.Audit)
	res, err := auditLogger.List(context.Background(), audit.Filter{Account: "admin"})
	if err != nil || res.Total < 5 {
		t.Fatalf("expected >=5 audit logs for admin, got %d err=%v", res.Total, err)
	}

	// 6. Logout invalidates admin session cookie
	logoutResp, _ := client.PostForm(ts.URL+"/logout", url.Values{})
	_ = logoutResp.Body.Close()
	afterLogout, _ := client.Get(ts.URL + "/")
	_ = afterLogout.Body.Close()
	if afterLogout.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect to /login after logout, got %d", afterLogout.StatusCode)
	}
}
