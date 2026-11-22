package user_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Florencea/erp-rbac/internal/auth"
	"github.com/Florencea/erp-rbac/internal/db"
	"github.com/Florencea/erp-rbac/internal/domain/department"
	"github.com/Florencea/erp-rbac/internal/domain/role"
	"github.com/Florencea/erp-rbac/internal/domain/user"
	"github.com/Florencea/erp-rbac/internal/rbac"
)

func TestDataScopesAntiIDORAndEscalation(t *testing.T) {
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

	sessions := auth.NewManager(store.AppWrite, store.AppRead, time.Hour, true)
	deptSvc := department.NewService(store.AppWrite, store.AppRead)
	roleSvc := role.NewService(store.AppWrite, store.AppRead)
	userSvc := user.NewService(store.AppWrite, store.AppRead, sessions)

	var adminID int64
	if err := store.AppRead.QueryRowContext(ctx, `SELECT id FROM users WHERE account = 'admin'`).Scan(&adminID); err != nil {
		t.Fatalf("admin id: %v", err)
	}
	adminPrincipal, err := rbac.LoadPrincipal(ctx, store.AppRead, adminID)
	if err != nil || adminPrincipal == nil {
		t.Fatalf("load admin principal: %v", err)
	}

	depts, _ := deptSvc.List(ctx)
	engID := depts[1].ID   // 研發部
	salesID := depts[2].ID // 業務部
	engSub, err := deptSvc.Create(ctx, department.Input{Name: "前端組", ParentID: &engID, Sort: 1})
	if err != nil {
		t.Fatalf("create engSub: %v", err)
	}

	perms, _ := roleSvc.ListPermissions(ctx)
	var userReadPermID, userUpdatePermID int64
	for _, p := range perms {
		if p.Code == "system:user:read" {
			userReadPermID = p.ID
		}
		if p.Code == "system:user:update" {
			userUpdatePermID = p.ID
		}
	}

	rolesList, _ := roleSvc.List(ctx)
	var superRoleID, deptMgrRoleID, empRoleID int64
	for _, r := range rolesList {
		switch r.Code {
		case "super_admin":
			superRoleID = r.ID
		case "dept_manager":
			deptMgrRoleID = r.ID
		case "employee":
			empRoleID = r.ID
		}
	}

	deptOnlyRole, err := roleSvc.Create(ctx, role.Input{
		Code:          "dept_only_lead",
		Name:          "單部門主管",
		DataScope:     "DEPT",
		PermissionIDs: []int64{userReadPermID, userUpdatePermID},
	})
	if err != nil {
		t.Fatalf("create dept_only_lead: %v", err)
	}
	customSalesRole, err := roleSvc.Create(ctx, role.Input{
		Code:          "custom_sales_viewer",
		Name:          "業務稽核員",
		DataScope:     "CUSTOM",
		PermissionIDs: []int64{userReadPermID},
		DepartmentIDs: []int64{salesID},
	})
	if err != nil {
		t.Fatalf("create custom_sales_viewer: %v", err)
	}

	// Create test users in Eng, EngSub, Sales
	uEngMgr, err := userSvc.Create(ctx, adminPrincipal, user.Input{
		Account: "eng_mgr", Password: "Password123!", Name: "研發主管", Status: "active",
		DepartmentID: &engID, RoleIDs: []int64{deptMgrRoleID},
	})
	if err != nil {
		t.Fatalf("create eng_mgr: %v", err)
	}
	uEngSub, err := userSvc.Create(ctx, adminPrincipal, user.Input{
		Account: "eng_sub", Password: "Password123!", Name: "子部門工程師", Status: "active",
		DepartmentID: &engSub.ID, RoleIDs: []int64{empRoleID},
	})
	if err != nil {
		t.Fatalf("create eng_sub: %v", err)
	}
	uSales, err := userSvc.Create(ctx, adminPrincipal, user.Input{
		Account: "sales_emp", Password: "Password123!", Name: "業務專員", Status: "active",
		DepartmentID: &salesID, RoleIDs: []int64{empRoleID},
	})
	if err != nil {
		t.Fatalf("create sales_emp: %v", err)
	}
	uDeptOnly, err := userSvc.Create(ctx, adminPrincipal, user.Input{
		Account: "eng_only_lead", Password: "Password123!", Name: "單部門主管", Status: "active",
		DepartmentID: &engID, RoleIDs: []int64{deptOnlyRole.ID},
	})
	if err != nil {
		t.Fatalf("create eng_only_lead: %v", err)
	}
	uCustom, err := userSvc.Create(ctx, adminPrincipal, user.Input{
		Account: "sales_auditor", Password: "Password123!", Name: "業務檢視者", Status: "active",
		DepartmentID: &engID, RoleIDs: []int64{customSalesRole.ID},
	})
	if err != nil {
		t.Fatalf("create sales_auditor: %v", err)
	}

	// 1. ALL scope sees all 6 users
	allVisible, err := userSvc.List(ctx, adminPrincipal, user.ListFilter{})
	if err != nil || len(allVisible) != 6 {
		t.Fatalf("expected 6 users for ALL scope, got %d err=%v", len(allVisible), err)
	}

	// 2. DEPT_AND_CHILD sees Eng + EngSub, NOT Sales or Root
	pEngMgr, _ := rbac.LoadPrincipal(ctx, store.AppRead, uEngMgr.ID)
	mgrVisible, err := userSvc.List(ctx, pEngMgr, user.ListFilter{})
	if err != nil {
		t.Fatalf("list for eng_mgr: %v", err)
	}
	mgrAccounts := accountsOf(mgrVisible)
	if !slices.Contains(mgrAccounts, "eng_mgr") || !slices.Contains(mgrAccounts, "eng_sub") {
		t.Fatalf("expected eng_mgr and eng_sub in DEPT_AND_CHILD, got %v", mgrAccounts)
	}
	if slices.Contains(mgrAccounts, "sales_emp") || slices.Contains(mgrAccounts, "admin") {
		t.Fatalf("DEPT_AND_CHILD leaked out-of-scope users: %v", mgrAccounts)
	}

	// Anti-IDOR: eng_mgr cannot read/update/delete sales_emp or admin
	if _, err := userSvc.GetForActor(ctx, pEngMgr, uSales.ID); !errors.Is(err, user.ErrPrivilegeEscalation) {
		t.Fatalf("expected ErrPrivilegeEscalation on cross-dept GetForActor, got %v", err)
	}
	if err := userSvc.Delete(ctx, pEngMgr, uSales.ID); !errors.Is(err, user.ErrPrivilegeEscalation) {
		t.Fatalf("expected ErrPrivilegeEscalation on cross-dept Delete, got %v", err)
	}
	// Anti-escalation: eng_mgr cannot assign super_admin to eng_sub
	if _, err := userSvc.Update(ctx, pEngMgr, uEngSub.ID, user.Input{
		Name: "子部門工程師", Status: "active", DepartmentID: &engSub.ID, RoleIDs: []int64{superRoleID},
	}); !errors.Is(err, user.ErrPrivilegeEscalation) {
		t.Fatalf("expected ErrPrivilegeEscalation assigning super_admin, got %v", err)
	}

	// 3. DEPT scope sees ONLY Eng, NOT EngSub
	pDeptOnly, _ := rbac.LoadPrincipal(ctx, store.AppRead, uDeptOnly.ID)
	deptOnlyVisible, _ := userSvc.List(ctx, pDeptOnly, user.ListFilter{})
	deptOnlyAccounts := accountsOf(deptOnlyVisible)
	if !slices.Contains(deptOnlyAccounts, "eng_mgr") || slices.Contains(deptOnlyAccounts, "eng_sub") {
		t.Fatalf("unexpected DEPT scope result: %v", deptOnlyAccounts)
	}

	// 4. SELF scope sees ONLY self
	pSales, _ := rbac.LoadPrincipal(ctx, store.AppRead, uSales.ID)
	selfVisible, _ := userSvc.List(ctx, pSales, user.ListFilter{})
	if len(selfVisible) != 1 || selfVisible[0].Account != "sales_emp" {
		t.Fatalf("expected only sales_emp for SELF scope, got %v", accountsOf(selfVisible))
	}

	// 5. CUSTOM scope sees Sales only
	pCustom, _ := rbac.LoadPrincipal(ctx, store.AppRead, uCustom.ID)
	customVisible, _ := userSvc.List(ctx, pCustom, user.ListFilter{})
	customAccounts := accountsOf(customVisible)
	if len(customAccounts) != 1 || customAccounts[0] != "sales_emp" {
		t.Fatalf("expected only sales_emp for CUSTOM scope, got %v", customAccounts)
	}

	// 6. Deactivating user immediately revokes sessions and blocks LoadPrincipal
	if _, err := userSvc.Update(ctx, adminPrincipal, uSales.ID, user.Input{
		Name: "業務專員", Status: "suspended", DepartmentID: &salesID, RoleIDs: []int64{empRoleID},
	}); err != nil {
		t.Fatalf("suspend sales_emp: %v", err)
	}
	pSalesAfter, err := rbac.LoadPrincipal(ctx, store.AppRead, uSales.ID)
	if err != nil || pSalesAfter != nil {
		t.Fatalf("expected suspended user principal to be nil, got %+v err=%v", pSalesAfter, err)
	}
}

func accountsOf(users []user.User) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.Account)
	}
	return out
}
