package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/Florencea/erp-rbac/internal/auth"
)

const DefaultAdminAccount = "admin"

// SeedOptions controls initial administrator seeding behavior.
type SeedOptions struct {
	AdminPassword      string
	ResetAdminPassword bool
}

// SeedResult reports whether the initial administrator was created or rotated.
type SeedResult struct {
	AdminCreated      bool
	GeneratedPassword string
}

type permSeed struct {
	Code string
	Name string
	Type string
	Sort int
}

var initialPermissions = []permSeed{
	{Code: "system:dept:read", Name: "查看部門", Type: "menu", Sort: 10},
	{Code: "system:dept:create", Name: "新增部門", Type: "button", Sort: 11},
	{Code: "system:dept:update", Name: "編輯部門", Type: "button", Sort: 12},
	{Code: "system:dept:delete", Name: "刪除部門", Type: "button", Sort: 13},

	{Code: "system:role:read", Name: "查看角色", Type: "menu", Sort: 20},
	{Code: "system:role:create", Name: "新增角色", Type: "button", Sort: 21},
	{Code: "system:role:update", Name: "編輯角色", Type: "button", Sort: 22},
	{Code: "system:role:delete", Name: "刪除角色", Type: "button", Sort: 23},

	{Code: "system:user:read", Name: "查看使用者", Type: "menu", Sort: 30},
	{Code: "system:user:create", Name: "新增使用者", Type: "button", Sort: 31},
	{Code: "system:user:update", Name: "編輯使用者", Type: "button", Sort: 32},
	{Code: "system:user:delete", Name: "刪除使用者", Type: "button", Sort: 33},

	{Code: "system:audit:read", Name: "查看稽核日誌", Type: "menu", Sort: 40},
}

// EnsureSeeded verifies that core RBAC tables contain baseline seed records and seeds if missing.
func EnsureSeeded(ctx context.Context, store *Store, opts SeedOptions) (SeedResult, error) {
	var adminCount int
	if err := store.AppRead.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM users WHERE account = ?`,
		DefaultAdminAccount,
	).Scan(&adminCount); err != nil {
		return SeedResult{}, err
	}
	var permCount int
	if err := store.AppRead.QueryRowContext(ctx, `SELECT COUNT(*) FROM permissions`).Scan(&permCount); err != nil {
		return SeedResult{}, err
	}
	if adminCount > 0 && permCount >= len(initialPermissions) && !opts.ResetAdminPassword {
		return SeedResult{}, nil
	}
	return Seed(ctx, store, opts)
}

// Seed idempotently populates default permissions, departments, roles, and the admin account.
func Seed(ctx context.Context, store *Store, opts SeedOptions) (SeedResult, error) {
	tx, err := store.AppWrite.BeginTx(ctx, nil)
	if err != nil {
		return SeedResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()

	// 1. Seed permissions
	for _, p := range initialPermissions {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO permissions (code, name, type, sort) VALUES (?, ?, ?, ?)`,
			p.Code, p.Name, p.Type, p.Sort,
		); err != nil {
			return SeedResult{}, fmt.Errorf("seed permission %s: %w", p.Code, err)
		}
	}

	// 2. Seed initial departments if empty
	var rootDeptID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM departments ORDER BY sort ASC, id ASC LIMIT 1`).Scan(&rootDeptID)
	if errors.Is(err, sql.ErrNoRows) {
		res, insErr := tx.ExecContext(
			ctx,
			`INSERT INTO departments (parent_id, name, path, sort, created_at, updated_at) VALUES (NULL, ?, ?, 1, ?, ?)`,
			"總部", "/1/", now, now,
		)
		if insErr != nil {
			return SeedResult{}, fmt.Errorf("seed root dept: %w", insErr)
		}
		rootDeptID, _ = res.LastInsertId()
		rootPath := fmt.Sprintf("/%d/", rootDeptID)
		if _, updErr := tx.ExecContext(ctx, `UPDATE departments SET path = ? WHERE id = ?`, rootPath, rootDeptID); updErr != nil {
			return SeedResult{}, updErr
		}

		for idx, name := range []string{"研發部", "業務部"} {
			childRes, cErr := tx.ExecContext(
				ctx,
				`INSERT INTO departments (parent_id, name, path, sort, created_at, updated_at) VALUES (?, ?, '', ?, ?, ?)`,
				rootDeptID, name, idx+1, now, now,
			)
			if cErr != nil {
				return SeedResult{}, fmt.Errorf("seed child dept %s: %w", name, cErr)
			}
			cid, _ := childRes.LastInsertId()
			cPath := fmt.Sprintf("%s%d/", rootPath, cid)
			if _, updErr := tx.ExecContext(ctx, `UPDATE departments SET path = ? WHERE id = ?`, cPath, cid); updErr != nil {
				return SeedResult{}, updErr
			}
		}
	} else if err != nil {
		return SeedResult{}, err
	}

	// 3. Seed roles
	roleSpecs := []struct {
		Code      string
		Name      string
		Desc      string
		DataScope string
		IsSystem  int
		Sort      int
	}{
		{
			Code:      "super_admin",
			Name:      "超級管理員",
			Desc:      "系統最高權限，可管理所有模組與全公司資料",
			DataScope: "ALL",
			IsSystem:  1,
			Sort:      1,
		},
		{
			Code:      "dept_manager",
			Name:      "部門主管",
			Desc:      "可管理本部門及子部門的使用者與組織",
			DataScope: "DEPT_AND_CHILD",
			IsSystem:  0,
			Sort:      2,
		},
		{
			Code:      "employee",
			Name:      "一般員工",
			Desc:      "一般使用者權限，僅能查看基本資訊",
			DataScope: "SELF",
			IsSystem:  0,
			Sort:      3,
		},
	}

	roleIDs := make(map[string]int64, len(roleSpecs))
	for _, rs := range roleSpecs {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO roles (code, name, description, data_scope, sort, is_system, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			rs.Code, rs.Name, rs.Desc, rs.DataScope, rs.Sort, rs.IsSystem, now, now,
		); err != nil {
			return SeedResult{}, fmt.Errorf("seed role %s: %w", rs.Code, err)
		}
		var rid int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE code = ?`, rs.Code).Scan(&rid); err != nil {
			return SeedResult{}, err
		}
		roleIDs[rs.Code] = rid
	}

	// 4. Assign permissions to preset roles idempotently
	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
		 SELECT ?, id FROM permissions`,
		roleIDs["super_admin"],
	); err != nil {
		return SeedResult{}, err
	}

	managerPerms := []string{
		"system:dept:read",
		"system:dept:create",
		"system:dept:update",
		"system:user:read",
		"system:user:create",
		"system:user:update",
		"system:role:read",
	}
	for _, code := range managerPerms {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
			 SELECT ?, id FROM permissions WHERE code = ?`,
			roleIDs["dept_manager"], code,
		); err != nil {
			return SeedResult{}, err
		}
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
		 SELECT ?, id FROM permissions WHERE code = 'system:user:read'`,
		roleIDs["employee"],
	); err != nil {
		return SeedResult{}, err
	}

	// 5. Seed or optionally reset admin user
	var result SeedResult
	var adminID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE account = ?`, DefaultAdminAccount).Scan(&adminID)
	if errors.Is(err, sql.ErrNoRows) {
		rawPass := opts.AdminPassword
		if rawPass == "" {
			rawPass, err = generateRandomPassword(20)
			if err != nil {
				return SeedResult{}, err
			}
			result.GeneratedPassword = rawPass
		} else if len(rawPass) < 8 {
			return SeedResult{}, errors.New("admin password must be at least 8 characters")
		}

		hash, err := auth.HashPassword(rawPass)
		if err != nil {
			return SeedResult{}, err
		}
		uid, err := NewUUID()
		if err != nil {
			return SeedResult{}, err
		}

		res, err := tx.ExecContext(
			ctx,
			`INSERT INTO users (uid, account, password_hash, name, employee_no, title, status, department_id, is_system, created_at, updated_at)
			 VALUES (?, ?, ?, ?, '', '', 'active', ?, 1, ?, ?)`,
			uid, DefaultAdminAccount, hash, "系統管理員", rootDeptID, now, now,
		)
		if err != nil {
			return SeedResult{}, fmt.Errorf("seed admin user: %w", err)
		}
		adminID, _ = res.LastInsertId()
		result.AdminCreated = true
	} else if err != nil {
		return SeedResult{}, err
	} else if opts.ResetAdminPassword {
		rawPass := opts.AdminPassword
		if rawPass == "" {
			rawPass, err = generateRandomPassword(20)
			if err != nil {
				return SeedResult{}, err
			}
			result.GeneratedPassword = rawPass
		} else if len(rawPass) < 8 {
			return SeedResult{}, errors.New("admin password must be at least 8 characters")
		}

		hash, err := auth.HashPassword(rawPass)
		if err != nil {
			return SeedResult{}, err
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE users SET password_hash = ?, status = 'active', updated_at = ? WHERE id = ?`,
			hash, now, adminID,
		); err != nil {
			return SeedResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, adminID); err != nil {
			return SeedResult{}, err
		}
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO user_roles (user_id, role_id, scope_type, scope_id) VALUES (?, ?, 'global', '')`,
		adminID, roleIDs["super_admin"],
	); err != nil {
		return SeedResult{}, err
	}

	if err := tx.Commit(); err != nil {
		return SeedResult{}, err
	}
	return result, nil
}

// NewUUID generates a random RFC 4122 version 4 UUID string using crypto/rand.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func generateRandomPassword(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
