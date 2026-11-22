package rbac

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const RoleSuperAdmin = "super_admin"

// Principal represents an active authenticated user with resolved roles, permissions, and data scopes.
type Principal struct {
	ID           int64
	Account      string
	Name         string
	EmployeeNo   string
	Title        string
	Status       string
	DepartmentID *int64
	IsSystem     bool
	Roles        []string
	Permissions  map[string]struct{}
	DataScopes   []string
}

// IsSuperAdmin reports whether the principal holds the super_admin role.
func (p *Principal) IsSuperAdmin() bool {
	if p == nil {
		return false
	}
	for _, r := range p.Roles {
		if r == RoleSuperAdmin {
			return true
		}
	}
	return false
}

// HasPerm checks whether the principal is allowed to execute the given permission code.
func (p *Principal) HasPerm(code string) bool {
	if p == nil {
		return false
	}
	if p.IsSuperAdmin() {
		return true
	}
	_, ok := p.Permissions[code]
	return ok
}

// HasAnyPerm checks whether the principal holds at least one of the specified permission codes.
func (p *Principal) HasAnyPerm(codes ...string) bool {
	for _, code := range codes {
		if p.HasPerm(code) {
			return true
		}
	}
	return false
}

// DisplayName returns the user's name if non-empty, otherwise their account identifier.
func (p *Principal) DisplayName() string {
	if p == nil {
		return ""
	}
	if strings.TrimSpace(p.Name) != "" {
		return p.Name
	}
	return p.Account
}

// LoadPrincipal loads an active user's identity, roles, permissions, and data scopes from readDB.
// Returns nil, nil if the user does not exist or is not active.
func LoadPrincipal(ctx context.Context, readDB *sql.DB, userID int64) (*Principal, error) {
	var p Principal
	var deptID sql.NullInt64
	var isSys int

	err := readDB.QueryRowContext(
		ctx,
		`SELECT id, account, name, employee_no, title, status, department_id, is_system
		 FROM users
		 WHERE id = ?`,
		userID,
	).Scan(&p.ID, &p.Account, &p.Name, &p.EmployeeNo, &p.Title, &p.Status, &deptID, &isSys)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if p.Status != "active" {
		return nil, nil
	}
	if deptID.Valid {
		v := deptID.Int64
		p.DepartmentID = &v
	}
	p.IsSystem = isSys == 1
	p.Permissions = make(map[string]struct{})

	roleRows, err := readDB.QueryContext(
		ctx,
		`SELECT r.id, r.code, r.data_scope
		 FROM roles r
		 INNER JOIN user_roles ur ON ur.role_id = r.id
		 WHERE ur.user_id = ?
		 ORDER BY r.sort ASC, r.id ASC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = roleRows.Close() }()

	var roleIDs []int64
	scopeSeen := make(map[string]struct{})
	for roleRows.Next() {
		var rid int64
		var code, scope string
		if err := roleRows.Scan(&rid, &code, &scope); err != nil {
			return nil, err
		}
		roleIDs = append(roleIDs, rid)
		p.Roles = append(p.Roles, code)
		if _, ok := scopeSeen[scope]; !ok {
			scopeSeen[scope] = struct{}{}
			p.DataScopes = append(p.DataScopes, scope)
		}
	}
	if err := roleRows.Err(); err != nil {
		return nil, err
	}

	if p.IsSuperAdmin() {
		p.DataScopes = []string{"ALL"}
		permRows, err := readDB.QueryContext(ctx, `SELECT code FROM permissions`)
		if err != nil {
			return nil, err
		}
		defer func() { _ = permRows.Close() }()
		for permRows.Next() {
			var code string
			if err := permRows.Scan(&code); err != nil {
				return nil, err
			}
			p.Permissions[code] = struct{}{}
		}
		return &p, permRows.Err()
	}

	if len(roleIDs) == 0 {
		return &p, nil
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(roleIDs)), ",")
	args := make([]any, 0, len(roleIDs))
	for _, rid := range roleIDs {
		args = append(args, rid)
	}

	permRows, err := readDB.QueryContext(
		ctx,
		`SELECT DISTINCT pm.code
		 FROM permissions pm
		 INNER JOIN role_permissions rp ON rp.permission_id = pm.id
		 WHERE rp.role_id IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = permRows.Close() }()

	for permRows.Next() {
		var code string
		if err := permRows.Scan(&code); err != nil {
			return nil, err
		}
		p.Permissions[code] = struct{}{}
	}
	if err := permRows.Err(); err != nil {
		return nil, err
	}

	return &p, nil
}
