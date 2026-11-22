package role

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"
)

var (
	ErrNotFound        = errors.New("role not found")
	ErrCodeExists      = errors.New("role code already exists")
	ErrCodeRequired    = errors.New("role code is required")
	ErrNameRequired    = errors.New("role name is required")
	ErrInvalidScope    = errors.New("invalid data scope")
	ErrSystemProtected = errors.New("system role is protected")
)

var ValidDataScopes = []string{"ALL", "DEPT_AND_CHILD", "DEPT", "SELF", "CUSTOM"}

// Permission describes an assignable RBAC permission record.
type Permission struct {
	ID   int64
	Code string
	Name string
	Type string
	Sort int
}

// Role represents a role along with its assigned permissions and custom department IDs.
type Role struct {
	ID            int64
	Code          string
	Name          string
	Description   string
	DataScope     string
	Sort          int
	IsSystem      bool
	CreatedAt     int64
	UpdatedAt     int64
	PermissionIDs []int64
	DepartmentIDs []int64
}

// Input defines fields for creating or updating a role.
type Input struct {
	Code          string
	Name          string
	Description   string
	DataScope     string
	Sort          int
	PermissionIDs []int64
	DepartmentIDs []int64
}

// Service manages RBAC roles and their permission/department assignments.
type Service struct {
	writeDB *sql.DB
	readDB  *sql.DB
}

// NewService constructs a role domain service.
func NewService(writeDB, readDB *sql.DB) *Service {
	return &Service{writeDB: writeDB, readDB: readDB}
}

// ListPermissions returns all available permissions ordered by sort and ID.
func (s *Service) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.readDB.QueryContext(
		ctx,
		`SELECT id, code, name, type, sort FROM permissions ORDER BY sort ASC, id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	items := make([]Permission, 0)
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Type, &p.Sort); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}

// List returns all roles with their associated permission IDs and custom department IDs.
func (s *Service) List(ctx context.Context) ([]Role, error) {
	rows, err := s.readDB.QueryContext(
		ctx,
		`SELECT id, code, name, description, data_scope, sort, is_system, created_at, updated_at
		 FROM roles ORDER BY sort ASC, id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	rolesList := make([]Role, 0)
	for rows.Next() {
		var r Role
		var isSys int
		if err := rows.Scan(
			&r.ID, &r.Code, &r.Name, &r.Description, &r.DataScope,
			&r.Sort, &isSys, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, err
		}
		r.IsSystem = isSys == 1
		rolesList = append(rolesList, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range rolesList {
		pIDs, dIDs, err := s.loadRelations(ctx, rolesList[i].ID)
		if err != nil {
			return nil, err
		}
		rolesList[i].PermissionIDs = pIDs
		rolesList[i].DepartmentIDs = dIDs
	}
	return rolesList, nil
}

// GetByID retrieves a single role by ID.
func (s *Service) GetByID(ctx context.Context, id int64) (*Role, error) {
	var r Role
	var isSys int
	err := s.readDB.QueryRowContext(
		ctx,
		`SELECT id, code, name, description, data_scope, sort, is_system, created_at, updated_at
		 FROM roles WHERE id = ?`,
		id,
	).Scan(&r.ID, &r.Code, &r.Name, &r.Description, &r.DataScope, &r.Sort, &isSys, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.IsSystem = isSys == 1

	pIDs, dIDs, err := s.loadRelations(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	r.PermissionIDs = pIDs
	r.DepartmentIDs = dIDs
	return &r, nil
}

func (s *Service) loadRelations(ctx context.Context, roleID int64) ([]int64, []int64, error) {
	pRows, err := s.readDB.QueryContext(
		ctx,
		`SELECT permission_id FROM role_permissions WHERE role_id = ? ORDER BY permission_id ASC`,
		roleID,
	)
	if err != nil {
		return nil, nil, err
	}
	var pIDs []int64
	for pRows.Next() {
		var pid int64
		if scanErr := pRows.Scan(&pid); scanErr != nil {
			_ = pRows.Close()
			return nil, nil, scanErr
		}
		pIDs = append(pIDs, pid)
	}
	if closeErr := pRows.Close(); closeErr != nil {
		return nil, nil, closeErr
	}
	if err := pRows.Err(); err != nil {
		return nil, nil, err
	}

	dRows, err := s.readDB.QueryContext(
		ctx,
		`SELECT department_id FROM role_departments WHERE role_id = ? ORDER BY department_id ASC`,
		roleID,
	)
	if err != nil {
		return nil, nil, err
	}
	var dIDs []int64
	for dRows.Next() {
		var did int64
		if scanErr := dRows.Scan(&did); scanErr != nil {
			_ = dRows.Close()
			return nil, nil, scanErr
		}
		dIDs = append(dIDs, did)
	}
	if closeErr := dRows.Close(); closeErr != nil {
		return nil, nil, closeErr
	}
	if err := dRows.Err(); err != nil {
		return nil, nil, err
	}

	return pIDs, dIDs, nil
}

// Create inserts a new custom role with its permission and custom department assignments.
func (s *Service) Create(ctx context.Context, input Input) (*Role, error) {
	code := strings.TrimSpace(input.Code)
	name := strings.TrimSpace(input.Name)
	if code == "" {
		return nil, ErrCodeRequired
	}
	if name == "" {
		return nil, ErrNameRequired
	}
	if !slices.Contains(ValidDataScopes, input.DataScope) {
		return nil, ErrInvalidScope
	}

	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM roles WHERE code = ?`, code).Scan(&exists)
	if err == nil {
		return nil, ErrCodeExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	now := time.Now().Unix()
	res, err := tx.ExecContext(
		ctx,
		`INSERT INTO roles (code, name, description, data_scope, sort, is_system, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		code, name, strings.TrimSpace(input.Description), input.DataScope, input.Sort, now, now,
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	if err := replaceRoleRelations(ctx, tx, id, input.DataScope, input.PermissionIDs, input.DepartmentIDs); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, id)
}

// Update modifies a role's metadata, permissions, and custom departments atomically.
func (s *Service) Update(ctx context.Context, id int64, input Input) (*Role, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, ErrNameRequired
	}
	if !slices.Contains(ValidDataScopes, input.DataScope) {
		return nil, ErrInvalidScope
	}

	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var currentCode string
	var isSys int
	err = tx.QueryRowContext(ctx, `SELECT code, is_system FROM roles WHERE id = ?`, id).Scan(&currentCode, &isSys)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if isSys == 1 && currentCode == "super_admin" && input.DataScope != "ALL" {
		return nil, ErrSystemProtected
	}

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE roles SET name = ?, description = ?, data_scope = ?, sort = ?, updated_at = ? WHERE id = ?`,
		name, strings.TrimSpace(input.Description), input.DataScope, input.Sort, time.Now().Unix(), id,
	); err != nil {
		return nil, err
	}

	if err := replaceRoleRelations(ctx, tx, id, input.DataScope, input.PermissionIDs, input.DepartmentIDs); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, id)
}

// Delete deletes a non-system role.
func (s *Service) Delete(ctx context.Context, id int64) error {
	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var isSys int
	err = tx.QueryRowContext(ctx, `SELECT is_system FROM roles WHERE id = ?`, id).Scan(&isSys)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if isSys == 1 {
		return ErrSystemProtected
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM roles WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceRoleRelations(
	ctx context.Context,
	tx *sql.Tx,
	roleID int64,
	dataScope string,
	permIDs []int64,
	deptIDs []int64,
) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = ?`, roleID); err != nil {
		return err
	}
	for _, pid := range uniquePositiveIDs(permIDs) {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)`,
			roleID, pid,
		); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM role_departments WHERE role_id = ?`, roleID); err != nil {
		return err
	}
	if dataScope == "CUSTOM" {
		for _, did := range uniquePositiveIDs(deptIDs) {
			if _, err := tx.ExecContext(
				ctx,
				`INSERT OR IGNORE INTO role_departments (role_id, department_id) VALUES (?, ?)`,
				roleID, did,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func uniquePositiveIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
