package user

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Florencea/erp-rbac/internal/auth"
	"github.com/Florencea/erp-rbac/internal/db"
	"github.com/Florencea/erp-rbac/internal/rbac"
)

var (
	ErrNotFound            = errors.New("user not found")
	ErrAccountExists       = errors.New("account already exists")
	ErrAccountRequired     = errors.New("account is required")
	ErrPasswordMinLen      = errors.New("password must be at least 8 characters")
	ErrInvalidStatus       = errors.New("invalid user status")
	ErrSystemProtected     = errors.New("system user is protected")
	ErrSelfDelete          = errors.New("cannot delete current user")
	ErrPrivilegeEscalation = errors.New("privilege escalation forbidden")
)

var ValidStatuses = []string{"active", "inactive", "suspended"}

// User represents a persisted ERP user record and assigned role IDs.
type User struct {
	ID           int64
	UID          string
	Account      string
	Name         string
	EmployeeNo   string
	Title        string
	Status       string
	DepartmentID *int64
	ReportsToID  *int64
	IsSystem     bool
	CreatedAt    int64
	UpdatedAt    int64
	RoleIDs      []int64
}

// ListFilter narrows the user listing view.
type ListFilter struct {
	Query  string
	Status string
}

// Input defines fields for creating or updating a user.
type Input struct {
	Account      string
	Password     string
	Name         string
	EmployeeNo   string
	Title        string
	Status       string
	DepartmentID *int64
	RoleIDs      []int64
}

// Service manages user accounts with strict Data Scope, anti-IDOR, and anti-escalation controls.
type Service struct {
	writeDB  *sql.DB
	readDB   *sql.DB
	sessions *auth.Manager
}

// NewService constructs a user domain service.
func NewService(writeDB, readDB *sql.DB, sessions *auth.Manager) *Service {
	return &Service{writeDB: writeDB, readDB: readDB, sessions: sessions}
}

// List returns users visible within the actor's Data Scope matching optional filters.
func (s *Service) List(ctx context.Context, actor *rbac.Principal, filter ListFilter) ([]User, error) {
	scopeClause, scopeArgs, err := rbac.BuildUserScopeSQL(ctx, s.readDB, actor, "id", "department_id")
	if err != nil {
		return nil, err
	}

	var clauses []string
	var args []any
	if scopeClause != "" {
		clauses = append(clauses, "("+scopeClause+")")
		args = append(args, scopeArgs...)
	}
	if q := strings.TrimSpace(filter.Query); q != "" {
		clauses = append(clauses, "(account LIKE ? OR name LIKE ? OR employee_no LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	if st := strings.TrimSpace(filter.Status); st != "" && slices.Contains(ValidStatuses, st) {
		clauses = append(clauses, "status = ?")
		args = append(args, st)
	}

	query := `SELECT id, uid, account, name, employee_no, title, status, department_id, reports_to_id, is_system, created_at, updated_at
		FROM users`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY id ASC"

	rows, err := s.readDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	items := make([]User, 0)
	for rows.Next() {
		u, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range items {
		rIDs, err := s.loadUserRoleIDs(ctx, items[i].ID)
		if err != nil {
			return nil, err
		}
		items[i].RoleIDs = rIDs
	}
	return items, nil
}

// GetForActor loads a single user only if accessible within the actor's Data Scope.
func (s *Service) GetForActor(ctx context.Context, actor *rbac.Principal, targetID int64) (*User, error) {
	allowed, err := rbac.CanAccessUser(ctx, s.readDB, actor, targetID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		// Check whether target exists at all to distinguish 404 vs 403/denied.
		var exists int
		if err := s.readDB.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, targetID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, ErrPrivilegeEscalation
	}

	u, err := s.getByID(ctx, targetID)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Service) getByID(ctx context.Context, id int64) (*User, error) {
	row := s.readDB.QueryRowContext(
		ctx,
		`SELECT id, uid, account, name, employee_no, title, status, department_id, reports_to_id, is_system, created_at, updated_at
		 FROM users WHERE id = ?`,
		id,
	)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rIDs, err := s.loadUserRoleIDs(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	u.RoleIDs = rIDs
	return &u, nil
}

func (s *Service) loadUserRoleIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.readDB.QueryContext(
		ctx,
		`SELECT role_id FROM user_roles WHERE user_id = ? ORDER BY role_id ASC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []int64
	for rows.Next() {
		var rid int64
		if err := rows.Scan(&rid); err != nil {
			return nil, err
		}
		out = append(out, rid)
	}
	return out, rows.Err()
}

// Create creates a new user account while enforcing password, uniqueness, and privilege checks.
func (s *Service) Create(ctx context.Context, actor *rbac.Principal, input Input) (*User, error) {
	account := strings.TrimSpace(input.Account)
	if account == "" {
		return nil, ErrAccountRequired
	}
	if len(input.Password) < 8 {
		return nil, ErrPasswordMinLen
	}
	status := strings.TrimSpace(input.Status)
	if status == "" {
		status = "active"
	}
	if !slices.Contains(ValidStatuses, status) {
		return nil, ErrInvalidStatus
	}

	if err := s.enforceRoleAssignmentAllowed(ctx, actor, input.RoleIDs, nil); err != nil {
		return nil, err
	}
	if err := s.enforceDepartmentWriteScope(ctx, actor, input.DepartmentID); err != nil {
		return nil, err
	}

	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}
	uid, err := db.NewUUID()
	if err != nil {
		return nil, err
	}

	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE account = ?`, account).Scan(&exists)
	if err == nil {
		return nil, ErrAccountExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	var deptVal sql.NullInt64
	if input.DepartmentID != nil && *input.DepartmentID > 0 {
		deptVal = sql.NullInt64{Int64: *input.DepartmentID, Valid: true}
	}

	now := time.Now().Unix()
	res, err := tx.ExecContext(
		ctx,
		`INSERT INTO users (uid, account, password_hash, name, employee_no, title, status, department_id, is_system, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		uid,
		account,
		passwordHash,
		strings.TrimSpace(input.Name),
		strings.TrimSpace(input.EmployeeNo),
		strings.TrimSpace(input.Title),
		status,
		deptVal,
		now,
		now,
	)
	if err != nil {
		return nil, err
	}
	userID, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	if err := replaceUserRoles(ctx, tx, userID, input.RoleIDs); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getByID(ctx, userID)
}

// Update modifies a user within the actor's Data Scope and revokes sessions on deactivation or password change.
func (s *Service) Update(ctx context.Context, actor *rbac.Principal, targetID int64, input Input) (*User, error) {
	existing, err := s.GetForActor(ctx, actor, targetID)
	if err != nil {
		return nil, err
	}
	if existing.IsSystem && !actor.IsSuperAdmin() {
		return nil, ErrPrivilegeEscalation
	}

	status := strings.TrimSpace(input.Status)
	if status == "" {
		status = existing.Status
	}
	if !slices.Contains(ValidStatuses, status) {
		return nil, ErrInvalidStatus
	}
	if existing.IsSystem && status != "active" {
		return nil, ErrSystemProtected
	}

	if input.Password != "" && len(input.Password) < 8 {
		return nil, ErrPasswordMinLen
	}

	if err := s.enforceRoleAssignmentAllowed(ctx, actor, input.RoleIDs, existing.RoleIDs); err != nil {
		return nil, err
	}
	if !equalInt64Ptr(existing.DepartmentID, input.DepartmentID) {
		if err := s.enforceDepartmentWriteScope(ctx, actor, input.DepartmentID); err != nil {
			return nil, err
		}
	}

	passwordChanged := input.Password != ""
	var newPasswordHash string
	if passwordChanged {
		newPasswordHash, err = auth.HashPassword(input.Password)
		if err != nil {
			return nil, err
		}
	}

	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var deptVal sql.NullInt64
	if input.DepartmentID != nil && *input.DepartmentID > 0 {
		deptVal = sql.NullInt64{Int64: *input.DepartmentID, Valid: true}
	}

	now := time.Now().Unix()
	if passwordChanged {
		_, err = tx.ExecContext(
			ctx,
			`UPDATE users SET password_hash = ?, name = ?, employee_no = ?, title = ?, status = ?, department_id = ?, updated_at = ? WHERE id = ?`,
			newPasswordHash,
			strings.TrimSpace(input.Name),
			strings.TrimSpace(input.EmployeeNo),
			strings.TrimSpace(input.Title),
			status,
			deptVal,
			now,
			targetID,
		)
	} else {
		_, err = tx.ExecContext(
			ctx,
			`UPDATE users SET name = ?, employee_no = ?, title = ?, status = ?, department_id = ?, updated_at = ? WHERE id = ?`,
			strings.TrimSpace(input.Name),
			strings.TrimSpace(input.EmployeeNo),
			strings.TrimSpace(input.Title),
			status,
			deptVal,
			now,
			targetID,
		)
	}
	if err != nil {
		return nil, err
	}

	if err := replaceUserRoles(ctx, tx, targetID, input.RoleIDs); err != nil {
		return nil, err
	}

	if passwordChanged || status != "active" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, targetID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getByID(ctx, targetID)
}

// Delete removes a user account within Data Scope while protecting system and current users.
func (s *Service) Delete(ctx context.Context, actor *rbac.Principal, targetID int64) error {
	existing, err := s.GetForActor(ctx, actor, targetID)
	if err != nil {
		return err
	}
	if existing.IsSystem || existing.Account == db.DefaultAdminAccount {
		return ErrSystemProtected
	}
	if actor != nil && actor.ID == targetID {
		return ErrSelfDelete
	}

	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, targetID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) enforceRoleAssignmentAllowed(
	ctx context.Context,
	actor *rbac.Principal,
	newRoleIDs []int64,
	existingRoleIDs []int64,
) error {
	if actor != nil && actor.IsSuperAdmin() {
		return nil
	}
	var superAdminID int64
	err := s.readDB.QueryRowContext(
		ctx,
		`SELECT id FROM roles WHERE code = ?`,
		rbac.RoleSuperAdmin,
	).Scan(&superAdminID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	hadSuper := slices.Contains(existingRoleIDs, superAdminID)
	wantsSuper := slices.Contains(newRoleIDs, superAdminID)
	if hadSuper != wantsSuper || wantsSuper {
		return ErrPrivilegeEscalation
	}
	return nil
}

func (s *Service) enforceDepartmentWriteScope(
	ctx context.Context,
	actor *rbac.Principal,
	targetDeptID *int64,
) error {
	if actor == nil {
		return ErrPrivilegeEscalation
	}
	if actor.IsSuperAdmin() || slices.Contains(actor.DataScopes, rbac.ScopeAll) {
		return nil
	}
	if targetDeptID == nil || *targetDeptID <= 0 {
		// Non-ALL actors assigning no department would fall outside dept scopes except SELF.
		if slices.Contains(actor.DataScopes, rbac.ScopeSelf) {
			return nil
		}
		return ErrPrivilegeEscalation
	}

	for _, scope := range actor.DataScopes {
		switch scope {
		case rbac.ScopeDept:
			if actor.DepartmentID != nil && *actor.DepartmentID == *targetDeptID {
				return nil
			}
		case rbac.ScopeDeptAndChild:
			if actor.DepartmentID != nil {
				var actorPath, targetPath string
				if err := s.readDB.QueryRowContext(ctx, `SELECT path FROM departments WHERE id = ?`, *actor.DepartmentID).Scan(&actorPath); err == nil {
					if err := s.readDB.QueryRowContext(ctx, `SELECT path FROM departments WHERE id = ?`, *targetDeptID).Scan(&targetPath); err == nil {
						if actorPath != "" && strings.HasPrefix(targetPath, actorPath) {
							return nil
						}
					}
				}
			}
		case rbac.ScopeCustom:
			var count int
			if err := s.readDB.QueryRowContext(
				ctx,
				`SELECT COUNT(*)
				 FROM role_departments rd
				 INNER JOIN user_roles ur ON ur.role_id = rd.role_id
				 WHERE ur.user_id = ? AND rd.department_id = ?`,
				actor.ID, *targetDeptID,
			).Scan(&count); err == nil && count > 0 {
				return nil
			}
		}
	}
	return ErrPrivilegeEscalation
}

func replaceUserRoles(ctx context.Context, tx *sql.Tx, userID int64, roleIDs []int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, userID); err != nil {
		return err
	}
	seen := make(map[int64]struct{}, len(roleIDs))
	for _, rid := range roleIDs {
		if rid <= 0 {
			continue
		}
		if _, ok := seen[rid]; ok {
			continue
		}
		seen[rid] = struct{}{}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO user_roles (user_id, role_id, scope_type, scope_id) VALUES (?, ?, 'global', '')`,
			userID, rid,
		); err != nil {
			return err
		}
	}
	return nil
}

func equalInt64Ptr(a, b *int64) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

type userRowScanner interface {
	Scan(dest ...any) error
}

func scanUser(r userRowScanner) (User, error) {
	var u User
	var deptID, reportsToID sql.NullInt64
	var isSys int
	if err := r.Scan(
		&u.ID, &u.UID, &u.Account, &u.Name, &u.EmployeeNo, &u.Title,
		&u.Status, &deptID, &reportsToID, &isSys, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return User{}, err
	}
	if deptID.Valid {
		v := deptID.Int64
		u.DepartmentID = &v
	}
	if reportsToID.Valid {
		v := reportsToID.Int64
		u.ReportsToID = &v
	}
	u.IsSystem = isSys == 1
	return u, nil
}
