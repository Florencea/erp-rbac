package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	ScopeAll          = "ALL"
	ScopeDeptAndChild = "DEPT_AND_CHILD"
	ScopeDept         = "DEPT"
	ScopeSelf         = "SELF"
	ScopeCustom       = "CUSTOM"
)

// BuildUserScopeSQL constructs a parameterized SQL predicate enforcing data scope rules.
// When empty clause is returned, no row-level filter applies (e.g. ALL scope).
func BuildUserScopeSQL(
	ctx context.Context,
	readDB *sql.DB,
	p *Principal,
	userCol string,
	deptCol string,
) (string, []any, error) {
	if p == nil {
		return "1 = 0", nil, nil
	}
	if p.IsSuperAdmin() || slices.Contains(p.DataScopes, ScopeAll) {
		return "", nil, nil
	}

	var orParts []string
	var args []any

	for _, scope := range p.DataScopes {
		switch scope {
		case ScopeSelf:
			orParts = append(orParts, userCol+" = ?")
			args = append(args, p.ID)

		case ScopeDept:
			if deptCol != "" && p.DepartmentID != nil {
				orParts = append(orParts, deptCol+" = ?")
				args = append(args, *p.DepartmentID)
			} else {
				orParts = append(orParts, userCol+" = ?")
				args = append(args, p.ID)
			}

		case ScopeDeptAndChild:
			if deptCol != "" && p.DepartmentID != nil {
				var currentPath string
				err := readDB.QueryRowContext(
					ctx,
					`SELECT path FROM departments WHERE id = ?`,
					*p.DepartmentID,
				).Scan(&currentPath)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return "", nil, err
				}
				if currentPath != "" {
					deptRows, err := readDB.QueryContext(
						ctx,
						`SELECT id FROM departments WHERE path LIKE ?`,
						currentPath+"%",
					)
					if err != nil {
						return "", nil, err
					}
					var deptIDs []int64
					for deptRows.Next() {
						var did int64
						if scanErr := deptRows.Scan(&did); scanErr != nil {
							_ = deptRows.Close()
							return "", nil, scanErr
						}
						deptIDs = append(deptIDs, did)
					}
					closeErr := deptRows.Close()
					if err := deptRows.Err(); err != nil {
						return "", nil, err
					}
					if closeErr != nil {
						return "", nil, closeErr
					}
					if len(deptIDs) > 0 {
						ph := strings.TrimSuffix(strings.Repeat("?,", len(deptIDs)), ",")
						orParts = append(orParts, fmt.Sprintf("%s IN (%s)", deptCol, ph))
						for _, did := range deptIDs {
							args = append(args, did)
						}
					}
				}
			} else {
				orParts = append(orParts, userCol+" = ?")
				args = append(args, p.ID)
			}

		case ScopeCustom:
			if deptCol != "" {
				rows, err := readDB.QueryContext(
					ctx,
					`SELECT DISTINCT rd.department_id
					 FROM role_departments rd
					 INNER JOIN user_roles ur ON ur.role_id = rd.role_id
					 WHERE ur.user_id = ?`,
					p.ID,
				)
				if err != nil {
					return "", nil, err
				}
				var deptIDs []int64
				for rows.Next() {
					var did int64
					if scanErr := rows.Scan(&did); scanErr != nil {
						_ = rows.Close()
						return "", nil, scanErr
					}
					deptIDs = append(deptIDs, did)
				}
				closeErr := rows.Close()
				if err := rows.Err(); err != nil {
					return "", nil, err
				}
				if closeErr != nil {
					return "", nil, closeErr
				}
				if len(deptIDs) > 0 {
					ph := strings.TrimSuffix(strings.Repeat("?,", len(deptIDs)), ",")
					orParts = append(orParts, fmt.Sprintf("%s IN (%s)", deptCol, ph))
					for _, did := range deptIDs {
						args = append(args, did)
					}
				}
			}
		}
	}

	if len(orParts) == 0 {
		// Fail closed to self-only access when no effective scope resolved.
		return userCol + " = ?", []any{p.ID}, nil
	}
	if len(orParts) == 1 {
		return orParts[0], args, nil
	}
	return "(" + strings.Join(orParts, " OR ") + ")", args, nil
}

// CanAccessUser checks whether a target user falls inside the actor's Data Scope.
func CanAccessUser(ctx context.Context, readDB *sql.DB, actor *Principal, targetUserID int64) (bool, error) {
	if actor == nil {
		return false, nil
	}
	if actor.IsSuperAdmin() || slices.Contains(actor.DataScopes, ScopeAll) {
		return true, nil
	}
	clause, args, err := BuildUserScopeSQL(ctx, readDB, actor, "id", "department_id")
	if err != nil {
		return false, err
	}
	query := "SELECT 1 FROM users WHERE id = ?"
	queryArgs := []any{targetUserID}
	if clause != "" {
		query += " AND (" + clause + ")"
		queryArgs = append(queryArgs, args...)
	}
	query += " LIMIT 1"

	var exists int
	err = readDB.QueryRowContext(ctx, query, queryArgs...).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}
