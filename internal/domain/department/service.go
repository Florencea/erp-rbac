package department

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotFound      = errors.New("department not found")
	ErrParentInvalid = errors.New("invalid parent department")
	ErrHasChildren   = errors.New("department has child departments")
	ErrHasUsers      = errors.New("department has assigned users")
	ErrNameRequired  = errors.New("department name is required")
)

// Department represents an organizational unit in the tree.
type Department struct {
	ID        int64
	ParentID  *int64
	Name      string
	Path      string
	Sort      int
	LeaderID  *int64
	CreatedAt int64
	UpdatedAt int64
}

// TreeRow augments Department with pre-order depth and discrete Bootstrap spacing classes.
type TreeRow struct {
	Department
	Depth        int
	PaddingClass string
	TreePrefix   string
}

// Input defines fields for creating or updating a department.
type Input struct {
	Name     string
	ParentID *int64
	Sort     int
}

// Service manages department persistence and materialized path invariants.
type Service struct {
	writeDB *sql.DB
	readDB  *sql.DB
}

// NewService creates a department domain service.
func NewService(writeDB, readDB *sql.DB) *Service {
	return &Service{writeDB: writeDB, readDB: readDB}
}

// List returns all departments ordered by sort and ID.
func (s *Service) List(ctx context.Context) ([]Department, error) {
	rows, err := s.readDB.QueryContext(
		ctx,
		`SELECT id, parent_id, name, path, sort, leader_id, created_at, updated_at
		 FROM departments
		 ORDER BY sort ASC, id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	items := make([]Department, 0)
	for rows.Next() {
		d, scanErr := scanDepartment(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, d)
	}
	return items, rows.Err()
}

// ListTree returns departments ordered as a pre-order depth-first tree using Bootstrap padding classes.
func (s *Service) ListTree(ctx context.Context) ([]TreeRow, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]Department, len(all))
	children := make(map[int64][]Department)
	var roots []Department

	for _, d := range all {
		byID[d.ID] = d
	}
	for _, d := range all {
		if d.ParentID == nil {
			roots = append(roots, d)
			continue
		}
		if _, ok := byID[*d.ParentID]; !ok {
			roots = append(roots, d)
			continue
		}
		children[*d.ParentID] = append(children[*d.ParentID], d)
	}

	out := make([]TreeRow, 0, len(all))
	var walk func(items []Department, depth int)
	walk = func(items []Department, depth int) {
		for _, d := range items {
			prefix := ""
			if depth > 0 {
				prefix = strings.Repeat("│ ", depth-1) + "└─ "
			}
			out = append(out, TreeRow{
				Department:   d,
				Depth:        depth,
				PaddingClass: depthToPaddingClass(depth),
				TreePrefix:   prefix,
			})
			if kids := children[d.ID]; len(kids) > 0 {
				walk(kids, depth+1)
			}
		}
	}
	walk(roots, 0)
	return out, nil
}

func depthToPaddingClass(depth int) string {
	switch depth {
	case 0:
		return "ps-0"
	case 1:
		return "ps-2"
	case 2:
		return "ps-3"
	case 3:
		return "ps-4"
	default:
		return "ps-5"
	}
}

// GetByID retrieves a single department by ID.
func (s *Service) GetByID(ctx context.Context, id int64) (*Department, error) {
	row := s.readDB.QueryRowContext(
		ctx,
		`SELECT id, parent_id, name, path, sort, leader_id, created_at, updated_at
		 FROM departments WHERE id = ?`,
		id,
	)
	d, err := scanDepartment(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// Create inserts a new department and computes its materialized path atomically.
func (s *Service) Create(ctx context.Context, input Input) (*Department, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, ErrNameRequired
	}

	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	parentPath := ""
	var parentVal sql.NullInt64
	if input.ParentID != nil && *input.ParentID > 0 {
		err := tx.QueryRowContext(ctx, `SELECT path FROM departments WHERE id = ?`, *input.ParentID).Scan(&parentPath)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrParentInvalid
		}
		if err != nil {
			return nil, err
		}
		parentVal = sql.NullInt64{Int64: *input.ParentID, Valid: true}
	}

	now := time.Now().Unix()
	res, err := tx.ExecContext(
		ctx,
		`INSERT INTO departments (parent_id, name, path, sort, created_at, updated_at)
		 VALUES (?, ?, '', ?, ?, ?)`,
		parentVal, name, input.Sort, now, now,
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	finalPath := fmt.Sprintf("/%d/", id)
	if parentPath != "" {
		finalPath = fmt.Sprintf("%s%d/", parentPath, id)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE departments SET path = ? WHERE id = ?`, finalPath, id); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, id)
}

// Update modifies department attributes, checks for cycles, and cascades materialized path updates.
func (s *Service) Update(ctx context.Context, id int64, input Input) (*Department, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, ErrNameRequired
	}

	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := scanDepartment(tx.QueryRowContext(
		ctx,
		`SELECT id, parent_id, name, path, sort, leader_id, created_at, updated_at
		 FROM departments WHERE id = ?`,
		id,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var newParentID *int64
	if input.ParentID != nil && *input.ParentID > 0 {
		v := *input.ParentID
		newParentID = &v
	}

	newPath := existing.Path
	if !equalInt64Ptr(existing.ParentID, newParentID) {
		parentPath := ""
		if newParentID != nil {
			if *newParentID == id {
				return nil, ErrParentInvalid
			}
			err := tx.QueryRowContext(ctx, `SELECT path FROM departments WHERE id = ?`, *newParentID).Scan(&parentPath)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrParentInvalid
			}
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(parentPath, existing.Path) {
				return nil, ErrParentInvalid
			}
		}

		newPath = fmt.Sprintf("/%d/", id)
		if parentPath != "" {
			newPath = fmt.Sprintf("%s%d/", parentPath, id)
		}

		// Cascade updated path prefix to all descendant departments inside the same transaction.
		descRows, err := tx.QueryContext(
			ctx,
			`SELECT id, path FROM departments WHERE path LIKE ? AND id != ?`,
			existing.Path+"%", id,
		)
		if err != nil {
			return nil, err
		}
		type descPath struct {
			ID   int64
			Path string
		}
		var updates []descPath
		for descRows.Next() {
			var dp descPath
			if scanErr := descRows.Scan(&dp.ID, &dp.Path); scanErr != nil {
				_ = descRows.Close()
				return nil, scanErr
			}
			dp.Path = newPath + strings.TrimPrefix(dp.Path, existing.Path)
			updates = append(updates, dp)
		}
		closeErr := descRows.Close()
		if err := descRows.Err(); err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		for _, upd := range updates {
			if _, err := tx.ExecContext(ctx, `UPDATE departments SET path = ? WHERE id = ?`, upd.Path, upd.ID); err != nil {
				return nil, err
			}
		}
	}

	var parentVal sql.NullInt64
	if newParentID != nil {
		parentVal = sql.NullInt64{Int64: *newParentID, Valid: true}
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE departments SET name = ?, parent_id = ?, path = ?, sort = ?, updated_at = ? WHERE id = ?`,
		name, parentVal, newPath, input.Sort, time.Now().Unix(), id,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, id)
}

// Delete removes a department only when it has no child departments and no assigned users.
func (s *Service) Delete(ctx context.Context, id int64) error {
	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM departments WHERE id = ?`, id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	var childCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM departments WHERE parent_id = ?`, id).Scan(&childCount); err != nil {
		return err
	}
	if childCount > 0 {
		return ErrHasChildren
	}

	var userCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE department_id = ?`, id).Scan(&userCount); err != nil {
		return err
	}
	if userCount > 0 {
		return ErrHasUsers
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM departments WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDepartment(r rowScanner) (Department, error) {
	var d Department
	var parentID, leaderID sql.NullInt64
	if err := r.Scan(&d.ID, &parentID, &d.Name, &d.Path, &d.Sort, &leaderID, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return Department{}, err
	}
	if parentID.Valid {
		v := parentID.Int64
		d.ParentID = &v
	}
	if leaderID.Valid {
		v := leaderID.Int64
		d.LeaderID = &v
	}
	return d, nil
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
