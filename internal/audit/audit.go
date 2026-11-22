package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// Event describes a security or administrative action recorded to audit.sqlite.
type Event struct {
	OccurredAt   int64
	ActorUserID  *int64
	ActorAccount string
	Action       string
	ResourceType string
	ResourceID   string
	Outcome      string
	IPAddress    string
	UserAgent    string
	Detail       map[string]any
}

// Record represents a stored audit log row.
type Record struct {
	ID           int64
	OccurredAt   int64
	ActorUserID  *int64
	ActorAccount string
	Action       string
	ResourceType string
	ResourceID   string
	Outcome      string
	IPAddress    string
	UserAgent    string
	DetailJSON   string
}

// Filter defines read-only query filters and pagination for audit logs.
type Filter struct {
	Account  string
	Action   string
	Outcome  string
	Page     int
	PageSize int
}

// PageResult returns paginated audit log records.
type PageResult struct {
	Items      []Record
	Total      int
	Page       int
	PageSize   int
	TotalPages int
}

// Logger provides append-only audit persistence and read-only queries against audit.sqlite.
type Logger struct {
	db *sql.DB
}

// NewLogger constructs an audit Logger backed by the dedicated audit SQLite database.
func NewLogger(db *sql.DB) *Logger {
	return &Logger{db: db}
}

// Record appends a single immutable audit event to audit_logs.
func (l *Logger) Record(ctx context.Context, ev Event) error {
	occurredAt := ev.OccurredAt
	if occurredAt == 0 {
		occurredAt = time.Now().Unix()
	}
	outcome := ev.Outcome
	if outcome != OutcomeSuccess && outcome != OutcomeFailure && outcome != OutcomeDenied {
		outcome = OutcomeFailure
	}
	detailJSON := "{}"
	if len(ev.Detail) > 0 {
		b, err := json.Marshal(ev.Detail)
		if err != nil {
			return fmt.Errorf("marshal audit detail: %w", err)
		}
		detailJSON = string(b)
	}

	var actorID sql.NullInt64
	if ev.ActorUserID != nil {
		actorID = sql.NullInt64{Int64: *ev.ActorUserID, Valid: true}
	}

	ua := ev.UserAgent
	if len(ua) > 255 {
		ua = ua[:255]
	}

	_, err := l.db.ExecContext(
		ctx,
		`INSERT INTO audit_logs (
			occurred_at, actor_user_id, actor_account, action, resource_type, resource_id,
			outcome, ip_address, user_agent, detail_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		occurredAt,
		actorID,
		ev.ActorAccount,
		ev.Action,
		ev.ResourceType,
		ev.ResourceID,
		outcome,
		ev.IPAddress,
		ua,
		detailJSON,
	)
	return err
}

// List queries audit_logs with optional account, action, and outcome filters.
func (l *Logger) List(ctx context.Context, f Filter) (PageResult, error) {
	page := f.Page
	if page < 1 {
		page = 1
	}
	pageSize := f.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 25
	}

	var clauses []string
	var args []any

	if acc := strings.TrimSpace(f.Account); acc != "" {
		clauses = append(clauses, "actor_account LIKE ?")
		args = append(args, "%"+acc+"%")
	}
	if act := strings.TrimSpace(f.Action); act != "" {
		clauses = append(clauses, "action LIKE ?")
		args = append(args, "%"+act+"%")
	}
	if out := strings.TrimSpace(f.Outcome); out != "" {
		clauses = append(clauses, "outcome = ?")
		args = append(args, out)
	}

	whereSQL := ""
	if len(clauses) > 0 {
		whereSQL = " WHERE " + strings.Join(clauses, " AND ")
	}

	var total int
	countSQL := "SELECT COUNT(*) FROM audit_logs" + whereSQL
	if err := l.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return PageResult{}, err
	}

	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	if page > totalPages {
		page = totalPages
	}
	offset := (page - 1) * pageSize

	queryArgs := append(append([]any{}, args...), pageSize, offset)
	querySQL := `SELECT id, occurred_at, actor_user_id, actor_account, action, resource_type, resource_id, outcome, ip_address, user_agent, detail_json
		FROM audit_logs` + whereSQL + ` ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?`

	rows, err := l.db.QueryContext(ctx, querySQL, queryArgs...)
	if err != nil {
		return PageResult{}, err
	}
	defer func() { _ = rows.Close() }()

	items := make([]Record, 0)
	for rows.Next() {
		var r Record
		var actorID sql.NullInt64
		if err := rows.Scan(
			&r.ID,
			&r.OccurredAt,
			&actorID,
			&r.ActorAccount,
			&r.Action,
			&r.ResourceType,
			&r.ResourceID,
			&r.Outcome,
			&r.IPAddress,
			&r.UserAgent,
			&r.DetailJSON,
		); err != nil {
			return PageResult{}, err
		}
		if actorID.Valid {
			v := actorID.Int64
			r.ActorUserID = &v
		}
		items = append(items, r)
	}
	if err := rows.Err(); err != nil {
		return PageResult{}, err
	}

	return PageResult{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}
