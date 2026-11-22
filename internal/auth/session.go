package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

const SessionCookieName = "erp_rbac_session"

// Session represents an authenticated user session persisted in SQLite.
type Session struct {
	TokenHash    string
	UserID       int64
	ExpiresAt    int64
	CreatedAt    int64
	LastSeenAt   int64
	IPAddress    string
	UserAgent    string
	FlashKind    string
	FlashMessage string
}

// Manager manages database-backed sessions and one-time PRG flash messages.
type Manager struct {
	writeDB        *sql.DB
	readDB         *sql.DB
	ttl            time.Duration
	insecureCookie bool
}

// NewManager creates a session manager backed by SQLite read and write pools.
func NewManager(writeDB, readDB *sql.DB, ttl time.Duration, insecureCookie bool) *Manager {
	return &Manager{
		writeDB:        writeDB,
		readDB:         readDB,
		ttl:            ttl,
		insecureCookie: insecureCookie,
	}
}

// HashToken returns the lowercase SHA-256 hex digest of a raw session cookie token.
func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Create inserts a new hashed session row and writes the HttpOnly session cookie.
func (m *Manager) Create(ctx context.Context, w http.ResponseWriter, userID int64, ip, userAgent string) (string, error) {
	rawToken, err := generateToken()
	if err != nil {
		return "", err
	}
	tokenHash := HashToken(rawToken)
	now := time.Now().Unix()
	expiresAt := time.Now().Add(m.ttl).Unix()

	_, err = m.writeDB.ExecContext(
		ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at, created_at, last_seen_at, ip_address, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tokenHash, userID, expiresAt, now, now, ip, truncateString(userAgent, 255),
	)
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    rawToken,
		Path:     "/",
		MaxAge:   int(m.ttl.Seconds()),
		HttpOnly: true,
		Secure:   !m.insecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	return tokenHash, nil
}

// Load resolves the current valid, non-expired session from the request cookie.
func (m *Manager) Load(ctx context.Context, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, nil
	}
	tokenHash := HashToken(cookie.Value)
	now := time.Now().Unix()

	var s Session
	err = m.readDB.QueryRowContext(
		ctx,
		`SELECT token_hash, user_id, expires_at, created_at, last_seen_at, ip_address, user_agent, flash_kind, flash_message
		 FROM sessions
		 WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, now,
	).Scan(
		&s.TokenHash,
		&s.UserID,
		&s.ExpiresAt,
		&s.CreatedAt,
		&s.LastSeenAt,
		&s.IPAddress,
		&s.UserAgent,
		&s.FlashKind,
		&s.FlashMessage,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Sliding activity timestamp update throttled to once per 60 seconds to minimize SQLite writes.
	if now-s.LastSeenAt >= 60 {
		_, _ = m.writeDB.ExecContext(
			ctx,
			`UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`,
			now, tokenHash,
		)
	}
	return &s, nil
}

// Delete removes the current session from SQLite and expires the browser cookie.
func (m *Manager) Delete(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		tokenHash := HashToken(cookie.Value)
		if _, delErr := m.writeDB.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); delErr != nil {
			return delErr
		}
	}
	m.ClearCookie(w)
	return nil
}

// ClearCookie removes the session cookie from the client.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !m.insecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// RevokeUserSessions invalidates all active sessions belonging to the specified user.
func (m *Manager) RevokeUserSessions(ctx context.Context, userID int64) error {
	_, err := m.writeDB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// SetFlash attaches a one-time alert message to the session for the next GET render.
func (m *Manager) SetFlash(ctx context.Context, tokenHash, kind, message string) error {
	if tokenHash == "" {
		return nil
	}
	_, err := m.writeDB.ExecContext(
		ctx,
		`UPDATE sessions SET flash_kind = ?, flash_message = ? WHERE token_hash = ?`,
		kind, message, tokenHash,
	)
	return err
}

// PopFlash reads and clears the one-time flash message on the session.
func (m *Manager) PopFlash(ctx context.Context, tokenHash string) (string, string, error) {
	if tokenHash == "" {
		return "", "", nil
	}
	tx, err := m.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback() }()

	var kind, msg string
	err = tx.QueryRowContext(
		ctx,
		`SELECT flash_kind, flash_message FROM sessions WHERE token_hash = ?`,
		tokenHash,
	).Scan(&kind, &msg)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	if kind != "" || msg != "" {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE sessions SET flash_kind = '', flash_message = '' WHERE token_hash = ?`,
			tokenHash,
		); err != nil {
			return "", "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return kind, msg, nil
}

// PurgeExpired removes all expired session rows from the database.
func (m *Manager) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := m.writeDB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// StartGC runs periodic cleanup of expired sessions until ctx is canceled.
func (m *Manager) StartGC(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = m.PurgeExpired(ctx)
		}
	}
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
