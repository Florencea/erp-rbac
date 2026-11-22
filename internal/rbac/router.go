package rbac

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"

	"github.com/Florencea/erp-rbac/internal/audit"
	"github.com/Florencea/erp-rbac/internal/auth"
)

// AccessLevel enumerates mandatory access declarations for every HTTP route.
type AccessLevel int

const (
	AccessPublic AccessLevel = iota + 1
	AccessAuthenticated
	AccessPermission
)

// RouteRecord captures registered route metadata for Canary security audits.
type RouteRecord struct {
	Pattern    string
	Level      AccessLevel
	Permission string
}

type contextKey int

const (
	ctxKeyPrincipal contextKey = iota + 1
	ctxKeySession
)

// PrincipalFromContext retrieves the authenticated Principal attached by Router.
func PrincipalFromContext(ctx context.Context) *Principal {
	v, _ := ctx.Value(ctxKeyPrincipal).(*Principal)
	return v
}

// SessionFromContext retrieves the active Session attached by Router.
func SessionFromContext(ctx context.Context) *auth.Session {
	v, _ := ctx.Value(ctxKeySession).(*auth.Session)
	return v
}

// ForbiddenFunc renders an HTTP 403 response for authenticated users lacking permissions.
type ForbiddenFunc func(w http.ResponseWriter, r *http.Request, p *Principal)

// CSRFDenyFunc renders an HTTP 403 response when CrossOriginProtection blocks a request.
type CSRFDenyFunc func(w http.ResponseWriter, r *http.Request)

// Router is a fail-closed HTTP router wrapper. It conceals http.ServeMux so every route
// must explicitly declare Public, Authenticated, or RequirePerm access control.
type Router struct {
	mux         *http.ServeMux
	readDB      *sql.DB
	sessions    *auth.Manager
	audit       *audit.Logger
	onForbidden ForbiddenFunc
	onCSRFDeny  CSRFDenyFunc
	routes      []RouteRecord
}

// NewRouter initializes a fail-closed RBAC router.
func NewRouter(
	readDB *sql.DB,
	sessions *auth.Manager,
	auditLogger *audit.Logger,
	onForbidden ForbiddenFunc,
	onCSRFDeny CSRFDenyFunc,
) *Router {
	return &Router{
		mux:         http.NewServeMux(),
		readDB:      readDB,
		sessions:    sessions,
		audit:       auditLogger,
		onForbidden: onForbidden,
		onCSRFDeny:  onCSRFDeny,
	}
}

// Public registers an explicitly public route that does not require authentication.
func (rt *Router) Public(pattern string, h http.HandlerFunc) {
	rt.routes = append(rt.routes, RouteRecord{
		Pattern: pattern,
		Level:   AccessPublic,
	})
	rt.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		r = rt.attachOptionalAuth(r)
		h(w, r)
	})
}

// Authenticated registers a route requiring an active session for an active user.
func (rt *Router) Authenticated(pattern string, h http.HandlerFunc) {
	rt.routes = append(rt.routes, RouteRecord{
		Pattern: pattern,
		Level:   AccessAuthenticated,
	})
	rt.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		r, _, ok := rt.requireAuthWithRequest(w, r)
		if !ok {
			return
		}
		h(w, r)
	})
}

// RequirePerm registers a route enforcing an explicit RBAC permission code.
func (rt *Router) RequirePerm(pattern, permCode string, h http.HandlerFunc) {
	if permCode == "" {
		panic("rbac: RequirePerm called with empty permission code for " + pattern)
	}
	rt.routes = append(rt.routes, RouteRecord{
		Pattern:    pattern,
		Level:      AccessPermission,
		Permission: permCode,
	})
	rt.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		r, p, ok := rt.requireAuthWithRequest(w, r)
		if !ok {
			return
		}
		if !p.HasPerm(permCode) {
			if rt.audit != nil {
				uid := p.ID
				_ = rt.audit.Record(r.Context(), audit.Event{
					ActorUserID:  &uid,
					ActorAccount: p.Account,
					Action:       "rbac.forbidden",
					ResourceType: "route",
					ResourceID:   r.URL.Path,
					Outcome:      audit.OutcomeDenied,
					IPAddress:    ClientIP(r),
					UserAgent:    r.UserAgent(),
					Detail: map[string]any{
						"method":              r.Method,
						"required_permission": permCode,
					},
				})
			}
			if rt.onForbidden != nil {
				rt.onForbidden(w, r, p)
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

// Routes returns a copy of all registered route access declarations.
func (rt *Router) Routes() []RouteRecord {
	out := make([]RouteRecord, len(rt.routes))
	copy(out, rt.routes)
	return out
}

// Handler wraps the internal ServeMux with panic recovery, security headers, and CSRF defense.
func (rt *Router) Handler() http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt.audit != nil {
			_ = rt.audit.Record(r.Context(), audit.Event{
				Action:       "security.csrf_rejected",
				ResourceType: "route",
				ResourceID:   r.URL.Path,
				Outcome:      audit.OutcomeDenied,
				IPAddress:    ClientIP(r),
				UserAgent:    r.UserAgent(),
				Detail: map[string]any{
					"method":         r.Method,
					"origin":         r.Header.Get("Origin"),
					"sec_fetch_site": r.Header.Get("Sec-Fetch-Site"),
				},
			})
		}
		if rt.onCSRFDeny != nil {
			rt.onCSRFDeny(w, r)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	}))

	return RecoverAndLogMiddleware(SecurityHeadersMiddleware(cop.Handler(rt.mux)))
}

func (rt *Router) attachOptionalAuth(r *http.Request) *http.Request {
	sess, err := rt.sessions.Load(r.Context(), r)
	if err != nil || sess == nil {
		return r
	}
	p, err := LoadPrincipal(r.Context(), rt.readDB, sess.UserID)
	if err != nil || p == nil {
		return r
	}
	ctx := context.WithValue(r.Context(), ctxKeySession, sess)
	ctx = context.WithValue(ctx, ctxKeyPrincipal, p)
	return r.WithContext(ctx)
}

func (rt *Router) requireAuth(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	_, p, ok := rt.requireAuthWithRequest(w, r)
	return p, ok
}

func (rt *Router) attachPrincipal(r *http.Request) *http.Request {
	// Ensure context already populated when called via requireAuthWithRequest; kept for clarity.
	return rt.attachOptionalAuth(r)
}

func (rt *Router) requireAuthWithRequest(w http.ResponseWriter, r *http.Request) (*http.Request, *Principal, bool) {
	sess, err := rt.sessions.Load(r.Context(), r)
	if err != nil || sess == nil {
		rt.redirectToLogin(w, r)
		return r, nil, false
	}
	p, err := LoadPrincipal(r.Context(), rt.readDB, sess.UserID)
	if err != nil || p == nil {
		// User missing or disabled: delete stale cookie & session immediately.
		_ = rt.sessions.Delete(r.Context(), w, r)
		rt.redirectToLogin(w, r)
		return r, nil, false
	}
	ctx := context.WithValue(r.Context(), ctxKeySession, sess)
	ctx = context.WithValue(ctx, ctxKeyPrincipal, p)
	return r.WithContext(ctx), p, true
}

func (rt *Router) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if r.Method == http.MethodGet && r.URL.Path != "/" && r.URL.Path != "/login" {
		next := r.URL.RequestURI()
		target = "/login?next=" + url.QueryEscape(next)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
