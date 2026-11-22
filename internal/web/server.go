package web

import (
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Florencea/erp-rbac/internal/audit"
	"github.com/Florencea/erp-rbac/internal/auth"
	"github.com/Florencea/erp-rbac/internal/config"
	"github.com/Florencea/erp-rbac/internal/db"
	"github.com/Florencea/erp-rbac/internal/domain/department"
	"github.com/Florencea/erp-rbac/internal/domain/role"
	"github.com/Florencea/erp-rbac/internal/domain/user"
	"github.com/Florencea/erp-rbac/internal/i18n"
	"github.com/Florencea/erp-rbac/internal/rbac"
)

const maxFormBodyBytes = 1 << 20 // 1 MiB

// Server wires domain services, templates, sessions, audit logger, and fail-closed RBAC routes.
type Server struct {
	cfg       config.Config
	store     *db.Store
	sessions  *auth.Manager
	audit     *audit.Logger
	depts     *department.Service
	roles     *role.Service
	users     *user.Service
	templates *TemplateSet
	router    *rbac.Router
}

// NewServer initializes all web handlers and registers them on the fail-closed RBAC router.
func NewServer(cfg config.Config, store *db.Store) (*Server, error) {
	ts, err := NewTemplateSet()
	if err != nil {
		return nil, err
	}
	staticFS, err := StaticFS()
	if err != nil {
		return nil, err
	}

	sessions := auth.NewManager(store.AppWrite, store.AppRead, cfg.SessionTTL, cfg.InsecureCookie)
	auditLogger := audit.NewLogger(store.Audit)

	s := &Server{
		cfg:       cfg,
		store:     store,
		sessions:  sessions,
		audit:     auditLogger,
		depts:     department.NewService(store.AppWrite, store.AppRead),
		roles:     role.NewService(store.AppWrite, store.AppRead),
		users:     user.NewService(store.AppWrite, store.AppRead, sessions),
		templates: ts,
	}

	s.router = rbac.NewRouter(
		store.AppRead,
		sessions,
		auditLogger,
		s.renderForbidden,
		s.renderCSRFDeny,
	)
	s.registerRoutes(staticFS)
	return s, nil
}

// Handler returns the complete HTTP handler chain with security headers and CSRF protection.
func (s *Server) Handler() http.Handler {
	return s.router.Handler()
}

// Router exposes the fail-closed router metadata for Canary contract tests.
func (s *Server) Router() *rbac.Router {
	return s.router
}

// Sessions exposes the session manager (e.g. for background GC).
func (s *Server) Sessions() *auth.Manager {
	return s.sessions
}

func (s *Server) registerRoutes(staticFS fs.FS) {
	fileServer := http.StripPrefix("/static/", http.FileServerFS(staticFS))

	s.router.Public("GET /healthz", s.handleHealthz)
	s.router.Public("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fileServer.ServeHTTP(w, r)
	})
	s.router.Public("GET /login", s.handleLoginGet)
	s.router.Public("POST /login", s.handleLoginPost)
	s.router.Public("POST /locale", s.handleLocalePost)

	s.router.Authenticated("GET /{$}", s.handleHome)
	s.router.Authenticated("POST /logout", s.handleLogoutPost)

	s.router.RequirePerm("GET /departments", "system:dept:read", s.handleDepartmentsList)
	s.router.RequirePerm("GET /departments/new", "system:dept:create", s.handleDepartmentNew)
	s.router.RequirePerm("POST /departments", "system:dept:create", s.handleDepartmentCreate)
	s.router.RequirePerm("GET /departments/{id}/edit", "system:dept:update", s.handleDepartmentEdit)
	s.router.RequirePerm("POST /departments/{id}", "system:dept:update", s.handleDepartmentUpdate)
	s.router.RequirePerm("GET /departments/{id}/delete", "system:dept:delete", s.handleDepartmentDeleteConfirm)
	s.router.RequirePerm("POST /departments/{id}/delete", "system:dept:delete", s.handleDepartmentDelete)

	s.router.RequirePerm("GET /roles", "system:role:read", s.handleRolesList)
	s.router.RequirePerm("GET /roles/new", "system:role:create", s.handleRoleNew)
	s.router.RequirePerm("POST /roles", "system:role:create", s.handleRoleCreate)
	s.router.RequirePerm("GET /roles/{id}/edit", "system:role:update", s.handleRoleEdit)
	s.router.RequirePerm("POST /roles/{id}", "system:role:update", s.handleRoleUpdate)
	s.router.RequirePerm("GET /roles/{id}/delete", "system:role:delete", s.handleRoleDeleteConfirm)
	s.router.RequirePerm("POST /roles/{id}/delete", "system:role:delete", s.handleRoleDelete)

	s.router.RequirePerm("GET /users", "system:user:read", s.handleUsersList)
	s.router.RequirePerm("GET /users/new", "system:user:create", s.handleUserNew)
	s.router.RequirePerm("POST /users", "system:user:create", s.handleUserCreate)
	s.router.RequirePerm("GET /users/{id}/edit", "system:user:update", s.handleUserEdit)
	s.router.RequirePerm("POST /users/{id}", "system:user:update", s.handleUserUpdate)
	s.router.RequirePerm("GET /users/{id}/delete", "system:user:delete", s.handleUserDeleteConfirm)
	s.router.RequirePerm("POST /users/{id}/delete", "system:user:delete", s.handleUserDelete)

	s.router.RequirePerm("GET /audit-logs", "system:audit:read", s.handleAuditLogsList)
}

func (s *Server) newBasePage(r *http.Request, pageTitle, activePath string) BasePage {
	locale := i18n.ResolveLocale(r, s.cfg.DefaultLocale)
	t := i18n.Catalog(locale)
	switchLocale := i18n.LocaleEnUS
	if locale == i18n.LocaleEnUS {
		switchLocale = i18n.LocaleZhTW
	}

	principal := rbac.PrincipalFromContext(r.Context())
	var nav []NavItem
	if principal != nil {
		nav = append(nav, NavItem{
			Href:   "/",
			Label:  t.Routes.Home,
			Active: activePath == "/",
		})
		if principal.HasPerm("system:user:read") {
			nav = append(nav, NavItem{
				Href:   "/users",
				Label:  t.Routes.Users,
				Active: strings.HasPrefix(activePath, "/users"),
			})
		}
		if principal.HasPerm("system:dept:read") {
			nav = append(nav, NavItem{
				Href:   "/departments",
				Label:  t.Routes.Departments,
				Active: strings.HasPrefix(activePath, "/departments"),
			})
		}
		if principal.HasPerm("system:role:read") {
			nav = append(nav, NavItem{
				Href:   "/roles",
				Label:  t.Routes.Roles,
				Active: strings.HasPrefix(activePath, "/roles"),
			})
		}
		if principal.HasPerm("system:audit:read") {
			nav = append(nav, NavItem{
				Href:   "/audit-logs",
				Label:  t.Routes.AuditLogs,
				Active: strings.HasPrefix(activePath, "/audit-logs"),
			})
		}
	}

	var flashKind, flashMsg string
	if sess := rbac.SessionFromContext(r.Context()); sess != nil && (sess.FlashKind != "" || sess.FlashMessage != "") {
		flashKind, flashMsg, _ = s.sessions.PopFlash(r.Context(), sess.TokenHash)
	}

	return BasePage{
		Lang:         locale,
		SwitchLocale: switchLocale,
		PageTitle:    pageTitle,
		ActivePath:   activePath,
		T:            t,
		Principal:    principal,
		NavItems:     nav,
		FlashKind:    flashKind,
		FlashMessage: flashMsg,
	}
}

func (s *Server) setFlash(r *http.Request, kind, message string) {
	if sess := rbac.SessionFromContext(r.Context()); sess != nil {
		_ = s.sessions.SetFlash(r.Context(), sess.TokenHash, kind, message)
	}
}

func (s *Server) recordAudit(
	r *http.Request,
	actor *rbac.Principal,
	action, resourceType, resourceID, outcome string,
	detail map[string]any,
) {
	var uid *int64
	account := ""
	if actor != nil {
		v := actor.ID
		uid = &v
		account = actor.Account
	}
	_ = s.audit.Record(r.Context(), audit.Event{
		ActorUserID:  uid,
		ActorAccount: account,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Outcome:      outcome,
		IPAddress:    rbac.ClientIP(r),
		UserAgent:    r.UserAgent(),
		Detail:       detail,
	})
}

func (s *Server) renderForbidden(w http.ResponseWriter, r *http.Request, _ *rbac.Principal) {
	t := i18n.Catalog(i18n.ResolveLocale(r, s.cfg.DefaultLocale))
	base := s.newBasePage(r, t.Routes.Forbidden, "/403")
	s.templates.RenderPage(w, http.StatusForbidden, "403.html", base)
}

func (s *Server) renderCSRFDeny(w http.ResponseWriter, r *http.Request) {
	t := i18n.Catalog(i18n.ResolveLocale(r, s.cfg.DefaultLocale))
	http.Error(w, t.Errors.CSRFRejected, http.StatusForbidden)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		http.Error(w, "database unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	t := i18n.Catalog(i18n.ResolveLocale(r, s.cfg.DefaultLocale))
	base := s.newBasePage(r, t.Routes.Home, "/")
	s.templates.RenderPage(w, http.StatusOK, "home.html", base)
}

func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	return r.ParseForm()
}

func parseIDParam(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func parseIDList(values []string) []int64 {
	out := make([]int64, 0, len(values))
	for _, raw := range values {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err == nil && id > 0 {
			out = append(out, id)
		}
	}
	return out
}

// SafeRedirectPath validates redirect targets against open redirects.
func SafeRedirectPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return u.RequestURI()
}
