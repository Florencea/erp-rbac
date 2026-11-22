package web

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Florencea/erp-rbac/internal/audit"
	"github.com/Florencea/erp-rbac/internal/auth"
	"github.com/Florencea/erp-rbac/internal/i18n"
	"github.com/Florencea/erp-rbac/internal/rbac"
)

type loginPageData struct {
	Lang         string
	SwitchLocale string
	T            i18n.Messages
	ErrorMessage string
	FieldErrors  map[string]string
	Account      string
	Next         string
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if rbac.PrincipalFromContext(r.Context()) != nil {
		http.Redirect(w, r, SafeRedirectPath(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	s.renderLoginPage(w, r, http.StatusOK, "", nil, "", SafeRedirectPath(r.URL.Query().Get("next")))
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	locale := i18n.ResolveLocale(r, s.cfg.DefaultLocale)
	t := i18n.Catalog(locale)

	if err := parseForm(w, r); err != nil {
		s.renderLoginPage(w, r, http.StatusBadRequest, t.Errors.InvalidRequest, nil, "", "/")
		return
	}

	account := strings.TrimSpace(r.FormValue("account"))
	password := r.FormValue("password")
	nextPath := SafeRedirectPath(r.FormValue("next"))

	fieldErrors := make(map[string]string)
	if account == "" {
		fieldErrors["account"] = t.Common.PleaseEnter + t.Auth.Account
	}
	if password == "" {
		fieldErrors["password"] = t.Common.PleaseEnter + t.Auth.Password
	}
	if len(fieldErrors) > 0 {
		s.renderLoginPage(w, r, http.StatusBadRequest, "", fieldErrors, account, nextPath)
		return
	}

	var userID int64
	var passwordHash, status string
	err := s.store.AppRead.QueryRowContext(
		r.Context(),
		`SELECT id, password_hash, status FROM users WHERE account = ?`,
		account,
	).Scan(&userID, &passwordHash, &status)

	if errors.Is(err, sql.ErrNoRows) || !auth.VerifyPassword(passwordHash, password) {
		_ = s.audit.Record(r.Context(), audit.Event{
			ActorAccount: account,
			Action:       "auth.login",
			ResourceType: "session",
			Outcome:      audit.OutcomeFailure,
			IPAddress:    rbac.ClientIP(r),
			UserAgent:    r.UserAgent(),
			Detail:       map[string]any{"reason": "invalid_credentials"},
		})
		s.renderLoginPage(w, r, http.StatusUnauthorized, t.Errors.InvalidCredentials, nil, account, nextPath)
		return
	}
	if err != nil {
		s.renderLoginPage(w, r, http.StatusInternalServerError, t.Errors.InternalServerError, nil, account, nextPath)
		return
	}

	if status != "active" {
		uid := userID
		_ = s.audit.Record(r.Context(), audit.Event{
			ActorUserID:  &uid,
			ActorAccount: account,
			Action:       "auth.login",
			ResourceType: "session",
			Outcome:      audit.OutcomeDenied,
			IPAddress:    rbac.ClientIP(r),
			UserAgent:    r.UserAgent(),
			Detail:       map[string]any{"reason": "account_disabled", "status": status},
		})
		s.renderLoginPage(w, r, http.StatusForbidden, t.Errors.AccountDisabled, nil, account, nextPath)
		return
	}

	if _, err := s.sessions.Create(r.Context(), w, userID, rbac.ClientIP(r), r.UserAgent()); err != nil {
		s.renderLoginPage(w, r, http.StatusInternalServerError, t.Errors.InternalServerError, nil, account, nextPath)
		return
	}

	uid := userID
	_ = s.audit.Record(r.Context(), audit.Event{
		ActorUserID:  &uid,
		ActorAccount: account,
		Action:       "auth.login",
		ResourceType: "session",
		Outcome:      audit.OutcomeSuccess,
		IPAddress:    rbac.ClientIP(r),
		UserAgent:    r.UserAgent(),
	})

	http.Redirect(w, r, nextPath, http.StatusSeeOther)
}

func (s *Server) handleLogoutPost(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	_ = s.sessions.Delete(r.Context(), w, r)
	s.recordAudit(r, principal, "auth.logout", "session", "", audit.OutcomeSuccess, nil)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleLocalePost(w http.ResponseWriter, r *http.Request) {
	_ = parseForm(w, r)
	targetLocale := strings.TrimSpace(r.FormValue("locale"))
	if targetLocale != i18n.LocaleEnUS && targetLocale != i18n.LocaleZhTW {
		targetLocale = i18n.LocaleZhTW
	}

	http.SetCookie(w, &http.Cookie{
		Name:     i18n.LocaleCookieName,
		Value:    targetLocale,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   !s.cfg.InsecureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	redirectTarget := "/"
	if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
		if u, err := url.Parse(ref); err == nil && (u.Host == "" || strings.EqualFold(u.Host, r.Host)) {
			redirectTarget = SafeRedirectPath(u.RequestURI())
		}
	} else if rbac.PrincipalFromContext(r.Context()) == nil {
		redirectTarget = "/login"
	}
	http.Redirect(w, r, redirectTarget, http.StatusSeeOther)
}

func (s *Server) renderLoginPage(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	errorMessage string,
	fieldErrors map[string]string,
	account string,
	nextPath string,
) {
	locale := i18n.ResolveLocale(r, s.cfg.DefaultLocale)
	switchLocale := i18n.LocaleEnUS
	if locale == i18n.LocaleEnUS {
		switchLocale = i18n.LocaleZhTW
	}
	if fieldErrors == nil {
		fieldErrors = map[string]string{}
	}
	s.templates.RenderLogin(w, status, loginPageData{
		Lang:         locale,
		SwitchLocale: switchLocale,
		T:            i18n.Catalog(locale),
		ErrorMessage: errorMessage,
		FieldErrors:  fieldErrors,
		Account:      account,
		Next:         nextPath,
	})
}
