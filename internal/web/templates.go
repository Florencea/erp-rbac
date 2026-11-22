package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/Florencea/erp-rbac/internal/i18n"
	"github.com/Florencea/erp-rbac/internal/rbac"
	webassets "github.com/Florencea/erp-rbac/web"
)

// NavItem represents a permission-filtered navigation menu item.
type NavItem struct {
	Href   string
	Label  string
	Active bool
}

// BasePage carries layout-level context required by every authenticated/layout page.
type BasePage struct {
	Lang         string
	SwitchLocale string
	PageTitle    string
	ActivePath   string
	T            i18n.Messages
	Principal    *rbac.Principal
	NavItems     []NavItem
	FlashKind    string
	FlashMessage string
}

// TemplateSet holds pre-parsed HTML templates for all routes.
type TemplateSet struct {
	pages map[string]*template.Template
	login *template.Template
}

// NewTemplateSet parses all embedded templates at startup so missing templates fail fast.
func NewTemplateSet() (*TemplateSet, error) {
	layoutPages := []string{
		"home.html",
		"403.html",
		"departments_list.html",
		"departments_form.html",
		"departments_delete.html",
		"roles_list.html",
		"roles_form.html",
		"roles_delete.html",
		"users_list.html",
		"users_form.html",
		"users_delete.html",
		"audit_logs.html",
	}

	pages := make(map[string]*template.Template, len(layoutPages))
	for _, page := range layoutPages {
		tmpl, err := template.New("layout").ParseFS(
			webassets.Assets,
			"templates/layout.html",
			"templates/"+page,
		)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		pages[page] = tmpl
	}

	loginTmpl, err := template.New("login").ParseFS(webassets.Assets, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("parse template login.html: %w", err)
	}

	return &TemplateSet{
		pages: pages,
		login: loginTmpl,
	}, nil
}

// RenderPage renders a layout-wrapped page into a buffer before writing status and headers.
func (ts *TemplateSet) RenderPage(w http.ResponseWriter, status int, page string, data any) {
	tmpl, ok := ts.pages[page]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		http.Error(w, "Template render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// RenderLogin renders the standalone login template.
func (ts *TemplateSet) RenderLogin(w http.ResponseWriter, status int, data any) {
	var buf bytes.Buffer
	if err := ts.login.ExecuteTemplate(&buf, "login", data); err != nil {
		http.Error(w, "Template render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// StaticFS returns the embedded static filesystem rooted at web/static.
func StaticFS() (fs.FS, error) {
	return fs.Sub(webassets.Assets, "static")
}
