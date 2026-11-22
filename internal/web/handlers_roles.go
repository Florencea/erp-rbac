package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Florencea/erp-rbac/internal/audit"
	"github.com/Florencea/erp-rbac/internal/domain/role"
	"github.com/Florencea/erp-rbac/internal/i18n"
	"github.com/Florencea/erp-rbac/internal/rbac"
)

type roleRow struct {
	role.Role
	DataScopeLabel string
}

type roleListPageData struct {
	BasePage
	Roles     []roleRow
	CanCreate bool
	CanUpdate bool
	CanDelete bool
}

type scopeOption struct {
	Value   string
	Label   string
	Checked bool
}

type checkOption struct {
	ID      int64
	Label   string
	Checked bool
}

type permOption struct {
	ID      int64
	Code    string
	Name    string
	Checked bool
}

type roleFormPageData struct {
	BasePage
	IsEdit       bool
	FormAction   string
	ErrorMessage string
	FieldErrors  map[string]string
	Code         string
	Name         string
	Description  string
	Sort         int
	ScopeOptions []scopeOption
	DeptOptions  []checkOption
	PermOptions  []permOption
}

type roleDeletePageData struct {
	BasePage
	Role         *role.Role
	ErrorMessage string
}

func (s *Server) handleRolesList(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	items, err := s.roles.List(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	base := s.newBasePage(r, "", "/roles")
	base.PageTitle = base.T.Role.Title

	rows := make([]roleRow, 0, len(items))
	for _, it := range items {
		rows = append(rows, roleRow{
			Role:           it,
			DataScopeLabel: base.T.DataScopeLabel(it.DataScope),
		})
	}

	s.templates.RenderPage(w, http.StatusOK, "roles_list.html", roleListPageData{
		BasePage:  base,
		Roles:     rows,
		CanCreate: principal.HasPerm("system:role:create"),
		CanUpdate: principal.HasPerm("system:role:update"),
		CanDelete: principal.HasPerm("system:role:delete"),
	})
}

func (s *Server) handleRoleNew(w http.ResponseWriter, r *http.Request) {
	s.renderRoleForm(w, r, http.StatusOK, false, 0, "", "", "", "SELF", 1, nil, nil, "", nil)
}

func (s *Server) handleRoleCreate(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	base := s.newBasePage(r, "", "/roles")

	if err := parseForm(w, r); err != nil {
		s.renderRoleForm(w, r, http.StatusBadRequest, false, 0, "", "", "", "SELF", 1, nil, nil, base.T.Errors.InvalidRequest, nil)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	dataScope := strings.TrimSpace(r.FormValue("data_scope"))
	if dataScope == "" {
		dataScope = "SELF"
	}
	sortVal, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("sort")))
	permIDs := parseIDList(r.Form["permission_ids"])
	deptIDs := parseIDList(r.Form["department_ids"])

	fieldErrors := map[string]string{}
	if code == "" {
		fieldErrors["code"] = base.T.Common.PleaseEnter + base.T.Role.Code
	}
	if name == "" {
		fieldErrors["name"] = base.T.Common.PleaseEnter + base.T.Role.Name
	}
	if !slices.Contains(role.ValidDataScopes, dataScope) {
		fieldErrors["data_scope"] = base.T.Errors.InvalidRequest
	}
	if len(fieldErrors) > 0 {
		s.renderRoleForm(w, r, http.StatusBadRequest, false, 0, code, name, desc, dataScope, sortVal, permIDs, deptIDs, "", fieldErrors)
		return
	}

	created, err := s.roles.Create(r.Context(), role.Input{
		Code:          code,
		Name:          name,
		Description:   desc,
		DataScope:     dataScope,
		Sort:          sortVal,
		PermissionIDs: permIDs,
		DepartmentIDs: deptIDs,
	})
	if err != nil {
		msg := base.T.Errors.InternalServerError
		if errors.Is(err, role.ErrCodeExists) {
			msg = base.T.Errors.RoleCodeExists
		} else if errors.Is(err, role.ErrInvalidScope) {
			msg = base.T.Errors.InvalidRequest
		}
		s.renderRoleForm(w, r, http.StatusBadRequest, false, 0, code, name, desc, dataScope, sortVal, permIDs, deptIDs, msg, nil)
		return
	}

	s.recordAudit(r, principal, "role.create", "role", strconv.FormatInt(created.ID, 10), audit.OutcomeSuccess, map[string]any{
		"code":       created.Code,
		"data_scope": created.DataScope,
	})
	s.setFlash(r, "success", base.T.Role.Saved)
	http.Redirect(w, r, "/roles", http.StatusSeeOther)
}

func (s *Server) handleRoleEdit(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	item, err := s.roles.GetByID(r.Context(), id)
	if errors.Is(err, role.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.renderRoleForm(w, r, http.StatusOK, true, item.ID, item.Code, item.Name, item.Description, item.DataScope, item.Sort, item.PermissionIDs, item.DepartmentIDs, "", nil)
}

func (s *Server) handleRoleUpdate(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	base := s.newBasePage(r, "", "/roles")

	existing, err := s.roles.GetByID(r.Context(), id)
	if errors.Is(err, role.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := parseForm(w, r); err != nil {
		s.renderRoleForm(w, r, http.StatusBadRequest, true, id, existing.Code, existing.Name, existing.Description, existing.DataScope, existing.Sort, existing.PermissionIDs, existing.DepartmentIDs, base.T.Errors.InvalidRequest, nil)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	dataScope := strings.TrimSpace(r.FormValue("data_scope"))
	if dataScope == "" {
		dataScope = existing.DataScope
	}
	sortVal, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("sort")))
	permIDs := parseIDList(r.Form["permission_ids"])
	deptIDs := parseIDList(r.Form["department_ids"])

	fieldErrors := map[string]string{}
	if name == "" {
		fieldErrors["name"] = base.T.Common.PleaseEnter + base.T.Role.Name
	}
	if !slices.Contains(role.ValidDataScopes, dataScope) {
		fieldErrors["data_scope"] = base.T.Errors.InvalidRequest
	}
	if len(fieldErrors) > 0 {
		s.renderRoleForm(w, r, http.StatusBadRequest, true, id, existing.Code, name, desc, dataScope, sortVal, permIDs, deptIDs, "", fieldErrors)
		return
	}

	updated, err := s.roles.Update(r.Context(), id, role.Input{
		Name:          name,
		Description:   desc,
		DataScope:     dataScope,
		Sort:          sortVal,
		PermissionIDs: permIDs,
		DepartmentIDs: deptIDs,
	})
	if err != nil {
		msg := base.T.Errors.InternalServerError
		if errors.Is(err, role.ErrSystemProtected) {
			msg = base.T.Errors.RoleSystemProtected
		} else if errors.Is(err, role.ErrInvalidScope) {
			msg = base.T.Errors.InvalidRequest
		}
		s.renderRoleForm(w, r, http.StatusBadRequest, true, id, existing.Code, name, desc, dataScope, sortVal, permIDs, deptIDs, msg, nil)
		return
	}

	s.recordAudit(r, principal, "role.update", "role", strconv.FormatInt(updated.ID, 10), audit.OutcomeSuccess, map[string]any{
		"code":       updated.Code,
		"data_scope": updated.DataScope,
	})
	s.setFlash(r, "success", base.T.Role.Saved)
	http.Redirect(w, r, "/roles", http.StatusSeeOther)
}

func (s *Server) handleRoleDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	item, err := s.roles.GetByID(r.Context(), id)
	if errors.Is(err, role.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	base := s.newBasePage(r, "", "/roles")
	base.PageTitle = base.T.Role.Delete
	s.templates.RenderPage(w, http.StatusOK, "roles_delete.html", roleDeletePageData{
		BasePage: base,
		Role:     item,
	})
}

func (s *Server) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	base := s.newBasePage(r, "", "/roles")
	base.PageTitle = base.T.Role.Delete

	existing, getErr := s.roles.GetByID(r.Context(), id)
	if errors.Is(getErr, role.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if getErr != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := s.roles.Delete(r.Context(), id); err != nil {
		msg := base.T.Errors.InternalServerError
		if errors.Is(err, role.ErrSystemProtected) {
			msg = base.T.Errors.RoleSystemProtected
		}
		s.templates.RenderPage(w, http.StatusBadRequest, "roles_delete.html", roleDeletePageData{
			BasePage:     base,
			Role:         existing,
			ErrorMessage: msg,
		})
		return
	}

	s.recordAudit(r, principal, "role.delete", "role", strconv.FormatInt(id, 10), audit.OutcomeSuccess, map[string]any{
		"code": existing.Code,
	})
	s.setFlash(r, "success", base.T.Role.Deleted)
	http.Redirect(w, r, "/roles", http.StatusSeeOther)
}

func (s *Server) renderRoleForm(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	isEdit bool,
	editID int64,
	code, name, desc, dataScope string,
	sortOrder int,
	selectedPermIDs, selectedDeptIDs []int64,
	errorMessage string,
	fieldErrors map[string]string,
) {
	base := s.newBasePage(r, "", "/roles")
	if isEdit {
		base.PageTitle = base.T.Role.Edit
	} else {
		base.PageTitle = base.T.Role.Create
	}
	if fieldErrors == nil {
		fieldErrors = map[string]string{}
	}

	allPerms, err := s.roles.ListPermissions(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	allDepts, err := s.depts.ListTree(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	permOpts := make([]permOption, 0, len(allPerms))
	for _, p := range allPerms {
		permOpts = append(permOpts, permOption{
			ID:      p.ID,
			Code:    p.Code,
			Name:    p.Name,
			Checked: slices.Contains(selectedPermIDs, p.ID),
		})
	}

	deptOpts := make([]checkOption, 0, len(allDepts))
	for _, d := range allDepts {
		deptOpts = append(deptOpts, checkOption{
			ID:      d.ID,
			Label:   d.TreePrefix + d.Name,
			Checked: slices.Contains(selectedDeptIDs, d.ID),
		})
	}

	scopeOpts := buildScopeOptions(base.T, dataScope)

	action := "/roles"
	if isEdit {
		action = "/roles/" + strconv.FormatInt(editID, 10)
	}

	s.templates.RenderPage(w, status, "roles_form.html", roleFormPageData{
		BasePage:     base,
		IsEdit:       isEdit,
		FormAction:   action,
		ErrorMessage: errorMessage,
		FieldErrors:  fieldErrors,
		Code:         code,
		Name:         name,
		Description:  desc,
		Sort:         sortOrder,
		ScopeOptions: scopeOpts,
		DeptOptions:  deptOpts,
		PermOptions:  permOpts,
	})
}

func buildScopeOptions(t i18n.Messages, selected string) []scopeOption {
	out := make([]scopeOption, 0, len(role.ValidDataScopes))
	for _, sc := range role.ValidDataScopes {
		out = append(out, scopeOption{
			Value:   sc,
			Label:   t.DataScopeLabel(sc),
			Checked: sc == selected,
		})
	}
	return out
}
