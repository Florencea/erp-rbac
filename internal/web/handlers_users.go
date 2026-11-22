package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Florencea/erp-rbac/internal/audit"
	"github.com/Florencea/erp-rbac/internal/domain/user"
	"github.com/Florencea/erp-rbac/internal/i18n"
	"github.com/Florencea/erp-rbac/internal/rbac"
)

type userRow struct {
	ID             int64
	Account        string
	Name           string
	EmployeeNo     string
	IsSystem       bool
	DepartmentName string
	RoleNames      []string
	StatusBadge    string
	StatusLabel    string
}

type userListPageData struct {
	BasePage
	Query        string
	StatusFilter string
	Users        []userRow
	CanCreate    bool
	CanUpdate    bool
	CanDelete    bool
}

type statusOption struct {
	Value   string
	Label   string
	Checked bool
}

type userFormPageData struct {
	BasePage
	IsEdit        bool
	FormAction    string
	ErrorMessage  string
	FieldErrors   map[string]string
	Account       string
	Name          string
	EmployeeNo    string
	JobTitle      string
	DeptOptions   []deptOption
	RoleOptions   []checkOption
	StatusOptions []statusOption
}

type userDeletePageData struct {
	BasePage
	Target       *user.User
	ErrorMessage string
}

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))

	usersList, err := s.users.List(r.Context(), principal, user.ListFilter{
		Query:  query,
		Status: statusFilter,
	})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	allDepts, err := s.depts.List(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	deptNames := make(map[int64]string, len(allDepts))
	for _, d := range allDepts {
		deptNames[d.ID] = d.Name
	}

	allRoles, err := s.roles.List(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	roleNames := make(map[int64]string, len(allRoles))
	for _, rl := range allRoles {
		roleNames[rl.ID] = rl.Name
	}

	base := s.newBasePage(r, "", "/users")
	base.PageTitle = base.T.User.Title

	rows := make([]userRow, 0, len(usersList))
	for _, u := range usersList {
		dName := "-"
		if u.DepartmentID != nil {
			if n, ok := deptNames[*u.DepartmentID]; ok {
				dName = n
			}
		}
		var rNames []string
		for _, rid := range u.RoleIDs {
			if rn, ok := roleNames[rid]; ok {
				rNames = append(rNames, rn)
			}
		}
		rows = append(rows, userRow{
			ID:             u.ID,
			Account:        u.Account,
			Name:           u.Name,
			EmployeeNo:     u.EmployeeNo,
			IsSystem:       u.IsSystem,
			DepartmentName: dName,
			RoleNames:      rNames,
			StatusBadge:    userStatusBadge(u.Status),
			StatusLabel:    base.T.UserStatusLabel(u.Status),
		})
	}

	s.templates.RenderPage(w, http.StatusOK, "users_list.html", userListPageData{
		BasePage:     base,
		Query:        query,
		StatusFilter: statusFilter,
		Users:        rows,
		CanCreate:    principal.HasPerm("system:user:create"),
		CanUpdate:    principal.HasPerm("system:user:update"),
		CanDelete:    principal.HasPerm("system:user:delete"),
	})
}

func userStatusBadge(status string) string {
	switch status {
	case "active":
		return "success"
	case "inactive":
		return "secondary"
	case "suspended":
		return "danger"
	default:
		return "secondary"
	}
}

func (s *Server) handleUserNew(w http.ResponseWriter, r *http.Request) {
	s.renderUserForm(w, r, http.StatusOK, false, 0, "", "", "", "", "active", 0, nil, "", nil)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	base := s.newBasePage(r, "", "/users")

	if err := parseForm(w, r); err != nil {
		s.renderUserForm(w, r, http.StatusBadRequest, false, 0, "", "", "", "", "active", 0, nil, base.T.Errors.InvalidRequest, nil)
		return
	}

	account := strings.TrimSpace(r.FormValue("account"))
	password := r.FormValue("password")
	name := strings.TrimSpace(r.FormValue("name"))
	empNo := strings.TrimSpace(r.FormValue("employee_no"))
	title := strings.TrimSpace(r.FormValue("title"))
	status := strings.TrimSpace(r.FormValue("status"))
	if status == "" {
		status = "active"
	}
	deptIDVal, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("department_id")), 10, 64)
	roleIDs := parseIDList(r.Form["role_ids"])

	fieldErrors := map[string]string{}
	if account == "" {
		fieldErrors["account"] = base.T.Common.PleaseEnter + base.T.User.Account
	}
	if len(password) < 8 {
		fieldErrors["password"] = base.T.Errors.UserPasswordMinLen
	}
	if len(fieldErrors) > 0 {
		s.renderUserForm(w, r, http.StatusBadRequest, false, 0, account, name, empNo, title, status, deptIDVal, roleIDs, "", fieldErrors)
		return
	}

	var deptPtr *int64
	if deptIDVal > 0 {
		deptPtr = &deptIDVal
	}

	created, err := s.users.Create(r.Context(), principal, user.Input{
		Account:      account,
		Password:     password,
		Name:         name,
		EmployeeNo:   empNo,
		Title:        title,
		Status:       status,
		DepartmentID: deptPtr,
		RoleIDs:      roleIDs,
	})
	if err != nil {
		httpStatus := http.StatusBadRequest
		msg := base.T.Errors.InternalServerError
		switch {
		case errors.Is(err, user.ErrAccountExists):
			msg = base.T.Errors.UserAccountExists
		case errors.Is(err, user.ErrPasswordMinLen):
			msg = base.T.Errors.UserPasswordMinLen
		case errors.Is(err, user.ErrPrivilegeEscalation):
			httpStatus = http.StatusForbidden
			msg = base.T.Errors.PrivilegeEscalation
		case errors.Is(err, user.ErrInvalidStatus):
			msg = base.T.Errors.InvalidRequest
		}
		s.renderUserForm(w, r, httpStatus, false, 0, account, name, empNo, title, status, deptIDVal, roleIDs, msg, nil)
		return
	}

	s.recordAudit(r, principal, "user.create", "user", strconv.FormatInt(created.ID, 10), audit.OutcomeSuccess, map[string]any{
		"account": created.Account,
		"status":  created.Status,
	})
	s.setFlash(r, "success", base.T.User.Saved)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleUserEdit(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	target, err := s.users.GetForActor(r.Context(), principal, id)
	if errors.Is(err, user.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, user.ErrPrivilegeEscalation) {
		s.renderForbidden(w, r, principal)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var deptID int64
	if target.DepartmentID != nil {
		deptID = *target.DepartmentID
	}
	s.renderUserForm(w, r, http.StatusOK, true, target.ID, target.Account, target.Name, target.EmployeeNo, target.Title, target.Status, deptID, target.RoleIDs, "", nil)
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	base := s.newBasePage(r, "", "/users")

	existing, err := s.users.GetForActor(r.Context(), principal, id)
	if errors.Is(err, user.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, user.ErrPrivilegeEscalation) {
		s.renderForbidden(w, r, principal)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := parseForm(w, r); err != nil {
		s.renderUserForm(w, r, http.StatusBadRequest, true, id, existing.Account, existing.Name, existing.EmployeeNo, existing.Title, existing.Status, 0, existing.RoleIDs, base.T.Errors.InvalidRequest, nil)
		return
	}

	password := r.FormValue("password")
	name := strings.TrimSpace(r.FormValue("name"))
	empNo := strings.TrimSpace(r.FormValue("employee_no"))
	title := strings.TrimSpace(r.FormValue("title"))
	status := strings.TrimSpace(r.FormValue("status"))
	if status == "" {
		status = existing.Status
	}
	deptIDVal, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("department_id")), 10, 64)
	roleIDs := parseIDList(r.Form["role_ids"])

	fieldErrors := map[string]string{}
	if password != "" && len(password) < 8 {
		fieldErrors["password"] = base.T.Errors.UserPasswordMinLen
	}
	if len(fieldErrors) > 0 {
		s.renderUserForm(w, r, http.StatusBadRequest, true, id, existing.Account, name, empNo, title, status, deptIDVal, roleIDs, "", fieldErrors)
		return
	}

	var deptPtr *int64
	if deptIDVal > 0 {
		deptPtr = &deptIDVal
	}

	updated, err := s.users.Update(r.Context(), principal, id, user.Input{
		Password:     password,
		Name:         name,
		EmployeeNo:   empNo,
		Title:        title,
		Status:       status,
		DepartmentID: deptPtr,
		RoleIDs:      roleIDs,
	})
	if err != nil {
		httpStatus := http.StatusBadRequest
		msg := base.T.Errors.InternalServerError
		switch {
		case errors.Is(err, user.ErrPrivilegeEscalation):
			httpStatus = http.StatusForbidden
			msg = base.T.Errors.PrivilegeEscalation
		case errors.Is(err, user.ErrSystemProtected):
			msg = base.T.Errors.UserSystemProtected
		case errors.Is(err, user.ErrPasswordMinLen):
			msg = base.T.Errors.UserPasswordMinLen
		case errors.Is(err, user.ErrInvalidStatus):
			msg = base.T.Errors.InvalidRequest
		}
		s.renderUserForm(w, r, httpStatus, true, id, existing.Account, name, empNo, title, status, deptIDVal, roleIDs, msg, nil)
		return
	}

	s.recordAudit(r, principal, "user.update", "user", strconv.FormatInt(updated.ID, 10), audit.OutcomeSuccess, map[string]any{
		"account":          updated.Account,
		"status":           updated.Status,
		"password_changed": password != "",
	})
	s.setFlash(r, "success", base.T.User.Saved)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleUserDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	target, err := s.users.GetForActor(r.Context(), principal, id)
	if errors.Is(err, user.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, user.ErrPrivilegeEscalation) {
		s.renderForbidden(w, r, principal)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	base := s.newBasePage(r, "", "/users")
	base.PageTitle = base.T.User.Delete
	s.templates.RenderPage(w, http.StatusOK, "users_delete.html", userDeletePageData{
		BasePage: base,
		Target:   target,
	})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	base := s.newBasePage(r, "", "/users")
	base.PageTitle = base.T.User.Delete

	existing, getErr := s.users.GetForActor(r.Context(), principal, id)
	if errors.Is(getErr, user.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(getErr, user.ErrPrivilegeEscalation) {
		s.renderForbidden(w, r, principal)
		return
	}
	if getErr != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := s.users.Delete(r.Context(), principal, id); err != nil {
		msg := base.T.Errors.InternalServerError
		switch {
		case errors.Is(err, user.ErrSystemProtected):
			msg = base.T.Errors.UserSystemProtected
		case errors.Is(err, user.ErrSelfDelete):
			msg = base.T.Errors.UserSelfDelete
		case errors.Is(err, user.ErrPrivilegeEscalation):
			msg = base.T.Errors.PrivilegeEscalation
		}
		s.templates.RenderPage(w, http.StatusBadRequest, "users_delete.html", userDeletePageData{
			BasePage:     base,
			Target:       existing,
			ErrorMessage: msg,
		})
		return
	}

	s.recordAudit(r, principal, "user.delete", "user", strconv.FormatInt(id, 10), audit.OutcomeSuccess, map[string]any{
		"account": existing.Account,
	})
	s.setFlash(r, "success", base.T.User.Deleted)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) renderUserForm(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	isEdit bool,
	editID int64,
	account, name, empNo, jobTitle, userStatus string,
	selectedDeptID int64,
	selectedRoleIDs []int64,
	errorMessage string,
	fieldErrors map[string]string,
) {
	principal := rbac.PrincipalFromContext(r.Context())
	base := s.newBasePage(r, "", "/users")
	if isEdit {
		base.PageTitle = base.T.User.Edit
	} else {
		base.PageTitle = base.T.User.Create
	}
	if fieldErrors == nil {
		fieldErrors = map[string]string{}
	}

	allDepts, err := s.depts.ListTree(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	allRoles, err := s.roles.List(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	deptOpts := make([]deptOption, 0, len(allDepts))
	for _, d := range allDepts {
		deptOpts = append(deptOpts, deptOption{
			ID:       d.ID,
			Label:    d.TreePrefix + d.Name,
			Selected: d.ID == selectedDeptID,
		})
	}

	roleOpts := make([]checkOption, 0, len(allRoles))
	for _, rl := range allRoles {
		if rl.Code == rbac.RoleSuperAdmin && (principal == nil || !principal.IsSuperAdmin()) && !slices.Contains(selectedRoleIDs, rl.ID) {
			continue
		}
		roleOpts = append(roleOpts, checkOption{
			ID:      rl.ID,
			Label:   rl.Name,
			Checked: slices.Contains(selectedRoleIDs, rl.ID),
		})
	}

	statusOpts := buildUserStatusOptions(base.T, userStatus)

	action := "/users"
	if isEdit {
		action = "/users/" + strconv.FormatInt(editID, 10)
	}

	s.templates.RenderPage(w, status, "users_form.html", userFormPageData{
		BasePage:      base,
		IsEdit:        isEdit,
		FormAction:    action,
		ErrorMessage:  errorMessage,
		FieldErrors:   fieldErrors,
		Account:       account,
		Name:          name,
		EmployeeNo:    empNo,
		JobTitle:      jobTitle,
		DeptOptions:   deptOpts,
		RoleOptions:   roleOpts,
		StatusOptions: statusOpts,
	})
}

func buildUserStatusOptions(t i18n.Messages, selected string) []statusOption {
	out := make([]statusOption, 0, len(user.ValidStatuses))
	for _, st := range user.ValidStatuses {
		out = append(out, statusOption{
			Value:   st,
			Label:   t.UserStatusLabel(st),
			Checked: st == selected,
		})
	}
	return out
}
