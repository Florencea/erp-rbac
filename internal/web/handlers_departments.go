package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Florencea/erp-rbac/internal/audit"
	"github.com/Florencea/erp-rbac/internal/domain/department"
	"github.com/Florencea/erp-rbac/internal/rbac"
)

type deptListPageData struct {
	BasePage
	Rows      []department.TreeRow
	CanCreate bool
	CanUpdate bool
	CanDelete bool
}

type deptOption struct {
	ID       int64
	Label    string
	Selected bool
}

type deptFormPageData struct {
	BasePage
	IsEdit        bool
	FormAction    string
	ErrorMessage  string
	FieldErrors   map[string]string
	Name          string
	Sort          int
	ParentOptions []deptOption
}

type deptDeletePageData struct {
	BasePage
	Dept         *department.Department
	ErrorMessage string
}

func (s *Server) handleDepartmentsList(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	rows, err := s.depts.ListTree(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	base := s.newBasePage(r, "", "/departments")
	base.PageTitle = base.T.Dept.Title
	s.templates.RenderPage(w, http.StatusOK, "departments_list.html", deptListPageData{
		BasePage:  base,
		Rows:      rows,
		CanCreate: principal.HasPerm("system:dept:create"),
		CanUpdate: principal.HasPerm("system:dept:update"),
		CanDelete: principal.HasPerm("system:dept:delete"),
	})
}

func (s *Server) handleDepartmentNew(w http.ResponseWriter, r *http.Request) {
	var presetParent int64
	if raw := strings.TrimSpace(r.URL.Query().Get("parent_id")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			presetParent = v
		}
	}
	s.renderDeptForm(w, r, http.StatusOK, false, 0, "", presetParent, 1, "", nil)
}

func (s *Server) handleDepartmentCreate(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	base := s.newBasePage(r, "", "/departments")

	if err := parseForm(w, r); err != nil {
		s.renderDeptForm(w, r, http.StatusBadRequest, false, 0, "", 0, 1, base.T.Errors.InvalidRequest, nil)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	parentIDVal, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("parent_id")), 10, 64)
	sortVal, sortErr := strconv.Atoi(strings.TrimSpace(r.FormValue("sort")))
	if sortErr != nil {
		sortVal = 0
	}

	fieldErrors := map[string]string{}
	if name == "" {
		fieldErrors["name"] = base.T.Common.PleaseEnter + base.T.Dept.Name
	}
	if len(fieldErrors) > 0 {
		s.renderDeptForm(w, r, http.StatusBadRequest, false, 0, name, parentIDVal, sortVal, "", fieldErrors)
		return
	}

	var parentPtr *int64
	if parentIDVal > 0 {
		parentPtr = &parentIDVal
	}
	created, err := s.depts.Create(r.Context(), department.Input{
		Name:     name,
		ParentID: parentPtr,
		Sort:     sortVal,
	})
	if err != nil {
		msg := base.T.Errors.InternalServerError
		if errors.Is(err, department.ErrParentInvalid) {
			msg = base.T.Errors.DeptParentInvalid
		}
		s.renderDeptForm(w, r, http.StatusBadRequest, false, 0, name, parentIDVal, sortVal, msg, nil)
		return
	}

	s.recordAudit(r, principal, "department.create", "department", strconv.FormatInt(created.ID, 10), audit.OutcomeSuccess, map[string]any{
		"name": created.Name,
		"path": created.Path,
	})
	s.setFlash(r, "success", base.T.Dept.Saved)
	http.Redirect(w, r, "/departments", http.StatusSeeOther)
}

func (s *Server) handleDepartmentEdit(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, err := s.depts.GetByID(r.Context(), id)
	if errors.Is(err, department.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var parentID int64
	if d.ParentID != nil {
		parentID = *d.ParentID
	}
	s.renderDeptForm(w, r, http.StatusOK, true, d.ID, d.Name, parentID, d.Sort, "", nil)
}

func (s *Server) handleDepartmentUpdate(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	base := s.newBasePage(r, "", "/departments")

	if err := parseForm(w, r); err != nil {
		s.renderDeptForm(w, r, http.StatusBadRequest, true, id, "", 0, 0, base.T.Errors.InvalidRequest, nil)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	parentIDVal, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("parent_id")), 10, 64)
	sortVal, sortErr := strconv.Atoi(strings.TrimSpace(r.FormValue("sort")))
	if sortErr != nil {
		sortVal = 0
	}

	fieldErrors := map[string]string{}
	if name == "" {
		fieldErrors["name"] = base.T.Common.PleaseEnter + base.T.Dept.Name
	}
	if len(fieldErrors) > 0 {
		s.renderDeptForm(w, r, http.StatusBadRequest, true, id, name, parentIDVal, sortVal, "", fieldErrors)
		return
	}

	var parentPtr *int64
	if parentIDVal > 0 {
		parentPtr = &parentIDVal
	}
	updated, err := s.depts.Update(r.Context(), id, department.Input{
		Name:     name,
		ParentID: parentPtr,
		Sort:     sortVal,
	})
	if err != nil {
		if errors.Is(err, department.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		msg := base.T.Errors.InternalServerError
		if errors.Is(err, department.ErrParentInvalid) {
			msg = base.T.Errors.DeptParentInvalid
		}
		s.renderDeptForm(w, r, http.StatusBadRequest, true, id, name, parentIDVal, sortVal, msg, nil)
		return
	}

	s.recordAudit(r, principal, "department.update", "department", strconv.FormatInt(updated.ID, 10), audit.OutcomeSuccess, map[string]any{
		"name": updated.Name,
		"path": updated.Path,
	})
	s.setFlash(r, "success", base.T.Dept.Saved)
	http.Redirect(w, r, "/departments", http.StatusSeeOther)
}

func (s *Server) handleDepartmentDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, err := s.depts.GetByID(r.Context(), id)
	if errors.Is(err, department.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	base := s.newBasePage(r, "", "/departments")
	base.PageTitle = base.T.Dept.Delete
	s.templates.RenderPage(w, http.StatusOK, "departments_delete.html", deptDeletePageData{
		BasePage: base,
		Dept:     d,
	})
}

func (s *Server) handleDepartmentDelete(w http.ResponseWriter, r *http.Request) {
	principal := rbac.PrincipalFromContext(r.Context())
	id, ok := parseIDParam(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	base := s.newBasePage(r, "", "/departments")
	base.PageTitle = base.T.Dept.Delete

	existing, getErr := s.depts.GetByID(r.Context(), id)
	if errors.Is(getErr, department.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if getErr != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err := s.depts.Delete(r.Context(), id)
	if err != nil {
		msg := base.T.Errors.InternalServerError
		switch {
		case errors.Is(err, department.ErrHasChildren):
			msg = base.T.Errors.DeptHasChildren
		case errors.Is(err, department.ErrHasUsers):
			msg = base.T.Errors.DeptHasUsers
		}
		s.templates.RenderPage(w, http.StatusBadRequest, "departments_delete.html", deptDeletePageData{
			BasePage:     base,
			Dept:         existing,
			ErrorMessage: msg,
		})
		return
	}

	s.recordAudit(r, principal, "department.delete", "department", strconv.FormatInt(id, 10), audit.OutcomeSuccess, map[string]any{
		"name": existing.Name,
	})
	s.setFlash(r, "success", base.T.Dept.Deleted)
	http.Redirect(w, r, "/departments", http.StatusSeeOther)
}

func (s *Server) renderDeptForm(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	isEdit bool,
	editID int64,
	name string,
	selectedParentID int64,
	sortOrder int,
	errorMessage string,
	fieldErrors map[string]string,
) {
	base := s.newBasePage(r, "", "/departments")
	if isEdit {
		base.PageTitle = base.T.Dept.Edit
	} else {
		base.PageTitle = base.T.Dept.Create
	}
	if fieldErrors == nil {
		fieldErrors = map[string]string{}
	}

	allDepts, err := s.depts.ListTree(r.Context())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var options []deptOption
	for _, row := range allDepts {
		if isEdit && row.ID == editID {
			continue
		}
		options = append(options, deptOption{
			ID:       row.ID,
			Label:    row.TreePrefix + row.Name,
			Selected: row.ID == selectedParentID,
		})
	}

	action := "/departments"
	if isEdit {
		action = "/departments/" + strconv.FormatInt(editID, 10)
	}

	s.templates.RenderPage(w, status, "departments_form.html", deptFormPageData{
		BasePage:      base,
		IsEdit:        isEdit,
		FormAction:    action,
		ErrorMessage:  errorMessage,
		FieldErrors:   fieldErrors,
		Name:          name,
		Sort:          sortOrder,
		ParentOptions: options,
	})
}
