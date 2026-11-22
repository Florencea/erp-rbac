package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Florencea/erp-rbac/internal/audit"
)

type auditRow struct {
	audit.Record
	OccurredAtFormatted string
	OutcomeBadge        string
	OutcomeLabel        string
}

type auditLogsPageData struct {
	BasePage
	AccountFilter string
	ActionFilter  string
	OutcomeFilter string
	Rows          []auditRow
	Page          int
	TotalPages    int
	HasPrev       bool
	HasNext       bool
	PrevHref      string
	NextHref      string
}

func (s *Server) handleAuditLogsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	account := strings.TrimSpace(q.Get("account"))
	action := strings.TrimSpace(q.Get("action"))
	outcome := strings.TrimSpace(q.Get("outcome"))
	page, err := strconv.Atoi(strings.TrimSpace(q.Get("page")))
	if err != nil || page < 1 {
		page = 1
	}

	res, err := s.audit.List(r.Context(), audit.Filter{
		Account:  account,
		Action:   action,
		Outcome:  outcome,
		Page:     page,
		PageSize: 25,
	})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	base := s.newBasePage(r, "", "/audit-logs")
	base.PageTitle = base.T.Audit.Title

	rows := make([]auditRow, 0, len(res.Items))
	for _, item := range res.Items {
		badge := "danger"
		label := base.T.Audit.OutcomeFail
		switch item.Outcome {
		case audit.OutcomeSuccess:
			badge = "success"
			label = base.T.Audit.OutcomeOK
		case audit.OutcomeDenied:
			badge = "warning"
			label = base.T.Audit.OutcomeDeny
		}
		rows = append(rows, auditRow{
			Record:              item,
			OccurredAtFormatted: time.Unix(item.OccurredAt, 0).UTC().Format("2006-01-02 15:04:05"),
			OutcomeBadge:        badge,
			OutcomeLabel:        label,
		})
	}

	buildHref := func(targetPage int) string {
		params := url.Values{}
		if account != "" {
			params.Set("account", account)
		}
		if action != "" {
			params.Set("action", action)
		}
		if outcome != "" {
			params.Set("outcome", outcome)
		}
		params.Set("page", strconv.Itoa(targetPage))
		return "/audit-logs?" + params.Encode()
	}

	s.templates.RenderPage(w, http.StatusOK, "audit_logs.html", auditLogsPageData{
		BasePage:      base,
		AccountFilter: account,
		ActionFilter:  action,
		OutcomeFilter: outcome,
		Rows:          rows,
		Page:          res.Page,
		TotalPages:    res.TotalPages,
		HasPrev:       res.Page > 1,
		HasNext:       res.Page < res.TotalPages,
		PrevHref:      buildHref(max(1, res.Page-1)),
		NextHref:      buildHref(min(res.TotalPages, res.Page+1)),
	})
}
