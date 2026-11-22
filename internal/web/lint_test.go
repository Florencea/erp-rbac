package web_test

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	webassets "github.com/Florencea/erp-rbac/web"
)

func TestBootstrapOnlyZeroJSAndAccessibility(t *testing.T) {
	t.Parallel()

	cssBytes, err := fs.ReadFile(webassets.Assets, "static/bootstrap.min.css")
	if err != nil {
		t.Fatalf("read embedded bootstrap.min.css: %v", err)
	}
	allowedClasses := parseCSSClasses(string(cssBytes))
	if len(allowedClasses) < 500 {
		t.Fatalf("expected hundreds of Bootstrap classes parsed, got %d", len(allowedClasses))
	}

	// Verify baseline expected Bootstrap classes were parsed properly.
	for _, required := range []string{"container-fluid", "btn-primary", "form-control", "is-invalid", "table-hover", "visually-hidden", "ps-3"} {
		if !allowedClasses[required] {
			t.Fatalf("CSS parser missed expected Bootstrap class %q", required)
		}
	}

	// 1. Static template inspection across all files in web/templates/*.html.
	entries, err := fs.ReadDir(webassets.Assets, "templates")
	if err != nil {
		t.Fatalf("read templates dir: %v", err)
	}

	forbiddenRawPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script\b`),
		regexp.MustCompile(`(?i)<style\b`),
		regexp.MustCompile(`(?i)\sstyle\s*=`),
		regexp.MustCompile(`(?i)\son[a-z]+\s*=`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)\bdata-bs-(toggle|dismiss|target|ride|slide)\b`),
	}

	for _, entry := range entries {
		raw, readErr := fs.ReadFile(webassets.Assets, "templates/"+entry.Name())
		if readErr != nil {
			t.Fatalf("read template %s: %v", entry.Name(), readErr)
		}
		text := string(raw)
		for _, re := range forbiddenRawPatterns {
			if loc := re.FindString(text); loc != "" {
				t.Fatalf("template %s contains forbidden token %q", entry.Name(), loc)
			}
		}
	}

	// 2. Render every GET route via live handler and validate rendered DOM, classes, and a11y invariants.
	h := newTestHarness(t)
	ts := httptest.NewServer(h.handler)
	defer ts.Close()

	unauthClient := &http.Client{}
	loginResp, err := unauthClient.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	loginHTML := readBody(t, loginResp)
	assertRenderedHTMLCompliant(t, "/login", loginHTML, allowedClasses, false)

	adminClient := loginClient(t, ts, "admin", "AdminPass123!")
	paths := []string{
		"/",
		"/departments",
		"/departments/new",
		"/departments/1/edit",
		"/departments/1/delete",
		"/roles",
		"/roles/new",
		"/roles/1/edit",
		"/roles/2/delete",
		"/users",
		"/users/new",
		"/users/1/edit",
		"/users/1/delete",
		"/audit-logs",
	}

	for _, p := range paths {
		resp, err := adminClient.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 on %s, got %d", p, resp.StatusCode)
		}
		assertRenderedHTMLCompliant(t, p, body, allowedClasses, true)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(b)
}

var (
	tagRe      = regexp.MustCompile(`<([a-zA-Z0-9]+)(\s+[^>]*)?>`)
	attrRe     = regexp.MustCompile(`([a-zA-Z0-9_-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?`)
	classSplit = regexp.MustCompile(`\s+`)
)

func assertRenderedHTMLCompliant(t *testing.T, route, htmlText string, allowed map[string]bool, expectTableOrMain bool) {
	t.Helper()

	if !strings.Contains(htmlText, `href="/static/bootstrap.min.css"`) {
		t.Errorf("%s missing /static/bootstrap.min.css stylesheet link", route)
	}
	if !strings.Contains(htmlText, `<html lang=`) {
		t.Errorf("%s missing <html lang=...>", route)
	}
	if expectTableOrMain && !strings.Contains(htmlText, `<main`) {
		t.Errorf("%s missing <main> landmark", route)
	}

	labelTargets := make(map[string]bool)
	type formControl struct {
		tag     string
		id      string
		typ     string
		ariaLbl string
	}
	var controls []formControl
	hasTable := false
	hasThScopeCol := false

	matches := tagRe.FindAllStringSubmatch(htmlText, -1)
	for _, m := range matches {
		tagName := strings.ToLower(m[1])
		attrsRaw := m[2]

		if tagName == "script" || tagName == "style" {
			t.Errorf("%s rendered forbidden <%s> tag", route, tagName)
		}
		if tagName == "table" {
			hasTable = true
		}

		attrs := parseTagAttrs(attrsRaw)
		for k, v := range attrs {
			kl := strings.ToLower(k)
			if kl == "style" || strings.HasPrefix(kl, "on") || strings.HasPrefix(kl, "data-bs-") {
				t.Errorf("%s rendered forbidden attribute %q on <%s>", route, kl, tagName)
			}
			if (kl == "href" || kl == "action") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "javascript:") {
				t.Errorf("%s rendered javascript: URI in %s", route, kl)
			}
			if kl == "rel" && strings.EqualFold(v, "stylesheet") {
				href := attrs["href"]
				if href != "/static/bootstrap.min.css" {
					t.Errorf("%s links external/custom stylesheet %q", route, href)
				}
			}
		}

		if classAttr, ok := attrs["class"]; ok {
			for _, cls := range classSplit.Split(strings.TrimSpace(classAttr), -1) {
				if cls == "" {
					continue
				}
				if !allowed[cls] {
					t.Errorf("%s uses non-Bootstrap class %q on <%s>", route, cls, tagName)
				}
			}
		}

		if tagName == "label" {
			if forID := attrs["for"]; forID != "" {
				labelTargets[forID] = true
			}
		}
		if tagName == "th" && attrs["scope"] == "col" {
			hasThScopeCol = true
		}
		if tagName == "input" || tagName == "select" || tagName == "textarea" {
			controls = append(controls, formControl{
				tag:     tagName,
				id:      attrs["id"],
				typ:     strings.ToLower(attrs["type"]),
				ariaLbl: attrs["aria-label"],
			})
		}
	}

	if hasTable && !hasThScopeCol {
		t.Errorf("%s renders <table> without <th scope=\"col\">", route)
	}

	for _, c := range controls {
		if c.tag == "input" && (c.typ == "hidden" || c.typ == "submit") {
			continue
		}
		if c.ariaLbl != "" {
			continue
		}
		if c.id == "" || !labelTargets[c.id] {
			t.Errorf("%s renders <%s id=%q> without matching <label for=%q> or aria-label", route, c.tag, c.id, c.id)
		}
	}
}

func parseTagAttrs(raw string) map[string]string {
	out := make(map[string]string)
	for _, m := range attrRe.FindAllStringSubmatch(raw, -1) {
		key := m[1]
		val := m[2]
		if val == "" {
			val = m[3]
		}
		if val == "" {
			val = m[4]
		}
		out[strings.ToLower(key)] = val
	}
	return out
}

// parseCSSClasses extracts class selector names from Bootstrap CSS while ignoring comments,
// declaration blocks, and non-selector at-rules (e.g. @keyframes, @font-face).
func parseCSSClasses(cssText string) map[string]bool {
	classes := make(map[string]bool)
	cleaned := stripCSSComments(cssText)

	const (
		ctxRoot = iota
		ctxAtGroup
		ctxSkipBlock
	)

	stack := []int{ctxRoot}
	var sel strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(cleaned); i++ {
		ch := cleaned[i]
		top := stack[len(stack)-1]

		if escaped {
			if top != ctxSkipBlock {
				sel.WriteByte(ch)
			}
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			if top != ctxSkipBlock {
				sel.WriteByte(ch)
			}
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			if top != ctxSkipBlock {
				sel.WriteByte(ch)
			}
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			if top != ctxSkipBlock {
				sel.WriteByte(ch)
			}
			continue
		}
		if ch == '\'' {
			inSingle = true
			if top != ctxSkipBlock {
				sel.WriteByte(ch)
			}
			continue
		}
		if ch == '"' {
			inDouble = true
			if top != ctxSkipBlock {
				sel.WriteByte(ch)
			}
			continue
		}

		switch ch {
		case '{':
			if top == ctxSkipBlock {
				stack = append(stack, ctxSkipBlock)
				continue
			}
			header := strings.TrimSpace(sel.String())
			sel.Reset()
			if strings.HasPrefix(header, "@") {
				lower := strings.ToLower(header)
				if strings.HasPrefix(lower, "@media") ||
					strings.HasPrefix(lower, "@supports") ||
					strings.HasPrefix(lower, "@container") ||
					strings.HasPrefix(lower, "@layer") {
					stack = append(stack, ctxAtGroup)
				} else {
					stack = append(stack, ctxSkipBlock)
				}
			} else {
				extractClassTokens(header, classes)
				stack = append(stack, ctxSkipBlock)
			}
		case '}':
			sel.Reset()
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case ';':
			if top != ctxSkipBlock {
				sel.Reset()
			}
		default:
			if top != ctxSkipBlock {
				sel.WriteByte(ch)
			}
		}
	}

	return classes
}

func stripCSSComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			i += 2
			for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var cssClassTokenRe = regexp.MustCompile(`\.((?:[A-Za-z_-]|\\.)(?:[A-Za-z0-9_-]|\\.)*)`)

func extractClassTokens(selectorList string, out map[string]bool) {
	for _, m := range cssClassTokenRe.FindAllStringSubmatch(selectorList, -1) {
		raw := strings.ReplaceAll(m[1], `\`, "")
		if raw != "" {
			out[raw] = true
		}
	}
}
