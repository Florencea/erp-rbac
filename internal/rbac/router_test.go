package rbac_test

import (
	"net/http"
	"testing"

	"github.com/Florencea/erp-rbac/internal/rbac"
)

func TestRequirePermPanicsOnEmptyPermission(t *testing.T) {
	t.Parallel()
	r := rbac.NewRouter(nil, nil, nil, nil, nil)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when RequirePerm is called with empty permission")
		}
	}()
	r.RequirePerm("GET /broken", "", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRouterTracksRouteDeclarations(t *testing.T) {
	t.Parallel()
	r := rbac.NewRouter(nil, nil, nil, nil, nil)
	h := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	r.Public("GET /healthz", h)
	r.Authenticated("GET /{$}", h)
	r.RequirePerm("GET /users", "system:user:read", h)

	routes := r.Routes()
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	if routes[0].Level != rbac.AccessPublic || routes[1].Level != rbac.AccessAuthenticated || routes[2].Level != rbac.AccessPermission {
		t.Fatalf("unexpected route levels: %+v", routes)
	}
}
