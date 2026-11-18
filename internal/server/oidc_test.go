package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDiscoverProviderTrailingSlash: Authentik publishes its issuer with a
// trailing slash; both spellings of OIDC_ISSUER must work.
func TestDiscoverProviderTrailingSlash(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		iss := srv.URL + "/application/o/inventory/"
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "authorization_endpoint": iss + "authorize/",
			"token_endpoint": iss + "token/", "jwks_uri": iss + "jwks/", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	defer srv.Close()
	for _, issuer := range []string{srv.URL + "/application/o/inventory/", srv.URL + "/application/o/inventory"} {
		p, err := discoverProvider(context.Background(), issuer)
		if err != nil || p == nil {
			t.Errorf("issuer %s: %v", issuer, err)
		}
	}
	if _, err := discoverProvider(context.Background(), srv.URL+"/application/o/other"); err == nil {
		t.Errorf("wrong issuer accepted")
	}
}
