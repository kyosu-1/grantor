package grantor_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

func TestErrorStatusCode(t *testing.T) {
	if got := grantor.StatusCodeOf(&grantor.Error{Code: "custom", StatusCode: http.StatusTeapot}); got != http.StatusTeapot {
		t.Fatalf("status = %d", got)
	}
	if got := grantor.StatusCodeOf(&grantor.Error{Code: grantor.CodeInvalidClient}); got != http.StatusUnauthorized {
		t.Fatalf("default status = %d", got)
	}
}

func TestCustomRouterAndPaths(t *testing.T) {
	e := newEnv(t, func(c *grantor.Config) {
		c.Endpoints = grantor.Endpoints{
			Authorization: "/oauth2/authorize", Token: "/oauth2/token", UserInfo: "/oauth2/userinfo",
			Introspection: "/oauth2/introspect", Revocation: "/oauth2/revoke", JWKS: "/oauth2/keys",
		}
	})
	e.registerClients()

	var tokenCalls int
	countToken := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { tokenCalls++; h(w, r) }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", e.p.ServeAuthorization)
	mux.HandleFunc("POST /oauth2/token", countToken(e.p.ServeToken))
	mux.HandleFunc("/oauth2/userinfo", e.p.ServeUserInfo)
	mux.HandleFunc("/oauth2/introspect", e.p.ServeIntrospection)
	mux.HandleFunc("/oauth2/revoke", e.p.ServeRevocation)
	mux.HandleFunc("/oauth2/keys", e.p.ServeJWKS)
	mux.HandleFunc("/.well-known/openid-configuration", e.p.ServeDiscovery)
	e.handler = mux

	m := decodeJSON(t, e.get("/.well-known/openid-configuration", nil))
	if m["token_endpoint"] != testIssuer+"/oauth2/token" || m["jwks_uri"] != testIssuer+"/oauth2/keys" ||
		m["authorization_endpoint"] != testIssuer+"/oauth2/authorize" || m["revocation_endpoint"] != testIssuer+"/oauth2/revoke" {
		t.Fatalf("discovery = %v", m)
	}

	pkce := newPKCE()
	e.pending = nil
	rec := e.get("/oauth2/authorize", authParams(publicClient, "openid", pkce))
	if e.pending == nil {
		t.Fatalf("authorization = %d %s", rec.Code, rec.Body.String())
	}
	rec, err := e.approve(e.pending.ID, grantor.Approval{Subject: "alice", Scopes: e.pending.Scopes, AuthTime: e.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {redirectParams(t, rec).Get("code")},
		"client_id": {publicClient}, "code_verifier": {pkce.verifier}}
	rec = e.postForm("/oauth2/token", form, nil)
	if rec.Code != http.StatusOK || tokenCalls != 1 {
		t.Fatalf("token = %d calls=%d %s", rec.Code, tokenCalls, rec.Body.String())
	}
	req := httpGet(testIssuer + "/oauth2/userinfo")
	req.Header.Set("Authorization", "Bearer "+decodeJSON(t, rec)["access_token"].(string))
	if rec := e.do(req); rec.Code != http.StatusOK {
		t.Fatalf("userinfo = %d", rec.Code)
	}

	// ServeHTTP routes the configured paths too.
	e.handler = e.p
	if rec := e.get("/oauth2/keys", nil); rec.Code != http.StatusOK {
		t.Fatalf("ServeHTTP custom JWKS path = %d", rec.Code)
	}
	if rec := e.get(grantor.PathJWKS, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("ServeHTTP default JWKS path = %d", rec.Code)
	}
}

func TestEndpointsValidation(t *testing.T) {
	testKeys(t)
	store := memory.New()
	for name, ep := range map[string]grantor.Endpoints{
		"relative":   {Token: "token"},
		"duplicate":  {Token: "/x", UserInfo: "/x"},
		"default":    {Token: grantor.PathJWKS},
		"well-known": {JWKS: "/.well-known/jwks"},
		"query":      {Token: "/token?x=1"},
	} {
		_, err := grantor.New(grantor.Config{
			Issuer:  &grantor.Issuer{URL: testIssuer, Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}},
			Clients: store, Storage: store, Endpoints: ep,
		})
		if err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	// Interact is only needed by ServeAuthorization.
	if _, err := grantor.New(grantor.Config{
		Issuer:  &grantor.Issuer{URL: testIssuer, Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}},
		Clients: store, Storage: store,
	}); err != nil {
		t.Fatalf("New without Interact: %v", err)
	}
}
