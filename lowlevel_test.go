package grantor_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
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
	rec, err := e.approve(e.pending, grantor.Approval{Subject: "alice", Scopes: e.pending.Scopes, AuthTime: e.clock.Now()})
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

func TestCustomAuthorizationHandler(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		req, err := e.p.ParseAuthorizationRequest(r)
		if err != nil {
			e.p.WriteAuthorizationError(w, r, err)
			return
		}
		// Policy: this deployment never grants email, and an extension
		// parameter selects the tenant.
		req.Scopes = slices.DeleteFunc(req.Scopes, func(s string) bool { return s == "email" })
		if req.Extra["tenant"] == "blocked" {
			if err := e.p.Deny(w, r, req, &grantor.Error{Code: "tenant_blocked", URI: "https://op.example.com/blocked"}); err != nil {
				t.Errorf("Deny: %v", err)
			}
			return
		}
		if req.LoginHint == "trusted" {
			// Complete immediately, without saving the request.
			if err := e.p.Approve(w, r, req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); err != nil {
				t.Errorf("Approve: %v", err)
			}
			return
		}
		if err := e.p.SaveAuthorizationRequest(w, r, req); err != nil {
			t.Errorf("SaveAuthorizationRequest: %v", err)
			return
		}
		e.pending = req
	})
	mux.Handle("/", e.p)
	e.handler = mux

	q := authParams(confidentialClient, "openid email profile", pkcePair{})
	q.Set("login_hint", "trusted")
	params := redirectParams(t, e.get("/authorize", q))
	status, body := e.exchangeCode(confidentialClient, params.Get("code"), "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK || body["scope"] != "openid profile" {
		t.Fatalf("immediate approval = %d %v", status, body)
	}

	q = authParams(confidentialClient, "openid", pkcePair{})
	q.Set("tenant", "blocked")
	params = redirectParams(t, e.get("/authorize", q))
	if params.Get("error") != "tenant_blocked" || params.Get("error_uri") != "https://op.example.com/blocked" || params.Get("state") != "xyz" {
		t.Fatalf("custom denial = %v", params)
	}

	e.pending = nil
	e.get("/authorize", authParams(confidentialClient, "openid email", pkcePair{}))
	if e.pending == nil || e.pending.ID == "" || slices.Contains(e.pending.Scopes, "email") {
		t.Fatalf("saved request = %+v", e.pending)
	}
	loaded, err := e.p.AuthorizationRequest(e.appRequest(http.MethodGet, "/login"), e.pending.ID)
	if err != nil || slices.Contains(loaded.Scopes, "email") {
		t.Fatalf("loaded = %+v, %v", loaded, err)
	}
	if _, err := e.approve(loaded, grantor.Approval{Subject: "alice", Scopes: loaded.Scopes, AuthTime: e.clock.Now()}); err != nil {
		t.Fatalf("Approve saved request: %v", err)
	}

	// Parse errors that must not be redirected are rendered as a page.
	q = authParams(confidentialClient, "openid", pkcePair{})
	q.Set("redirect_uri", "https://attacker.example.com/cb")
	if rec := e.get("/authorize", q); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("unregistered redirect URI = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestApproveSavedRequestInSameHTTPRequest(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := e.p.ParseAuthorizationRequest(r)
		if err != nil {
			e.p.WriteAuthorizationError(w, r, err)
			return
		}
		if err := e.p.SaveAuthorizationRequest(w, r, req); err != nil {
			t.Errorf("SaveAuthorizationRequest: %v", err)
			return
		}
		if err := e.p.Approve(w, r, req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); err != nil {
			t.Errorf("Approve in the same request: %v", err)
		}
	})
	if p := redirectParams(t, e.get("/authorize", authParams(publicClient, "openid", newPKCE()))); p.Get("code") == "" {
		t.Fatalf("response = %v", p)
	}
}

func TestSavedRequestCannotBeModified(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	req := e.startAuthorization(authParams(publicClient, "openid", newPKCE()))
	req.RedirectURI = "http://127.0.0.1:9999/native"
	if _, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); !errors.Is(err, grantor.ErrAuthorizationRequestModified) {
		t.Fatalf("Approve modified request = %v", err)
	}
}

func TestUnsavedRequestIsRevalidated(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	parse := func() *grantor.AuthorizationRequest {
		t.Helper()
		r := httpGet(testIssuer + "/authorize?" + authParams(publicClient, "openid", newPKCE()).Encode())
		req, err := e.p.ParseAuthorizationRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	approval := grantor.Approval{Subject: "alice", Scopes: []string{"openid"}, AuthTime: e.clock.Now()}
	for name, modify := range map[string]func(*grantor.AuthorizationRequest){
		"unregistered redirect URI": func(r *grantor.AuthorizationRequest) { r.RedirectURI = "https://attacker.example.com/cb" },
		"code challenge removed":    func(r *grantor.AuthorizationRequest) { r.CodeChallenge, r.CodeChallengeMethod = "", "" },
		"scope not registered":      func(r *grantor.AuthorizationRequest) { r.Scopes = append(r.Scopes, "admin") },
		"other issuer":              func(r *grantor.AuthorizationRequest) { r.Issuer = "https://other.example.com" },
		"implicit flow":             func(r *grantor.AuthorizationRequest) { r.ResponseType = "token" },
	} {
		req := parse()
		modify(req)
		rec := httptest.NewRecorder()
		if err := e.p.Approve(rec, httpGet(testIssuer+"/authorize"), req, approval); err == nil {
			t.Errorf("%s: Approve succeeded", name)
		}
		if rec.Header().Get("Location") != "" {
			t.Errorf("%s: a response was written", name)
		}
	}
	// The unmodified request is accepted.
	if err := e.p.Approve(httptest.NewRecorder(), httpGet(testIssuer+"/authorize"), parse(), approval); err != nil {
		t.Fatalf("Approve: %v", err)
	}
}

// tokenHandler is a token endpoint written with the building blocks.
func (e *env) tokenHandler(adjust func(*grantor.TokenRequest)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := e.p.ParseTokenRequest(r)
		if err != nil {
			e.p.WriteTokenError(w, r, err)
			return
		}
		adjust(req)
		resp, err := e.p.Exchange(r.Context(), req)
		if err != nil {
			e.p.WriteTokenError(w, r, err)
			return
		}
		e.p.WriteTokenResponse(w, resp)
	})
}

func TestCustomTokenHandler(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.handler = e.tokenHandler(func(req *grantor.TokenRequest) {
		if _, ok := req.Form["client_secret"]; ok {
			t.Error("Form exposes client_secret")
		}
		// Policy: the api scope is never granted through this endpoint.
		if req.Scopes != nil {
			req.Scopes = slices.DeleteFunc(req.Scopes, func(s string) bool { return s == "api" })
		}
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api openid"}}, nil)
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client")
	status, body = e.tokenRequest(url.Values{
		"grant_type": {"client_credentials"}, "scope": {"api openid"},
		"client_id": {serviceClient}, "client_secret": {confidentialSecret},
	}, nil)
	expectError(t, status, body, http.StatusBadRequest, "invalid_scope") // openid is still rejected
	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK || body["scope"] != nil {
		t.Fatalf("narrowed client credentials = %d %v", status, body)
	}

	e.handler = e.p
	code := e.login(authParams(confidentialClient, "openid profile", pkcePair{}), nil)
	e.handler = e.tokenHandler(func(req *grantor.TokenRequest) { req.Scopes = []string{"openid"} })
	status, body = e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK || body["scope"] != "openid" {
		t.Fatalf("narrowed code exchange = %d %v", status, body)
	}

	e.handler = e.p
	code = e.login(authParams(confidentialClient, "openid", pkcePair{}), nil)
	e.handler = e.tokenHandler(func(req *grantor.TokenRequest) { req.Scopes = []string{"openid", "profile"} })
	status, body = e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_scope")
}

func TestExchangeRejectsForeignTokenRequests(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	if _, err := e.p.Exchange(context.Background(), &grantor.TokenRequest{GrantType: grantor.GrantTypeClientCredentials}); err == nil {
		t.Fatal("Exchange accepted a TokenRequest that was not parsed")
	}
	r := httptest.NewRequest(http.MethodPost, testIssuer+"/token", strings.NewReader("grant_type=client_credentials&scope=api"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(serviceClient, confidentialSecret)
	req, err := e.p.ParseTokenRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.store.Client(context.Background(), testIssuer, resourceServer)
	if err != nil {
		t.Fatal(err)
	}
	req.Client = other
	if _, err := e.p.Exchange(context.Background(), req); err == nil {
		t.Fatal("Exchange accepted a replaced client")
	}
}

const apiKeyGrant grantor.GrantType = "urn:example:params:oauth:grant-type:api-key"

func TestCustomGrant(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.Grants = map[grantor.GrantType]grantor.GrantFunc{
			apiKeyGrant: func(ctx context.Context, req *grantor.TokenRequest) (*grantor.TokenResponse, error) {
				if req.Form.Get("api_key") != "key-for-alice" {
					return nil, &grantor.Error{Code: grantor.CodeInvalidGrant, Description: "unknown API key"}
				}
				return e.p.IssueTokens(ctx, req, grantor.Grant{Subject: "alice", Scopes: []string{"openid", "api"}, AuthTime: e.clock.Now()})
			},
		}
	})
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "cli", SecretHash: grantor.HashSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{apiKeyGrant}, Scopes: []string{"openid", "api"},
	})

	status, body := e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}, "api_key": {"key-for-alice"}}, basic("cli", confidentialSecret))
	if status != http.StatusOK || body["id_token"] == nil || body["scope"] != "openid api" || body["refresh_token"] != nil {
		t.Fatalf("custom grant = %d %v", status, body)
	}
	if info := e.userInfo(body["access_token"].(string)); info["sub"] != "alice" {
		t.Fatalf("userinfo = %v", info)
	}
	status, body = e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}, "api_key": {"wrong"}}, basic("cli", confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")
	status, body = e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}, "api_key": {"key-for-alice"}}, basic(serviceClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "unauthorized_client")
	status, body = e.tokenRequest(url.Values{"grant_type": {"urn:example:unknown"}}, basic("cli", confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "unsupported_grant_type")

	m := decodeJSON(t, e.get(grantor.PathOpenIDConfig, nil))
	if !slices.Contains(m["grant_types_supported"].([]any), any(string(apiKeyGrant))) {
		t.Fatalf("grant_types_supported = %v", m["grant_types_supported"])
	}
}

func TestCustomGrantValidation(t *testing.T) {
	testKeys(t)
	store := memory.New()
	base := grantor.Config{
		Issuer:  &grantor.Issuer{URL: testIssuer, Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}},
		Clients: store, Storage: store,
	}
	noop := func(context.Context, *grantor.TokenRequest) (*grantor.TokenResponse, error) { return nil, nil }
	for name, grants := range map[string]map[grantor.GrantType]grantor.GrantFunc{
		"built-in": {grantor.GrantTypeRefreshToken: noop},
		"empty":    {"": noop},
		"nil func": {apiKeyGrant: nil},
	} {
		cfg := base
		cfg.Grants = grants
		if _, err := grantor.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func TestBeforeIssue(t *testing.T) {
	disabled := map[string]bool{}
	var seen []grantor.GrantType
	e := newEnv(t)
	e.registerClients()
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			seen = append(seen, is.GrantType)
			if disabled[is.Subject] {
				return &grantor.Error{Code: grantor.CodeInvalidGrant, Description: "the account is disabled"}
			}
			is.Scopes = slices.DeleteFunc(is.Scopes, func(s string) bool { return s == "phone" })
			return nil
		}
	})

	code := e.login(authParams(confidentialClient, "openid phone offline_access", pkcePair{}), nil)
	status, body := e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK || body["scope"] != "openid offline_access" || body["refresh_token"] == nil {
		t.Fatalf("code exchange = %d %v", status, body)
	}

	disabled["alice"] = true
	status, refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}},
		basic(confidentialClient, confidentialSecret))
	if status != http.StatusBadRequest || refreshed["error"] != "invalid_grant" || refreshed["error_description"] != "the account is disabled" {
		t.Fatalf("refresh for a disabled account = %d %v", status, refreshed)
	}

	status, cc := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("client credentials = %d %v", status, cc)
	}
	want := []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken, grantor.GrantTypeClientCredentials}
	if !slices.Equal(seen, want) {
		t.Fatalf("BeforeIssue saw %v, want %v", seen, want)
	}
}

func TestBeforeIssueCanWithholdRefreshToken(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			is.RefreshToken = false
			return nil
		}
	})
	code := e.login(authParams(confidentialClient, "openid offline_access", pkcePair{}), nil)
	status, body := e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK || body["refresh_token"] != nil {
		t.Fatalf("code exchange = %d %v", status, body)
	}
}

func TestBeforeIssueCannotWiden(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			is.Scopes = append(is.Scopes, "admin")
			return nil
		}
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
}

func TestCustomErrorFromBeforeIssue(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(context.Context, *grantor.Issuance) error {
			return &grantor.Error{Code: "account_suspended", Description: "suspended", URI: "https://op.example.com/help", StatusCode: http.StatusForbidden}
		}
	})
	rec := e.postForm(grantor.PathToken, url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	body := decodeJSON(t, rec)
	if rec.Code != http.StatusForbidden || body["error"] != "account_suspended" || body["error_uri"] != "https://op.example.com/help" {
		t.Fatalf("custom error = %d %v", rec.Code, body)
	}
}
