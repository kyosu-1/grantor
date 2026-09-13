package grantor_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

func httpGet(u string) *http.Request { return httptest.NewRequest(http.MethodGet, u, nil) }

func hs256Assertion(t *testing.T, aud string, exp time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(strings.Repeat("k", 32))},
		(&jose.SignerOptions{}).WithHeader("kid", "client-key"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: jwtClient, Subject: jwtClient, Audience: jwt.Audience{aud},
		Expiry: jwt.NewNumericDate(exp), ID: "hs-jti",
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *env) introspect(token, clientID string) map[string]any {
	e.t.Helper()
	rec := e.postForm(grantor.PathIntrospection, url.Values{"token": {token}}, basic(clientID, confidentialSecret))
	if rec.Code != http.StatusOK {
		e.t.Fatalf("introspection = %d %s", rec.Code, rec.Body.String())
	}
	return decodeJSON(e.t, rec)
}

func (e *env) tokensFor(clientID, scopes string) map[string]any {
	e.t.Helper()
	code := e.login(authParams(clientID, scopes, pkcePair{}), nil)
	status, body := e.exchangeCode(clientID, code, "", basic(clientID, confidentialSecret))
	if status != http.StatusOK {
		e.t.Fatalf("token exchange = %d %v", status, body)
	}
	return body
}

func TestUserInfoRequests(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	tokens := e.tokensFor(confidentialClient, "openid email org")
	at := tokens["access_token"].(string)

	info := e.userInfo(at)
	if info["email"] != "alice@example.com" || info["email_verified"] != true || info["department"] != "engineering" || info["name"] != nil {
		t.Fatalf("userinfo = %v", info)
	}

	post := func(body url.Values, header string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, testIssuer+grantor.PathUserInfo, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		return e.do(req)
	}
	if rec := post(url.Values{"access_token": {at}}, ""); rec.Code != http.StatusOK {
		t.Fatalf("form body token = %d", rec.Code)
	}
	if rec := post(url.Values{"access_token": {at}}, "Bearer "+at); rec.Code != http.StatusBadRequest {
		t.Fatalf("two tokens = %d", rec.Code)
	}

	rec := e.do(httpGet(testIssuer + grantor.PathUserInfo))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer realm="userinfo"` {
		t.Fatalf("no token = %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	req := httpGet(testIssuer + grantor.PathUserInfo)
	req.Header.Set("Authorization", "Bearer invalid")
	rec = e.do(req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("invalid token = %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// Query string tokens are not accepted.
	if rec := e.get(grantor.PathUserInfo, url.Values{"access_token": {at}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("query token = %d", rec.Code)
	}

	// A token without openid cannot call UserInfo.
	status, cc := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("client credentials = %d %v", status, cc)
	}
	req = httpGet(testIssuer + grantor.PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+cc["access_token"].(string))
	if rec := e.do(req); rec.Code != http.StatusForbidden {
		t.Fatalf("token without openid = %d", rec.Code)
	}

	e.clock.Advance(2 * time.Hour)
	req = httpGet(testIssuer + grantor.PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+at)
	if rec := e.do(req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token = %d", rec.Code)
	}
}

func TestIntrospection(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	tokens := e.tokensFor(confidentialClient, "openid profile offline_access")
	at, rt := tokens["access_token"].(string), tokens["refresh_token"].(string)

	own := e.introspect(at, confidentialClient)
	if own["active"] != true || own["sub"] != "alice" || own["scope"] != "openid profile offline_access" ||
		own["token_type"] != "Bearer" || own["iss"] != testIssuer {
		t.Fatalf("own token = %v", own)
	}
	if rs := e.introspect(at, resourceServer); rs["active"] != true {
		t.Fatalf("resource server = %v", rs)
	}
	if other := e.introspect(at, serviceClient); other["active"] != false || len(other) != 1 {
		t.Fatalf("other client = %v", other)
	}
	if refresh := e.introspect(rt, confidentialClient); refresh["active"] != true || refresh["token_type"] != nil {
		t.Fatalf("refresh token = %v", refresh)
	}
	if unknown := e.introspect("unknown", confidentialClient); unknown["active"] != false {
		t.Fatalf("unknown token = %v", unknown)
	}

	rec := e.postForm(grantor.PathIntrospection, url.Values{"token": {at}, "client_id": {publicClient}}, nil)
	expectError(t, rec.Code, decodeJSON(t, rec), http.StatusUnauthorized, "invalid_client")
}

func TestRevocation(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	auth := basic(confidentialClient, confidentialSecret)

	tokens := e.tokensFor(confidentialClient, "openid offline_access")
	rec := e.postForm(grantor.PathRevocation, url.Values{"token": {tokens["access_token"].(string)}}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke access token = %d %s", rec.Code, rec.Body.String())
	}
	if info := e.introspect(tokens["access_token"].(string), confidentialClient); info["active"] != false {
		t.Fatalf("revoked access token = %v", info)
	}
	if info := e.introspect(tokens["refresh_token"].(string), confidentialClient); info["active"] != true {
		t.Fatalf("refresh token after access token revocation = %v", info)
	}

	tokens = e.tokensFor(confidentialClient, "openid offline_access")
	rec = e.postForm(grantor.PathRevocation, url.Values{"token": {tokens["refresh_token"].(string)}, "token_type_hint": {"refresh_token"}}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke refresh token = %d", rec.Code)
	}
	if info := e.introspect(tokens["access_token"].(string), confidentialClient); info["active"] != false {
		t.Fatalf("access token after refresh token revocation = %v", info)
	}

	if rec := e.postForm(grantor.PathRevocation, url.Values{"token": {"unknown"}}, auth); rec.Code != http.StatusOK {
		t.Fatalf("unknown token = %d", rec.Code)
	}

	tokens = e.tokensFor(confidentialClient, "openid")
	rec = e.postForm(grantor.PathRevocation, url.Values{"token": {tokens["access_token"].(string)}}, basic(serviceClient, confidentialSecret))
	expectError(t, rec.Code, decodeJSON(t, rec), http.StatusBadRequest, "unauthorized_client")
	if info := e.introspect(tokens["access_token"].(string), confidentialClient); info["active"] != true {
		t.Fatalf("another client revoked the token: %v", info)
	}
}

func TestRedirectURIValidation(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	errorPage := func(q url.Values) {
		t.Helper()
		rec := e.get(grantor.PathAuthorization, q)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || e.pending != nil {
			t.Fatalf("expected an error page, got %d Location=%q", rec.Code, rec.Header().Get("Location"))
		}
	}

	q := authParams(publicClient, "openid", newPKCE())
	q.Set("redirect_uri", "https://attacker.example.com/cb")
	errorPage(q)

	q = authParams(publicClient, "openid", newPKCE())
	q.Set("redirect_uri", clientRedirect+"/extra")
	errorPage(q)

	q = authParams(publicClient, "openid", newPKCE())
	q.Del("redirect_uri")
	errorPage(q)

	q = authParams("unknown-client", "openid", newPKCE())
	errorPage(q)

	q = authParams(publicClient, "openid", newPKCE())
	q.Add("client_id", publicClient)
	errorPage(q)

	// Loopback redirect URIs may use any port.
	q = authParams(publicClient, "openid", newPKCE())
	q.Set("redirect_uri", "http://127.0.0.1:53124/native")
	e.startAuthorization(q)
	q.Set("redirect_uri", "http://127.0.0.1:53124/other")
	e.pending = nil
	errorPage(q)
}

func TestAuthorizationErrorsAreRedirected(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	cases := []struct {
		name   string
		modify func(url.Values)
		want   string
	}{
		{"missing response_type", func(q url.Values) { q.Del("response_type") }, "invalid_request"},
		{"implicit flow", func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		{"hybrid flow", func(q url.Values) { q.Set("response_type", "code id_token") }, "unsupported_response_type"},
		{"unregistered scope", func(q url.Values) { q.Set("scope", "openid admin") }, "invalid_scope"},
		{"repeated parameter", func(q url.Values) { q.Add("scope", "openid") }, "invalid_request"},
		{"request object", func(q url.Values) { q.Set("request", "eyJhbGciOiJub25lIn0.e30.") }, "request_not_supported"},
		{"request_uri", func(q url.Values) { q.Set("request_uri", "https://client.example.com/req") }, "request_uri_not_supported"},
		{"prompt none with login", func(q url.Values) { q.Set("prompt", "none login") }, "invalid_request"},
		{"unknown prompt", func(q url.Values) { q.Set("prompt", "bogus") }, "invalid_request"},
		{"bad max_age", func(q url.Values) { q.Set("max_age", "-1") }, "invalid_request"},
		{"bad claims", func(q url.Values) { q.Set("claims", "{not json") }, "invalid_request"},
		{"bad id_token_hint", func(q url.Values) { q.Set("id_token_hint", "not-a-jwt") }, "invalid_request"},
		{"bad response_mode", func(q url.Values) { q.Set("response_mode", "web_message") }, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := authParams(publicClient, "openid", newPKCE())
			tc.modify(q)
			e.pending = nil
			params := redirectParams(t, e.get(grantor.PathAuthorization, q))
			if params.Get("error") != tc.want || params.Get("state") != "xyz" || params.Get("iss") != testIssuer {
				t.Fatalf("got %v, want error=%s", params, tc.want)
			}
			if e.pending != nil {
				t.Fatal("invalid request reached the application")
			}
		})
	}

	t.Run("unknown parameters are ignored", func(t *testing.T) {
		q := authParams(publicClient, "openid", newPKCE())
		q.Set("vendor_extension", "1")
		e.startAuthorization(q)
	})

	t.Run("POST authorization request", func(t *testing.T) {
		q := authParams(publicClient, "openid", newPKCE())
		e.pending = nil
		rec := e.postForm(grantor.PathAuthorization, q, nil)
		if rec.Code != http.StatusOK || e.pending == nil {
			t.Fatalf("POST authorization = %d", rec.Code)
		}
	})
}

func TestResponseModes(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	q := authParams(publicClient, "openid", newPKCE())
	q.Set("response_mode", "form_post")
	req := e.startAuthorization(q)
	rec, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `action="`+clientRedirect+`"`) ||
		!strings.Contains(body, `name="code"`) || !strings.Contains(body, `name="state" value="xyz"`) {
		t.Fatalf("form_post = %d %s", rec.Code, body)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'sha256-") {
		t.Fatalf("form_post CSP = %q", csp)
	}

	q = authParams(publicClient, "openid", newPKCE())
	q.Set("response_mode", "fragment")
	req = e.startAuthorization(q)
	rec, err = e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	frag, _ := url.ParseQuery(u.Fragment)
	if u.RawQuery != "" || frag.Get("code") == "" || frag.Get("iss") != testIssuer {
		t.Fatalf("fragment response = %s", rec.Header().Get("Location"))
	}

	// State is escaped in form_post pages.
	q = authParams(publicClient, "openid", newPKCE())
	q.Set("response_mode", "form_post")
	q.Set("state", `"><script>alert(1)</script>`)
	req = e.startAuthorization(q)
	rec, _ = e.deny(req.ID, grantor.ErrAccessDenied)
	if strings.Contains(rec.Body.String(), "<script>alert") {
		t.Fatalf("form_post does not escape state: %s", rec.Body.String())
	}
}

func TestPromptAndMaxAge(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	t.Run("prompt=none denied", func(t *testing.T) {
		q := authParams(publicClient, "openid", newPKCE())
		q.Set("prompt", "none")
		req := e.startAuthorization(q)
		if !req.HasPrompt("none") {
			t.Fatalf("prompt = %v", req.Prompt)
		}
		rec, err := e.deny(req.ID, grantor.ErrLoginRequired)
		if err != nil {
			t.Fatal(err)
		}
		if p := redirectParams(t, rec); p.Get("error") != "login_required" || p.Get("state") != "xyz" {
			t.Fatalf("deny = %v", p)
		}
		if _, err := e.deny(req.ID, grantor.ErrLoginRequired); !errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
			t.Fatalf("second deny = %v", err)
		}
	})

	t.Run("prompt=login requires fresh authentication", func(t *testing.T) {
		q := authParams(publicClient, "openid", newPKCE())
		q.Set("prompt", "login")
		e.clock.Advance(time.Minute)
		req := e.startAuthorization(q)
		old := e.clock.Now().Add(-10 * time.Minute)
		if !req.NeedsAuthentication(old) {
			t.Fatal("NeedsAuthentication(old) = false")
		}
		if _, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: old}); err == nil {
			t.Fatal("Approve accepted a stale authentication")
		}
		e.clock.Advance(5 * time.Second)
		if _, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); err != nil {
			t.Fatalf("Approve after re-authentication: %v", err)
		}
	})

	t.Run("max_age", func(t *testing.T) {
		q := authParams(publicClient, "openid", newPKCE())
		q.Set("max_age", "300")
		req := e.startAuthorization(q)
		if req.MaxAge == nil || *req.MaxAge != 5*time.Minute {
			t.Fatalf("MaxAge = %v", req.MaxAge)
		}
		if _, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now().Add(-time.Hour)}); err == nil {
			t.Fatal("Approve accepted an authentication older than max_age")
		}
		authTime := e.clock.Now().Add(-time.Minute)
		rec, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: authTime})
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if redirectParams(t, rec).Get("code") == "" {
			t.Fatal("no code")
		}
	})

	t.Run("approval validation", func(t *testing.T) {
		req := e.startAuthorization(authParams(publicClient, "openid profile", newPKCE()))
		bad := []grantor.Approval{
			{Scopes: req.Scopes, AuthTime: e.clock.Now()},
			{Subject: "alice", Scopes: []string{"openid", "email"}, AuthTime: e.clock.Now()},
			{Subject: "alice", Scopes: []string{"profile"}, AuthTime: e.clock.Now()},
			{Subject: "alice", Scopes: req.Scopes},
			{Subject: strings.Repeat("a", 256), Scopes: req.Scopes, AuthTime: e.clock.Now()},
		}
		for i, a := range bad {
			if _, err := e.approve(req.ID, a); err == nil {
				t.Errorf("approval %d was accepted", i)
			}
		}
		if _, err := e.deny(req.ID, &grantor.Error{Code: grantor.CodeInvalidGrant}); err == nil {
			t.Error("Deny accepted a token endpoint error code")
		}
	})
}

func TestInteractionBinding(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	req := e.startAuthorization(authParams(publicClient, "openid", newPKCE()))

	// A request from another browser, without the binding cookie, cannot
	// see or complete the authorization request.
	other := httptest.NewRequest(http.MethodPost, testIssuer+"/login", nil)
	if _, err := e.p.AuthorizationRequest(other, req.ID); !errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
		t.Fatalf("AuthorizationRequest from another browser = %v", err)
	}
	if err := e.p.Approve(httptest.NewRecorder(), other, req.ID, grantor.Approval{Subject: "mallory", Scopes: req.Scopes, AuthTime: e.clock.Now()}); !errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
		t.Fatalf("Approve from another browser = %v", err)
	}

	if _, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); !errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
		t.Fatalf("second Approve = %v", err)
	}

	// Interact can approve within the authorization request itself, before
	// the user agent has stored the binding cookie.
	e.interact = func(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest) {
		if err := e.p.Approve(w, r, req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); err != nil {
			t.Errorf("Approve inside Interact: %v", err)
		}
	}
	fresh, _ := cookiejar.New(nil)
	e.jar = fresh
	rec := e.get(grantor.PathAuthorization, authParams(publicClient, "openid", newPKCE()))
	if p := redirectParams(t, rec); p.Get("code") == "" {
		t.Fatalf("immediate approval = %v", p)
	}
	e.interact = nil

	req = e.startAuthorization(authParams(publicClient, "openid", newPKCE()))
	e.clock.Advance(16 * time.Minute)
	if _, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); !errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
		t.Fatalf("Approve after expiry = %v", err)
	}
}

func TestClaimsParameter(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	q := authParams(confidentialClient, "openid", pkcePair{})
	q.Set("claims", `{"id_token":{"email":null,"acr":{"essential":true,"values":["urn:loa:2"]}},"userinfo":{"phone_number":{"essential":true}}}`)
	req := e.startAuthorization(q)
	if _, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), ACR: "urn:loa:1"}); err == nil {
		t.Fatal("Approve ignored an unsatisfied essential acr")
	}
	rec, err := e.approve(req.ID, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), ACR: "urn:loa:2"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	status, body := e.exchangeCode(confidentialClient, redirectParams(t, rec).Get("code"), "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, body)
	}
	claims := e.verifyJWT(body["id_token"].(string))
	if claims["email"] != "alice@example.com" || claims["acr"] != "urn:loa:2" || claims["phone_number"] != nil {
		t.Fatalf("ID token claims = %v", claims)
	}
	info := e.userInfo(body["access_token"].(string))
	if info["phone_number"] != "+1 555 0100" || info["email"] != nil {
		t.Fatalf("userinfo = %v", info)
	}
}

func TestIDTokenScopeClaims(t *testing.T) {
	e := newEnv(t, func(c *grantor.Config) { c.IDTokenScopeClaims = true })
	e.registerClients()
	body := e.tokensFor(confidentialClient, "openid email")
	if claims := e.verifyJWT(body["id_token"].(string)); claims["email"] != "alice@example.com" {
		t.Fatalf("ID token claims = %v", claims)
	}
}

func TestIDTokenHint(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	body := e.tokensFor(confidentialClient, "openid")
	hint := body["id_token"].(string)

	e.clock.Advance(2 * time.Hour) // expired hints are still valid hints
	q := authParams(confidentialClient, "openid", pkcePair{})
	q.Set("id_token_hint", hint)
	q.Set("prompt", "none")
	req := e.startAuthorization(q)
	if req.IDTokenHintSubject != "alice" {
		t.Fatalf("IDTokenHintSubject = %q", req.IDTokenHintSubject)
	}
	if _, err := e.approve(req.ID, grantor.Approval{Subject: "bob", Scopes: req.Scopes, AuthTime: e.clock.Now()}); err == nil {
		t.Fatal("Approve accepted a subject that differs from id_token_hint")
	}

	// A hint issued to another client is rejected.
	q = authParams(postClient, "openid", pkcePair{})
	q.Set("id_token_hint", hint)
	if p := redirectParams(t, e.get(grantor.PathAuthorization, q)); p.Get("error") != "invalid_request" {
		t.Fatalf("hint for another client = %v", p)
	}
}

func TestMultipleIssuers(t *testing.T) {
	testKeys(t)
	store := memory.New()
	issuers := map[string]*grantor.Issuer{
		"a.example.com": {URL: "https://a.example.com", Keys: []grantor.SigningKey{{ID: "a", Signer: rsaKey}}},
		"b.example.com": {URL: "https://b.example.com", Keys: []grantor.SigningKey{{ID: "b", Signer: rsaKey}}},
	}
	var pending *grantor.AuthorizationRequest
	p, err := grantor.New(grantor.Config{
		IssuerFor: func(r *http.Request) (*grantor.Issuer, error) {
			if iss, ok := issuers[r.Host]; ok {
				return iss, nil
			}
			return nil, fmt.Errorf("unknown host %q", r.Host)
		},
		Clients: store,
		Storage: store,
		Interact: func(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest) {
			pending = req
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range issuers {
		store.SetClient(iss.URL, grantor.Client{
			ID: "app", SecretHash: grantor.HashSecret(confidentialSecret),
			RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid"},
		})
	}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httpGet("https://c.example.com"+grantor.PathOpenIDConfig))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown issuer = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httpGet("https://b.example.com"+grantor.PathOpenIDConfig))
	var m map[string]any
	json.Unmarshal(rec.Body.Bytes(), &m)
	if m["issuer"] != "https://b.example.com" {
		t.Fatalf("issuer b metadata = %v", m)
	}

	q := authParams("app", "openid", pkcePair{})
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httpGet("https://a.example.com/authorize?"+q.Encode()))
	if pending == nil || pending.Issuer != "https://a.example.com" {
		t.Fatalf("pending = %+v", pending)
	}
	cookies := rec.Result().Cookies()

	// Tenant b cannot complete tenant a's request.
	approveAt := func(host string) (*httptest.ResponseRecorder, error) {
		req := httptest.NewRequest(http.MethodPost, "https://"+host+"/login", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		return rec, p.Approve(rec, req, pending.ID, grantor.Approval{Subject: "alice", Scopes: []string{"openid"}, AuthTime: time.Now()})
	}
	if _, err := approveAt("b.example.com"); !errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
		t.Fatalf("cross-tenant Approve = %v", err)
	}
	rec, err = approveAt("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("code")

	exchange := func(host string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {clientRedirect}}
		req := httptest.NewRequest(http.MethodPost, "https://"+host+"/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("app", confidentialSecret)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return rec
	}
	if rec := exchange("b.example.com"); rec.Code != http.StatusBadRequest {
		t.Fatalf("code redeemed at another issuer = %d %s", rec.Code, rec.Body.String())
	}
	rec = exchange("a.example.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange = %d %s", rec.Code, rec.Body.String())
	}
	var tokens map[string]any
	json.Unmarshal(rec.Body.Bytes(), &tokens)

	req := httpGet("https://b.example.com/userinfo")
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("access token accepted by another issuer = %d", rec.Code)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	testKeys(t)
	store := memory.New()
	smallRSA, _ := rsa.GenerateKey(rand.Reader, 1024)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	base := func() grantor.Config {
		return grantor.Config{
			Issuer:   &grantor.Issuer{URL: "https://op.example.com", Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}},
			Clients:  store,
			Storage:  store,
			Interact: func(http.ResponseWriter, *http.Request, *grantor.AuthorizationRequest) {},
		}
	}
	cases := map[string]func(*grantor.Config){
		"http issuer":       func(c *grantor.Config) { c.Issuer.URL = "http://op.example.com" },
		"issuer with query": func(c *grantor.Config) { c.Issuer.URL = "https://op.example.com?x=1" },
		"trailing slash":    func(c *grantor.Config) { c.Issuer.URL = "https://op.example.com/" },
		"no keys":           func(c *grantor.Config) { c.Issuer.Keys = nil },
		"small RSA key":     func(c *grantor.Config) { c.Issuer.Keys[0].Signer = smallRSA },
		"alg mismatch": func(c *grantor.Config) {
			c.Issuer.Keys[0] = grantor.SigningKey{ID: "k", Signer: p384, Algorithm: "ES256"}
		},
		"duplicate kid": func(c *grantor.Config) {
			c.Issuer.Keys = append(c.Issuer.Keys, grantor.SigningKey{ID: "k", Signer: ecKey})
		},
		"no storage":  func(c *grantor.Config) { c.Storage = nil },
		"no interact": func(c *grantor.Config) { c.Interact = nil },
		"issuer and resolver": func(c *grantor.Config) {
			c.IssuerFor = func(*http.Request) (*grantor.Issuer, error) { return nil, nil }
		},
		"redefine openid": func(c *grantor.Config) { c.ScopeClaims = map[string][]string{"openid": {"sub"}} },
	}
	for name, modify := range cases {
		cfg := base()
		modify(&cfg)
		if _, err := grantor.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	cfg := base()
	cfg.Issuer.URL = "http://localhost:8080"
	if _, err := grantor.New(cfg); err != nil {
		t.Errorf("http loopback issuer: %v", err)
	}
}
