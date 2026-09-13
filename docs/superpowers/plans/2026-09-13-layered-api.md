# Layered API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose grantor's protocol steps as a public low-level API and rebuild `Provider.ServeHTTP` on top of it.

**Architecture:** Every endpoint gets an exported `ServeXxx` method; the authorization and token endpoints also get Parse / complete / Write steps. `ServeHTTP` becomes a router over configurable `Config.Endpoints`. A single internal issuance path runs the new `Config.BeforeIssue` hook for built-in and custom grants (`Config.Grants`, `Provider.IssueTokens`).

**Tech Stack:** Go 1.26+, `net/http`, go-jose/v4 (unchanged dependency set).

**Spec:** `docs/superpowers/specs/2026-09-13-layered-api-design.md`

## Global Constraints

- No new module dependencies in the root module.
- Public docs (README, godoc, design docs) must not name other OAuth libraries.
- Every change keeps `go vet ./...` and `go test -race ./...` passing in the root module and in `examples/`.
- Existing behaviour of `ServeHTTP` does not change; the OpenID conformance Basic OP, Config OP and Form Post Basic OP plans keep passing.
- Plain structs and small function types only; no getter/setter interfaces, no strategy or factory types.
- Commit messages end with the session's Co-Authored-By / Claude-Session trailer lines.

---

### Task 1: Error URI and status code

**Files:**
- Modify: `errors.go` (Error struct, statusCode, new `validErrorCode`, `sanitizeURI`)
- Modify: `params.go` (`writeTokenError` → exported `WriteTokenError` in Task 4; here only add `error_uri`)
- Modify: `authorize.go` (`writeAuthorizationError` adds `error_uri`)
- Modify: `userinfo.go` (`bearerToken` uses `StatusCode`, `writeBearerError` adds `error_uri`)
- Test: `lowlevel_test.go` (new)

**Interfaces:**
- Produces: `Error.URI string`, `Error.StatusCode int`, `validErrorCode(code string) bool`, `sanitizeURI(s string) string`.

- [ ] **Step 1: Write the failing test**

```go
func TestErrorURIAndStatus(t *testing.T) {
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
```
(`mustProvider` and `Issuance` arrive in Tasks 2 and 5; this test is added in Task 5. For Task 1 add the unit test below.)

```go
func TestErrorStatusCode(t *testing.T) {
	e := &grantor.Error{Code: "custom", StatusCode: http.StatusTeapot}
	if got := grantor.StatusCodeOf(e); got != http.StatusTeapot {
		t.Fatalf("status = %d", got)
	}
}
```
with `export_test.go`: `func StatusCodeOf(e *Error) int { return e.statusCode() }`.

- [ ] **Step 2: Run** `go test -run TestErrorStatusCode .` — expect compile failure (no StatusCode field).
- [ ] **Step 3: Implement** in `errors.go`:

```go
type Error struct {
	Code        string
	Description string
	// URI identifies a web page with information about the error. It is
	// sent as error_uri.
	URI string
	// StatusCode is the HTTP status of token endpoint and other JSON error
	// responses. Zero selects the status RFC 6749 and RFC 6750 define for
	// Code.
	StatusCode int

	cause error
}

func (e *Error) statusCode() int {
	if e.StatusCode != 0 {
		return e.StatusCode
	}
	// ...existing switch...
}

// validErrorCode reports whether code only uses the characters RFC 6749
// allows in error codes (%x20-21 / %x23-5B / %x5D-7E).
func validErrorCode(code string) bool {
	if code == "" {
		return false
	}
	for i := 0; i < len(code); i++ {
		if c := code[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// sanitizeURI removes characters RFC 6749 does not allow in error_uri
// (%x21 / %x23-5B / %x5D-7E).
func sanitizeURI(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, s)
}
```
Replace `&Error{status: http.StatusUnauthorized}` in `userinfo.go` with `&Error{StatusCode: http.StatusUnauthorized}`. Add `error_uri` where `error_description` is written (token JSON body, authorization redirect values, Bearer challenge `error_uri="..."`).

- [ ] **Step 4: Run** `go test -race ./...` — PASS.
- [ ] **Step 5: Commit** "Add Error.URI and Error.StatusCode".

### Task 2: Endpoints configuration and ServeXxx methods

**Files:**
- Create: `endpoints.go` (Endpoints type, defaults, validation, `ServeXxx` methods, `withIssuer`)
- Modify: `provider.go` (Config fields, New validation, ServeHTTP routing, Interact optional)
- Modify: `discovery.go` (URLs from endpoints; export `ServeDiscovery`, `ServeJWKS` via endpoints.go)
- Test: `lowlevel_test.go`, `helpers_test.go` (`mustProvider`), `endpoints_test.go` (remove "no interact" case)

**Interfaces:**
- Produces: `type Endpoints struct{ Authorization, Token, UserInfo, Introspection, Revocation, JWKS string }`, `Config.Endpoints`, `(*Provider).ServeAuthorization/ServeToken/ServeUserInfo/ServeIntrospection/ServeRevocation/ServeJWKS/ServeDiscovery(w http.ResponseWriter, r *http.Request)`, `(*resolvedIssuer).endpoint(path string) string` (unchanged), `(*Provider).endpointURL(iss *resolvedIssuer, path string) string`.
- Test helper: `func mustProvider(t *testing.T, e *env, opts ...envOption) *grantor.Provider` rebuilds the provider for `e` with extra options.

- [ ] **Step 1: Write the failing test** (`lowlevel_test.go`)

```go
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
	mux.HandleFunc("/oauth2/keys", e.p.ServeJWKS)
	mux.HandleFunc("/.well-known/openid-configuration", e.p.ServeDiscovery)
	e.handler = mux

	m := decodeJSON(t, e.get("/.well-known/openid-configuration", nil))
	if m["token_endpoint"] != testIssuer+"/oauth2/token" || m["jwks_uri"] != testIssuer+"/oauth2/keys" ||
		m["authorization_endpoint"] != testIssuer+"/oauth2/authorize" {
		t.Fatalf("discovery = %v", m)
	}

	pkce := newPKCE()
	q := authParams(publicClient, "openid", pkce)
	e.pending = nil
	rec := e.get("/oauth2/authorize", q)
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
		"well-known": {JWKS: "/.well-known/jwks"},
		"query":      {Token: "/token?x=1"},
	} {
		_, err := grantor.New(grantor.Config{
			Issuer:    &grantor.Issuer{URL: testIssuer, Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}},
			Clients:   store, Storage: store, Endpoints: ep,
		})
		if err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}
```
`env` gains `handler http.Handler` (defaults to `e.p`); `env.do` calls `e.handler.ServeHTTP`. `mustProvider(t, e, opts...)` calls `newEnv`'s construction with the extra options and returns the provider; `newEnv` sets `e.handler = p`.

- [ ] **Step 2: Run** `go test -run 'TestCustomRouterAndPaths|TestEndpointsValidation' .` — compile failure.
- [ ] **Step 3: Implement** `endpoints.go`:

```go
package grantor

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Endpoints are the paths of the protocol endpoints, relative to the issuer
// URL. They are published in the discovery document and routed by
// [Provider.ServeHTTP]. Empty fields use the Path constants.
type Endpoints struct {
	Authorization string
	Token         string
	UserInfo      string
	Introspection string
	Revocation    string
	JWKS          string
}

func (e *Endpoints) setDefaults() {
	for _, f := range []struct {
		field *string
		def   string
	}{
		{&e.Authorization, PathAuthorization}, {&e.Token, PathToken}, {&e.UserInfo, PathUserInfo},
		{&e.Introspection, PathIntrospection}, {&e.Revocation, PathRevocation}, {&e.JWKS, PathJWKS},
	} {
		if *f.field == "" {
			*f.field = f.def
		}
	}
}

func (e *Endpoints) validate() error {
	seen := map[string]bool{}
	for _, path := range []string{e.Authorization, e.Token, e.UserInfo, e.Introspection, e.Revocation, e.JWKS} {
		if !strings.HasPrefix(path, "/") || (&url.URL{Path: path}).EscapedPath() != path {
			return fmt.Errorf("endpoint path %q must start with / and contain only path characters", path)
		}
		if strings.HasPrefix(path, "/.well-known/") {
			return fmt.Errorf("endpoint path %q must not be below /.well-known/", path)
		}
		if seen[path] {
			return fmt.Errorf("endpoint path %q is used twice", path)
		}
		seen[path] = true
	}
	return nil
}

// withIssuer resolves the issuer of r and calls fn, or responds 404.
func (p *Provider) withIssuer(w http.ResponseWriter, r *http.Request, fn func(http.ResponseWriter, *http.Request, *resolvedIssuer)) {
	iss, err := p.issuerFor(r)
	if err != nil {
		p.cfg.Logger.DebugContext(r.Context(), "grantor: no issuer for request", "path", r.URL.Path, "error", err)
		http.NotFound(w, r)
		return
	}
	fn(w, r, iss)
}

// ServeAuthorization serves the authorization endpoint. It parses and saves
// the request and calls Config.Interact.
func (p *Provider) ServeAuthorization(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, p.serveAuthorization)
}

// ServeToken serves the token endpoint.
func (p *Provider) ServeToken(w http.ResponseWriter, r *http.Request) { p.withIssuer(w, r, p.serveToken) }

// ServeUserInfo serves the UserInfo endpoint.
func (p *Provider) ServeUserInfo(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, p.serveUserInfo)
}

// ServeIntrospection serves the token introspection endpoint.
func (p *Provider) ServeIntrospection(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, p.serveIntrospection)
}

// ServeRevocation serves the token revocation endpoint.
func (p *Provider) ServeRevocation(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, p.serveRevocation)
}

// ServeJWKS serves the issuer's public keys.
func (p *Provider) ServeJWKS(w http.ResponseWriter, r *http.Request) { p.withIssuer(w, r, p.serveJWKS) }

// ServeDiscovery serves the OpenID Provider and RFC 8414 metadata document.
func (p *Provider) ServeDiscovery(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, p.serveDiscovery)
}

var errNoInteract = errors.New("Config.Interact is not set")
```
`provider.go`: add `Endpoints Endpoints` to `Config`; in `New` call `cfg.Endpoints.setDefaults()` and `validate()` (wrap error with `grantor: `); remove the `Interact` requirement and document it as required for `ServeAuthorization`. `ServeHTTP` routing switch uses `e := p.cfg.Endpoints` fields instead of the Path constants. `discovery.go` uses `iss.endpoint(p.cfg.Endpoints.Xxx)`. `serveAuthorization` checks `p.cfg.Interact == nil` and renders `ErrorPage` with `errServer(errNoInteract)`.

- [ ] **Step 4: Run** `go test -race ./...` — PASS (after removing the "no interact" case from `TestNewValidatesConfig`).
- [ ] **Step 5: Commit** "Add configurable endpoints and per-endpoint Serve methods".

### Task 3: Authorization building blocks

**Files:**
- Modify: `authorize.go` (Parse/WriteAuthorizationError/Save/serveAuthorization, Extra, authorizationError)
- Create: `approve.go` (Approve, Deny, completable, loadPending, checkRequest, sameProtocolFields, binding helpers; moved from authorize.go)
- Modify: `pkce.go` (`checkPKCEPolicy`)
- Modify: `records.go` (`Extra`)
- Modify: `params.go` (`parseForm(r *http.Request)` without writer)
- Modify: `storagetest/storagetest.go` (Extra round trip)
- Modify tests: every `e.approve(req.ID, …)`/`e.deny(req.ID, …)` → `e.approve(req, …)`/`e.deny(req, …)`; `TestInteractionBinding` loads through `AuthorizationRequest` from the other browser.
- Modify: `examples/internal/opapp/opapp.go` (Approve/Deny pass `req`)
- Test: `lowlevel_test.go`

**Interfaces:**
- Consumes: `Endpoints` (Task 2), `Error.URI` (Task 1).
- Produces:
  - `func (p *Provider) ParseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error)`
  - `func (p *Provider) WriteAuthorizationError(w http.ResponseWriter, r *http.Request, err error)`
  - `func (p *Provider) SaveAuthorizationRequest(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) error`
  - `func (p *Provider) Approve(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, a Approval) error`
  - `func (p *Provider) Deny(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, reason *Error) error`
  - `var ErrAuthorizationRequestModified error`
  - `AuthorizationRequest.Extra map[string]string`

- [ ] **Step 1: Write the failing tests** (`lowlevel_test.go`)

```go
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
		// Policy: this deployment never grants email, and a tenant parameter
		// selects the realm.
		req.Scopes = slices.DeleteFunc(req.Scopes, func(s string) bool { return s == "email" })
		if req.Extra["tenant"] == "blocked" {
			if err := e.p.Deny(w, r, req, &grantor.Error{Code: "tenant_blocked", URI: "https://op.example.com/blocked"}); err != nil {
				t.Errorf("Deny: %v", err)
			}
			return
		}
		if r.URL.Query().Get("login_hint") == "trusted" {
			// Complete immediately without saving.
			if err := e.p.Approve(w, r, req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); err != nil {
				t.Errorf("Approve: %v", err)
			}
			return
		}
		if err := e.p.SaveAuthorizationRequest(w, r, req); err != nil {
			t.Errorf("Save: %v", err)
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
		t.Fatalf("Approve saved: %v", err)
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
			t.Fatal(err)
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
	} {
		req := parse()
		modify(req)
		if err := e.p.Approve(httptest.NewRecorder(), httpGet(testIssuer+"/authorize"), req, approval); err == nil {
			t.Errorf("%s: Approve succeeded", name)
		}
	}
}
```

- [ ] **Step 2: Run** `go test -run 'TestCustomAuthorizationHandler|TestApproveSavedRequestInSameHTTPRequest|TestSavedRequestCannotBeModified|TestUnsavedRequestIsRevalidated' .` — compile failure.
- [ ] **Step 3: Implement.**

`records.go`: add to `AuthorizationRequest` after `Claims`:
```go
	// Extra holds the non-empty request parameters grantor does not process,
	// such as extension parameters.
	Extra map[string]string `json:"extra,omitempty"`
```

`params.go`: `func parseForm(r *http.Request) (params, *Error)` using `http.MaxBytesReader(nil, r.Body, maxBodyBytes)`; update callers.

`authorize.go`:
```go
// authorizationParams are the authorization request parameters grantor
// processes; others are kept in AuthorizationRequest.Extra.
var authorizationParams = map[string]bool{
	"response_type": true, "client_id": true, "redirect_uri": true, "scope": true, "state": true,
	"response_mode": true, "code_challenge": true, "code_challenge_method": true, "nonce": true,
	"display": true, "prompt": true, "max_age": true, "ui_locales": true, "claims_locales": true,
	"id_token_hint": true, "login_hint": true, "acr_values": true, "claims": true,
	"request": true, "request_uri": true,
}

// authorizationError is an error from ParseAuthorizationRequest. A non-nil
// target means it may be redirected to the client.
type authorizationError struct {
	err    *Error
	iss    *resolvedIssuer
	target *authorizationTarget
}

func (e *authorizationError) Error() string { return e.err.Error() }
func (e *authorizationError) Unwrap() error { return e.err }

// ParseAuthorizationRequest validates an authorization request and returns
// it unsaved. Complete it with Approve or Deny, or save it with
// SaveAuthorizationRequest to complete it later. Errors should be written
// with WriteAuthorizationError, which redirects them to the client when
// that is safe.
func (p *Provider) ParseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, &Error{Code: CodeInvalidRequest, Description: "unknown issuer", StatusCode: http.StatusNotFound, cause: err}
	}
	return p.parseAuthorization(r, iss)
}

func (p *Provider) parseAuthorization(r *http.Request, iss *resolvedIssuer) (*AuthorizationRequest, error) {
	var q params
	switch r.Method {
	case http.MethodGet:
		q = newParams(r.URL.Query())
	case http.MethodPost:
		var perr *Error
		if q, perr = parseForm(r); perr != nil {
			return nil, &authorizationError{err: perr, iss: iss}
		}
	default:
		return nil, &authorizationError{err: &Error{Code: CodeInvalidRequest, Description: "method not allowed", StatusCode: http.StatusMethodNotAllowed}, iss: iss}
	}
	client, target, perr := p.authorizationTarget(r.Context(), iss, q)
	if perr != nil {
		return nil, &authorizationError{err: perr, iss: iss}
	}
	req, perr := p.parseAuthorizationRequest(iss, client, q, target)
	if perr != nil {
		return nil, &authorizationError{err: perr, iss: iss, target: target}
	}
	return req, nil
}

// WriteAuthorizationError writes an error for an authorization request:
// errors from ParseAuthorizationRequest that are safe to redirect go to the
// client; everything else is rendered with Config.ErrorPage.
func (p *Provider) WriteAuthorizationError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *authorizationError
	if errors.As(err, &ae) && ae.target != nil {
		if ae.err.Code == CodeServerError {
			p.logError(r.Context(), "authorization endpoint", ae.err)
		}
		p.writeAuthorizationError(w, r, ae.iss, ae.target, ae.err)
		return
	}
	e := asProtocolError(err)
	if e.Code == CodeServerError {
		p.logError(r.Context(), "authorization endpoint", err)
	}
	p.cfg.ErrorPage(w, r, e)
}

// SaveAuthorizationRequest stores a request returned by
// ParseAuthorizationRequest so that it can be completed later, typically
// after a login page. It assigns req.ID and binds the request to the user
// agent with a cookie. Changes to req must be made before saving.
func (p *Provider) SaveAuthorizationRequest(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) error {
	iss, err := p.issuerFor(r)
	if err != nil {
		return fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	if req.ID != "" {
		return errors.New("grantor: authorization request is already saved")
	}
	client, err := p.client(r.Context(), iss, req.ClientID)
	if err != nil {
		return fmt.Errorf("grantor: look up client: %w", err)
	}
	if err := p.checkRequest(iss, client, req); err != nil {
		return err
	}
	saved := *req
	saved.ID = randomToken()
	saved.Claims = p.claimsForClient(client, saved.Claims)
	var binding string
	if !p.cfg.DisableInteractionBinding {
		binding = randomToken()
		saved.BindingHash = hashToken(binding)
	}
	if err := p.cfg.Storage.CreateAuthorizationRequest(r.Context(), &saved); err != nil {
		return fmt.Errorf("grantor: save authorization request: %w", err)
	}
	if binding != "" {
		http.SetCookie(w, &http.Cookie{
			Name: bindingCookieName(saved.ID, iss.secure), Value: binding, Path: "/",
			MaxAge:   int(p.cfg.Lifetimes.AuthorizationRequest / time.Second),
			Secure:   iss.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	*req = saved
	return nil
}

func (p *Provider) serveAuthorization(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	req, err := p.parseAuthorization(r, iss)
	if err != nil {
		p.WriteAuthorizationError(w, r, err)
		return
	}
	if p.cfg.Interact == nil {
		p.logError(r.Context(), "authorization endpoint", errNoInteract)
		p.cfg.ErrorPage(w, r, errServer(errNoInteract))
		return
	}
	if err := p.SaveAuthorizationRequest(w, r, req); err != nil {
		p.logError(r.Context(), "save authorization request", err)
		p.writeAuthorizationError(w, r, iss, targetOf(req), errServer(err))
		return
	}
	interactReq := r
	if req.BindingHash != "" {
		// The user agent only sends the cookie from its next request on; add
		// it so that AuthorizationRequest works inside Interact.
		interactReq = r.Clone(r.Context())
		if c := bindingFromResponse(w, bindingCookieName(req.ID, iss.secure)); c != "" {
			interactReq.AddCookie(&http.Cookie{Name: bindingCookieName(req.ID, iss.secure), Value: c})
		}
	}
	reqCopy := *req
	p.cfg.Interact(w, interactReq, &reqCopy)
}

func targetOf(req *AuthorizationRequest) *authorizationTarget {
	return &authorizationTarget{redirectURI: req.RedirectURI, mode: req.ResponseMode, state: req.State}
}
```
In `parseAuthorizationRequest`: remove `ID: randomToken()`; collect `Extra`:
```go
	for name, v := range q.values {
		if !authorizationParams[name] {
			if req.Extra == nil {
				req.Extra = map[string]string{}
			}
			req.Extra[name] = v
		}
	}
```
Replace the PKCE policy branch of `parsePKCE` with a call to `checkPKCEPolicy(client, req)`:
```go
// checkPKCEPolicy reports whether a request without a code challenge is
// allowed by the client's PKCE policy.
func checkPKCEPolicy(client *Client, req *AuthorizationRequest) *Error {
	switch client.pkcePolicy() {
	case PKCEOptional:
		return nil
	case PKCEUnlessNonce:
		if req.IsOpenID() && req.Nonce != "" {
			return nil
		}
	}
	return errInvalidRequest("code_challenge is required")
}
```

`approve.go` (moved `Approve`, `Deny`, `completeRequest`, `validateApproval`, `bindingCookieName`, `clearBinding`, `pendingRequest`, `AuthorizationRequest`, `ErrAuthorizationRequestNotFound`, `Approval` from authorize.go, with these changes):
```go
// ErrAuthorizationRequestModified is returned by Approve and Deny when a
// saved request was changed after SaveAuthorizationRequest.
var ErrAuthorizationRequestModified = errors.New("grantor: authorization request was modified after it was saved")

func (p *Provider) AuthorizationRequest(r *http.Request, id string) (*AuthorizationRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	return p.loadPending(nil, r, iss, id)
}

// loadPending loads a saved request and checks its issuer, expiry and
// binding. w may be nil; when set, a binding cookie set on w in this request
// is accepted.
func (p *Provider) loadPending(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer, id string) (*AuthorizationRequest, error) {
	if id == "" {
		return nil, ErrAuthorizationRequestNotFound
	}
	req, err := p.cfg.Storage.AuthorizationRequest(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrAuthorizationRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("grantor: load authorization request: %w", err)
	}
	if req.ID != id || req.Issuer != iss.url || !p.now().Before(req.ExpiresAt) {
		return nil, ErrAuthorizationRequestNotFound
	}
	if req.BindingHash != "" {
		name := bindingCookieName(req.ID, iss.secure)
		value := ""
		if c, err := r.Cookie(name); err == nil {
			value = c.Value
		} else if w != nil {
			value = bindingFromResponse(w, name)
		}
		if value == "" || subtle.ConstantTimeCompare([]byte(hashToken(value)), []byte(req.BindingHash)) != 1 {
			return nil, ErrAuthorizationRequestNotFound
		}
	}
	return req, nil
}

// bindingFromResponse returns the value of a cookie set on w in this request.
func bindingFromResponse(w http.ResponseWriter, name string) string {
	for _, line := range w.Header().Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(line); err == nil && c.Name == name && c.MaxAge >= 0 {
			return c.Value
		}
	}
	return ""
}

// completable returns the request to complete: the stored copy of a saved
// request, or req itself; either way re-validated against the client.
func (p *Provider) completable(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) (*resolvedIssuer, *AuthorizationRequest, error) {
	if req == nil {
		return nil, nil, ErrAuthorizationRequestNotFound
	}
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, nil, fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	current := req
	if req.ID != "" {
		stored, err := p.loadPending(w, r, iss, req.ID)
		if err != nil {
			return nil, nil, err
		}
		if !sameProtocolFields(stored, req) {
			return nil, nil, ErrAuthorizationRequestModified
		}
		current = stored
	} else {
		copied := *req
		current = &copied
		if !p.now().Before(current.ExpiresAt) {
			return nil, nil, ErrAuthorizationRequestNotFound
		}
	}
	client, err := p.client(r.Context(), iss, current.ClientID)
	if err != nil {
		return nil, nil, fmt.Errorf("grantor: look up client: %w", err)
	}
	if err := p.checkRequest(iss, client, current); err != nil {
		return nil, nil, err
	}
	current.Claims = p.claimsForClient(client, current.Claims)
	return iss, current, nil
}

// checkRequest re-validates a request against the client registration and
// provider policy, so that edits by the application cannot weaken security.
func (p *Provider) checkRequest(iss *resolvedIssuer, client *Client, req *AuthorizationRequest) error {
	invalid := func(reason string) error { return errors.New("grantor: invalid authorization request: " + reason) }
	switch {
	case req.Issuer != iss.url:
		return invalid("it belongs to another issuer")
	case req.ClientID != client.ID:
		return invalid("client mismatch")
	case !client.allowsGrant(GrantTypeAuthorizationCode):
		return invalid("the client may not use the authorization code grant")
	case req.ResponseType != "code":
		return invalid("response_type must be code")
	case !client.matchRedirectURI(req.RedirectURI):
		return invalid("redirect URI is not registered")
	}
	switch req.ResponseMode {
	case responseModeQuery, responseModeFragment:
	case responseModeFormPost:
		if !isHTTPURL(req.RedirectURI) {
			return invalid("form_post requires an http or https redirect URI")
		}
	default:
		return invalid("unsupported response mode")
	}
	for _, s := range req.Scopes {
		if !validScopeToken(s) || !slices.Contains(client.Scopes, s) {
			return invalid("scope is not registered for the client")
		}
	}
	if req.CodeChallenge == "" {
		if req.CodeChallengeMethod != "" || checkPKCEPolicy(client, req) != nil {
			return invalid("PKCE is required")
		}
	} else if req.CodeChallengeMethod != "S256" || len(req.CodeChallenge) != 43 || !isUnreserved(req.CodeChallenge) {
		return invalid("malformed code challenge")
	}
	return nil
}

func sameProtocolFields(a, b *AuthorizationRequest) bool {
	return a.Issuer == b.Issuer && a.ClientID == b.ClientID && a.RedirectURI == b.RedirectURI &&
		a.RedirectURIInRequest == b.RedirectURIInRequest && a.ResponseType == b.ResponseType &&
		a.ResponseMode == b.ResponseMode && a.State == b.State && slices.Equal(a.Scopes, b.Scopes) &&
		a.CodeChallenge == b.CodeChallenge && a.CodeChallengeMethod == b.CodeChallengeMethod &&
		a.Nonce == b.Nonce && slices.Equal(a.Prompt, b.Prompt) &&
		(a.MaxAge == nil) == (b.MaxAge == nil) && (a.MaxAge == nil || *a.MaxAge == *b.MaxAge) &&
		a.RequestedSubject == b.RequestedSubject
}

func (p *Provider) Approve(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, a Approval) error {
	iss, req, err := p.completable(w, r, req)
	if err != nil {
		return err
	}
	scopes, claims, err := p.validateApproval(req, &a)
	if err != nil {
		return err
	}
	if req.ID != "" {
		if err := p.completeRequest(r, req); err != nil {
			return err
		}
	}
	// ...issue the code exactly as before, using iss, req, scopes, claims...
}

func (p *Provider) Deny(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, reason *Error) error {
	if reason == nil {
		reason = ErrAccessDenied
	}
	if !validErrorCode(reason.Code) {
		return fmt.Errorf("grantor: %q is not a valid error code", reason.Code)
	}
	iss, req, err := p.completable(w, r, req)
	if err != nil {
		return err
	}
	if req.ID != "" {
		if err := p.completeRequest(r, req); err != nil {
			return err
		}
	}
	p.clearBinding(w, req, iss)
	p.writeAuthorizationError(w, r, iss, targetOf(req), reason)
	return nil
}
```
`storagetest`: add `Extra: map[string]string{"tenant": "acme"}` to `fullAuthorizationRequest`.

Tests: `helpers_test.go` `approve(req *grantor.AuthorizationRequest, a)` and `deny(req, reason)`; replace call sites; in `TestInteractionBinding` replace the other-browser `Approve` with `e.p.Approve(httptest.NewRecorder(), other, &grantor.AuthorizationRequest{ID: req.ID}, …)` and keep expecting `ErrAuthorizationRequestNotFound`; the "Approve inside Interact" block passes `req`; the "Deny accepted a token endpoint error code" assertion becomes an invalid-characters code (`&grantor.Error{Code: "bad\"code"}`). `examples/internal/opapp/opapp.go`: `deny(w, r, req *grantor.AuthorizationRequest, reason)`, `Approve(w, r, req, …)`.

- [ ] **Step 4: Run** `go test -race ./... && (cd examples && go test -race ./...)` — PASS.
- [ ] **Step 5: Commit** "Expose authorization endpoint building blocks".

### Task 4: Token building blocks

**Files:**
- Modify: `token.go` (TokenRequest, TokenResponse, ParseTokenRequest, Exchange, WriteTokenResponse, grants use `*TokenRequest`)
- Modify: `params.go` (`writeTokenError` → exported `WriteTokenError` with `error_uri`)
- Modify: `authorize.go`/`token.go` callers of `validateScopes` (now `[]string`)
- Test: `lowlevel_test.go`

**Interfaces:**
- Consumes: Task 2 `ServeToken` → `serveToken(w, r, iss)`.
- Produces:
  - `type TokenRequest struct { Client *Client; GrantType GrantType; Scopes []string; Form url.Values; iss *resolvedIssuer; clientID string }`
  - `type TokenResponse struct { AccessToken, TokenType string; ExpiresIn int64; RefreshToken, Scope, IDToken string }` with JSON tags
  - `func (p *Provider) ParseTokenRequest(r *http.Request) (*TokenRequest, error)`
  - `func (p *Provider) Exchange(ctx context.Context, req *TokenRequest) (*TokenResponse, error)`
  - `func (p *Provider) WriteTokenResponse(w http.ResponseWriter, resp *TokenResponse)`
  - `func (p *Provider) WriteTokenError(w http.ResponseWriter, r *http.Request, err error)`
  - internal `func (p *Provider) checkTokenRequest(req *TokenRequest) *Error`

- [ ] **Step 1: Write the failing tests**

```go
func TestCustomTokenHandler(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := e.p.ParseTokenRequest(r)
		if err != nil {
			e.p.WriteTokenError(w, r, err)
			return
		}
		if _, ok := req.Form["client_secret"]; ok {
			t.Error("Form exposes client_secret")
		}
		// Policy: the api scope is never granted through this endpoint.
		if req.Scopes != nil {
			req.Scopes = slices.DeleteFunc(req.Scopes, func(s string) bool { return s == "api" })
		}
		resp, err := e.p.Exchange(r.Context(), req)
		if err != nil {
			e.p.WriteTokenError(w, r, err)
			return
		}
		e.p.WriteTokenResponse(w, resp)
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api openid"}}, basic(serviceClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_scope") // openid is still invalid for client credentials
	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK || body["scope"] != nil {
		t.Fatalf("narrowed client credentials = %d %v", status, body)
	}

	code := e.login(authParams(confidentialClient, "openid profile", pkcePair{}), nil)
	e.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := e.p.ParseTokenRequest(r)
		if err != nil {
			e.p.WriteTokenError(w, r, err)
			return
		}
		req.Scopes = []string{"openid"} // narrow the code exchange
		resp, err := e.p.Exchange(r.Context(), req)
		if err != nil {
			e.p.WriteTokenError(w, r, err)
			return
		}
		e.p.WriteTokenResponse(w, resp)
	})
	status, body = e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK || body["scope"] != "openid" {
		t.Fatalf("narrowed code exchange = %d %v", status, body)
	}
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
	other, _ := e.store.Client(context.Background(), testIssuer, resourceServer)
	req.Client = other
	if _, err := e.p.Exchange(context.Background(), req); err == nil {
		t.Fatal("Exchange accepted a replaced client")
	}
}
```
Note the scope expectation: narrowing `api` away leaves an empty non-nil scope set, so the token response has no `scope`.

- [ ] **Step 2: Run** the two tests — compile failure.
- [ ] **Step 3: Implement** in `token.go`:

```go
// TokenRequest is a parsed token request from an authenticated client.
type TokenRequest struct {
	// Client is the authenticated client. It must not be replaced.
	Client    *Client
	GrantType GrantType
	// Scopes is the scope parameter, or nil if it was not sent. It may be
	// narrowed before Exchange.
	Scopes []string
	// Form holds the request parameters except client credentials.
	Form url.Values

	iss      *resolvedIssuer
	clientID string
}

// TokenResponse is a successful token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func (p *Provider) ParseTokenRequest(r *http.Request) (*TokenRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, &Error{Code: CodeInvalidRequest, Description: "unknown issuer", StatusCode: http.StatusNotFound, cause: err}
	}
	req, perr := p.parseToken(r, iss)
	if perr != nil {
		return nil, perr
	}
	return req, nil
}

func (p *Provider) parseToken(r *http.Request, iss *resolvedIssuer) (*TokenRequest, *Error) {
	if r.Method != http.MethodPost {
		return nil, &Error{Code: CodeInvalidRequest, Description: "the token endpoint only accepts POST", StatusCode: http.StatusMethodNotAllowed}
	}
	q, perr := parseForm(r)
	if perr != nil {
		return nil, perr
	}
	if len(q.repeated) > 0 {
		return nil, errInvalidRequest("parameters must not be repeated")
	}
	client, perr := p.authenticateClient(r, iss, q)
	if perr != nil {
		return nil, perr
	}
	if !q.has("grant_type") {
		return nil, errInvalidRequest("grant_type is required")
	}
	req := &TokenRequest{Client: client, GrantType: GrantType(q.get("grant_type")), Form: url.Values{}, iss: iss, clientID: client.ID}
	for name, v := range q.values {
		if name != "client_secret" && name != "client_assertion" {
			req.Form.Set(name, v)
		}
	}
	if q.has("scope") {
		req.Scopes = splitSpaces(q.get("scope"))
		if req.Scopes == nil {
			req.Scopes = []string{}
		}
	}
	return req, nil
}

// checkTokenRequest rejects token requests that were not produced by
// ParseTokenRequest or whose client was replaced.
func checkTokenRequest(req *TokenRequest) *Error {
	if req == nil || req.iss == nil {
		return errServer(errors.New("the TokenRequest was not created by ParseTokenRequest"))
	}
	if req.Client == nil || req.Client.ID != req.clientID {
		return errServer(errors.New("TokenRequest.Client was replaced"))
	}
	return nil
}

func (p *Provider) Exchange(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	resp, perr := p.exchange(ctx, req)
	if perr != nil {
		return nil, perr
	}
	return resp, nil
}

func (p *Provider) exchange(ctx context.Context, req *TokenRequest) (*TokenResponse, *Error) {
	if perr := checkTokenRequest(req); perr != nil {
		return nil, perr
	}
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return p.exchangeAuthorizationCode(ctx, req)
	case GrantTypeRefreshToken:
		return p.exchangeRefreshToken(ctx, req)
	case GrantTypeClientCredentials:
		return p.exchangeClientCredentials(ctx, req)
	}
	return nil, newError(CodeUnsupportedGrantType, "the grant type is not supported")
}

// WriteTokenResponse writes a successful token response.
func (p *Provider) WriteTokenResponse(w http.ResponseWriter, resp *TokenResponse) {
	noStore(w)
	writeJSON(w, http.StatusOK, resp)
}

func (p *Provider) serveToken(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	req, perr := p.parseToken(r, iss)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	resp, perr := p.exchange(r.Context(), req)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	p.WriteTokenResponse(w, resp)
}
```
Grant functions take `(ctx, req *TokenRequest)` and read `req.Form.Get("code")`, `req.Form.Get("redirect_uri")`, `req.Form.Get("code_verifier")`, `req.Form.Get("refresh_token")`, `req.iss`, `req.Client`. Scope handling:
```go
// narrowScopes applies a requested scope to the scopes a grant allows.
func narrowScopes(allowed, requested []string) ([]string, *Error) {
	if requested == nil {
		return allowed, nil
	}
	var out []string
	for _, s := range requested {
		if !slices.Contains(allowed, s) {
			return nil, newError(CodeInvalidScope, "the requested scope exceeds the grant")
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}
```
Code exchange: after `checkClientScopes`, `accessScopes, perr := narrowScopes(t.Scopes, req.Scopes)` before `consume`. Refresh: replace the `q.has("scope")` block with `narrowScopes(t.Scopes, req.Scopes)`. Client credentials: `validateScopes(client, req.Scopes)` with signature `validateScopes(client *Client, scopes []string) ([]string, *Error)`. `params.go`: rename to `WriteTokenError(w, r, err error)` with doc comment and `error_uri`; update callers in introspect.go and revoke.go.

- [ ] **Step 4: Run** `go test -race ./...` — PASS.
- [ ] **Step 5: Commit** "Expose token endpoint building blocks".

### Task 5: Issuance hook and custom grants

**Files:**
- Create: `issue.go` (Grant, Issuance, GrantFunc, IssueTokens, runBeforeIssue)
- Modify: `token.go` (`issueTokens` takes `grantType` and runs the hook; `exchange` dispatches `Config.Grants`)
- Modify: `provider.go` (Config.Grants, Config.BeforeIssue, New validation)
- Modify: `client.go` (`validate` accepts any non-empty grant type)
- Modify: `discovery.go` (`grant_types_supported` includes custom grants)
- Test: `lowlevel_test.go`

**Interfaces:**
- Consumes: `TokenRequest`, `TokenResponse`, `checkTokenRequest` (Task 4).
- Produces: `type GrantFunc func(ctx context.Context, req *TokenRequest) (*TokenResponse, error)`, `type Grant struct{…}`, `type Issuance struct{…}`, `func (p *Provider) IssueTokens(ctx context.Context, req *TokenRequest, g Grant) (*TokenResponse, error)`, `Config.Grants map[GrantType]GrantFunc`, `Config.BeforeIssue func(ctx context.Context, is *Issuance) error`.

- [ ] **Step 1: Write the failing tests**

```go
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
	if status != http.StatusOK || body["id_token"] == nil || body["scope"] != "openid api" {
		t.Fatalf("custom grant = %d %v", status, body)
	}
	if info := e.userInfo(body["access_token"].(string)); info["sub"] != "alice" {
		t.Fatalf("userinfo = %v", info)
	}
	status, body = e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}, "api_key": {"wrong"}}, basic("cli", confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")
	status, body = e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}, "api_key": {"key-for-alice"}}, basic(serviceClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "unauthorized_client")

	m := decodeJSON(t, e.get(grantor.PathOpenIDConfig, nil))
	if !slices.Contains(m["grant_types_supported"].([]any), any(string(apiKeyGrant))) {
		t.Fatalf("grant_types_supported = %v", m["grant_types_supported"])
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
	expectError(t, status, refreshed, http.StatusBadRequest, "invalid_grant")

	status, cc := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("client credentials = %d %v", status, cc)
	}
	want := []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken, grantor.GrantTypeClientCredentials}
	if !slices.Equal(seen, want) {
		t.Fatalf("BeforeIssue saw %v, want %v", seen, want)
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
```

- [ ] **Step 2: Run** the tests — compile failure.
- [ ] **Step 3: Implement** `issue.go`:

```go
package grantor

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// GrantFunc handles a custom grant type at the token endpoint. It decides
// whether access is granted and issues tokens with Provider.IssueTokens.
// Returning an *Error sends it to the client.
type GrantFunc func(ctx context.Context, req *TokenRequest) (*TokenResponse, error)

// Grant describes the access a custom grant issues tokens for.
type Grant struct {
	// Subject identifies the end-user; empty when no end-user is involved.
	Subject string
	// Scopes must be a subset of the client's registered scopes.
	Scopes   []string
	AuthTime time.Time
	ACR      string
	AMR      []string
	// RefreshToken also issues a refresh token. The client must be allowed
	// the refresh_token grant.
	RefreshToken bool
}

// Issuance describes tokens that are about to be issued, for
// Config.BeforeIssue.
type Issuance struct {
	Issuer    string
	GrantType GrantType
	// Client is the client the tokens are issued to. It must not be changed.
	Client  *Client
	GrantID string
	Subject string
	// Scopes are the access token scopes. The hook may remove scopes.
	Scopes   []string
	AuthTime time.Time
	// RefreshToken reports whether a refresh token is issued. The hook may
	// set it to false.
	RefreshToken bool
}

// IssueTokens issues tokens for a custom grant.
func (p *Provider) IssueTokens(ctx context.Context, req *TokenRequest, g Grant) (*TokenResponse, error) {
	if perr := checkTokenRequest(req); perr != nil {
		return nil, perr
	}
	client := req.Client
	if g.Subject != "" {
		if err := validateSubject(g.Subject); err != nil {
			return nil, errServer(err)
		}
	}
	var scopes []string
	for _, s := range g.Scopes {
		if !slices.Contains(client.Scopes, s) {
			return nil, newError(CodeInvalidScope, "the client may not request one of the scopes")
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	if g.Subject == "" && (slices.Contains(scopes, "openid") || slices.Contains(scopes, "offline_access")) {
		return nil, errServer(errors.New("IssueTokens: openid and offline_access need a subject"))
	}
	if g.RefreshToken && !client.allowsGrant(GrantTypeRefreshToken) {
		return nil, errServer(fmt.Errorf("IssueTokens: client %q may not use refresh tokens", client.ID))
	}
	grant := &Token{
		GrantID: randomToken(), Issuer: req.iss.url, ClientID: client.ID,
		Subject: g.Subject, Scopes: scopes, AuthTime: g.AuthTime, ACR: g.ACR, AMR: g.AMR,
	}
	resp, perr := p.issueTokens(ctx, req.iss, client, grant, scopes, g.RefreshToken, "", req.GrantType)
	if perr != nil {
		return nil, perr
	}
	return resp, nil
}

// runBeforeIssue calls Config.BeforeIssue and returns the possibly narrowed
// access scopes and refresh token decision.
func (p *Provider) runBeforeIssue(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, grantType GrantType, scopes []string, withRefresh bool) ([]string, bool, *Error) {
	if p.cfg.BeforeIssue == nil {
		return scopes, withRefresh, nil
	}
	c := *client
	is := &Issuance{
		Issuer: iss.url, GrantType: grantType, Client: &c, GrantID: grant.GrantID,
		Subject: grant.Subject, Scopes: slices.Clone(scopes), AuthTime: grant.AuthTime, RefreshToken: withRefresh,
	}
	if err := p.cfg.BeforeIssue(ctx, is); err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, false, e
		}
		return nil, false, errServer(fmt.Errorf("BeforeIssue: %w", err))
	}
	var narrowed []string
	for _, s := range is.Scopes {
		if !slices.Contains(scopes, s) {
			return nil, false, errServer(fmt.Errorf("BeforeIssue added scope %q", s))
		}
		if !slices.Contains(narrowed, s) {
			narrowed = append(narrowed, s)
		}
	}
	if is.RefreshToken && !withRefresh {
		return nil, false, errServer(errors.New("BeforeIssue enabled a refresh token"))
	}
	return narrowed, is.RefreshToken, nil
}
```
Move the subject checks of `validateApproval` into `validateSubject(subject string) error` and call it from both. `issueTokens` signature gains `grantType GrantType` and starts with `accessScopes, withRefresh, perr := p.runBeforeIssue(...)`. `exchange`: after the built-in switch:
```go
	if fn, ok := p.cfg.Grants[req.GrantType]; ok {
		if !req.Client.allowsGrant(req.GrantType) {
			return nil, newError(CodeUnauthorizedClient, "the client may not use this grant type")
		}
		resp, err := fn(ctx, req)
		if err != nil {
			return nil, asProtocolError(err)
		}
		if resp == nil {
			return nil, errServer(fmt.Errorf("grant %q returned no response", req.GrantType))
		}
		return resp, nil
	}
```
`provider.go` New: for each `Config.Grants` key: reject empty keys, nil functions and the three built-in grant types. `client.go` `validate`: replace the grant-type switch with a check that each grant type is non-empty. `discovery.go`: `GrantTypesSupported` = built-ins followed by sorted `Config.Grants` keys.

- [ ] **Step 4: Run** `go test -race ./...` — PASS; add `TestErrorURIAndStatus` from Task 1 now.
- [ ] **Step 5: Commit** "Add BeforeIssue hook and custom grants".

### Task 6: Example, documentation, verification

**Files:**
- Create: `examples/lowlevel/main.go`, `examples/lowlevel/server.go`, `examples/lowlevel/server_test.go`
- Modify: `README.md` (Low-level API section, quick start `Approve(w, r, req, …)`), `doc.go` (overview of both layers), `docs/design.md` (Architecture section for layers, hook, grants), `examples/conformance` unchanged
- Test: `examples/lowlevel/server_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces: `func newServer(issuer string, logger *slog.Logger) (http.Handler, error)` in package `main`.

- [ ] **Step 1: Write the failing test** (`examples/lowlevel/server_test.go`)

```go
func TestLowLevelServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	defer srv.Close()
	h, err := newServer(srv.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	verifier := oauth2.GenerateVerifier()
	q := url.Values{
		"response_type": {"code"}, "client_id": {"cli"}, "redirect_uri": {"http://127.0.0.1/callback"},
		"scope": {"openid api"}, "state": {"s"}, "code_challenge": {oauth2.S256ChallengeFromVerifier(verifier)},
		"code_challenge_method": {"S256"}, "login_hint": {"alice"},
	}
	resp, err := client.Get(srv.URL + "/oauth2/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	tok := postForm(t, client, srv.URL+"/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"cli"}, "code_verifier": {verifier},
	})
	if tok["access_token"] == nil || tok["scope"] != "openid api" {
		t.Fatalf("token = %v", tok)
	}
	apiKey := postForm(t, client, srv.URL+"/oauth2/token", url.Values{
		"grant_type": {"urn:example:params:oauth:grant-type:api-key"}, "client_id": {"cli"}, "api_key": {"demo-api-key"},
	})
	if apiKey["access_token"] == nil {
		t.Fatalf("api key grant = %v", apiKey)
	}
	q.Set("login_hint", "mallory")
	resp, err = client.Get(srv.URL + "/oauth2/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	loc, _ = url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Fatalf("disabled user = %s", resp.Header.Get("Location"))
	}
}
```
(with a small `postForm` helper decoding JSON). `srv.Config.Handler` is set before the first request.

- [ ] **Step 2: Run** `cd examples && go test ./lowlevel/` — compile failure.
- [ ] **Step 3: Implement** `examples/lowlevel/server.go`: RSA key, memory store with public client `cli` (redirect `http://127.0.0.1/callback`, grants authorization_code + api-key grant, scopes openid api); `http.ServeMux` with `/oauth2/authorize` (parse → deny `access_denied` for `login_hint=mallory` → approve immediately as the login hint user; this example has no login page), `POST /oauth2/token` (`ServeToken`), `/oauth2/userinfo`, `/oauth2/keys`, `/.well-known/openid-configuration`; `Config.Endpoints` with those paths; `Config.Grants` with the API key grant (`demo-api-key` → subject `service-account`, scopes `api`); `Config.BeforeIssue` logging each issuance with the logger. `main.go`: listens on `localhost:9003` with issuer `http://localhost:9003`.
- [ ] **Step 4: Run** full verification:
  - `gofmt -l .` (empty), `go vet ./...`, `go test -race ./...`
  - `cd examples && go vet ./... && go test -race ./...`
  - OpenID conformance plans via `examples/conformance/run.sh` flow (suite containers + conformance provider): Basic OP, Config OP, Form Post Basic OP — no FAILED/WARNING results, exit 0.
- [ ] **Step 5: Update docs** (README "Low-level API" section with the router example and hook/grant snippets; doc.go overview; design.md Architecture), then commit "Add low-level example and document the layered API" and push.
