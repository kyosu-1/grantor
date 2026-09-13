# Pushed Authorization Requests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support RFC 9126 pushed authorization requests: a PAR endpoint, `request_uri` redemption at the authorization endpoint, per-provider and per-client requirements, discovery metadata and low-level building blocks.

**Architecture:** A new `par.go` holds the policy type, the PAR endpoint (parse, push, write, serve) and redemption. Pushed requests are stored with the existing authorization request methods under `par:` IDs. `authorize.go` redeems `request_uri` and enforces the requirement; `approve.go` keeps pushed records out of reach of `AuthorizationRequest`/`Approve`/`Deny`.

**Tech Stack:** Go 1.26 module, standard library, go-jose/v4 (unchanged).

**Spec:** [docs/superpowers/specs/2026-09-14-pushed-authorization-requests-design.md](../specs/2026-09-14-pushed-authorization-requests-design.md)

## Global Constraints

- No new dependencies; `Storage` gains no methods.
- Public docs and commit messages never name other OAuth libraries; write "OAuth 2.1" for the generic protocol.
- Commit messages end with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01AjnCPFuynyhecn9wP1djyo`.
- Work on `main`; push after verification.
- Verification: `go vet ./... && go test -race ./... && (cd examples && go vet ./... && go test -race ./...)`.

---

### Task 1: Configuration, discovery and the PAR endpoint

**Files:**
- Create: `par.go`, `par_test.go`
- Modify: `provider.go` (Config.PAR, Lifetimes, New, route, client), `client.go` (field), `endpoints.go` (Endpoints field, defaults, validate), `records.go` (Pushed, pushedBy), `authorize.go` (parseAuthorizationRequest signature), `discovery.go`, `storage.go` (ID doc), `storagetest/storagetest.go` (fixture)

**Interfaces:**
- Produces: `type PARPolicy string` with `PARDisabled`, `PARAllowed`, `PARRequired`; `Config.PAR`; `Client.RequirePushedAuthorizationRequests bool`; `Endpoints.PushedAuthorization string`; `PathPushedAuthorization = "/par"`; `Lifetimes.PushedAuthorizationRequest time.Duration`; `AuthorizationRequest.Pushed bool` and unexported `pushedBy string`; `type PushedAuthorizationResponse struct { RequestURI string; ExpiresIn int64 }`; `(*Provider).ServePushedAuthorization(w, r)`; `ParsePushedAuthorizationRequest(r) (*AuthorizationRequest, error)`; `PushAuthorizationRequest(r, req) (*PushedAuthorizationResponse, error)`; `WritePushedAuthorizationResponse(w, resp)`; unexported `requestURIPrefix = "urn:ietf:params:oauth:request_uri:"`, `pushedIDPrefix = "par:"`, `(*Provider).parRequired(*Client) bool`; `parseAuthorizationRequest(iss, client, q, target, pushed bool)`.

- [ ] **Step 1: Write failing tests** in `par_test.go`:

```go
package grantor_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

func parEnv(t *testing.T, policy grantor.PARPolicy) *env {
	t.Helper()
	e := newEnv(t, func(c *grantor.Config) { c.PAR = policy })
	e.registerClients()
	return e
}

// push sends form to the PAR endpoint.
func (e *env) push(form url.Values, auth func(*http.Request)) (int, map[string]any, http.Header) {
	e.t.Helper()
	rec := e.postForm(grantor.PathPushedAuthorization, form, auth)
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, rec.Header()
}

func TestPushedAuthorizationEndpoint(t *testing.T) {
	e := parEnv(t, grantor.PARAllowed)
	auth := basic(confidentialClient, confidentialSecret)

	status, body, header := e.push(authParams(confidentialClient, "openid profile", pkcePair{}), auth)
	if status != http.StatusCreated || header.Get("Cache-Control") != "no-store" {
		t.Fatalf("push = %d %v %v", status, body, header)
	}
	uri, _ := body["request_uri"].(string)
	if !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") || len(uri) < len("urn:ietf:params:oauth:request_uri:")+43 || body["expires_in"] != float64(60) {
		t.Fatalf("push response = %v", body)
	}

	for name, tc := range map[string]struct {
		form   url.Values
		auth   func(*http.Request)
		status int
		code   string
	}{
		"no client authentication": {authParams(confidentialClient, "openid", pkcePair{}), nil, http.StatusUnauthorized, "invalid_client"},
		"request_uri in the body":  {withParam(authParams(confidentialClient, "openid", pkcePair{}), "request_uri", uri), auth, http.StatusBadRequest, "invalid_request"},
		"unregistered redirect":    {withParam(authParams(confidentialClient, "openid", pkcePair{}), "redirect_uri", "https://evil.example.com/cb"), auth, http.StatusBadRequest, "invalid_request"},
		"request object":           {withParam(authParams(confidentialClient, "openid", pkcePair{}), "request", "a.b.c"), auth, http.StatusBadRequest, "request_not_supported"},
		"missing client_id":        {withoutParam(authParams(confidentialClient, "openid", pkcePair{}), "client_id"), auth, http.StatusBadRequest, "invalid_request"},
		"mismatched client_id":     {authParams(postClient, "openid", pkcePair{}), auth, http.StatusBadRequest, "invalid_request"},
	} {
		status, body, _ := e.push(tc.form, tc.auth)
		if status != tc.status || body["error"] != tc.code {
			t.Errorf("%s: push = %d %v, want %d %s", name, status, body, tc.status, tc.code)
		}
	}

	// Public clients push with their client_id, as at the token endpoint.
	pkce := newPKCE()
	if status, body, _ := e.push(authParams(publicClient, "openid", pkce), nil); status != http.StatusCreated {
		t.Fatalf("public client push = %d %v", status, body)
	}

	if rec := e.get(grantor.PathPushedAuthorization, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d", rec.Code)
	}
}

func withParam(q url.Values, name, value string) url.Values {
	q = url.Values(maps.Clone(q))
	q.Set(name, value)
	return q
}

func withoutParam(q url.Values, name string) url.Values {
	q = url.Values(maps.Clone(q))
	q.Del(name)
	return q
}

func TestPushedAuthorizationDisabled(t *testing.T) {
	e := parEnv(t, grantor.PARDisabled)
	if rec := e.postForm(grantor.PathPushedAuthorization, authParams(confidentialClient, "openid", pkcePair{}), basic(confidentialClient, confidentialSecret)); rec.Code != http.StatusNotFound {
		t.Fatalf("PAR endpoint while disabled = %d", rec.Code)
	}
	m := decodeJSON(t, e.get(grantor.PathOpenIDConfiguration, nil))
	if _, ok := m["pushed_authorization_request_endpoint"]; ok {
		t.Fatalf("discovery advertises PAR while disabled: %v", m)
	}
	e.store.SetClient(testIssuer, grantor.Client{ID: "par-only", RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid"}, RequirePushedAuthorizationRequests: true})
	status, body, _ := e.push(authParams("par-only", "openid", newPKCE()), nil)
	if status != http.StatusNotFound {
		t.Fatalf("push for a client requiring PAR while disabled = %d %v", status, body)
	}
}

func TestPushedAuthorizationDiscovery(t *testing.T) {
	for policy, required := range map[grantor.PARPolicy]bool{grantor.PARAllowed: false, grantor.PARRequired: true} {
		e := parEnv(t, policy)
		m := decodeJSON(t, e.get(grantor.PathOpenIDConfiguration, nil))
		if m["pushed_authorization_request_endpoint"] != testIssuer+grantor.PathPushedAuthorization {
			t.Errorf("%s: endpoint = %v", policy, m["pushed_authorization_request_endpoint"])
		}
		if got, _ := m["require_pushed_authorization_requests"].(bool); got != required {
			t.Errorf("%s: require_pushed_authorization_requests = %v", policy, m["require_pushed_authorization_requests"])
		}
	}
}

func TestPushedAuthorizationConfigValidation(t *testing.T) {
	testKeys(t)
	store := memory.New()
	for name, modify := range map[string]func(*grantor.Config){
		"unknown policy":      func(c *grantor.Config) { c.PAR = "sometimes" },
		"sub-second lifetime": func(c *grantor.Config) { c.PAR = grantor.PARAllowed; c.Lifetimes.PushedAuthorizationRequest = time.Millisecond },
	} {
		cfg := grantor.Config{Issuer: &grantor.Issuer{URL: testIssuer, Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}}, Clients: store, Storage: store}
		modify(&cfg)
		if _, err := grantor.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

// Applications can parse, adjust and push requests themselves.
func TestPushedAuthorizationLowLevel(t *testing.T) {
	e := parEnv(t, grantor.PARAllowed)
	e.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := e.p.ParsePushedAuthorizationRequest(r)
		if err != nil {
			e.p.WriteTokenError(w, r, err)
			return
		}
		req.Scopes = slices.DeleteFunc(req.Scopes, func(s string) bool { return s == "email" })
		resp, err := e.p.PushAuthorizationRequest(r, req)
		if err != nil {
			e.p.WriteTokenError(w, r, err)
			return
		}
		e.p.WritePushedAuthorizationResponse(w, resp)
	})
	status, body, _ := e.push(authParams(confidentialClient, "openid email", pkcePair{}), basic(confidentialClient, confidentialSecret))
	if status != http.StatusCreated {
		t.Fatalf("custom PAR endpoint = %d %v", status, body)
	}
	e.handler = e.p
	req := e.startAuthorization(url.Values{"client_id": {confidentialClient}, "request_uri": {body["request_uri"].(string)}})
	if !slices.Equal(req.Scopes, []string{"openid"}) || !req.Pushed {
		t.Fatalf("redeemed request = %+v", req)
	}

	// Front-channel requests cannot be pushed.
	r := httpGet(testIssuer + grantor.PathAuthorization + "?" + authParams(confidentialClient, "openid", pkcePair{}).Encode())
	front, err := e.p.ParseAuthorizationRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.PushAuthorizationRequest(r, front); err == nil {
		t.Fatal("PushAuthorizationRequest accepted a request from ParseAuthorizationRequest")
	}
	_ = context.Background
}
```

Add `"maps"` to the imports. `TestPushedAuthorizationLowLevel` also depends on Task 2 (redemption); it is expected to fail until then — write it now, keep it failing through this task, and run only the other tests in Step 4.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go vet .`
Expected: compile errors for `grantor.PARPolicy`, `PathPushedAuthorization` and the new methods.

- [ ] **Step 3: Implement configuration and the endpoint**

`par.go`:

```go
package grantor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// PARPolicy controls pushed authorization requests (RFC 9126).
type PARPolicy string

const (
	// PARDisabled serves no pushed authorization request endpoint and rejects
	// request_uri at the authorization endpoint. It is the default.
	PARDisabled PARPolicy = ""
	// PARAllowed lets clients push authorization requests; requests with all
	// parameters in the URL are still accepted, except from clients with
	// Client.RequirePushedAuthorizationRequests.
	PARAllowed PARPolicy = "allowed"
	// PARRequired accepts authorization requests only through the pushed
	// authorization request endpoint.
	PARRequired PARPolicy = "required"
)

const (
	// requestURIPrefix is the prefix of request_uri values issued by the
	// pushed authorization request endpoint (RFC 9126 section 2.2).
	requestURIPrefix = "urn:ietf:params:oauth:request_uri:"
	// pushedIDPrefix is the prefix of the storage IDs of pushed requests.
	// Pending request IDs are base64url and never contain a colon.
	pushedIDPrefix = "par:"
)

// PushedAuthorizationResponse is a successful response of the pushed
// authorization request endpoint.
type PushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

var errPARDisabled = &Error{Code: CodeInvalidRequest, Description: "pushed authorization requests are not enabled", StatusCode: http.StatusNotFound}

// ServePushedAuthorization serves the pushed authorization request endpoint
// (RFC 9126). Use ParsePushedAuthorizationRequest, PushAuthorizationRequest
// and WritePushedAuthorizationResponse to write one of your own. It
// responds with 404 unless Config.PAR enables pushed authorization requests.
func (p *Provider) ServePushedAuthorization(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, true, p.servePushedAuthorization)
}

func (p *Provider) servePushedAuthorization(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if p.cfg.PAR == PARDisabled {
		p.WriteTokenError(w, r, errPARDisabled)
		return
	}
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	req, perr := p.parsePushedAuthorization(w, r, iss)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	resp, perr := p.pushAuthorization(r.Context(), iss, req)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	p.WritePushedAuthorizationResponse(w, resp)
}

// ParsePushedAuthorizationRequest authenticates the client of a pushed
// authorization request and validates it like an authorization request.
// Adjust the result if needed and store it with PushAuthorizationRequest;
// write errors with WriteTokenError.
func (p *Provider) ParsePushedAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, issuerError(err)
	}
	req, perr := p.parsePushedAuthorization(nil, r, iss)
	if perr != nil {
		return nil, perr
	}
	return req, nil
}

func (p *Provider) parsePushedAuthorization(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) (*AuthorizationRequest, *Error) {
	if p.cfg.PAR == PARDisabled {
		return nil, errPARDisabled
	}
	if r.Method != http.MethodPost {
		return nil, &Error{Code: CodeInvalidRequest, Description: "the pushed authorization request endpoint only accepts POST", StatusCode: http.StatusMethodNotAllowed}
	}
	q, perr := parseForm(w, r)
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
	// RFC 9126 section 2.1: client_id is required, and request_uri must not
	// be pushed.
	switch {
	case q.get("client_id") != client.ID:
		return nil, errInvalidRequest("client_id is required and must identify the authenticated client")
	case q.has("request_uri"):
		return nil, errInvalidRequest("request_uri must not be pushed")
	}
	_, target, perr := p.authorizationTarget(r.Context(), iss, q)
	if perr != nil {
		return nil, perr
	}
	req, perr := p.parseAuthorizationRequest(iss, client, q, target, true)
	if perr != nil {
		return nil, perr
	}
	req.pushedBy = client.ID
	return req, nil
}

// PushAuthorizationRequest validates a request from
// ParsePushedAuthorizationRequest again, stores it and returns the response
// with its request_uri.
func (p *Provider) PushAuthorizationRequest(r *http.Request, req *AuthorizationRequest) (*PushedAuthorizationResponse, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, issuerError(err)
	}
	resp, perr := p.pushAuthorization(r.Context(), iss, req)
	if perr != nil {
		return nil, perr
	}
	return resp, nil
}

func (p *Provider) pushAuthorization(ctx context.Context, iss *resolvedIssuer, req *AuthorizationRequest) (*PushedAuthorizationResponse, *Error) {
	switch {
	case p.cfg.PAR == PARDisabled:
		return nil, errPARDisabled
	case req == nil || req.pushedBy == "" || req.pushedBy != req.ClientID:
		return nil, errServer(errors.New("the AuthorizationRequest was not created by ParsePushedAuthorizationRequest"))
	case req.ID != "":
		return nil, errServer(errors.New("the authorization request is already saved"))
	}
	client, err := p.client(ctx, iss, req.ClientID)
	if err != nil {
		return nil, errServer(fmt.Errorf("look up client: %w", err))
	}
	if err := p.checkRequest(iss, client, req); err != nil {
		return nil, errServer(err)
	}
	ref := randomToken()
	now := p.now()
	pushed := *req
	pushed.ID = pushedIDPrefix + ref
	pushed.Pushed = true
	pushed.parsed = false
	pushed.pushedBy = ""
	pushed.BindingHash = ""
	pushed.Claims = p.claimsForClient(client, pushed.Claims)
	pushed.CreatedAt = now
	pushed.ExpiresAt = now.Add(p.cfg.Lifetimes.PushedAuthorizationRequest)
	if err := p.cfg.Storage.CreateAuthorizationRequest(ctx, &pushed); err != nil {
		return nil, errServer(fmt.Errorf("save pushed authorization request: %w", err))
	}
	return &PushedAuthorizationResponse{
		RequestURI: requestURIPrefix + ref,
		ExpiresIn:  int64(p.cfg.Lifetimes.PushedAuthorizationRequest / time.Second),
	}, nil
}

// WritePushedAuthorizationResponse writes a successful pushed authorization
// response.
func (p *Provider) WritePushedAuthorizationResponse(w http.ResponseWriter, resp *PushedAuthorizationResponse) {
	noStore(w)
	writeJSON(w, http.StatusCreated, resp)
}

// parRequired reports whether authorization requests of client must be
// pushed.
func (p *Provider) parRequired(client *Client) bool {
	return p.cfg.PAR == PARRequired || client.RequirePushedAuthorizationRequests
}
```

Other files:
- `records.go` `AuthorizationRequest`: after `Audience`:

```go
	// Pushed reports whether the request was sent to the pushed authorization
	// request endpoint (RFC 9126).
	Pushed bool `json:"pushed,omitempty"`
```

and next to `parsed`: `pushedBy string // the client that pushed an unsaved request; never stored`.
- `authorize.go` `parseAuthorizationRequest(iss, client, q, target, pushed bool)`: after the `request_uri` check add

```go
	if !pushed && p.parRequired(client) {
		return nil, errInvalidRequest("the client must use pushed authorization requests")
	}
```

set `Pushed: pushed,` in the literal, and update the call in `parseAuthorization` to pass `false`.
- `client.go` `Client`, after `PKCE`:

```go
	// RequirePushedAuthorizationRequests accepts authorization requests of
	// the client only through the pushed authorization request endpoint
	// (RFC 9126). Config.PAR must enable pushed authorization requests.
	RequirePushedAuthorizationRequests bool
```

- `provider.go`: `Config.PAR PARPolicy` with doc "PAR enables pushed authorization requests (RFC 9126). The zero value disables them."; `Lifetimes.PushedAuthorizationRequest time.Duration // default 60 seconds`; in `New` validate `switch cfg.PAR { case PARDisabled, PARAllowed, PARRequired: default: return nil, fmt.Errorf("grantor: unknown Config.PAR %q", cfg.PAR) }`, `setDefault(&cfg.Lifetimes.PushedAuthorizationRequest, time.Minute)` and include it in the "at least a second" loop; in `client()` after `c.validate()`:

```go
	if c.RequirePushedAuthorizationRequests && p.cfg.PAR == PARDisabled {
		return nil, fmt.Errorf("client %q requires pushed authorization requests, which Config.PAR does not enable", c.ID)
	}
```

in `route` add `case e.PushedAuthorization: p.servePushedAuthorization(w, r, iss)`; add `PathPushedAuthorization = "/par"` to the path constants.
- `endpoints.go`: `PushedAuthorization string` field, default `PathPushedAuthorization` in `setDefaults`, included in `validate`.
- `discovery.go`: fields

```go
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests,omitempty"`
```

set with `if p.cfg.PAR != PARDisabled { m.PushedAuthorizationRequestEndpoint = iss.endpoint(p.cfg.Endpoints.PushedAuthorization); m.RequirePushedAuthorizationRequests = p.cfg.PAR == PARRequired }`.
- `storage.go` `CreateAuthorizationRequest` doc: "IDs are ASCII strings of at most 64 bytes."
- `storagetest.fullAuthorizationRequest`: `Pushed: true`, and in `testAuthorizationRequestRoundTrip` also round-trip a copy with `ID: "par:" + randomID()`.

- [ ] **Step 4: Run the tests**

Run: `go test -race -run 'TestPushedAuthorization(Endpoint|Disabled|Discovery|ConfigValidation)' .`
Expected: PASS. `TestPushedAuthorizationLowLevel` still fails (redemption comes in Task 2).

- [ ] **Step 5: Commit** (after the verification command passes except `TestPushedAuthorizationLowLevel`; skip it with `-skip TestPushedAuthorizationLowLevel`)

```bash
git add -A && git commit -m "Add the pushed authorization request endpoint

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AjnCPFuynyhecn9wP1djyo"
```

---

### Task 2: Redemption at the authorization endpoint and the requirement

**Files:**
- Modify: `par.go` (redeemPushedRequest), `authorize.go` (parseAuthorization), `approve.go` (loadPending, sameProtocolFields)
- Test: `par_test.go`

**Interfaces:**
- Consumes: Task 1 names.
- Produces: `(*Provider).redeemPushedRequest(r *http.Request, iss *resolvedIssuer, q params) (*AuthorizationRequest, error)`.

- [ ] **Step 1: Write failing tests** (append to `par_test.go`):

```go
// pushFor pushes an authorization request for confidentialClient and returns
// its request_uri.
func (e *env) pushFor(q url.Values) string {
	e.t.Helper()
	status, body, _ := e.push(q, basic(confidentialClient, confidentialSecret))
	if status != http.StatusCreated {
		e.t.Fatalf("push = %d %v", status, body)
	}
	return body["request_uri"].(string)
}

func TestPushedAuthorizationFlow(t *testing.T) {
	e := parEnv(t, grantor.PARAllowed)
	uri := e.pushFor(authParams(confidentialClient, "openid profile offline_access", pkcePair{}))

	// Only client_id and request_uri count; other parameters are ignored.
	q := url.Values{"client_id": {confidentialClient}, "request_uri": {uri}, "scope": {"openid email"}, "state": {"changed"}, "redirect_uri": {"https://evil.example.com/cb"}}
	req := e.startAuthorization(q)
	if !req.Pushed || req.State != "xyz" || !slices.Equal(req.Scopes, []string{"openid", "profile", "offline_access"}) || req.RedirectURI != clientRedirect || req.ID == "" {
		t.Fatalf("redeemed request = %+v", req)
	}
	if _, err := e.p.AuthorizationRequest(e.appRequest(http.MethodGet, "/login"), req.ID); err != nil {
		t.Fatalf("saved redeemed request: %v", err)
	}
	rec, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, Audience: req.Audience, AuthTime: e.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	params := redirectParams(t, rec)
	if params.Get("state") != "xyz" {
		t.Fatalf("authorization response = %v", params)
	}
	status, body := e.exchangeCode(confidentialClient, params.Get("code"), "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK || body["id_token"] == nil || body["refresh_token"] == nil {
		t.Fatalf("token exchange = %d %v", status, body)
	}

	// A request_uri is single-use.
	if rec := e.get(grantor.PathAuthorization, url.Values{"client_id": {confidentialClient}, "request_uri": {uri}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request_uri") {
		t.Fatalf("reused request_uri = %d %s", rec.Code, rec.Body.String())
	}
}

func TestPushedAuthorizationRedemptionErrors(t *testing.T) {
	e := parEnv(t, grantor.PARAllowed)
	errorPage := func(name string, q url.Values, code string) {
		t.Helper()
		rec := e.get(grantor.PathAuthorization, q)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %q %s, want error page %s", name, rec.Code, rec.Header().Get("Location"), rec.Body.String(), code)
		}
	}

	uri := e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))
	errorPage("unknown request_uri", url.Values{"client_id": {confidentialClient}, "request_uri": {"urn:ietf:params:oauth:request_uri:unknown"}}, "invalid_request_uri")
	errorPage("missing client_id", url.Values{"request_uri": {uri}}, "invalid_request")
	errorPage("another client", url.Values{"client_id": {postClient}, "request_uri": {uri}}, "invalid_request_uri")
	// The mismatch did not consume the request_uri.
	e.startAuthorization(url.Values{"client_id": {confidentialClient}, "request_uri": {uri}})

	uri = e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))
	e.clock.Advance(61 * time.Second)
	errorPage("expired", url.Values{"client_id": {confidentialClient}, "request_uri": {uri}}, "invalid_request_uri")

	// The client registration is checked again when the request is redeemed.
	uri = e.pushFor(authParams(confidentialClient, "openid profile", pkcePair{}))
	c, _ := e.store.Client(context.Background(), testIssuer, confidentialClient)
	registered := *c
	c.Scopes = []string{"openid"}
	e.store.SetClient(testIssuer, *c)
	rec := e.get(grantor.PathAuthorization, url.Values{"client_id": {confidentialClient}, "request_uri": {uri}})
	if p := redirectParams(t, rec); p.Get("error") != "invalid_request" || p.Get("state") != "xyz" {
		t.Errorf("scope removed after push: %v", p)
	}
	e.store.SetClient(testIssuer, registered)
	uri = e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))
	c.Scopes, c.RedirectURIs = registered.Scopes, []string{"https://client.example.com/other"}
	e.store.SetClient(testIssuer, *c)
	errorPage("redirect URI removed after push", url.Values{"client_id": {confidentialClient}, "request_uri": {uri}}, "invalid_request")
	e.store.SetClient(testIssuer, registered)

	// A client cannot use its request_uri reference as a pending request ID.
	uri = e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))
	ref := strings.TrimPrefix(uri, "urn:ietf:params:oauth:request_uri:")
	for _, id := range []string{"par:" + ref, ref, uri} {
		if _, err := e.p.AuthorizationRequest(e.appRequest(http.MethodGet, "/login"), id); !errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
			t.Errorf("AuthorizationRequest(%q) = %v", id, err)
		}
	}
}

func TestPushedAuthorizationRequired(t *testing.T) {
	e := parEnv(t, grantor.PARRequired)
	rec := e.get(grantor.PathAuthorization, authParams(confidentialClient, "openid", pkcePair{}))
	if p := redirectParams(t, rec); p.Get("error") != "invalid_request" {
		t.Fatalf("plain request with PAR required = %v", p)
	}
	e.startAuthorization(url.Values{"client_id": {confidentialClient}, "request_uri": {e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))}})

	e = parEnv(t, grantor.PARAllowed)
	c, _ := e.store.Client(context.Background(), testIssuer, confidentialClient)
	c.RequirePushedAuthorizationRequests = true
	e.store.SetClient(testIssuer, *c)
	rec = e.get(grantor.PathAuthorization, authParams(confidentialClient, "openid", pkcePair{}))
	if p := redirectParams(t, rec); p.Get("error") != "invalid_request" {
		t.Fatalf("plain request from a client requiring PAR = %v", p)
	}
	e.startAuthorization(authParams(publicClient, "openid", newPKCE())) // other clients are unaffected
}

func TestRequestURIWithoutPAR(t *testing.T) {
	e := parEnv(t, grantor.PARDisabled)
	q := withParam(authParams(confidentialClient, "openid", pkcePair{}), "request_uri", "urn:ietf:params:oauth:request_uri:x")
	if p := redirectParams(t, e.get(grantor.PathAuthorization, q)); p.Get("error") != "request_uri_not_supported" {
		t.Fatalf("request_uri while PAR is disabled = %v", p)
	}
}
```

Add `"errors"` to the imports and remove the `_ = context.Background` line from Task 1's test.

- [ ] **Step 2: Run to verify failure**

Run: `go test -run 'TestPushedAuthorization|TestRequestURIWithoutPAR' .`
Expected: FAIL — `request_uri` is rejected with `request_uri_not_supported`.

- [ ] **Step 3: Implement redemption**

`par.go`:

```go
// redeemPushedRequest returns the pushed authorization request that an
// authorization request refers to with request_uri, after deleting it so
// that it cannot be used again. Only client_id and request_uri of the
// authorization request are read (RFC 9126 section 4).
func (p *Provider) redeemPushedRequest(r *http.Request, iss *resolvedIssuer, q params) (*AuthorizationRequest, error) {
	ctx := r.Context()
	page := func(perr *Error) error { return &authorizationError{err: perr, iss: iss} }
	invalidURI := page(newError(CodeInvalidRequestURI, "request_uri is invalid, expired or already used"))

	if q.isRepeated("client_id") || q.isRepeated("request_uri") {
		return nil, page(errInvalidRequest("client_id and request_uri must not be repeated"))
	}
	clientID := q.get("client_id")
	if clientID == "" {
		return nil, page(errInvalidRequest("client_id is required"))
	}
	ref, ok := strings.CutPrefix(q.get("request_uri"), requestURIPrefix)
	if !ok || ref == "" {
		return nil, invalidURI
	}
	pushed, err := p.cfg.Storage.AuthorizationRequest(ctx, pushedIDPrefix+ref)
	if errors.Is(err, ErrNotFound) {
		return nil, invalidURI
	}
	if err != nil {
		return nil, page(errServer(fmt.Errorf("load pushed authorization request: %w", err)))
	}
	if pushed.ID != pushedIDPrefix+ref || !pushed.Pushed || pushed.Issuer != iss.url || pushed.ClientID != clientID || !p.now().Before(pushed.ExpiresAt) {
		return nil, invalidURI
	}
	switch err := p.cfg.Storage.DeleteAuthorizationRequest(ctx, pushed.ID); {
	case errors.Is(err, ErrNotFound):
		return nil, invalidURI
	case err != nil:
		return nil, page(errServer(fmt.Errorf("delete pushed authorization request: %w", err)))
	}

	// The client registration may have changed since the request was pushed
	// (RFC 9126 section 7.4).
	client, err := p.client(ctx, iss, clientID)
	if errors.Is(err, ErrNotFound) {
		return nil, page(errInvalidRequest("the client is not registered"))
	}
	if err != nil {
		return nil, page(errServer(err))
	}
	if err := p.checkDelivery(iss, client, pushed); err != nil {
		return nil, page(errInvalidRequest("the pushed request no longer matches the client registration"))
	}
	if err := p.checkRequest(iss, client, pushed); err != nil {
		return nil, &authorizationError{err: errInvalidRequest("the pushed request no longer matches the client registration"), iss: iss, target: targetOf(pushed)}
	}

	now := p.now()
	req := *pushed
	req.ID = ""
	req.parsed = true
	req.CreatedAt = now
	req.ExpiresAt = now.Add(p.cfg.Lifetimes.AuthorizationRequest)
	return &req, nil
}
```

(Add `"strings"` to the imports.)

`authorize.go` `parseAuthorization`, after the method switch and before `authorizationTarget`:

```go
	if p.cfg.PAR != PARDisabled && q.has("request_uri") {
		return p.redeemPushedRequest(r, iss, q)
	}
```

`approve.go` `loadPending`: `if id == "" || strings.HasPrefix(id, pushedIDPrefix) { return nil, ErrAuthorizationRequestNotFound }` (add `"strings"` import); `sameProtocolFields`: add `a.Pushed == b.Pushed &&`.

- [ ] **Step 4: Verify**

Run: `go test -race -run 'TestPushedAuthorization|TestRequestURIWithoutPAR' .` — Expected: PASS. Then the verification command — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "Redeem pushed authorization requests and enforce PAR requirements

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AjnCPFuynyhecn9wP1djyo"
```

---

### Task 3: Documentation, example, review and push

**Files:**
- Modify: `README.md`, `docs/design.md`, `doc.go`, `CHANGELOG.md`, `examples/lowlevel/server.go`, `examples/lowlevel/server_test.go`, `example_test.go`

- [ ] **Step 1: Low-level example uses PAR**

In `examples/lowlevel/server.go`: `PAR: grantor.PARAllowed`, `Endpoints.PushedAuthorization: "/oauth2/par"`, and `mux.HandleFunc("POST /oauth2/par", provider.ServePushedAuthorization)`. In `server_test.go` add a test that pushes `client_id=cli&response_type=code&redirect_uri=http://127.0.0.1/callback&scope=openid api&code_challenge=…&login_hint=alice` with `client_id=cli` (public client, PKCE), follows `/oauth2/authorize?client_id=cli&request_uri=…` to the redirect, exchanges the code and checks the access token. Read the existing test first and reuse its helpers.

- [ ] **Step 2: Example function**

`example_test.go`: `ExampleProvider_ParsePushedAuthorizationRequest` — a custom PAR endpoint that narrows scopes by policy before `PushAuthorizationRequest`, writing errors with `WriteTokenError`.

- [ ] **Step 3: Docs**

- `README.md`: Features list gains "**Pushed authorization requests** (RFC 9126), optional or required per provider or client"; a "Pushed authorization requests" section showing `Config.PAR`, `Client.RequirePushedAuthorizationRequests` and the flow; Specifications table row `[RFC 9126: OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)` | "PAR endpoint, `request_uri` at the authorization endpoint, `require_pushed_authorization_requests`"; remove PAR from the Roadmap.
- `docs/design.md`: a "Pushed authorization requests" subsection covering P2–P6 and P11; remove "Pushed authorization requests" from "Not yet implemented".
- `doc.go`: add RFC 9126 to the supported specifications.
- `CHANGELOG.md`: add `## [Unreleased]` with `### Added` "Pushed authorization requests (RFC 9126): `Config.PAR`, `Client.RequirePushedAuthorizationRequests`, the PAR endpoint and its building blocks, and `AuthorizationRequest.Pushed`." and `### Changed` "`Storage` documents that authorization request IDs are at most 64 bytes."

- [ ] **Step 4: Verify, review, conformance**

Run the verification command and `gofmt -l .`. Dispatch a code reviewer (superpowers:requesting-code-review) for the range from the spec commit to HEAD; fix Critical and Important findings with tests. Push; both CI workflows (including the OpenID conformance plans, which exercise the changed authorization endpoint) must pass.

- [ ] **Step 5: Commit and push**

```bash
git add -A && git commit -m "Document pushed authorization requests and use them in the low-level example

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AjnCPFuynyhecn9wP1djyo"
git push origin main
```
