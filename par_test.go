package grantor_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
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

// push sends form to the pushed authorization request endpoint.
func (e *env) push(form url.Values, auth func(*http.Request)) (int, map[string]any, http.Header) {
	e.t.Helper()
	rec := e.postForm(grantor.PathPushedAuthorization, form, auth)
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, rec.Header()
}

func withParam(q url.Values, name, value string) url.Values {
	q = maps.Clone(q)
	q.Set(name, value)
	return q
}

func withoutParam(q url.Values, name string) url.Values {
	q = maps.Clone(q)
	q.Del(name)
	return q
}

func TestPushedAuthorizationEndpoint(t *testing.T) {
	e := parEnv(t, grantor.PARAllowed)
	auth := basic(confidentialClient, confidentialSecret)

	status, body, header := e.push(authParams(confidentialClient, "openid profile", pkcePair{}), auth)
	if status != http.StatusCreated || header.Get("Cache-Control") != "no-store" {
		t.Fatalf("push = %d %v %v", status, body, header)
	}
	const prefix = "urn:ietf:params:oauth:request_uri:"
	uri, _ := body["request_uri"].(string)
	if !strings.HasPrefix(uri, prefix) || len(uri) < len(prefix)+43 || body["expires_in"] != float64(60) {
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
	if status, body, _ := e.push(authParams(publicClient, "openid", newPKCE()), nil); status != http.StatusCreated {
		t.Fatalf("public client push = %d %v", status, body)
	}

	if rec := e.get(grantor.PathPushedAuthorization, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d", rec.Code)
	}
}

func TestPushedAuthorizationDisabled(t *testing.T) {
	e := parEnv(t, grantor.PARDisabled)
	if status, body, _ := e.push(authParams(confidentialClient, "openid", pkcePair{}), basic(confidentialClient, confidentialSecret)); status != http.StatusNotFound {
		t.Fatalf("PAR endpoint while disabled = %d %v", status, body)
	}
	m := decodeJSON(t, e.get(grantor.PathOpenIDConfiguration, nil))
	if _, ok := m["pushed_authorization_request_endpoint"]; ok {
		t.Fatalf("discovery advertises PAR while disabled: %v", m)
	}

	// A client that requires PAR while it is disabled is misconfigured.
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "par-only", RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid"},
		RequirePushedAuthorizationRequests: true,
	})
	if rec := e.get(grantor.PathAuthorization, authParams("par-only", "openid", newPKCE())); rec.Code != http.StatusInternalServerError {
		t.Fatalf("authorization request of a misconfigured client = %d %s", rec.Code, rec.Body.String())
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
		"unknown policy": func(c *grantor.Config) { c.PAR = "sometimes" },
		"sub-second lifetime": func(c *grantor.Config) {
			c.PAR = grantor.PARAllowed
			c.Lifetimes.PushedAuthorizationRequest = time.Millisecond
		},
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
}

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
	q := url.Values{
		"client_id": {confidentialClient}, "request_uri": {uri},
		"scope": {"openid email"}, "state": {"changed"}, "redirect_uri": {"https://evil.example.com/cb"},
	}
	req := e.startAuthorization(q)
	if !req.Pushed || req.State != "xyz" || !slices.Equal(req.Scopes, []string{"openid", "profile", "offline_access"}) || req.RedirectURI != clientRedirect || req.ID == "" {
		t.Fatalf("redeemed request = %+v", req)
	}
	if saved, err := e.p.AuthorizationRequest(e.appRequest(http.MethodGet, "/login"), req.ID); err != nil || !saved.Pushed {
		t.Fatalf("saved redeemed request = %+v, %v", saved, err)
	}
	rec, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, Audience: req.Audience, AuthTime: e.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	params := redirectParams(t, rec)
	if params.Get("state") != "xyz" || params.Get("code") == "" {
		t.Fatalf("authorization response = %v", params)
	}
	status, body := e.exchangeCode(confidentialClient, params.Get("code"), "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK || body["id_token"] == nil || body["refresh_token"] == nil {
		t.Fatalf("token exchange = %d %v", status, body)
	}

	// A request_uri is single-use.
	rec = e.get(grantor.PathAuthorization, url.Values{"client_id": {confidentialClient}, "request_uri": {uri}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request_uri") {
		t.Fatalf("reused request_uri = %d %s", rec.Code, rec.Body.String())
	}
}

func TestPushedAuthorizationRedemptionErrors(t *testing.T) {
	e := parEnv(t, grantor.PARAllowed)
	errorPage := func(name string, q url.Values, code string) {
		t.Helper()
		rec := e.get(grantor.PathAuthorization, q)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %q %s, want an error page with %s", name, rec.Code, rec.Header().Get("Location"), rec.Body.String(), code)
		}
	}
	redeem := func(uri string) url.Values {
		return url.Values{"client_id": {confidentialClient}, "request_uri": {uri}}
	}

	uri := e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))
	errorPage("unknown request_uri", redeem("urn:ietf:params:oauth:request_uri:unknown"), "invalid_request_uri")
	errorPage("other URI scheme", redeem("https://client.example.com/request.jwt"), "invalid_request_uri")
	errorPage("missing client_id", url.Values{"request_uri": {uri}}, "invalid_request")
	errorPage("another client", url.Values{"client_id": {postClient}, "request_uri": {uri}}, "invalid_request_uri")
	// A mismatch does not consume the request_uri.
	e.startAuthorization(redeem(uri))

	uri = e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))
	e.clock.Advance(61 * time.Second)
	errorPage("expired", redeem(uri), "invalid_request_uri")

	// The client registration is checked again when the request is redeemed.
	registered, err := e.store.Client(context.Background(), testIssuer, confidentialClient)
	if err != nil {
		t.Fatal(err)
	}
	uri = e.pushFor(authParams(confidentialClient, "openid profile", pkcePair{}))
	changed := *registered
	changed.Scopes = []string{"openid"}
	e.store.SetClient(testIssuer, changed)
	if p := redirectParams(t, e.get(grantor.PathAuthorization, redeem(uri))); p.Get("error") != "invalid_request" || p.Get("state") != "xyz" {
		t.Errorf("scope removed after the push: %v", p)
	}
	e.store.SetClient(testIssuer, *registered)
	uri = e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))
	changed = *registered
	changed.RedirectURIs = []string{"https://client.example.com/other"}
	e.store.SetClient(testIssuer, changed)
	errorPage("redirect URI removed after the push", redeem(uri), "invalid_request")
	e.store.SetClient(testIssuer, *registered)

	// A client cannot use its request_uri as a pending request ID.
	uri = e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))
	ref := strings.TrimPrefix(uri, "urn:ietf:params:oauth:request_uri:")
	for _, id := range []string{"par:" + ref, ref, uri} {
		if _, err := e.p.AuthorizationRequest(e.appRequest(http.MethodGet, "/login"), id); !errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
			t.Errorf("AuthorizationRequest(%q) = %v, want ErrAuthorizationRequestNotFound", id, err)
		}
	}
	e.startAuthorization(redeem(uri))
}

func TestPushedAuthorizationRequired(t *testing.T) {
	e := parEnv(t, grantor.PARRequired)
	if p := redirectParams(t, e.get(grantor.PathAuthorization, authParams(confidentialClient, "openid", pkcePair{}))); p.Get("error") != "invalid_request" {
		t.Fatalf("plain request with PAR required = %v", p)
	}
	e.startAuthorization(url.Values{"client_id": {confidentialClient}, "request_uri": {e.pushFor(authParams(confidentialClient, "openid", pkcePair{}))}})

	e = parEnv(t, grantor.PARAllowed)
	c, err := e.store.Client(context.Background(), testIssuer, confidentialClient)
	if err != nil {
		t.Fatal(err)
	}
	c.RequirePushedAuthorizationRequests = true
	e.store.SetClient(testIssuer, *c)
	if p := redirectParams(t, e.get(grantor.PathAuthorization, authParams(confidentialClient, "openid", pkcePair{}))); p.Get("error") != "invalid_request" {
		t.Fatalf("plain request from a client that requires PAR = %v", p)
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
