package grantor_test

import (
	"encoding/json"
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
