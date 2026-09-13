package grantor_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/kyosu-1/grantor"
)

func apiClient(format grantor.AccessTokenFormat) grantor.Client {
	return grantor.Client{
		ID: "api-client", SecretHash: grantor.HashClientSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
		GrantTypes:        []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes:            []string{"openid", "api", "offline_access"},
		Audience:          []string{"https://a.example.com", "https://b.example.com"},
		AccessTokenFormat: format, PKCE: grantor.PKCEOptional,
	}
}

// authorizeHandler serves the authorization endpoint with fn instead of
// Config.Interact.
func (e *env) authorizeHandler(fn func(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := e.p.ParseAuthorizationRequest(r)
		if err != nil {
			e.p.WriteAuthorizationError(w, r, err)
			return
		}
		fn(w, r, req)
	})
}

// Filtering a list down to nothing yields nil in Go, so nil must never grant
// more than an empty list.
func TestApprovalAudienceNilMeansNone(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, apiClient(""))
	req := e.startAuthorization(authParams("api-client", "openid api", pkcePair{}))
	if !slices.Equal(req.Audience, []string{"https://a.example.com", "https://b.example.com"}) {
		t.Fatalf("request audience = %v, want the client audience", req.Audience)
	}
	for name, audience := range map[string][]string{"nil": nil, "empty": {}} {
		req := e.startAuthorization(authParams("api-client", "openid api", pkcePair{}))
		rec, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: audience})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		status, body := e.exchangeCode("api-client", redirectParams(t, rec).Get("code"), "", basic("api-client", confidentialSecret))
		if status != http.StatusOK {
			t.Fatalf("%s: exchange = %d %v", name, status, body)
		}
		if info := e.introspect(body["access_token"].(string), "api-client"); info["aud"] != nil {
			t.Errorf("%s audience granted %v, want none", name, info["aud"])
		}
	}
}

func TestApprovalValidationErrors(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, apiClient(grantor.AccessTokenFormatJWT))
	req := e.startAuthorization(authParams("api-client", "openid api", pkcePair{}))
	for name, a := range map[string]grantor.Approval{
		"JWT client without audience": {Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()},
		"audience not requested":      {Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: []string{"https://c.example.com"}},
		"no subject":                  {Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: req.Audience},
		"scope not requested":         {Subject: "alice", Scopes: []string{"openid", "offline_access"}, AuthTime: e.clock.Now(), Audience: req.Audience},
	} {
		if _, err := e.approve(req, a); !errors.Is(err, grantor.ErrInvalidApproval) {
			t.Errorf("%s: Approve = %v, want ErrInvalidApproval", name, err)
		}
	}
	if _, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: req.Audience}); err != nil {
		t.Fatalf("valid approval after rejected ones: %v", err)
	}

	// An unsaved request cannot be widened beyond the client registration.
	called := false
	e.handler = e.authorizeHandler(func(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest) {
		called = true
		req.Audience = append(req.Audience, "https://evil.example.com")
		err := e.p.Approve(w, r, req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: req.Audience})
		if !errors.Is(err, grantor.ErrInvalidAuthorizationRequest) {
			t.Errorf("widened unsaved request: Approve = %v, want ErrInvalidAuthorizationRequest", err)
		}
		if err := e.p.SaveAuthorizationRequest(w, r, req); !errors.Is(err, grantor.ErrInvalidAuthorizationRequest) {
			t.Errorf("widened unsaved request: SaveAuthorizationRequest = %v, want ErrInvalidAuthorizationRequest", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	e.get(grantor.PathAuthorization, authParams("api-client", "openid api", pkcePair{}))
	if !called {
		t.Fatal("authorization handler was not called")
	}
}

// Narrowing TokenRequest.Scopes, as a custom token endpoint might try, must
// fail loudly instead of being ignored.
func TestTokenRequestScopesAreReadOnly(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.handler = e.tokenHandler(func(req *grantor.TokenRequest) {
		req.Scopes = slices.DeleteFunc(req.Scopes, func(s string) bool { return s == "api" })
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
}

func TestBeforeIssueSeesTokenRequest(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	var encodedGrantType grantor.GrantType
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{
			"recording": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				encodedGrantType = at.GrantType
				return "rec_" + at.ID, nil
			},
		}
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			if is.Request == nil || is.Request.GrantType != is.GrantType {
				t.Errorf("Issuance.Request = %+v", is.Request)
				return nil
			}
			if drop := is.Request.Form.Get("drop"); drop != "" {
				is.Scopes = slices.DeleteFunc(is.Scopes, func(s string) bool { return s == drop })
			}
			is.AccessTokenFormat = "recording"
			// Informational fields are copies.
			is.Request.GrantType = "urn:example:changed"
			is.Request.Client.Scopes[0] = "admin"
			is.Client.Scopes[0] = "admin"
			return nil
		}
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}, "drop": {"api"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK || body["scope"] != nil {
		t.Fatalf("narrowed to nothing = %d %v, want no scope", status, body)
	}
	if encodedGrantType != grantor.GrantTypeClientCredentials {
		t.Fatalf("grant type after the hook changed Issuance.Request = %q", encodedGrantType)
	}
	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK || body["scope"] != "api" {
		t.Fatalf("client after the hook changed Issuance.Client = %d %v", status, body)
	}
}

// A saved request is completed from its stored copy; a changed audience is
// reported like any other changed protocol field.
func TestSavedRequestAudienceModified(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, apiClient(""))
	req := e.startAuthorization(authParams("api-client", "openid api", pkcePair{}))
	req.Audience = req.Audience[:1]
	if _, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: req.Audience}); !errors.Is(err, grantor.ErrAuthorizationRequestModified) {
		t.Fatalf("Approve with a changed audience = %v, want ErrAuthorizationRequestModified", err)
	}
}
