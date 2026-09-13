package grantor_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

func TestServeHTTPIgnoresScopeOnCodeExchange(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	for _, scope := range []string{"openid profile email", "profile"} {
		req := e.startAuthorization(authParams(confidentialClient, "openid profile email", pkcePair{}))
		rec, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: []string{"openid", "profile"}, AuthTime: e.clock.Now()})
		if err != nil {
			t.Fatal(err)
		}
		status, body := e.tokenRequest(url.Values{
			"grant_type": {"authorization_code"}, "code": {redirectParams(t, rec).Get("code")},
			"redirect_uri": {clientRedirect}, "scope": {scope},
		}, basic(confidentialClient, confidentialSecret))
		if status != http.StatusOK || body["scope"] != "openid profile" || body["id_token"] == nil {
			t.Fatalf("scope=%q: %d %v", scope, status, body)
		}
	}
}

func TestTypedNilErrors(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "cli", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{apiKeyGrant}, Scopes: []string{"api"},
	})
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.Grants = map[grantor.GrantType]grantor.GrantFunc{
			apiKeyGrant: func(ctx context.Context, req *grantor.TokenRequest) (*grantor.TokenResponse, error) {
				var e *grantor.Error
				return nil, e
			},
		}
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}}, basic("cli", confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")

	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(context.Context, *grantor.Issuance) error {
			var e *grantor.Error
			return e
		}
	})
	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")

	rec := httptest.NewRecorder()
	var nilErr *grantor.Error
	e.p.WriteTokenError(rec, httpGet(testIssuer+"/token"), nilErr)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("WriteTokenError(nil *Error) = %d", rec.Code)
	}
}

func TestSavedRequestWithClearedIDIsRejected(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	req := e.startAuthorization(authParams(publicClient, "openid", newPKCE()))
	loaded, err := e.p.AuthorizationRequest(e.appRequest(http.MethodGet, "/login"), req.ID)
	if err != nil {
		t.Fatal(err)
	}
	approval := grantor.Approval{Subject: "alice", Scopes: loaded.Scopes, AuthTime: e.clock.Now()}
	for name, forged := range map[string]*grantor.AuthorizationRequest{
		"loaded request with ID cleared":      func() *grantor.AuthorizationRequest { c := *loaded; c.ID = ""; return &c }(),
		"interaction request with ID cleared": func() *grantor.AuthorizationRequest { c := *req; c.ID = ""; return &c }(),
		"request literal": {
			Issuer: testIssuer, ClientID: publicClient, RedirectURI: clientRedirect, ResponseType: "code",
			ResponseMode: "query", Scopes: []string{"openid"}, CodeChallenge: req.CodeChallenge,
			CodeChallengeMethod: "S256", ExpiresAt: e.clock.Now().Add(time.Hour),
		},
	} {
		other := httptest.NewRequest(http.MethodPost, testIssuer+"/login", nil)
		if err := e.p.Approve(httptest.NewRecorder(), other, forged, approval); err == nil {
			t.Errorf("%s: Approve succeeded", name)
		}
	}
	if _, err := e.approve(loaded, approval); err != nil {
		t.Fatalf("Approve of the saved request: %v", err)
	}
}

func TestIssueTokensOutsideExchange(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	parse := func(form string, id string) *grantor.TokenRequest {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, testIssuer+"/token", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(id, confidentialSecret)
		req, err := e.p.ParseTokenRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	ctx := context.Background()
	if _, err := e.p.IssueTokens(ctx, parse("grant_type=authorization_code", serviceClient), grantor.Grant{Scopes: []string{"api"}}); err == nil {
		t.Error("IssueTokens accepted a built-in grant type")
	}
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "cli", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{apiKeyGrant}, Scopes: []string{"openid", "api"},
	})
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.Grants = map[grantor.GrantType]grantor.GrantFunc{apiKeyGrant: func(context.Context, *grantor.TokenRequest) (*grantor.TokenResponse, error) { return nil, nil }}
	})
	if _, err := e.p.IssueTokens(ctx, parse("grant_type="+url.QueryEscape(string(apiKeyGrant)), serviceClient), grantor.Grant{Scopes: []string{"api"}}); err == nil {
		t.Error("IssueTokens accepted a client that may not use the grant type")
	}
	for name, g := range map[string]grantor.Grant{
		"openid without subject": {Scopes: []string{"openid"}},
		"refresh not allowed":    {Subject: "alice", Scopes: []string{"api"}, RefreshToken: true},
		"scope outside client":   {Scopes: []string{"admin"}},
	} {
		if _, err := e.p.IssueTokens(ctx, parse("grant_type="+url.QueryEscape(string(apiKeyGrant)), "cli"), g); err == nil {
			t.Errorf("%s: IssueTokens succeeded", name)
		}
	}

	// Editing the client in place has no effect on what is issued.
	req := parse("grant_type=client_credentials&scope=api", serviceClient)
	req.Client.Scopes = append(req.Client.Scopes, "admin")
	req.Scopes = []string{"admin"}
	if resp, err := e.p.Exchange(ctx, req); err != nil || resp.Scope != "api" {
		t.Errorf("Exchange after editing the request = %+v, %v; want the parsed scope", resp, err)
	}
}

func TestErrorStatusCodeOutOfRange(t *testing.T) {
	if got := (&grantor.Error{Code: grantor.CodeInvalidGrant, StatusCode: 42}).HTTPStatus(); got != http.StatusBadRequest {
		t.Fatalf("status = %d", got)
	}
}

func TestBeforeIssueFailureDoesNotConsumeRefreshToken(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	fail := false
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(context.Context, *grantor.Issuance) error {
			if fail {
				return errors.New("directory unavailable")
			}
			return nil
		}
	})
	tokens := e.tokensFor(confidentialClient, "openid offline_access")
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}}

	fail = true
	status, body := e.tokenRequest(refresh, basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
	fail = false
	if status, body := e.tokenRequest(refresh, basic(confidentialClient, confidentialSecret)); status != http.StatusOK {
		t.Fatalf("retry after a hook failure = %d %v", status, body)
	}
}

func TestBeforeIssueRules(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "cli", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{apiKeyGrant}, Scopes: []string{"api"},
	})
	var seen []grantor.GrantType
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.Grants = map[grantor.GrantType]grantor.GrantFunc{
			apiKeyGrant: func(ctx context.Context, req *grantor.TokenRequest) (*grantor.TokenResponse, error) {
				return e.p.IssueTokens(ctx, req, grantor.Grant{Scopes: []string{"api"}})
			},
		}
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			seen = append(seen, is.GrantType)
			if is.GrantType == grantor.GrantTypeClientCredentials {
				is.RefreshToken = true
			}
			return nil
		}
	})
	if status, body := e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}}, basic("cli", confidentialSecret)); status != http.StatusOK {
		t.Fatalf("custom grant = %d %v", status, body)
	}
	if len(seen) != 1 || seen[0] != apiKeyGrant {
		t.Fatalf("BeforeIssue saw %v", seen)
	}
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
}

func TestDenyAfterRegistrationChange(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	req := e.startAuthorization(authParams(confidentialClient, "openid email", pkcePair{}))
	e.store.SetClient(testIssuer, grantor.Client{
		ID: confidentialClient, SecretHash: grantor.HashClientSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid"}, PKCE: grantor.PKCEOptional,
	})
	rec, err := e.deny(req, &grantor.Error{Code: grantor.CodeAccessDenied})
	if err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if p := redirectParams(t, rec); p.Get("error") != "access_denied" {
		t.Fatalf("deny = %v", p)
	}
}

func TestExtraLimits(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	q := authParams(publicClient, "openid", newPKCE())
	q.Set("client_secret", "leaked")
	q.Set("long", strings.Repeat("x", 2000))
	for i := range 40 {
		q.Set("ext"+string(rune('a'+i/26))+string(rune('a'+i%26)), "v")
	}
	req := e.startAuthorization(q)
	if _, ok := req.Extra["client_secret"]; ok {
		t.Error("Extra kept client_secret")
	}
	if _, ok := req.Extra["long"]; ok {
		t.Error("Extra kept an oversized value")
	}
	if len(req.Extra) > 32 {
		t.Errorf("Extra has %d entries", len(req.Extra))
	}
}

func TestClientWithUnknownGrantType(t *testing.T) {
	e := newEnv(t)
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "typo", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{"client_credential"}, Scopes: []string{"api"},
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("typo", confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
}

func TestServeAuthorizationWithoutInteract(t *testing.T) {
	testKeys(t)
	store := memory.New()
	store.SetClient(testIssuer, grantor.Client{ID: publicClient, RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid"}})
	p, err := grantor.New(grantor.Config{
		Issuer:  &grantor.Issuer{URL: testIssuer, Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}},
		Clients: store, Storage: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httpGet(testIssuer+grantor.PathAuthorization+"?"+authParams(publicClient, "openid", newPKCE()).Encode()))
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" {
		t.Fatalf("without Interact = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
