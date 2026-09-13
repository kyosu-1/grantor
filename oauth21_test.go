package grantor_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/kyosu-1/grantor"
)

// registerPKCEClients registers confidential clients with each PKCE policy.
func (e *env) registerPKCEClients() {
	for id, policy := range map[string]grantor.PKCEPolicy{
		"default-pkce": "",
		"unless-nonce": grantor.PKCEUnlessNonce,
	} {
		e.store.SetClient(e.issuer, grantor.Client{
			ID:           id,
			SecretHash:   grantor.HashClientSecret(confidentialSecret),
			RedirectURIs: []string{clientRedirect},
			Scopes:       []string{"openid", "api"},
			PKCE:         policy,
		})
	}
}

func TestConfidentialClientsRequirePKCEByDefault(t *testing.T) {
	e := newEnv(t)
	e.registerPKCEClients()

	rec := e.get(grantor.PathAuthorization, authParams("default-pkce", "openid", pkcePair{}))
	if p := redirectParams(t, rec); p.Get("error") != "invalid_request" {
		t.Fatalf("confidential client without PKCE = %v", p)
	}
	e.startAuthorization(authParams("default-pkce", "openid", newPKCE()))
}

func TestPKCEUnlessNonce(t *testing.T) {
	e := newEnv(t)
	e.registerPKCEClients()

	e.startAuthorization(authParams("unless-nonce", "openid", pkcePair{}))

	withoutNonce := authParams("unless-nonce", "openid", pkcePair{})
	withoutNonce.Del("nonce")
	if p := redirectParams(t, e.get(grantor.PathAuthorization, withoutNonce)); p.Get("error") != "invalid_request" {
		t.Fatalf("OpenID request without nonce or PKCE = %v", p)
	}
	oauthOnly := authParams("unless-nonce", "api", pkcePair{})
	if p := redirectParams(t, e.get(grantor.PathAuthorization, oauthOnly)); p.Get("error") != "invalid_request" {
		t.Fatalf("OAuth request without PKCE = %v", p)
	}
}

func TestPublicClientCannotRelaxPKCE(t *testing.T) {
	e := newEnv(t)
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "bad-public", RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid"},
		PKCE: grantor.PKCEOptional,
	})
	rec := e.get(grantor.PathAuthorization, authParams("bad-public", "openid", pkcePair{}))
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" {
		t.Fatalf("misconfigured public client = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestTokenRequestWithoutRedirectURI(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	// With PKCE, the redirect_uri of the authorization request need not be
	// repeated (OAuth 2.1 section 4.1.3).
	pkce := newPKCE()
	code := e.login(authParams(publicClient, "openid", pkce), nil)
	status, body := e.tokenRequest(url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {publicClient}, "code_verifier": {pkce.verifier},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("OAuth 2.1 token request = %d %v", status, body)
	}

	// Without PKCE, RFC 6749 applies and redirect_uri is required.
	code = e.login(authParams(confidentialClient, "openid", pkcePair{}), nil)
	status, body = e.tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}},
		basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")
}

func TestCodeReplayWithInvalidVerifierDoesNotRevoke(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	pkce := newPKCE()
	code := e.login(authParams(publicClient, "openid", pkce), nil)
	status, body := e.exchangeCode(publicClient, code, pkce.verifier, nil)
	if status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, body)
	}
	at := body["access_token"].(string)

	// Someone with the code but not the verifier cannot revoke the tokens.
	status, replay := e.exchangeCode(publicClient, code, newPKCE().verifier, nil)
	expectError(t, status, replay, http.StatusBadRequest, "invalid_grant")
	if info := e.introspect(at, resourceServer); info["active"] != true {
		t.Fatalf("an invalid replay revoked the grant: %v", info)
	}

	// A valid replay does.
	status, replay = e.exchangeCode(publicClient, code, pkce.verifier, nil)
	expectError(t, status, replay, http.StatusBadRequest, "invalid_grant")
	if info := e.introspect(at, resourceServer); info["active"] != false {
		t.Fatalf("a valid replay did not revoke the grant: %v", info)
	}
}

func TestPrivateUseSchemeMustBeReverseDomain(t *testing.T) {
	e := newEnv(t)
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "bad-native", RedirectURIs: []string{"myapp:/cb"}, Scopes: []string{"openid"},
	})
	rec := e.get(grantor.PathAuthorization, url.Values{
		"response_type": {"code"}, "client_id": {"bad-native"}, "redirect_uri": {"myapp:/cb"},
		"code_challenge": {newPKCE().challenge}, "code_challenge_method": {"S256"},
	})
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" {
		t.Fatalf("private-use scheme without a dot = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
