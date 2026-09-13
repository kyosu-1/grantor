package grantor_test

import (
	"encoding/base64"
	"crypto/sha256"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/grantor"
)

func TestDiscovery(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{grantor.PathOpenIDConfig, "/.well-known/oauth-authorization-server"} {
		rec := e.get(path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		m := decodeJSON(t, rec)
		if m["issuer"] != testIssuer || m["token_endpoint"] != testIssuer+"/token" || m["jwks_uri"] != testIssuer+"/jwks" {
			t.Fatalf("unexpected metadata: %v", m)
		}
		if m["authorization_response_iss_parameter_supported"] != true || m["request_uri_parameter_supported"] != false {
			t.Fatalf("unexpected metadata flags: %v", m)
		}
		if got := m["code_challenge_methods_supported"].([]any); len(got) != 1 || got[0] != "S256" {
			t.Fatalf("code_challenge_methods_supported = %v", got)
		}
		algs := m["id_token_signing_alg_values_supported"].([]any)
		if !slices.Contains(algs, any("RS256")) || !slices.Contains(algs, any("ES256")) {
			t.Fatalf("id_token_signing_alg_values_supported = %v", algs)
		}
		if !slices.Contains(m["scopes_supported"].([]any), any("org")) {
			t.Fatalf("custom scope missing from scopes_supported")
		}
	}

	rec := e.get(grantor.PathJWKS, nil)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `"kid":"rsa-1"`) || !strings.Contains(body, `"kid":"ec-1"`) {
		t.Fatalf("JWKS = %d %s", rec.Code, body)
	}
	if strings.Contains(body, `"d":`) {
		t.Fatal("JWKS leaks private key material")
	}
}

func TestRFC8414MetadataPathForIssuerWithPath(t *testing.T) {
	testKeys(t)
	e := newEnv(t, func(c *grantor.Config) { c.Issuer.URL = "https://op.example.com/tenant-a" })
	e.issuer = "https://op.example.com/tenant-a"
	req := httpGet("https://op.example.com/.well-known/oauth-authorization-server/tenant-a")
	if rec := e.do(req); rec.Code != http.StatusOK || decodeJSON(t, rec)["token_endpoint"] != "https://op.example.com/tenant-a/token" {
		t.Fatalf("RFC 8414 metadata = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.get(grantor.PathOpenIDConfig, nil); rec.Code != http.StatusOK {
		t.Fatalf("OIDC discovery = %d", rec.Code)
	}
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	pkce := newPKCE()

	q := authParams(publicClient, "openid profile email", pkce)
	req := e.startAuthorization(q)
	if req.ClientID != publicClient || !req.IsOpenID() || req.Nonce != "n-0S6_WzA2Mj" {
		t.Fatalf("unexpected pending request: %+v", req)
	}
	got, err := e.p.AuthorizationRequest(e.appRequest(http.MethodGet, "/login"), req.ID)
	if err != nil || got.ID != req.ID {
		t.Fatalf("AuthorizationRequest = %v, %v", got, err)
	}

	authTime := e.clock.Now()
	rec, err := e.approve(req.ID, grantor.Approval{
		Subject:  "alice",
		Scopes:   []string{"openid", "profile"}, // the end-user declined email
		AuthTime: authTime,
		ACR:      "urn:example:loa:1",
		AMR:      []string{"pwd"},
	})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	params := redirectParams(t, rec)
	if params.Get("state") != "xyz" || params.Get("iss") != testIssuer || params.Get("code") == "" {
		t.Fatalf("authorization response = %v", params)
	}

	status, body := e.exchangeCode(publicClient, params.Get("code"), pkce.verifier, nil)
	if status != http.StatusOK {
		t.Fatalf("token response = %d %v", status, body)
	}
	if body["token_type"] != "Bearer" || body["scope"] != "openid profile" || body["expires_in"] != float64(3600) {
		t.Fatalf("token response = %v", body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatal("refresh token issued without offline_access")
	}

	accessToken := body["access_token"].(string)
	claims := e.verifyJWT(body["id_token"].(string))
	sum := sha256.Sum256([]byte(accessToken))
	wantAtHash := base64.RawURLEncoding.EncodeToString(sum[:16])
	want := map[string]any{
		"iss":       testIssuer,
		"sub":       "alice",
		"aud":       publicClient,
		"nonce":     "n-0S6_WzA2Mj",
		"auth_time": float64(authTime.Unix()),
		"acr":       "urn:example:loa:1",
		"at_hash":   wantAtHash,
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("ID token %s = %v, want %v", k, claims[k], v)
		}
	}
	if _, ok := claims["name"]; ok {
		t.Error("scope claims must not be in the ID token by default")
	}

	// UserInfo returns profile claims but not email, which was not granted,
	// and never lets ClaimsFunc override protocol claims.
	info := e.userInfo(accessToken)
	if info["sub"] != "alice" || info["name"] != "Alice Example" {
		t.Fatalf("userinfo = %v", info)
	}
	for _, k := range []string{"email", "iss", "department"} {
		if _, ok := info[k]; ok {
			t.Errorf("userinfo contains %s: %v", k, info)
		}
	}
}

func (e *env) userInfo(accessToken string) map[string]any {
	e.t.Helper()
	req := httpGet(e.issuer + grantor.PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := e.do(req)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("userinfo = %d %s %s", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String())
	}
	return decodeJSON(e.t, rec)
}

func TestConfidentialClientAuthentication(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	t.Run("client_secret_basic", func(t *testing.T) {
		code := e.login(authParams(confidentialClient, "openid", pkcePair{}), nil)
		status, body := e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
		if status != http.StatusOK || body["id_token"] == nil {
			t.Fatalf("token response = %d %v", status, body)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		code := e.login(authParams(confidentialClient, "openid", pkcePair{}), nil)
		rec := e.postForm(grantor.PathToken, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {clientRedirect},
		}, basic(confidentialClient, "wrong"))
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("wrong secret = %d %v", rec.Code, rec.Header())
		}
		expectError(t, rec.Code, decodeJSON(t, rec), http.StatusUnauthorized, "invalid_client")
	})

	t.Run("client_secret_post with ES256 ID token", func(t *testing.T) {
		code := e.login(authParams(postClient, "openid", pkcePair{}), nil)
		status, body := e.tokenRequest(url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {clientRedirect},
			"client_id": {postClient}, "client_secret": {confidentialSecret},
		}, nil)
		if status != http.StatusOK {
			t.Fatalf("token response = %d %v", status, body)
		}
		if claims := e.verifyJWT(body["id_token"].(string)); claims["aud"] != postClient {
			t.Fatalf("ID token claims = %v", claims)
		}
	})

	t.Run("method not registered for client", func(t *testing.T) {
		code := e.login(authParams(postClient, "openid", pkcePair{}), nil)
		status, body := e.exchangeCode(postClient, code, "", basic(postClient, confidentialSecret))
		expectError(t, status, body, http.StatusUnauthorized, "invalid_client")
	})

	t.Run("multiple methods", func(t *testing.T) {
		status, body := e.tokenRequest(url.Values{
			"grant_type": {"client_credentials"}, "client_id": {serviceClient}, "client_secret": {confidentialSecret},
		}, basic(serviceClient, confidentialSecret))
		expectError(t, status, body, http.StatusBadRequest, "invalid_request")
	})

	t.Run("public client without client_id", func(t *testing.T) {
		status, body := e.tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}, nil)
		expectError(t, status, body, http.StatusUnauthorized, "invalid_client")
	})
}

func TestPrivateKeyJWT(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	tokenURL := testIssuer + grantor.PathToken
	exp := e.clock.Now().Add(2 * time.Minute)

	send := func(assertion string) (int, map[string]any) {
		return e.tokenRequest(url.Values{
			"grant_type":            {"client_credentials"},
			"scope":                 {"api"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
		}, nil)
	}

	assertion := clientAssertion(t, tokenURL, exp, "jti-1", clientEC, "ES256")
	if status, body := send(assertion); status != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("private_key_jwt = %d %v", status, body)
	}
	status, body := send(assertion)
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client") // replay

	status, body = send(clientAssertion(t, testIssuer, exp, "jti-2", clientEC, "ES256"))
	if status != http.StatusOK {
		t.Fatalf("issuer as audience = %d %v", status, body)
	}

	status, body = send(clientAssertion(t, "https://other.example.com/token", exp, "jti-3", clientEC, "ES256"))
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client") // wrong audience

	status, body = send(clientAssertion(t, tokenURL, e.clock.Now().Add(-time.Hour), "jti-4", clientEC, "ES256"))
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client") // expired

	status, body = send(clientAssertion(t, tokenURL, e.clock.Now().Add(24*time.Hour), "jti-5", clientEC, "ES256"))
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client") // too long-lived

	status, body = send(clientAssertion(t, tokenURL, exp, "jti-6", ecKey, "ES256"))
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client") // wrong key

	status, body = send(hs256Assertion(t, tokenURL, exp))
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client") // symmetric algorithm
}

func TestPublicClientRequiresPKCE(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	rec := e.get(grantor.PathAuthorization, authParams(publicClient, "openid", pkcePair{}))
	if p := redirectParams(t, rec); p.Get("error") != "invalid_request" || p.Get("state") != "xyz" || p.Get("iss") != testIssuer {
		t.Fatalf("missing code_challenge = %v", p)
	}

	q := authParams(publicClient, "openid", newPKCE())
	q.Set("code_challenge_method", "plain")
	if p := redirectParams(t, e.get(grantor.PathAuthorization, q)); p.Get("error") != "invalid_request" {
		t.Fatalf("plain method = %v", p)
	}
}

func TestPKCEVerification(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	pkce := newPKCE()

	code := e.login(authParams(publicClient, "openid", pkce), nil)
	status, body := e.exchangeCode(publicClient, code, newPKCE().verifier, nil)
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")
	// A failed verification does not consume the code.
	if status, body := e.exchangeCode(publicClient, code, pkce.verifier, nil); status != http.StatusOK {
		t.Fatalf("correct verifier after a wrong one = %d %v", status, body)
	}

	code = e.login(authParams(publicClient, "openid", pkce), nil)
	status, body = e.exchangeCode(publicClient, code, "", nil)
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")

	// Downgrade: a verifier for a code issued without a challenge is rejected.
	code = e.login(authParams(confidentialClient, "openid", pkcePair{}), nil)
	status, body = e.exchangeCode(confidentialClient, code, pkce.verifier, basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")
}

func TestAuthorizationCodeReuseRevokesGrant(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	pkce := newPKCE()
	code := e.login(authParams(publicClient, "openid offline_access", pkce), nil)

	status, body := e.exchangeCode(publicClient, code, pkce.verifier, nil)
	if status != http.StatusOK || body["refresh_token"] == nil {
		t.Fatalf("first exchange = %d %v", status, body)
	}
	status, second := e.exchangeCode(publicClient, code, pkce.verifier, nil)
	expectError(t, status, second, http.StatusBadRequest, "invalid_grant")

	if active := e.introspect(body["access_token"].(string), resourceServer); active["active"] != false {
		t.Fatalf("access token still active after code reuse: %v", active)
	}
	status, refreshed := e.tokenRequest(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "client_id": {publicClient},
	}, nil)
	expectError(t, status, refreshed, http.StatusBadRequest, "invalid_grant")
}

func TestAuthorizationCodeBinding(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	code := e.login(authParams(confidentialClient, "openid", pkcePair{}), nil)
	status, body := e.exchangeCode(postClient, code, "", nil)
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client")

	// Another client cannot redeem the code, even with valid credentials.
	status, body = e.tokenRequest(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {clientRedirect},
		"client_id": {postClient}, "client_secret": {confidentialSecret},
	}, nil)
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")

	// redirect_uri must match the authorization request.
	status, body = e.tokenRequest(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example.com/other"},
	}, basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")

	// Codes expire.
	code = e.login(authParams(confidentialClient, "openid", pkcePair{}), nil)
	e.clock.Advance(2 * time.Minute)
	status, body = e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")
}

func TestRefreshTokenRotation(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	code := e.login(authParams(confidentialClient, "openid profile offline_access", pkcePair{}), nil)
	auth := basic(confidentialClient, confidentialSecret)
	status, first := e.exchangeCode(confidentialClient, code, "", auth)
	if status != http.StatusOK || first["refresh_token"] == nil {
		t.Fatalf("exchange = %d %v", status, first)
	}

	refresh := func(token string, scope string) (int, map[string]any) {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
		if scope != "" {
			form.Set("scope", scope)
		}
		return e.tokenRequest(form, auth)
	}

	status, second := refresh(first["refresh_token"].(string), "openid")
	if status != http.StatusOK || second["scope"] != "openid" || second["refresh_token"] == first["refresh_token"] {
		t.Fatalf("refresh = %d %v", status, second)
	}
	claims := e.verifyJWT(second["id_token"].(string))
	if claims["sub"] != "alice" || claims["nonce"] != nil {
		t.Fatalf("refreshed ID token claims = %v", claims)
	}

	// The rotated refresh token keeps the original scope.
	status, third := refresh(second["refresh_token"].(string), "")
	if status != http.StatusOK || third["scope"] != "openid profile offline_access" {
		t.Fatalf("second refresh = %d %v", status, third)
	}

	status, body := refresh(third["refresh_token"].(string), "openid email")
	expectError(t, status, body, http.StatusBadRequest, "invalid_scope")

	// Reusing a rotated refresh token revokes the whole grant.
	status, body = refresh(first["refresh_token"].(string), "")
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")
	if active := e.introspect(third["access_token"].(string), resourceServer); active["active"] != false {
		t.Fatalf("access token still active after refresh token reuse: %v", active)
	}
	status, body = refresh(third["refresh_token"].(string), "")
	expectError(t, status, body, http.StatusBadRequest, "invalid_grant")
}

func TestClientCredentials(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	auth := basic(serviceClient, confidentialSecret)

	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, auth)
	if status != http.StatusOK || body["scope"] != "api" || body["refresh_token"] != nil || body["id_token"] != nil {
		t.Fatalf("client credentials = %d %v", status, body)
	}
	info := e.introspect(body["access_token"].(string), serviceClient)
	if info["active"] != true || info["client_id"] != serviceClient || info["sub"] != nil {
		t.Fatalf("introspection = %v", info)
	}

	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"openid"}}, auth)
	expectError(t, status, body, http.StatusBadRequest, "invalid_scope")
	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"profile"}}, auth)
	expectError(t, status, body, http.StatusBadRequest, "invalid_scope")

	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "unauthorized_client")

	status, body = e.tokenRequest(url.Values{"grant_type": {"password"}}, auth)
	expectError(t, status, body, http.StatusBadRequest, "unsupported_grant_type")
}
