package grantor_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

func TestApprovalAudienceMustBeRegistered(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "api-client", SecretHash: grantor.HashSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid", "api"},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Audience:   []string{"https://a.example.com", "https://b.example.com"}, PKCE: grantor.PKCEOptional,
	})
	req := e.startAuthorization(authParams("api-client", "openid api", pkcePair{}))
	if _, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: []string{"https://c.example.com"}}); err == nil {
		t.Fatal("Approve accepted an audience outside the client registration")
	}
	rec, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: []string{"https://a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := e.exchangeCode("api-client", redirectParams(t, rec).Get("code"), "", basic("api-client", confidentialSecret)); status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, body)
	}
}

func TestAccessTokenConfigValidation(t *testing.T) {
	testKeys(t)
	store := memory.New()
	base := func() grantor.Config {
		return grantor.Config{
			Issuer:  &grantor.Issuer{URL: testIssuer, Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}},
			Clients: store, Storage: store,
		}
	}
	enc := func(context.Context, *grantor.AccessToken, grantor.SignFunc) (string, error) { return "", nil }
	for name, modify := range map[string]func(*grantor.Config){
		"redefine jwt": func(c *grantor.Config) {
			c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{"jwt": enc}
		},
		"empty name": func(c *grantor.Config) {
			c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{"": enc}
		},
		"nil encoder": func(c *grantor.Config) {
			c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{"x": nil}
		},
		"unknown default": func(c *grantor.Config) { c.AccessTokenFormat = "paseto" },
	} {
		cfg := base()
		modify(&cfg)
		if _, err := grantor.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	cfg := base()
	cfg.AccessTokenFormat = grantor.AccessTokenFormatJWT
	cfg.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{"custom": enc}
	if _, err := grantor.New(cfg); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

func TestJWTAccessToken(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "jwt-at", SecretHash: grantor.HashSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid", "api", "offline_access"},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Audience:   []string{"https://api.example.com"}, AccessTokenFormat: grantor.AccessTokenFormatJWT,
		AccessTokenLifetime: 5 * time.Minute, PKCE: grantor.PKCEOptional,
	})
	body := e.tokensFor("jwt-at", "openid api offline_access")
	at := body["access_token"].(string)
	header, claims := e.parseJWT(at)
	if header["typ"] != "at+jwt" || header["kid"] != "rsa-1" || header["alg"] != "RS256" {
		t.Fatalf("header = %v", header)
	}
	want := map[string]any{
		"iss": testIssuer, "sub": "alice", "aud": "https://api.example.com",
		"client_id": "jwt-at", "scope": "openid api offline_access",
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %s = %v, want %v", k, claims[k], v)
		}
	}
	if claims["exp"].(float64)-claims["iat"].(float64) != 300 || claims["jti"] == nil || claims["auth_time"] == nil || body["expires_in"] != float64(300) {
		t.Fatalf("claims = %v, expires_in = %v", claims, body["expires_in"])
	}
	if info := e.userInfo(at); info["sub"] != "alice" {
		t.Fatalf("userinfo = %v", info)
	}
	if rec := e.postForm(grantor.PathRevocation, url.Values{"token": {at}}, basic("jwt-at", confidentialSecret)); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	if info := e.introspect(at, "jwt-at"); info["active"] != false {
		t.Fatalf("revoked JWT access token = %v", info)
	}
}

func TestJWTAccessTokenForClientCredentials(t *testing.T) {
	e := newEnv(t, func(c *grantor.Config) { c.AccessTokenFormat = grantor.AccessTokenFormatJWT })
	e.registerClients()
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("client credentials = %d %v", status, body)
	}
	_, claims := e.parseJWT(body["access_token"].(string))
	if claims["sub"] != serviceClient || claims["aud"] != serviceClient || claims["scope"] != nil || claims["auth_time"] != nil {
		t.Fatalf("claims = %v", claims)
	}
}

func TestAccessTokenFormatSelection(t *testing.T) {
	e := newEnv(t, func(c *grantor.Config) { c.AccessTokenFormat = grantor.AccessTokenFormatJWT })
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "opaque-client", SecretHash: grantor.HashSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
		AccessTokenFormat: grantor.AccessTokenFormatOpaque,
	})
	_, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("opaque-client", confidentialSecret))
	if strings.Contains(body["access_token"].(string), ".") {
		t.Fatalf("client override to opaque was ignored: %v", body["access_token"])
	}
	_, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic(serviceClient, confidentialSecret))
	if strings.Count(body["access_token"].(string), ".") != 2 {
		t.Fatalf("config default JWT was ignored: %v", body["access_token"])
	}

	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.AccessTokenFormat = grantor.AccessTokenFormatOpaque
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			if is.GrantType == grantor.GrantTypeClientCredentials {
				is.AccessTokenFormat = grantor.AccessTokenFormatJWT
			}
			return nil
		}
	})
	_, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("opaque-client", confidentialSecret))
	if strings.Count(body["access_token"].(string), ".") != 2 {
		t.Fatalf("format chosen by BeforeIssue was ignored: %v", body["access_token"])
	}
}

func TestCustomAccessTokenFormats(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{
			"prefixed": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				return "gat_" + at.ID, nil
			},
			"scp-jwt": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				return sign("JWT", map[string]any{"iss": at.Issuer, "sub": at.Subject, "scp": at.Scopes, "exp": at.ExpiresAt.Unix(), "jti": at.ID})
			},
		}
	})
	checks := map[grantor.AccessTokenFormat]func(string){
		"prefixed": func(at string) {
			if !strings.HasPrefix(at, "gat_") {
				t.Errorf("prefixed token = %q", at)
			}
		},
		"scp-jwt": func(at string) {
			if header, claims := e.parseJWT(at); header["typ"] != "JWT" || claims["scp"] == nil {
				t.Errorf("scp-jwt = %v %v", header, claims)
			}
		},
	}
	for format, check := range checks {
		e.store.SetClient(testIssuer, grantor.Client{
			ID: "custom", SecretHash: grantor.HashSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
			Scopes: []string{"openid", "api"}, AccessTokenFormat: format, PKCE: grantor.PKCEOptional,
		})
		body := e.tokensFor("custom", "openid api")
		at := body["access_token"].(string)
		check(at)
		if info := e.userInfo(at); info["sub"] != "alice" {
			t.Errorf("%s: userinfo = %v", format, info)
		}
		if info := e.introspect(at, "custom"); info["active"] != true {
			t.Errorf("%s: introspection = %v", format, info)
		}
	}

	e.store.SetClient(testIssuer, grantor.Client{
		ID: "unknown-format", SecretHash: grantor.HashSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, AccessTokenFormat: "paseto",
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("unknown-format", confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")

	e.store.SetClient(testIssuer, grantor.Client{
		ID: "no-key", SecretHash: grantor.HashSecret(confidentialSecret),
		GrantTypes:        []grantor.GrantType{grantor.GrantTypeClientCredentials},
		AccessTokenFormat: grantor.AccessTokenFormatJWT, AccessTokenSigningAlg: "ES512",
	})
	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("no-key", confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
}

func TestIssuanceClaimsAudienceAndLifetimes(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "rich", SecretHash: grantor.HashSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes:     []string{"openid", "api", "offline_access"}, Audience: []string{"https://a.example.com", "https://b.example.com"},
		AccessTokenFormat: grantor.AccessTokenFormatJWT, RefreshTokenLifetime: time.Hour, IDTokenLifetime: 10 * time.Minute,
		PKCE: grantor.PKCEOptional,
	})
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			is.AccessTokenClaims = map[string]any{"tenant": "acme"}
			is.IDTokenClaims = map[string]any{"tenant": "acme"}
			if is.GrantType == grantor.GrantTypeRefreshToken {
				is.Audience = []string{"https://b.example.com"}
				is.AccessTokenLifetime = 2 * time.Minute
			}
			return nil
		}
	})
	body := e.tokensFor("rich", "openid api offline_access")
	_, claims := e.parseJWT(body["access_token"].(string))
	if aud, ok := claims["aud"].([]any); !ok || len(aud) != 2 || claims["tenant"] != "acme" {
		t.Fatalf("access token claims = %v", claims)
	}
	_, idClaims := e.parseJWT(body["id_token"].(string))
	if idClaims["tenant"] != "acme" || idClaims["exp"].(float64)-idClaims["iat"].(float64) != 600 {
		t.Fatalf("ID token claims = %v", idClaims)
	}

	status, refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}, basic("rich", confidentialSecret))
	if status != http.StatusOK || refreshed["expires_in"] != float64(120) {
		t.Fatalf("refresh = %d %v", status, refreshed)
	}
	if _, claims := e.parseJWT(refreshed["access_token"].(string)); claims["aud"] != "https://b.example.com" {
		t.Fatalf("narrowed audience = %v", claims["aud"])
	}
	e.clock.Advance(2 * time.Hour)
	status, expired := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed["refresh_token"].(string)}}, basic("rich", confidentialSecret))
	expectError(t, status, expired, http.StatusBadRequest, "invalid_grant")
}

func TestIssuanceValidation(t *testing.T) {
	for name, hook := range map[string]func(*grantor.Issuance){
		"protected access token claim": func(is *grantor.Issuance) { is.AccessTokenClaims = map[string]any{"sub": "mallory"} },
		"protected ID token claim":     func(is *grantor.Issuance) { is.IDTokenClaims = map[string]any{"aud": "x"} },
		"widened audience":             func(is *grantor.Issuance) { is.Audience = append(is.Audience, "https://evil.example.com") },
		"unknown format":               func(is *grantor.Issuance) { is.AccessTokenFormat = "paseto" },
		"zero lifetime":                func(is *grantor.Issuance) { is.AccessTokenLifetime = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registerClients()
			e.p = mustProvider(t, e, func(c *grantor.Config) {
				c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error { hook(is); return nil }
			})
			status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic(serviceClient, confidentialSecret))
			expectError(t, status, body, http.StatusInternalServerError, "server_error")
		})
	}
}

func TestIntrospectionAudienceAndClaims(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "api-client", SecretHash: grantor.HashSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes:     []string{"openid", "api", "offline_access"}, Audience: []string{"https://a.example.com", "https://b.example.com"},
		PKCE: grantor.PKCEOptional,
	})
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			is.AccessTokenClaims = map[string]any{"tenant": "acme"}
			return nil
		}
	})
	req := e.startAuthorization(authParams("api-client", "openid api offline_access", pkcePair{}))
	rec, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: []string{"https://a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	status, body := e.exchangeCode("api-client", redirectParams(t, rec).Get("code"), "", basic("api-client", confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, body)
	}
	info := e.introspect(body["access_token"].(string), "api-client")
	if info["aud"] != "https://a.example.com" || info["tenant"] != "acme" {
		t.Fatalf("access token introspection = %v", info)
	}
	if info := e.introspect(body["refresh_token"].(string), "api-client"); info["aud"] != "https://a.example.com" || info["tenant"] != nil {
		t.Fatalf("refresh token introspection = %v", info)
	}
	// Tokens without an audience keep returning no aud.
	cc := e.tokensFor(confidentialClient, "openid")
	if info := e.introspect(cc["access_token"].(string), confidentialClient); info["aud"] != nil {
		t.Fatalf("introspection without audience = %v", info)
	}
}

func TestValidateAccessToken(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	body := e.tokensFor(confidentialClient, "openid offline_access")
	r := httpGet(testIssuer + "/api")
	got, err := e.p.ValidateAccessToken(r, body["access_token"].(string))
	if err != nil || got.Subject != "alice" || got.Type != grantor.TokenTypeAccessToken {
		t.Fatalf("ValidateAccessToken = %+v, %v", got, err)
	}
	if _, err := e.p.ValidateAccessToken(r, body["refresh_token"].(string)); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("refresh token = %v", err)
	}
	if _, err := e.p.ValidateAccessToken(r, "unknown"); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("unknown token = %v", err)
	}
	other := e.tokensFor(confidentialClient, "openid")
	if rec := e.postForm(grantor.PathRevocation, url.Values{"token": {other["access_token"].(string)}}, basic(confidentialClient, confidentialSecret)); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	if _, err := e.p.ValidateAccessToken(r, other["access_token"].(string)); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("revoked token = %v", err)
	}
	e.clock.Advance(2 * time.Hour)
	if _, err := e.p.ValidateAccessToken(r, body["access_token"].(string)); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("expired token = %v", err)
	}
}
