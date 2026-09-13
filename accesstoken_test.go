package grantor_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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
		ID: "api-client", SecretHash: grantor.HashClientSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid", "api"},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Audience:   []string{"https://a.example.com", "https://b.example.com"}, PKCE: grantor.PKCEOptional,
	})
	req := e.startAuthorization(authParams("api-client", "openid api", pkcePair{}))
	if _, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: []string{"https://c.example.com"}}); !errors.Is(err, grantor.ErrInvalidApproval) {
		t.Fatalf("Approve with an audience outside the client registration = %v, want ErrInvalidApproval", err)
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
		"unknown default":     func(c *grantor.Config) { c.AccessTokenFormat = "paseto" },
		"sub-second lifetime": func(c *grantor.Config) { c.Lifetimes.AccessToken = 500 * time.Millisecond },
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
		ID: "jwt-at", SecretHash: grantor.HashClientSecret(confidentialSecret),
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
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "jwt-service", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
		Audience: []string{"https://api.example.com"},
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("jwt-service", confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("client credentials = %d %v", status, body)
	}
	_, claims := e.parseJWT(body["access_token"].(string))
	if claims["sub"] != "jwt-service" || claims["aud"] != "https://api.example.com" || claims["scope"] != nil || claims["auth_time"] != nil {
		t.Fatalf("claims = %v", claims)
	}
}

// ID tokens use the client ID as aud, so a JWT access token that defaulted
// to it could be replayed as an ID token. JWT access tokens therefore need an
// audience, and failing to have one is a server error.
func TestJWTAccessTokenNeedsAudience(t *testing.T) {
	e := newEnv(t, func(c *grantor.Config) { c.AccessTokenFormat = grantor.AccessTokenFormatJWT })
	e.registerClients()
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic(serviceClient, confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")

	e.store.SetClient(testIssuer, grantor.Client{
		ID: "jwt-service", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
		Audience: []string{"https://api.example.com"},
	})
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			is.Audience = nil
			return nil
		}
	})
	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("jwt-service", confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
}

func TestAccessTokenClientValidation(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	for name, c := range map[string]grantor.Client{
		"JWT without audience": {AccessTokenFormat: grantor.AccessTokenFormatJWT},
		"sub-second lifetime":  {AccessTokenLifetime: 500 * time.Millisecond},
		"negative lifetime":    {RefreshTokenLifetime: -time.Hour},
	} {
		c.ID = "misconfigured"
		c.SecretHash = grantor.HashClientSecret(confidentialSecret)
		c.GrantTypes = []grantor.GrantType{grantor.GrantTypeClientCredentials}
		c.Scopes = []string{"api"}
		e.store.SetClient(testIssuer, c)
		status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("misconfigured", confidentialSecret))
		if status != http.StatusInternalServerError {
			t.Errorf("%s: token request = %d %v", name, status, body)
		}
	}
}

func TestAccessTokenFormatSelection(t *testing.T) {
	e := newEnv(t, func(c *grantor.Config) { c.AccessTokenFormat = grantor.AccessTokenFormatJWT })
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "opaque-client", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
		AccessTokenFormat: grantor.AccessTokenFormatOpaque, Audience: []string{"https://api.example.com"},
	})
	e.store.SetClient(testIssuer, grantor.Client{
		ID: serviceClient, SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
		Audience: []string{"https://api.example.com"},
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
	signWith := func(typ string) grantor.AccessTokenEncoder {
		return func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
			return sign(typ, map[string]any{"iss": at.Issuer, "sub": at.Subject, "aud": at.Audience, "scp": at.Scopes, "exp": at.ExpiresAt.Unix(), "jti": at.ID})
		}
	}
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{
			"prefixed": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				return "gat_" + at.ID, nil
			},
			"scp-jwt":        signWith("at+jwt"),
			"jwt-typ":        signWith("JWT"),
			"media-type-typ": signWith("application/jwt"),
			"empty-typ":      signWith(""),
		}
	})
	checks := map[grantor.AccessTokenFormat]func(string){
		"prefixed": func(at string) {
			if !strings.HasPrefix(at, "gat_") {
				t.Errorf("prefixed token = %q", at)
			}
		},
		"scp-jwt": func(at string) {
			if header, claims := e.parseJWT(at); header["typ"] != "at+jwt" || claims["scp"] == nil || claims["aud"] == nil {
				t.Errorf("scp-jwt = %v %v", header, claims)
			}
		},
	}
	for format, check := range checks {
		e.store.SetClient(testIssuer, grantor.Client{
			ID: "custom", SecretHash: grantor.HashClientSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
			Scopes: []string{"openid", "api"}, AccessTokenFormat: format, PKCE: grantor.PKCEOptional,
			Audience: []string{"https://api.example.com"},
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
		if rec := e.postForm(grantor.PathRevocation, url.Values{"token": {at}}, basic("custom", confidentialSecret)); rec.Code != http.StatusOK {
			t.Errorf("%s: revoke = %d", format, rec.Code)
		}
		if info := e.introspect(at, "custom"); info["active"] != false {
			t.Errorf("%s: revoked token introspection = %v", format, info)
		}
	}

	// Access tokens typed like ID tokens are refused.
	for _, format := range []grantor.AccessTokenFormat{"jwt-typ", "media-type-typ", "empty-typ"} {
		e.store.SetClient(testIssuer, grantor.Client{
			ID: "untyped", SecretHash: grantor.HashClientSecret(confidentialSecret),
			GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
			AccessTokenFormat: format, Audience: []string{"https://api.example.com"},
		})
		status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("untyped", confidentialSecret))
		expectError(t, status, body, http.StatusInternalServerError, "server_error")
	}

	e.store.SetClient(testIssuer, grantor.Client{
		ID: "unknown-format", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, AccessTokenFormat: "paseto",
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("unknown-format", confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")

	e.store.SetClient(testIssuer, grantor.Client{
		ID: "no-key", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes:        []grantor.GrantType{grantor.GrantTypeClientCredentials},
		AccessTokenFormat: grantor.AccessTokenFormatJWT, AccessTokenSigningAlg: "ES512",
		Audience: []string{"https://api.example.com"},
	})
	status, body = e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("no-key", confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
}

func TestIssuanceClaimsAudienceAndLifetimes(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "rich", SecretHash: grantor.HashClientSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes:     []string{"openid", "api", "offline_access"}, Audience: []string{"https://a.example.com", "https://b.example.com"},
		AccessTokenFormat: grantor.AccessTokenFormatJWT, RefreshTokenLifetime: time.Hour, IDTokenLifetime: 10 * time.Minute,
		PKCE: grantor.PKCEOptional,
	})
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			// The claim maps start empty, not nil.
			is.AccessTokenClaims["tenant"] = "acme"
			is.IDTokenClaims["tenant"] = "acme"
			if is.GrantType == grantor.GrantTypeRefreshToken {
				is.Audience = []string{"https://b.example.com"}
				is.AccessTokenLifetime = 2 * time.Minute
				is.RefreshTokenLifetime = 30 * time.Minute
				is.IDTokenLifetime = 3 * time.Minute
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
	if info := e.introspect(body["refresh_token"].(string), "rich"); info["exp"].(float64)-info["iat"].(float64) != 3600 {
		t.Fatalf("refresh token introspection = %v", info)
	}

	status, refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}, basic("rich", confidentialSecret))
	if status != http.StatusOK || refreshed["expires_in"] != float64(120) {
		t.Fatalf("refresh = %d %v", status, refreshed)
	}
	if _, claims := e.parseJWT(refreshed["access_token"].(string)); claims["aud"] != "https://b.example.com" {
		t.Fatalf("narrowed audience = %v", claims["aud"])
	}
	if _, idClaims := e.parseJWT(refreshed["id_token"].(string)); idClaims["exp"].(float64)-idClaims["iat"].(float64) != 180 {
		t.Fatalf("refreshed ID token claims = %v", idClaims)
	}
	// The rotated refresh token keeps the full audience of the grant.
	info := e.introspect(refreshed["refresh_token"].(string), "rich")
	if aud, ok := info["aud"].([]any); !ok || len(aud) != 2 || info["exp"].(float64)-info["iat"].(float64) != 1800 {
		t.Fatalf("rotated refresh token introspection = %v", info)
	}
	e.clock.Advance(31 * time.Minute)
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
		"sub-second lifetime":          func(is *grantor.Issuance) { is.AccessTokenLifetime = 500 * time.Millisecond },
		"zero refresh token lifetime":  func(is *grantor.Issuance) { is.RefreshTokenLifetime = 0 },
		"negative ID token lifetime":   func(is *grantor.Issuance) { is.IDTokenLifetime = -time.Minute },
		"access token claim not JSON":  func(is *grantor.Issuance) { is.AccessTokenClaims["f"] = func() {} },
		"ID token claim not JSON":      func(is *grantor.Issuance) { is.IDTokenClaims["c"] = make(chan int) },
		"JWT without audience":         func(is *grantor.Issuance) { is.AccessTokenFormat = grantor.AccessTokenFormatJWT },
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
		ID: "api-client", SecretHash: grantor.HashClientSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
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
	if err != nil || got.Subject != "alice" || got.Kind != grantor.TokenKindAccessToken {
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

// A failure while minting tokens, such as a signing service outage, must not
// consume the authorization code or refresh token: the client's retry would
// otherwise look like reuse and revoke the grant.
func TestIssuanceFailureKeepsGrant(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	failEncoder, badClaim := false, false
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{
			"flaky": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				if failEncoder {
					return "", errors.New("signing service unavailable")
				}
				return "flaky_" + at.ID, nil
			},
		}
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			if badClaim {
				is.AccessTokenClaims["f"] = func() {}
			}
			return nil
		}
	})
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "flaky", SecretHash: grantor.HashClientSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes:     []string{"openid", "api", "offline_access"}, AccessTokenFormat: "flaky", PKCE: grantor.PKCEOptional,
	})
	auth := basic("flaky", confidentialSecret)

	for name, fail := range map[string]*bool{"encoder error": &failEncoder, "claims that are not JSON": &badClaim} {
		t.Run(name, func(t *testing.T) {
			code := e.login(authParams("flaky", "openid api offline_access", pkcePair{}), nil)
			*fail = true
			status, body := e.exchangeCode("flaky", code, "", auth)
			expectError(t, status, body, http.StatusInternalServerError, "server_error")
			*fail = false
			status, body = e.exchangeCode("flaky", code, "", auth)
			if status != http.StatusOK {
				t.Fatalf("retried code exchange = %d %v", status, body)
			}

			refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}
			*fail = true
			status, failed := e.tokenRequest(refresh, auth)
			expectError(t, status, failed, http.StatusInternalServerError, "server_error")
			*fail = false
			status, refreshed := e.tokenRequest(refresh, auth)
			if status != http.StatusOK {
				t.Fatalf("retried refresh = %d %v", status, refreshed)
			}
			if info := e.introspect(body["access_token"].(string), "flaky"); info["active"] != true {
				t.Fatalf("access token after retried refresh = %v", info)
			}
		})
	}
}

// Scopes and audiences of a grant are checked against the current client
// registration whenever tokens are issued from it.
func TestGrantAudienceRecheckedAgainstClient(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	client := grantor.Client{
		ID: "api-client", SecretHash: grantor.HashClientSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes:     []string{"openid", "api", "offline_access"}, Audience: []string{"https://a.example.com", "https://b.example.com"},
		PKCE: grantor.PKCEOptional,
	}
	e.store.SetClient(testIssuer, client)
	body := e.tokensFor("api-client", "openid api offline_access")

	client.Audience = []string{"https://a.example.com"}
	e.store.SetClient(testIssuer, client)
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}
	status, failed := e.tokenRequest(refresh, basic("api-client", confidentialSecret))
	expectError(t, status, failed, http.StatusBadRequest, "invalid_grant")

	code := e.login(authParams("api-client", "openid api", pkcePair{}), nil)
	client.Audience = nil
	e.store.SetClient(testIssuer, client)
	status, failed = e.exchangeCode("api-client", code, "", basic("api-client", confidentialSecret))
	expectError(t, status, failed, http.StatusBadRequest, "invalid_grant")
}

// Encoders and hooks cannot change what grantor stores, and claims are
// stored as decoded JSON.
func TestIssuedTokenIsolation(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	var hookClaims map[string]any
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{
			"meddling": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				hookClaims["later"] = "added after the hook returned"
				hookClaims["roles"].([]any)[0] = "root"
				at.Claims["sub"] = "mallory"
				at.Claims["roles"].([]any)[0] = "admin"
				at.ExpiresAt = at.ExpiresAt.Add(365 * 24 * time.Hour)
				at.Audience[0] = "https://evil.example.com"
				at.Scopes[0] = "admin"
				return "meddling_" + at.ID, nil
			},
		}
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			is.AccessTokenClaims["roles"] = []any{"reader"}
			is.AccessTokenClaims["count"] = 3
			is.AccessTokenClaims["dropped"] = nil
			hookClaims = is.AccessTokenClaims
			return nil
		}
	})
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "meddling", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
		AccessTokenFormat: "meddling", Audience: []string{"https://api.example.com"},
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic("meddling", confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("client credentials = %d %v", status, body)
	}
	got, err := e.p.ValidateAccessToken(httpGet(testIssuer+"/api"), body["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	wantClaims := map[string]any{"roles": []any{"reader"}, "count": float64(3)}
	if !reflect.DeepEqual(got.AccessTokenClaims, wantClaims) {
		t.Errorf("stored claims = %#v, want %#v", got.AccessTokenClaims, wantClaims)
	}
	if !got.ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) || !reflect.DeepEqual(got.Audience, []string{"https://api.example.com"}) || !reflect.DeepEqual(got.Scopes, []string{"api"}) {
		t.Errorf("stored token = %+v", got)
	}
}

func TestCustomGrantAudience(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.Grants = map[grantor.GrantType]grantor.GrantFunc{
			apiKeyGrant: func(ctx context.Context, req *grantor.TokenRequest) (*grantor.Grant, error) {
				return &grantor.Grant{Scopes: []string{"api"}, Audience: req.Form["audience"]}, nil
			},
		}
	})
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "cli", SecretHash: grantor.HashClientSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{apiKeyGrant}, Scopes: []string{"api"},
		Audience: []string{"https://a.example.com", "https://b.example.com"},
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}, "audience": {"https://b.example.com"}}, basic("cli", confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("custom grant = %d %v", status, body)
	}
	if info := e.introspect(body["access_token"].(string), "cli"); info["aud"] != "https://b.example.com" {
		t.Fatalf("introspection = %v", info)
	}
	status, body = e.tokenRequest(url.Values{"grant_type": {string(apiKeyGrant)}, "audience": {"https://c.example.com"}}, basic("cli", confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_target")
}

func TestValidateAccessTokenOfOtherIssuer(t *testing.T) {
	testKeys(t)
	store := memory.New()
	issuers := map[string]*grantor.Issuer{
		"a.example.com": {URL: "https://a.example.com", Keys: []grantor.SigningKey{{ID: "a", Signer: rsaKey}}},
		"b.example.com": {URL: "https://b.example.com", Keys: []grantor.SigningKey{{ID: "b", Signer: rsaKey}}},
	}
	p, err := grantor.New(grantor.Config{
		IssuerFor: func(r *http.Request) (*grantor.Issuer, error) {
			if iss, ok := issuers[r.Host]; ok {
				return iss, nil
			}
			return nil, grantor.ErrNotFound
		},
		Clients: store,
		Storage: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range issuers {
		store.SetClient(iss.URL, grantor.Client{
			ID: "service", SecretHash: grantor.HashClientSecret(confidentialSecret),
			GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
		})
	}
	req := httptest.NewRequest(http.MethodPost, "https://a.example.com"+grantor.PathToken, strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("service", confidentialSecret)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("client credentials = %d %s", rec.Code, rec.Body.String())
	}
	token := decodeJSON(t, rec)["access_token"].(string)
	if _, err := p.ValidateAccessToken(httpGet("https://a.example.com/api"), token); err != nil {
		t.Fatalf("own issuer = %v", err)
	}
	if _, err := p.ValidateAccessToken(httpGet("https://b.example.com/api"), token); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("other issuer = %v", err)
	}
}
