package grantor_test

import (
	"context"
	"net/http"
	"testing"

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
