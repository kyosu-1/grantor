package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"time"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

// apiKeyGrant is an in-house grant type that exchanges an API key for an
// access token.
const apiKeyGrant grantor.GrantType = "urn:example:params:oauth:grant-type:api-key"

// newServer builds an OpenID Provider from grantor's building blocks: its own
// routes and paths, a custom authorization endpoint, a custom grant type and
// an issuance hook. It has no login page; the login_hint parameter stands in
// for an authenticated end-user.
func newServer(issuer string, logger *slog.Logger) (http.Handler, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	store := memory.New()
	store.SetClient(issuer, grantor.Client{
		ID:           "cli",
		RedirectURIs: []string{"http://127.0.0.1/callback"},
		GrantTypes:   []grantor.GrantType{grantor.GrantTypeAuthorizationCode, apiKeyGrant},
		Scopes:       []string{"openid", "api"},
		// JWT access tokens (RFC 9068) that the API validates with the JWKS.
		AccessTokenFormat:   grantor.AccessTokenFormatJWT,
		Audience:            []string{"https://api.example.com"},
		AccessTokenLifetime: 10 * time.Minute,
	})
	disabledUsers := map[string]bool{"mallory": true}

	provider, err := grantor.New(grantor.Config{
		Issuer:  &grantor.Issuer{URL: issuer, Keys: []grantor.SigningKey{{ID: "example", Signer: key}}},
		Clients: store,
		Storage: store,
		Endpoints: grantor.Endpoints{
			Authorization: "/oauth2/authorize",
			Token:         "/oauth2/token",
			UserInfo:      "/oauth2/userinfo",
			Introspection: "/oauth2/introspect",
			Revocation:    "/oauth2/revoke",
			JWKS:          "/oauth2/keys",
			// Pushed authorization requests (RFC 9126), enabled by Config.PAR.
			PushedAuthorization: "/oauth2/par",
		},
		PAR: grantor.PARAllowed,
		Grants: map[grantor.GrantType]grantor.GrantFunc{
			apiKeyGrant: func(ctx context.Context, req *grantor.TokenRequest) (*grantor.Grant, error) {
				if subtle.ConstantTimeCompare([]byte(req.Form.Get("api_key")), []byte("demo-api-key")) != 1 {
					return nil, &grantor.Error{Code: grantor.CodeInvalidGrant, Description: "unknown API key"}
				}
				// The client uses JWT access tokens, which need an audience.
				return &grantor.Grant{Scopes: []string{"api"}, Audience: req.Client.Audience}, nil
			},
		},
		BeforeIssue: func(ctx context.Context, is *grantor.Issuance) error {
			if disabledUsers[is.Subject] {
				return &grantor.Error{Code: grantor.CodeInvalidGrant, Description: "the account is disabled"}
			}
			logger.InfoContext(ctx, "issuing tokens", "client_id", is.Client.ID, "grant_type", is.GrantType,
				"subject", is.Subject, "scopes", is.Scopes, "audience", is.Audience)
			is.AccessTokenClaims = map[string]any{"tenant": "example"}
			return nil
		},
		Claims: func(ctx context.Context, grant *grantor.Token) (map[string]any, error) {
			return map[string]any{"name": grant.Subject}, nil
		},
		Logger: logger,
	})
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		req, err := provider.ParseAuthorizationRequest(r)
		if err != nil {
			provider.WriteAuthorizationError(w, r, err)
			return
		}
		// NEVER DO THIS IN A REAL PROVIDER: login_hint is chosen by the client,
		// so trusting it lets anyone sign in as anyone. A real application
		// authenticates the end-user here, saving the request with
		// SaveAuthorizationRequest when it needs a login page.
		user := req.LoginHint
		if user == "" || disabledUsers[user] {
			if err := provider.Deny(w, r, req, &grantor.Error{Code: grantor.CodeAccessDenied}); err != nil {
				logger.ErrorContext(r.Context(), "deny", "error", err)
				http.Error(w, "unable to complete the request", http.StatusInternalServerError)
			}
			return
		}
		err = provider.Approve(w, r, req, grantor.Approval{Subject: user, Scopes: req.Scopes, Audience: req.Audience, AuthTime: time.Now()})
		if err != nil {
			logger.ErrorContext(r.Context(), "approve", "error", err)
			http.Error(w, "unable to complete the request", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /oauth2/token", provider.ServeToken)
	mux.HandleFunc("/oauth2/userinfo", provider.ServeUserInfo)
	mux.HandleFunc("POST /oauth2/introspect", provider.ServeIntrospection)
	mux.HandleFunc("POST /oauth2/revoke", provider.ServeRevocation)
	mux.HandleFunc("GET /oauth2/keys", provider.ServeJWKS)
	mux.HandleFunc("POST /oauth2/par", provider.ServePushedAuthorization)
	mux.HandleFunc("GET /.well-known/openid-configuration", provider.ServeDiscovery)
	return mux, nil
}
