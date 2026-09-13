package grantor_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

func ExampleNew() {
	key, err := rsa.GenerateKey(rand.Reader, 2048) // in production, load the key or use a KMS-backed crypto.Signer
	if err != nil {
		panic(err)
	}
	store := memory.New()
	store.SetClient("https://id.example.com", grantor.Client{
		ID:           "web-app",
		SecretHash:   grantor.HashClientSecret("a secret from grantor.GenerateClientSecret"),
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
	})
	provider, err := grantor.New(grantor.Config{
		Issuer:  &grantor.Issuer{URL: "https://id.example.com", Keys: []grantor.SigningKey{{ID: "2026-09", Signer: key}}},
		Clients: store,
		Storage: store,
		Interact: func(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest) {
			http.Redirect(w, r, "/login?id="+url.QueryEscape(req.ID), http.StatusFound)
		},
	})
	if err != nil {
		panic(err)
	}

	// The provider serves every endpoint, including discovery.
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://id.example.com"+grantor.PathOpenIDConfiguration, nil))
	var metadata struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		panic(err)
	}
	fmt.Println(metadata.Issuer)
	fmt.Println(metadata.TokenEndpoint)
	// Output:
	// https://id.example.com
	// https://id.example.com/token
}

// A provider can serve many issuers, each with its own keys and clients.
func Example_multipleIssuers() {
	tenants := map[string]*grantor.Issuer{} // Host header -> issuer, loaded by the application
	store := memory.New()
	_, err := grantor.New(grantor.Config{
		IssuerFor: func(r *http.Request) (*grantor.Issuer, error) {
			if iss, ok := tenants[r.Host]; ok {
				return iss, nil
			}
			// Unknown hosts get 404; other errors are logged and get 500.
			return nil, fmt.Errorf("no tenant for %q: %w", r.Host, grantor.ErrNotFound)
		},
		Clients: store, // clients are looked up per issuer URL
		Storage: store,
	})
	fmt.Println(err)
	// Output: <nil>
}

// A custom authorization endpoint approves requests of signed-in end-users
// right away and sends everyone else to a login page.
func ExampleProvider_ParseAuthorizationRequest() {
	var provider *grantor.Provider // from grantor.New
	session := func(r *http.Request) (subject string, authTime time.Time, ok bool) {
		return "", time.Time{}, false // look up the application's session
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		req, err := provider.ParseAuthorizationRequest(r)
		if err != nil {
			provider.WriteAuthorizationError(w, r, err)
			return
		}
		// Requests may be narrowed by policy; grantor validates them again.
		req.Scopes = slices.DeleteFunc(req.Scopes, func(s string) bool { return s == "admin" })

		subject, authTime, ok := session(r)
		if ok && !req.NeedsAuthentication(authTime) && !req.HasPrompt("consent") {
			err := provider.Approve(w, r, req, grantor.Approval{
				Subject:  subject,
				Scopes:   req.Scopes,
				Audience: req.Audience,
				AuthTime: authTime,
			})
			if err != nil {
				http.Error(w, "cannot complete sign-in", http.StatusInternalServerError)
			}
			return
		}
		if req.HasPrompt("none") {
			if err := provider.Deny(w, r, req, &grantor.Error{Code: grantor.CodeLoginRequired}); err != nil {
				http.Error(w, "cannot complete sign-in", http.StatusInternalServerError)
			}
			return
		}
		// Save the request and complete it after the login page with
		// provider.AuthorizationRequest and provider.Approve.
		if err := provider.SaveAuthorizationRequest(w, r, req); err != nil {
			http.Error(w, "cannot start sign-in", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/login?id="+url.QueryEscape(req.ID), http.StatusFound)
	})
}

// A custom token endpoint runs its own code around the protocol steps.
func ExampleProvider_Exchange() {
	var provider *grantor.Provider // from grantor.New

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		req, err := provider.ParseTokenRequest(r) // authenticates the client
		if err != nil {
			provider.WriteTokenError(w, r, err)
			return
		}
		resp, err := provider.Exchange(r.Context(), req)
		if err != nil {
			provider.WriteTokenError(w, r, err)
			return
		}
		provider.WriteTokenResponse(w, resp)
	})
}

// BeforeIssue sees every issuance, for every grant type, before any token is
// created or any authorization code or refresh token is used up.
func ExampleConfig_beforeIssue() {
	disabled := map[string]bool{"mallory": true}
	tenants := map[string]string{"web-app": "acme"}
	cfg := grantor.Config{
		BeforeIssue: func(ctx context.Context, is *grantor.Issuance) error {
			if disabled[is.Subject] {
				return &grantor.Error{Code: grantor.CodeInvalidGrant, Description: "the account is disabled"}
			}
			// Narrow by policy, using the token request if needed: refreshes
			// keep the admin scope only when the client asks for it again.
			if is.GrantType == grantor.GrantTypeRefreshToken && !slices.Contains(strings.Fields(is.Request.Form.Get("scope")), "admin") {
				is.Scopes = slices.DeleteFunc(is.Scopes, func(s string) bool { return s == "admin" })
			}
			// Claims come from the application's own data, never from the request.
			is.AccessTokenClaims["tenant"] = tenants[is.Client.ID]
			is.AccessTokenLifetime = 10 * time.Minute
			return nil
		},
	}
	_ = cfg
}

// A custom grant type exchanges an API key for tokens. The grant function
// only decides what is granted; grantor checks it against the client
// registration and issues the tokens.
func ExampleGrantFunc() {
	lookupAPIKey := func(ctx context.Context, key string) (subject string, ok bool) {
		return "", false // look the key up in the application's database
	}
	cfg := grantor.Config{
		Grants: map[grantor.GrantType]grantor.GrantFunc{
			"urn:example:params:oauth:grant-type:api-key": func(ctx context.Context, req *grantor.TokenRequest) (*grantor.Grant, error) {
				subject, ok := lookupAPIKey(ctx, req.Form.Get("api_key"))
				if !ok {
					return nil, &grantor.Error{Code: grantor.CodeInvalidGrant, Description: "unknown API key"}
				}
				return &grantor.Grant{
					Subject:  subject,
					Scopes:   []string{"api"},
					Audience: req.Client.Audience,
					AuthTime: time.Now(),
				}, nil
			},
		},
	}
	_ = cfg
}

// A custom access token format only decides the token value. grantor stores
// every access token by its hash, so introspection, UserInfo and revocation
// work for it too.
func ExampleAccessTokenEncoder() {
	cfg := grantor.Config{
		AccessTokenFormats: map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{
			// Prefixed tokens are easy to find with secret scanners.
			"prefixed": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				return "exat_" + at.ID, nil
			},
		},
		AccessTokenFormat: "prefixed", // or per client with Client.AccessTokenFormat
	}
	_ = cfg
}

// A custom pushed authorization request endpoint (RFC 9126) narrows requests
// by policy before storing them. Config.PAR must enable pushed authorization
// requests.
func ExampleProvider_ParsePushedAuthorizationRequest() {
	var provider *grantor.Provider // from grantor.New with Config.PAR set

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/par", func(w http.ResponseWriter, r *http.Request) {
		req, err := provider.ParsePushedAuthorizationRequest(r) // authenticates the client
		if err != nil {
			provider.WriteTokenError(w, r, err)
			return
		}
		req.Scopes = slices.DeleteFunc(req.Scopes, func(s string) bool { return s == "admin" })
		resp, err := provider.PushAuthorizationRequest(r, req)
		if err != nil {
			provider.WriteTokenError(w, r, err)
			return
		}
		provider.WritePushedAuthorizationResponse(w, resp)
	})
}
