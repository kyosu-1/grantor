# grantor

A flexible, idiomatic Go toolkit for building OAuth 2.1 authorization servers and OpenID Connect providers.

grantor implements the protocol; your application keeps control of everything else: where data is stored, how end-users sign in, what the consent screen looks like, and which claims are released.

> **Status:** early development. The API may change before v1.

## Features

- **OAuth 2.1**: authorization code flow with PKCE (S256, required for every client by default), refresh token rotation with reuse detection, client credentials, exact redirect URI matching
- **OpenID Connect Core**: ID tokens, UserInfo, `nonce`, `prompt`, `max_age`, `id_token_hint`, `acr`/`amr`, the `claims` parameter, `offline_access`
- **Discovery**: OpenID Provider metadata and RFC 8414 authorization server metadata, JWKS
- **Token introspection** (RFC 7662) and **revocation** (RFC 7009)
- **Client authentication**: `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none`
- **Response modes**: `query`, `fragment`, `form_post`; the RFC 9207 `iss` parameter on every authorization response
- **Native apps**: loopback redirect URIs on any port (RFC 8252)
- **Multiple issuers** in one process, with per-issuer keys and clients
- **Signing keys** from any `crypto.Signer` (RSA, ECDSA, Ed25519), so keys can live in a KMS or HSM

Implicit and password grants are intentionally not supported, following OAuth 2.1 and RFC 9700. Clients that predate OAuth 2.1 can be allowed to skip PKCE per client with `Client.PKCE`; see [docs/design.md](docs/design.md).

## Design

- **Plain data.** Authorization requests, tokens and clients are structs with exported fields. Storage serializes data, never interfaces.
- **Wired at compile time.** `grantor.New` takes typed dependencies. A missing storage method is a compile error, not a runtime surprise.
- **Small, explicit contracts.** Storage is one interface whose atomicity requirements are spelled out, such as single-use consumption of authorization codes and refresh tokens. The `storagetest` package verifies an implementation against them.
- **The application owns the UI.** Valid authorization requests are handed to your code, which calls `Approve` or `Deny` when it is done.
- **Two layers.** Mount the whole `Provider`, or build your own endpoints from the same building blocks: parse, adjust, complete and write each request yourself.
- **Safe errors.** Clients only ever see RFC error codes and fixed descriptions; internal causes go to your logger.
- **Minimal dependencies.** The standard library plus [go-jose](https://github.com/go-jose/go-jose) for JOSE. No cryptography is implemented here.

See [docs/design.md](docs/design.md) for details.

## Quick start

```go
store := memory.New() // implements grantor.Storage and grantor.ClientStore
store.SetClient("https://id.example.com", grantor.Client{
	ID:           "web-app",
	SecretHash:   grantor.HashSecret(secret), // secret from grantor.GenerateSecret()
	RedirectURIs: []string{"https://app.example.com/callback"},
	GrantTypes:   []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
	Scopes:       []string{"openid", "profile", "email", "offline_access"},
})

provider, err := grantor.New(grantor.Config{
	Issuer: &grantor.Issuer{
		URL:  "https://id.example.com",
		Keys: []grantor.SigningKey{{ID: "2026-09", Signer: rsaPrivateKey}},
	},
	Clients: store,
	Storage: store,
	// Called for every valid authorization request.
	Interact: func(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest) {
		http.Redirect(w, r, "/login?id="+url.QueryEscape(req.ID), http.StatusFound)
	},
	// End-user claims; grantor filters them by granted scopes.
	Claims: func(ctx context.Context, grant *grantor.Token) (map[string]any, error) {
		return users.Claims(ctx, grant.Subject)
	},
})

mux := http.NewServeMux()
mux.Handle("/", provider) // /authorize, /token, /userinfo, /jwks, /.well-known/...
mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
	req, err := provider.AuthorizationRequest(r, r.FormValue("id"))
	// ... authenticate the end-user and ask for consent ...
	err = provider.Approve(w, r, req, grantor.Approval{
		Subject:  user.ID,
		Scopes:   grantedScopes,
		AuthTime: authTime,
	})
})
```

## Low-level API

`Provider.ServeHTTP` is built from exported building blocks that you can use directly when you need your own router, paths, checks or grant types.

Every endpoint has a `ServeXxx` method that mounts on any `net/http` router, and `Config.Endpoints` sets the paths published in discovery:

```go
mux.HandleFunc("GET /oauth2/keys", provider.ServeJWKS)
mux.Handle("POST /oauth2/token", rateLimit(http.HandlerFunc(provider.ServeToken)))
```

The authorization and token endpoints can be written step by step. Requests are plain structs that you may adjust; grantor validates them again before completing them, so adjustments cannot weaken security:

```go
mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
	req, err := provider.ParseAuthorizationRequest(r)
	if err != nil {
		provider.WriteAuthorizationError(w, r, err)
		return
	}
	req.Scopes = policy.Allowed(req.ClientID, req.Scopes) // narrow by policy
	// Signed in, and no consent screen needed (also handle prompt=none and prompt=consent).
	if user, ok := session(r); ok && !req.NeedsAuthentication(user.AuthTime) && hasConsent(user, req) {
		approval := grantor.Approval{Subject: user.ID, Scopes: req.Scopes, AuthTime: user.AuthTime}
		if err := provider.Approve(w, r, req, approval); err != nil {
			http.Error(w, "cannot complete sign-in", http.StatusInternalServerError)
		}
		return
	}
	// Complete it after the login page.
	if err := provider.SaveAuthorizationRequest(w, r, req); err != nil {
		http.Error(w, "cannot start sign-in", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login?id="+url.QueryEscape(req.ID), http.StatusFound)
})

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
```

Two hooks work with either layer:

```go
cfg.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
	if users.Disabled(ctx, is.Subject) { // runs for every grant type, including refreshes
		return &grantor.Error{Code: grantor.CodeInvalidGrant, Description: "the account is disabled"}
	}
	return nil
}
cfg.Grants = map[grantor.GrantType]grantor.GrantFunc{
	"urn:example:grant-type:api-key": func(ctx context.Context, req *grantor.TokenRequest) (*grantor.TokenResponse, error) {
		key, err := apiKeys.Lookup(ctx, req.Form.Get("api_key"))
		if err != nil {
			return nil, &grantor.Error{Code: grantor.CodeInvalidGrant}
		}
		return provider.IssueTokens(ctx, req, grantor.Grant{Subject: key.Owner, Scopes: key.Scopes})
	},
}
```

[`examples/lowlevel`](examples/lowlevel) is a runnable provider built this way.

## Example apps

[`examples/`](examples) contains a runnable OpenID Provider with login and consent pages, and a relying party built on `golang.org/x/oauth2` and `github.com/coreos/go-oidc`:

```sh
cd examples
go run ./op   # provider on http://localhost:9001
go run ./rp   # relying party on http://localhost:9002
```

Open http://localhost:9002 and sign in as `alice` or `bob` with the password `password`. The relying party shows the verified ID token, UserInfo, and buttons to refresh, introspect and revoke tokens.

`examples/internal/e2e` drives both apps through the whole flow in a test. [`examples/lowlevel`](examples/lowlevel) is a provider built from the low-level API (`go run ./lowlevel`, on http://localhost:9003).

## Storage

Implement `grantor.Storage` (authorization requests, tokens, assertion replay protection) and `grantor.ClientStore` for your database, then run the conformance suite:

```go
func TestStorage(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) grantor.Storage { return newPostgresStorage(t) })
}
```

The suite checks round-tripping of every field, conflict and not-found semantics, grant revocation, and that concurrent consumption of a single-use token succeeds exactly once.

## Multiple issuers

Set `Config.IssuerFor` instead of `Config.Issuer` to resolve the issuer from each request, for example from the Host header or a path prefix. Clients are looked up per issuer, and tokens and authorization requests are only accepted by the issuer that created them.

## Conformance

The example provider passes the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)'s Basic OP, Config OP and Form Post Basic OP plans with no failures or warnings, run locally with [`examples/conformance`](examples/conformance). Tests that ask a human to review a screenshot are reported as REVIEW, and the request object test is skipped because request objects are not supported. grantor has not been submitted for OpenID Certification.

## Specifications

OAuth 2.1 is still an Internet-Draft; grantor follows draft-ietf-oauth-v2-1-16. Specification titles below are the official ones, so some still say "OAuth 2.0".

| Specification | Support |
|---|---|
| [The OAuth 2.1 Authorization Framework (draft-ietf-oauth-v2-1)](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | Authorization code, refresh token and client credentials grants |
| [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749) | The base that OAuth 2.1 consolidates; `redirect_uri` handling for clients without PKCE |
| [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) | UserInfo endpoint (Authorization header and form body, not the query string) |
| [RFC 7636: Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636) | `S256` only |
| [RFC 7009: Token Revocation](https://www.rfc-editor.org/rfc/rfc7009) | Revocation endpoint |
| [RFC 7662: Token Introspection](https://www.rfc-editor.org/rfc/rfc7662) | Introspection endpoint |
| [RFC 8414: Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414) | `/.well-known/oauth-authorization-server` |
| [RFC 9207: Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207) | `iss` in every authorization response |
| [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252) | Loopback redirect URIs on any port, reverse domain private-use schemes |
| [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700) | Security recommendations |
| [RFC 7521: Assertion Framework](https://www.rfc-editor.org/rfc/rfc7521) and [RFC 7523: JWT Profile for Client Authentication](https://www.rfc-editor.org/rfc/rfc7523) | `private_key_jwt` |
| [draft-ietf-oauth-rfc7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/) | Issuer identifier as the sole client assertion audience |
| [RFC 7515 (JWS)](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7517 (JWK)](https://www.rfc-editor.org/rfc/rfc7517), [RFC 7518 (JWA)](https://www.rfc-editor.org/rfc/rfc7518), [RFC 7519 (JWT)](https://www.rfc-editor.org/rfc/rfc7519) | ID tokens, JWKS and client assertions, through go-jose |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | Authorization code flow, ID tokens, UserInfo, claims parameter, `prompt`, `max_age`, `id_token_hint`, `offline_access` |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html) | `query` and `fragment` response modes |
| [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html) | `form_post` response mode |

## Roadmap

Pushed authorization requests (RFC 9126), DPoP (RFC 9449), JWT access tokens (RFC 9068), RP-initiated logout, dynamic client registration, and running the OpenID Foundation conformance suite in CI.

## License

Apache License 2.0. See [LICENSE](LICENSE).
