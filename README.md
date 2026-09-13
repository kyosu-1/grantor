# grantor

A flexible, idiomatic Go toolkit for building OAuth 2.0 authorization servers and OpenID Connect providers.

grantor implements the protocol; your application keeps control of everything else: where data is stored, how end-users sign in, what the consent screen looks like, and which claims are released.

> **Status:** early development. The API may change before v1.

## Features

- **Authorization code flow with PKCE** (S256; required for public clients), refresh tokens with rotation and reuse detection, client credentials
- **OpenID Connect Core**: ID tokens, UserInfo, `nonce`, `prompt`, `max_age`, `id_token_hint`, `acr`/`amr`, the `claims` parameter, `offline_access`
- **Discovery**: OpenID Provider metadata and RFC 8414 authorization server metadata, JWKS
- **Token introspection** (RFC 7662) and **revocation** (RFC 7009)
- **Client authentication**: `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none`
- **Response modes**: `query`, `fragment`, `form_post`; the RFC 9207 `iss` parameter on every authorization response
- **Native apps**: loopback redirect URIs on any port (RFC 8252)
- **Multiple issuers** in one process, with per-issuer keys and clients
- **Signing keys** from any `crypto.Signer` (RSA, ECDSA, Ed25519), so keys can live in a KMS or HSM

Implicit and password grants are intentionally not supported, following OAuth 2.1 and the OAuth 2.0 Security Best Current Practice (RFC 9700).

## Design

- **Plain data.** Authorization requests, tokens and clients are structs with exported fields. Storage serializes data, never interfaces.
- **Wired at compile time.** `grantor.New` takes typed dependencies. A missing storage method is a compile error, not a runtime surprise.
- **Small, explicit contracts.** Storage is one interface whose atomicity requirements are spelled out, such as single-use consumption of authorization codes and refresh tokens. The `storagetest` package verifies an implementation against them.
- **The application owns the UI.** Valid authorization requests are handed to your code, which calls `Approve` or `Deny` when it is done.
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
	err = provider.Approve(w, r, req.ID, grantor.Approval{
		Subject:  user.ID,
		Scopes:   grantedScopes,
		AuthTime: authTime,
	})
})
```

## Example apps

[`examples/`](examples) contains a runnable OpenID Provider with login and consent pages, and a relying party built on `golang.org/x/oauth2` and `github.com/coreos/go-oidc`:

```sh
cd examples
go run ./op   # provider on http://localhost:9001
go run ./rp   # relying party on http://localhost:9002
```

Open http://localhost:9002 and sign in as `alice` or `bob` with the password `password`. The relying party shows the verified ID token, UserInfo, and buttons to refresh, introspect and revoke tokens.

`examples/internal/e2e` drives both apps through the whole flow in a test.

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

## Roadmap

Pushed authorization requests (RFC 9126), DPoP (RFC 9449), JWT access tokens (RFC 9068), RP-initiated logout, dynamic client registration, and running the OpenID Foundation conformance suite in CI.
