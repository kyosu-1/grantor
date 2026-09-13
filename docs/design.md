# grantor design

This document records the decisions behind the initial implementation. They are meant to be revisited.

## Goals

- A library for building OAuth 2.0 authorization servers and OpenID Connect providers that is as flexible as a low-level toolkit, with an API that reads like ordinary Go.
- Correct and secure by default: current specifications and the OAuth 2.0 Security BCP (RFC 9700), with no hand-written cryptography.
- Multiple issuers in one process from the start.
- Few dependencies: the standard library and go-jose.

## Principles

**Data is plain structs.** `Client`, `AuthorizationRequest` and `Token` are structs with exported fields and JSON tags. There are no getter/setter interfaces and no session interfaces to implement, clone or type-assert. A storage implementation can persist a record as a JSON column.

**Dependencies are typed.** `Config` takes `ClientStore`, `Storage`, `InteractionFunc` and `ClaimsFunc`, and `New` validates the configuration up front. Nothing is discovered at runtime through type assertions, so a storage that does not implement the contract does not compile.

**Small surface, explicit behaviour.** Configuration is a struct with documented zero values. Extension points are functions (`Interact`, `Claims`, `IssuerFor`, `ErrorPage`) instead of strategy, provider or factory types.

**Protocol errors are separate from internal errors.** `*grantor.Error` carries an RFC error code and a fixed description that is safe to send. Internal failures become `server_error` for the client and are logged with their cause.

## Architecture

```
Provider (http.Handler)
├── authorization endpoint ──> Config.Interact ──> application login/consent
│                                                   └── Provider.Approve / Deny
├── token endpoint (authorization_code, refresh_token, client_credentials)
├── userinfo, introspection, revocation
└── jwks, discovery (OpenID + RFC 8414)

Storage      authorization requests, tokens, client assertion jti
ClientStore  registered clients, per issuer
```

### Authorization requests and interaction

The authorization endpoint validates the request completely before the application sees it: client, redirect URI, response type and mode, scopes, PKCE, prompt, max_age, claims and id_token_hint. Scopes the client is not registered for are ignored, as OpenID Connect Core §3.1.2.1 recommends for scopes that are not understood; the token response reports the granted scope. Errors that cannot be redirected safely (unknown client, unregistered redirect URI) go to `Config.ErrorPage`; all others are redirected with `state` and `iss`.

A valid request is saved with a random ID and handed to `Config.Interact`. The application authenticates the end-user however it likes and finishes with `Provider.Approve` or `Provider.Deny`. `Approve` enforces what the application must not get wrong:

- granted scopes are a subset of the requested scopes, and include `openid` for OpenID Connect requests;
- `prompt=login` and `max_age` are honoured, using `AuthTime`;
- the end-user is the one the client asked for with `id_token_hint` or a `sub` claim value;
- an essential `acr` claim request is satisfied;
- individually approved claims (`Approval.Claims`) were actually requested.

`AuthorizationRequest.NeedsAuthentication` lets the application decide up front whether to show a login page.

**Browser binding.** The authorization endpoint sets a cookie (with the `__Host-` prefix on https) holding a random value whose hash is stored with the request. The cookie is also added to the request passed to `Interact`, so that the application can approve immediately when the end-user already has a session. `AuthorizationRequest`, `Approve` and `Deny` only find the request when the cookie matches. A leaked request ID therefore cannot be completed from another browser, which also protects login forms that check the request first against cross-site request forgery. `Config.DisableInteractionBinding` turns this off for login pages on another site.

### Tokens

Authorization codes, access tokens and refresh tokens are 256-bit random values. Only their SHA-256 hashes are stored, so a database leak does not leak usable tokens, and no server-side secret has to be managed or rotated.

Every token records its `GrantID`. Tokens issued from one authorization share it, which makes these rules straightforward:

- **Authorization code reuse** revokes every token of the grant (RFC 6749 §4.1.2), even after the code has expired.
- **Refresh tokens rotate** on every use. Reusing a rotated refresh token revokes the grant (RFC 9700 §4.14).
- **Revoking a refresh token** revokes the access tokens of its grant (RFC 7009 §2.1).

Single-use semantics are part of the storage contract: `ConsumeToken` must be atomic, and exactly one concurrent call sees an unconsumed token. The provider validates a code's client, redirect URI and PKCE verifier before consuming it, so a request that fails verification cannot burn a code.

Refresh tokens are issued when the client may use the refresh token grant and, for OpenID Connect requests, `offline_access` was granted (OpenID Connect Core §11).

### Client authentication

`client_secret_basic` (with form-decoding of credentials), `client_secret_post`, `private_key_jwt` and `none`. A client must use its registered method, and a request may only use one method. Client assertions accept asymmetric algorithms only, require `exp` and `jti`, expire within an hour, and are single-use through `Storage.ClaimAssertionID`. Their audience must be a single value, either the issuer identifier or the token endpoint URL, so that an assertion made for another server cannot be replayed.

Client secrets are stored as SHA-256 hashes and compared in constant time. This is sound only for high-entropy secrets, which `GenerateSecret` produces; it avoids a password-hashing dependency.

### PKCE

Only `S256` is supported. Public clients must use PKCE, and `Client.RequirePKCE` extends that to confidential clients. A `code_verifier` for a code issued without a challenge is rejected, which prevents PKCE downgrade.

### Claims

`Config.Claims` returns everything the application knows about the end-user. The provider releases a claim only if:

- a granted scope maps to it (the OpenID Connect Core §5.4 mapping, extensible with `Config.ScopeClaims`), or
- it was requested individually with the `claims` parameter, the client is registered for a scope that maps to it, and the application approved it in `Approval.Claims`, typically after showing it on the consent screen.

`AuthorizationRequest.Claims` is already reduced to claims the client may receive, so `req.Claims.Names()` lists what can be approved. Protocol claims such as `iss`, `sub` and `aud` are always set by the provider.

For the code flow, scope claims are returned from UserInfo and not put in the ID token unless `Config.IDTokenScopeClaims` is set.

### Keys

`SigningKey` wraps a `crypto.Signer`, so keys can be held in a KMS or HSM. Keys are validated at startup (RSA of at least 2048 bits; the algorithm must match the key type), and every issuer needs an RS256 key, which OpenID Connect Discovery requires. All keys are published in the JWKS; for each algorithm the first key signs. ID tokens use the client's registered algorithm, defaulting to RS256 as OpenID Connect requires.

### Multiple issuers

`Config.IssuerFor` resolves the issuer per request. The issuer URL is part of every stored request and token and is checked on every use, and clients are looked up per issuer, so tenants are isolated even when they share one storage.

## Not yet implemented

- Request objects and `request_uri` (rejected with `request_not_supported` / `request_uri_not_supported`)
- Pushed authorization requests, DPoP, mutual TLS, JWT access tokens
- Pairwise subject identifiers, session management and logout specifications
- Dynamic client registration
- A grace period for concurrent refresh token rotation
- An absolute lifetime for grants; refresh tokens currently slide
