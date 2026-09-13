# grantor design

This document records the decisions behind the initial implementation. They are meant to be revisited.

## Goals

- A library for building OAuth 2.1 authorization servers and OpenID Connect providers that is as flexible as a low-level toolkit, with an API that reads like ordinary Go.
- Correct and secure by default: OAuth 2.1 (draft-ietf-oauth-v2-1-16), OpenID Connect and RFC 9700, with no hand-written cryptography.
- Multiple issuers in one process from the start.
- Few dependencies: the standard library and go-jose.

## Principles

**Data is plain structs.** `Client`, `AuthorizationRequest` and `Token` are structs with exported fields and JSON tags. There are no getter/setter interfaces and no session interfaces to implement, clone or type-assert. A storage implementation can persist a record as a JSON column.

**Dependencies are typed.** `Config` takes `ClientStore`, `Storage`, `InteractionFunc` and `ClaimsFunc`, and `New` validates the configuration up front. Nothing is discovered at runtime through type assertions, so a storage that does not implement the contract does not compile.

**Small surface, explicit behaviour.** Configuration is a struct with documented zero values. Extension points are functions (`Interact`, `Claims`, `IssuerFor`, `ErrorPage`) instead of strategy, provider or factory types.

**Protocol errors are separate from internal errors.** `*grantor.Error` carries an RFC error code and a fixed description that is safe to send. Internal failures become `server_error` for the client and are logged with their cause. Errors meant for the application wrap sentinels (`ErrInvalidApproval`, `ErrInvalidAuthorizationRequest`, `ErrNotFound`), and there are no exported `*Error` values that callers could modify.

**Lists fail safe.** A nil or empty list of scopes or audiences always means none. Defaults are filled in before the application sees a value (`AuthorizationRequest.Audience` starts as `Client.Audience`), so the usual Go filter idiom, which returns nil when it removes everything, can never grant more than intended.

**Contracts do not grow.** `Storage` will not gain methods. Records may gain fields, which implementations persist, and features that need other storage take their own interface in an optional `Config` field.

## Architecture

```
Provider.ServeHTTP                convenience layer: routes Config.Endpoints
│
├── ServeAuthorization  = ParseAuthorizationRequest → SaveAuthorizationRequest → Config.Interact
│                                                     application login/consent → Approve / Deny
├── ServeToken          = ParseTokenRequest → Exchange → WriteTokenResponse
│                         built-in grants and Config.Grants → issuance → Config.BeforeIssue
├── ServeUserInfo, ServeIntrospection, ServeRevocation
└── ServeJWKS, ServeDiscovery

Storage      authorization requests, tokens, replay protection (ClaimOnce)
ClientStore  registered clients, per issuer
```

The convenience layer uses only exported building blocks, so an application can replace any part of it: mount the `ServeXxx` methods on its own router, or write the authorization and token endpoints itself. The design of the two layers is described in [superpowers/specs/2026-09-13-layered-api-design.md](superpowers/specs/2026-09-13-layered-api-design.md).

Authorization requests are plain structs that the application may adjust between parsing and completion. Completion validates them again against the client registration (redirect URI, response type and mode, scopes, audience, PKCE policy), and a saved request is completed from its stored copy and cannot be changed. `Exchange` only accepts token requests it parsed for the client that authenticated; their `Scopes` are informational, and `BeforeIssue` narrows token issuance with the parsed request at hand. Custom grant functions return a `Grant` that grantor checks against the client registration before issuing. Hooks and custom grants can only narrow what is issued.

### Authorization requests and interaction

The authorization endpoint validates the request completely before the application sees it: client, redirect URI, response type and mode, scopes, PKCE, prompt, max_age, claims and id_token_hint. Scopes the client is not registered for are ignored, as OpenID Connect Core §3.1.2.1 recommends for scopes that are not understood; the token response reports the granted scope. A request without a scope is processed with no scopes, which is grantor's documented default (OAuth 2.1 §1.4.1).

Redirect URIs are compared with simple string comparison, except for the port of loopback IP redirect URIs. Private-use URI schemes must be reverse domain names such as `com.example.app` (OAuth 2.1 §2.3.1). Errors that cannot be redirected safely (unknown client, unregistered redirect URI) go to `Config.ErrorPage`; all others are redirected with `state` and `iss`.

A valid request is saved with a random ID and handed to `Config.Interact`. The application authenticates the end-user however it likes and finishes with `Provider.Approve` or `Provider.Deny`. `Approve` enforces what the application must not get wrong:

- granted scopes are a subset of the requested scopes, and include `openid` for OpenID Connect requests;
- granted audiences are a subset of the request's audience, and not empty for clients that use JWT access tokens;
- `prompt=login` and `max_age` are honoured, using `AuthTime`;
- the end-user is the one the client asked for with `id_token_hint` or a `sub` claim value;
- an essential `acr` claim request is satisfied;
- individually approved claims (`Approval.Claims`) were actually requested.

`AuthorizationRequest.NeedsAuthentication` lets the application decide up front whether to show a login page.

**Browser binding.** The authorization endpoint sets a cookie (with the `__Host-` prefix on https) holding a random value whose hash is stored with the request. The cookie is also added to the request passed to `Interact`, so that the application can approve immediately when the end-user already has a session. `AuthorizationRequest`, `Approve` and `Deny` only find the request when the cookie matches. A leaked request ID therefore cannot be completed from another browser, which also protects login forms that check the request first against cross-site request forgery. `Config.DisableInteractionBinding` turns this off for login pages on another site.

### Tokens

Authorization codes and refresh tokens are 256-bit random values. Access tokens use the client's format: opaque 256-bit random values by default, JWT access tokens (RFC 9068), or a custom `AccessTokenEncoder`. Only the SHA-256 hashes of token values are stored, so a database leak does not leak usable tokens, and no server-side secret has to be managed or rotated.

A format only decides the value of an access token. Because every access token is stored and looked up by hash, UserInfo, introspection, revocation, grant revocation and `ValidateAccessToken` need no per-format code, and a custom format cannot produce a token that is valid without being stored. Resource servers that validate JWT access tokens locally do not see revocations; the introspection endpoint does.

Each issuance is planned before tokens are minted: the format, audience and lifetimes start from the client registration and `Config`, `BeforeIssue` adjusts them, and grantor checks that the hook only narrowed scopes and audiences, chose a configured format, kept lifetimes at a second or more, set only JSON claims and no protocol claims. Tokens are then minted (encoded, with claims fetched and ID tokens signed) and stored before an authorization code or refresh token is consumed. A failing hook, encoder, key or storage call therefore leaves the code or refresh token usable, instead of turning the client's retry into a reuse that revokes the grant. If storing or consuming fails, the stored tokens are revoked on a best-effort basis; they are never returned, and their values were never disclosed. A token stored after a revocation of its grant is never returned either, because consuming the code or refresh token then fails. `RevokeGrant` therefore only has to affect existing tokens, and storage never keeps revoked-grant markers.

The audience is part of the grant (`Approval.Audience`, `Grant.Audience`, within `Client.Audience`), is carried through refreshes, and is checked against the current registration like scopes. JWT access tokens need an audience: ID tokens use the client ID as `aud`, so defaulting to it would make the two interchangeable for verifiers that ignore `typ` (RFC 9068 §5, RFC 8725 §2.8). For the same reason `SignFunc` refuses the `JWT` type. Encoders receive a copy of the token description, and claims are stored as decoded JSON, so neither hooks nor encoders can change what is stored after the checks.

Every token records its `GrantID`. Tokens issued from one authorization share it, which makes these rules straightforward:

- **Authorization code reuse** revokes every token of the grant (RFC 6749 §4.1.2), even after the code has expired.
- **Refresh tokens rotate** on every use. Reusing a rotated refresh token revokes the grant (RFC 9700 §4.14).
- **Revoking a refresh token** revokes the access tokens of its grant (RFC 7009 §2.1).

Single-use semantics are part of the storage contract: `ConsumeToken` must be atomic, and exactly one concurrent call sees an unconsumed token. The provider validates a code's client, redirect URI and PKCE verifier before it looks at reuse or consumes the code. A request that fails verification therefore cannot burn a code, and a replay by someone who does not hold the verifier does not revoke the legitimate client's tokens (OAuth 2.1 §7.5.3).

OAuth 2.1 removed `redirect_uri` from the token request. It is still compared when a client sends it, and required as in RFC 6749 for codes issued without PKCE (OAuth 2.1 §10.2).

Authorization codes, access tokens and refresh tokens are 43-character base64url strings. Authorization request parameters may be up to 8000 bytes each.

Refresh tokens are issued when the client may use the refresh token grant and, for OpenID Connect requests, `offline_access` was granted (OpenID Connect Core §11).

### Client authentication

`client_secret_basic` (with form-decoding of credentials), `client_secret_post`, `private_key_jwt` and `none`. A request may only use one method. A client with a secret may send it with either secret method, since OAuth 2.1 §2.4.1 requires accepting it in the request body; otherwise the client must use its registered method. Client assertions accept asymmetric algorithms only, require `exp` and `jti`, expire within an hour, and are single-use through `Storage.ClaimOnce`. Following RFC 7523bis, which OAuth 2.1 adopts, their audience must be the issuer identifier as its only value; the token endpoint URL is rejected.

OAuth 2.1 §2.4.1 requires protecting endpoints that accept client secrets against brute force. grantor does not rate-limit; wrap the provider with rate-limiting middleware for the token, introspection and revocation endpoints.

Client secrets are stored as SHA-256 hashes and compared in constant time. This is sound only for high-entropy secrets, which `GenerateClientSecret` produces; it avoids a password-hashing dependency.

### PKCE

Only `S256` is supported; OAuth 2.1 forbids `plain`. Every client must use PKCE by default. `Client.PKCE` relaxes this for confidential clients only:

- `PKCEUnlessNonce` allows omitting PKCE on OpenID Connect requests that carry a nonce, the exception in OAuth 2.1 §7.5.1.1 for clients known to validate the nonce;
- `PKCEOptional` allows omitting PKCE altogether, as OAuth 2.0 and OpenID Connect Core do. This does not conform to OAuth 2.1 and is meant for clients that cannot be updated. The OpenID conformance harness uses it, because the OpenID Connect plans send most requests without PKCE.

A `code_verifier` for a code issued without a challenge is rejected, which prevents PKCE downgrade.

### Claims

`Config.Claims` returns everything the application knows about the end-user. The provider releases a claim only if:

- a granted scope maps to it (the OpenID Connect Core §5.4 mapping, extensible with `Config.ScopeClaims`), or
- it was requested individually with the `claims` parameter, the client is registered for a scope that maps to it, and the application approved it in `Approval.Claims`, typically after showing it on the consent screen.

`AuthorizationRequest.Claims` is already reduced to claims the client may receive, so `req.Claims.Names()` lists what can be approved. Protocol claims such as `iss`, `sub` and `aud` are always set by the provider.

For the code flow, scope claims are returned from UserInfo and not put in the ID token unless `Config.IDTokenScopeClaims` is set.

### Keys

`SigningKey` wraps a `crypto.Signer`, so keys can be held in a KMS or HSM. Keys are validated at startup (RSA of at least 2048 bits; the algorithm must match the key type), and every issuer needs an RS256 key, which OpenID Connect Discovery requires. All keys are published in the JWKS; for each algorithm the first key signs. ID tokens use the client's registered algorithm, defaulting to RS256 as OpenID Connect requires.

### Multiple issuers

`Config.IssuerFor` resolves the issuer per request. The issuer URL is part of every stored request and token and is checked on every use, and clients are looked up per issuer, so tenants are isolated even when they share one storage. Only errors wrapping `ErrNotFound` mean "no such issuer" (404); any other failure, including an issuer with invalid keys, is logged and answered with 500, so an outage of the tenant directory does not look like a missing tenant.

## Not yet implemented

- Request objects and `request_uri` (rejected with `request_not_supported` / `request_uri_not_supported`)
- Pushed authorization requests, resource indicators, DPoP, mutual TLS
- Pairwise subject identifiers, session management and logout specifications
- Dynamic client registration
- A grace period for concurrent refresh token rotation
- An absolute lifetime for grants; refresh tokens currently slide
