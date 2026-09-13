# Access tokens: formats, claims, audience and lifetimes

Date: 2026-09-13
Status: direction approved by the user ("design it and proceed"); details decided autonomously (see "Decisions")
Follows: [2026-09-13-layered-api-design.md](2026-09-13-layered-api-design.md)

## Problem

Access tokens are always opaque 43-character random strings, valid for one global lifetime, with no audience and no room for application data. Resource servers must call the introspection endpoint for every request. Low-level OAuth toolkits let applications choose the token format per client (including JWT access tokens), add claims per issuance, set audiences, and tune lifetimes per client and grant; grantor should offer the same freedom.

## Goal and success criteria

Using only the public API, an application must be able to:

1. **Issue JWT access tokens** as specified by RFC 9068, per client or per issuance, so resource servers can validate them locally with the JWKS.
2. **Plug in its own token format**, including formats signed with the issuer's keys, without reimplementing storage, introspection or revocation.
3. **Add claims** to access tokens and ID tokens per issuance, visible in JWT access tokens and in introspection responses.
4. **Control the audience** of access tokens per client, per approval, per custom grant and per issuance.
5. **Control lifetimes** of access, refresh and ID tokens per client and per issuance (and so per grant type).
6. **Validate an access token in process**, for resource servers that run in the same process as the provider.

All existing guarantees hold: opaque access tokens stay the default, ServeHTTP behaviour does not change for existing configurations, every access token remains stored by hash so introspection, UserInfo and revocation keep working for every format, hooks and approvals can only narrow scopes and audiences within the client registration, and the OpenID conformance plans keep passing.

Out of scope: RFC 8707 resource parameters (the audience API is ready for them), sender-constrained tokens (DPoP, mTLS), JWT-encoded refresh tokens or authorization codes, encrypted tokens, stateless (unstored) access tokens.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| A1 | A token format only decides the **value** of an access token. Every access token, whatever its format, is stored by the SHA-256 hash of its value. | Lookup by hash is format-agnostic, so UserInfo, introspection, revocation, reuse detection and grant revocation need no per-format validation code. A format is one function, not a generate/validate/signature trio. |
| A2 | Built-in formats `opaque` (default) and `jwt` (RFC 9068). Custom formats are `AccessTokenEncoder` functions registered in `Config.AccessTokenFormats`. | Mirrors `Config.Grants`: a map keyed by name, no strategy types. |
| A3 | Encoders receive a `SignFunc` bound to the issuer's keys and the client's access token signing algorithm. | Custom JWT layouts (for example an `scp` array or other header types) reuse key management and rotation. |
| A4 | The format is chosen per client (`Client.AccessTokenFormat`), defaulting to `Config.AccessTokenFormat`, and may be changed per issuance by `BeforeIssue`. | Per-client and per-grant control without extra configuration types. |
| A5 | Audience is part of the grant: `Client.Audience` lists allowed audiences and is the default; `Approval.Audience` and `Grant.Audience` choose a subset; `BeforeIssue` may narrow it. Stored in `Token.Audience` and carried through refreshes. | Keeps the "only narrow within the registration" invariant; RFC 8707 can later fill `Approval.Audience` from `resource` parameters. |
| A6 | JWT access tokens without an audience use the client ID as `aud`. | RFC 9068 requires `aud`; the client is the only default resource indicator that always exists. |
| A7 | Extra claims are set per issuance by `BeforeIssue` (`AccessTokenClaims`, `IDTokenClaims`). Access token claims are stored with the access token and returned by introspection. Setting a protocol claim is a server error. | One customization point; surfacing misuse instead of silently dropping it. |
| A8 | Lifetimes: `Client.AccessTokenLifetime`, `RefreshTokenLifetime`, `IDTokenLifetime` override `Config.Lifetimes`; `BeforeIssue` may set any positive lifetime per issuance. | Lifetimes are policy, not a security boundary between client and provider; the hook knows the grant type. |
| A9 | `Client.AccessTokenSigningAlg` selects the JWS algorithm of JWT access tokens, defaulting to RS256. | Same rules as `IDTokenSigningAlg`; RFC 9068 requires RS256 support. |
| A10 | `Provider.ValidateAccessToken(r, token)` returns the stored access token if it is active for the request's issuer. | In-process resource servers get introspection semantics without HTTP. |

## API

### Configuration and clients

```go
type AccessTokenFormat string

const (
	AccessTokenFormatOpaque AccessTokenFormat = "opaque"
	AccessTokenFormatJWT    AccessTokenFormat = "jwt"
)

// SignFunc signs claims as a compact JWS with the issuer's key for the
// client's access token signing algorithm; typ is the JOSE "typ" header.
type SignFunc func(typ string, claims any) (string, error)

// AccessTokenEncoder returns the value of an access token in a custom
// format. The value must be unique and impossible to guess.
type AccessTokenEncoder func(ctx context.Context, at *AccessToken, sign SignFunc) (string, error)

type AccessToken struct {
	ID        string    // unique identifier, used as jti
	Issuer    string
	ClientID  string
	Subject   string    // empty when no end-user is involved
	Audience  []string  // never empty: defaults to the client ID
	Scopes    []string
	GrantType GrantType
	AuthTime  time.Time
	ACR       string
	AMR       []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Claims    map[string]any // extra claims from BeforeIssue
}

type Config struct {
	// ...existing fields...
	AccessTokenFormat  AccessTokenFormat                        // default for clients; "" means opaque
	AccessTokenFormats map[AccessTokenFormat]AccessTokenEncoder // custom formats
}

type Client struct {
	// ...existing fields...
	AccessTokenFormat     AccessTokenFormat // "" uses Config.AccessTokenFormat
	AccessTokenSigningAlg string            // JWT access tokens; default RS256
	Audience              []string          // allowed and default audiences
	AccessTokenLifetime   time.Duration     // 0 uses Config.Lifetimes
	RefreshTokenLifetime  time.Duration
	IDTokenLifetime       time.Duration
}
```

Validation: `New` rejects custom formats named `opaque` or `jwt`, empty names and nil encoders, and an unknown `Config.AccessTokenFormat`. A client with an unknown format, a negative lifetime, or an access token signing algorithm the issuer has no key for (only checked when the client's format needs signing) is a server-side misconfiguration.

### Grants, approvals and issuance

```go
type Approval struct {
	// ...existing fields...
	Audience []string // subset of Client.Audience; nil means all of it
}

type Grant struct {
	// ...existing fields...
	Audience []string // subset of Client.Audience; nil means all of it
}

type Issuance struct {
	// ...existing read-only fields and Scopes/RefreshToken...
	Audience             []string          // may be narrowed
	AccessTokenFormat    AccessTokenFormat // may be changed to any configured format
	AccessTokenClaims    map[string]any    // may be set
	IDTokenClaims        map[string]any    // may be set
	AccessTokenLifetime  time.Duration     // may be changed; must stay positive
	RefreshTokenLifetime time.Duration
	IDTokenLifetime      time.Duration
}
```

`Token` gains `Audience []string` and `AccessTokenClaims map[string]any` (JSON-serializable; stored with access tokens only).

After `BeforeIssue` returns, grantor rejects with `server_error`: added scopes or audiences, a refresh token switched on, an unknown format, non-positive lifetimes, and protocol claims in `AccessTokenClaims` (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `client_id`, `scope`, `auth_time`, `acr`, `amr`, `cnf`) or `IDTokenClaims` (the existing protocol claim set).

### JWT access tokens (RFC 9068)

Header: `typ: at+jwt`, `kid`, `alg` from `Client.AccessTokenSigningAlg`.
Claims: `iss`, `sub` (the end-user, or the client ID for grants without one), `aud` (a string when there is one audience, otherwise an array), `exp`, `iat`, `jti`, `client_id`, `scope` (space-separated, omitted when empty), `auth_time`/`acr`/`amr` when present, then `AccessTokenClaims`.

### Introspection

Active access tokens additionally return `aud` (string or array) and their `AccessTokenClaims`. Refresh tokens return `aud` too.

### In-process validation

```go
// ValidateAccessToken returns the access token record for token if it is an
// active access token of the issuer that r belongs to, or ErrNotFound.
func (p *Provider) ValidateAccessToken(r *http.Request, token string) (*Token, error)
```

## Data flow

1. Code exchange, refresh, client credentials and custom grants build the grant record (subject, scopes, audience) as today; the audience comes from the approval, the custom grant, or the client default.
2. `runBeforeIssue` fills `Issuance` with effective defaults: scopes, audience, format (`Client.AccessTokenFormat` → `Config.AccessTokenFormat` → opaque), lifetimes (client → config), empty claim maps. The hook adjusts it; grantor validates the result.
3. `mintTokens` computes `IssuedAt`/`ExpiresAt`, builds the `AccessToken`, and calls the encoder of the chosen format: opaque returns a random value, jwt signs RFC 9068 claims, custom encoders receive the descriptor and a `SignFunc`.
4. The access token record stores the hash, audience, scopes, claims and expiry; the refresh token record stores the grant audience and scopes with the refresh lifetime; the ID token uses the ID token lifetime and `IDTokenClaims`. `expires_in` reports the access token lifetime.

## Security

- The hash lookup means a custom encoder cannot create a token that validates without being stored, and a leaked database still does not leak usable tokens.
- JWT access tokens cannot be revoked for resource servers that validate them locally; revocation still takes effect at introspection, UserInfo and `ValidateAccessToken`. The docs recommend short access token lifetimes for JWT access tokens.
- Audiences and scopes can only narrow; formats are limited to configured ones; protocol claims cannot be overridden.
- Encoder errors and duplicate token values (`ErrConflict` from storage) become `server_error`.

## Testing

- JWT access token: signature verified with the JWKS, `typ` header, all RFC 9068 claims, one and several audiences, `sub` for client credentials, `scope` omission.
- Format selection: config default, per client, per issuance; unknown formats rejected at `New` and for clients.
- Custom encoders: a prefixed opaque format and a custom JWT layout using `SignFunc`; the tokens work at UserInfo, introspection and revocation.
- Claims: access token claims in JWT and introspection; ID token claims; protocol claims rejected.
- Audience: client default, approval subset, invalid approval audience rejected, custom grant audience, hook narrowing, widening rejected, audience preserved across refresh, introspection `aud`.
- Lifetimes: client overrides and hook overrides reflected in `expires_in`, `exp` and stored expiry for access, refresh and ID tokens; non-positive hook lifetimes rejected.
- `ValidateAccessToken`: active, expired, revoked, refresh token, other issuer.
- Existing tests and the example end-to-end tests pass unchanged; the OpenID conformance plans are re-run.
- `examples/lowlevel` issues JWT access tokens with an extra claim; README and design notes document formats, claims, audiences and lifetimes.
