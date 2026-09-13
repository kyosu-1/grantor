# Layered API: protocol building blocks under the Provider

Date: 2026-09-13
Status: approved direction; details decided autonomously (see "Decisions")

## Problem

`Provider` is a single `http.Handler`. Applications mount it whole, at fixed paths, and customize behaviour only through a few callbacks (`Interact`, `Claims`, `IssuerFor`, `ErrorPage`). Low-level OAuth toolkits let applications write their own handlers and call protocol steps directly; grantor cannot do the same today.

## Goal and success criteria

Add a low-level layer of exported protocol building blocks, and rebuild the existing `Provider.ServeHTTP` on top of it as a convenience layer. Using only the public API, an application must be able to:

1. **Use its own router and paths**: mount each endpoint on any router at any path, with different middleware per endpoint, and have discovery publish those URLs.
2. **Check before issuing tokens**: reject token issuance with its own logic, for example when the end-user was disabled before a refresh, and see every issuance for auditing.
3. **Add grant types**: implement a custom `grant_type`, such as token exchange or an in-house grant, and have grantor issue the tokens.
4. **Adjust requests**: narrow the scopes of an authorization or token request by policy, read authorization request parameters grantor does not know, and send custom error responses.

Existing security guarantees must hold for anything an application does through the low-level layer, and the existing behaviour of `ServeHTTP` must not change: all current tests and the OpenID conformance plans keep passing.

Out of scope (next spec): JWT access tokens, custom access token claims, per-client lifetimes, token format plug-ins.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Building blocks are methods on `*Provider` using `net/http` types. | Every mainstream Go router is `net/http` compatible; a separate "core" type would duplicate configuration. |
| D2 | Each endpoint gets an exported `ServeXxx(w, r)` method; `ServeHTTP` becomes a router over them. | Method values plug into `mux.HandleFunc` with no adapter; this alone satisfies criterion 1 for endpoints that need no further hooks. |
| D3 | The authorization and token endpoints additionally expose Parse / complete / Write steps. | They are where criteria 2–4 apply. UserInfo, introspection, revocation, JWKS and discovery get `ServeXxx` only (YAGNI). |
| D4 | Endpoint paths are configured with `Config.Endpoints`, relative to the issuer URL; defaults are the current paths. | Discovery must publish the real URLs; relative paths keep multiple issuers working. |
| D5 | `Approve` and `Deny` take the `*AuthorizationRequest` instead of its ID. A request is either unsaved (fresh from `ParseAuthorizationRequest`) or saved (`SaveAuthorizationRequest`, then loaded with `AuthorizationRequest`). | One pair of functions covers "complete immediately" and "pause for login". |
| D6 | Approval re-validates the request against the client registration and provider policy. | Applications may edit a request (criterion 4); edits must never weaken security. |
| D7 | A saved request is completed from its stored copy; `Approve`/`Deny` return an error if protocol fields of the passed request differ from it. | The stored copy is the source of truth; silently ignoring edits would be surprising. |
| D8 | `Client` stays a plain struct. | Consistent with the plain-data principle; applications that need more data look it up by client ID. |
| D9 | Custom grants are `GrantFunc` values in `Config.Grants`, keyed by grant type, and issue tokens through `Provider.IssueTokens`. | A map avoids ordering; the function decides who gets access, grantor issues and stores tokens. |
| D10 | One issuance hook, `Config.BeforeIssue`, runs for every grant, built-in or custom. It may reject, narrow scopes, or withhold the refresh token. | A single choke point for criteria 2 and 4 at the token endpoint. |
| D11 | `Error` gains exported `URI` and `StatusCode`; `Deny` accepts any syntactically valid error code. | Custom error responses (criterion 4) with RFC 6749 extension codes. |
| D12 | Authorization request parameters that grantor does not process are kept in `AuthorizationRequest.Extra`. | Criterion 4 without persisting raw requests. |

## API

### Endpoints

```go
type Endpoints struct {
	Authorization string // default "/authorize"
	Token         string // default "/token"
	UserInfo      string // default "/userinfo"
	Introspection string // default "/introspect"
	Revocation    string // default "/revoke"
	JWKS          string // default "/jwks"
}

type Config struct {
	// ...existing fields...
	Endpoints   Endpoints
	Grants      map[GrantType]GrantFunc
	BeforeIssue func(ctx context.Context, is *Issuance) error
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request)          // router over the methods below
func (p *Provider) ServeAuthorization(w http.ResponseWriter, r *http.Request)
func (p *Provider) ServeToken(w http.ResponseWriter, r *http.Request)
func (p *Provider) ServeUserInfo(w http.ResponseWriter, r *http.Request)
func (p *Provider) ServeIntrospection(w http.ResponseWriter, r *http.Request)
func (p *Provider) ServeRevocation(w http.ResponseWriter, r *http.Request)
func (p *Provider) ServeJWKS(w http.ResponseWriter, r *http.Request)
func (p *Provider) ServeDiscovery(w http.ResponseWriter, r *http.Request)     // OpenID and RFC 8414 document
```

Every `ServeXxx` resolves the issuer from the request like `ServeHTTP` does and ignores the request path. `ServeHTTP` keeps serving discovery at `/.well-known/openid-configuration` below the issuer path and at the RFC 8414 location. Endpoint paths must start with `/`, must be distinct, and must not collide with the well-known paths; `New` validates this.

### Authorization endpoint

```go
func (p *Provider) ParseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error)
func (p *Provider) WriteAuthorizationError(w http.ResponseWriter, r *http.Request, err error)
func (p *Provider) SaveAuthorizationRequest(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) error
func (p *Provider) AuthorizationRequest(r *http.Request, id string) (*AuthorizationRequest, error)
func (p *Provider) Approve(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, a Approval) error
func (p *Provider) Deny(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, reason *Error) error
```

- `ParseAuthorizationRequest` performs today's validation and returns an unsaved request (`ID == ""`). Its errors remember whether they may be redirected to the client; `WriteAuthorizationError` redirects them, or renders `Config.ErrorPage` for errors that must not be redirected and for errors that did not come from parsing.
- `SaveAuthorizationRequest` assigns the ID, sets `BindingHash` and the binding cookie on the response, and stores the request. Within the same HTTP request, `Approve` and `Deny` accept the binding cookie from the `Set-Cookie` header already written to the response, because the user agent has not sent it back yet.
- `AuthorizationRequest` is unchanged: it loads a saved request and checks issuer, expiry and binding.
- `Approve` and `Deny`:
  1. For a saved request (`ID != ""`): load the stored copy, check issuer, expiry and binding (cookie on `r`, or the `Set-Cookie` header on `w`), compare protocol fields with `req` (D7), and delete the stored copy atomically. The stored copy is used from here on.
  2. Re-validate the request (D6): client exists; redirect URI registered; `response_type` is `code`; response mode valid for the redirect URI; scopes are a subset of the client's scopes; the PKCE policy is satisfied; the code challenge is well formed; issuer matches the request.
  3. `Approve` then validates the approval (unchanged rules) and issues the code; `Deny` sends the error.
- Compared protocol fields (D7): `Issuer`, `ClientID`, `RedirectURI`, `RedirectURIInRequest`, `ResponseType`, `ResponseMode`, `State`, `Scopes`, `CodeChallenge`, `CodeChallengeMethod`, `Nonce`, `Prompt`, `MaxAge`, `RequestedSubject`. Edits to a request must be made before saving it.
- `AuthorizationRequest.Extra map[string]string` holds non-empty parameters grantor does not process.
- `Deny` accepts any `reason.Code` made of the characters RFC 6749 allows for error codes; `reason.Description` and `reason.URI` are sent as `error_description` and `error_uri`.

Convenience layer: `ServeAuthorization` = parse → on error `WriteAuthorizationError` → `SaveAuthorizationRequest` → `Config.Interact`. `Config.Interact` stays required for `ServeAuthorization`/`ServeHTTP`, but `New` no longer requires it when only the low-level layer is used; `ServeAuthorization` without `Interact` responds with `server_error`.

### Token endpoint

```go
type TokenRequest struct {
	Client    *Client   // the authenticated client
	GrantType GrantType
	Scopes    []string  // the scope parameter, nil if it was not sent; may be narrowed before Exchange
	Form      url.Values // request parameters except client credentials, each with a single value

	// unexported: resolved issuer, authenticated client ID
}

type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
	IDToken      string
}

type GrantFunc func(ctx context.Context, req *TokenRequest) (*TokenResponse, error)

type Grant struct {
	Subject      string    // empty when no end-user is involved
	Scopes       []string  // subset of the client's scopes
	AuthTime     time.Time
	ACR          string
	AMR          []string
	RefreshToken bool      // also issue a refresh token; the client must allow the refresh_token grant
}

func (p *Provider) ParseTokenRequest(r *http.Request) (*TokenRequest, error)
func (p *Provider) Exchange(ctx context.Context, req *TokenRequest) (*TokenResponse, error)
func (p *Provider) IssueTokens(ctx context.Context, req *TokenRequest, g Grant) (*TokenResponse, error)
func (p *Provider) WriteTokenResponse(w http.ResponseWriter, resp *TokenResponse)
func (p *Provider) WriteTokenError(w http.ResponseWriter, r *http.Request, err error)
```

- `ParseTokenRequest`: POST form parsing, repeated-parameter check, client authentication, `grant_type` required. The scope parameter is parsed into `Scopes`. `client_secret` and `client_assertion` are removed from `Form`.
- `Exchange`: rejects a `TokenRequest` not produced by `ParseTokenRequest` or whose `Client.ID` no longer matches the authenticated client; dispatches to the built-in grants or `Config.Grants`; `unsupported_grant_type` when no handler exists, `unauthorized_client` when the client may not use the grant. For built-in grants, `Scopes` replaces the scope parameter: nil means "not sent" and grants everything the grant allows; otherwise it must be a subset of what the grant allows (`invalid_scope`) and becomes the access token scope. This applies to the authorization code grant too, so an application can narrow a code exchange. The refresh token keeps the grant's full scope, as RFC 6749 section 6 requires.
- `IssueTokens`: for custom grants. Validates the grant (subject syntax, scopes ⊆ client scopes, refresh token allowed, no `openid` without a subject), creates a new grant ID, runs `BeforeIssue`, issues the access token, optional refresh token and, when `openid` is granted with a subject, an ID token.
- Built-in grants call the same internal issuance path, so `BeforeIssue` runs for all grants.
- Custom grant types are declared per client in `Client.GrantTypes`; `Client` validation no longer rejects unknown grant types. `Config.Grants` must not redefine a built-in grant type, and its keys are added to `grant_types_supported`.

### Issuance hook

```go
type Issuance struct {
	Issuer       string
	GrantType    GrantType
	Client       *Client   // read-only
	GrantID      string
	Subject      string
	Scopes       []string  // may be narrowed
	AuthTime     time.Time
	RefreshToken bool      // may be set to false
}
```

`BeforeIssue` runs after all protocol checks and before any token is created. Returning an `*Error` sends it to the client; any other error becomes `server_error`. Afterwards grantor verifies that `Scopes` is a subset of the original scopes and that `RefreshToken` was not switched on; violations are server errors. For a code exchange the authorization code is consumed before the hook runs, so a rejected exchange cannot be retried with the same code; for a refresh the same holds for the refresh token.

### Errors

```go
type Error struct {
	Code        string
	Description string
	URI         string // sent as error_uri
	StatusCode  int    // HTTP status for token-style responses; 0 selects the default for Code
}
```

## Security invariants

These hold regardless of what the application does with the building blocks:

- Tokens are only issued to the client that authenticated in the same token request (`Exchange` checks the client ID).
- A code is only issued for a registered redirect URI, a valid response mode, scopes within the client registration, and a request that satisfies the client's PKCE policy (re-validated in `Approve`).
- Saved requests stay single-use, bound to the user agent, and immutable after saving.
- Hooks and custom grants can only narrow what is issued.

## Testing

- All existing tests pass after migrating to the new `Approve`/`Deny` signatures.
- New tests, one per criterion, using only the public API:
  1. Custom paths on `http.ServeMux` with per-endpoint middleware; discovery publishes the configured URLs; `ServeHTTP` routes configured paths.
  2. `BeforeIssue` rejects a refresh for a disabled user with a custom error, sees every grant type, narrows scopes, withholds a refresh token; attempts to widen are rejected.
  3. A custom grant type issues tokens via `IssueTokens`; unknown grant types and clients not allowed are rejected; `grant_types_supported` lists it.
  4. A custom authorization handler narrows scopes before saving, reads `Extra`, approves an unsaved request immediately, and denies with a custom error code and URI.
- Invariant tests: editing a saved request is rejected; `Approve` on an unsaved request with an unregistered redirect URI or a removed code challenge is rejected; a `TokenRequest` with a swapped client is rejected; a `TokenRequest` not from `ParseTokenRequest` is rejected.
- Example apps and the end-to-end test are migrated; a runnable example of the low-level layer is added (`examples/lowlevel`) and covered by a test.
- The OpenID conformance Basic OP, Config OP and Form Post Basic OP plans are re-run.
