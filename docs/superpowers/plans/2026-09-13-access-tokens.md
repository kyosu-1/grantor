# Access Tokens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pluggable access token formats (opaque, RFC 9068 JWT, custom), per-issuance claims, audiences and per-client/per-issuance lifetimes, plus in-process access token validation.

**Architecture:** A format only renders the token value; every access token is still stored by hash. `runBeforeIssue` becomes `planIssuance`, which resolves defaults (format, audience, lifetimes, claims), runs `Config.BeforeIssue`, and validates the result into an `issuePlan` that `mintTokens` executes.

**Tech Stack:** Go 1.26+, go-jose/v4 (existing dependency), `net/http`.

**Spec:** `docs/superpowers/specs/2026-09-13-access-tokens-design.md`

## Global Constraints

- No new module dependencies in the root module.
- Opaque access tokens stay the default; existing configurations behave exactly as before.
- Every access token, whatever its format, is stored by the SHA-256 hash of its value.
- Hooks and approvals can only narrow scopes and audiences within the client registration.
- Public docs must not name other OAuth libraries.
- `go vet ./...` and `go test -race ./...` pass in the root module and in `examples/` after every task.
- Commit messages end with the session's Co-Authored-By / Claude-Session trailer lines.

---

### Task 1: Data model, audiences and validation

**Files:**
- Modify: `records.go` (`Token.Audience`, `Token.AccessTokenClaims`)
- Modify: `client.go` (`AccessTokenFormat` type and constants, new `Client` fields, `accessTokenAlg`, lifetime validation)
- Modify: `provider.go` (`Config.AccessTokenFormat`, `Config.AccessTokenFormats`, `New` validation, `client()` format check)
- Modify: `approve.go` (`Approval.Audience`, `completable` returns the client, audience resolution, code record audience)
- Modify: `issue.go` (`Grant.Audience`)
- Modify: `token.go` (client credentials grant audience)
- Modify: `errors.go` (`CodeInvalidTarget`)
- Modify: `storagetest/storagetest.go` (round-trip the new fields)
- Test: `accesstoken_test.go` (new)

**Interfaces:**
- Produces:
  - `type AccessTokenFormat string`; `AccessTokenFormatOpaque`, `AccessTokenFormatJWT`
  - `Client.AccessTokenFormat AccessTokenFormat`, `Client.AccessTokenSigningAlg string`, `Client.Audience []string`, `Client.AccessTokenLifetime`, `Client.RefreshTokenLifetime`, `Client.IDTokenLifetime time.Duration`
  - `Config.AccessTokenFormat AccessTokenFormat`, `Config.AccessTokenFormats map[AccessTokenFormat]AccessTokenEncoder` (type declared in Task 2; declare `AccessTokenEncoder` and `SignFunc` here so the config compiles)
  - `Token.Audience []string`, `Token.AccessTokenClaims map[string]any`
  - `Approval.Audience []string`, `Grant.Audience []string`
  - `func resolveAudience(allowed, requested []string) ([]string, error)`
  - `func (p *Provider) knownFormat(f AccessTokenFormat) bool`

- [ ] **Step 1: Write the failing tests**

```go
func TestAudienceFromApproval(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "api-client", SecretHash: grantor.HashSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid", "api"},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Audience: []string{"https://a.example.com", "https://b.example.com"}, PKCE: grantor.PKCEOptional,
	})
	req := e.startAuthorization(authParams("api-client", "openid api", pkcePair{}))
	if _, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: []string{"https://c.example.com"}}); err == nil {
		t.Fatal("Approve accepted an audience outside the client registration")
	}
	rec, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Audience: []string{"https://a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	status, body := e.exchangeCode("api-client", redirectParams(t, rec).Get("code"), "", basic("api-client", confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, body)
	}
	if info := e.introspect(body["access_token"].(string), "api-client"); info["aud"] != "https://a.example.com" {
		t.Fatalf("introspection aud = %v", info["aud"])
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
		"redefine jwt":    func(c *grantor.Config) { c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{"jwt": enc} },
		"empty name":      func(c *grantor.Config) { c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{"": enc} },
		"nil encoder":     func(c *grantor.Config) { c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{"x": nil} },
		"unknown default": func(c *grantor.Config) { c.AccessTokenFormat = "paseto" },
	} {
		cfg := base()
		modify(&cfg)
		if _, err := grantor.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}
```
(`introspect` returning `aud` is completed in Task 3; in Task 1 assert only that the exchange succeeds and the stored token audience via `ValidateAccessToken` arrives in Task 3 — for Task 1 run `TestAccessTokenConfigValidation` and the Approve rejection half.)

- [ ] **Step 2: Run** `go test -run 'TestAccessTokenConfigValidation' .` — compile failure.
- [ ] **Step 3: Implement.**

`client.go`:
```go
// AccessTokenFormat names how access token values are encoded.
type AccessTokenFormat string

const (
	// AccessTokenFormatOpaque issues random 43-character tokens. It is the default.
	AccessTokenFormatOpaque AccessTokenFormat = "opaque"
	// AccessTokenFormatJWT issues JWT access tokens (RFC 9068).
	AccessTokenFormatJWT AccessTokenFormat = "jwt"
)
```
New `Client` fields with doc comments (as in the spec); `func (c *Client) accessTokenAlg() string` returning `"RS256"` when empty; in `validate`, reject negative `AccessTokenLifetime`, `RefreshTokenLifetime`, `IDTokenLifetime`.

`records.go` `Token`:
```go
	// Audience lists the intended recipients of access tokens of the grant.
	Audience []string `json:"audience,omitempty"`
	// AccessTokenClaims are extra claims of an access token, set by
	// Config.BeforeIssue.
	AccessTokenClaims map[string]any `json:"access_token_claims,omitempty"`
```

`provider.go`: `Config` fields
```go
	// AccessTokenFormat is the format of access tokens for clients that do not
	// set Client.AccessTokenFormat. It defaults to AccessTokenFormatOpaque.
	AccessTokenFormat AccessTokenFormat

	// AccessTokenFormats adds custom access token formats.
	AccessTokenFormats map[AccessTokenFormat]AccessTokenEncoder
```
In `New`: reject empty names, `opaque`/`jwt` keys, nil encoders; reject unknown `cfg.AccessTokenFormat` (after defaults "" → opaque). `knownFormat`:
```go
func (p *Provider) knownFormat(f AccessTokenFormat) bool {
	if f == AccessTokenFormatOpaque || f == AccessTokenFormatJWT {
		return true
	}
	_, ok := p.cfg.AccessTokenFormats[f]
	return ok
}
```
In `client()`: `if c.AccessTokenFormat != "" && !p.knownFormat(c.AccessTokenFormat)` → error.

`approve.go`: `Approval.Audience []string` (doc: subset of `Client.Audience`, nil means all of it). `completable` returns `(*resolvedIssuer, *Client, *AuthorizationRequest, error)`; `Approve` calls `audience, err := resolveAudience(client.Audience, a.Audience)` and stores `Audience: audience` on the code record.
```go
// resolveAudience returns the requested audiences, which must all be
// allowed, or all allowed audiences when requested is nil.
func resolveAudience(allowed, requested []string) ([]string, error) {
	if requested == nil {
		return slices.Clone(allowed), nil
	}
	out := []string{}
	for _, a := range requested {
		if !slices.Contains(allowed, a) {
			return nil, fmt.Errorf("grantor: audience %q is not registered for the client", a)
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, nil
}
```
`issue.go`: `Grant.Audience []string`; `issueGrant` resolves it, returning `newError(CodeInvalidTarget, "the audience is not registered for the client")` on error, and sets `grant.Audience`. `token.go` client credentials: `Audience: slices.Clone(client.Audience)`. `errors.go`: `CodeInvalidTarget = "invalid_target"`. Declare in `accesstoken.go` (new):
```go
// SignFunc signs claims as a compact JWS with the issuer's key for the
// client's access token signing algorithm; typ is the JOSE typ header.
type SignFunc func(typ string, claims any) (string, error)

// AccessTokenEncoder returns the value of an access token in a custom format.
// The value must be unique and impossible to guess: grantor stores only its
// hash and looks tokens up by it.
type AccessTokenEncoder func(ctx context.Context, at *AccessToken, sign SignFunc) (string, error)
```
and the `AccessToken` struct from the spec. `storagetest`: add `Audience: []string{"https://api.example.com"}` and `AccessTokenClaims: map[string]any{"tenant": "acme", "admin": true}` to `fullToken`.

- [ ] **Step 4: Run** `go test -race ./... && (cd examples && go test ./...)` — PASS.
- [ ] **Step 5: Commit** "Add access token formats, audiences and lifetimes to the data model".

### Task 2: Issuance plan, formats and JWT access tokens

**Files:**
- Modify: `issue.go` (`Issuance` fields; `runBeforeIssue` → `planIssuance` returning `*issuePlan`)
- Modify: `token.go` (`mintTokens(ctx, iss, client, grant, plan, withIDToken, nonce, grantType)`; callers)
- Modify: `accesstoken.go` (`encodeAccessToken`, `jwtAccessTokenClaims`, protected claim set)
- Modify: `idtoken.go` (`issueIDToken` takes lifetime and extra claims)
- Test: `accesstoken_test.go`, `helpers_test.go` (`parseJWT`)

**Interfaces:**
- Consumes: Task 1 types.
- Produces:
  - `type issuePlan struct { scopes, audience []string; refresh bool; format AccessTokenFormat; accessClaims, idClaims map[string]any; accessLifetime, refreshLifetime, idLifetime time.Duration }`
  - `func (p *Provider) planIssuance(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, grantType GrantType, scopes []string, withRefresh bool) (*issuePlan, *Error)`
  - `func (p *Provider) encodeAccessToken(ctx context.Context, iss *resolvedIssuer, client *Client, format AccessTokenFormat, at *AccessToken) (string, error)`
  - Test helper `func (e *env) parseJWT(token string) (header map[string]any, claims map[string]any)`

- [ ] **Step 1: Write the failing tests**

```go
func TestJWTAccessToken(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "jwt-at", SecretHash: grantor.HashSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect}, Scopes: []string{"openid", "api", "offline_access"},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Audience: []string{"https://api.example.com"}, AccessTokenFormat: grantor.AccessTokenFormatJWT,
		AccessTokenLifetime: 5 * time.Minute, PKCE: grantor.PKCEOptional,
	})
	body := e.tokensFor("jwt-at", "openid api offline_access")
	at := body["access_token"].(string)
	header, claims := e.parseJWT(at)
	if header["typ"] != "at+jwt" || header["kid"] != "rsa-1" {
		t.Fatalf("header = %v", header)
	}
	want := map[string]any{"iss": testIssuer, "sub": "alice", "aud": "https://api.example.com", "client_id": "jwt-at", "scope": "openid api offline_access"}
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
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic(serviceClient, confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("client credentials = %d %v", status, body)
	}
	_, claims := e.parseJWT(body["access_token"].(string))
	if claims["sub"] != serviceClient || claims["aud"] != serviceClient || claims["scope"] != nil || claims["auth_time"] != nil {
		t.Fatalf("claims = %v", claims)
	}
}

func TestAccessTokenFormatSelection(t *testing.T) {
	e := newEnv(t, func(c *grantor.Config) { c.AccessTokenFormat = grantor.AccessTokenFormatJWT })
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "opaque-client", SecretHash: grantor.HashSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, Scopes: []string{"api"},
		AccessTokenFormat: grantor.AccessTokenFormatOpaque,
	})
	_, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("opaque-client", confidentialSecret))
	if strings.Count(body["access_token"].(string), ".") != 0 {
		t.Fatalf("client override to opaque was ignored: %v", body["access_token"])
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
		t.Fatalf("hook format change was ignored: %v", body["access_token"])
	}
}

func TestCustomAccessTokenFormats(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.AccessTokenFormats = map[grantor.AccessTokenFormat]grantor.AccessTokenEncoder{
			"prefixed": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				return "gat_" + at.ID, nil
			},
			"scp-jwt": func(ctx context.Context, at *grantor.AccessToken, sign grantor.SignFunc) (string, error) {
				return sign("JWT", map[string]any{"iss": at.Issuer, "sub": at.Subject, "scp": at.Scopes, "exp": at.ExpiresAt.Unix(), "jti": at.ID})
			},
		}
	})
	for format, check := range map[grantor.AccessTokenFormat]func(string){
		"prefixed": func(at string) {
			if !strings.HasPrefix(at, "gat_") {
				t.Errorf("prefixed token = %q", at)
			}
		},
		"scp-jwt": func(at string) {
			if header, claims := e.parseJWT(at); header["typ"] != "JWT" || claims["scp"] == nil {
				t.Errorf("scp-jwt = %v %v", header, claims)
			}
		},
	} {
		e.store.SetClient(testIssuer, grantor.Client{
			ID: "custom", SecretHash: grantor.HashSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
			Scopes: []string{"openid", "api"}, AccessTokenFormat: format, PKCE: grantor.PKCEOptional,
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
	}
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "unknown-format", SecretHash: grantor.HashSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials}, AccessTokenFormat: "paseto",
	})
	status, body := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, basic("unknown-format", confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
}

func TestIssuanceClaimsAudienceAndLifetimes(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	e.store.SetClient(testIssuer, grantor.Client{
		ID: "rich", SecretHash: grantor.HashSecret(confidentialSecret), RedirectURIs: []string{clientRedirect},
		GrantTypes: []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes: []string{"openid", "api", "offline_access"}, Audience: []string{"https://a.example.com", "https://b.example.com"},
		AccessTokenFormat: grantor.AccessTokenFormatJWT, RefreshTokenLifetime: time.Hour, IDTokenLifetime: 10 * time.Minute,
		PKCE: grantor.PKCEOptional,
	})
	e.p = mustProvider(t, e, func(c *grantor.Config) {
		c.BeforeIssue = func(ctx context.Context, is *grantor.Issuance) error {
			is.AccessTokenClaims = map[string]any{"tenant": "acme"}
			is.IDTokenClaims = map[string]any{"tenant": "acme"}
			if is.GrantType == grantor.GrantTypeRefreshToken {
				is.Audience = []string{"https://b.example.com"}
				is.AccessTokenLifetime = 2 * time.Minute
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
	if info := e.introspect(body["access_token"].(string), "rich"); info["tenant"] != "acme" {
		t.Fatalf("introspection = %v", info)
	}

	status, refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}, basic("rich", confidentialSecret))
	if status != http.StatusOK || refreshed["expires_in"] != float64(120) {
		t.Fatalf("refresh = %d %v", status, refreshed)
	}
	if _, claims := e.parseJWT(refreshed["access_token"].(string)); claims["aud"] != "https://b.example.com" {
		t.Fatalf("narrowed audience = %v", claims["aud"])
	}
	// The refresh token keeps the full audience of the grant.
	if info := e.introspect(refreshed["refresh_token"].(string), "rich"); len(info["aud"].([]any)) != 2 {
		t.Fatalf("refresh token audience = %v", info["aud"])
	}
	e.clock.Advance(2 * time.Hour)
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
```
`helpers_test.go`:
```go
// parseJWT verifies a JWT with the provider's JWKS and returns its header
// and claims.
func (e *env) parseJWT(token string) (map[string]any, map[string]any) {
	e.t.Helper()
	claims := e.verifyJWT(token)
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		e.t.Fatalf("decode JWT header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		e.t.Fatalf("parse JWT header: %v", err)
	}
	return header, claims
}
```

- [ ] **Step 2: Run** the new tests — compile failure (Issuance fields).
- [ ] **Step 3: Implement.**

`issue.go`, `Issuance` gains:
```go
	// Audience lists the audiences of the access token. The hook may remove
	// audiences but not add any.
	Audience []string
	// AccessTokenFormat is the format of the access token. The hook may
	// choose any configured format.
	AccessTokenFormat AccessTokenFormat
	// AccessTokenClaims and IDTokenClaims are extra claims. Protocol claims
	// such as iss, sub, aud and exp cannot be set.
	AccessTokenClaims map[string]any
	IDTokenClaims     map[string]any
	// Lifetimes of the tokens; the hook may set any positive value.
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	IDTokenLifetime      time.Duration
```
`planIssuance` (replaces `runBeforeIssue`):
```go
type issuePlan struct {
	scopes, audience                            []string
	refresh                                     bool
	format                                      AccessTokenFormat
	accessClaims, idClaims                      map[string]any
	accessLifetime, refreshLifetime, idLifetime time.Duration
}

func (p *Provider) planIssuance(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, grantType GrantType, scopes []string, withRefresh bool) (*issuePlan, *Error) {
	plan := &issuePlan{
		scopes:          scopes,
		audience:        grant.Audience,
		refresh:         withRefresh,
		format:          firstFormat(client.AccessTokenFormat, p.cfg.AccessTokenFormat),
		accessLifetime:  firstDuration(client.AccessTokenLifetime, p.cfg.Lifetimes.AccessToken),
		refreshLifetime: firstDuration(client.RefreshTokenLifetime, p.cfg.Lifetimes.RefreshToken),
		idLifetime:      firstDuration(client.IDTokenLifetime, p.cfg.Lifetimes.IDToken),
	}
	if p.cfg.BeforeIssue == nil {
		return plan, nil
	}
	c := *client
	is := &Issuance{
		Issuer: iss.url, GrantType: grantType, Client: &c, GrantID: grant.GrantID,
		Subject: grant.Subject, AuthTime: grant.AuthTime,
		Scopes: slices.Clone(scopes), RefreshToken: withRefresh,
		Audience: slices.Clone(grant.Audience), AccessTokenFormat: plan.format,
		AccessTokenLifetime: plan.accessLifetime, RefreshTokenLifetime: plan.refreshLifetime, IDTokenLifetime: plan.idLifetime,
	}
	if err := p.cfg.BeforeIssue(ctx, is); err != nil {
		return nil, asProtocolError(err)
	}
	var err error
	if plan.scopes, err = narrowed(scopes, is.Scopes, "scope"); err != nil {
		return nil, errServer(fmt.Errorf("BeforeIssue: %w", err))
	}
	if plan.audience, err = narrowed(grant.Audience, is.Audience, "audience"); err != nil {
		return nil, errServer(fmt.Errorf("BeforeIssue: %w", err))
	}
	switch {
	case is.RefreshToken && !withRefresh:
		return nil, errServer(errors.New("BeforeIssue enabled a refresh token"))
	case !p.knownFormat(is.AccessTokenFormat):
		return nil, errServer(fmt.Errorf("BeforeIssue chose the unknown access token format %q", is.AccessTokenFormat))
	case is.AccessTokenLifetime <= 0 || is.RefreshTokenLifetime <= 0 || is.IDTokenLifetime <= 0:
		return nil, errServer(errors.New("BeforeIssue set a lifetime that is not positive"))
	}
	for name := range is.AccessTokenClaims {
		if accessTokenProtectedClaims[name] {
			return nil, errServer(fmt.Errorf("BeforeIssue set the protected access token claim %q", name))
		}
	}
	for name := range is.IDTokenClaims {
		if protocolClaims[name] {
			return nil, errServer(fmt.Errorf("BeforeIssue set the protected ID token claim %q", name))
		}
	}
	plan.refresh = is.RefreshToken
	plan.format = is.AccessTokenFormat
	plan.accessClaims, plan.idClaims = is.AccessTokenClaims, is.IDTokenClaims
	plan.accessLifetime, plan.refreshLifetime, plan.idLifetime = is.AccessTokenLifetime, is.RefreshTokenLifetime, is.IDTokenLifetime
	return plan, nil
}

// narrowed checks that got only contains values of allowed and returns it
// without duplicates.
func narrowed(allowed, got []string, what string) ([]string, error) {
	var out []string
	for _, v := range got {
		if !slices.Contains(allowed, v) {
			return nil, fmt.Errorf("added the %s %q", what, v)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

func firstFormat(formats ...AccessTokenFormat) AccessTokenFormat {
	for _, f := range formats {
		if f != "" {
			return f
		}
	}
	return AccessTokenFormatOpaque
}

func firstDuration(ds ...time.Duration) time.Duration {
	for _, d := range ds {
		if d > 0 {
			return d
		}
	}
	return 0
}
```
`accesstoken.go`:
```go
// accessTokenProtectedClaims are set by grantor in JWT access tokens and
// introspection responses.
var accessTokenProtectedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	"client_id": true, "scope": true, "auth_time": true, "acr": true, "amr": true, "cnf": true,
	"active": true, "token_type": true,
}

func (p *Provider) encodeAccessToken(ctx context.Context, iss *resolvedIssuer, client *Client, format AccessTokenFormat, at *AccessToken) (string, error) {
	sign := func(typ string, claims any) (string, error) {
		key, ok := iss.keys.forAlg(client.accessTokenAlg())
		if !ok {
			return "", fmt.Errorf("issuer has no key for the %s algorithm of client %q", client.accessTokenAlg(), client.ID)
		}
		return key.sign(claims, typ)
	}
	var value string
	var err error
	switch format {
	case AccessTokenFormatOpaque:
		return randomToken(), nil
	case AccessTokenFormatJWT:
		value, err = sign("at+jwt", jwtAccessTokenClaims(at))
	default:
		enc, ok := p.cfg.AccessTokenFormats[format]
		if !ok {
			return "", fmt.Errorf("unknown access token format %q", format)
		}
		value, err = enc(ctx, at, sign)
	}
	if err != nil {
		return "", fmt.Errorf("encode %s access token: %w", format, err)
	}
	if value == "" {
		return "", fmt.Errorf("the %s access token encoder returned an empty token", format)
	}
	return value, nil
}

// jwtAccessTokenClaims returns the RFC 9068 claims of an access token.
func jwtAccessTokenClaims(at *AccessToken) map[string]any {
	claims := map[string]any{}
	for k, v := range at.Claims {
		claims[k] = v
	}
	claims["iss"] = at.Issuer
	claims["sub"] = at.Subject
	if at.Subject == "" {
		claims["sub"] = at.ClientID
	}
	if len(at.Audience) == 1 {
		claims["aud"] = at.Audience[0]
	} else {
		claims["aud"] = at.Audience
	}
	claims["exp"] = at.ExpiresAt.Unix()
	claims["iat"] = at.IssuedAt.Unix()
	claims["jti"] = at.ID
	claims["client_id"] = at.ClientID
	if len(at.Scopes) > 0 {
		claims["scope"] = strings.Join(at.Scopes, " ")
	}
	if !at.AuthTime.IsZero() {
		claims["auth_time"] = at.AuthTime.Unix()
	}
	if at.ACR != "" {
		claims["acr"] = at.ACR
	}
	if len(at.AMR) > 0 {
		claims["amr"] = at.AMR
	}
	return claims
}
```
`token.go`: code exchange and refresh call `plan, perr := p.planIssuance(...)` before `consume`, then `p.mintTokens(ctx, iss, client, t, plan, withIDToken, nonce, req.GrantType)`; `issueTokens` calls `planIssuance` then `mintTokens`. `mintTokens`:
```go
func (p *Provider) mintTokens(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, plan *issuePlan, withIDToken bool, nonce string, grantType GrantType) (*TokenResponse, *Error) {
	now := p.now()
	audience := plan.audience
	if len(audience) == 0 {
		audience = []string{client.ID}
	}
	at := &AccessToken{
		ID: randomToken(), Issuer: iss.url, ClientID: client.ID, Subject: grant.Subject,
		Audience: slices.Clone(audience), Scopes: slices.Clone(plan.scopes), GrantType: grantType,
		AuthTime: grant.AuthTime, ACR: grant.ACR, AMR: slices.Clone(grant.AMR),
		IssuedAt: now, ExpiresAt: now.Add(plan.accessLifetime), Claims: plan.accessClaims,
	}
	accessToken, err := p.encodeAccessToken(ctx, iss, client, plan.format, at)
	if err != nil {
		return nil, errServer(err)
	}
	resp := &TokenResponse{
		AccessToken: accessToken, TokenType: "Bearer",
		ExpiresIn: int64(plan.accessLifetime.Seconds()), Scope: strings.Join(plan.scopes, " "),
	}
	derive := func(value string, typ TokenType, scopes []string) *Token { /* as today, plus t.AccessTokenClaims = nil */ }
	access := derive(accessToken, TokenTypeAccessToken, plan.scopes)
	access.Audience = plan.audience
	access.AccessTokenClaims = plan.accessClaims
	access.ExpiresAt = at.ExpiresAt
	toStore := []*Token{access}
	if plan.refresh {
		refreshToken := randomToken()
		refresh := derive(refreshToken, TokenTypeRefreshToken, grant.Scopes)
		refresh.ExpiresAt = now.Add(plan.refreshLifetime)
		toStore = append(toStore, refresh)
		resp.RefreshToken = refreshToken
	}
	if withIDToken && grant.Subject != "" {
		idToken, err := p.issueIDToken(ctx, iss, client, access, nonce, accessToken, plan.idLifetime, plan.idClaims)
		// ...
	}
	// ...store as today
}
```
`idtoken.go`: `issueIDToken(ctx, iss, client, grant, nonce, accessToken string, lifetime time.Duration, extra map[string]any)`: after end-user claims, copy `extra` into `claims`, then set protocol claims; `exp` uses `lifetime`.

- [ ] **Step 4: Run** `go test -race ./... && (cd examples && go test ./...)` — PASS.
- [ ] **Step 5: Commit** "Issue JWT and custom access token formats with claims, audiences and lifetimes".

### Task 3: Introspection and in-process validation

**Files:**
- Modify: `introspect.go` (`aud`, access token claims)
- Create: `validate.go` (`ValidateAccessToken`)
- Test: `accesstoken_test.go`

**Interfaces:**
- Produces: `func (p *Provider) ValidateAccessToken(r *http.Request, token string) (*Token, error)`

- [ ] **Step 1: Write the failing test**

```go
func TestValidateAccessToken(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	body := e.tokensFor(confidentialClient, "openid offline_access")
	r := httpGet(testIssuer + "/api")
	got, err := e.p.ValidateAccessToken(r, body["access_token"].(string))
	if err != nil || got.Subject != "alice" || got.Type != grantor.TokenTypeAccessToken {
		t.Fatalf("ValidateAccessToken = %+v, %v", got, err)
	}
	if _, err := e.p.ValidateAccessToken(r, body["refresh_token"].(string)); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("refresh token = %v", err)
	}
	if _, err := e.p.ValidateAccessToken(r, "unknown"); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("unknown token = %v", err)
	}
	e.clock.Advance(2 * time.Hour)
	if _, err := e.p.ValidateAccessToken(r, body["access_token"].(string)); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("expired token = %v", err)
	}
}
```
Also re-enable the `aud` assertion in `TestAudienceFromApproval`.

- [ ] **Step 2: Run** — compile failure.
- [ ] **Step 3: Implement.** `validate.go`:
```go
// ValidateAccessToken returns the stored access token if token is an active
// access token of the issuer r belongs to, or ErrNotFound. Resource servers
// in the same process use it instead of the introspection endpoint.
func (p *Provider) ValidateAccessToken(r *http.Request, token string) (*Token, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	t, err := p.cfg.Storage.Token(r.Context(), hashToken(token))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("grantor: look up access token: %w", err)
	}
	if t.Type != TokenTypeAccessToken || t.Issuer != iss.url || !p.now().Before(t.ExpiresAt) {
		return nil, ErrNotFound
	}
	return t, nil
}
```
`introspect.go`, before writing an active response:
```go
	for name, value := range t.AccessTokenClaims {
		if !accessTokenProtectedClaims[name] {
			resp[name] = value
		}
	}
	switch len(t.Audience) {
	case 0:
	case 1:
		resp["aud"] = t.Audience[0]
	default:
		resp["aud"] = t.Audience
	}
```
- [ ] **Step 4: Run** `go test -race ./...` — PASS.
- [ ] **Step 5: Commit** "Return audiences and claims from introspection; add ValidateAccessToken".

### Task 4: Example and documentation

**Files:**
- Modify: `examples/lowlevel/server.go` (client `cli` uses JWT access tokens with audience `https://api.example.com`; `BeforeIssue` adds a `tenant` claim)
- Modify: `examples/lowlevel/server_test.go` (assert the JWT `typ`, `aud`, `tenant`)
- Modify: `README.md` (Features: access token formats; new "Access tokens" section), `docs/design.md` (Tokens section), `doc.go` (supported specifications: RFC 9068)

- [ ] **Step 1: Write the failing test** — in `TestLowLevelServer` after the code exchange:
```go
	parts := strings.Split(tok["access_token"].(string), ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT: %v", tok["access_token"])
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	if claims["aud"] != "https://api.example.com" || claims["tenant"] != "example" {
		t.Fatalf("access token claims = %v", claims)
	}
```
- [ ] **Step 2: Run** `cd examples && go test ./lowlevel/` — FAIL.
- [ ] **Step 3: Implement** the example changes (`AccessTokenFormat: grantor.AccessTokenFormatJWT`, `Audience: []string{"https://api.example.com"}`, `is.AccessTokenClaims = map[string]any{"tenant": "example"}` in the hook) and the docs:
  - README Features bullet: "**Access tokens**: opaque by default, JWT access tokens (RFC 9068), or a custom format; per-client and per-issuance audiences, claims and lifetimes".
  - README "Access tokens" section with a client example, a `BeforeIssue` claims/lifetime example, a custom encoder example, the revocation trade-off, and `ValidateAccessToken`.
  - Specifications table row for RFC 9068.
  - design.md Tokens section: formats only render values; storage by hash; audience and claims flow.
- [ ] **Step 4: Run** all tests — PASS.
- [ ] **Step 5: Commit** "Document access token formats and use JWT access tokens in the low-level example".

### Task 5: Verification

- [ ] `gofmt -l .` is empty; `go vet ./...` and `go test -race ./...` pass in root and `examples/`.
- [ ] Independent code review of the range (superpowers:requesting-code-review); fix Critical and Important findings with regression tests.
- [ ] Re-run the OpenID conformance Basic OP, Config OP and Form Post Basic OP plans; no FAILED or WARNING results.
- [ ] Push to `main`; CI green.
