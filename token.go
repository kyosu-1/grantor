package grantor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// TokenRequest is a parsed token request from an authenticated client,
// returned by [Provider.ParseTokenRequest].
type TokenRequest struct {
	// Client is the authenticated client, or for public clients the client
	// identified by client_id. Changing it has no effect; replacing it makes
	// Exchange fail.
	Client    *Client
	GrantType GrantType
	// Scopes is the scope parameter, or nil if it was not sent. It is always
	// nil for the authorization code grant, which has no scope parameter.
	// Changing it has no effect; narrow scopes in Config.BeforeIssue.
	Scopes []string
	// Form holds the request parameters except client credentials.
	Form url.Values

	iss    *resolvedIssuer
	client Client   // the authenticated client, unaffected by changes to Client
	scopes []string // the scope parameter, unaffected by changes to Scopes
}

// TokenResponse is a successful token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// ParseTokenRequest parses a token request and authenticates the client.
// Pass the result to Exchange, and write errors with WriteTokenError.
func (p *Provider) ParseTokenRequest(r *http.Request) (*TokenRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, &Error{Code: CodeInvalidRequest, Description: "unknown issuer", StatusCode: http.StatusNotFound, cause: err}
	}
	req, perr := p.parseToken(nil, r, iss)
	if perr != nil {
		return nil, perr
	}
	return req, nil
}

func (p *Provider) parseToken(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) (*TokenRequest, *Error) {
	if r.Method != http.MethodPost {
		return nil, &Error{Code: CodeInvalidRequest, Description: "the token endpoint only accepts POST", StatusCode: http.StatusMethodNotAllowed}
	}
	q, perr := parseForm(w, r)
	if perr != nil {
		return nil, perr
	}
	if len(q.repeated) > 0 {
		return nil, errInvalidRequest("parameters must not be repeated")
	}
	client, perr := p.authenticateClient(r, iss, q)
	if perr != nil {
		return nil, perr
	}
	if !q.has("grant_type") {
		return nil, errInvalidRequest("grant_type is required")
	}
	req := &TokenRequest{
		Client:    client,
		GrantType: GrantType(q.get("grant_type")),
		Form:      url.Values{},
		iss:       iss,
		client:    *client,
	}
	for name, v := range q.values {
		if name != "client_secret" && name != "client_assertion" {
			req.Form.Set(name, v)
		}
	}
	if q.has("scope") && req.GrantType != GrantTypeAuthorizationCode {
		req.scopes = splitSpaces(q.get("scope"))
		if req.scopes == nil {
			req.scopes = []string{}
		}
		req.Scopes = slices.Clone(req.scopes)
	}
	return req, nil
}

// checkTokenRequest rejects token requests that were not created by
// ParseTokenRequest or whose client was replaced, and returns a copy of the
// authenticated client.
func checkTokenRequest(req *TokenRequest) (*Client, *Error) {
	if req == nil || req.iss == nil {
		return nil, errServer(errors.New("the TokenRequest was not created by ParseTokenRequest"))
	}
	if req.Client == nil || req.Client.ID != req.client.ID {
		return nil, errServer(errors.New("TokenRequest.Client was replaced"))
	}
	c := req.client
	return &c, nil
}

// Exchange performs the grant of a token request and issues tokens.
func (p *Provider) Exchange(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	resp, perr := p.exchange(ctx, req)
	if perr != nil {
		return nil, perr
	}
	return resp, nil
}

func (p *Provider) exchange(ctx context.Context, req *TokenRequest) (*TokenResponse, *Error) {
	client, perr := checkTokenRequest(req)
	if perr != nil {
		return nil, perr
	}
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return p.exchangeAuthorizationCode(ctx, req, client)
	case GrantTypeRefreshToken:
		return p.exchangeRefreshToken(ctx, req, client)
	case GrantTypeClientCredentials:
		return p.exchangeClientCredentials(ctx, req, client)
	}
	fn, ok := p.cfg.Grants[req.GrantType]
	if !ok {
		return nil, newError(CodeUnsupportedGrantType, "the grant type is not supported")
	}
	if !client.allowsGrant(req.GrantType) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use this grant type")
	}
	resp, err := fn(ctx, req)
	if err != nil {
		return nil, asProtocolError(err)
	}
	if resp == nil {
		return nil, errServer(fmt.Errorf("grant %q returned no response", req.GrantType))
	}
	return resp, nil
}

// WriteTokenResponse writes a successful token response.
func (p *Provider) WriteTokenResponse(w http.ResponseWriter, resp *TokenResponse) {
	noStore(w)
	writeJSON(w, http.StatusOK, resp)
}

func (p *Provider) serveToken(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	req, perr := p.parseToken(w, r, iss)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	resp, perr := p.exchange(r.Context(), req)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	p.WriteTokenResponse(w, resp)
}

func (p *Provider) exchangeAuthorizationCode(ctx context.Context, req *TokenRequest, client *Client) (*TokenResponse, *Error) {
	iss := req.iss
	if !client.allowsGrant(GrantTypeAuthorizationCode) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use the authorization code grant")
	}
	code := req.Form.Get("code")
	if code == "" {
		return nil, errInvalidRequest("code is required")
	}
	hash := hashToken(code)
	t, perr := p.singleUseToken(ctx, iss, client, hash, TokenKindAuthorizationCode)
	if perr != nil {
		return nil, perr
	}

	// OAuth 2.1 removed redirect_uri from the token request, because PKCE
	// prevents code injection. It is still checked when sent, and required
	// as in RFC 6749 section 4.1.3 for codes issued without PKCE (OAuth 2.1
	// section 10.2).
	redirectURI := req.Form.Get("redirect_uri")
	if (redirectURI != "" || (t.RedirectURIInRequest && t.CodeChallenge == "")) && redirectURI != t.RedirectURI {
		return nil, errInvalidGrant("redirect_uri does not match the authorization request")
	}
	if perr := verifyPKCE(t, req.Form.Get("code_verifier")); perr != nil {
		return nil, perr
	}
	// Reuse is only acted on once the rest of the request is valid, so that
	// someone holding a stolen code without its verifier cannot revoke the
	// legitimate client's tokens (OAuth 2.1 section 7.5.3).
	if perr := p.checkUnused(ctx, t); perr != nil {
		return nil, perr
	}
	if perr := checkClientGrant(client, t); perr != nil {
		return nil, perr
	}
	accessScopes, perr := narrowScopes(t.Scopes, req.scopes)
	if perr != nil {
		return nil, perr
	}
	withRefresh := client.allowsGrant(GrantTypeRefreshToken) &&
		(!t.HasScope("openid") || t.HasScope("offline_access"))
	// The hook runs and the tokens are minted and stored before the code is
	// consumed, so that a failing hook, encoder, signing key or storage does
	// not turn the client's retry into a reuse that revokes the grant.
	plan, perr := p.planIssuance(ctx, req, client, t, accessScopes, withRefresh)
	if perr != nil {
		return nil, perr
	}
	// OpenID Connect Core section 3.1.3.3: a successful code exchange for an
	// OpenID Connect request returns an ID token, even if the access token
	// scope was narrowed.
	minted, perr := p.mintTokens(ctx, iss, client, t, plan, t.HasScope("openid"), t.Nonce, req.GrantType)
	if perr != nil {
		return nil, perr
	}
	return p.storeAndConsume(ctx, minted, hash)
}

func (p *Provider) exchangeRefreshToken(ctx context.Context, req *TokenRequest, client *Client) (*TokenResponse, *Error) {
	iss := req.iss
	if !client.allowsGrant(GrantTypeRefreshToken) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use the refresh token grant")
	}
	refreshToken := req.Form.Get("refresh_token")
	if refreshToken == "" {
		return nil, errInvalidRequest("refresh_token is required")
	}
	hash := hashToken(refreshToken)
	t, perr := p.singleUseToken(ctx, iss, client, hash, TokenKindRefreshToken)
	if perr != nil {
		return nil, perr
	}
	if perr := p.checkUnused(ctx, t); perr != nil {
		return nil, perr
	}
	// RFC 6749 section 6: the requested scope must not exceed the original.
	accessScopes, perr := narrowScopes(t.Scopes, req.scopes)
	if perr != nil {
		return nil, perr
	}
	if perr := checkClientGrant(client, t); perr != nil {
		return nil, perr
	}
	plan, perr := p.planIssuance(ctx, req, client, t, accessScopes, true)
	if perr != nil {
		return nil, perr
	}
	// Refresh tokens are rotated on every use; the new refresh token keeps
	// the scope and audience of the grant, while the access token may be
	// narrowed.
	minted, perr := p.mintTokens(ctx, iss, client, t, plan, slices.Contains(plan.scopes, "openid"), "", req.GrantType)
	if perr != nil {
		return nil, perr
	}
	return p.storeAndConsume(ctx, minted, hash)
}

func (p *Provider) exchangeClientCredentials(ctx context.Context, req *TokenRequest, client *Client) (*TokenResponse, *Error) {
	iss := req.iss
	if client.isPublic() || !client.allowsGrant(GrantTypeClientCredentials) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use the client credentials grant")
	}
	scopes, perr := validateScopes(client, req.scopes)
	if perr != nil {
		return nil, perr
	}
	if slices.Contains(scopes, "openid") || slices.Contains(scopes, "offline_access") {
		return nil, newError(CodeInvalidScope, "the client credentials grant has no end-user")
	}
	grant := &Token{GrantID: randomToken(), Issuer: iss.url, ClientID: client.ID, Scopes: scopes, Audience: slices.Clone(client.Audience)}
	return p.issueTokens(ctx, req, client, grant, scopes, false)
}

// narrowScopes applies a requested scope to the scopes a grant allows. A nil
// request keeps all of them.
func narrowScopes(allowed, requested []string) ([]string, *Error) {
	if requested == nil {
		return allowed, nil
	}
	var out []string
	for _, s := range requested {
		if !slices.Contains(allowed, s) {
			return nil, newError(CodeInvalidScope, "the requested scope exceeds the grant")
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// checkClientGrant rejects a grant whose scopes or audiences the client is no
// longer registered for.
func checkClientGrant(client *Client, grant *Token) *Error {
	for _, s := range grant.Scopes {
		if !slices.Contains(client.Scopes, s) {
			return newError(CodeInvalidScope, "the client may no longer request the granted scope")
		}
	}
	for _, a := range grant.Audience {
		if !slices.Contains(client.Audience, a) {
			return errInvalidGrant("the client may no longer access the granted audience")
		}
	}
	return nil
}

// singleUseToken loads an authorization code or refresh token issued by iss
// to client. It does not check whether the token was used or has expired;
// see checkUnused.
func (p *Provider) singleUseToken(ctx context.Context, iss *resolvedIssuer, client *Client, hash string, typ TokenKind) (*Token, *Error) {
	t, err := p.cfg.Storage.Token(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return nil, errInvalidGrant("the grant is invalid, expired or revoked")
	}
	if err != nil {
		return nil, errServer(err)
	}
	if t.Kind != typ || t.Issuer != iss.url || t.ClientID != client.ID {
		return nil, errInvalidGrant("the grant is invalid, expired or revoked")
	}
	return t, nil
}

// checkUnused rejects a single-use token that was already used, revoking its
// grant, or that has expired. Reuse is detected even after expiry, so that a
// replayed token still revokes what was issued from it.
func (p *Provider) checkUnused(ctx context.Context, t *Token) *Error {
	if !t.ConsumedAt.IsZero() {
		return p.revokeReusedGrant(ctx, t)
	}
	if !p.now().Before(t.ExpiresAt) {
		return errInvalidGrant("the grant is invalid, expired or revoked")
	}
	return nil
}

// consume atomically marks a single-use token as used.
func (p *Provider) consume(ctx context.Context, hash string) *Error {
	t, err := p.cfg.Storage.ConsumeToken(ctx, hash, p.now())
	if errors.Is(err, ErrNotFound) {
		return errInvalidGrant("the grant is invalid, expired or revoked")
	}
	if err != nil {
		return errServer(err)
	}
	if !t.ConsumedAt.IsZero() {
		return p.revokeReusedGrant(ctx, t)
	}
	return nil
}

// revokeReusedGrant revokes every token of a grant whose authorization code
// or refresh token was used twice, which indicates that it was stolen
// (OAuth 2.1 sections 4.1.3 and 4.3.1).
func (p *Provider) revokeReusedGrant(ctx context.Context, t *Token) *Error {
	if err := p.cfg.Storage.RevokeGrant(ctx, t.GrantID); err != nil {
		return errServer(err)
	}
	p.cfg.Logger.WarnContext(ctx, "grantor: single-use token reused; grant revoked",
		"client_id", t.ClientID, "token_type", string(t.Kind))
	return errInvalidGrant("the grant is invalid, expired or revoked")
}

// issueTokens runs Config.BeforeIssue and issues tokens for grants that do
// not consume a single-use token: client credentials and custom grants. An
// ID token is issued when the access token has the openid scope and the
// grant has a subject.
func (p *Provider) issueTokens(ctx context.Context, req *TokenRequest, client *Client, grant *Token, accessScopes []string, withRefresh bool) (*TokenResponse, *Error) {
	plan, perr := p.planIssuance(ctx, req, client, grant, accessScopes, withRefresh)
	if perr != nil {
		return nil, perr
	}
	minted, perr := p.mintTokens(ctx, req.iss, client, grant, plan, slices.Contains(plan.scopes, "openid"), "", req.GrantType)
	if perr != nil {
		return nil, perr
	}
	if perr := p.storeTokens(ctx, minted); perr != nil {
		return nil, perr
	}
	return minted.resp, nil
}

// mintedTokens are issued tokens that have not been stored yet.
type mintedTokens struct {
	resp    *TokenResponse
	records []*Token
}

// mintTokens creates the access token, and optionally a refresh token and an
// ID token, that plan describes for grant. It runs access token encoders,
// Config.Claims and signing, which may all fail, and stores nothing; see
// storeAndConsume. Every grant type issues tokens here after
// Config.BeforeIssue has run.
func (p *Provider) mintTokens(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, plan *issuePlan, withIDToken bool, nonce string, grantType GrantType) (*mintedTokens, *Error) {
	now := p.now()
	expiresAt := now.Add(plan.accessLifetime)
	at := &AccessToken{
		ID:        randomToken(),
		Issuer:    iss.url,
		ClientID:  client.ID,
		Subject:   grant.Subject,
		Audience:  plan.audience,
		Scopes:    plan.scopes,
		GrantType: grantType,
		AuthTime:  grant.AuthTime,
		ACR:       grant.ACR,
		AMR:       grant.AMR,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Claims:    plan.accessClaims,
	}
	accessToken, err := p.encodeAccessToken(ctx, iss, client, plan.format, at.clone())
	if err != nil {
		return nil, errServer(err)
	}
	resp := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(plan.accessLifetime / time.Second),
		Scope:       strings.Join(plan.scopes, " "),
	}

	derive := func(value string, typ TokenKind, scopes []string) *Token {
		t := *grant
		t.Hash = hashToken(value)
		t.Kind = typ
		t.Scopes = scopes
		t.RedirectURI, t.RedirectURIInRequest, t.Nonce = "", false, ""
		t.CodeChallenge, t.CodeChallengeMethod = "", ""
		t.CreatedAt = now
		t.ConsumedAt = time.Time{}
		t.AccessTokenClaims = nil
		return &t
	}

	access := derive(accessToken, TokenKindAccessToken, plan.scopes)
	access.Audience = plan.audience
	access.AccessTokenClaims = plan.accessClaims
	access.ExpiresAt = expiresAt
	minted := &mintedTokens{resp: resp, records: []*Token{access}}

	if plan.refresh {
		refreshToken := randomToken()
		refresh := derive(refreshToken, TokenKindRefreshToken, grant.Scopes)
		refresh.ExpiresAt = now.Add(plan.refreshLifetime)
		minted.records = append(minted.records, refresh)
		resp.RefreshToken = refreshToken
	}

	if withIDToken && grant.Subject != "" {
		idToken, err := p.issueIDToken(ctx, iss, client, access, nonce, accessToken, plan.idLifetime, plan.idClaims)
		if err != nil {
			return nil, errServer(err)
		}
		resp.IDToken = idToken
	}
	return minted, nil
}

// storeTokens stores minted tokens.
func (p *Provider) storeTokens(ctx context.Context, minted *mintedTokens) *Error {
	for _, t := range minted.records {
		if err := p.cfg.Storage.CreateToken(ctx, t); err != nil {
			return errServer(err)
		}
	}
	return nil
}

// storeAndConsume stores minted tokens and then consumes the authorization
// code or refresh token they were issued for. In this order a failure to
// store leaves the single-use token usable for a retry, and no token of a
// grant is stored after a revocation of the grant. Tokens stored before a
// failed consume are revoked, since they are never returned.
func (p *Provider) storeAndConsume(ctx context.Context, minted *mintedTokens, hash string) (*TokenResponse, *Error) {
	if perr := p.storeTokens(ctx, minted); perr != nil {
		p.discardTokens(ctx, minted)
		return nil, perr
	}
	if perr := p.consume(ctx, hash); perr != nil {
		p.discardTokens(ctx, minted)
		return nil, perr
	}
	return minted.resp, nil
}

// discardTokens revokes minted tokens that will not be returned to the
// client. Failures are logged; the token values were never disclosed.
func (p *Provider) discardTokens(ctx context.Context, minted *mintedTokens) {
	for _, t := range minted.records {
		if err := p.cfg.Storage.RevokeToken(ctx, t.Hash); err != nil {
			p.logError(ctx, "revoke undelivered token", err)
		}
	}
}
