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
	// Setting or narrowing it before Exchange narrows the access token of
	// the authorization code and refresh token grants and the scope of the
	// client credentials grant.
	Scopes []string
	// Form holds the request parameters except client credentials.
	Form url.Values

	iss    *resolvedIssuer
	client Client // the authenticated client, unaffected by changes to Client
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
		req.Scopes = splitSpaces(q.get("scope"))
		if req.Scopes == nil {
			req.Scopes = []string{}
		}
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
	t, perr := p.singleUseToken(ctx, iss, client, hash, TokenTypeAuthorizationCode)
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
	if perr := checkClientScopes(client, t.Scopes); perr != nil {
		return nil, perr
	}
	accessScopes, perr := narrowScopes(t.Scopes, req.Scopes)
	if perr != nil {
		return nil, perr
	}
	withRefresh := client.allowsGrant(GrantTypeRefreshToken) &&
		(!t.HasScope("openid") || t.HasScope("offline_access"))
	// The hook runs before the code is consumed, so that a failing hook does
	// not turn the client's retry into a reuse that revokes the grant.
	accessScopes, withRefresh, perr = p.runBeforeIssue(ctx, iss, client, t, req.GrantType, accessScopes, withRefresh)
	if perr != nil {
		return nil, perr
	}
	if perr := p.consume(ctx, hash); perr != nil {
		return nil, perr
	}
	// OpenID Connect Core section 3.1.3.3: a successful code exchange for an
	// OpenID Connect request returns an ID token, even if the access token
	// scope was narrowed.
	return p.mintTokens(ctx, iss, client, t, accessScopes, withRefresh, t.HasScope("openid"), t.Nonce)
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
	t, perr := p.singleUseToken(ctx, iss, client, hash, TokenTypeRefreshToken)
	if perr != nil {
		return nil, perr
	}
	if perr := p.checkUnused(ctx, t); perr != nil {
		return nil, perr
	}
	// RFC 6749 section 6: the requested scope must not exceed the original.
	accessScopes, perr := narrowScopes(t.Scopes, req.Scopes)
	if perr != nil {
		return nil, perr
	}
	if perr := checkClientScopes(client, t.Scopes); perr != nil {
		return nil, perr
	}
	accessScopes, withRefresh, perr := p.runBeforeIssue(ctx, iss, client, t, req.GrantType, accessScopes, true)
	if perr != nil {
		return nil, perr
	}
	if perr := p.consume(ctx, hash); perr != nil {
		return nil, perr
	}
	// Refresh tokens are rotated on every use; the new refresh token keeps
	// the scope of the grant, while the access token may be narrowed.
	return p.mintTokens(ctx, iss, client, t, accessScopes, withRefresh, slices.Contains(accessScopes, "openid"), "")
}

func (p *Provider) exchangeClientCredentials(ctx context.Context, req *TokenRequest, client *Client) (*TokenResponse, *Error) {
	iss := req.iss
	if client.isPublic() || !client.allowsGrant(GrantTypeClientCredentials) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use the client credentials grant")
	}
	scopes, perr := validateScopes(client, req.Scopes)
	if perr != nil {
		return nil, perr
	}
	if slices.Contains(scopes, "openid") || slices.Contains(scopes, "offline_access") {
		return nil, newError(CodeInvalidScope, "the client credentials grant has no end-user")
	}
	grant := &Token{GrantID: randomToken(), Issuer: iss.url, ClientID: client.ID, Scopes: scopes}
	return p.issueTokens(ctx, iss, client, grant, scopes, false, req.GrantType)
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

// checkClientScopes rejects a grant whose scopes the client is no longer
// registered for.
func checkClientScopes(client *Client, scopes []string) *Error {
	for _, s := range scopes {
		if !slices.Contains(client.Scopes, s) {
			return newError(CodeInvalidScope, "the client may no longer request the granted scope")
		}
	}
	return nil
}

// singleUseToken loads an authorization code or refresh token issued by iss
// to client. It does not check whether the token was used or has expired;
// see checkUnused.
func (p *Provider) singleUseToken(ctx context.Context, iss *resolvedIssuer, client *Client, hash string, typ TokenType) (*Token, *Error) {
	t, err := p.cfg.Storage.Token(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return nil, errInvalidGrant("the grant is invalid, expired or revoked")
	}
	if err != nil {
		return nil, errServer(err)
	}
	if t.Type != typ || t.Issuer != iss.url || t.ClientID != client.ID {
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
		"client_id", t.ClientID, "token_type", string(t.Type))
	return errInvalidGrant("the grant is invalid, expired or revoked")
}

// issueTokens runs Config.BeforeIssue and issues tokens for grants that do
// not consume a single-use token: client credentials and custom grants. An
// ID token is issued when the access token has the openid scope and the
// grant has a subject.
func (p *Provider) issueTokens(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, accessScopes []string, withRefresh bool, grantType GrantType) (*TokenResponse, *Error) {
	accessScopes, withRefresh, perr := p.runBeforeIssue(ctx, iss, client, grant, grantType, accessScopes, withRefresh)
	if perr != nil {
		return nil, perr
	}
	return p.mintTokens(ctx, iss, client, grant, accessScopes, withRefresh, slices.Contains(accessScopes, "openid"), "")
}

// mintTokens creates and stores an access token with accessScopes, and
// optionally a refresh token and an ID token, for grant. Every grant type
// issues tokens here after Config.BeforeIssue has run.
func (p *Provider) mintTokens(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, accessScopes []string, withRefresh, withIDToken bool, nonce string) (*TokenResponse, *Error) {
	now := p.now()
	accessToken := randomToken()
	resp := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(p.cfg.Lifetimes.AccessToken.Seconds()),
		Scope:       strings.Join(accessScopes, " "),
	}

	derive := func(value string, typ TokenType, scopes []string) *Token {
		t := *grant
		t.Hash = hashToken(value)
		t.Type = typ
		t.Scopes = scopes
		t.RedirectURI, t.RedirectURIInRequest, t.Nonce = "", false, ""
		t.CodeChallenge, t.CodeChallengeMethod = "", ""
		t.CreatedAt = now
		t.ConsumedAt = time.Time{}
		return &t
	}

	access := derive(accessToken, TokenTypeAccessToken, accessScopes)
	access.ExpiresAt = now.Add(p.cfg.Lifetimes.AccessToken)
	toStore := []*Token{access}

	if withRefresh {
		refreshToken := randomToken()
		refresh := derive(refreshToken, TokenTypeRefreshToken, grant.Scopes)
		refresh.ExpiresAt = now.Add(p.cfg.Lifetimes.RefreshToken)
		toStore = append(toStore, refresh)
		resp.RefreshToken = refreshToken
	}

	if withIDToken && grant.Subject != "" {
		idToken, err := p.issueIDToken(ctx, iss, client, access, nonce, accessToken)
		if err != nil {
			return nil, errServer(err)
		}
		resp.IDToken = idToken
	}

	for _, t := range toStore {
		if err := p.cfg.Storage.CreateToken(ctx, t); err != nil {
			return nil, errServer(err)
		}
	}
	return resp, nil
}
