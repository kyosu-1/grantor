package grantor

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func (p *Provider) serveToken(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	q, perr := parseForm(w, r)
	if perr != nil {
		p.writeTokenError(w, r, perr)
		return
	}
	if len(q.repeated) > 0 {
		p.writeTokenError(w, r, errInvalidRequest("parameters must not be repeated"))
		return
	}
	client, perr := p.authenticateClient(r, iss, q)
	if perr != nil {
		p.writeTokenError(w, r, perr)
		return
	}

	var resp *tokenResponse
	switch GrantType(q.get("grant_type")) {
	case "":
		perr = errInvalidRequest("grant_type is required")
	case GrantTypeAuthorizationCode:
		resp, perr = p.exchangeAuthorizationCode(r.Context(), iss, client, q)
	case GrantTypeRefreshToken:
		resp, perr = p.exchangeRefreshToken(r.Context(), iss, client, q)
	case GrantTypeClientCredentials:
		resp, perr = p.exchangeClientCredentials(r.Context(), iss, client, q)
	default:
		perr = newError(CodeUnsupportedGrantType, "the grant type is not supported")
	}
	if perr != nil {
		p.writeTokenError(w, r, perr)
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, resp)
}

func (p *Provider) exchangeAuthorizationCode(ctx context.Context, iss *resolvedIssuer, client *Client, q params) (*tokenResponse, *Error) {
	if !client.allowsGrant(GrantTypeAuthorizationCode) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use the authorization code grant")
	}
	code := q.get("code")
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
	redirectURI := q.get("redirect_uri")
	if (redirectURI != "" || (t.RedirectURIInRequest && t.CodeChallenge == "")) && redirectURI != t.RedirectURI {
		return nil, errInvalidGrant("redirect_uri does not match the authorization request")
	}
	if perr := verifyPKCE(t, q.get("code_verifier")); perr != nil {
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
	if perr := p.consume(ctx, hash); perr != nil {
		return nil, perr
	}

	withRefresh := client.allowsGrant(GrantTypeRefreshToken) &&
		(!t.HasScope("openid") || t.HasScope("offline_access"))
	return p.issueTokens(ctx, iss, client, t, t.Scopes, withRefresh, t.Nonce)
}

func (p *Provider) exchangeRefreshToken(ctx context.Context, iss *resolvedIssuer, client *Client, q params) (*tokenResponse, *Error) {
	if !client.allowsGrant(GrantTypeRefreshToken) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use the refresh token grant")
	}
	refreshToken := q.get("refresh_token")
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
	scopes := t.Scopes
	if q.has("scope") {
		scopes = splitSpaces(q.get("scope"))
		for _, s := range scopes {
			if !t.HasScope(s) {
				return nil, newError(CodeInvalidScope, "the requested scope exceeds the original grant")
			}
		}
	}
	if perr := checkClientScopes(client, t.Scopes); perr != nil {
		return nil, perr
	}
	if perr := p.consume(ctx, hash); perr != nil {
		return nil, perr
	}
	// Refresh tokens are rotated on every use; the new refresh token keeps
	// the scope of the grant, while the access token may be narrowed.
	return p.issueTokens(ctx, iss, client, t, scopes, true, "")
}

func (p *Provider) exchangeClientCredentials(ctx context.Context, iss *resolvedIssuer, client *Client, q params) (*tokenResponse, *Error) {
	if client.isPublic() || !client.allowsGrant(GrantTypeClientCredentials) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use the client credentials grant")
	}
	scopes, perr := validateScopes(client, q.get("scope"))
	if perr != nil {
		return nil, perr
	}
	if slices.Contains(scopes, "openid") || slices.Contains(scopes, "offline_access") {
		return nil, newError(CodeInvalidScope, "the client credentials grant has no end-user")
	}
	grant := &Token{GrantID: randomToken(), Issuer: iss.url, ClientID: client.ID, Scopes: scopes}
	return p.issueTokens(ctx, iss, client, grant, scopes, false, "")
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

// issueTokens issues an access token with accessScopes, and optionally a
// refresh token and an ID token, for grant.
func (p *Provider) issueTokens(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, accessScopes []string, withRefresh bool, nonce string) (*tokenResponse, *Error) {
	now := p.now()
	accessToken := randomToken()
	resp := &tokenResponse{
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

	if slices.Contains(accessScopes, "openid") && grant.Subject != "" {
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
