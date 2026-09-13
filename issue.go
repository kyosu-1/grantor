package grantor

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// GrantFunc handles a custom grant type at the token endpoint. It decides
// whether access is granted and issues tokens with [Provider.IssueTokens].
// Returning an *Error sends it to the client; other errors become
// server_error.
type GrantFunc func(ctx context.Context, req *TokenRequest) (*TokenResponse, error)

// Grant describes the access a custom grant issues tokens for.
type Grant struct {
	// Subject identifies the end-user. It is empty when no end-user is
	// involved.
	Subject string
	// Scopes must be a subset of the client's registered scopes. An ID token
	// is issued when they include openid and Subject is set.
	Scopes   []string
	AuthTime time.Time
	ACR      string
	AMR      []string
	// RefreshToken also issues a refresh token. The client must be allowed
	// the refresh_token grant.
	RefreshToken bool
}

// Issuance describes tokens that are about to be issued. It is passed to
// Config.BeforeIssue.
type Issuance struct {
	Issuer    string
	GrantType GrantType
	// Client is the client the tokens are issued to. Changes to it have no
	// effect.
	Client *Client
	// GrantID identifies the authorization the tokens belong to.
	GrantID string
	// Subject identifies the end-user; it is empty for grants without one.
	Subject  string
	AuthTime time.Time
	// Scopes are the scopes of the access token. The hook may remove scopes
	// but not add any.
	Scopes []string
	// RefreshToken reports whether a refresh token is issued. The hook may
	// set it to false.
	RefreshToken bool
}

// IssueTokens issues tokens for a custom grant; see [GrantFunc].
func (p *Provider) IssueTokens(ctx context.Context, req *TokenRequest, g Grant) (*TokenResponse, error) {
	resp, perr := p.issueGrant(ctx, req, g)
	if perr != nil {
		return nil, perr
	}
	return resp, nil
}

func (p *Provider) issueGrant(ctx context.Context, req *TokenRequest, g Grant) (*TokenResponse, *Error) {
	if perr := checkTokenRequest(req); perr != nil {
		return nil, perr
	}
	client := req.Client
	if g.Subject != "" {
		if err := validateSubject(g.Subject); err != nil {
			return nil, errServer(err)
		}
	}
	var scopes []string
	for _, s := range g.Scopes {
		if !slices.Contains(client.Scopes, s) {
			return nil, newError(CodeInvalidScope, "the client may not request one of the scopes")
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	if g.Subject == "" && (slices.Contains(scopes, "openid") || slices.Contains(scopes, "offline_access")) {
		return nil, errServer(errors.New("IssueTokens: the openid and offline_access scopes need a subject"))
	}
	if g.RefreshToken && !client.allowsGrant(GrantTypeRefreshToken) {
		return nil, errServer(fmt.Errorf("IssueTokens: client %q may not use refresh tokens", client.ID))
	}
	grant := &Token{
		GrantID:  randomToken(),
		Issuer:   req.iss.url,
		ClientID: client.ID,
		Subject:  g.Subject,
		Scopes:   scopes,
		AuthTime: g.AuthTime,
		ACR:      g.ACR,
		AMR:      g.AMR,
	}
	return p.issueTokens(ctx, req.iss, client, grant, scopes, g.RefreshToken, "", req.GrantType)
}

// runBeforeIssue calls Config.BeforeIssue and returns the access token scopes
// and refresh token decision it leaves.
func (p *Provider) runBeforeIssue(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, grantType GrantType, scopes []string, withRefresh bool) ([]string, bool, *Error) {
	if p.cfg.BeforeIssue == nil {
		return scopes, withRefresh, nil
	}
	c := *client
	is := &Issuance{
		Issuer:       iss.url,
		GrantType:    grantType,
		Client:       &c,
		GrantID:      grant.GrantID,
		Subject:      grant.Subject,
		AuthTime:     grant.AuthTime,
		Scopes:       slices.Clone(scopes),
		RefreshToken: withRefresh,
	}
	if err := p.cfg.BeforeIssue(ctx, is); err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, false, e
		}
		return nil, false, errServer(fmt.Errorf("BeforeIssue: %w", err))
	}
	var narrowed []string
	for _, s := range is.Scopes {
		if !slices.Contains(scopes, s) {
			return nil, false, errServer(fmt.Errorf("BeforeIssue added the %q scope", s))
		}
		if !slices.Contains(narrowed, s) {
			narrowed = append(narrowed, s)
		}
	}
	if is.RefreshToken && !withRefresh {
		return nil, false, errServer(errors.New("BeforeIssue enabled a refresh token"))
	}
	return narrowed, is.RefreshToken, nil
}
