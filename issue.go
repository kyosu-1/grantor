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
//
// req.Client has authenticated unless it is a public client, which is only
// identified by client_id; such grants must rely on credentials in the
// request itself.
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
	// Audience must be a subset of Client.Audience; nil means all of it.
	Audience []string
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
	// but not add any. A refresh token keeps the full scope of the grant,
	// and for the authorization code grant an OpenID Connect request still
	// receives an ID token.
	Scopes []string
	// RefreshToken reports whether a refresh token is issued. The hook may
	// set it to false; removing offline_access from Scopes does not.
	RefreshToken bool
	// Audience lists the audiences of the access token. The hook may remove
	// audiences but not add any; a refresh token keeps the grant's audience.
	Audience []string
	// AccessTokenFormat is the format of the access token. The hook may
	// choose any built-in or configured format.
	AccessTokenFormat AccessTokenFormat
	// AccessTokenClaims are extra claims of the access token, returned in
	// JWT access tokens and by introspection. IDTokenClaims are extra claims
	// of the ID token. Protocol claims such as iss, sub, aud and exp cannot
	// be set.
	AccessTokenClaims map[string]any
	IDTokenClaims     map[string]any
	// Lifetimes of the tokens. The hook may set any positive value.
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	IDTokenLifetime      time.Duration
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
	client, perr := checkTokenRequest(req)
	if perr != nil {
		return nil, perr
	}
	switch req.GrantType {
	case GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypeClientCredentials:
		return nil, errServer(fmt.Errorf("IssueTokens is for custom grants, not %s", req.GrantType))
	}
	if !client.allowsGrant(req.GrantType) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use this grant type")
	}
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
	audience, err := resolveAudience(client.Audience, g.Audience)
	if err != nil {
		return nil, newError(CodeInvalidTarget, "the audience is not registered for the client")
	}
	grant := &Token{
		Audience: audience,
		GrantID:  randomToken(),
		Issuer:   req.iss.url,
		ClientID: client.ID,
		Subject:  g.Subject,
		Scopes:   scopes,
		AuthTime: g.AuthTime,
		ACR:      g.ACR,
		AMR:      g.AMR,
	}
	return p.issueTokens(ctx, req.iss, client, grant, scopes, g.RefreshToken, req.GrantType)
}

// issuePlan is what an issuance produces after defaults and
// Config.BeforeIssue have been applied.
type issuePlan struct {
	scopes          []string
	audience        []string
	refresh         bool
	format          AccessTokenFormat
	accessClaims    map[string]any
	idClaims        map[string]any
	accessLifetime  time.Duration
	refreshLifetime time.Duration
	idLifetime      time.Duration
}

// planIssuance resolves the format, audience and lifetimes of the tokens for
// grant, runs Config.BeforeIssue, and checks that the hook only narrowed what
// it may not widen.
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
		Issuer:               iss.url,
		GrantType:            grantType,
		Client:               &c,
		GrantID:              grant.GrantID,
		Subject:              grant.Subject,
		AuthTime:             grant.AuthTime,
		Scopes:               slices.Clone(scopes),
		RefreshToken:         withRefresh,
		Audience:             slices.Clone(grant.Audience),
		AccessTokenFormat:    plan.format,
		AccessTokenLifetime:  plan.accessLifetime,
		RefreshTokenLifetime: plan.refreshLifetime,
		IDTokenLifetime:      plan.idLifetime,
	}
	if err := p.cfg.BeforeIssue(ctx, is); err != nil {
		return nil, asProtocolError(err)
	}
	var err error
	if plan.scopes, err = narrowed(scopes, is.Scopes, "scope"); err != nil {
		return nil, errServer(fmt.Errorf("BeforeIssue %w", err))
	}
	if plan.audience, err = narrowed(grant.Audience, is.Audience, "audience"); err != nil {
		return nil, errServer(fmt.Errorf("BeforeIssue %w", err))
	}
	switch {
	case is.RefreshToken && !withRefresh:
		return nil, errServer(errors.New("BeforeIssue enabled a refresh token"))
	case !p.knownFormat(is.AccessTokenFormat):
		return nil, errServer(fmt.Errorf("BeforeIssue chose the unknown access token format %q", is.AccessTokenFormat))
	case is.AccessTokenLifetime <= 0 || is.RefreshTokenLifetime <= 0 || is.IDTokenLifetime <= 0:
		return nil, errServer(errors.New("BeforeIssue set a token lifetime that is not positive"))
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
	plan.accessClaims = is.AccessTokenClaims
	plan.idClaims = is.IDTokenClaims
	plan.accessLifetime = is.AccessTokenLifetime
	plan.refreshLifetime = is.RefreshTokenLifetime
	plan.idLifetime = is.IDTokenLifetime
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

func firstDuration(durations ...time.Duration) time.Duration {
	for _, d := range durations {
		if d > 0 {
			return d
		}
	}
	return 0
}
