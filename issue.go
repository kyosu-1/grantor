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
	// Other audiences fail with CodeInvalidTarget.
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
	// JWT access tokens need at least one.
	Audience []string
	// AccessTokenFormat is the format of the access token. The hook may
	// choose any built-in or configured format.
	AccessTokenFormat AccessTokenFormat
	// AccessTokenClaims are extra claims of the access token, returned in
	// JWT access tokens and by introspection; the client can read them, so
	// they must not hold secrets. IDTokenClaims are extra claims of the ID
	// token, which take precedence over claims from Config.Claims. Both
	// start empty, must be JSON-serializable and are stored as decoded JSON
	// (numbers become float64); claims with nil values are dropped. Protocol
	// claims such as iss, sub, aud and exp cannot be set.
	AccessTokenClaims map[string]any
	IDTokenClaims     map[string]any
	// Lifetimes of the tokens. The hook may set any value of at least a
	// second.
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
// it may not widen. It runs before any single-use token is consumed.
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
	if p.cfg.BeforeIssue != nil {
		if perr := p.runBeforeIssue(ctx, iss, client, grant, grantType, plan); perr != nil {
			return nil, perr
		}
	}
	// ID tokens use the client ID as aud, so JWT access tokens never default
	// to it: the audience is what keeps the two apart (RFC 9068 section 5,
	// RFC 8725 section 2.8).
	if plan.format == AccessTokenFormatJWT && len(plan.audience) == 0 {
		return nil, errServer(fmt.Errorf("JWT access tokens for client %q need an audience; set Client.Audience", client.ID))
	}
	return plan, nil
}

// runBeforeIssue lets Config.BeforeIssue adjust plan and validates the result.
func (p *Provider) runBeforeIssue(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, grantType GrantType, plan *issuePlan) *Error {
	c := *client
	is := &Issuance{
		Issuer:               iss.url,
		GrantType:            grantType,
		Client:               &c,
		GrantID:              grant.GrantID,
		Subject:              grant.Subject,
		AuthTime:             grant.AuthTime,
		Scopes:               slices.Clone(plan.scopes),
		RefreshToken:         plan.refresh,
		Audience:             slices.Clone(plan.audience),
		AccessTokenFormat:    plan.format,
		AccessTokenClaims:    map[string]any{},
		IDTokenClaims:        map[string]any{},
		AccessTokenLifetime:  plan.accessLifetime,
		RefreshTokenLifetime: plan.refreshLifetime,
		IDTokenLifetime:      plan.idLifetime,
	}
	if err := p.cfg.BeforeIssue(ctx, is); err != nil {
		return asProtocolError(err)
	}
	scopes, err := narrowed(plan.scopes, is.Scopes, "scope")
	if err != nil {
		return errServer(fmt.Errorf("BeforeIssue %w", err))
	}
	audience, err := narrowed(plan.audience, is.Audience, "audience")
	if err != nil {
		return errServer(fmt.Errorf("BeforeIssue %w", err))
	}
	switch {
	case is.RefreshToken && !plan.refresh:
		return errServer(errors.New("BeforeIssue enabled a refresh token"))
	case !p.knownFormat(is.AccessTokenFormat):
		return errServer(fmt.Errorf("BeforeIssue chose the unknown access token format %q", is.AccessTokenFormat))
	case !validLifetime(is.AccessTokenLifetime) || !validLifetime(is.RefreshTokenLifetime) || !validLifetime(is.IDTokenLifetime):
		return errServer(errors.New("BeforeIssue set a token lifetime shorter than a second"))
	}
	for name := range is.AccessTokenClaims {
		if accessTokenProtectedClaims[name] {
			return errServer(fmt.Errorf("BeforeIssue set the protected access token claim %q", name))
		}
	}
	for name := range is.IDTokenClaims {
		if protocolClaims[name] {
			return errServer(fmt.Errorf("BeforeIssue set the protected ID token claim %q", name))
		}
	}
	accessClaims, err := normalizeClaims(is.AccessTokenClaims)
	if err != nil {
		return errServer(fmt.Errorf("BeforeIssue set access token claims that are not JSON: %w", err))
	}
	idClaims, err := normalizeClaims(is.IDTokenClaims)
	if err != nil {
		return errServer(fmt.Errorf("BeforeIssue set ID token claims that are not JSON: %w", err))
	}
	plan.scopes = scopes
	plan.audience = audience
	plan.refresh = is.RefreshToken
	plan.format = is.AccessTokenFormat
	plan.accessClaims = accessClaims
	plan.idClaims = idClaims
	plan.accessLifetime = is.AccessTokenLifetime
	plan.refreshLifetime = is.RefreshTokenLifetime
	plan.idLifetime = is.IDTokenLifetime
	return nil
}

// validLifetime reports whether d can be a token lifetime: expires_in and
// the exp claim count whole seconds.
func validLifetime(d time.Duration) bool {
	return d >= time.Second
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
