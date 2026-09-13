package grantor

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SignFunc signs claims as a compact JWS with the issuer's key for the
// client's access token signing algorithm; typ is the JOSE typ header. The
// typ must name the token type, such as at+jwt: an empty typ and JWT, which
// ID tokens use, are refused so that access tokens cannot be mistaken for ID
// tokens (RFC 8725 section 3.11).
type SignFunc func(typ string, claims any) (string, error)

// AccessTokenEncoder returns the value of an access token in a custom format.
// The value must be unique and impossible to guess: grantor stores only its
// hash and looks tokens up by it, so every format works with introspection,
// UserInfo and revocation.
type AccessTokenEncoder func(ctx context.Context, at *AccessToken, sign SignFunc) (string, error)

// AccessToken describes an access token being issued, for access token
// encoders. Encoders receive a copy; changing it has no effect.
type AccessToken struct {
	// ID uniquely identifies the token; JWT access tokens use it as jti.
	ID       string
	Issuer   string
	ClientID string
	// Subject identifies the end-user; it is empty when no end-user is
	// involved.
	Subject string
	// Audience is the granted audience. It is never empty for JWT access
	// tokens, but may be for custom formats; formats that sign JWTs must not
	// fall back to the client ID, which is the audience of ID tokens.
	Audience  []string
	Scopes    []string
	GrantType GrantType
	AuthTime  time.Time
	ACR       string
	AMR       []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Claims are extra claims set by Config.BeforeIssue, as decoded JSON.
	Claims map[string]any
}

// clone returns a copy of at that shares no slices or maps with it.
func (at *AccessToken) clone() *AccessToken {
	c := *at
	c.Audience = slices.Clone(at.Audience)
	c.Scopes = slices.Clone(at.Scopes)
	c.AMR = slices.Clone(at.AMR)
	c.Claims = copyJSON(at.Claims).(map[string]any)
	return &c
}

// accessTokenProtectedClaims are set by grantor in JWT access tokens and
// introspection responses, and cannot be set by Config.BeforeIssue.
var accessTokenProtectedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	"client_id": true, "scope": true, "auth_time": true, "acr": true, "amr": true, "cnf": true,
	"active": true, "token_type": true,
}

// encodeAccessToken returns the value of an access token in format.
func (p *Provider) encodeAccessToken(ctx context.Context, iss *resolvedIssuer, client *Client, format AccessTokenFormat, at *AccessToken) (string, error) {
	sign := func(typ string, claims any) (string, error) {
		if t := strings.TrimPrefix(strings.ToLower(typ), "application/"); t == "" || t == "jwt" {
			return "", fmt.Errorf("access tokens must be signed with an explicit typ, not %q", typ)
		}
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

// jwtAccessTokenClaims returns the claims of a JWT access token (RFC 9068
// section 2.2). Without an end-user, sub is the client ID, so client IDs must
// not collide with subject identifiers (RFC 9068 section 5).
func jwtAccessTokenClaims(at *AccessToken) map[string]any {
	claims := make(map[string]any, len(at.Claims)+12)
	for name, value := range at.Claims {
		claims[name] = value
	}
	claims["iss"] = at.Issuer
	claims["sub"] = at.Subject
	if at.Subject == "" {
		// RFC 9068 section 2.2: without an end-user, sub is the client.
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
