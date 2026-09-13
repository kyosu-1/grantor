package grantor

import (
	"context"
	"time"
)

// SignFunc signs claims as a compact JWS with the issuer's key for the
// client's access token signing algorithm; typ is the JOSE typ header.
type SignFunc func(typ string, claims any) (string, error)

// AccessTokenEncoder returns the value of an access token in a custom format.
// The value must be unique and impossible to guess: grantor stores only its
// hash and looks tokens up by it, so every format works with introspection,
// UserInfo and revocation.
type AccessTokenEncoder func(ctx context.Context, at *AccessToken, sign SignFunc) (string, error)

// AccessToken describes an access token being issued, for access token
// encoders.
type AccessToken struct {
	// ID uniquely identifies the token; JWT access tokens use it as jti.
	ID       string
	Issuer   string
	ClientID string
	// Subject identifies the end-user; it is empty when no end-user is
	// involved.
	Subject string
	// Audience is the granted audience, or the client ID when none was
	// granted.
	Audience  []string
	Scopes    []string
	GrantType GrantType
	AuthTime  time.Time
	ACR       string
	AMR       []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Claims are extra claims set by Config.BeforeIssue.
	Claims map[string]any
}
