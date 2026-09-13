package grantor

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

// AuthMethod is a token endpoint client authentication method
// (token_endpoint_auth_method).
type AuthMethod string

const (
	AuthMethodClientSecretBasic AuthMethod = "client_secret_basic"
	AuthMethodClientSecretPost  AuthMethod = "client_secret_post"
	AuthMethodPrivateKeyJWT     AuthMethod = "private_key_jwt"
	// AuthMethodNone is used by public clients, which cannot keep a secret.
	AuthMethodNone AuthMethod = "none"
)

// GrantType is an OAuth 2.1 grant type.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
)

// AccessTokenFormat names how access token values are encoded.
type AccessTokenFormat string

const (
	// AccessTokenFormatOpaque issues random 43-character access tokens. It is
	// the default.
	AccessTokenFormatOpaque AccessTokenFormat = "opaque"
	// AccessTokenFormatJWT issues JWT access tokens (RFC 9068), which
	// resource servers can validate with the issuer's JWKS. They need an
	// audience, and for grants without an end-user their sub is the client
	// ID, so client IDs must not collide with subject identifiers.
	AccessTokenFormatJWT AccessTokenFormat = "jwt"
)

// PKCEPolicy controls when a client must use PKCE.
type PKCEPolicy string

const (
	// PKCERequired requires PKCE on every authorization request, as OAuth 2.1
	// does. It is the default.
	PKCERequired PKCEPolicy = "required"

	// PKCEUnlessNonce lets a confidential client omit PKCE on OpenID Connect
	// requests that carry a nonce. OAuth 2.1 section 7.5.1.1 allows this
	// only when the client is known to validate the nonce properly.
	PKCEUnlessNonce PKCEPolicy = "unless_nonce"

	// PKCEOptional lets a confidential client omit PKCE altogether, as OAuth
	// 2.0 and OpenID Connect Core allow. It does not conform to OAuth 2.1;
	// use it only for clients that cannot be updated.
	PKCEOptional PKCEPolicy = "optional"
)

// Client is a registered OAuth 2.1 client.
type Client struct {
	// ID is the client_id.
	ID string

	// AuthMethod is how the client authenticates at the token, introspection
	// and revocation endpoints. It defaults to client_secret_basic when
	// SecretHash is set, private_key_jwt when JWKS is set, and none
	// otherwise. A client with a secret may send it with either
	// client_secret_basic or client_secret_post, since OAuth 2.1 requires
	// accepting credentials in the request body.
	AuthMethod AuthMethod

	// SecretHash verifies the client secret. Set it to the value
	// [HashClientSecret] returns and treat it as opaque. It is only suitable
	// for high-entropy secrets such as those from [GenerateClientSecret],
	// never for secrets chosen by people.
	SecretHash []byte

	// JWKS is the client's JSON Web Key Set, used to verify private_key_jwt
	// client assertions.
	JWKS []byte

	// RedirectURIs are the registered redirection URIs. They are compared
	// with simple string comparison, except that the port of a loopback
	// redirect URI (http://127.0.0.1 or http://[::1]) may vary, as required
	// by RFC 8252 section 7.3.
	RedirectURIs []string

	// GrantTypes lists the grant types the client may use. It defaults to
	// authorization_code.
	GrantTypes []GrantType

	// Scopes lists the scopes the client may request.
	Scopes []string

	// PKCE controls when the client must use PKCE. It defaults to
	// PKCERequired, and public clients always require PKCE.
	PKCE PKCEPolicy

	// IDTokenSigningAlg is the JWS algorithm for ID tokens issued to this
	// client (id_token_signed_response_alg). It defaults to RS256.
	IDTokenSigningAlg string

	// AllowIntrospection lets the client introspect tokens issued to other
	// clients, as a resource server does. Every client can introspect its own
	// tokens.
	AllowIntrospection bool

	// AccessTokenFormat is the format of access tokens issued to the client.
	// It defaults to Config.AccessTokenFormat.
	AccessTokenFormat AccessTokenFormat

	// AccessTokenSigningAlg is the JWS algorithm of JWT access tokens and of
	// the SignFunc passed to custom formats. It defaults to RS256.
	AccessTokenSigningAlg string

	// Audience lists the audiences, such as resource server URLs, that
	// access tokens of the client may be issued for. Approvals and custom
	// grants select from it (see [Approval.Audience] and [Grant.Audience]),
	// the client credentials grant uses all of it, and Config.BeforeIssue
	// may narrow any issuance. JWT access tokens need at least one audience.
	Audience []string

	// Lifetimes of tokens issued to the client. Zero values use
	// Config.Lifetimes.
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	IDTokenLifetime      time.Duration
}

// clone returns a copy of c that shares no slices with it.
func (c *Client) clone() *Client {
	out := *c
	out.SecretHash = slices.Clone(c.SecretHash)
	out.JWKS = slices.Clone(c.JWKS)
	out.RedirectURIs = slices.Clone(c.RedirectURIs)
	out.GrantTypes = slices.Clone(c.GrantTypes)
	out.Scopes = slices.Clone(c.Scopes)
	out.Audience = slices.Clone(c.Audience)
	return &out
}

// HashClientSecret returns the value to store in [Client.SecretHash].
func HashClientSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// GenerateClientSecret returns a new random client secret with 256 bits of entropy.
func GenerateClientSecret() string {
	return randomToken()
}

func (c *Client) authMethod() AuthMethod {
	switch {
	case c.AuthMethod != "":
		return c.AuthMethod
	case len(c.SecretHash) > 0:
		return AuthMethodClientSecretBasic
	case len(c.JWKS) > 0:
		return AuthMethodPrivateKeyJWT
	default:
		return AuthMethodNone
	}
}

func (c *Client) isPublic() bool { return c.authMethod() == AuthMethodNone }

func (c *Client) usesSecret() bool {
	m := c.authMethod()
	return m == AuthMethodClientSecretBasic || m == AuthMethodClientSecretPost
}

func (c *Client) pkcePolicy() PKCEPolicy {
	if c.PKCE == "" || c.isPublic() {
		return PKCERequired
	}
	return c.PKCE
}

func (c *Client) grantTypes() []GrantType {
	if len(c.GrantTypes) == 0 {
		return []GrantType{GrantTypeAuthorizationCode}
	}
	return c.GrantTypes
}

func (c *Client) allowsGrant(g GrantType) bool {
	return slices.Contains(c.grantTypes(), g)
}

func (c *Client) accessTokenAlg() string {
	if c.AccessTokenSigningAlg == "" {
		return "RS256"
	}
	return c.AccessTokenSigningAlg
}

func (c *Client) idTokenAlg() string {
	if c.IDTokenSigningAlg == "" {
		return "RS256"
	}
	return c.IDTokenSigningAlg
}

func (c *Client) verifySecret(secret string) bool {
	if len(c.SecretHash) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(HashClientSecret(secret), c.SecretHash) == 1
}

// validate checks that a client returned by the ClientStore is well formed.
// A malformed client is a server-side misconfiguration.
func (c *Client) validate() error {
	if c.ID == "" {
		return errors.New("client has no ID")
	}
	switch m := c.authMethod(); m {
	case AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
		if len(c.SecretHash) != sha256.Size {
			return fmt.Errorf("client %q uses %s but SecretHash is not a SHA-256 hash", c.ID, m)
		}
	case AuthMethodPrivateKeyJWT:
		if len(c.JWKS) == 0 {
			return fmt.Errorf("client %q uses private_key_jwt but has no JWKS", c.ID)
		}
	case AuthMethodNone:
		if len(c.SecretHash) > 0 {
			return fmt.Errorf("client %q is public but has a SecretHash", c.ID)
		}
		if c.allowsGrant(GrantTypeClientCredentials) {
			return fmt.Errorf("client %q is public and cannot use client_credentials", c.ID)
		}
	default:
		return fmt.Errorf("client %q has unsupported auth method %q", c.ID, m)
	}
	for _, d := range []time.Duration{c.AccessTokenLifetime, c.RefreshTokenLifetime, c.IDTokenLifetime} {
		if d != 0 && !validLifetime(d) {
			return fmt.Errorf("client %q has a token lifetime that is neither zero nor at least a second", c.ID)
		}
	}
	if c.AccessTokenFormat == AccessTokenFormatJWT && len(c.Audience) == 0 {
		return fmt.Errorf("client %q uses JWT access tokens but has no Audience", c.ID)
	}
	switch c.PKCE {
	case "", PKCERequired:
	case PKCEUnlessNonce, PKCEOptional:
		if c.isPublic() {
			return fmt.Errorf("client %q is public and must always use PKCE", c.ID)
		}
	default:
		return fmt.Errorf("client %q has unsupported PKCE policy %q", c.ID, c.PKCE)
	}
	for _, g := range c.grantTypes() {
		if g == "" {
			return fmt.Errorf("client %q has an empty grant type", c.ID)
		}
	}
	for _, u := range c.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return fmt.Errorf("client %q: %w", c.ID, err)
		}
	}
	return nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid redirect URI %q: %w", raw, err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("redirect URI %q is not absolute", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("redirect URI %q has a fragment", raw)
	}
	switch scheme := strings.ToLower(u.Scheme); scheme {
	case "http", "https":
	case "javascript", "data", "vbscript", "file", "blob":
		return fmt.Errorf("redirect URI %q uses a forbidden scheme", raw)
	default:
		// OAuth 2.1 section 2.3.1: private-use URI schemes should be reverse
		// domain names, such as com.example.app.
		if !strings.Contains(scheme, ".") {
			return fmt.Errorf("redirect URI %q must use a reverse domain name scheme such as com.example.app", raw)
		}
	}
	return nil
}

// matchRedirectURI reports whether requested is one of the client's registered
// redirect URIs.
func (c *Client) matchRedirectURI(requested string) bool {
	for _, registered := range c.RedirectURIs {
		if requested == registered {
			return true
		}
		if loopbackMatch(registered, requested) {
			return true
		}
	}
	return false
}

// loopbackMatch implements RFC 8252 section 7.3: for loopback IP redirect
// URIs the port is ignored, everything else must match exactly.
func loopbackMatch(registered, requested string) bool {
	ru, err := url.Parse(registered)
	if err != nil || ru.Scheme != "http" || !isLoopbackIP(ru.Hostname()) {
		return false
	}
	qu, err := url.Parse(requested)
	if err != nil || qu.Scheme != "http" || qu.Hostname() != ru.Hostname() {
		return false
	}
	if qu.User != nil || ru.User != nil || strings.Contains(requested, "#") {
		return false
	}
	return qu.EscapedPath() == ru.EscapedPath() && qu.RawQuery == ru.RawQuery
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// randomToken returns 32 random bytes encoded with unpadded base64url.
func randomToken() string {
	b := make([]byte, 32)
	// crypto/rand.Read never returns an error; it crashes the program if the
	// system random source fails.
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken returns the storage key for a token value. Only hashes are
// stored, so a leaked database does not leak usable tokens.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
