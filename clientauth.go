package grantor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const clientAssertionTypeJWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

const (
	// assertionLeeway is the clock skew tolerated for client assertions.
	assertionLeeway = 30 * time.Second
	// maxAssertionLifetime bounds how far in the future a client assertion
	// may expire, which bounds how long its jti must be remembered.
	maxAssertionLifetime = time.Hour
)

// assertionAlgorithms are the asymmetric algorithms accepted for
// private_key_jwt. Symmetric algorithms and "none" are never accepted.
var assertionAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

func assertionAlgorithmNames() []string {
	names := make([]string, len(assertionAlgorithms))
	for i, a := range assertionAlgorithms {
		names[i] = string(a)
	}
	return names
}

// authenticateClient authenticates the client of a request to the token,
// introspection or revocation endpoint (RFC 6749 section 2.3). endpoint is
// the URL of the endpoint being called.
func (p *Provider) authenticateClient(r *http.Request, iss *resolvedIssuer, q params, endpoint string) (*Client, *Error) {
	ctx := r.Context()
	basicID, basicSecret, hasBasic := r.BasicAuth()
	hasPost := q.has("client_secret")
	hasAssertion := q.has("client_assertion") || q.has("client_assertion_type")

	methods := 0
	for _, used := range []bool{hasBasic, hasPost, hasAssertion} {
		if used {
			methods++
		}
	}
	if methods > 1 {
		return nil, errInvalidRequest("only one client authentication method may be used")
	}

	switch {
	case hasBasic:
		// RFC 6749 section 2.3.1: credentials are form-encoded before being
		// put in the Authorization header.
		id, err1 := url.QueryUnescape(basicID)
		secret, err2 := url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil {
			return nil, errInvalidClient("malformed client credentials")
		}
		if v := q.get("client_id"); v != "" && v != id {
			return nil, errInvalidRequest("client_id does not match the Authorization header")
		}
		return p.authenticateWithSecret(ctx, iss, id, secret, AuthMethodClientSecretBasic)

	case hasPost:
		return p.authenticateWithSecret(ctx, iss, q.get("client_id"), q.get("client_secret"), AuthMethodClientSecretPost)

	case hasAssertion:
		if q.get("client_assertion_type") != clientAssertionTypeJWT {
			return nil, errInvalidClient("unsupported client_assertion_type")
		}
		audiences := []string{iss.url, iss.endpoint(PathToken), endpoint}
		client, perr := p.verifyClientAssertion(ctx, iss, q.get("client_assertion"), audiences)
		if perr != nil {
			return nil, perr
		}
		if v := q.get("client_id"); v != "" && v != client.ID {
			return nil, errInvalidRequest("client_id does not match the client assertion")
		}
		return client, nil

	default:
		client, perr := p.lookupAuthenticatingClient(ctx, iss, q.get("client_id"))
		if perr != nil {
			return nil, perr
		}
		if client.authMethod() != AuthMethodNone {
			return nil, errInvalidClient("client authentication failed")
		}
		return client, nil
	}
}

func (p *Provider) lookupAuthenticatingClient(ctx context.Context, iss *resolvedIssuer, id string) (*Client, *Error) {
	if id == "" {
		return nil, errInvalidClient("client authentication failed")
	}
	client, err := p.client(ctx, iss, id)
	if errors.Is(err, ErrNotFound) {
		return nil, errInvalidClient("client authentication failed")
	}
	if err != nil {
		return nil, errServer(err)
	}
	return client, nil
}

func (p *Provider) authenticateWithSecret(ctx context.Context, iss *resolvedIssuer, id, secret string, method AuthMethod) (*Client, *Error) {
	client, perr := p.lookupAuthenticatingClient(ctx, iss, id)
	if perr != nil {
		return nil, perr
	}
	if client.authMethod() != method || !client.verifySecret(secret) {
		return nil, errInvalidClient("client authentication failed")
	}
	return client, nil
}

// verifyClientAssertion authenticates a private_key_jwt client assertion
// (RFC 7523 section 2.2 and OpenID Connect Core section 9).
func (p *Provider) verifyClientAssertion(ctx context.Context, iss *resolvedIssuer, assertion string, audiences []string) (*Client, *Error) {
	if assertion == "" {
		return nil, errInvalidClient("client_assertion is required")
	}
	tok, err := jwt.ParseSigned(assertion, assertionAlgorithms)
	if err != nil || len(tok.Headers) != 1 {
		return nil, errInvalidClient("client_assertion is malformed")
	}
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, errInvalidClient("client_assertion is malformed")
	}
	client, perr := p.lookupAuthenticatingClient(ctx, iss, unverified.Subject)
	if perr != nil {
		return nil, perr
	}
	if client.authMethod() != AuthMethodPrivateKeyJWT {
		return nil, errInvalidClient("client authentication failed")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(client.JWKS, &set); err != nil {
		return nil, errServer(errors.New("client " + client.ID + " has an invalid JWKS"))
	}

	header := tok.Headers[0]
	var claims jwt.Claims
	verified := false
	for _, k := range set.Keys {
		if !k.IsPublic() || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if header.KeyID != "" && k.KeyID != header.KeyID {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != header.Algorithm {
			continue
		}
		if tok.Claims(k.Key, &claims) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errInvalidClient("client authentication failed")
	}

	now := p.now()
	if claims.Expiry == nil || claims.ID == "" {
		return nil, errInvalidClient("client_assertion must contain exp and jti")
	}
	expected := jwt.Expected{
		Issuer:      client.ID,
		Subject:     client.ID,
		AnyAudience: audiences,
		Time:        now,
	}
	if err := claims.ValidateWithLeeway(expected, assertionLeeway); err != nil {
		return nil, errInvalidClient("client_assertion is invalid or expired")
	}
	exp := claims.Expiry.Time()
	if exp.After(now.Add(maxAssertionLifetime)) {
		return nil, errInvalidClient("client_assertion expires too far in the future")
	}
	err = p.cfg.Storage.ClaimAssertionID(ctx, iss.url, client.ID, claims.ID, exp.Add(assertionLeeway))
	if errors.Is(err, ErrConflict) {
		return nil, errInvalidClient("client_assertion was already used")
	}
	if err != nil {
		return nil, errServer(err)
	}
	return client, nil
}
