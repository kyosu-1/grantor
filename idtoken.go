package grantor

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// issueIDToken signs an ID token for grant. accessToken, when not empty, is
// bound with the at_hash claim.
func (p *Provider) issueIDToken(ctx context.Context, iss *resolvedIssuer, client *Client, grant *Token, nonce, accessToken string, lifetime time.Duration, extra map[string]any) (string, error) {
	key, ok := iss.keys.forAlg(client.idTokenAlg())
	if !ok {
		return "", fmt.Errorf("issuer has no key for the %s algorithm registered for client %q", client.idTokenAlg(), client.ID)
	}

	var requested map[string]*ClaimRequest
	if grant.Claims != nil {
		requested = grant.Claims.IDToken
	}
	claims, err := p.endUserClaims(ctx, grant, p.allowedClaims(grant, requested, p.cfg.IDTokenScopeClaims))
	if err != nil {
		return "", err
	}

	for name, value := range extra {
		claims[name] = value
	}
	now := p.now()
	claims["iss"] = iss.url
	claims["sub"] = grant.Subject
	claims["aud"] = client.ID
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(lifetime).Unix()
	if !grant.AuthTime.IsZero() {
		claims["auth_time"] = grant.AuthTime.Unix()
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if grant.ACR != "" {
		claims["acr"] = grant.ACR
	}
	if len(grant.AMR) > 0 {
		claims["amr"] = grant.AMR
	}
	if accessToken != "" {
		if h := hashForAlg(key.alg); h != nil {
			claims["at_hash"] = leftHalfHash(h, accessToken)
		}
	}
	return key.sign(claims, "JWT")
}

// hashForAlg returns the hash function used by at_hash for a JWS algorithm,
// or nil when OpenID Connect does not define one unambiguously.
func hashForAlg(alg jose.SignatureAlgorithm) hash.Hash {
	switch alg {
	case jose.RS256, jose.PS256, jose.ES256:
		return sha256.New()
	case jose.RS384, jose.PS384, jose.ES384:
		return sha512.New384()
	case jose.RS512, jose.PS512, jose.ES512:
		return sha512.New()
	default:
		return nil
	}
}

// leftHalfHash computes an at_hash value (OpenID Connect Core section 3.1.3.6).
func leftHalfHash(h hash.Hash, value string) string {
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// verifyIDTokenHint verifies an ID token previously issued by iss to
// clientID and returns its subject. Expired ID tokens are accepted, as
// OpenID Connect Core section 3.1.2.1 allows.
func verifyIDTokenHint(iss *resolvedIssuer, hint, clientID string) (string, error) {
	var algs []jose.SignatureAlgorithm
	for _, a := range iss.keys.algorithms() {
		algs = append(algs, jose.SignatureAlgorithm(a))
	}
	tok, err := jwt.ParseSigned(hint, algs)
	if err != nil {
		return "", err
	}
	if len(tok.Headers) != 1 {
		return "", errors.New("id_token_hint must have exactly one signature")
	}
	h := tok.Headers[0]
	pub, alg, ok := iss.keys.verificationKey(h.KeyID)
	if !ok || h.Algorithm != string(alg) {
		return "", errors.New("id_token_hint is not signed by a key of this issuer")
	}
	var c jwt.Claims
	if err := tok.Claims(pub, &c); err != nil {
		return "", err
	}
	if c.Issuer != iss.url || c.Subject == "" || !c.Audience.Contains(clientID) {
		return "", errors.New("id_token_hint was not issued to this client by this issuer")
	}
	return c.Subject, nil
}
