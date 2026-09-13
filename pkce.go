package grantor

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// parsePKCE validates the PKCE parameters of an authorization request
// (OAuth 2.1 section 4.1.1). Only the S256 method is supported; OAuth 2.1
// forbids the plain method.
func parsePKCE(client *Client, q params, req *AuthorizationRequest) *Error {
	challenge, method := q.get("code_challenge"), q.get("code_challenge_method")
	if challenge == "" {
		if method != "" {
			return errInvalidRequest("code_challenge_method was sent without code_challenge")
		}
		return checkPKCEPolicy(client, req)
	}
	if method != "S256" {
		return errInvalidRequest("code_challenge_method must be S256")
	}
	// A base64url-encoded SHA-256 hash is exactly 43 characters.
	if len(challenge) != 43 || !isUnreserved(challenge) {
		return errInvalidRequest("code_challenge is malformed")
	}
	req.CodeChallenge = challenge
	req.CodeChallengeMethod = method
	return nil
}

// checkPKCEPolicy reports whether the client's PKCE policy allows req, which
// has no code challenge.
func checkPKCEPolicy(client *Client, req *AuthorizationRequest) *Error {
	switch client.pkcePolicy() {
	case PKCEOptional:
		return nil
	case PKCEUnlessNonce:
		if req.IsOpenID() && req.Nonce != "" {
			return nil
		}
	}
	return errInvalidRequest("code_challenge is required")
}

// verifyPKCE checks the code_verifier of a token request against the
// challenge bound to the authorization code.
func verifyPKCE(code *Token, verifier string) *Error {
	if code.CodeChallenge == "" {
		// Rejecting an unexpected verifier prevents PKCE downgrade attacks.
		if verifier != "" {
			return errInvalidGrant("code_verifier was sent but no code_challenge was used")
		}
		return nil
	}
	if len(verifier) < 43 || len(verifier) > 128 || !isUnreserved(verifier) {
		return errInvalidGrant("code_verifier is missing or malformed")
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(code.CodeChallenge)) != 1 {
		return errInvalidGrant("code_verifier does not match code_challenge")
	}
	return nil
}

// isUnreserved reports whether s only contains the unreserved characters of
// RFC 3986: ALPHA / DIGIT / "-" / "." / "_" / "~".
func isUnreserved(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}
