package grantor

import (
	"errors"
	"net/http"
)

// serveRevocation implements RFC 7009 token revocation.
func (p *Provider) serveRevocation(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	q, perr := parseForm(w, r)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	if len(q.repeated) > 0 {
		p.WriteTokenError(w, r, errInvalidRequest("parameters must not be repeated"))
		return
	}
	client, perr := p.authenticateClient(r, iss, q)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	token := q.get("token")
	if token == "" {
		p.WriteTokenError(w, r, errInvalidRequest("token is required"))
		return
	}

	hash := hashToken(token)
	t, err := p.cfg.Storage.Token(r.Context(), hash)
	switch {
	case errors.Is(err, ErrNotFound):
		// Invalid tokens do not cause an error (RFC 7009 section 2.2).
	case err != nil:
		p.WriteTokenError(w, r, errServer(err))
		return
	case t.Issuer != iss.url || t.Kind == TokenKindAuthorizationCode:
		// Treated like an unknown token.
	case t.ClientID != client.ID:
		p.WriteTokenError(w, r, newError(CodeUnauthorizedClient, "the token was not issued to this client"))
		return
	case t.Kind == TokenKindRefreshToken:
		// Revoking a refresh token also invalidates the access tokens of the
		// same grant (RFC 7009 section 2.1).
		err = p.cfg.Storage.RevokeGrant(r.Context(), t.GrantID)
	default:
		err = p.cfg.Storage.RevokeToken(r.Context(), hash)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		p.WriteTokenError(w, r, errServer(err))
		return
	}
	noStore(w)
	w.WriteHeader(http.StatusOK)
}
