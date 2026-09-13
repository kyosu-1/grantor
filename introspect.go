package grantor

import (
	"errors"
	"net/http"
	"strings"
)

// serveIntrospection implements RFC 7662 token introspection.
func (p *Provider) serveIntrospection(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
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
	if client.isPublic() {
		p.WriteTokenError(w, r, errInvalidClient("public clients may not introspect tokens"))
		return
	}
	token := q.get("token")
	if token == "" {
		p.WriteTokenError(w, r, errInvalidRequest("token is required"))
		return
	}

	noStore(w)
	inactive := map[string]any{"active": false}
	t, err := p.cfg.Storage.Token(r.Context(), hashToken(token))
	if errors.Is(err, ErrNotFound) {
		writeJSON(w, http.StatusOK, inactive)
		return
	}
	if err != nil {
		p.WriteTokenError(w, r, errServer(err))
		return
	}
	active := t.Issuer == iss.url &&
		p.now().Before(t.ExpiresAt) &&
		(t.Type == TokenTypeAccessToken || (t.Type == TokenTypeRefreshToken && t.ConsumedAt.IsZero())) &&
		(t.ClientID == client.ID || client.AllowIntrospection)
	if !active {
		writeJSON(w, http.StatusOK, inactive)
		return
	}

	resp := map[string]any{}
	for name, value := range t.AccessTokenClaims {
		if !accessTokenProtectedClaims[name] {
			resp[name] = value
		}
	}
	switch len(t.Audience) {
	case 0:
	case 1:
		resp["aud"] = t.Audience[0]
	default:
		resp["aud"] = t.Audience
	}
	for name, value := range map[string]any{
		"active":    true,
		"client_id": t.ClientID,
		"iss":       t.Issuer,
		"iat":       t.CreatedAt.Unix(),
		"exp":       t.ExpiresAt.Unix(),
	} {
		resp[name] = value
	}
	if len(t.Scopes) > 0 {
		resp["scope"] = strings.Join(t.Scopes, " ")
	}
	if t.Subject != "" {
		resp["sub"] = t.Subject
	}
	if t.Type == TokenTypeAccessToken {
		resp["token_type"] = "Bearer"
	}
	writeJSON(w, http.StatusOK, resp)
}
