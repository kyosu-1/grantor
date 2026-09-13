package grantor

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

func (p *Provider) serveUserInfo(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	// OpenID Connect Core section 5.3: the UserInfo endpoint SHOULD support
	// CORS. Requests carry bearer tokens, not cookies, so any origin is safe.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !allowMethods(w, r, http.MethodGet, http.MethodPost, http.MethodOptions) {
		return
	}
	w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
	token, perr := bearerToken(w, r)
	if perr != nil {
		p.writeBearerError(w, r, perr)
		return
	}
	t, err := p.cfg.Storage.Token(r.Context(), hashToken(token))
	if err != nil && !errors.Is(err, ErrNotFound) {
		p.writeBearerError(w, r, errServer(err))
		return
	}
	if err != nil || t.Kind != TokenKindAccessToken || t.Issuer != iss.url || !p.now().Before(t.ExpiresAt) {
		p.writeBearerError(w, r, newError(CodeInvalidToken, "the access token is invalid or expired"))
		return
	}
	if !t.HasScope("openid") || t.Subject == "" {
		p.writeBearerError(w, r, newError(CodeInsufficientScope, "the access token was not granted the openid scope"))
		return
	}

	var requested map[string]*ClaimRequest
	if t.Claims != nil {
		requested = t.Claims.UserInfo
	}
	claims, err := p.endUserClaims(r.Context(), t, p.allowedClaims(t, requested, true))
	if err != nil {
		p.writeBearerError(w, r, errServer(err))
		return
	}
	claims["sub"] = t.Subject
	noStore(w)
	writeJSON(w, http.StatusOK, claims)
}

// bearerToken extracts an RFC 6750 bearer token from the Authorization
// header or a form-encoded body. Tokens in the query string are not accepted.
func bearerToken(w http.ResponseWriter, r *http.Request) (string, *Error) {
	var tokens []string
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, value, _ := strings.Cut(h, " ")
		switch {
		case !strings.EqualFold(scheme, "Bearer"):
			// RFC 6750 section 3.1: other authentication schemes get no
			// error code.
			return "", &Error{StatusCode: http.StatusUnauthorized}
		case value == "":
			return "", errInvalidRequest("malformed Authorization header")
		}
		tokens = append(tokens, value)
	}
	if r.Method == http.MethodPost {
		if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct == "application/x-www-form-urlencoded" {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
			if err := r.ParseForm(); err != nil {
				return "", errInvalidRequest("the request body could not be parsed")
			}
			if v := r.PostForm["access_token"]; len(v) > 0 {
				tokens = append(tokens, v...)
			}
		}
	}
	switch len(tokens) {
	case 0:
		// RFC 6750 section 3.1: no error code when no credentials were sent.
		return "", &Error{StatusCode: http.StatusUnauthorized}
	case 1:
		return tokens[0], nil
	default:
		return "", errInvalidRequest("only one access token may be sent")
	}
}

// writeBearerError writes an RFC 6750 section 3 error response.
func (p *Provider) writeBearerError(w http.ResponseWriter, r *http.Request, e *Error) {
	if e.Code == CodeServerError {
		p.logError(r.Context(), "userinfo endpoint", e)
		noStore(w)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": CodeServerError})
		return
	}
	challenge := `Bearer realm="userinfo"`
	if e.Code != "" {
		challenge += fmt.Sprintf(`, error=%q`, e.Code)
		if e.Description != "" {
			challenge += fmt.Sprintf(`, error_description=%q`, sanitizeDescription(e.Description))
		}
		if e.URI != "" {
			challenge += fmt.Sprintf(`, error_uri=%q`, sanitizeURI(e.URI))
		}
	}
	w.Header().Set("WWW-Authenticate", challenge)
	noStore(w)
	if e.Code == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, e.HTTPStatus(), map[string]string{"error": e.Code})
}
