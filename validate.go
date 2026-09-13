package grantor

import (
	"errors"
	"fmt"
	"net/http"
)

// ValidateAccessToken returns the stored access token if token is an active
// access token of the issuer r belongs to. It returns an error wrapping
// ErrNotFound for tokens that are not active and for requests of unknown
// issuers. Resource servers
// that run in the same process as the provider can use it instead of the
// introspection endpoint; it works for every access token format.
func (p *Provider) ValidateAccessToken(r *http.Request, token string) (*Token, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	t, err := p.cfg.Storage.Token(r.Context(), hashToken(token))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("grantor: look up access token: %w", err)
	}
	if t.Kind != TokenKindAccessToken || t.Issuer != iss.url || !p.now().Before(t.ExpiresAt) {
		return nil, ErrNotFound
	}
	return t, nil
}
