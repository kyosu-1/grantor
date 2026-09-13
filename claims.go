package grantor

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// standardScopeClaims is the scope to claims mapping of OpenID Connect Core
// section 5.4.
var standardScopeClaims = map[string][]string{
	"profile": {
		"name", "family_name", "given_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "gender",
		"birthdate", "zoneinfo", "locale", "updated_at",
	},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// protocolClaims are set by the provider and never taken from ClaimsFunc.
var protocolClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"nbf": true, "jti": true, "auth_time": true, "nonce": true, "acr": true,
	"amr": true, "azp": true, "at_hash": true, "c_hash": true, "sid": true,
	"client_id": true, "scope": true, "cnf": true,
}

func (p *Provider) scopeClaims(scope string) []string {
	if c, ok := p.cfg.ScopeClaims[scope]; ok {
		return c
	}
	return standardScopeClaims[scope]
}

// supportedClaims lists every claim name the provider can return, for the
// discovery document.
func (p *Provider) supportedClaims() []string {
	set := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true, "iat": true,
		"auth_time": true, "nonce": true, "acr": true, "amr": true, "at_hash": true,
	}
	for _, claims := range standardScopeClaims {
		for _, c := range claims {
			set[c] = true
		}
	}
	for _, claims := range p.cfg.ScopeClaims {
		for _, c := range claims {
			set[c] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

func (p *Provider) supportedScopes() []string {
	set := map[string]bool{"openid": true, "offline_access": true}
	for s := range standardScopeClaims {
		set[s] = true
	}
	for s := range p.cfg.ScopeClaims {
		set[s] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// allowedClaims returns the names of the end-user claims a grant may
// receive: those granted through scopes (when includeScopes is set) and
// those requested individually with the claims parameter.
func (p *Provider) allowedClaims(grant *Token, requested map[string]*ClaimRequest, includeScopes bool) map[string]bool {
	allowed := map[string]bool{}
	if includeScopes {
		for _, scope := range grant.Scopes {
			for _, c := range p.scopeClaims(scope) {
				allowed[c] = true
			}
		}
	}
	for name := range requested {
		allowed[name] = true
	}
	return allowed
}

// claimsForClient reduces a claims request to the claims the client may
// receive: those mapped from a scope the client is registered for, plus the
// sub, acr and auth_time claims whose requests affect authentication.
func (p *Provider) claimsForClient(client *Client, c *ClaimsRequest) *ClaimsRequest {
	allowed := map[string]bool{"sub": true, "acr": true, "auth_time": true}
	for _, scope := range client.Scopes {
		for _, name := range p.scopeClaims(scope) {
			allowed[name] = true
		}
	}
	return c.filter(func(name string) bool { return allowed[name] })
}

// endUserClaims returns the filtered end-user claims for a grant.
func (p *Provider) endUserClaims(ctx context.Context, grant *Token, allowed map[string]bool) (map[string]any, error) {
	out := map[string]any{}
	if p.cfg.Claims == nil || len(allowed) == 0 {
		return out, nil
	}
	g := *grant
	all, err := p.cfg.Claims(ctx, &g)
	if err != nil {
		return nil, fmt.Errorf("claims func: %w", err)
	}
	for name, value := range all {
		if allowed[name] && !protocolClaims[name] && value != nil {
			out[name] = value
		}
	}
	return out, nil
}

// requestedEssentialACR returns the acr values requested as essential through the
// claims parameter, if any.
func requestedEssentialACR(c *ClaimsRequest) (values []string, essential bool) {
	if c == nil {
		return nil, false
	}
	req, ok := c.IDToken["acr"]
	if !ok || req == nil || !req.Essential {
		return nil, false
	}
	if s, ok := req.Value.(string); ok {
		values = append(values, s)
	}
	for _, v := range req.Values {
		if s, ok := v.(string); ok {
			values = append(values, s)
		}
	}
	return values, true
}

// normalizeClaims returns claims as decoded JSON, or nil when there are none.
// Claims that cannot be serialized fail before any token is issued, the
// result shares nothing with the caller's map, and encoders, storage and
// responses all see the same values. Claims with nil values are dropped, as
// they are for Config.Claims.
func normalizeClaims(claims map[string]any) (map[string]any, error) {
	if len(claims) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	for name, value := range out {
		if value == nil {
			delete(out, name)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// copyJSON deep-copies a value decoded from JSON.
func copyJSON(v any) any {
	switch v := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(v))
		for name, value := range v {
			m[name] = copyJSON(value)
		}
		return m
	case []any:
		s := make([]any, len(v))
		for i, value := range v {
			s[i] = copyJSON(value)
		}
		return s
	default:
		return v
	}
}
