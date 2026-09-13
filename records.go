package grantor

import (
	"maps"
	"slices"
	"time"
)

// AuthorizationRequest is a validated authorization request waiting for the
// application to authenticate the end-user and obtain consent.
type AuthorizationRequest struct {
	// ID identifies the request in [Provider.AuthorizationRequest],
	// [Provider.Approve] and [Provider.Deny]. It is a secret: anyone who
	// knows it can try to complete the request.
	ID     string `json:"id"`
	Issuer string `json:"issuer"`

	ClientID string `json:"client_id"`
	// RedirectURI is the redirection endpoint the response is sent to.
	RedirectURI string `json:"redirect_uri"`
	// RedirectURIInRequest reports whether redirect_uri was present in the
	// request, in which case the token request must repeat it.
	RedirectURIInRequest bool   `json:"redirect_uri_in_request,omitempty"`
	ResponseType         string `json:"response_type"`
	ResponseMode         string `json:"response_mode"`
	State                string `json:"state,omitempty"`

	// Scopes are the requested scopes, in request order without duplicates.
	Scopes []string `json:"scopes,omitempty"`

	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// OpenID Connect parameters.
	Nonce  string   `json:"nonce,omitempty"`
	Prompt []string `json:"prompt,omitempty"`
	// MaxAge is the max_age parameter, or nil if it was not sent.
	MaxAge        *time.Duration `json:"max_age,omitempty"`
	Display       string         `json:"display,omitempty"`
	UILocales     []string       `json:"ui_locales,omitempty"`
	ClaimsLocales []string       `json:"claims_locales,omitempty"`
	LoginHint     string         `json:"login_hint,omitempty"`
	ACRValues     []string       `json:"acr_values,omitempty"`
	// RequestedSubject is the end-user the client asked for, with a valid
	// id_token_hint or a sub claim requested with a value. Only this end-user
	// may be approved.
	RequestedSubject string `json:"requested_subject,omitempty"`
	// Claims is the claims request parameter, reduced to the claims the
	// client may receive. See [Approval.Claims].
	Claims *ClaimsRequest `json:"claims,omitempty"`

	// Audience is the audience the request may be approved for. It starts as
	// Client.Audience; see [Approval.Audience].
	Audience []string `json:"audience,omitempty"`

	// Extra holds the non-empty request parameters that grantor does not
	// process, such as extension parameters.
	Extra map[string]string `json:"extra,omitempty"`

	// BindingHash binds the request to the user agent that started it.
	BindingHash string `json:"binding_hash,omitempty"`

	// parsed marks an unsaved request returned by ParseAuthorizationRequest.
	// It is never stored, so a saved request with its ID cleared cannot be
	// passed off as unsaved.
	parsed bool

	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// HasScope reports whether scope was requested.
func (r *AuthorizationRequest) HasScope(scope string) bool {
	return slices.Contains(r.Scopes, scope)
}

// HasPrompt reports whether the prompt parameter contains value.
func (r *AuthorizationRequest) HasPrompt(value string) bool {
	return slices.Contains(r.Prompt, value)
}

// IsOpenID reports whether this is an OpenID Connect authentication request.
func (r *AuthorizationRequest) IsOpenID() bool { return r.HasScope("openid") }

// NeedsAuthentication reports whether an end-user who authenticated at
// authTime must authenticate again before the request can be approved,
// because of prompt=login or max_age. A zero authTime always needs
// authentication.
func (r *AuthorizationRequest) NeedsAuthentication(authTime time.Time) bool {
	return r.needsAuthentication(authTime, time.Now())
}

func (r *AuthorizationRequest) needsAuthentication(authTime, now time.Time) bool {
	if authTime.IsZero() {
		return true
	}
	// Timestamps in ID tokens have one-second precision.
	authenticatedDuringRequest := !authTime.Before(r.CreatedAt.Truncate(time.Second))
	if r.HasPrompt("login") && !authenticatedDuringRequest {
		return true
	}
	if r.MaxAge != nil {
		if *r.MaxAge == 0 {
			return !authenticatedDuringRequest
		}
		if now.Sub(authTime) > *r.MaxAge {
			return true
		}
	}
	return false
}

// TokenKind is the kind of a stored token. It is not the token_type of a
// token response.
type TokenKind string

const (
	TokenKindAuthorizationCode TokenKind = "authorization_code"
	TokenKindAccessToken       TokenKind = "access_token"
	TokenKindRefreshToken      TokenKind = "refresh_token"
)

// Token is a stored authorization code, access token or refresh token.
//
// Tokens issued from the same authorization share a GrantID, so that a whole
// grant can be revoked at once, for example when an authorization code or
// refresh token is reused.
type Token struct {
	// Hash is the SHA-256 hash of the token value. The value itself is never
	// stored.
	Hash    string    `json:"hash"`
	Kind    TokenKind `json:"kind"`
	GrantID string    `json:"grant_id"`
	Issuer  string    `json:"issuer"`

	ClientID string `json:"client_id"`
	// Subject identifies the end-user. It is empty for client credentials.
	Subject string   `json:"subject,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`

	AuthTime time.Time      `json:"auth_time,omitzero"`
	ACR      string         `json:"acr,omitempty"`
	AMR      []string       `json:"amr,omitempty"`
	Claims   *ClaimsRequest `json:"claims,omitempty"`

	// Audience lists the intended recipients of access tokens of the grant.
	Audience []string `json:"audience,omitempty"`
	// AccessTokenClaims are extra claims of an access token, set by
	// Config.BeforeIssue.
	AccessTokenClaims map[string]any `json:"access_token_claims,omitempty"`

	// Fields used by authorization codes only.
	RedirectURI          string `json:"redirect_uri,omitempty"`
	RedirectURIInRequest bool   `json:"redirect_uri_in_request,omitempty"`
	Nonce                string `json:"nonce,omitempty"`
	CodeChallenge        string `json:"code_challenge,omitempty"`
	CodeChallengeMethod  string `json:"code_challenge_method,omitempty"`

	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	ConsumedAt time.Time `json:"consumed_at,omitzero"`
}

// HasScope reports whether the token was granted scope.
func (t *Token) HasScope(scope string) bool {
	return slices.Contains(t.Scopes, scope)
}

// ClaimsRequest is the OpenID Connect claims request parameter
// (OpenID Connect Core section 5.5).
type ClaimsRequest struct {
	UserInfo map[string]*ClaimRequest `json:"userinfo,omitempty"`
	IDToken  map[string]*ClaimRequest `json:"id_token,omitempty"`
}

// ClaimRequest describes how an individual claim is requested. A nil
// *ClaimRequest requests the claim in the default manner.
type ClaimRequest struct {
	Essential bool  `json:"essential,omitempty"`
	Value     any   `json:"value,omitempty"`
	Values    []any `json:"values,omitempty"`
}

// Names returns the sorted names of the end-user claims requested for the
// ID token or the UserInfo response. Claims that the provider sets itself,
// such as sub and acr, are not included. Names is safe to call on a nil
// *ClaimsRequest.
func (c *ClaimsRequest) Names() []string {
	if c == nil {
		return nil
	}
	set := map[string]bool{}
	for _, m := range []map[string]*ClaimRequest{c.IDToken, c.UserInfo} {
		for name := range m {
			if !protocolClaims[name] {
				set[name] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// filter returns the part of the request for which keep returns true, or
// nil if nothing remains.
func (c *ClaimsRequest) filter(keep func(name string) bool) *ClaimsRequest {
	if c == nil {
		return nil
	}
	sub := func(m map[string]*ClaimRequest) map[string]*ClaimRequest {
		var out map[string]*ClaimRequest
		for name, req := range m {
			if keep(name) {
				if out == nil {
					out = map[string]*ClaimRequest{}
				}
				out[name] = req
			}
		}
		return out
	}
	out := &ClaimsRequest{IDToken: sub(c.IDToken), UserInfo: sub(c.UserInfo)}
	if out.IDToken == nil && out.UserInfo == nil {
		return nil
	}
	return out
}
