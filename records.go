package grantor

import (
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
	// IDTokenHintSubject is the subject of a valid id_token_hint.
	IDTokenHintSubject string         `json:"id_token_hint_subject,omitempty"`
	Claims             *ClaimsRequest `json:"claims,omitempty"`

	// BindingHash binds the request to the user agent that started it.
	BindingHash string `json:"binding_hash,omitempty"`

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

// TokenType is the kind of a stored token.
type TokenType string

const (
	TokenTypeAuthorizationCode TokenType = "authorization_code"
	TokenTypeAccessToken       TokenType = "access_token"
	TokenTypeRefreshToken      TokenType = "refresh_token"
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
	Type    TokenType `json:"type"`
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
