package grantor

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	responseModeQuery    = "query"
	responseModeFragment = "fragment"
	responseModeFormPost = "form_post"

	// maxParamLength bounds individual authorization request parameters.
	maxParamLength = 4096
	// maxMaxAge bounds max_age so it cannot overflow time.Duration.
	maxMaxAge = 10 * 365 * 24 * 60 * 60
)

// ErrAuthorizationRequestNotFound is returned by [Provider.AuthorizationRequest],
// [Provider.Approve] and [Provider.Deny] when the authorization request does
// not exist, has expired, was already completed, or belongs to another user
// agent or issuer.
var ErrAuthorizationRequestNotFound = errors.New("grantor: authorization request not found")

// Approval is the application's decision to approve an authorization
// request.
type Approval struct {
	// Subject identifies the authenticated end-user. It must be at most 255
	// ASCII characters, and must never be reassigned to another end-user.
	Subject string

	// Scopes are the scopes the end-user granted. They must be a subset of
	// the requested scopes and include openid if it was requested. Per
	// OpenID Connect Core section 11, grant offline_access only when the
	// end-user consented to it.
	Scopes []string

	// AuthTime is when the end-user authenticated. It is required for OpenID
	// Connect requests.
	AuthTime time.Time

	// ACR is the authentication context class reference that was satisfied.
	ACR string

	// AMR lists the authentication methods used.
	AMR []string

	// Claims lists the claims requested individually with the claims
	// parameter that the end-user agreed to release, as returned by
	// [ClaimsRequest.Names]. Claims granted through Scopes need not be
	// listed.
	Claims []string
}

// authorizationTarget is where an authorization response is delivered.
type authorizationTarget struct {
	redirectURI string
	mode        string
	state       string
}

func (p *Provider) serveAuthorization(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	var q params
	if r.Method == http.MethodPost {
		var perr *Error
		if q, perr = parseForm(w, r); perr != nil {
			p.cfg.ErrorPage(w, r, perr)
			return
		}
	} else {
		q = newParams(r.URL.Query())
	}

	client, target, perr := p.authorizationTarget(r.Context(), iss, q)
	if perr != nil {
		if perr.Code == CodeServerError {
			p.logError(r.Context(), "authorization endpoint", perr)
		}
		p.cfg.ErrorPage(w, r, perr)
		return
	}

	req, perr := p.parseAuthorizationRequest(iss, client, q, target)
	if perr != nil {
		if perr.Code == CodeServerError {
			p.logError(r.Context(), "authorization endpoint", perr)
		}
		p.writeAuthorizationError(w, r, iss, target, perr)
		return
	}

	interactReq := r
	if !p.cfg.DisableInteractionBinding {
		binding := randomToken()
		req.BindingHash = hashToken(binding)
		cookie := &http.Cookie{
			Name:     bindingCookieName(req.ID, iss.secure),
			Value:    binding,
			Path:     "/",
			MaxAge:   int(p.cfg.Lifetimes.AuthorizationRequest / time.Second),
			Secure:   iss.secure,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)
		// The user agent only sends the cookie from its next request on.
		// Add it to the current request too, so that Interact can approve
		// immediately, for example when the end-user already has a session.
		interactReq = r.Clone(r.Context())
		interactReq.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	if err := p.cfg.Storage.CreateAuthorizationRequest(r.Context(), req); err != nil {
		p.logError(r.Context(), "save authorization request", err)
		p.writeAuthorizationError(w, r, iss, target, errServer(err))
		return
	}
	reqCopy := *req
	p.cfg.Interact(w, interactReq, &reqCopy)
}

// authorizationTarget authenticates the client_id and redirect_uri of an
// authorization request. Until both are known to be valid, errors must be
// shown to the user instead of being redirected (RFC 6749 section 4.1.2.1).
func (p *Provider) authorizationTarget(ctx context.Context, iss *resolvedIssuer, q params) (*Client, *authorizationTarget, *Error) {
	if q.isRepeated("client_id") || q.isRepeated("redirect_uri") {
		return nil, nil, errInvalidRequest("client_id and redirect_uri must not be repeated")
	}
	clientID := q.get("client_id")
	if clientID == "" {
		return nil, nil, errInvalidRequest("client_id is required")
	}
	client, err := p.client(ctx, iss, clientID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, errInvalidRequest("the client is not registered")
	}
	if err != nil {
		return nil, nil, errServer(err)
	}

	target := &authorizationTarget{mode: responseModeQuery, state: q.get("state")}
	switch redirectURI := q.get("redirect_uri"); {
	case redirectURI != "":
		if !client.matchRedirectURI(redirectURI) {
			return nil, nil, errInvalidRequest("redirect_uri is not registered for the client")
		}
		target.redirectURI = redirectURI
	case slices.Contains(splitSpaces(q.get("scope")), "openid"):
		return nil, nil, errInvalidRequest("redirect_uri is required")
	case len(client.RedirectURIs) == 1:
		target.redirectURI = client.RedirectURIs[0]
	default:
		return nil, nil, errInvalidRequest("redirect_uri is required")
	}
	if mode := q.get("response_mode"); mode != "" && !q.isRepeated("response_mode") {
		switch mode {
		case responseModeQuery, responseModeFragment:
			target.mode = mode
		case responseModeFormPost:
			// A form cannot be posted to a custom URI scheme; errors about the
			// response mode are then delivered in the query instead.
			if isHTTPURL(target.redirectURI) {
				target.mode = mode
			}
		}
	}
	return client, target, nil
}

// parseAuthorizationRequest validates the parameters of an authorization
// request whose client and redirect URI are already verified. Errors are
// redirected to the client.
func (p *Provider) parseAuthorizationRequest(iss *resolvedIssuer, client *Client, q params, target *authorizationTarget) (*AuthorizationRequest, *Error) {
	if len(q.repeated) > 0 {
		return nil, errInvalidRequest("parameters must not be repeated")
	}
	for _, v := range q.values {
		if len(v) > maxParamLength {
			return nil, errInvalidRequest("a parameter is too long")
		}
	}
	if q.has("request") {
		return nil, newError(CodeRequestNotSupported, "request objects are not supported")
	}
	if q.has("request_uri") {
		return nil, newError(CodeRequestURINotSupported, "request_uri is not supported")
	}
	if mode := q.get("response_mode"); mode != "" && mode != target.mode {
		return nil, errInvalidRequest("the response_mode is not supported for this redirect_uri")
	}

	switch rt := q.get("response_type"); rt {
	case "":
		return nil, errInvalidRequest("response_type is required")
	case "code":
	default:
		return nil, newError(CodeUnsupportedResponseType, "only the code response type is supported")
	}
	if !client.allowsGrant(GrantTypeAuthorizationCode) {
		return nil, newError(CodeUnauthorizedClient, "the client may not use the authorization code grant")
	}

	now := p.now()
	req := &AuthorizationRequest{
		ID:                   randomToken(),
		Issuer:               iss.url,
		ClientID:             client.ID,
		RedirectURI:          target.redirectURI,
		RedirectURIInRequest: q.has("redirect_uri"),
		ResponseType:         "code",
		ResponseMode:         target.mode,
		State:                target.state,
		Nonce:                q.get("nonce"),
		Display:              q.get("display"),
		LoginHint:            q.get("login_hint"),
		UILocales:            splitSpaces(q.get("ui_locales")),
		ClaimsLocales:        splitSpaces(q.get("claims_locales")),
		ACRValues:            splitSpaces(q.get("acr_values")),
		CreatedAt:            now,
		ExpiresAt:            now.Add(p.cfg.Lifetimes.AuthorizationRequest),
	}

	// OpenID Connect Core section 3.1.2.1: scope values that are not
	// understood SHOULD be ignored. Scopes the client may not request are
	// ignored the same way; the token response reports the granted scope.
	for _, s := range splitSpaces(q.get("scope")) {
		if !validScopeToken(s) {
			return nil, newError(CodeInvalidScope, "scope contains invalid characters")
		}
		if slices.Contains(client.Scopes, s) {
			req.Scopes = append(req.Scopes, s)
		}
	}

	if perr := parsePKCE(client, q, req); perr != nil {
		return nil, perr
	}

	req.Prompt = splitSpaces(q.get("prompt"))
	for _, v := range req.Prompt {
		switch v {
		case "none", "login", "consent", "select_account":
		default:
			return nil, errInvalidRequest("unsupported prompt value")
		}
	}
	if req.HasPrompt("none") && len(req.Prompt) > 1 {
		return nil, errInvalidRequest("prompt=none must not be combined with other values")
	}

	if v := q.get("max_age"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 || n > maxMaxAge {
			return nil, errInvalidRequest("max_age must be a non-negative integer")
		}
		d := time.Duration(n) * time.Second
		req.MaxAge = &d
	}

	if v := q.get("claims"); v != "" {
		var claims ClaimsRequest
		if err := json.Unmarshal([]byte(v), &claims); err != nil {
			return nil, errInvalidRequest("claims is not a valid JSON object")
		}
		req.Claims = p.claimsForClient(client, &claims)
	}

	if v := q.get("id_token_hint"); v != "" {
		sub, err := verifyIDTokenHint(iss, v, client.ID)
		if err != nil {
			return nil, errInvalidRequest("id_token_hint is not valid")
		}
		req.RequestedSubject = sub
	}
	// OpenID Connect Core section 3.1.2.2: a sub claim requested with a value
	// restricts the response to that end-user.
	if req.Claims != nil {
		if sub, ok := req.Claims.IDToken["sub"]; ok && sub != nil && sub.Value != nil {
			s, ok := sub.Value.(string)
			if !ok || s == "" || (req.RequestedSubject != "" && req.RequestedSubject != s) {
				return nil, errInvalidRequest("the requested sub claim value is invalid or conflicts with id_token_hint")
			}
			req.RequestedSubject = s
		}
	}
	return req, nil
}

// validateScopes checks the scope of a client credentials request.
func validateScopes(client *Client, scope string) ([]string, *Error) {
	scopes := splitSpaces(scope)
	for _, s := range scopes {
		if !validScopeToken(s) {
			return nil, newError(CodeInvalidScope, "scope contains invalid characters")
		}
		if !slices.Contains(client.Scopes, s) {
			return nil, newError(CodeInvalidScope, "the client may not request one of the scopes")
		}
	}
	return scopes, nil
}

// validScopeToken implements scope-token from RFC 6749 section 3.3.
func validScopeToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return s != ""
}

// AuthorizationRequest returns the pending authorization request with the
// given ID, so that the application can show the client and the requested
// scopes to the end-user. r must be a request from the user agent that
// started the authorization request.
func (p *Provider) AuthorizationRequest(r *http.Request, id string) (*AuthorizationRequest, error) {
	_, req, err := p.pendingRequest(r, id)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (p *Provider) pendingRequest(r *http.Request, id string) (*resolvedIssuer, *AuthorizationRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, nil, fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	if id == "" {
		return nil, nil, ErrAuthorizationRequestNotFound
	}
	req, err := p.cfg.Storage.AuthorizationRequest(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, ErrAuthorizationRequestNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("grantor: load authorization request: %w", err)
	}
	if req.ID != id || req.Issuer != iss.url || !p.now().Before(req.ExpiresAt) {
		return nil, nil, ErrAuthorizationRequestNotFound
	}
	if req.BindingHash != "" {
		c, err := r.Cookie(bindingCookieName(req.ID, iss.secure))
		if err != nil || subtle.ConstantTimeCompare([]byte(hashToken(c.Value)), []byte(req.BindingHash)) != 1 {
			return nil, nil, ErrAuthorizationRequestNotFound
		}
	}
	return iss, req, nil
}

// Approve completes the authorization request with the given ID and
// redirects the user agent back to the client with an authorization code.
//
// If Approve returns an error, nothing has been written to w. The error
// describes why the approval is not acceptable, for example because the
// end-user must authenticate again; see
// [AuthorizationRequest.NeedsAuthentication].
func (p *Provider) Approve(w http.ResponseWriter, r *http.Request, id string, a Approval) error {
	iss, req, err := p.pendingRequest(r, id)
	if err != nil {
		return err
	}
	scopes, claims, err := p.validateApproval(req, &a)
	if err != nil {
		return err
	}
	client, err := p.client(r.Context(), iss, req.ClientID)
	if err != nil {
		return fmt.Errorf("grantor: look up client: %w", err)
	}
	if !client.matchRedirectURI(req.RedirectURI) {
		return fmt.Errorf("grantor: redirect URI is no longer registered for client %q", client.ID)
	}
	if err := p.completeRequest(r, req); err != nil {
		return err
	}

	now := p.now()
	code := randomToken()
	t := &Token{
		Hash:                 hashToken(code),
		Type:                 TokenTypeAuthorizationCode,
		GrantID:              randomToken(),
		Issuer:               iss.url,
		ClientID:             req.ClientID,
		Subject:              a.Subject,
		Scopes:               scopes,
		AuthTime:             a.AuthTime,
		ACR:                  a.ACR,
		AMR:                  a.AMR,
		Claims:               claims,
		RedirectURI:          req.RedirectURI,
		RedirectURIInRequest: req.RedirectURIInRequest,
		Nonce:                req.Nonce,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		CreatedAt:            now,
		ExpiresAt:            now.Add(p.cfg.Lifetimes.AuthorizationCode),
	}
	target := &authorizationTarget{redirectURI: req.RedirectURI, mode: req.ResponseMode, state: req.State}
	if err := p.cfg.Storage.CreateToken(r.Context(), t); err != nil {
		p.logError(r.Context(), "save authorization code", err)
		p.writeAuthorizationError(w, r, iss, target, errServer(err))
		return nil
	}
	p.clearBinding(w, req, iss)
	p.writeAuthorizationResponse(w, r, iss, target, url.Values{"code": {code}})
	return nil
}

// Deny completes the authorization request with the given ID and redirects
// the user agent back to the client with an error, such as
// [ErrAccessDenied] or, for prompt=none requests, [ErrLoginRequired].
//
// If Deny returns an error, nothing has been written to w.
func (p *Provider) Deny(w http.ResponseWriter, r *http.Request, id string, reason *Error) error {
	if reason == nil {
		reason = ErrAccessDenied
	}
	switch reason.Code {
	case CodeAccessDenied, CodeLoginRequired, CodeConsentRequired, CodeInteractionRequired,
		CodeAccountSelectionRequired, CodeTemporarilyUnavailable, CodeServerError, CodeInvalidScope:
	default:
		return fmt.Errorf("grantor: %q cannot be used to deny an authorization request", reason.Code)
	}
	iss, req, err := p.pendingRequest(r, id)
	if err != nil {
		return err
	}
	if err := p.completeRequest(r, req); err != nil {
		return err
	}
	p.clearBinding(w, req, iss)
	target := &authorizationTarget{redirectURI: req.RedirectURI, mode: req.ResponseMode, state: req.State}
	p.writeAuthorizationError(w, r, iss, target, reason)
	return nil
}

// completeRequest deletes a pending request so it cannot be completed twice.
func (p *Provider) completeRequest(r *http.Request, req *AuthorizationRequest) error {
	err := p.cfg.Storage.DeleteAuthorizationRequest(r.Context(), req.ID)
	if errors.Is(err, ErrNotFound) {
		return ErrAuthorizationRequestNotFound
	}
	if err != nil {
		return fmt.Errorf("grantor: delete authorization request: %w", err)
	}
	return nil
}

// validateApproval checks an approval against its request and returns the
// granted scopes and the approved part of the claims request.
func (p *Provider) validateApproval(req *AuthorizationRequest, a *Approval) ([]string, *ClaimsRequest, error) {
	if a.Subject == "" || len(a.Subject) > 255 {
		return nil, nil, errors.New("grantor: approval subject must be 1 to 255 characters")
	}
	for i := 0; i < len(a.Subject); i++ {
		if a.Subject[i] < 0x20 || a.Subject[i] > 0x7e {
			return nil, nil, errors.New("grantor: approval subject must be printable ASCII")
		}
	}
	var scopes []string
	for _, s := range a.Scopes {
		if !req.HasScope(s) {
			return nil, nil, fmt.Errorf("grantor: approved scope %q was not requested", s)
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	requestedClaims := req.Claims.Names()
	for _, c := range a.Claims {
		if !slices.Contains(requestedClaims, c) {
			return nil, nil, fmt.Errorf("grantor: approved claim %q was not requested", c)
		}
	}
	if !req.IsOpenID() {
		return scopes, nil, nil
	}
	if !slices.Contains(scopes, "openid") {
		return nil, nil, errors.New("grantor: the openid scope must be approved for OpenID Connect requests")
	}
	now := p.now()
	if a.AuthTime.IsZero() || a.AuthTime.After(now.Add(time.Minute)) {
		return nil, nil, errors.New("grantor: approval AuthTime must be set and not in the future")
	}
	if req.needsAuthentication(a.AuthTime, now) {
		return nil, nil, errors.New("grantor: the end-user must authenticate again (prompt=login or max_age)")
	}
	if req.RequestedSubject != "" && req.RequestedSubject != a.Subject {
		return nil, nil, errors.New("grantor: the authenticated end-user is not the one the client requested")
	}
	if values, essential := requestedEssentialACR(req.Claims); essential {
		if a.ACR == "" || (len(values) > 0 && !slices.Contains(values, a.ACR)) {
			return nil, nil, errors.New("grantor: the essential acr claim request is not satisfied")
		}
	}
	return scopes, req.Claims.filter(func(name string) bool { return slices.Contains(a.Claims, name) }), nil
}

// bindingCookieName returns the name of the cookie that binds an
// authorization request to the user agent. On https the __Host- prefix
// stops sibling subdomains from setting the cookie.
func bindingCookieName(requestID string, secure bool) string {
	name := "grantor_" + hashToken(requestID)[:16]
	if secure {
		name = "__Host-" + name
	}
	return name
}

func (p *Provider) clearBinding(w http.ResponseWriter, req *AuthorizationRequest, iss *resolvedIssuer) {
	if req.BindingHash == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     bindingCookieName(req.ID, iss.secure),
		Path:     "/",
		MaxAge:   -1,
		Secure:   iss.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (p *Provider) writeAuthorizationError(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer, target *authorizationTarget, e *Error) {
	v := url.Values{"error": {e.Code}}
	if e.Description != "" {
		v.Set("error_description", sanitizeDescription(e.Description))
	}
	p.writeAuthorizationResponse(w, r, iss, target, v)
}

// writeAuthorizationResponse delivers response parameters to the client's
// redirection endpoint, adding state and the RFC 9207 iss parameter.
func (p *Provider) writeAuthorizationResponse(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer, target *authorizationTarget, v url.Values) {
	if target.state != "" {
		v.Set("state", target.state)
	}
	v.Set("iss", iss.url)
	noStore(w)

	switch target.mode {
	case responseModeFormPost:
		writeFormPost(w, target.redirectURI, v)
		return
	case responseModeFragment:
		redirect(w, r, target.redirectURI+"#"+v.Encode())
	default:
		u := target.redirectURI
		switch {
		case strings.HasSuffix(u, "?"):
			u += v.Encode()
		case strings.Contains(u, "?"):
			u += "&" + v.Encode()
		default:
			u += "?" + v.Encode()
		}
		redirect(w, r, u)
	}
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http")
}

func redirect(w http.ResponseWriter, r *http.Request, location string) {
	status := http.StatusFound
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		status = http.StatusSeeOther
	}
	w.Header().Set("Location", location)
	w.WriteHeader(status)
}
