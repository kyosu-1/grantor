package grantor

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"
)

var (
	// ErrAuthorizationRequestNotFound is returned by
	// [Provider.AuthorizationRequest], [Provider.Approve] and [Provider.Deny]
	// when a saved authorization request does not exist, has expired, was
	// already completed, or belongs to another user agent or issuer.
	ErrAuthorizationRequestNotFound = errors.New("grantor: authorization request not found")

	// ErrAuthorizationRequestModified is returned by [Provider.Approve] and
	// [Provider.Deny] when a saved authorization request was changed after
	// it was saved.
	ErrAuthorizationRequestModified = errors.New("grantor: authorization request was modified after it was saved")
)

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

// AuthorizationRequest returns the saved authorization request with the
// given ID, so that the application can show the client and the requested
// scopes to the end-user. r must be a request from the user agent that
// started the authorization request.
func (p *Provider) AuthorizationRequest(r *http.Request, id string) (*AuthorizationRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	return p.loadPending(nil, r, iss, id)
}

// loadPending loads a saved request and checks its issuer, expiry and
// binding. When w is not nil, a binding cookie set on w during this request
// is accepted, because the user agent has not sent it back yet.
func (p *Provider) loadPending(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer, id string) (*AuthorizationRequest, error) {
	if id == "" {
		return nil, ErrAuthorizationRequestNotFound
	}
	req, err := p.cfg.Storage.AuthorizationRequest(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrAuthorizationRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("grantor: load authorization request: %w", err)
	}
	if req.ID != id || req.Issuer != iss.url || !p.now().Before(req.ExpiresAt) {
		return nil, ErrAuthorizationRequestNotFound
	}
	if req.BindingHash != "" {
		name := bindingCookieName(req.ID, iss.secure)
		var value string
		if c, err := r.Cookie(name); err == nil {
			value = c.Value
		} else if w != nil {
			value = bindingFromResponse(w, name)
		}
		if value == "" || subtle.ConstantTimeCompare([]byte(hashToken(value)), []byte(req.BindingHash)) != 1 {
			return nil, ErrAuthorizationRequestNotFound
		}
	}
	return req, nil
}

// bindingFromResponse returns the value of the named cookie if it was set on
// w during this request.
func bindingFromResponse(w http.ResponseWriter, name string) string {
	for _, line := range w.Header().Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(line); err == nil && c.Name == name && c.MaxAge >= 0 {
			return c.Value
		}
	}
	return ""
}

// Approve completes an authorization request and redirects the user agent
// back to the client with an authorization code. req is either an unsaved
// request from ParseAuthorizationRequest or a saved request from
// AuthorizationRequest.
//
// The request is validated again against the client registration, so that
// changes the application made to it cannot weaken security. If Approve
// returns an error, nothing has been written to w. The error describes why
// the approval is not acceptable, for example because the end-user must
// authenticate again; see [AuthorizationRequest.NeedsAuthentication].
func (p *Provider) Approve(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, a Approval) error {
	iss, req, err := p.completable(w, r, req, true)
	if err != nil {
		return err
	}
	scopes, claims, err := p.validateApproval(req, &a)
	if err != nil {
		return err
	}
	if req.ID != "" {
		if err := p.completeRequest(r, req); err != nil {
			return err
		}
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
	target := targetOf(req)
	if err := p.cfg.Storage.CreateToken(r.Context(), t); err != nil {
		p.logError(r.Context(), "save authorization code", err)
		p.writeAuthorizationError(w, r, iss, target, errServer(err))
		return nil
	}
	p.clearBinding(w, req, iss)
	p.writeAuthorizationResponse(w, r, iss, target, url.Values{"code": {code}})
	return nil
}

// Deny completes an authorization request and redirects the user agent back
// to the client with an error, such as [ErrAccessDenied] or, for
// prompt=none requests, [ErrLoginRequired]. Extension error codes can be
// sent with a custom *Error, including its Description and URI. req is
// either an unsaved request from ParseAuthorizationRequest or a saved
// request from AuthorizationRequest.
//
// If Deny returns an error, nothing has been written to w.
func (p *Provider) Deny(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, reason *Error) error {
	if reason == nil {
		reason = ErrAccessDenied
	}
	if !validErrorCode(reason.Code) {
		return fmt.Errorf("grantor: %q is not a valid error code", reason.Code)
	}
	iss, req, err := p.completable(w, r, req, false)
	if err != nil {
		return err
	}
	if req.ID != "" {
		if err := p.completeRequest(r, req); err != nil {
			return err
		}
	}
	p.clearBinding(w, req, iss)
	p.writeAuthorizationError(w, r, iss, targetOf(req), reason)
	return nil
}

// completable returns the request to complete: the stored copy of a saved
// request, or a copy of an unsaved one. Either way it is validated again
// against the client registration: fully for an approval, and for a denial
// only as far as needed to deliver the error safely.
func (p *Provider) completable(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, approval bool) (*resolvedIssuer, *AuthorizationRequest, error) {
	if req == nil {
		return nil, nil, ErrAuthorizationRequestNotFound
	}
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, nil, fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	var current *AuthorizationRequest
	if req.ID != "" {
		stored, err := p.loadPending(w, r, iss, req.ID)
		if err != nil {
			return nil, nil, err
		}
		if !sameProtocolFields(stored, req) {
			return nil, nil, ErrAuthorizationRequestModified
		}
		current = stored
	} else {
		if !req.parsed {
			return nil, nil, errors.New("grantor: an unsaved authorization request must come from ParseAuthorizationRequest")
		}
		copied := *req
		current = &copied
		if !p.now().Before(current.ExpiresAt) {
			return nil, nil, ErrAuthorizationRequestNotFound
		}
	}
	client, err := p.client(r.Context(), iss, current.ClientID)
	if err != nil {
		return nil, nil, fmt.Errorf("grantor: look up client: %w", err)
	}
	check := p.checkRequest
	if !approval {
		check = p.checkDelivery
	}
	if err := check(iss, client, current); err != nil {
		return nil, nil, err
	}
	current.Claims = p.claimsForClient(client, current.Claims)
	return iss, current, nil
}

func invalidRequest(reason string) error {
	return errors.New("grantor: invalid authorization request: " + reason)
}

// checkDelivery validates what is needed to send an authorization response
// safely: the issuer, a registered redirect URI and a usable response mode.
func (p *Provider) checkDelivery(iss *resolvedIssuer, client *Client, req *AuthorizationRequest) error {
	switch {
	case req.Issuer != iss.url:
		return invalidRequest("it belongs to another issuer")
	case req.ClientID != client.ID:
		return invalidRequest("the client does not match")
	case !client.matchRedirectURI(req.RedirectURI):
		return invalidRequest("the redirect URI is not registered for the client")
	}
	switch req.ResponseMode {
	case responseModeQuery, responseModeFragment:
	case responseModeFormPost:
		if !isHTTPURL(req.RedirectURI) {
			return invalidRequest("form_post requires an http or https redirect URI")
		}
	default:
		return invalidRequest("unsupported response mode")
	}
	return nil
}

// checkRequest validates a request against the client registration and the
// provider policy, so that changes made by the application cannot weaken
// security.
func (p *Provider) checkRequest(iss *resolvedIssuer, client *Client, req *AuthorizationRequest) error {
	if err := p.checkDelivery(iss, client, req); err != nil {
		return err
	}
	invalid := invalidRequest
	switch {
	case !client.allowsGrant(GrantTypeAuthorizationCode):
		return invalid("the client may not use the authorization code grant")
	case req.ResponseType != "code":
		return invalid("response_type must be code")
	}
	for _, s := range req.Scopes {
		if !validScopeToken(s) || !slices.Contains(client.Scopes, s) {
			return invalid("a scope is not registered for the client")
		}
	}
	if req.CodeChallenge == "" {
		if req.CodeChallengeMethod != "" || checkPKCEPolicy(client, req) != nil {
			return invalid("the client must use PKCE")
		}
	} else if req.CodeChallengeMethod != "S256" || len(req.CodeChallenge) != 43 || !isUnreserved(req.CodeChallenge) {
		return invalid("the code challenge is malformed")
	}
	return nil
}

// sameProtocolFields reports whether two requests agree on every field that
// affects the authorization response or the security of the grant.
func sameProtocolFields(a, b *AuthorizationRequest) bool {
	return a.Issuer == b.Issuer &&
		a.ClientID == b.ClientID &&
		a.RedirectURI == b.RedirectURI &&
		a.RedirectURIInRequest == b.RedirectURIInRequest &&
		a.ResponseType == b.ResponseType &&
		a.ResponseMode == b.ResponseMode &&
		a.State == b.State &&
		slices.Equal(a.Scopes, b.Scopes) &&
		a.CodeChallenge == b.CodeChallenge &&
		a.CodeChallengeMethod == b.CodeChallengeMethod &&
		a.Nonce == b.Nonce &&
		slices.Equal(a.Prompt, b.Prompt) &&
		(a.MaxAge == nil) == (b.MaxAge == nil) && (a.MaxAge == nil || *a.MaxAge == *b.MaxAge) &&
		a.RequestedSubject == b.RequestedSubject
}

// completeRequest deletes a saved request so it cannot be completed twice.
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

// validateSubject checks the syntax of an end-user identifier (OpenID Connect
// Core section 2).
func validateSubject(subject string) error {
	if subject == "" || len(subject) > 255 {
		return errors.New("grantor: subject must be 1 to 255 characters")
	}
	for i := 0; i < len(subject); i++ {
		if subject[i] < 0x20 || subject[i] > 0x7e {
			return errors.New("grantor: subject must be printable ASCII")
		}
	}
	return nil
}

// validateApproval checks an approval against its request and returns the
// granted scopes and the approved part of the claims request.
func (p *Provider) validateApproval(req *AuthorizationRequest, a *Approval) ([]string, *ClaimsRequest, error) {
	if err := validateSubject(a.Subject); err != nil {
		return nil, nil, err
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
