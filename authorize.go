package grantor

import (
	"context"
	"encoding/base64"
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
	// OAuth 2.1 section 1.7.1 asks for values that fit an 8000-octet
	// request line to be supported.
	maxParamLength = 8000
	// maxMaxAge bounds max_age so it cannot overflow time.Duration.
	maxMaxAge = 10 * 365 * 24 * 60 * 60
)

// authorizationTarget is where an authorization response is delivered.
type authorizationTarget struct {
	redirectURI string
	mode        string
	state       string
}

// authorizationParams are the authorization request parameters grantor
// processes; others are kept in AuthorizationRequest.Extra.
var authorizationParams = map[string]bool{
	"response_type": true, "client_id": true, "redirect_uri": true, "scope": true, "state": true,
	"response_mode": true, "code_challenge": true, "code_challenge_method": true, "nonce": true,
	"display": true, "prompt": true, "max_age": true, "ui_locales": true, "claims_locales": true,
	"id_token_hint": true, "login_hint": true, "acr_values": true, "claims": true,
	"request": true, "request_uri": true,
}

// authorizationError is an error from ParseAuthorizationRequest. A non-nil
// target means the error may be redirected to the client.
type authorizationError struct {
	err    *Error
	iss    *resolvedIssuer
	target *authorizationTarget
}

func (e *authorizationError) Error() string { return e.err.Error() }
func (e *authorizationError) Unwrap() error { return e.err }

// ParseAuthorizationRequest validates an authorization request and returns
// it unsaved. Complete it right away with Approve or Deny, or save it with
// SaveAuthorizationRequest to complete it later, for example after a login
// page. Write errors with WriteAuthorizationError, which redirects them to
// the client when that is safe.
func (p *Provider) ParseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, &Error{Code: CodeInvalidRequest, Description: "unknown issuer", StatusCode: http.StatusNotFound, cause: err}
	}
	return p.parseAuthorization(r, iss)
}

func (p *Provider) parseAuthorization(r *http.Request, iss *resolvedIssuer) (*AuthorizationRequest, error) {
	var q params
	switch r.Method {
	case http.MethodGet:
		q = newParams(r.URL.Query())
	case http.MethodPost:
		var perr *Error
		if q, perr = parseForm(r); perr != nil {
			return nil, &authorizationError{err: perr, iss: iss}
		}
	default:
		return nil, &authorizationError{err: &Error{Code: CodeInvalidRequest, Description: "method not allowed", StatusCode: http.StatusMethodNotAllowed}, iss: iss}
	}
	client, target, perr := p.authorizationTarget(r.Context(), iss, q)
	if perr != nil {
		return nil, &authorizationError{err: perr, iss: iss}
	}
	req, perr := p.parseAuthorizationRequest(iss, client, q, target)
	if perr != nil {
		return nil, &authorizationError{err: perr, iss: iss, target: target}
	}
	return req, nil
}

// WriteAuthorizationError writes an error for an authorization request.
// Errors from ParseAuthorizationRequest that are safe to redirect are sent to
// the client; all other errors are rendered with Config.ErrorPage. To send an
// error for a parsed request, use Deny.
func (p *Provider) WriteAuthorizationError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *authorizationError
	if errors.As(err, &ae) && ae.target != nil {
		if ae.err.Code == CodeServerError {
			p.logError(r.Context(), "authorization endpoint", ae.err)
		}
		p.writeAuthorizationError(w, r, ae.iss, ae.target, ae.err)
		return
	}
	e := asProtocolError(err)
	if e.Code == CodeServerError {
		p.logError(r.Context(), "authorization endpoint", err)
	}
	p.cfg.ErrorPage(w, r, e)
}

// SaveAuthorizationRequest stores a request returned by
// ParseAuthorizationRequest so that it can be completed later with Approve or
// Deny. It sets req.ID, which identifies the request in
// AuthorizationRequest, and binds the request to the user agent with a
// cookie. A saved request cannot be changed; make changes before saving.
func (p *Provider) SaveAuthorizationRequest(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) error {
	iss, err := p.issuerFor(r)
	if err != nil {
		return fmt.Errorf("grantor: resolve issuer: %w", err)
	}
	if req.ID != "" {
		return errors.New("grantor: authorization request is already saved")
	}
	client, err := p.client(r.Context(), iss, req.ClientID)
	if err != nil {
		return fmt.Errorf("grantor: look up client: %w", err)
	}
	if err := p.checkRequest(iss, client, req); err != nil {
		return err
	}
	saved := *req
	saved.ID = randomToken()
	saved.Claims = p.claimsForClient(client, saved.Claims)
	var binding string
	if !p.cfg.DisableInteractionBinding {
		binding = randomToken()
		saved.BindingHash = hashToken(binding)
	}
	if err := p.cfg.Storage.CreateAuthorizationRequest(r.Context(), &saved); err != nil {
		return fmt.Errorf("grantor: save authorization request: %w", err)
	}
	if binding != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     bindingCookieName(saved.ID, iss.secure),
			Value:    binding,
			Path:     "/",
			MaxAge:   int(p.cfg.Lifetimes.AuthorizationRequest / time.Second),
			Secure:   iss.secure,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	*req = saved
	return nil
}

func (p *Provider) serveAuthorization(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if !allowMethods(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if p.cfg.Interact == nil {
		p.logError(r.Context(), "authorization endpoint", errNoInteract)
		p.cfg.ErrorPage(w, r, errServer(errNoInteract))
		return
	}
	req, err := p.parseAuthorization(r, iss)
	if err != nil {
		p.WriteAuthorizationError(w, r, err)
		return
	}
	if err := p.SaveAuthorizationRequest(w, r, req); err != nil {
		p.logError(r.Context(), "save authorization request", err)
		p.writeAuthorizationError(w, r, iss, targetOf(req), errServer(err))
		return
	}
	interactReq := r
	if req.BindingHash != "" {
		// The user agent only sends the binding cookie from its next request
		// on. Add it to the request passed to Interact, so that
		// AuthorizationRequest also works there.
		name := bindingCookieName(req.ID, iss.secure)
		interactReq = r.Clone(r.Context())
		interactReq.AddCookie(&http.Cookie{Name: name, Value: bindingFromResponse(w, name)})
	}
	reqCopy := *req
	p.cfg.Interact(w, interactReq, &reqCopy)
}

func targetOf(req *AuthorizationRequest) *authorizationTarget {
	return &authorizationTarget{redirectURI: req.RedirectURI, mode: req.ResponseMode, state: req.State}
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
	responseMode := q.get("response_mode")
	if v := q.get("request"); v != "" {
		// Request objects are rejected, but the rejection must reach the
		// client the way it asked for, which it may have said only inside
		// the request object.
		objMode, objState := requestObjectResponseHints(v)
		if responseMode == "" {
			responseMode = objMode
		}
		if target.state == "" {
			target.state = objState
		}
	}
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
	if mode := responseMode; mode != "" && !q.isRepeated("response_mode") {
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

	for name, v := range q.values {
		if !authorizationParams[name] {
			if req.Extra == nil {
				req.Extra = map[string]string{}
			}
			req.Extra[name] = v
		}
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
func validateScopes(client *Client, scopes []string) ([]string, *Error) {
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

// requestObjectResponseHints reads response_mode and state from the payload of
// an unsupported request object, without verifying it. The values only
// decide how the request_not_supported error is delivered to the redirect
// URI that was already validated, so they need not be trusted.
func requestObjectResponseHints(requestObject string) (responseMode, state string) {
	parts := strings.Split(requestObject, ".")
	if len(parts) != 3 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var hints struct {
		ResponseMode string `json:"response_mode"`
		State        string `json:"state"`
	}
	if json.Unmarshal(payload, &hints) != nil {
		return "", ""
	}
	return hints.ResponseMode, hints.State
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

func (p *Provider) writeAuthorizationError(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer, target *authorizationTarget, e *Error) {
	v := url.Values{"error": {e.Code}}
	if e.Description != "" {
		v.Set("error_description", sanitizeDescription(e.Description))
	}
	if e.URI != "" {
		v.Set("error_uri", sanitizeURI(e.URI))
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
