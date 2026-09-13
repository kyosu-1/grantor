package grantor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// PARPolicy controls pushed authorization requests (RFC 9126).
type PARPolicy string

const (
	// PARDisabled serves no pushed authorization request endpoint and rejects
	// request_uri at the authorization endpoint. It is the default.
	PARDisabled PARPolicy = ""
	// PARAllowed lets clients push authorization requests. Authorization
	// requests with their parameters in the URL are still accepted, except
	// from clients with Client.RequirePushedAuthorizationRequests.
	PARAllowed PARPolicy = "allowed"
	// PARRequired accepts authorization requests only through the pushed
	// authorization request endpoint.
	PARRequired PARPolicy = "required"
)

const (
	// requestURIPrefix is the prefix of the request_uri values issued by the
	// pushed authorization request endpoint (RFC 9126 section 2.2).
	requestURIPrefix = "urn:ietf:params:oauth:request_uri:"
	// pushedIDPrefix is the prefix of the storage IDs of pushed requests.
	// The IDs of pending requests are base64url and never contain a colon.
	pushedIDPrefix = "par:"
)

// PushedAuthorizationResponse is a successful response of the pushed
// authorization request endpoint.
type PushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

func errPARDisabled() *Error {
	return &Error{Code: CodeInvalidRequest, Description: "pushed authorization requests are not enabled", StatusCode: http.StatusNotFound}
}

// ServePushedAuthorization serves the pushed authorization request endpoint
// (RFC 9126). It responds with 404 unless Config.PAR enables pushed
// authorization requests. Use ParsePushedAuthorizationRequest,
// PushAuthorizationRequest and WritePushedAuthorizationResponse to write an
// endpoint of your own.
func (p *Provider) ServePushedAuthorization(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, true, p.servePushedAuthorization)
}

func (p *Provider) servePushedAuthorization(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	if p.cfg.PAR == PARDisabled {
		p.WriteTokenError(w, r, errPARDisabled())
		return
	}
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	req, perr := p.parsePushedAuthorization(w, r, iss)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	resp, perr := p.pushAuthorization(r.Context(), iss, req)
	if perr != nil {
		p.WriteTokenError(w, r, perr)
		return
	}
	p.WritePushedAuthorizationResponse(w, resp)
}

// ParsePushedAuthorizationRequest authenticates the client of a pushed
// authorization request and validates the request like an authorization
// request. Adjust the result if needed and store it with
// PushAuthorizationRequest. Write errors with WriteTokenError.
func (p *Provider) ParsePushedAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, issuerError(err)
	}
	req, perr := p.parsePushedAuthorization(nil, r, iss)
	if perr != nil {
		return nil, perr
	}
	return req, nil
}

func (p *Provider) parsePushedAuthorization(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) (*AuthorizationRequest, *Error) {
	if p.cfg.PAR == PARDisabled {
		return nil, errPARDisabled()
	}
	if r.Method != http.MethodPost {
		return nil, &Error{Code: CodeInvalidRequest, Description: "the pushed authorization request endpoint only accepts POST", StatusCode: http.StatusMethodNotAllowed}
	}
	q, perr := parseForm(w, r)
	if perr != nil {
		return nil, perr
	}
	if len(q.repeated) > 0 {
		return nil, errInvalidRequest("parameters must not be repeated")
	}
	client, perr := p.authenticateClient(r, iss, q)
	if perr != nil {
		return nil, perr
	}
	// RFC 9126 section 2.1: client_id is required, and request_uri must not
	// be pushed.
	switch {
	case q.get("client_id") != client.ID:
		return nil, errInvalidRequest("client_id is required and must identify the authenticated client")
	case q.has("request_uri"):
		return nil, errInvalidRequest("request_uri must not be pushed")
	}
	_, target, perr := p.authorizationTarget(r.Context(), iss, q)
	if perr != nil {
		return nil, perr
	}
	req, perr := p.parseAuthorizationRequest(iss, client, q, target, true)
	if perr != nil {
		return nil, perr
	}
	req.pushedBy = client.ID
	return req, nil
}

// PushAuthorizationRequest validates a request from
// ParsePushedAuthorizationRequest again, stores it and returns the response
// with its request_uri. Write errors with WriteTokenError.
func (p *Provider) PushAuthorizationRequest(r *http.Request, req *AuthorizationRequest) (*PushedAuthorizationResponse, error) {
	iss, err := p.issuerFor(r)
	if err != nil {
		return nil, issuerError(err)
	}
	resp, perr := p.pushAuthorization(r.Context(), iss, req)
	if perr != nil {
		return nil, perr
	}
	return resp, nil
}

func (p *Provider) pushAuthorization(ctx context.Context, iss *resolvedIssuer, req *AuthorizationRequest) (*PushedAuthorizationResponse, *Error) {
	switch {
	case p.cfg.PAR == PARDisabled:
		return nil, errPARDisabled()
	case req == nil || req.pushedBy == "" || req.pushedBy != req.ClientID:
		return nil, errServer(errors.New("the AuthorizationRequest was not created by ParsePushedAuthorizationRequest"))
	case req.ID != "":
		return nil, errServer(errors.New("the authorization request is already saved"))
	}
	client, err := p.client(ctx, iss, req.ClientID)
	if err != nil {
		return nil, errServer(fmt.Errorf("look up client: %w", err))
	}
	if err := p.checkRequest(iss, client, req); err != nil {
		return nil, errServer(err)
	}
	ref := randomToken()
	now := p.now()
	pushed := *req
	pushed.ID = pushedIDPrefix + ref
	pushed.Pushed = true
	pushed.parsed = false
	pushed.pushedBy = ""
	pushed.BindingHash = ""
	pushed.Claims = p.claimsForClient(client, pushed.Claims)
	pushed.CreatedAt = now
	pushed.ExpiresAt = now.Add(p.cfg.Lifetimes.PushedAuthorizationRequest)
	if err := p.cfg.Storage.CreateAuthorizationRequest(ctx, &pushed); err != nil {
		return nil, errServer(fmt.Errorf("save pushed authorization request: %w", err))
	}
	return &PushedAuthorizationResponse{
		RequestURI: requestURIPrefix + ref,
		ExpiresIn:  int64(p.cfg.Lifetimes.PushedAuthorizationRequest / time.Second),
	}, nil
}

// WritePushedAuthorizationResponse writes a successful pushed authorization
// request response.
func (p *Provider) WritePushedAuthorizationResponse(w http.ResponseWriter, resp *PushedAuthorizationResponse) {
	noStore(w)
	writeJSON(w, http.StatusCreated, resp)
}

// parRequired reports whether the authorization requests of client must be
// pushed.
func (p *Provider) parRequired(client *Client) bool {
	return p.cfg.PAR == PARRequired || client.RequirePushedAuthorizationRequests
}
