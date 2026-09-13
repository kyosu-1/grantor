# Pushed authorization requests (RFC 9126)

Date: 2026-09-14
Status: approved by the user ("ok.") as presented in chat; details below follow that design
Follows: [2026-09-13-v0.1-api-design.md](2026-09-13-v0.1-api-design.md)

## Problem

Authorization request parameters travel through the browser in the query string, where they can be read, logged and tampered with, and the client is not authenticated until the token request. RFC 9126 lets a client push the parameters to the authorization server over a direct, authenticated request and send only a short reference through the browser. grantor rejects `request_uri` today.

## Goal and success criteria

1. Clients can push authorization requests to a PAR endpoint, authenticated like at the token endpoint, and receive a `request_uri` (RFC 9126 section 2).
2. The authorization endpoint accepts `client_id` plus `request_uri`, uses only the pushed parameters, and continues with the usual interaction, approval and token flow (section 4).
3. Providers can require PAR for all clients or per client; requests without it are refused with `invalid_request`.
4. Applications that build endpoints from the low-level layer can parse, adjust and store pushed requests themselves, and their existing authorization endpoints work with pushed requests unchanged.
5. Discovery advertises the endpoint and the requirement (section 5).
6. Nothing changes for providers that do not enable PAR: no new endpoint is served and `request_uri` is still rejected with `request_uri_not_supported`.

All existing guarantees hold: `go test -race` passes in both modules and the OpenID conformance plans keep passing.

Out of scope: request objects (`request`, RFC 9101) at either endpoint, per-request redirect URIs for authenticated clients (section 2.4, a MAY), DPoP key binding (`dpop_jkt`), FAPI 2.0 conformance plans (they also need DPoP or mTLS).

## Decisions

| # | Decision | Rationale |
|---|---|---|
| P1 | `Config.PAR` is a `PARPolicy`: `PARDisabled` (zero value), `PARAllowed`, `PARRequired`. `Client.RequirePushedAuthorizationRequests` requires PAR per client; setting it while PAR is disabled is a client misconfiguration. | Opt-in keeps the v0.1 promise that unconfigured features serve no endpoints; mirrors `PKCEPolicy`; the client field mirrors RFC 9126 client metadata. |
| P2 | Pushed requests are stored with the existing authorization request methods under the ID `par:` + a 256-bit random reference; `request_uri` is `urn:ietf:params:oauth:request_uri:` + the same reference. | No new storage methods (V6). The `:` cannot appear in the base64url IDs of pending requests, so the two kinds never collide. |
| P3 | `AuthorizationRequest`, `Approve` and `Deny` never load IDs starting with `par:`. | A client knows its request_uri; it must not be able to pass it to a login page as a pending request ID. |
| P4 | A `request_uri` is redeemed at most once: `ParseAuthorizationRequest` deletes the pushed record (atomically, through `DeleteAuthorizationRequest`) before returning the request. | RFC 9126 section 7.3 recommends one-time use; reload tolerance is a MAY that weakens replay protection. |
| P5 | At the authorization endpoint only `client_id` and `request_uri` are read; other query parameters are ignored. The pushed request is validated again against the current client registration (section 7.4) and gets fresh `CreatedAt`/`ExpiresAt` from `Lifetimes.AuthorizationRequest`. | The pushed parameters are authoritative; re-validation catches policy changes; `prompt=login` and `max_age` measure from the browser's arrival. |
| P6 | Errors before a pushed request is trusted (missing `client_id`, unknown or expired or used `request_uri`, client mismatch, redirect URI no longer registered) go to `Config.ErrorPage` with `invalid_request_uri` or `invalid_request`; errors after the redirect URI is validated are redirected to the client. | Same rule as for ordinary requests (RFC 6749 section 4.1.2.1). |
| P7 | The PAR endpoint authenticates clients with the token endpoint rules, including public clients by `client_id`, requires `client_id` in the body to match the authenticated client, rejects `request_uri`, and validates the rest exactly like an authorization request. Errors are JSON, as at the token endpoint; nothing is redirected. | RFC 9126 section 2.1 and 2.3. |
| P8 | `AuthorizationRequest.Pushed` reports whether a request arrived through PAR; it is stored and survives saving. | Applications can audit or apply policy; storage round-trips it. |
| P9 | Low-level API: `ParsePushedAuthorizationRequest`, `PushAuthorizationRequest`, `WritePushedAuthorizationResponse`, `ServePushedAuthorization`; errors are written with `WriteTokenError`. `PushAuthorizationRequest` only accepts requests from `ParsePushedAuthorizationRequest` and validates them again. | Same parse → adjust → complete → write shape as the other endpoints; unauthenticated front-channel requests cannot be pushed. |
| P10 | `Lifetimes.PushedAuthorizationRequest` defaults to 60 seconds and must be at least a second; `Endpoints.PushedAuthorization` defaults to `/par`. | RFC 9126 suggests 5 to 600 seconds; `expires_in` counts whole seconds. |
| P11 | Client assertion audiences stay the issuer identifier only. | RFC 7523bis replaces RFC 9126's audience paragraph with that rule. |

## API

```go
// PARPolicy controls pushed authorization requests (RFC 9126).
type PARPolicy string

const (
	PARDisabled PARPolicy = ""         // no PAR endpoint; request_uri is rejected
	PARAllowed  PARPolicy = "allowed"  // clients may push authorization requests
	PARRequired PARPolicy = "required" // every authorization request must be pushed
)

type Config struct {
	// ...
	PAR PARPolicy
}

type Client struct {
	// ...
	RequirePushedAuthorizationRequests bool
}

type Endpoints struct {
	// ...
	PushedAuthorization string // default "/par"
}

type Lifetimes struct {
	// ...
	PushedAuthorizationRequest time.Duration // default 60 seconds
}

type AuthorizationRequest struct {
	// ...
	Pushed bool `json:"pushed,omitempty"`
}

// PushedAuthorizationResponse is the response of the PAR endpoint.
type PushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

const PathPushedAuthorization = "/par"

func (p *Provider) ServePushedAuthorization(w http.ResponseWriter, r *http.Request)
func (p *Provider) ParsePushedAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error)
func (p *Provider) PushAuthorizationRequest(r *http.Request, req *AuthorizationRequest) (*PushedAuthorizationResponse, error)
func (p *Provider) WritePushedAuthorizationResponse(w http.ResponseWriter, resp *PushedAuthorizationResponse)
```

`Storage` documents that authorization request IDs are ASCII strings of at most 64 bytes.

Discovery adds `pushed_authorization_request_endpoint` when PAR is enabled and `require_pushed_authorization_requests: true` when it is required.

## Data flow

Push:
1. `ServePushedAuthorization` → `ParsePushedAuthorizationRequest`: POST form, no repeated parameters, `authenticateClient`, `client_id` present and equal to the authenticated client, no `request_uri`, then the authorization request checks (`authorizationTarget` and `parseAuthorizationRequest`). The request is marked as pushable by that client (unexported).
2. `PushAuthorizationRequest`: not saved, pushable by its client, `checkRequest` against the current registration, then `CreateAuthorizationRequest` with ID `par:<ref>`, `Pushed: true`, `ExpiresAt = now + Lifetimes.PushedAuthorizationRequest`.
3. `WritePushedAuthorizationResponse`: `201`, `Cache-Control: no-store`, JSON.

Redeem:
1. `ParseAuthorizationRequest` sees `request_uri` with PAR enabled; requires `client_id`; strips the URN prefix; loads `par:<ref>`; requires `Pushed`, the issuer, the client ID and an unexpired record; deletes it (a concurrent or repeated use gets `ErrNotFound` → `invalid_request_uri`).
2. Looks up the client, runs `checkDelivery` (error page on failure) and `checkRequest` (redirected error on failure).
3. Returns an unsaved request (`parsed`, no ID, fresh times, `Pushed: true`). `ServeAuthorization` continues as today.

Requirement: an authorization request without `request_uri` from a client that must use PAR fails in `parseAuthorizationRequest` with a redirected `invalid_request`.

## Security

- The reference has 256 bits of entropy (RFC 9126 section 7.1), is bound to the client, is single-use and expires quickly.
- Pushed requests are validated when pushed and again when redeemed; approvals validate them a third time as today.
- Pushed records are unreachable through `AuthorizationRequest`, `Approve` and `Deny`.
- Only authenticated clients (or public clients by `client_id`, exactly as at the token endpoint) can push; redirect URIs must be registered.
- Credentials sent for client authentication are never stored in `Extra`.

## Testing

- PAR endpoint: success (201, URN format, `expires_in`, `no-store`), confidential client without credentials (`invalid_client`), public client push, missing or mismatched `client_id`, `request_uri` in the body, unregistered redirect URI (JSON `invalid_request`, no redirect), `request` parameter (`request_not_supported`), GET (405), disabled PAR (404), custom lifetime.
- Redemption: full flow to tokens; query parameters (`scope`, `state`, `redirect_uri`) ignored; reuse, expiry, unknown reference and client mismatch go to the error page; redirect URI removed from the client after pushing → error page; scope removed after pushing → redirected error; `Pushed` survives `SaveAuthorizationRequest`; `AuthorizationRequest(r, "par:…")` is not found.
- Requirement: `PARRequired` and `RequirePushedAuthorizationRequests` refuse plain requests with a redirected `invalid_request`; a client requiring PAR while PAR is disabled is a server error.
- Low-level: parse, narrow scopes, push; pushing a request from `ParseAuthorizationRequest` is refused.
- Discovery metadata with PAR disabled, allowed and required.
- `storagetest` fixture sets `Pushed`; README, design notes, package docs, CHANGELOG and `examples/lowlevel` cover PAR.
