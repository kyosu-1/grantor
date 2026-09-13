// Package grantor is a toolkit for building OAuth 2.1 authorization servers
// and OpenID Connect providers.
//
// A [Provider] is an http.Handler that serves the protocol endpoints of one
// or more issuers: authorization, token, UserInfo, introspection, revocation,
// JWKS and discovery. The application stays in charge of everything that is
// not protocol: it stores data behind the [Storage] and [ClientStore]
// interfaces, authenticates end-users and asks for consent in its own pages,
// and supplies end-user claims.
//
// # Layers
//
// [Provider.ServeHTTP] serves every endpoint at the paths in
// [Config.Endpoints]. It is built from exported building blocks that
// applications can use directly: a ServeXxx method per endpoint for any
// router, [Provider.ParseAuthorizationRequest], [Provider.Approve] and
// [Provider.Deny] for a custom authorization endpoint,
// [Provider.ParseTokenRequest] and [Provider.Exchange] for a custom token
// endpoint, [Config.BeforeIssue] to check every issuance, and
// [Config.Grants] with [Provider.IssueTokens] for custom grant types.
//
// # Authorization flow
//
// When a valid authorization request arrives, the provider saves it and
// calls [Config.Interact]. The application authenticates the end-user,
// typically on a login page of its own, and finishes the request with
// [Provider.Approve] or [Provider.Deny]:
//
//	cfg.Interact = func(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest) {
//		http.Redirect(w, r, "/login?id="+url.QueryEscape(req.ID), http.StatusFound)
//	}
//
//	// in the login handler, after authenticating the end-user:
//	req, err := provider.AuthorizationRequest(r, id)
//	// ...
//	err = provider.Approve(w, r, req, grantor.Approval{
//		Subject:  user.ID,
//		Scopes:   req.Scopes,
//		AuthTime: authTime,
//	})
//
// # Supported specifications
//
//   - OAuth 2.1 (draft-ietf-oauth-v2-1-16): authorization code with PKCE,
//     refresh token and client credentials grants
//   - RFC 7636 PKCE (S256 only; required for every client by default)
//   - RFC 7009 token revocation and RFC 7662 token introspection
//   - RFC 9068 JWT access tokens, alongside opaque and custom formats
//   - RFC 8414 authorization server metadata and RFC 9207 issuer identification
//   - RFC 8252 loopback redirect URIs for native apps
//   - OpenID Connect Core 1.0 (code flow), Discovery 1.0 and the Form Post
//     Response Mode
//   - client_secret_basic, client_secret_post, private_key_jwt (RFC 7523 and
//     RFC 7523bis) and none client authentication
//
// Implicit and resource owner password credentials grants are not supported,
// as OAuth 2.1 omits them.
package grantor
