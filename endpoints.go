package grantor

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Endpoints are the paths of the protocol endpoints, relative to the issuer
// URL. They are published in the discovery document and routed by
// [Provider.ServeHTTP]. Empty fields use the Path constants. Endpoints of
// features that are not configured are never served, so upgrading grantor
// does not expose new endpoints.
type Endpoints struct {
	Authorization string
	Token         string
	UserInfo      string
	Introspection string
	Revocation    string
	JWKS          string
}

func (e *Endpoints) setDefaults() {
	for _, f := range []struct {
		path *string
		def  string
	}{
		{&e.Authorization, PathAuthorization},
		{&e.Token, PathToken},
		{&e.UserInfo, PathUserInfo},
		{&e.Introspection, PathIntrospection},
		{&e.Revocation, PathRevocation},
		{&e.JWKS, PathJWKS},
	} {
		if *f.path == "" {
			*f.path = f.def
		}
	}
}

func (e *Endpoints) validate() error {
	seen := map[string]bool{}
	for _, path := range []string{e.Authorization, e.Token, e.UserInfo, e.Introspection, e.Revocation, e.JWKS} {
		if !strings.HasPrefix(path, "/") || (&url.URL{Path: path}).EscapedPath() != path {
			return fmt.Errorf("endpoint path %q must start with / and contain only path characters", path)
		}
		if strings.HasPrefix(path, "/.well-known/") {
			return fmt.Errorf("endpoint path %q must not be below /.well-known/", path)
		}
		if seen[path] {
			return fmt.Errorf("endpoint path %q is used twice", path)
		}
		seen[path] = true
	}
	return nil
}

var errNoInteract = errors.New("Config.Interact is not set")

// withIssuer resolves the issuer of r and calls fn. Requests for unknown
// issuers get 404, and failures to resolve an issuer are logged and get 500:
// as a JSON error response when jsonErrors is set, otherwise with
// Config.ErrorPage.
func (p *Provider) withIssuer(w http.ResponseWriter, r *http.Request, jsonErrors bool, fn func(http.ResponseWriter, *http.Request, *resolvedIssuer)) {
	iss, err := p.issuerFor(r)
	if err == nil {
		fn(w, r, iss)
		return
	}
	perr := issuerError(err)
	if perr.Code == CodeServerError {
		p.logError(r.Context(), "resolve issuer", perr)
	} else {
		p.cfg.Logger.DebugContext(r.Context(), "grantor: no issuer for request", "path", r.URL.Path, "error", err)
	}
	switch {
	case jsonErrors:
		noStore(w)
		writeJSON(w, perr.HTTPStatus(), map[string]string{"error": perr.Code, "error_description": perr.Description})
	case perr.Code == CodeServerError:
		p.cfg.ErrorPage(w, r, perr)
	default:
		http.NotFound(w, r)
	}
}

// ServeAuthorization serves the authorization endpoint: it parses and saves
// the authorization request and hands it to Config.Interact. Use
// ParseAuthorizationRequest and the related methods to write an
// authorization endpoint of your own.
func (p *Provider) ServeAuthorization(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, false, p.serveAuthorization)
}

// ServeToken serves the token endpoint. Use ParseTokenRequest, Exchange and
// WriteTokenResponse to write a token endpoint of your own.
func (p *Provider) ServeToken(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, true, p.serveToken)
}

// ServeUserInfo serves the UserInfo endpoint.
func (p *Provider) ServeUserInfo(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, true, p.serveUserInfo)
}

// ServeIntrospection serves the token introspection endpoint.
func (p *Provider) ServeIntrospection(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, true, p.serveIntrospection)
}

// ServeRevocation serves the token revocation endpoint.
func (p *Provider) ServeRevocation(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, true, p.serveRevocation)
}

// ServeJWKS serves the public keys of the issuer.
func (p *Provider) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, false, p.serveJWKS)
}

// ServeDiscovery serves the OpenID Provider and RFC 8414 authorization server
// metadata document. Mount it at /.well-known/openid-configuration below
// the issuer path, and for RFC 8414 at
// /.well-known/oauth-authorization-server followed by the issuer path.
func (p *Provider) ServeDiscovery(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, false, p.serveDiscovery)
}
