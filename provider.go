package grantor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Default endpoint paths, relative to the issuer URL. See [Endpoints].
const (
	PathAuthorization       = "/authorize"
	PathToken               = "/token"
	PathUserInfo            = "/userinfo"
	PathIntrospection       = "/introspect"
	PathRevocation          = "/revoke"
	PathJWKS                = "/jwks"
	PathOpenIDConfiguration = "/.well-known/openid-configuration"
)

// PathAuthorizationServerMetadata is the RFC 8414 metadata path. For issuers
// with a path component, the issuer path is appended to it rather than
// prepended: https://id.example.com/.well-known/oauth-authorization-server/tenant.
const PathAuthorizationServerMetadata = "/.well-known/oauth-authorization-server"

// Issuer is the configuration of a single issuer (tenant).
type Issuer struct {
	// URL is the issuer identifier. It must be an https URL without query or
	// fragment; http is accepted only for loopback hosts, for development.
	// Endpoints are served below it, for example URL + "/token".
	URL string

	// Keys signs ID tokens. Every key is published in the JWKS. For each
	// algorithm, the first key with that algorithm signs new tokens, so a key
	// can be rotated by putting the new key before the old one and removing
	// the old key once tokens signed with it have expired.
	Keys []SigningKey
}

// Lifetimes configures how long issued artifacts stay valid. Zero values use
// the defaults; token lifetimes must be at least a second.
type Lifetimes struct {
	AuthorizationRequest time.Duration // default 15 minutes
	AuthorizationCode    time.Duration // default 1 minute
	AccessToken          time.Duration // default 1 hour
	RefreshToken         time.Duration // default 30 days
	IDToken              time.Duration // default 1 hour
}

// InteractionFunc handles a validated authorization request that needs the
// application: it authenticates the end-user and obtains consent, usually
// by redirecting to a login page, and eventually calls [Provider.Approve] or
// [Provider.Deny] with req.ID.
type InteractionFunc func(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest)

// ClaimsFunc returns the claims the application holds about the end-user of
// a grant. The provider filters them down to what the client is authorized
// to receive, based on the granted scopes and the claims request parameter.
// Protocol claims such as iss, aud and exp in the result are ignored.
type ClaimsFunc func(ctx context.Context, grant *Token) (map[string]any, error)

// Config configures a [Provider].
type Config struct {
	// Issuer is the issuer of a single-tenant provider. Exactly one of Issuer
	// and IssuerFor must be set.
	Issuer *Issuer

	// IssuerFor returns the issuer a request belongs to, for providers that
	// serve many issuers. It must only return issuers the application
	// controls, for example by looking up the Host header in a fixed table;
	// returning an error rejects the request with 404.
	IssuerFor func(r *http.Request) (*Issuer, error)

	// Clients looks up registered clients.
	Clients ClientStore

	// Storage persists authorization requests and tokens.
	Storage Storage

	// Interact is called by ServeAuthorization, and so by ServeHTTP, for
	// every valid authorization request. It is not used by applications that
	// write their own authorization endpoint.
	Interact InteractionFunc

	// Claims provides end-user claims for ID tokens and the UserInfo endpoint.
	// If nil, only the sub claim is returned.
	Claims ClaimsFunc

	// ScopeClaims maps additional scopes to the claims they grant access to,
	// on top of the standard profile, email, address and phone scopes.
	ScopeClaims map[string][]string

	// IDTokenScopeClaims also puts claims granted through scopes into the ID
	// token. By default they are only returned from the UserInfo endpoint,
	// as OpenID Connect Core section 5.4 specifies for the code flow.
	IDTokenScopeClaims bool

	Lifetimes Lifetimes

	// Endpoints configures the paths of the protocol endpoints.
	Endpoints Endpoints

	// AccessTokenFormat is the format of access tokens for clients that do not
	// set Client.AccessTokenFormat. It defaults to AccessTokenFormatOpaque.
	AccessTokenFormat AccessTokenFormat

	// AccessTokenFormats adds custom access token formats, which clients and
	// Config.BeforeIssue can select by name.
	AccessTokenFormats map[AccessTokenFormat]AccessTokenEncoder

	// Grants adds custom grant types to the token endpoint. Clients must list
	// a grant type in Client.GrantTypes to use it. The built-in grant types
	// cannot be redefined.
	Grants map[GrantType]GrantFunc

	// BeforeIssue is called before tokens are issued for any grant type,
	// after all protocol checks. Returning an *Error sends it to the client;
	// other errors become server_error. It may remove scopes from
	// is.Scopes and set is.RefreshToken to false.
	BeforeIssue func(ctx context.Context, is *Issuance) error

	// DisableInteractionBinding stops binding authorization requests to the
	// user agent with a cookie. Only disable it when the login pages run on
	// a different site than the provider.
	DisableInteractionBinding bool

	// ErrorPage renders errors that cannot be redirected to the client,
	// such as an unknown client or an invalid redirect_uri. The default
	// writes a plain-text response.
	ErrorPage func(w http.ResponseWriter, r *http.Request, err *Error)

	// Logger receives internal errors. It defaults to slog.Default().
	Logger *slog.Logger
}

// Provider is an OAuth 2.1 authorization server and OpenID Provider.
// It is an http.Handler serving all protocol endpoints.
type Provider struct {
	cfg    Config
	static *resolvedIssuer
	now    func() time.Time
}

// resolvedIssuer is an Issuer whose configuration has been validated.
type resolvedIssuer struct {
	url      string
	basePath string
	secure   bool
	keys     *keySet
}

// New validates cfg and returns a Provider.
func New(cfg Config) (*Provider, error) {
	if (cfg.Issuer == nil) == (cfg.IssuerFor == nil) {
		return nil, errors.New("grantor: exactly one of Config.Issuer and Config.IssuerFor must be set")
	}
	if cfg.Clients == nil {
		return nil, errors.New("grantor: Config.Clients is required")
	}
	if cfg.Storage == nil {
		return nil, errors.New("grantor: Config.Storage is required")
	}
	for scope := range cfg.ScopeClaims {
		if scope == "openid" || scope == "offline_access" {
			return nil, fmt.Errorf("grantor: Config.ScopeClaims cannot redefine the %q scope", scope)
		}
	}
	for gt, fn := range cfg.Grants {
		switch {
		case gt == "":
			return nil, errors.New("grantor: Config.Grants has an empty grant type")
		case gt == GrantTypeAuthorizationCode, gt == GrantTypeRefreshToken, gt == GrantTypeClientCredentials:
			return nil, fmt.Errorf("grantor: Config.Grants cannot redefine the %s grant type", gt)
		case fn == nil:
			return nil, fmt.Errorf("grantor: Config.Grants has no function for %s", gt)
		}
	}
	for name, enc := range cfg.AccessTokenFormats {
		switch {
		case name == "":
			return nil, errors.New("grantor: Config.AccessTokenFormats has an empty format name")
		case name == AccessTokenFormatOpaque, name == AccessTokenFormatJWT:
			return nil, fmt.Errorf("grantor: Config.AccessTokenFormats cannot redefine the %s format", name)
		case enc == nil:
			return nil, fmt.Errorf("grantor: Config.AccessTokenFormats has no encoder for %s", name)
		}
	}
	if cfg.AccessTokenFormat == "" {
		cfg.AccessTokenFormat = AccessTokenFormatOpaque
	}
	cfg.Endpoints.setDefaults()
	if err := cfg.Endpoints.validate(); err != nil {
		return nil, fmt.Errorf("grantor: %w", err)
	}
	setDefault(&cfg.Lifetimes.AuthorizationRequest, 15*time.Minute)
	setDefault(&cfg.Lifetimes.AuthorizationCode, time.Minute)
	setDefault(&cfg.Lifetimes.AccessToken, time.Hour)
	setDefault(&cfg.Lifetimes.RefreshToken, 30*24*time.Hour)
	setDefault(&cfg.Lifetimes.IDToken, time.Hour)
	for _, d := range []time.Duration{cfg.Lifetimes.AccessToken, cfg.Lifetimes.RefreshToken, cfg.Lifetimes.IDToken} {
		if !validLifetime(d) {
			return nil, errors.New("grantor: Config.Lifetimes of tokens must be at least a second")
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ErrorPage == nil {
		cfg.ErrorPage = defaultErrorPage
	}
	p := &Provider{cfg: cfg, now: time.Now}
	if !p.knownFormat(cfg.AccessTokenFormat) {
		return nil, fmt.Errorf("grantor: unknown Config.AccessTokenFormat %q", cfg.AccessTokenFormat)
	}
	if cfg.Issuer != nil {
		iss, err := resolveIssuer(cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("grantor: %w", err)
		}
		p.static = iss
	}
	return p, nil
}

func setDefault(d *time.Duration, v time.Duration) {
	if *d <= 0 {
		*d = v
	}
}

func resolveIssuer(iss *Issuer) (*resolvedIssuer, error) {
	u, err := url.Parse(iss.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL %q: %w", iss.URL, err)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (isLoopbackIP(u.Hostname()) || u.Hostname() == "localhost"):
	default:
		return nil, fmt.Errorf("issuer URL %q must use https", iss.URL)
	}
	if u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || strings.HasSuffix(iss.URL, "/") {
		return nil, fmt.Errorf("issuer URL %q must have a host, no query, fragment or user info, and no trailing slash", iss.URL)
	}
	keys, err := newKeySet(iss.Keys)
	if err != nil {
		return nil, fmt.Errorf("issuer %q: %w", iss.URL, err)
	}
	return &resolvedIssuer{
		url:      iss.URL,
		basePath: u.EscapedPath(),
		secure:   u.Scheme == "https",
		keys:     keys,
	}, nil
}

func (iss *resolvedIssuer) endpoint(path string) string { return iss.url + path }

func (p *Provider) issuerFor(r *http.Request) (*resolvedIssuer, error) {
	if p.static != nil {
		return p.static, nil
	}
	cfg, err := p.cfg.IssuerFor(r)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("IssuerFor returned no issuer")
	}
	return resolveIssuer(cfg)
}

// ServeHTTP routes requests to the protocol endpoints of the issuer the
// request belongs to, at the paths configured in Config.Endpoints, and serves
// the discovery documents at their well-known locations.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.withIssuer(w, r, p.route)
}

func (p *Provider) route(w http.ResponseWriter, r *http.Request, iss *resolvedIssuer) {
	path := r.URL.EscapedPath()
	if path == PathAuthorizationServerMetadata+iss.basePath {
		p.serveDiscovery(w, r, iss)
		return
	}
	rel, ok := strings.CutPrefix(path, iss.basePath)
	if !ok {
		http.NotFound(w, r)
		return
	}
	e := &p.cfg.Endpoints
	switch rel {
	case e.Authorization:
		p.serveAuthorization(w, r, iss)
	case e.Token:
		p.serveToken(w, r, iss)
	case e.UserInfo:
		p.serveUserInfo(w, r, iss)
	case e.Introspection:
		p.serveIntrospection(w, r, iss)
	case e.Revocation:
		p.serveRevocation(w, r, iss)
	case e.JWKS:
		p.serveJWKS(w, r, iss)
	case PathOpenIDConfiguration:
		p.serveDiscovery(w, r, iss)
	default:
		http.NotFound(w, r)
	}
}

// client looks up and validates a client of iss.
func (p *Provider) client(ctx context.Context, iss *resolvedIssuer, id string) (*Client, error) {
	c, err := p.cfg.Clients.Client(ctx, iss.url, id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("look up client: %w", err)
	}
	if c == nil {
		return nil, fmt.Errorf("client store returned no client and no error for %q", id)
	}
	if c.ID != id {
		return nil, fmt.Errorf("client store returned client %q for %q", c.ID, id)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if c.AccessTokenFormat != "" && !p.knownFormat(c.AccessTokenFormat) {
		return nil, fmt.Errorf("client %q has the unknown access token format %q", c.ID, c.AccessTokenFormat)
	}
	for _, gt := range c.grantTypes() {
		switch gt {
		case GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypeClientCredentials:
		default:
			if _, ok := p.cfg.Grants[gt]; !ok {
				return nil, fmt.Errorf("client %q has grant type %q, which is not built in or in Config.Grants", c.ID, gt)
			}
		}
	}
	return c, nil
}

// knownFormat reports whether f is a built-in or configured access token
// format.
func (p *Provider) knownFormat(f AccessTokenFormat) bool {
	if f == AccessTokenFormatOpaque || f == AccessTokenFormatJWT {
		return true
	}
	_, ok := p.cfg.AccessTokenFormats[f]
	return ok
}

func (p *Provider) logError(ctx context.Context, msg string, err error) {
	var e *Error
	if errors.As(err, &e) && e != nil && e.cause != nil {
		err = e.cause
	}
	p.cfg.Logger.ErrorContext(ctx, "grantor: "+msg, "error", err)
}

func defaultErrorPage(w http.ResponseWriter, _ *http.Request, err *Error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(err.HTTPStatus())
	fmt.Fprintln(w, err.Code)
	if err.Description != "" {
		fmt.Fprintln(w, sanitizeDescription(err.Description))
	}
}
