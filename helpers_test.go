package grantor_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

const testIssuer = "https://op.example.com"

var (
	keyOnce  sync.Once
	rsaKey   *rsa.PrivateKey
	ecKey    *ecdsa.PrivateKey
	clientEC *ecdsa.PrivateKey
)

func testKeys(t *testing.T) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
		if clientEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
	})
}

// clock is a controllable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// env is a provider wired to an in-memory store, driven through
// httptest.ResponseRecorder.
type env struct {
	t        *testing.T
	p        *grantor.Provider
	handler  http.Handler
	store    *memory.Store
	clock    *clock
	issuer   string
	jar      *cookiejar.Jar
	pending  *grantor.AuthorizationRequest
	claims   map[string]map[string]any
	interact grantor.InteractionFunc
	opts     []envOption
}

type envOption func(*grantor.Config)

func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()
	testKeys(t)
	e := &env{
		t:      t,
		store:  memory.New(),
		clock:  &clock{now: time.Now().Truncate(time.Second)},
		issuer: testIssuer,
		opts:   opts,
		claims: map[string]map[string]any{
			"alice": {
				"name":           "Alice Example",
				"email":          "alice@example.com",
				"email_verified": true,
				"phone_number":   "+1 555 0100",
				"department":     "engineering",
				"iss":            "https://attacker.example.com",
			},
		},
	}
	e.jar, _ = cookiejar.New(nil)
	e.p = e.build()
	e.handler = e.p
	return e
}

// build creates a provider for e with the options of newEnv and extra.
func (e *env) build(extra ...envOption) *grantor.Provider {
	e.t.Helper()
	cfg := grantor.Config{
		Issuer: &grantor.Issuer{
			URL: testIssuer,
			Keys: []grantor.SigningKey{
				{ID: "rsa-1", Signer: rsaKey},
				{ID: "ec-1", Signer: ecKey},
			},
		},
		Clients: e.store,
		Storage: e.store,
		Interact: func(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest) {
			e.pending = req
			if e.interact != nil {
				e.interact(w, r, req)
				return
			}
			io.WriteString(w, "login page")
		},
		Claims: func(_ context.Context, grant *grantor.Token) (map[string]any, error) {
			return e.claims[grant.Subject], nil
		},
		ScopeClaims: map[string][]string{"org": {"department"}},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, o := range append(slices.Clone(e.opts), extra...) {
		o(&cfg)
	}
	p, err := grantor.New(cfg)
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	grantor.SetClock(p, e.clock.Now)
	return p
}

// mustProvider replaces the provider of e with one that also applies opts.
func mustProvider(t *testing.T, e *env, opts ...envOption) *grantor.Provider {
	t.Helper()
	p := e.build(opts...)
	e.handler = p
	return p
}

const (
	publicClient       = "public-app"
	confidentialClient = "web-app"
	confidentialSecret = "web-app-secret-with-plenty-of-entropy-0123456789"
	postClient         = "post-app"
	jwtClient          = "jwt-app"
	serviceClient      = "service"
	resourceServer     = "resource-server"
	clientRedirect     = "https://client.example.com/cb"
)

var allScopes = []string{"openid", "profile", "email", "phone", "offline_access", "org", "api"}

func (e *env) registerClients() {
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: clientEC.Public(), KeyID: "client-key", Use: "sig"}}})
	e.store.SetClient(e.issuer, grantor.Client{
		ID:           publicClient,
		RedirectURIs: []string{clientRedirect, "http://127.0.0.1/native"},
		GrantTypes:   []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes:       allScopes,
	})
	// Many tests exercise confidential clients without PKCE, as OAuth 2.0
	// and OpenID Connect Core allow; the OAuth 2.1 default is tested
	// separately.
	e.store.SetClient(e.issuer, grantor.Client{
		ID:           confidentialClient,
		SecretHash:   grantor.HashSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect},
		GrantTypes:   []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeRefreshToken},
		Scopes:       allScopes,
		PKCE:         grantor.PKCEOptional,
	})
	e.store.SetClient(e.issuer, grantor.Client{
		ID:                postClient,
		AuthMethod:        grantor.AuthMethodClientSecretPost,
		SecretHash:        grantor.HashSecret(confidentialSecret),
		RedirectURIs:      []string{clientRedirect},
		Scopes:            allScopes,
		IDTokenSigningAlg: "ES256",
		PKCE:              grantor.PKCEOptional,
	})
	e.store.SetClient(e.issuer, grantor.Client{
		ID:           jwtClient,
		JWKS:         jwks,
		RedirectURIs: []string{clientRedirect},
		GrantTypes:   []grantor.GrantType{grantor.GrantTypeAuthorizationCode, grantor.GrantTypeClientCredentials},
		Scopes:       allScopes,
	})
	e.store.SetClient(e.issuer, grantor.Client{
		ID:         serviceClient,
		SecretHash: grantor.HashSecret(confidentialSecret),
		GrantTypes: []grantor.GrantType{grantor.GrantTypeClientCredentials},
		Scopes:     []string{"api", "openid"},
	})
	e.store.SetClient(e.issuer, grantor.Client{
		ID:                 resourceServer,
		SecretHash:         grantor.HashSecret(confidentialSecret),
		GrantTypes:         []grantor.GrantType{grantor.GrantTypeClientCredentials},
		AllowIntrospection: true,
	})
}

// do sends a request through the provider, carrying the cookie jar.
func (e *env) do(req *http.Request) *httptest.ResponseRecorder {
	e.t.Helper()
	for _, c := range e.jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	e.jar.SetCookies(req.URL, rec.Result().Cookies())
	return rec
}

func (e *env) get(path string, q url.Values) *httptest.ResponseRecorder {
	u := e.issuer + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return e.do(httptest.NewRequest(http.MethodGet, u, nil))
}

func (e *env) postForm(path string, form url.Values, auth func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, e.issuer+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if auth != nil {
		auth(req)
	}
	return e.do(req)
}

func basic(id, secret string) func(*http.Request) {
	return func(r *http.Request) { r.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret)) }
}

// appRequest builds a request to an application page on the provider's host,
// carrying the browser's cookies.
func (e *env) appRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, e.issuer+path, nil)
	for _, c := range e.jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	return req
}

func (e *env) approve(id string, a grantor.Approval) (*httptest.ResponseRecorder, error) {
	e.t.Helper()
	req := e.appRequest(http.MethodPost, "/login")
	rec := httptest.NewRecorder()
	err := e.p.Approve(rec, req, id, a)
	e.jar.SetCookies(req.URL, rec.Result().Cookies())
	return rec, err
}

func (e *env) deny(id string, reason *grantor.Error) (*httptest.ResponseRecorder, error) {
	e.t.Helper()
	req := e.appRequest(http.MethodPost, "/login")
	rec := httptest.NewRecorder()
	err := e.p.Deny(rec, req, id, reason)
	return rec, err
}

type pkcePair struct{ verifier, challenge string }

func newPKCE() pkcePair {
	b := make([]byte, 32)
	rand.Read(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return pkcePair{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

func authParams(clientID string, scopes string, pkce pkcePair) url.Values {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {clientRedirect},
		"scope":         {scopes},
		"state":         {"xyz"},
		"nonce":         {"n-0S6_WzA2Mj"},
	}
	if pkce.challenge != "" {
		q.Set("code_challenge", pkce.challenge)
		q.Set("code_challenge_method", "S256")
	}
	return q
}

// startAuthorization sends an authorization request that must reach the
// application, and returns the pending request.
func (e *env) startAuthorization(q url.Values) *grantor.AuthorizationRequest {
	e.t.Helper()
	e.pending = nil
	rec := e.get(grantor.PathAuthorization, q)
	if rec.Code != http.StatusOK || e.pending == nil {
		e.t.Fatalf("authorization request did not reach the application: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	return e.pending
}

// redirectParams parses the query of an authorization response redirect.
func redirectParams(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound && rec.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect, got %d %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad Location %q: %v", loc, err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != clientRedirect && !strings.HasPrefix(loc, "http://127.0.0.1") {
		t.Fatalf("redirected to %q, want %q", got, clientRedirect)
	}
	return u.Query()
}

// login runs an authorization request through approval and returns the
// authorization code.
func (e *env) login(q url.Values, scopes []string) string {
	e.t.Helper()
	req := e.startAuthorization(q)
	if scopes == nil {
		scopes = req.Scopes
	}
	rec, err := e.approve(req.ID, grantor.Approval{
		Subject:  "alice",
		Scopes:   scopes,
		AuthTime: e.clock.Now(),
		AMR:      []string{"pwd"},
	})
	if err != nil {
		e.t.Fatalf("Approve: %v", err)
	}
	params := redirectParams(e.t, rec)
	if params.Get("iss") != e.issuer {
		e.t.Fatalf("authorization response iss = %q, want %q", params.Get("iss"), e.issuer)
	}
	if params.Get("state") != q.Get("state") {
		e.t.Fatalf("authorization response state = %q, want %q", params.Get("state"), q.Get("state"))
	}
	code := params.Get("code")
	if code == "" {
		e.t.Fatalf("no code in authorization response: %v", params)
	}
	return code
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode JSON response %q: %v", rec.Body.String(), err)
	}
	return v
}

func (e *env) tokenRequest(form url.Values, auth func(*http.Request)) (int, map[string]any) {
	e.t.Helper()
	rec := e.postForm(grantor.PathToken, form, auth)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		e.t.Errorf("token response Cache-Control = %q, want no-store", cc)
	}
	return rec.Code, decodeJSON(e.t, rec)
}

func (e *env) exchangeCode(clientID, code, verifier string, auth func(*http.Request)) (int, map[string]any) {
	e.t.Helper()
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {clientRedirect},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	if auth == nil {
		form.Set("client_id", clientID)
	}
	return e.tokenRequest(form, auth)
}

func expectError(t *testing.T, status int, body map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || body["error"] != wantCode {
		t.Fatalf("got %d %v, want %d error=%s", status, body, wantStatus, wantCode)
	}
}

// verifyJWT verifies a JWT against the provider's published JWKS and returns
// its claims.
func (e *env) verifyJWT(token string) map[string]any {
	e.t.Helper()
	rec := e.get(grantor.PathJWKS, nil)
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		e.t.Fatalf("decode JWKS: %v", err)
	}
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		e.t.Fatalf("parse JWT: %v", err)
	}
	keys := set.Key(tok.Headers[0].KeyID)
	if len(keys) != 1 {
		e.t.Fatalf("JWT kid %q not found in JWKS", tok.Headers[0].KeyID)
	}
	var claims map[string]any
	if err := tok.Claims(keys[0].Key, &claims); err != nil {
		e.t.Fatalf("verify JWT: %v", err)
	}
	return claims
}

// clientAssertion signs a private_key_jwt assertion for jwtClient.
func clientAssertion(t *testing.T, aud string, exp time.Time, jti string, key crypto.Signer, alg jose.SignatureAlgorithm) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "client-key"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := jwt.Claims{
		Issuer:   jwtClient,
		Subject:  jwtClient,
		Audience: jwt.Audience{aud},
		Expiry:   jwt.NewNumericDate(exp),
		ID:       jti,
	}
	s, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return s
}
