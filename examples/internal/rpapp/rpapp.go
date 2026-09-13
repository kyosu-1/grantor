// Package rpapp is a small OpenID Connect relying party used to exercise the
// example provider. It uses golang.org/x/oauth2 and github.com/coreos/go-oidc,
// independent client libraries, to show interoperability.
package rpapp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config configures the relying party.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// BaseURL is where the relying party is served, for example
	// http://localhost:9002. The redirect URI is BaseURL + "/callback".
	BaseURL string
	Scopes  []string
}

// App is the relying party.
type App struct {
	cfg Config

	initMu     sync.Mutex
	provider   *oidc.Provider
	oauth      *oauth2.Config
	verifier   *oidc.IDTokenVerifier
	revokeURL  string
	introspect string

	mu       sync.Mutex
	pending  map[string]*pendingLogin // by cookie value
	sessions map[string]*session      // by cookie value
}

type pendingLogin struct {
	state, nonce, verifier string
	created                time.Time
}

type session struct {
	Token        *oauth2.Token
	IDToken      string
	IDClaims     map[string]any
	UserInfo     map[string]any
	Introspected map[string]any
	Message      string
}

const (
	pendingCookie = "rp_login"
	sessionCookie = "rp_session"
)

// New returns a relying party. Discovery happens on first use, so the
// provider does not need to be running yet.
func New(cfg Config) *App {
	return &App{cfg: cfg, pending: map[string]*pendingLogin{}, sessions: map[string]*session{}}
}

// Handler returns the HTTP handler of the relying party.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /callback", a.callback)
	mux.HandleFunc("POST /refresh", a.refresh)
	mux.HandleFunc("POST /introspect", a.introspectToken)
	mux.HandleFunc("POST /logout", a.logout)
	return mux
}

func (a *App) setup(ctx context.Context) error {
	a.initMu.Lock()
	defer a.initMu.Unlock()
	if a.provider != nil {
		return nil
	}
	provider, err := oidc.NewProvider(ctx, a.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("discover %s: %w", a.cfg.Issuer, err)
	}
	var extra struct {
		RevocationEndpoint    string `json:"revocation_endpoint"`
		IntrospectionEndpoint string `json:"introspection_endpoint"`
	}
	if err := provider.Claims(&extra); err != nil {
		return err
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	a.oauth = &oauth2.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  a.cfg.BaseURL + "/callback",
		Scopes:       a.cfg.Scopes,
	}
	a.verifier = provider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID})
	a.revokeURL = extra.RevocationEndpoint
	a.introspect = extra.IntrospectionEndpoint
	a.provider = provider
	return nil
}

func randomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if err := a.setup(r.Context()); err != nil {
		a.fail(w, http.StatusBadGateway, err)
		return
	}
	p := &pendingLogin{state: randomString(), nonce: randomString(), verifier: oauth2.GenerateVerifier(), created: time.Now()}
	id := randomString()
	a.mu.Lock()
	a.pending[id] = p
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: pendingCookie, Value: id, Path: "/", MaxAge: 600,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})

	opts := []oauth2.AuthCodeOption{oidc.Nonce(p.nonce), oauth2.S256ChallengeOption(p.verifier)}
	if prompt := r.URL.Query().Get("prompt"); prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", prompt))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(p.state, opts...), http.StatusFound)
}

func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.setup(ctx); err != nil {
		a.fail(w, http.StatusBadGateway, err)
		return
	}
	c, err := r.Cookie(pendingCookie)
	if err != nil {
		a.fail(w, http.StatusBadRequest, errors.New("no login in progress"))
		return
	}
	a.mu.Lock()
	p := a.pending[c.Value]
	delete(a.pending, c.Value)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: pendingCookie, Path: "/", MaxAge: -1})

	q := r.URL.Query()
	if p == nil || time.Since(p.created) > 10*time.Minute ||
		subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(p.state)) != 1 {
		a.fail(w, http.StatusBadRequest, errors.New("state mismatch"))
		return
	}
	// RFC 9207: reject responses from an unexpected issuer (mix-up attacks).
	if q.Get("iss") != a.cfg.Issuer {
		a.fail(w, http.StatusBadRequest, fmt.Errorf("unexpected issuer %q", q.Get("iss")))
		return
	}
	if e := q.Get("error"); e != "" {
		a.fail(w, http.StatusUnauthorized, fmt.Errorf("authorization failed: %s %s", e, q.Get("error_description")))
		return
	}

	token, err := a.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(p.verifier))
	if err != nil {
		a.fail(w, http.StatusBadGateway, fmt.Errorf("exchange code: %w", err))
		return
	}
	s, err := a.verifyTokens(ctx, token, p.nonce)
	if err != nil {
		a.fail(w, http.StatusBadGateway, err)
		return
	}
	s.Message = "Signed in."

	id := randomString()
	a.mu.Lock()
	a.sessions[id] = s
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// verifyTokens validates the ID token of a token response and loads
// UserInfo. nonce is empty for refreshed tokens.
func (a *App) verifyTokens(ctx context.Context, token *oauth2.Token, nonce string) (*session, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("token response has no id_token")
	}
	idToken, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify ID token: %w", err)
	}
	if nonce != "" && subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("ID token nonce mismatch")
	}
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
			return nil, fmt.Errorf("verify at_hash: %w", err)
		}
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	info, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	if info.Subject != idToken.Subject {
		return nil, errors.New("userinfo subject does not match the ID token")
	}
	var userInfo map[string]any
	if err := info.Claims(&userInfo); err != nil {
		return nil, err
	}
	return &session{Token: token, IDToken: raw, IDClaims: claims, UserInfo: userInfo}, nil
}

func (a *App) currentSession(r *http.Request) (string, *session) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return c.Value, a.sessions[c.Value]
}

func (a *App) refresh(w http.ResponseWriter, r *http.Request) {
	id, s := a.currentSession(r)
	if s == nil || s.Token.RefreshToken == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// A token source with only a refresh token always refreshes.
	token, err := a.oauth.TokenSource(r.Context(), &oauth2.Token{RefreshToken: s.Token.RefreshToken}).Token()
	if err != nil {
		a.fail(w, http.StatusBadGateway, fmt.Errorf("refresh: %w", err))
		return
	}
	next, err := a.verifyTokens(r.Context(), token, "")
	if err != nil {
		a.fail(w, http.StatusBadGateway, err)
		return
	}
	next.Message = "Tokens refreshed; the refresh token was rotated."
	a.mu.Lock()
	a.sessions[id] = next
	a.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// introspectToken asks the provider about the current access token, as a
// resource server would.
func (a *App) introspectToken(w http.ResponseWriter, r *http.Request) {
	_, s := a.currentSession(r)
	if s == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	body, err := a.postClientAuthenticated(r.Context(), a.introspect, url.Values{"token": {s.Token.AccessToken}})
	if err != nil {
		a.fail(w, http.StatusBadGateway, err)
		return
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		a.fail(w, http.StatusBadGateway, err)
		return
	}
	a.mu.Lock()
	s.Introspected = result
	s.Message = "Access token introspected."
	a.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	id, s := a.currentSession(r)
	if s != nil {
		token := s.Token.RefreshToken
		if token == "" {
			token = s.Token.AccessToken
		}
		if _, err := a.postClientAuthenticated(r.Context(), a.revokeURL, url.Values{"token": {token}}); err != nil {
			slog.Warn("revoke token", "error", err)
		}
		a.mu.Lock()
		delete(a.sessions, id)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) postClientAuthenticated(ctx context.Context, endpoint string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.cfg.ClientSecret))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s: %s", endpoint, resp.Status, b)
	}
	return b, nil
}

var homeTemplate = template.Must(template.New("home").Funcs(template.FuncMap{
	"json": func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>grantor example relying party</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 52rem; margin: 2rem auto; padding: 0 1rem; }
  pre { background: color-mix(in srgb, CanvasText 6%, transparent); padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: .85rem; }
  form { display: inline; }
  button, a.button { font: inherit; padding: .5rem 1rem; border-radius: 8px; border: 1px solid #3b5bdb; background: transparent; color: inherit; cursor: pointer; text-decoration: none; }
  .message { padding: .5rem 1rem; border-left: 4px solid #2f9e44; }
</style>
</head>
<body>
<h1>Example relying party</h1>
{{if .Session}}
  {{with .Session.Message}}<p class="message">{{.}}</p>{{end}}
  <p>
    <form method="post" action="/refresh"><button>Refresh tokens</button></form>
    <form method="post" action="/introspect"><button>Introspect access token</button></form>
    <form method="post" action="/logout"><button>Revoke and sign out</button></form>
    <a class="button" href="/login?prompt=login">Sign in again</a>
  </p>
  <h2>ID token claims</h2>
  <pre>{{json .Session.IDClaims}}</pre>
  <h2>UserInfo</h2>
  <pre>{{json .Session.UserInfo}}</pre>
  {{with .Session.Introspected}}<h2>Introspection</h2><pre>{{json .}}</pre>{{end}}
  <h2>Token response</h2>
  <pre>scope:         {{.Session.Token.Extra "scope"}}
expires:       {{.Session.Token.Expiry.Format "2006-01-02 15:04:05 MST"}}
refresh_token: {{if .Session.Token.RefreshToken}}issued{{else}}none{{end}}</pre>
{{else}}
  <p>Signs in with the grantor example provider at <code>{{.Issuer}}</code> using the authorization code flow with PKCE.</p>
  <p><a class="button" href="/login">Sign in</a></p>
{{end}}
</body>
</html>
`))

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	_, s := a.currentSession(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := homeTemplate.Execute(w, map[string]any{"Session": s, "Issuer": a.cfg.Issuer}); err != nil {
		slog.Error("render home", "error", err)
	}
}

func (a *App) fail(w http.ResponseWriter, status int, err error) {
	slog.Error("relying party", "error", err)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "Error: %v\n", err)
}
