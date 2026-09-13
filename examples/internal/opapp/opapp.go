// Package opapp is a small OpenID Provider built with grantor. It keeps
// users, sessions and consents in memory and is meant as an example only.
package opapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// Config configures the example provider.
type Config struct {
	// Issuer is the issuer URL, for example http://localhost:9001.
	Issuer string
	// Clients are registered at startup.
	Clients []grantor.Client
	// AutoConsent skips the consent screen, as if the end-user granted every
	// requested scope. The conformance suite harness uses it.
	AutoConsent bool
	Logger      *slog.Logger
}

// User is a demo end-user account.
type User struct {
	Subject      string
	Username     string
	PasswordHash []byte
	Claims       map[string]any
}

// App is the example provider: grantor's protocol endpoints plus login and
// consent pages.
type App struct {
	provider    *grantor.Provider
	autoConsent bool
	users       map[string]*User // by username
	dummyHash   []byte           // compared against for unknown users

	mu       sync.Mutex
	sessions map[string]*session // by session cookie value
}

type session struct {
	subject  string
	authTime time.Time
	consents map[string]consent // by client ID
}

// consent remembers which scopes the end-user was asked about for a client,
// and which of them were granted.
type consent struct {
	asked, granted []string
}

const sessionCookie = "op_session"

// DemoUsers returns the demo accounts. The password of each is "password".
func DemoUsers() []*User {
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return []*User{
		{
			Subject: "248289761001", Username: "alice", PasswordHash: hash,
			Claims: map[string]any{
				"name": "Alice Liddell", "given_name": "Alice", "family_name": "Liddell",
				"middle_name": "Pleasance", "nickname": "Ali", "preferred_username": "alice",
				"profile": "https://alice.example.com", "picture": "https://alice.example.com/photo.jpg",
				"website": "https://alice.example.com", "gender": "female", "birthdate": "1852-05-04",
				"zoneinfo": "Europe/London", "locale": "en-GB", "updated_at": 1757750400,
				"email": "alice@example.com", "email_verified": true,
				"phone_number": "+44 20 7946 0000", "phone_number_verified": true,
				"address": map[string]any{
					"formatted":      "1 Rabbit Hole\nOxford OX1 1DP\nUnited Kingdom",
					"street_address": "1 Rabbit Hole", "locality": "Oxford",
					"postal_code": "OX1 1DP", "country": "United Kingdom",
				},
			},
		},
		{
			Subject: "248289761002", Username: "bob", PasswordHash: hash,
			Claims: map[string]any{
				"name": "Bob Builder", "preferred_username": "bob",
				"email": "bob@example.com", "email_verified": false,
				"phone_number": "+81 90 0000 0000", "phone_number_verified": true,
			},
		},
	}
}

// New creates the example provider.
func New(cfg Config, users []*User) (*App, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	a := &App{users: map[string]*User{}, sessions: map[string]*session{}, autoConsent: cfg.AutoConsent}
	for _, u := range users {
		a.users[u.Username] = u
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte("not a password"), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	a.dummyHash = dummy

	// A real deployment loads a persistent key, ideally from a KMS; this
	// example generates one at startup.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	store := memory.New()
	for _, c := range cfg.Clients {
		store.SetClient(cfg.Issuer, c)
	}

	a.provider, err = grantor.New(grantor.Config{
		Issuer: &grantor.Issuer{
			URL:  cfg.Issuer,
			Keys: []grantor.SigningKey{{ID: "demo-" + time.Now().UTC().Format("20060102"), Signer: key}},
		},
		Clients:   store,
		Storage:   store,
		Interact:  a.interact,
		Claims:    a.claims,
		ErrorPage: a.errorPage,
		Logger:    cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Handler returns the HTTP handler of the provider.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", a.showLogin)
	mux.HandleFunc("POST /login", a.submitLogin)
	mux.HandleFunc("POST /consent", a.submitConsent)
	mux.Handle("/", a.provider)
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func (a *App) claims(_ context.Context, grant *grantor.Token) (map[string]any, error) {
	for _, u := range a.users {
		if u.Subject == grant.Subject {
			return u.Claims, nil
		}
	}
	return nil, fmt.Errorf("unknown subject %q", grant.Subject)
}

// interact decides what an authorization request needs: a login, a consent
// screen, or nothing at all.
func (a *App) interact(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest) {
	a.continueRequest(w, r, req, a.currentSession(r))
}

func (a *App) continueRequest(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest, s *session) {
	loginNeeded := s == nil || req.NeedsAuthentication(s.authTime) ||
		(req.IDTokenHintSubject != "" && req.IDTokenHintSubject != s.subject) ||
		// This example has no account chooser; it shows the login form once.
		(req.HasPrompt("select_account") && s.authTime.Before(req.CreatedAt))
	if loginNeeded {
		if req.HasPrompt("none") {
			a.deny(w, r, req.ID, grantor.ErrLoginRequired)
			return
		}
		http.Redirect(w, r, "/login?id="+url.QueryEscape(req.ID), http.StatusFound)
		return
	}

	if a.autoConsent {
		a.approve(w, r, req, s, req.Scopes)
		return
	}
	a.mu.Lock()
	previous, ok := s.consents[req.ClientID]
	a.mu.Unlock()
	decided := ok && containsAll(previous.asked, req.Scopes)
	if !decided || req.HasPrompt("consent") {
		if req.HasPrompt("none") {
			a.deny(w, r, req.ID, grantor.ErrConsentRequired)
			return
		}
		a.render(w, "consent.html", map[string]any{"Request": req})
		return
	}
	a.approve(w, r, req, s, previous.granted)
}

func containsAll(set, values []string) bool {
	for _, v := range values {
		if !slices.Contains(set, v) {
			return false
		}
	}
	return true
}

func (a *App) showLogin(w http.ResponseWriter, r *http.Request) {
	req, err := a.provider.AuthorizationRequest(r, r.URL.Query().Get("id"))
	if err != nil {
		a.renderError(w, err)
		return
	}
	a.render(w, "login.html", map[string]any{"Request": req, "LoginHint": req.LoginHint})
}

func (a *App) submitLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	// Check the authorization request first: it is bound to this browser,
	// which also protects the login form against cross-site request forgery.
	req, err := a.provider.AuthorizationRequest(r, r.PostFormValue("id"))
	if err != nil {
		a.renderError(w, err)
		return
	}
	if r.PostFormValue("action") == "cancel" {
		a.deny(w, r, req.ID, grantor.ErrAccessDenied)
		return
	}

	// Compare against a dummy hash for unknown users, so that response times
	// do not reveal which usernames exist.
	user := a.users[r.PostFormValue("username")]
	hash := a.dummyHash
	if user != nil {
		hash = user.PasswordHash
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(r.PostFormValue("password"))) != nil || user == nil {
		a.renderStatus(w, http.StatusUnauthorized, "login.html", map[string]any{
			"Request": req, "Error": "Invalid username or password.", "LoginHint": r.PostFormValue("username"),
		})
		return
	}

	s := a.startSession(w, r, user.Subject)
	a.continueRequest(w, r, req, s)
}

func (a *App) submitConsent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	req, err := a.provider.AuthorizationRequest(r, r.PostFormValue("id"))
	if err != nil {
		a.renderError(w, err)
		return
	}
	s := a.currentSession(r)
	if s == nil {
		http.Redirect(w, r, "/login?id="+url.QueryEscape(req.ID), http.StatusSeeOther)
		return
	}
	if r.PostFormValue("action") != "allow" {
		a.deny(w, r, req.ID, grantor.ErrAccessDenied)
		return
	}
	var granted []string
	for _, scope := range req.Scopes {
		// openid is required for OpenID Connect; other scopes can be declined.
		if scope == "openid" || r.PostForm.Has("scope_"+scope) {
			granted = append(granted, scope)
		}
	}
	a.mu.Lock()
	s.consents[req.ClientID] = consent{asked: req.Scopes, granted: granted}
	a.mu.Unlock()
	a.approve(w, r, req, s, granted)
}

func (a *App) approve(w http.ResponseWriter, r *http.Request, req *grantor.AuthorizationRequest, s *session, granted []string) {
	var scopes []string
	for _, scope := range req.Scopes {
		if slices.Contains(granted, scope) {
			scopes = append(scopes, scope)
		}
	}
	// Password login is the only method here; report it as assurance level
	// 1 when the client asks for that level.
	var acr string
	if slices.Contains(req.ACRValues, "1") {
		acr = "1"
	}
	err := a.provider.Approve(w, r, req.ID, grantor.Approval{
		Subject:  s.subject,
		Scopes:   scopes,
		AuthTime: s.authTime,
		ACR:      acr,
		AMR:      []string{"pwd"},
	})
	if err != nil {
		a.renderError(w, err)
	}
}

func (a *App) deny(w http.ResponseWriter, r *http.Request, id string, reason *grantor.Error) {
	if err := a.provider.Deny(w, r, id, reason); err != nil {
		a.renderError(w, err)
	}
}

func (a *App) startSession(w http.ResponseWriter, r *http.Request, subject string) *session {
	b := make([]byte, 32)
	rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)

	s := &session{subject: subject, authTime: time.Now(), consents: map[string]consent{}}
	a.mu.Lock()
	// Keep consents when the same user logs in again.
	if old := a.sessionLocked(r); old != nil && old.subject == subject {
		s.consents = old.consents
	}
	a.sessions[id] = s
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	return s
}

func (a *App) currentSession(r *http.Request) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionLocked(r)
}

func (a *App) sessionLocked(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	return a.sessions[c.Value]
}

func (a *App) render(w http.ResponseWriter, name string, data map[string]any) {
	a.renderStatus(w, http.StatusOK, name, data)
}

func (a *App) renderStatus(w http.ResponseWriter, status int, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render template", "template", name, "error", err)
	}
}

// errorPage renders authorization errors that cannot be sent to the client,
// such as an unregistered redirect URI.
func (a *App) errorPage(w http.ResponseWriter, _ *http.Request, err *grantor.Error) {
	a.renderStatus(w, http.StatusBadRequest, "error.html", map[string]any{
		"Message": "The sign-in request is invalid: " + err.Code + ". " + err.Description,
	})
}

func (a *App) renderError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	msg := "Something went wrong."
	if errors.Is(err, grantor.ErrAuthorizationRequestNotFound) {
		status = http.StatusBadRequest
		msg = "This sign-in request has expired or was already completed. Return to the application and try again."
	} else {
		slog.Error("authorization", "error", err)
	}
	a.renderStatus(w, status, "error.html", map[string]any{"Message": msg})
}
