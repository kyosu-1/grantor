// Package e2e runs the example provider and relying party on real listeners
// and drives them like a browser would.
package e2e

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/grantor/examples/internal/demo"
	"github.com/kyosu-1/grantor/examples/internal/opapp"
	"github.com/kyosu-1/grantor/examples/internal/rpapp"
)

func serve(t *testing.T, h func(baseURL string) http.Handler) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + l.Addr().String()
	srv := &http.Server{Handler: h(baseURL)}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return baseURL
}

type browser struct {
	t      *testing.T
	client *http.Client
}

func (b *browser) do(method, u string, form url.Values) (*http.Response, string) {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(resp.Body)
	return resp, string(text)
}

func TestExampleApps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// The provider must know the relying party's URL and vice versa, so
	// reserve the relying party's listener first.
	rpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rpURL := "http://" + rpListener.Addr().String()

	opURL := serve(t, func(issuer string) http.Handler {
		app, err := opapp.New(opapp.Config{Issuer: issuer, Clients: demo.Clients(rpURL), Logger: logger}, opapp.DemoUsers())
		if err != nil {
			t.Fatal(err)
		}
		return app.Handler()
	})
	rp := rpapp.New(rpapp.Config{
		Issuer: opURL, ClientID: demo.ClientID, ClientSecret: demo.ClientSecret,
		BaseURL: rpURL, Scopes: []string{"openid", "profile", "email", "offline_access"},
	})
	rpServer := &http.Server{Handler: rp.Handler()}
	go rpServer.Serve(rpListener)
	t.Cleanup(func() { rpServer.Close() })

	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, client: &http.Client{Jar: jar}}

	// Start signing in at the relying party; the provider shows its login page.
	resp, page := b.do(http.MethodGet, rpURL+"/login", nil)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/login" || !strings.Contains(page, "Sign in") {
		t.Fatalf("expected the login page, got %d %s\n%s", resp.StatusCode, resp.Request.URL, page)
	}
	requestID := resp.Request.URL.Query().Get("id")

	resp, page = b.do(http.MethodPost, opURL+"/login", url.Values{
		"id": {requestID}, "username": {"alice"}, "password": {"wrong"}, "action": {"login"},
	})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(page, "Invalid username or password") {
		t.Fatalf("wrong password: %d\n%s", resp.StatusCode, page)
	}

	resp, page = b.do(http.MethodPost, opURL+"/login", url.Values{
		"id": {requestID}, "username": {"alice"}, "password": {"password"}, "action": {"login"},
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Authorize access") {
		t.Fatalf("expected the consent page, got %d\n%s", resp.StatusCode, page)
	}

	// Allow everything except email.
	resp, page = b.do(http.MethodPost, opURL+"/consent", url.Values{
		"id": {requestID}, "action": {"allow"}, "scope_profile": {"on"}, "scope_offline_access": {"on"},
	})
	if resp.StatusCode != http.StatusOK || resp.Request.URL.String() != rpURL+"/" {
		t.Fatalf("expected the relying party home page, got %d %s\n%s", resp.StatusCode, resp.Request.URL, page)
	}
	for _, want := range []string{"Signed in.", `&#34;sub&#34;: &#34;248289761001&#34;`, "Alice Liddell", "refresh_token: issued"} {
		if !strings.Contains(page, want) {
			t.Fatalf("home page is missing %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "alice@example.com") {
		t.Fatalf("declined email claim was released:\n%s", page)
	}

	resp, page = b.do(http.MethodPost, rpURL+"/refresh", url.Values{})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "refresh token was rotated") {
		t.Fatalf("refresh: %d\n%s", resp.StatusCode, page)
	}

	resp, page = b.do(http.MethodPost, rpURL+"/introspect", url.Values{})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `&#34;active&#34;: true`) {
		t.Fatalf("introspect: %d\n%s", resp.StatusCode, page)
	}

	// With a session and remembered consent, signing in again needs no
	// interaction.
	resp, page = b.do(http.MethodGet, rpURL+"/login", nil)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.String() != rpURL+"/" || !strings.Contains(page, "Signed in.") {
		t.Fatalf("single sign-on: %d %s\n%s", resp.StatusCode, resp.Request.URL, page)
	}

	// prompt=login forces the login page even with a session. Authentication
	// times have one-second precision, so move past the second in which
	// alice signed in.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	resp, page = b.do(http.MethodGet, rpURL+"/login?prompt=login", nil)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/login" || !strings.Contains(page, "Sign in") {
		t.Fatalf("prompt=login: %d %s", resp.StatusCode, resp.Request.URL)
	}

	resp, page = b.do(http.MethodPost, rpURL+"/logout", url.Values{})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `href="/login"`) {
		t.Fatalf("logout: %d\n%s", resp.StatusCode, page)
	}
}
