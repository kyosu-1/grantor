package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func startServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + l.Addr().String()
	h, err := newServer(issuer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return issuer
}

func postForm(t *testing.T, client *http.Client, u string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := client.Post(u, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func TestLowLevelServer(t *testing.T) {
	issuer := startServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	var meta map[string]any
	resp, err := client.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&meta)
	resp.Body.Close()
	if meta["token_endpoint"] != issuer+"/oauth2/token" {
		t.Fatalf("discovery = %v", meta)
	}

	authorize := func(loginHint string) url.Values {
		t.Helper()
		verifier := oauth2.GenerateVerifier()
		q := url.Values{
			"response_type": {"code"}, "client_id": {"cli"}, "redirect_uri": {"http://127.0.0.1/callback"},
			"scope": {"openid api"}, "state": {"s"}, "code_challenge": {oauth2.S256ChallengeFromVerifier(verifier)},
			"code_challenge_method": {"S256"}, "login_hint": {loginHint},
		}
		resp, err := client.Get(issuer + "/oauth2/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		v := loc.Query()
		v.Set("code_verifier", verifier)
		return v
	}

	result := authorize("alice")
	if result.Get("code") == "" {
		t.Fatalf("authorize = %v", result)
	}
	status, tok := postForm(t, client, issuer+"/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {result.Get("code")},
		"client_id": {"cli"}, "code_verifier": {result.Get("code_verifier")},
	})
	if status != http.StatusOK || tok["scope"] != "openid api" || tok["id_token"] == nil {
		t.Fatalf("token = %d %v", status, tok)
	}
	parts := strings.Split(tok["access_token"].(string), ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT: %v", tok["access_token"])
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != "https://api.example.com" || claims["tenant"] != "example" || claims["sub"] != "alice" {
		t.Fatalf("access token claims = %v", claims)
	}

	if result := authorize("mallory"); result.Get("error") != "access_denied" {
		t.Fatalf("disabled user = %v", result)
	}

	status, apiKey := postForm(t, client, issuer+"/oauth2/token", url.Values{
		"grant_type": {"urn:example:params:oauth:grant-type:api-key"}, "client_id": {"cli"}, "api_key": {"demo-api-key"},
	})
	if status != http.StatusOK || apiKey["scope"] != "api" {
		t.Fatalf("API key grant = %d %v", status, apiKey)
	}
	status, bad := postForm(t, client, issuer+"/oauth2/token", url.Values{
		"grant_type": {"urn:example:params:oauth:grant-type:api-key"}, "client_id": {"cli"}, "api_key": {"wrong"},
	})
	if status != http.StatusBadRequest || bad["error"] != "invalid_grant" {
		t.Fatalf("wrong API key = %d %v", status, bad)
	}
}
