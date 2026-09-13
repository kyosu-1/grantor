package grantor_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

// Only requests for unknown issuers get 404; failures to resolve an issuer
// are operational problems and must not look like unknown tenants.
func TestIssuerForErrors(t *testing.T) {
	testKeys(t)
	var logs bytes.Buffer
	store := memory.New()
	p, err := grantor.New(grantor.Config{
		IssuerFor: func(r *http.Request) (*grantor.Issuer, error) {
			switch r.Host {
			case "ok.example.com":
				return &grantor.Issuer{URL: "https://ok.example.com", Keys: []grantor.SigningKey{{ID: "k", Signer: rsaKey}}}, nil
			case "nokeys.example.com":
				return &grantor.Issuer{URL: "https://nokeys.example.com"}, nil
			case "nil.example.com":
				return nil, nil
			case "down.example.com":
				return nil, errors.New("tenant database unavailable")
			default:
				return nil, fmt.Errorf("host %q: %w", r.Host, grantor.ErrNotFound)
			}
		},
		Clients: store,
		Storage: store,
		Logger:  slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]int{
		"ok.example.com":      http.StatusOK,
		"unknown.example.com": http.StatusNotFound,
		"down.example.com":    http.StatusInternalServerError,
		"nokeys.example.com":  http.StatusInternalServerError,
		"nil.example.com":     http.StatusInternalServerError,
	} {
		logs.Reset()
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+host+grantor.PathOpenIDConfiguration, nil))
		if rec.Code != want {
			t.Errorf("%s: discovery = %d, want %d", host, rec.Code, want)
		}
		if logged := strings.Contains(logs.String(), "level=ERROR"); logged != (want == http.StatusInternalServerError) {
			t.Errorf("%s: logged at error level = %v:\n%s", host, logged, logs.String())
		}
		if host == "ok.example.com" {
			continue
		}

		r := httptest.NewRequest(http.MethodPost, "https://"+host+grantor.PathToken, strings.NewReader("grant_type=client_credentials"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, err := p.ParseTokenRequest(r)
		var perr *grantor.Error
		if !errors.As(err, &perr) || perr.HTTPStatus() != want {
			t.Errorf("%s: ParseTokenRequest = %v, want an *Error with status %d", host, err, want)
		}

		rec = httptest.NewRecorder()
		p.ServeToken(rec, httptest.NewRequest(http.MethodPost, "https://"+host+grantor.PathToken, strings.NewReader("grant_type=client_credentials")))
		if rec.Code != want || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: token endpoint = %d %q, want %d with a JSON error", host, rec.Code, rec.Header().Get("Content-Type"), want)
		}

		// The authorization-side building blocks classify issuer errors the
		// same way, so WriteAuthorizationError picks the right status.
		_, err = p.AuthorizationRequest(httptest.NewRequest(http.MethodGet, "https://"+host+"/login", nil), "id")
		rec = httptest.NewRecorder()
		p.WriteAuthorizationError(rec, httptest.NewRequest(http.MethodGet, "https://"+host+"/login", nil), err)
		if rec.Code != want {
			t.Errorf("%s: WriteAuthorizationError(AuthorizationRequest error) = %d, want %d", host, rec.Code, want)
		}

		_, err = p.ValidateAccessToken(httptest.NewRequest(http.MethodGet, "https://"+host+"/api", nil), "token")
		if errors.Is(err, grantor.ErrNotFound) != (want == http.StatusNotFound) {
			t.Errorf("%s: ValidateAccessToken = %v", host, err)
		}
	}
}
