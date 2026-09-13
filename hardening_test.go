package grantor_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
)

func TestClaimsParameterCannotWidenAccess(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	const narrowClient = "narrow-app"
	e.store.SetClient(testIssuer, grantor.Client{
		ID:           narrowClient,
		SecretHash:   grantor.HashClientSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect},
		Scopes:       []string{"openid", "profile"},
		PKCE:         grantor.PKCEOptional,
	})
	requested := `{"userinfo":{"name":null,"email":null,"phone_number":null,"department":null,"internal_role":null},"id_token":{"email":null}}`

	exchange := func(clientID string, approve func(*grantor.AuthorizationRequest) grantor.Approval) map[string]any {
		t.Helper()
		q := authParams(clientID, "openid", pkcePair{})
		q.Set("claims", requested)
		req := e.startAuthorization(q)
		rec, err := e.approve(req, approve(req))
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		status, body := e.exchangeCode(clientID, redirectParams(t, rec).Get("code"), "", basic(clientID, confidentialSecret))
		if status != http.StatusOK {
			t.Fatalf("exchange = %d %v", status, body)
		}
		return body
	}

	// Only claims covered by a scope the client is registered for can be
	// requested individually.
	e.claims["alice"]["internal_role"] = "admin"
	var names []string
	body := exchange(narrowClient, func(req *grantor.AuthorizationRequest) grantor.Approval {
		names = req.Claims.Names()
		return grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Claims: names}
	})
	if len(names) != 1 || names[0] != "name" {
		t.Fatalf("Claims.Names() for a client registered for profile = %v, want [name]", names)
	}
	info := e.userInfo(body["access_token"].(string))
	for _, c := range []string{"email", "phone_number", "department", "internal_role"} {
		if _, ok := info[c]; ok {
			t.Errorf("userinfo released %s to a client that may not receive it: %v", c, info)
		}
	}
	if info["name"] != "Alice Example" {
		t.Errorf("approved claim missing: %v", info)
	}

	// Claims the end-user did not approve are not released.
	body = exchange(confidentialClient, func(req *grantor.AuthorizationRequest) grantor.Approval {
		return grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}
	})
	if info := e.userInfo(body["access_token"].(string)); len(info) != 1 {
		t.Fatalf("userinfo released unapproved claims: %v", info)
	}
	if claims := e.verifyJWT(body["id_token"].(string)); claims["email"] != nil {
		t.Fatalf("ID token released an unapproved claim: %v", claims)
	}

	// Approving a claim that was not requested is an error.
	q := authParams(confidentialClient, "openid", pkcePair{})
	req := e.startAuthorization(q)
	if _, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now(), Claims: []string{"email"}}); err == nil {
		t.Fatal("Approve accepted a claim that was not requested")
	}
}

func TestRequestedSubjectClaim(t *testing.T) {
	e := newEnv(t)
	e.registerClients()

	q := authParams(confidentialClient, "openid", pkcePair{})
	q.Set("claims", `{"id_token":{"sub":{"value":"bob"}}}`)
	req := e.startAuthorization(q)
	if req.RequestedSubject != "bob" {
		t.Fatalf("RequestedSubject = %q", req.RequestedSubject)
	}
	if _, err := e.approve(req, grantor.Approval{Subject: "alice", Scopes: req.Scopes, AuthTime: e.clock.Now()}); err == nil {
		t.Fatal("Approve accepted an end-user other than the requested sub")
	}

	hint := e.tokensFor(confidentialClient, "openid")["id_token"].(string)
	q = authParams(confidentialClient, "openid", pkcePair{})
	q.Set("id_token_hint", hint)
	q.Set("claims", `{"id_token":{"sub":{"value":"bob"}}}`)
	if p := redirectParams(t, e.get(grantor.PathAuthorization, q)); p.Get("error") != "invalid_request" {
		t.Fatalf("sub conflicting with id_token_hint = %v", p)
	}
}

func TestUnregisteredScopesAreIgnored(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	req := e.startAuthorization(authParams(publicClient, "openid admin profile", newPKCE()))
	if strings.Join(req.Scopes, " ") != "openid profile" {
		t.Fatalf("Scopes = %v", req.Scopes)
	}
}

func TestFormPostToCustomSchemeFallsBackToQuery(t *testing.T) {
	e := newEnv(t)
	e.store.SetClient(testIssuer, grantor.Client{
		ID:           "native-app",
		RedirectURIs: []string{"com.example.app:/cb"},
		Scopes:       []string{"openid"},
	})
	q := url.Values{
		"response_type": {"code"}, "client_id": {"native-app"}, "redirect_uri": {"com.example.app:/cb"},
		"scope": {"openid"}, "state": {"s"}, "response_mode": {"form_post"},
		"code_challenge": {newPKCE().challenge}, "code_challenge_method": {"S256"},
	}
	rec := e.get(grantor.PathAuthorization, q)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, "com.example.app:/cb?") || !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("form_post to custom scheme = %d Location=%q body=%s", rec.Code, loc, rec.Body.String())
	}
}

func TestExpiredCodeReuseRevokesGrant(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	auth := basic(confidentialClient, confidentialSecret)
	code := e.login(authParams(confidentialClient, "openid", pkcePair{}), nil)
	status, body := e.exchangeCode(confidentialClient, code, "", auth)
	if status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, body)
	}
	e.clock.Advance(2 * time.Minute)
	status, second := e.exchangeCode(confidentialClient, code, "", auth)
	expectError(t, status, second, http.StatusBadRequest, "invalid_grant")
	if info := e.introspect(body["access_token"].(string), confidentialClient); info["active"] != false {
		t.Fatalf("access token still active after replaying an expired code: %v", info)
	}
}

func TestCodeExchangeRechecksClientScopes(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	code := e.login(authParams(confidentialClient, "openid email", pkcePair{}), nil)
	e.store.SetClient(testIssuer, grantor.Client{
		ID:           confidentialClient,
		SecretHash:   grantor.HashClientSecret(confidentialSecret),
		RedirectURIs: []string{clientRedirect},
		Scopes:       []string{"openid"},
		PKCE:         grantor.PKCEOptional,
	})
	status, body := e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusBadRequest, "invalid_scope")
}

func TestUserInfoOtherAuthorizationScheme(t *testing.T) {
	e := newEnv(t)
	req := httpGet(testIssuer + grantor.PathUserInfo)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := e.do(req)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer realm="userinfo"` {
		t.Fatalf("Basic authorization = %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestUserInfoCORS(t *testing.T) {
	e := newEnv(t)
	req := httpGet(testIssuer + grantor.PathUserInfo)
	req.Method = http.MethodOptions
	req.Header.Set("Origin", "https://spa.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := e.do(req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "*" ||
		!strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight = %d %v", rec.Code, rec.Header())
	}
}

func TestClientAssertionAudience(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	exp := e.clock.Now().Add(time.Minute)
	send := func(assertion string) (int, map[string]any) {
		return e.tokenRequest(url.Values{
			"grant_type":            {"client_credentials"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
		}, nil)
	}

	status, body := send(clientAssertion(t, testIssuer+grantor.PathIntrospection, exp, "aud-1", clientEC, "ES256"))
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client")

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: clientEC},
		(&jose.SignerOptions{}).WithHeader("kid", "client-key"))
	if err != nil {
		t.Fatal(err)
	}
	multi, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: jwtClient, Subject: jwtClient, ID: "aud-2", Expiry: jwt.NewNumericDate(exp),
		Audience: jwt.Audience{testIssuer, "https://other-server.example.com"},
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	status, body = send(multi)
	expectError(t, status, body, http.StatusUnauthorized, "invalid_client")
}

func TestBindingCookieUsesHostPrefix(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	rec := e.get(grantor.PathAuthorization, authParams(publicClient, "openid", newPKCE()))
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0].Name, "__Host-grantor_") || !cookies[0].Secure || cookies[0].Path != "/" {
		t.Fatalf("binding cookie = %+v", cookies)
	}
}

type nilClientStore struct{}

func (nilClientStore) Client(context.Context, string, string) (*grantor.Client, error) {
	return nil, nil
}

func TestClientStoreReturningNil(t *testing.T) {
	e := newEnv(t, func(c *grantor.Config) { c.Clients = nilClientStore{} })
	rec := e.get(grantor.PathAuthorization, authParams(publicClient, "openid", newPKCE()))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil client = %d %s", rec.Code, rec.Body.String())
	}
}

func TestIssuerRequiresRS256Key(t *testing.T) {
	testKeys(t)
	store := memory.New()
	_, err := grantor.New(grantor.Config{
		Issuer:   &grantor.Issuer{URL: testIssuer, Keys: []grantor.SigningKey{{ID: "ec", Signer: ecKey}}},
		Clients:  store,
		Storage:  store,
		Interact: func(http.ResponseWriter, *http.Request, *grantor.AuthorizationRequest) {},
	})
	if err == nil || errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("New with only an EC key = %v, want an error", err)
	}
}

func TestRejectedRequestObjectUsesItsResponseMode(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"response_mode":"form_post","state":"from-object"}`))
	q := url.Values{
		"response_type": {"code"}, "client_id": {confidentialClient}, "redirect_uri": {clientRedirect},
		"scope": {"openid"}, "request": {"eyJhbGciOiJub25lIn0." + payload + "."},
	}
	rec := e.get(grantor.PathAuthorization, q)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `value="request_not_supported"`) || !strings.Contains(body, `value="from-object"`) {
		t.Fatalf("rejected request object = %d %s", rec.Code, body)
	}
}
