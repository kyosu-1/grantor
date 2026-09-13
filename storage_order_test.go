package grantor_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kyosu-1/grantor"
)

// flakyStorage fails the next CreateToken of an access token (or of a
// refresh token when failRefresh is set), or the next ConsumeToken, when
// armed.
type flakyStorage struct {
	grantor.Storage
	failCreate, failConsume, failRefresh atomic.Bool
}

func (s *flakyStorage) CreateToken(ctx context.Context, t *grantor.Token) error {
	kind := grantor.TokenKindAccessToken
	if s.failRefresh.Load() {
		kind = grantor.TokenKindRefreshToken
	}
	if t.Kind == kind && s.failCreate.CompareAndSwap(true, false) {
		return errors.New("database unavailable")
	}
	return s.Storage.CreateToken(ctx, t)
}

func (s *flakyStorage) ConsumeToken(ctx context.Context, hash string, now time.Time) (*grantor.Token, error) {
	if s.failConsume.CompareAndSwap(true, false) {
		return nil, errors.New("database unavailable")
	}
	return s.Storage.ConsumeToken(ctx, hash, now)
}

// recordingStorage records every created token.
type recordingStorage struct {
	grantor.Storage
	mu      sync.Mutex
	created []*grantor.Token
}

func (s *recordingStorage) CreateToken(ctx context.Context, t *grantor.Token) error {
	s.mu.Lock()
	s.created = append(s.created, t)
	s.mu.Unlock()
	return s.Storage.CreateToken(ctx, t)
}

// A storage failure while storing new tokens must not consume the
// authorization code or refresh token, or the client's retry would revoke
// the grant.
func TestStorageFailureKeepsGrant(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	flaky := &flakyStorage{Storage: e.store}
	e.p = mustProvider(t, e, func(c *grantor.Config) { c.Storage = flaky })
	auth := basic(confidentialClient, confidentialSecret)

	code := e.login(authParams(confidentialClient, "openid offline_access", pkcePair{}), nil)
	flaky.failCreate.Store(true)
	status, body := e.exchangeCode(confidentialClient, code, "", auth)
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
	status, body = e.exchangeCode(confidentialClient, code, "", auth)
	if status != http.StatusOK {
		t.Fatalf("retried code exchange = %d %v", status, body)
	}

	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}
	flaky.failCreate.Store(true)
	status, failed := e.tokenRequest(refresh, auth)
	expectError(t, status, failed, http.StatusInternalServerError, "server_error")
	status, refreshed := e.tokenRequest(refresh, auth)
	if status != http.StatusOK {
		t.Fatalf("retried refresh = %d %v", status, refreshed)
	}
}

// Tokens stored before a failed consume are revoked, so they cannot be used
// even if they leaked.
func TestFailedConsumeRevokesStoredTokens(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	flaky := &flakyStorage{Storage: e.store}
	recording := &recordingStorage{Storage: flaky}
	e.p = mustProvider(t, e, func(c *grantor.Config) { c.Storage = recording })

	code := e.login(authParams(confidentialClient, "openid offline_access", pkcePair{}), nil)
	flaky.failConsume.Store(true)
	status, body := e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")

	minted := 0
	for _, tok := range recording.created {
		if tok.Kind == grantor.TokenKindAuthorizationCode {
			continue
		}
		minted++
		if _, err := e.store.Token(context.Background(), tok.Hash); !errors.Is(err, grantor.ErrNotFound) {
			t.Errorf("%s stored before the failed consume is still active: %v", tok.Kind, err)
		}
	}
	if minted != 2 {
		t.Fatalf("stored %d tokens before the consume, want an access and a refresh token", minted)
	}
}

// When only some of the new tokens could be stored, the stored ones are
// revoked: they are never returned.
func TestPartialStoreRevokesStoredTokens(t *testing.T) {
	e := newEnv(t)
	e.registerClients()
	flaky := &flakyStorage{Storage: e.store}
	recording := &recordingStorage{Storage: flaky}
	e.p = mustProvider(t, e, func(c *grantor.Config) { c.Storage = recording })

	code := e.login(authParams(confidentialClient, "openid offline_access", pkcePair{}), nil)
	flaky.failRefresh.Store(true)
	flaky.failCreate.Store(true)
	status, body := e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	expectError(t, status, body, http.StatusInternalServerError, "server_error")
	accessTokens := 0
	for _, tok := range recording.created {
		if tok.Kind != grantor.TokenKindAccessToken {
			continue
		}
		accessTokens++
		if _, err := e.store.Token(context.Background(), tok.Hash); !errors.Is(err, grantor.ErrNotFound) {
			t.Errorf("access token stored before the refresh token failed is still active: %v", err)
		}
	}
	if accessTokens != 1 {
		t.Fatalf("stored %d access tokens, want 1", accessTokens)
	}
	status, body = e.exchangeCode(confidentialClient, code, "", basic(confidentialClient, confidentialSecret))
	if status != http.StatusOK {
		t.Fatalf("retried code exchange = %d %v", status, body)
	}
}

// Concurrent refreshes with the same refresh token: at most one succeeds,
// and when reuse is detected the tokens of the winner are revoked too.
func TestConcurrentRefresh(t *testing.T) {
	for range 20 {
		e := newEnv(t)
		e.registerClients()
		auth := basic(confidentialClient, confidentialSecret)
		code := e.login(authParams(confidentialClient, "openid offline_access", pkcePair{}), nil)
		_, body := e.exchangeCode(confidentialClient, code, "", auth)
		refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var winners []map[string]any
		rejected := 0
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				status, body := e.tokenRequest(refresh, auth)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case status == http.StatusOK:
					winners = append(winners, body)
				case body["error"] == "invalid_grant":
					rejected++
				default:
					t.Errorf("refresh = %d %v", status, body)
				}
			}()
		}
		wg.Wait()
		if len(winners) > 1 {
			t.Fatalf("%d concurrent refreshes succeeded", len(winners))
		}
		if len(winners) == 1 && rejected > 0 {
			for _, name := range []string{"access_token", "refresh_token"} {
				if info := e.introspect(winners[0][name].(string), confidentialClient); info["active"] != false {
					t.Fatalf("%s of the winner is active after reuse was detected", name)
				}
			}
		}
	}
}

// revokingStorage revokes the grant of a refresh just before its tokens are
// stored or its refresh token is consumed, as a concurrent revocation would.
type revokingStorage struct {
	grantor.Storage
	beforeCreate, beforeConsume atomic.Bool
}

func (s *revokingStorage) CreateToken(ctx context.Context, t *grantor.Token) error {
	if t.Kind != grantor.TokenKindAuthorizationCode && s.beforeCreate.CompareAndSwap(true, false) {
		s.Storage.RevokeGrant(ctx, t.GrantID)
	}
	return s.Storage.CreateToken(ctx, t)
}

func (s *revokingStorage) ConsumeToken(ctx context.Context, hash string, now time.Time) (*grantor.Token, error) {
	if s.beforeConsume.CompareAndSwap(true, false) {
		if t, err := s.Storage.Token(ctx, hash); err == nil {
			s.Storage.RevokeGrant(ctx, t.GrantID)
		}
	}
	return s.Storage.ConsumeToken(ctx, hash, now)
}

// A revocation that races a refresh wins: the refresh fails and nothing it
// stored stays active, although RevokeGrant only covers existing tokens.
func TestRevocationRacingRefresh(t *testing.T) {
	for _, when := range []string{"before store", "before consume"} {
		t.Run(when, func(t *testing.T) {
			e := newEnv(t)
			e.registerClients()
			revoking := &revokingStorage{Storage: e.store}
			recording := &recordingStorage{Storage: revoking}
			e.p = mustProvider(t, e, func(c *grantor.Config) { c.Storage = recording })
			auth := basic(confidentialClient, confidentialSecret)
			code := e.login(authParams(confidentialClient, "openid offline_access", pkcePair{}), nil)
			_, body := e.exchangeCode(confidentialClient, code, "", auth)
			recording.created = nil

			if when == "before store" {
				revoking.beforeCreate.Store(true)
			} else {
				revoking.beforeConsume.Store(true)
			}
			status, refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}, auth)
			if status == http.StatusOK {
				t.Fatalf("refresh after revocation = %d %v", status, refreshed)
			}
			for _, tok := range recording.created {
				if _, err := e.store.Token(context.Background(), tok.Hash); !errors.Is(err, grantor.ErrNotFound) {
					t.Errorf("%s stored during the revoked refresh is still active", tok.Kind)
				}
			}
		})
	}
}
