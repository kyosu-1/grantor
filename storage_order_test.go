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

// flakyStorage fails the next CreateToken of an access token, or the next
// ConsumeToken, when armed.
type flakyStorage struct {
	grantor.Storage
	failCreate, failConsume atomic.Bool
}

func (s *flakyStorage) CreateToken(ctx context.Context, t *grantor.Token) error {
	if t.Kind == grantor.TokenKindAccessToken && s.failCreate.CompareAndSwap(true, false) {
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
