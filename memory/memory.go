// Package memory provides an in-memory implementation of grantor.Storage and
// grantor.ClientStore, for tests, examples and development.
//
// Data is lost when the process exits and is not shared between processes.
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/kyosu-1/grantor"
)

// Store is an in-memory grantor.Storage and grantor.ClientStore. The zero
// value is not usable; call [New].
type Store struct {
	mu             sync.Mutex
	clients        map[clientKey]*grantor.Client
	requests       map[string]*grantor.AuthorizationRequest
	tokens         map[string]*grantor.Token
	claims         map[string]time.Time
	now            func() time.Time
	lastCollection time.Time
}

type clientKey struct{ issuer, id string }

var (
	_ grantor.Storage     = (*Store)(nil)
	_ grantor.ClientStore = (*Store)(nil)
)

// New returns an empty Store.
func New() *Store {
	return &Store{
		clients:  map[clientKey]*grantor.Client{},
		requests: map[string]*grantor.AuthorizationRequest{},
		tokens:   map[string]*grantor.Token{},
		claims:   map[string]time.Time{},
		now:      time.Now,
	}
}

// SetClient registers or replaces a client of issuer.
func (s *Store) SetClient(issuer string, c grantor.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[clientKey{issuer, c.ID}] = clone(&c)
}

// Client implements grantor.ClientStore.
func (s *Store) Client(_ context.Context, issuer, clientID string) (*grantor.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientKey{issuer, clientID}]
	if !ok {
		return nil, grantor.ErrNotFound
	}
	return clone(c), nil
}

// CreateAuthorizationRequest implements grantor.Storage.
func (s *Store) CreateAuthorizationRequest(_ context.Context, req *grantor.AuthorizationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collectLocked()
	if _, ok := s.requests[req.ID]; ok {
		return grantor.ErrConflict
	}
	s.requests[req.ID] = clone(req)
	return nil
}

// AuthorizationRequest implements grantor.Storage.
func (s *Store) AuthorizationRequest(_ context.Context, id string) (*grantor.AuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[id]
	if !ok {
		return nil, grantor.ErrNotFound
	}
	return clone(req), nil
}

// DeleteAuthorizationRequest implements grantor.Storage.
func (s *Store) DeleteAuthorizationRequest(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.requests[id]; !ok {
		return grantor.ErrNotFound
	}
	delete(s.requests, id)
	return nil
}

// CreateToken implements grantor.Storage.
func (s *Store) CreateToken(_ context.Context, t *grantor.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collectLocked()
	if _, ok := s.tokens[t.Hash]; ok {
		return grantor.ErrConflict
	}
	s.tokens[t.Hash] = clone(t)
	return nil
}

// Token implements grantor.Storage.
func (s *Store) Token(_ context.Context, hash string) (*grantor.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tokenLocked(hash)
	if err != nil {
		return nil, err
	}
	return clone(t), nil
}

// ConsumeToken implements grantor.Storage.
func (s *Store) ConsumeToken(_ context.Context, hash string, now time.Time) (*grantor.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tokenLocked(hash)
	if err != nil {
		return nil, err
	}
	before := clone(t)
	if t.ConsumedAt.IsZero() {
		t.ConsumedAt = now
	}
	return before, nil
}

func (s *Store) tokenLocked(hash string) (*grantor.Token, error) {
	t, ok := s.tokens[hash]
	if !ok {
		return nil, grantor.ErrNotFound
	}
	return t, nil
}

// RevokeToken implements grantor.Storage.
func (s *Store) RevokeToken(_ context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, hash)
	return nil
}

// RevokeGrant implements grantor.Storage.
func (s *Store) RevokeGrant(_ context.Context, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, t := range s.tokens {
		if t.GrantID == grantID {
			delete(s.tokens, hash)
		}
	}
	return nil
}

// ClaimOnce implements grantor.Storage.
func (s *Store) ClaimOnce(_ context.Context, key string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collectLocked()
	if exp, ok := s.claims[key]; ok && s.now().Before(exp) {
		return grantor.ErrConflict
	}
	s.claims[key] = expiresAt
	return nil
}

// collectLocked removes expired records at most once a minute.
func (s *Store) collectLocked() {
	now := s.now()
	if now.Sub(s.lastCollection) < time.Minute {
		return
	}
	s.lastCollection = now
	for id, req := range s.requests {
		if now.After(req.ExpiresAt) {
			delete(s.requests, id)
		}
	}
	for hash, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, hash)
		}
	}
	for key, exp := range s.claims {
		if now.After(exp) {
			delete(s.claims, key)
		}
	}
}

// clone deep-copies a record through JSON, which is also how a persistent
// store would round-trip it.
func clone[T any](v *T) *T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("memory: marshal %T: %v", v, err))
	}
	out := new(T)
	if err := json.Unmarshal(b, out); err != nil {
		panic(fmt.Sprintf("memory: unmarshal %T: %v", v, err))
	}
	return out
}
