// Package storagetest verifies that a grantor.Storage implementation meets
// the contract the provider relies on, including its atomicity guarantees.
//
// Run it from a test in the package that implements the storage:
//
//	func TestStorage(t *testing.T) {
//		storagetest.Run(t, func(t *testing.T) grantor.Storage {
//			return newTestStorage(t)
//		})
//	}
package storagetest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kyosu-1/grantor"
)

// Run runs the conformance tests. newStorage must return a new, empty
// storage for every call.
func Run(t *testing.T, newStorage func(t *testing.T) grantor.Storage) {
	t.Run("AuthorizationRequestRoundTrip", func(t *testing.T) { testAuthorizationRequestRoundTrip(t, newStorage(t)) })
	t.Run("AuthorizationRequestConflict", func(t *testing.T) { testAuthorizationRequestConflict(t, newStorage(t)) })
	t.Run("AuthorizationRequestDeleteOnce", func(t *testing.T) { testAuthorizationRequestDeleteOnce(t, newStorage(t)) })
	t.Run("TokenRoundTrip", func(t *testing.T) { testTokenRoundTrip(t, newStorage(t)) })
	t.Run("TokenConflict", func(t *testing.T) { testTokenConflict(t, newStorage(t)) })
	t.Run("TokenNotFound", func(t *testing.T) { testTokenNotFound(t, newStorage(t)) })
	t.Run("ConsumeToken", func(t *testing.T) { testConsumeToken(t, newStorage(t)) })
	t.Run("ConsumeTokenConcurrently", func(t *testing.T) { testConsumeTokenConcurrently(t, newStorage(t)) })
	t.Run("RevokeToken", func(t *testing.T) { testRevokeToken(t, newStorage(t)) })
	t.Run("RevokeGrant", func(t *testing.T) { testRevokeGrant(t, newStorage(t)) })
	t.Run("RevokeGrantCoversLaterTokens", func(t *testing.T) { testRevokeGrantCoversLaterTokens(t, newStorage(t)) })
	t.Run("ReturnedRecordsAreCopies", func(t *testing.T) { testReturnedRecordsAreCopies(t, newStorage(t)) })
	t.Run("ClaimAssertionID", func(t *testing.T) { testClaimAssertionID(t, newStorage(t)) })
	t.Run("ClaimAssertionIDConcurrently", func(t *testing.T) { testClaimAssertionIDConcurrently(t, newStorage(t)) })
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// now returns the current time truncated to microseconds, the precision
// most databases keep.
func now() time.Time { return time.Now().Truncate(time.Microsecond) }

func fullAuthorizationRequest() *grantor.AuthorizationRequest {
	maxAge := 5 * time.Minute
	n := now()
	return &grantor.AuthorizationRequest{
		ID:                   randomID(),
		Issuer:               "https://issuer.example.com",
		ClientID:             "client-1",
		RedirectURI:          "https://client.example.com/cb",
		RedirectURIInRequest: true,
		ResponseType:         "code",
		ResponseMode:         "query",
		State:                "state-value",
		Scopes:               []string{"openid", "profile"},
		CodeChallenge:        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod:  "S256",
		Nonce:                "nonce-value",
		Prompt:               []string{"login", "consent"},
		MaxAge:               &maxAge,
		Display:              "page",
		UILocales:            []string{"en", "ja"},
		ClaimsLocales:        []string{"en"},
		LoginHint:            "alice@example.com",
		ACRValues:            []string{"urn:acr:1"},
		RequestedSubject:     "alice",
		Claims: &grantor.ClaimsRequest{
			UserInfo: map[string]*grantor.ClaimRequest{"email": nil, "name": {Essential: true}},
			IDToken:  map[string]*grantor.ClaimRequest{"acr": {Essential: true, Values: []any{"urn:acr:1"}}},
		},
		Extra:       map[string]string{"tenant": "acme"},
		BindingHash: "binding-hash",
		CreatedAt:   n,
		ExpiresAt:   n.Add(15 * time.Minute),
	}
}

func fullToken(typ grantor.TokenType, grantID string) *grantor.Token {
	n := now()
	return &grantor.Token{
		Hash:                 randomID(),
		Type:                 typ,
		GrantID:              grantID,
		Issuer:               "https://issuer.example.com",
		ClientID:             "client-1",
		Subject:              "alice",
		Scopes:               []string{"openid", "offline_access"},
		AuthTime:             n.Add(-time.Minute),
		ACR:                  "urn:acr:1",
		AMR:                  []string{"pwd", "otp"},
		Claims:               &grantor.ClaimsRequest{UserInfo: map[string]*grantor.ClaimRequest{"email": nil}},
		RedirectURI:          "https://client.example.com/cb",
		RedirectURIInRequest: true,
		Nonce:                "nonce-value",
		CodeChallenge:        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod:  "S256",
		CreatedAt:            n,
		ExpiresAt:            n.Add(time.Hour),
	}
}

func testAuthorizationRequestRoundTrip(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	want := fullAuthorizationRequest()
	if err := s.CreateAuthorizationRequest(ctx, want); err != nil {
		t.Fatalf("CreateAuthorizationRequest: %v", err)
	}
	got, err := s.AuthorizationRequest(ctx, want.ID)
	if err != nil {
		t.Fatalf("AuthorizationRequest: %v", err)
	}
	assertEqual(t, got, want)
}

func testAuthorizationRequestConflict(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	req := fullAuthorizationRequest()
	if err := s.CreateAuthorizationRequest(ctx, req); err != nil {
		t.Fatalf("CreateAuthorizationRequest: %v", err)
	}
	if err := s.CreateAuthorizationRequest(ctx, req); !errors.Is(err, grantor.ErrConflict) {
		t.Fatalf("second CreateAuthorizationRequest = %v, want ErrConflict", err)
	}
	if _, err := s.AuthorizationRequest(ctx, randomID()); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("AuthorizationRequest(unknown) = %v, want ErrNotFound", err)
	}
}

func testAuthorizationRequestDeleteOnce(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	req := fullAuthorizationRequest()
	if err := s.CreateAuthorizationRequest(ctx, req); err != nil {
		t.Fatalf("CreateAuthorizationRequest: %v", err)
	}
	const workers = 32
	var succeeded atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.DeleteAuthorizationRequest(ctx, req.ID)
			switch {
			case err == nil:
				succeeded.Add(1)
			case !errors.Is(err, grantor.ErrNotFound):
				t.Errorf("DeleteAuthorizationRequest = %v, want nil or ErrNotFound", err)
			}
		}()
	}
	wg.Wait()
	if n := succeeded.Load(); n != 1 {
		t.Fatalf("%d concurrent deletes succeeded, want exactly 1", n)
	}
	if _, err := s.AuthorizationRequest(ctx, req.ID); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("AuthorizationRequest after delete = %v, want ErrNotFound", err)
	}
}

func testTokenRoundTrip(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	for _, typ := range []grantor.TokenType{grantor.TokenTypeAuthorizationCode, grantor.TokenTypeAccessToken, grantor.TokenTypeRefreshToken} {
		want := fullToken(typ, randomID())
		if err := s.CreateToken(ctx, want); err != nil {
			t.Fatalf("CreateToken(%s): %v", typ, err)
		}
		got, err := s.Token(ctx, want.Hash)
		if err != nil {
			t.Fatalf("Token(%s): %v", typ, err)
		}
		assertEqual(t, got, want)
	}

	// Minimal tokens, such as client credentials access tokens, keep their
	// zero values.
	minimal := &grantor.Token{
		Hash: randomID(), Type: grantor.TokenTypeAccessToken, GrantID: randomID(),
		Issuer: "https://issuer.example.com", ClientID: "client-1",
		CreatedAt: now(), ExpiresAt: now().Add(time.Hour),
	}
	if err := s.CreateToken(ctx, minimal); err != nil {
		t.Fatalf("CreateToken(minimal): %v", err)
	}
	got, err := s.Token(ctx, minimal.Hash)
	if err != nil {
		t.Fatalf("Token(minimal): %v", err)
	}
	assertEqual(t, got, minimal)
}

func testTokenConflict(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	tok := fullToken(grantor.TokenTypeAccessToken, randomID())
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if err := s.CreateToken(ctx, tok); !errors.Is(err, grantor.ErrConflict) {
		t.Fatalf("second CreateToken = %v, want ErrConflict", err)
	}
}

func testTokenNotFound(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	if _, err := s.Token(ctx, randomID()); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("Token(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.ConsumeToken(ctx, randomID(), now()); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("ConsumeToken(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.RevokeToken(ctx, randomID()); err != nil {
		t.Fatalf("RevokeToken(unknown) = %v, want nil", err)
	}
	if err := s.RevokeGrant(ctx, randomID()); err != nil {
		t.Fatalf("RevokeGrant(unknown) = %v, want nil", err)
	}
}

func testConsumeToken(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	tok := fullToken(grantor.TokenTypeAuthorizationCode, randomID())
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	consumedAt := now()
	first, err := s.ConsumeToken(ctx, tok.Hash, consumedAt)
	if err != nil {
		t.Fatalf("first ConsumeToken: %v", err)
	}
	if !first.ConsumedAt.IsZero() {
		t.Fatalf("first ConsumeToken returned ConsumedAt %v, want zero", first.ConsumedAt)
	}
	assertEqual(t, first, tok)

	second, err := s.ConsumeToken(ctx, tok.Hash, consumedAt.Add(time.Second))
	if err != nil {
		t.Fatalf("second ConsumeToken: %v", err)
	}
	if !second.ConsumedAt.Equal(consumedAt) {
		t.Fatalf("second ConsumeToken returned ConsumedAt %v, want %v", second.ConsumedAt, consumedAt)
	}
	got, err := s.Token(ctx, tok.Hash)
	if err != nil {
		t.Fatalf("Token after consume: %v", err)
	}
	if !got.ConsumedAt.Equal(consumedAt) {
		t.Fatalf("Token after consume has ConsumedAt %v, want %v", got.ConsumedAt, consumedAt)
	}
}

func testConsumeTokenConcurrently(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	tok := fullToken(grantor.TokenTypeRefreshToken, randomID())
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	const workers = 32
	var firstUses atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.ConsumeToken(ctx, tok.Hash, now())
			if err != nil {
				t.Errorf("ConsumeToken: %v", err)
				return
			}
			if got.ConsumedAt.IsZero() {
				firstUses.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := firstUses.Load(); n != 1 {
		t.Fatalf("%d concurrent ConsumeToken calls saw an unconsumed token, want exactly 1", n)
	}
}

func testRevokeToken(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	grantID := randomID()
	a := fullToken(grantor.TokenTypeAccessToken, grantID)
	b := fullToken(grantor.TokenTypeRefreshToken, grantID)
	for _, tok := range []*grantor.Token{a, b} {
		if err := s.CreateToken(ctx, tok); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
	}
	if err := s.RevokeToken(ctx, a.Hash); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := s.Token(ctx, a.Hash); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("Token after RevokeToken = %v, want ErrNotFound", err)
	}
	if _, err := s.Token(ctx, b.Hash); err != nil {
		t.Fatalf("RevokeToken revoked another token of the grant: %v", err)
	}
}

func testRevokeGrant(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	grantID := randomID()
	revoked := []*grantor.Token{
		fullToken(grantor.TokenTypeAuthorizationCode, grantID),
		fullToken(grantor.TokenTypeAccessToken, grantID),
		fullToken(grantor.TokenTypeRefreshToken, grantID),
	}
	other := fullToken(grantor.TokenTypeAccessToken, randomID())
	for _, tok := range append(revoked, other) {
		if err := s.CreateToken(ctx, tok); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
	}
	if err := s.RevokeGrant(ctx, grantID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	for _, tok := range revoked {
		if _, err := s.Token(ctx, tok.Hash); !errors.Is(err, grantor.ErrNotFound) {
			t.Fatalf("Token(%s) after RevokeGrant = %v, want ErrNotFound", tok.Type, err)
		}
		if _, err := s.ConsumeToken(ctx, tok.Hash, now()); !errors.Is(err, grantor.ErrNotFound) {
			t.Fatalf("ConsumeToken(%s) after RevokeGrant = %v, want ErrNotFound", tok.Type, err)
		}
	}
	if _, err := s.Token(ctx, other.Hash); err != nil {
		t.Fatalf("RevokeGrant revoked a token of another grant: %v", err)
	}
}

func testRevokeGrantCoversLaterTokens(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	grantID := randomID()
	if err := s.RevokeGrant(ctx, grantID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	tok := fullToken(grantor.TokenTypeAccessToken, grantID)
	if err := s.CreateToken(ctx, tok); err != nil && !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("CreateToken after RevokeGrant = %v, want nil or ErrNotFound", err)
	}
	if _, err := s.Token(ctx, tok.Hash); !errors.Is(err, grantor.ErrNotFound) {
		t.Fatalf("Token created after RevokeGrant = %v, want ErrNotFound", err)
	}
}

func testReturnedRecordsAreCopies(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	req := fullAuthorizationRequest()
	if err := s.CreateAuthorizationRequest(ctx, req); err != nil {
		t.Fatalf("CreateAuthorizationRequest: %v", err)
	}
	req.Scopes[0] = "mutated-after-create"
	got, err := s.AuthorizationRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("AuthorizationRequest: %v", err)
	}
	if got.Scopes[0] != "openid" {
		t.Fatalf("storage kept a reference to the created request")
	}
	got.Scopes[0] = "mutated-after-read"
	again, err := s.AuthorizationRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("AuthorizationRequest: %v", err)
	}
	if again.Scopes[0] != "openid" {
		t.Fatalf("storage returned a reference to its own request")
	}

	tok := fullToken(grantor.TokenTypeAccessToken, randomID())
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	tok.Scopes[0] = "mutated-after-create"
	gotTok, err := s.Token(ctx, tok.Hash)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if gotTok.Scopes[0] != "openid" {
		t.Fatalf("storage kept a reference to the created token")
	}
	gotTok.Scopes[0] = "mutated-after-read"
	againTok, err := s.Token(ctx, tok.Hash)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if againTok.Scopes[0] != "openid" {
		t.Fatalf("storage returned a reference to its own token")
	}
}

func testClaimAssertionID(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	const issuer, client = "https://issuer.example.com", "client-1"
	jti := randomID()
	exp := time.Now().Add(time.Minute)
	if err := s.ClaimAssertionID(ctx, issuer, client, jti, exp); err != nil {
		t.Fatalf("ClaimAssertionID: %v", err)
	}
	if err := s.ClaimAssertionID(ctx, issuer, client, jti, exp); !errors.Is(err, grantor.ErrConflict) {
		t.Fatalf("second ClaimAssertionID = %v, want ErrConflict", err)
	}
	if err := s.ClaimAssertionID(ctx, issuer, "client-2", jti, exp); err != nil {
		t.Fatalf("ClaimAssertionID for another client: %v", err)
	}
	if err := s.ClaimAssertionID(ctx, "https://other.example.com", client, jti, exp); err != nil {
		t.Fatalf("ClaimAssertionID for another issuer: %v", err)
	}

	expired := randomID()
	if err := s.ClaimAssertionID(ctx, issuer, client, expired, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("ClaimAssertionID(expired): %v", err)
	}
	if err := s.ClaimAssertionID(ctx, issuer, client, expired, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("ClaimAssertionID after the previous claim expired = %v, want nil", err)
	}
}

func testClaimAssertionIDConcurrently(t *testing.T, s grantor.Storage) {
	ctx := context.Background()
	jti := randomID()
	exp := time.Now().Add(time.Minute)
	const workers = 32
	var succeeded atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.ClaimAssertionID(ctx, "https://issuer.example.com", "client-1", jti, exp)
			switch {
			case err == nil:
				succeeded.Add(1)
			case !errors.Is(err, grantor.ErrConflict):
				t.Errorf("ClaimAssertionID = %v, want nil or ErrConflict", err)
			}
		}()
	}
	wg.Wait()
	if n := succeeded.Load(); n != 1 {
		t.Fatalf("%d concurrent ClaimAssertionID calls succeeded, want exactly 1", n)
	}
}

// assertEqual compares records, treating times as equal instants and nil and
// empty slices as equal.
func assertEqual[T any](t *testing.T, got, want *T) {
	t.Helper()
	if !equalValues(reflect.ValueOf(got).Elem(), reflect.ValueOf(want).Elem()) {
		t.Fatalf("record did not round-trip:\n got: %+v\nwant: %+v", got, want)
	}
}

var timeType = reflect.TypeFor[time.Time]()

func equalValues(a, b reflect.Value) bool {
	if a.Type() == timeType {
		return a.Interface().(time.Time).Equal(b.Interface().(time.Time))
	}
	switch a.Kind() {
	case reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return equalValues(a.Elem(), b.Elem())
	case reflect.Struct:
		for i := range a.NumField() {
			if !equalValues(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if a.Len() != b.Len() {
			return false
		}
		for i := range a.Len() {
			if !equalValues(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.Len() != b.Len() {
			return false
		}
		for _, k := range a.MapKeys() {
			bv := b.MapIndex(k)
			if !bv.IsValid() || !equalValues(a.MapIndex(k), bv) {
				return false
			}
		}
		return true
	case reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return reflect.DeepEqual(a.Elem().Interface(), b.Elem().Interface())
	default:
		return reflect.DeepEqual(a.Interface(), b.Interface())
	}
}
