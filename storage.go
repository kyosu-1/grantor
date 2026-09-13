package grantor

import (
	"context"
	"errors"
	"time"
)

// Errors returned by [Storage] and [ClientStore] implementations.
var (
	// ErrNotFound means the record does not exist, was deleted, or was
	// revoked.
	ErrNotFound = errors.New("grantor: not found")
	// ErrConflict means the record already exists, or a single-use value was
	// already used.
	ErrConflict = errors.New("grantor: conflict")
)

// ClientStore looks up registered clients.
type ClientStore interface {
	// Client returns the client with the given ID registered for issuer, or
	// ErrNotFound. Clients of different issuers must never be mixed up.
	Client(ctx context.Context, issuer, clientID string) (*Client, error)
}

// Storage persists authorization requests, tokens and replay-protection state.
//
// Records are plain structs; implementations may store them in any form,
// for example as JSON, and must persist every exported field. Returned
// records must not alias memory held by the storage. The storagetest package
// verifies an implementation against this contract, including its
// concurrency guarantees.
//
// Storage will not gain methods in future versions, so implementations keep
// compiling. Records may gain fields. Features that need other storage, such
// as sessions or device codes, take their own interface in an optional
// Config field.
type Storage interface {
	// CreateAuthorizationRequest saves a pending authorization request.
	// It returns ErrConflict if a request with the same ID exists.
	CreateAuthorizationRequest(ctx context.Context, req *AuthorizationRequest) error

	// AuthorizationRequest returns the pending authorization request with the
	// given ID, or ErrNotFound. It may return expired requests.
	AuthorizationRequest(ctx context.Context, id string) (*AuthorizationRequest, error)

	// DeleteAuthorizationRequest deletes a pending authorization request.
	// It returns ErrNotFound if the request does not exist. Deletion must be
	// atomic: when called concurrently for the same ID, exactly one call
	// returns nil.
	DeleteAuthorizationRequest(ctx context.Context, id string) error

	// CreateToken saves a token. It returns ErrConflict if a token with the
	// same Hash exists.
	CreateToken(ctx context.Context, t *Token) error

	// Token returns the token with the given hash, or ErrNotFound if it does
	// not exist or has been revoked, either directly or through its grant.
	// It may return expired and consumed tokens.
	Token(ctx context.Context, hash string) (*Token, error)

	// ConsumeToken marks a single-use token (an authorization code or a
	// refresh token) as consumed and returns the token as it was before the
	// call. If the returned token's ConsumedAt is non-zero, the token had
	// already been consumed. It returns ErrNotFound under the same conditions
	// as Token.
	//
	// The operation must be atomic: when called concurrently for the same
	// hash, exactly one call returns a token with a zero ConsumedAt.
	ConsumeToken(ctx context.Context, hash string, now time.Time) (*Token, error)

	// RevokeToken revokes a single token. Revoking an unknown token is not an
	// error.
	RevokeToken(ctx context.Context, hash string) error

	// RevokeGrant revokes every token that has the given GrantID. Revoking an
	// unknown grant is not an error.
	RevokeGrant(ctx context.Context, grantID string) error

	// ClaimOnce records key until expiresAt, for replay protection. It
	// returns ErrConflict if key was already claimed and has not expired.
	// Keys are ASCII strings of at most 128 bytes. The operation must be
	// atomic: when called concurrently for the same key, exactly one call
	// returns nil.
	ClaimOnce(ctx context.Context, key string, expiresAt time.Time) error
}
