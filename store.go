package webeid

import (
	"context"
	"errors"
	"time"
)

// ChallengeNonceStore stores challenge nonces keyed by the caller's session.
//
// Implementations must guarantee single use: GetAndRemove atomically returns
// and deletes the stored nonce. The Azugo integration layer provides
// session-backed implementations.
type ChallengeNonceStore interface {
	// Put stores the nonce for the current session, replacing any existing one.
	Put(ctx context.Context, nonce *ChallengeNonce) error
	// GetAndRemove returns and atomically removes the nonce for the current
	// session. It returns exceptions.ErrChallengeNonceNotFound when absent.
	GetAndRemove(ctx context.Context) (*ChallengeNonce, error)
}

// ChallengeNonce is a generated, time-stamped challenge nonce.
type ChallengeNonce struct {
	// Base64EncodedNonce is the standard-base64 encoding of the random nonce.
	Base64EncodedNonce string
	// IssuedAt is when the nonce was generated.
	IssuedAt time.Time
}

// Expired reports whether the nonce is older than ttl relative to now.
func (n *ChallengeNonce) Expired(now time.Time, ttl time.Duration) bool {
	return now.Sub(n.IssuedAt) > ttl
}

// errStoreNil is returned by builders when no store has been configured.
var errStoreNil = errors.New("a ChallengeNonceStore is required")
