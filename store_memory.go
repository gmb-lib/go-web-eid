package webeid

import (
	"context"
	"sync"
	"time"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

// SessionKeyFunc derives the session key for the current request from the
// context. It allows the framework-agnostic stores to bind nonces to a browser
// session without depending on any particular web framework.
type SessionKeyFunc func(ctx context.Context) (string, error)

// InMemoryStore is a thread-safe, in-process ChallengeNonceStore suitable for
// single-instance deployments and tests. Each session holds at most one nonce.
//
// A background-free lazy sweep removes expired entries on access; callers that
// need bounded memory under churn should prefer a TTL-aware external store
// (e.g. Redis) for clustered deployments.
type InMemoryStore struct {
	sessionKey SessionKeyFunc
	ttl        time.Duration
	now        func() time.Time

	mu      sync.Mutex
	entries map[string]*ChallengeNonce
}

// NewInMemoryStore creates an InMemoryStore. The sessionKey function maps a
// request context to its session identifier; ttl bounds nonce lifetime for the
// lazy sweep.
func NewInMemoryStore(sessionKey SessionKeyFunc, ttl time.Duration) *InMemoryStore {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	return &InMemoryStore{
		sessionKey: sessionKey,
		ttl:        ttl,
		now:        time.Now,
		entries:    make(map[string]*ChallengeNonce),
	}
}

// Put stores the nonce for the current session.
func (s *InMemoryStore) Put(ctx context.Context, nonce *ChallengeNonce) error {
	key, err := s.sessionKey(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.entries[key] = nonce
	return nil
}

// GetAndRemove returns and atomically removes the nonce for the current session.
func (s *InMemoryStore) GetAndRemove(ctx context.Context) (*ChallengeNonce, error) {
	key, err := s.sessionKey(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	nonce, ok := s.entries[key]
	if !ok {
		return nil, exceptions.ErrChallengeNonceNotFound
	}
	delete(s.entries, key)
	return nonce, nil
}

// sweepLocked removes expired entries. The caller must hold s.mu.
func (s *InMemoryStore) sweepLocked() {
	now := s.now()
	for k, n := range s.entries {
		if n.Expired(now, s.ttl) {
			delete(s.entries, k)
		}
	}
}
