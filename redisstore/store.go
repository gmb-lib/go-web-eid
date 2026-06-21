// Package redisstore provides a Redis-backed webeid.ChallengeNonceStore for
// clustered Web eID deployments.
//
// The in-process InMemoryStore in the core package only works on a single
// instance: a challenge issued by one pod is invisible to another pod that
// receives the login. This store keeps nonces in Redis keyed by the browser
// session, so any pod can serve any request, and uses an atomic GETDEL to
// guarantee a nonce is consumed exactly once (single use). Redis key expiry
// provides the TTL, so expired nonces are evicted automatically.
package redisstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	webeid "github.com/gmb-lib/go-web-eid"
	"github.com/gmb-lib/go-web-eid/exceptions"
)

// defaultKeyPrefix namespaces nonce keys in Redis.
const defaultKeyPrefix = "webeid:nonce:"

// Client is the minimal Redis surface the store needs. It uses plain return
// types so it is trivial to fake in tests; wrap a real go-redis client with
// Wrap. *redis.Client, *redis.ClusterClient and redis.UniversalClient are all
// supported through Wrap.
type Client interface {
	// Set stores value at key with the given expiration.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// GetDel atomically returns and deletes the value at key. It returns
	// (nil, nil) when the key is absent.
	GetDel(ctx context.Context, key string) ([]byte, error)
}

// Wrap adapts a go-redis universal client to Client.
func Wrap(c redis.UniversalClient) Client { return goRedisClient{c: c} }

// goRedisClient adapts redis.UniversalClient to Client.
type goRedisClient struct{ c redis.UniversalClient }

func (g goRedisClient) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return g.c.Set(ctx, key, value, ttl).Err()
}

func (g goRedisClient) GetDel(ctx context.Context, key string) ([]byte, error) {
	b, err := g.c.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Store is a Redis-backed, session-keyed ChallengeNonceStore.
type Store struct {
	client     Client
	sessionKey webeid.SessionKeyFunc
	ttl        time.Duration
	prefix     string
}

// Option customises a Store.
type Option func(*Store)

// WithKeyPrefix overrides the Redis key namespace (default "webeid:nonce:").
func WithKeyPrefix(prefix string) Option {
	return func(s *Store) {
		if prefix != "" {
			s.prefix = prefix
		}
	}
}

// New builds a Redis-backed store. sessionKey maps a request context to the
// browser session identifier (use webeidazugo.SessionKey for the Azugo
// integration); ttl bounds nonce lifetime and is applied as the Redis key TTL.
func New(client Client, sessionKey webeid.SessionKeyFunc, ttl time.Duration, opts ...Option) (*Store, error) {
	if client == nil {
		return nil, errors.New("redisstore: a Redis client is required")
	}
	if sessionKey == nil {
		return nil, errors.New("redisstore: a session key function is required")
	}
	if ttl <= 0 {
		ttl = webeid.DefaultNonceTTL
	}
	s := &Store{
		client:     client,
		sessionKey: sessionKey,
		ttl:        ttl,
		prefix:     defaultKeyPrefix,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// storedNonce is the on-the-wire representation of a ChallengeNonce.
type storedNonce struct {
	Nonce    string    `json:"nonce"`
	IssuedAt time.Time `json:"issuedAt"`
}

// Put stores the nonce for the current session, replacing any existing one.
func (s *Store) Put(ctx context.Context, nonce *webeid.ChallengeNonce) error {
	key, err := s.sessionKey(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(storedNonce{
		Nonce:    nonce.Base64EncodedNonce,
		IssuedAt: nonce.IssuedAt,
	})
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.prefix+key, payload, s.ttl)
}

// GetAndRemove atomically returns and removes the nonce for the current
// session, guaranteeing single use. It returns ErrChallengeNonceNotFound when
// no nonce exists (absent, already consumed, or TTL-expired).
func (s *Store) GetAndRemove(ctx context.Context) (*webeid.ChallengeNonce, error) {
	key, err := s.sessionKey(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := s.client.GetDel(ctx, s.prefix+key)
	if err != nil {
		return nil, exceptions.Wrap(exceptions.ErrChallengeNonceNotFound, err)
	}
	if raw == nil {
		return nil, exceptions.ErrChallengeNonceNotFound
	}
	var sn storedNonce
	if err := json.Unmarshal(raw, &sn); err != nil {
		return nil, exceptions.Wrap(exceptions.ErrChallengeNonceNotFound, err)
	}
	return &webeid.ChallengeNonce{
		Base64EncodedNonce: sn.Nonce,
		IssuedAt:           sn.IssuedAt,
	}, nil
}

// compile-time assertion that *Store satisfies the core interface.
var _ webeid.ChallengeNonceStore = (*Store)(nil)
