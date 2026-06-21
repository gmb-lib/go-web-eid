package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	webeid "github.com/gmb-lib/go-web-eid"
	"github.com/gmb-lib/go-web-eid/exceptions"
)

// newMiniredisStore spins up an in-memory Redis (no external server needed) and
// returns a Store wired to it via the go-redis adapter.
func newMiniredisStore(t *testing.T, sessionID string, ttl time.Duration, opts ...Option) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	s, err := New(Wrap(client), fixedSessionKey(sessionID), ttl, opts...)
	qt.Assert(t, qt.IsNil(err))
	return s, mr
}

func TestRedisIntegrationSingleUse(t *testing.T) {
	s, _ := newMiniredisStore(t, "sess-1", time.Minute)
	ctx := context.Background()

	issued := time.Now().Truncate(time.Second)
	qt.Assert(t, qt.IsNil(s.Put(ctx, &webeid.ChallengeNonce{
		Base64EncodedNonce: "bm9uY2UtdmFsdWU",
		IssuedAt:           issued,
	})))

	got, err := s.GetAndRemove(ctx)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Base64EncodedNonce, "bm9uY2UtdmFsdWU"))
	qt.Check(t, qt.IsTrue(got.IssuedAt.Equal(issued)))

	// Second read must fail: GETDEL consumed the nonce atomically.
	_, err = s.GetAndRemove(ctx)
	qt.Check(t, qt.ErrorIs(err, exceptions.ErrChallengeNonceNotFound))
}

func TestRedisIntegrationTTLExpiry(t *testing.T) {
	s, mr := newMiniredisStore(t, "sess-2", time.Minute)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(s.Put(ctx, &webeid.ChallengeNonce{
		Base64EncodedNonce: "expiring",
		IssuedAt:           time.Now(),
	})))

	// Advance miniredis's clock past the TTL; the key must have expired.
	mr.FastForward(2 * time.Minute)

	_, err := s.GetAndRemove(ctx)
	qt.Check(t, qt.ErrorIs(err, exceptions.ErrChallengeNonceNotFound))
}

func TestRedisIntegrationCrossPodHandoff(t *testing.T) {
	// Two Store instances sharing one Redis model two service pods: the nonce
	// issued via storeA must be consumable via storeB.
	mr, err := miniredis.Run()
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	storeA, err := New(Wrap(client), fixedSessionKey("shared"), time.Minute)
	qt.Assert(t, qt.IsNil(err))
	storeB, err := New(Wrap(client), fixedSessionKey("shared"), time.Minute)
	qt.Assert(t, qt.IsNil(err))

	ctx := context.Background()
	qt.Assert(t, qt.IsNil(storeA.Put(ctx, &webeid.ChallengeNonce{
		Base64EncodedNonce: "handoff",
		IssuedAt:           time.Now(),
	})))

	got, err := storeB.GetAndRemove(ctx)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Base64EncodedNonce, "handoff"))
}

func TestRedisIntegrationKeyPrefix(t *testing.T) {
	s, mr := newMiniredisStore(t, "abc", time.Minute, WithKeyPrefix("custom:nonce:"))
	qt.Assert(t, qt.IsNil(s.Put(context.Background(), &webeid.ChallengeNonce{
		Base64EncodedNonce: "y",
		IssuedAt:           time.Now(),
	})))
	qt.Check(t, qt.IsTrue(mr.Exists("custom:nonce:abc")))
}
