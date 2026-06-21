package webeid

import (
	"context"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestInMemoryStoreSweepsExpired(t *testing.T) {
	key := func(context.Context) (string, error) { return "s", nil }
	store := NewInMemoryStore(key, time.Hour)

	// Inject an already-expired nonce, then store a fresh one which triggers a sweep.
	store.now = func() time.Time { return time.Now() }
	store.entries["other"] = &ChallengeNonce{IssuedAt: time.Now().Add(-2 * time.Hour)}

	err := store.Put(context.Background(), &ChallengeNonce{
		Base64EncodedNonce: "fresh",
		IssuedAt:           time.Now(),
	})
	qt.Assert(t, qt.IsNil(err))

	// The expired "other" entry must have been swept.
	_, ok := store.entries["other"]
	qt.Check(t, qt.IsFalse(ok))

	got, err := store.GetAndRemove(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Base64EncodedNonce, "fresh"))
}

func TestInMemoryStoreDefaultsTTL(t *testing.T) {
	store := NewInMemoryStore(func(context.Context) (string, error) { return "s", nil }, 0)
	qt.Check(t, qt.Equals(store.ttl, DefaultNonceTTL))
}

func TestInMemoryStorePropagatesKeyError(t *testing.T) {
	wantErr := context.Canceled
	store := NewInMemoryStore(func(context.Context) (string, error) { return "", wantErr }, time.Minute)

	err := store.Put(context.Background(), &ChallengeNonce{})
	qt.Check(t, qt.ErrorIs(err, wantErr))

	_, err = store.GetAndRemove(context.Background())
	qt.Check(t, qt.ErrorIs(err, wantErr))
}
