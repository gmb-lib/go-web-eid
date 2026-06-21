package webeid

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func testStore(t *testing.T) *InMemoryStore {
	t.Helper()
	return NewInMemoryStore(func(context.Context) (string, error) {
		return "session-1", nil
	}, time.Minute)
}

func TestGenerateAndStoreNonceEntropy(t *testing.T) {
	store := testStore(t)
	gen, err := NewChallengeNonceGeneratorBuilder().WithChallengeNonceStore(store).Build()
	qt.Assert(t, qt.IsNil(err))

	nonce, err := gen.GenerateAndStoreNonce(context.Background())
	qt.Assert(t, qt.IsNil(err))

	raw, err := base64.StdEncoding.DecodeString(nonce.Base64EncodedNonce)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(len(raw) >= 32))
	qt.Check(t, qt.IsTrue(len(nonce.Base64EncodedNonce) >= 44))
}

func TestNonceSingleUse(t *testing.T) {
	store := testStore(t)
	gen, err := NewChallengeNonceGeneratorBuilder().WithChallengeNonceStore(store).Build()
	qt.Assert(t, qt.IsNil(err))

	_, err = gen.GenerateAndStoreNonce(context.Background())
	qt.Assert(t, qt.IsNil(err))

	_, err = store.GetAndRemove(context.Background())
	qt.Assert(t, qt.IsNil(err))

	// Second retrieval must fail (single use).
	_, err = store.GetAndRemove(context.Background())
	qt.Check(t, qt.IsNotNil(err))
}

func TestNonceExpiry(t *testing.T) {
	n := &ChallengeNonce{IssuedAt: time.Now().Add(-10 * time.Minute)}
	qt.Check(t, qt.IsTrue(n.Expired(time.Now(), 5*time.Minute)))
	qt.Check(t, qt.IsFalse(n.Expired(time.Now(), 30*time.Minute)))
}

func TestBuilderRequiresStore(t *testing.T) {
	_, err := NewChallengeNonceGeneratorBuilder().Build()
	qt.Check(t, qt.IsNotNil(err))
}
