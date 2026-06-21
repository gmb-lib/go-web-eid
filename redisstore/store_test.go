package redisstore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	webeid "github.com/gmb-lib/go-web-eid"
	"github.com/gmb-lib/go-web-eid/exceptions"
)

// fakeClient is an in-memory Client implementing atomic single-use GETDEL.
type fakeClient struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newFakeClient() *fakeClient { return &fakeClient{m: map[string][]byte{}} }

func (f *fakeClient) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[key] = append([]byte(nil), value...)
	return nil
}

func (f *fakeClient) GetDel(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	if !ok {
		return nil, nil
	}
	delete(f.m, key)
	return v, nil
}

func fixedSessionKey(id string) webeid.SessionKeyFunc {
	return func(context.Context) (string, error) { return id, nil }
}

func TestStoreRoundTripAndSingleUse(t *testing.T) {
	s, err := New(newFakeClient(), fixedSessionKey("sess-1"), time.Minute)
	qt.Assert(t, qt.IsNil(err))

	issued := time.Now().Truncate(time.Second)
	put := &webeid.ChallengeNonce{Base64EncodedNonce: "bm9uY2U", IssuedAt: issued}
	qt.Assert(t, qt.IsNil(s.Put(context.Background(), put)))

	got, err := s.GetAndRemove(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Base64EncodedNonce, "bm9uY2U"))
	qt.Check(t, qt.IsTrue(got.IssuedAt.Equal(issued)))

	// Second read must fail: the nonce is single use.
	_, err = s.GetAndRemove(context.Background())
	qt.Check(t, qt.ErrorIs(err, exceptions.ErrChallengeNonceNotFound))
}

func TestStoreMissingNonce(t *testing.T) {
	s, err := New(newFakeClient(), fixedSessionKey("sess-2"), time.Minute)
	qt.Assert(t, qt.IsNil(err))
	_, err = s.GetAndRemove(context.Background())
	qt.Check(t, qt.ErrorIs(err, exceptions.ErrChallengeNonceNotFound))
}

func TestNewValidation(t *testing.T) {
	_, err := New(nil, fixedSessionKey("x"), time.Minute)
	qt.Check(t, qt.IsNotNil(err))
	_, err = New(newFakeClient(), nil, time.Minute)
	qt.Check(t, qt.IsNotNil(err))
}
