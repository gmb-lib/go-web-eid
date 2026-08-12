package certificate

import (
	"crypto/x509/pkix"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

func TestRuntimeTrustStoreStartsEmpty(t *testing.T) {
	ts := NewRuntimeTrustStore()

	ca, caKey := makeCert(t, certOptions{isCA: true, subject: pkix.Name{CommonName: "TEST CA"}}, nil, nil)
	leaf, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "LEAF"}}, ca, caKey)

	qt.Check(t, qt.HasLen(ts.Intermediates(), 0))
	qt.Check(t, qt.IsNil(ts.IssuerOf(leaf)))

	err := ts.Verify(leaf, time.Now())
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsTrue(isNotTrusted(err)))
}

// isNotTrusted reports whether err carries the CERTIFICATE_NOT_TRUSTED code
// (Wrap clones the sentinel, so identity comparison does not apply).
func isNotTrusted(err error) bool {
	var xerr *exceptions.Error
	return errors.As(err, &xerr) && xerr.Code == exceptions.ErrCertificateNotTrusted.Code
}

func TestTrustStoreReloadMakesNewSetEffective(t *testing.T) {
	ts := NewRuntimeTrustStore()

	ca, caKey := makeCert(t, certOptions{isCA: true, subject: pkix.Name{CommonName: "TEST CA"}}, nil, nil)
	leaf, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "LEAF"}}, ca, caKey)

	qt.Assert(t, qt.IsNotNil(ts.Verify(leaf, time.Now())))

	qt.Assert(t, qt.IsNil(ts.Reload(ca)))

	qt.Check(t, qt.IsNil(ts.Verify(leaf, time.Now())))
	qt.Check(t, qt.Equals(ts.IssuerOf(leaf), ca))
	qt.Check(t, qt.HasLen(ts.Intermediates(), 1))
}

func TestTrustStoreReloadRefusesEmptyAndKeepsOldSet(t *testing.T) {
	ca, caKey := makeCert(t, certOptions{isCA: true, subject: pkix.Name{CommonName: "TEST CA"}}, nil, nil)
	leaf, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "LEAF"}}, ca, caKey)

	ts, err := NewTrustStore(ca)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNotNil(ts.Reload()))

	// The refused reload must leave the previous set in effect.
	qt.Check(t, qt.IsNil(ts.Verify(leaf, time.Now())))
}

func TestTrustStoreReloadReplacesNotAppends(t *testing.T) {
	caA, caAKey := makeCert(t, certOptions{isCA: true, subject: pkix.Name{CommonName: "CA A"}}, nil, nil)
	leafA, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "LEAF A"}}, caA, caAKey)
	caB, caBKey := makeCert(t, certOptions{isCA: true, subject: pkix.Name{CommonName: "CA B"}}, nil, nil)
	leafB, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "LEAF B"}}, caB, caBKey)

	ts, err := NewTrustStore(caA)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(ts.Reload(caB)))

	qt.Check(t, qt.IsNil(ts.Verify(leafB, time.Now())))
	err = ts.Verify(leafA, time.Now())
	qt.Check(t, qt.IsTrue(isNotTrusted(err)))
}

func TestTrustStoreReloadIsSafeUnderConcurrentReads(t *testing.T) {
	ca, caKey := makeCert(t, certOptions{isCA: true, subject: pkix.Name{CommonName: "TEST CA"}}, nil, nil)
	leaf, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "LEAF"}}, ca, caKey)

	ts, err := NewTrustStore(ca)
	qt.Assert(t, qt.IsNil(err))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Every read must see a complete set: either verification
				// outcome is fine, a torn state is not (the race detector
				// guards the latter).
				_ = ts.Verify(leaf, time.Now())
				_ = ts.IssuerOf(leaf)
				_ = ts.Intermediates()
			}
		}()
	}
	for range 100 {
		qt.Assert(t, qt.IsNil(ts.Reload(ca)))
	}
	close(stop)
	wg.Wait()

	qt.Check(t, qt.IsNil(ts.Verify(leaf, time.Now())))
}
