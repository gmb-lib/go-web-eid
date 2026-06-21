package exceptions

import (
	"errors"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestErrorInterface(t *testing.T) {
	qt.Check(t, qt.Equals(ErrTokenParse.StatusCode(), 400))
	qt.Check(t, qt.Equals(ErrChallengeNonceExpired.StatusCode(), 401))
	qt.Check(t, qt.Equals(ErrOCSPRequestFailed.StatusCode(), 502))
	qt.Check(t, qt.Equals(ErrNoSupportedHashFunction.StatusCode(), 422))

	qt.Check(t, qt.IsTrue(len(ErrTokenParse.SafeError()) > 0))
	qt.Check(t, qt.IsTrue(len(ErrTokenParse.Error()) > 0))
}

func TestWrapPreservesCauseAndIdentity(t *testing.T) {
	cause := errors.New("root cause")
	wrapped := Wrap(ErrCertificateRevoked, cause)

	qt.Check(t, qt.Equals(wrapped.StatusCode(), ErrCertificateRevoked.StatusCode()))
	qt.Check(t, qt.Equals(wrapped.Code, ErrCertificateRevoked.Code))
	qt.Check(t, qt.ErrorIs(wrapped, cause))
	qt.Check(t, qt.IsTrue(len(wrapped.Error()) > len(ErrCertificateRevoked.SafeError())))

	// The safe message never leaks the cause.
	qt.Check(t, qt.Equals(wrapped.SafeError(), ErrCertificateRevoked.SafeError()))

	// Wrapping must not mutate the shared base error.
	qt.Check(t, qt.IsNil(ErrCertificateRevoked.Unwrap()))
}

func TestWrapNilBase(t *testing.T) {
	qt.Check(t, qt.IsNil(Wrap(nil, errors.New("x"))))
}
