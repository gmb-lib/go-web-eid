package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestSplitP1363RejectsWrongLength(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	// P-256 expects a 64-byte signature; supply a short one.
	_, _, err = splitP1363([]byte{0x01, 0x02}, &priv.PublicKey)
	qt.Check(t, qt.IsNotNil(err))
}

func TestSplitP1363Valid(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	sig := make([]byte, 64)
	sig[63] = 0x01
	r, s, err := splitP1363(sig, &priv.PublicKey)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(r.Sign(), 0))
	qt.Check(t, qt.Equals(s.Int64(), int64(1)))
}

func TestIsSupportedAlgorithm(t *testing.T) {
	for _, algo := range []string{"RS256", "PS384", "ES512"} {
		qt.Check(t, qt.IsTrue(IsSupportedAlgorithm(algo)))
	}
	qt.Check(t, qt.IsFalse(IsSupportedAlgorithm("HS256")))
}
