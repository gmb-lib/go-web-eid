package signing

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestSelectHashFunctionPrefersOrder(t *testing.T) {
	supported := []SignatureAlgorithm{
		{CryptoAlgorithm: "ECC", HashFunction: "SHA-512"},
		{CryptoAlgorithm: "ECC", HashFunction: "SHA-384"},
	}
	got, err := SelectHashFunction([]string{"SHA-256", "SHA-384", "SHA-512"}, supported)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, "SHA-384"))
}

func TestSelectHashFunctionNoMatch(t *testing.T) {
	supported := []SignatureAlgorithm{{HashFunction: "SHA3-512"}}
	_, err := SelectHashFunction([]string{"SHA-256"}, supported)
	qt.Check(t, qt.IsNotNil(err))
}

func TestNewSignerRejectsBadPreference(t *testing.T) {
	_, err := NewSigner(Options{HashPreference: []string{"MD5"}})
	qt.Check(t, qt.IsNotNil(err))

	_, err = NewSigner(Options{HashPreference: nil})
	qt.Check(t, qt.IsNotNil(err))
}
