package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// selfSignedCert builds a self-signed certificate carrying pub.
func selfSignedCert(t *testing.T, priv crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	qt.Assert(t, qt.IsNil(err))
	cert, err := x509.ParseCertificate(der)
	qt.Assert(t, qt.IsNil(err))
	return cert
}

func digestOf(h crypto.Hash, data []byte) []byte {
	hasher := h.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func p1363(r, s *big.Int, curve elliptic.Curve) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*byteLen)
	r.FillBytes(out[:byteLen])
	s.FillBytes(out[byteLen:])
	return out
}

func TestVerifyECDSA(t *testing.T) {
	cases := map[string]elliptic.Curve{
		"ES256": elliptic.P256(),
		"ES384": elliptic.P384(),
		"ES512": elliptic.P521(),
	}
	signedData := []byte("origin-hash||challenge-hash")
	for algo, curve := range cases {
		t.Run(algo, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(curve, rand.Reader)
			qt.Assert(t, qt.IsNil(err))
			cert := selfSignedCert(t, priv)

			h, _ := HashFor(algo)
			r, s, err := ecdsa.Sign(rand.Reader, priv, digestOf(h, signedData))
			qt.Assert(t, qt.IsNil(err))
			sig := p1363(r, s, curve)

			qt.Check(t, qt.IsNil(Verify(cert, algo, signedData, sig)))

			sig[0] ^= 0xff
			qt.Check(t, qt.IsNotNil(Verify(cert, algo, signedData, sig)))
		})
	}
}

func TestVerifyRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))
	cert := selfSignedCert(t, priv)
	signedData := []byte("origin-hash||challenge-hash")

	t.Run("RS256", func(t *testing.T) {
		h, _ := HashFor("RS256")
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, h, digestOf(h, signedData))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.IsNil(Verify(cert, "RS256", signedData, sig)))
	})

	t.Run("PS256", func(t *testing.T) {
		h, _ := HashFor("PS256")
		sig, err := rsa.SignPSS(rand.Reader, priv, h, digestOf(h, signedData), &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       h,
		})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.IsNil(Verify(cert, "PS256", signedData, sig)))
	})

	t.Run("tampered", func(t *testing.T) {
		h, _ := HashFor("RS256")
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, h, digestOf(h, signedData))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.IsNotNil(Verify(cert, "RS256", []byte("different"), sig)))
	})
}

func TestVerifyUnsupportedAlgorithm(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	cert := selfSignedCert(t, priv)
	qt.Check(t, qt.IsNotNil(Verify(cert, "HS256", []byte("x"), []byte("y"))))
}
