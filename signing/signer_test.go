package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-web-eid/certificate"
)

func makeSigningCert(t *testing.T, keyUsage x509.KeyUsage, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     keyUsage,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, key.Public(), signerKey)
	qt.Assert(t, qt.IsNil(err))
	cert, err := x509.ParseCertificate(der)
	qt.Assert(t, qt.IsNil(err))
	return cert, key
}

func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SIGNING CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	qt.Assert(t, qt.IsNil(err))
	cert, err := x509.ParseCertificate(der)
	qt.Assert(t, qt.IsNil(err))
	return cert, key
}

func supportedAlgos() []SignatureAlgorithm {
	return []SignatureAlgorithm{
		{CryptoAlgorithm: "ECC", HashFunction: "SHA-384", PaddingScheme: "NONE"},
		{CryptoAlgorithm: "ECC", HashFunction: "SHA-512", PaddingScheme: "NONE"},
	}
}

func TestPrepareSigningNoTrust(t *testing.T) {
	signer, err := NewSigner(Options{HashPreference: []string{"SHA-256", "SHA-384"}})
	qt.Assert(t, qt.IsNil(err))

	cert, _ := makeSigningCert(t, x509.KeyUsageContentCommitment, nil, nil)
	gotCert, algo, hashFn, err := signer.PrepareSigning(context.Background(), cert.Raw, supportedAlgos())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(hashFn, "SHA-384"))
	qt.Check(t, qt.Equals(algo.HashFunction, "SHA-384"))
	qt.Check(t, qt.Equals(gotCert.Subject.CommonName, "signer"))
}

func TestPrepareSigningWithTrust(t *testing.T) {
	ca, caKey := makeCA(t)
	trust, err := certificate.NewTrustStore(ca)
	qt.Assert(t, qt.IsNil(err))

	signer, err := NewSigner(Options{
		HashPreference: []string{"SHA-512"},
		Trust:          trust,
	})
	qt.Assert(t, qt.IsNil(err))

	cert, _ := makeSigningCert(t, x509.KeyUsageContentCommitment, ca, caKey)
	_, _, hashFn, err := signer.PrepareSigning(context.Background(), cert.Raw, supportedAlgos())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(hashFn, "SHA-512"))
}

func TestPrepareSigningUntrusted(t *testing.T) {
	ca, _ := makeCA(t)
	otherCA, otherKey := makeCA(t)
	trust, err := certificate.NewTrustStore(ca)
	qt.Assert(t, qt.IsNil(err))

	signer, err := NewSigner(Options{HashPreference: []string{"SHA-384"}, Trust: trust})
	qt.Assert(t, qt.IsNil(err))

	cert, _ := makeSigningCert(t, x509.KeyUsageContentCommitment, otherCA, otherKey)
	_, _, _, err = signer.PrepareSigning(context.Background(), cert.Raw, supportedAlgos())
	qt.Check(t, qt.IsNotNil(err))
}

func TestPrepareSigningRejectsBadCert(t *testing.T) {
	signer, err := NewSigner(Options{HashPreference: []string{"SHA-384"}})
	qt.Assert(t, qt.IsNil(err))

	_, _, _, err = signer.PrepareSigning(context.Background(), []byte("not der"), supportedAlgos())
	qt.Check(t, qt.IsNotNil(err))
}

func TestPrepareSigningWrongKeyUsage(t *testing.T) {
	signer, err := NewSigner(Options{HashPreference: []string{"SHA-384"}})
	qt.Assert(t, qt.IsNil(err))

	cert, _ := makeSigningCert(t, x509.KeyUsageDigitalSignature, nil, nil)
	_, _, _, err = signer.PrepareSigning(context.Background(), cert.Raw, supportedAlgos())
	qt.Check(t, qt.IsNotNil(err))
}

func TestPrepareSigningNoHashMatch(t *testing.T) {
	signer, err := NewSigner(Options{HashPreference: []string{"SHA-256"}})
	qt.Assert(t, qt.IsNil(err))

	cert, _ := makeSigningCert(t, x509.KeyUsageContentCommitment, nil, nil)
	_, _, _, err = signer.PrepareSigning(context.Background(), cert.Raw, supportedAlgos())
	qt.Check(t, qt.IsNotNil(err))
}

func TestFinalize(t *testing.T) {
	signer, err := NewSigner(Options{HashPreference: []string{"SHA-384"}})
	qt.Assert(t, qt.IsNil(err))

	authCert, _ := makeSigningCert(t, x509.KeyUsageDigitalSignature, nil, nil)
	sigValue := []byte{0x01, 0x02, 0x03}

	gotCert, signed, err := signer.Finalize(sigValue, authCert.Raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(signed, sigValue))
	qt.Check(t, qt.Equals(gotCert.Subject.CommonName, "signer"))
}

func TestFinalizeRejectsEmptySignature(t *testing.T) {
	signer, err := NewSigner(Options{HashPreference: []string{"SHA-384"}})
	qt.Assert(t, qt.IsNil(err))

	authCert, _ := makeSigningCert(t, x509.KeyUsageDigitalSignature, nil, nil)
	_, _, err = signer.Finalize(nil, authCert.Raw)
	qt.Check(t, qt.IsNotNil(err))
}

func TestFinalizeRejectsBadAuthCert(t *testing.T) {
	signer, err := NewSigner(Options{HashPreference: []string{"SHA-384"}})
	qt.Assert(t, qt.IsNil(err))

	_, _, err = signer.Finalize([]byte{0x01}, []byte("not der"))
	qt.Check(t, qt.IsNotNil(err))
}

func TestParseSigningCertificate(t *testing.T) {
	cert, _ := makeSigningCert(t, x509.KeyUsageContentCommitment, nil, nil)
	parsed, err := ParseSigningCertificate(cert.Raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(parsed.Subject.CommonName, "signer"))

	_, err = ParseSigningCertificate([]byte("garbage"))
	qt.Check(t, qt.IsNotNil(err))
}

func TestPickAlgorithmForHash(t *testing.T) {
	supported := supportedAlgos()
	got := pickAlgorithmForHash("SHA-512", supported)
	qt.Check(t, qt.Equals(got.HashFunction, "SHA-512"))
	qt.Check(t, qt.Equals(got.CryptoAlgorithm, "ECC"))

	// No match falls back to a synthetic entry carrying just the hash.
	fallback := pickAlgorithmForHash("SHA3-256", supported)
	qt.Check(t, qt.Equals(fallback.HashFunction, "SHA3-256"))
	qt.Check(t, qt.Equals(fallback.CryptoAlgorithm, ""))
}

func TestIsSupportedHashFunction(t *testing.T) {
	qt.Check(t, qt.IsTrue(IsSupportedHashFunction("SHA-256")))
	qt.Check(t, qt.IsTrue(IsSupportedHashFunction("SHA3-512")))
	qt.Check(t, qt.IsFalse(IsSupportedHashFunction("MD5")))
}
