package webeid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

const testOrigin = "https://example.org"

type testPKI struct {
	caCert  *x509.Certificate
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TEST INTERMEDIATE CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	qt.Assert(t, qt.IsNil(err))
	caCert, err := x509.ParseCertificate(caDER)
	qt.Assert(t, qt.IsNil(err))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "JÕEORG,JAAK-KRISTJAN,38001085718",
			SerialNumber: "PNOEE-38001085718",
			Country:      []string{"EE"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	qt.Assert(t, qt.IsNil(err))
	leaf, err := x509.ParseCertificate(leafDER)
	qt.Assert(t, qt.IsNil(err))

	return &testPKI{caCert: caCert, leaf: leaf, leafKey: leafKey}
}

func (p *testPKI) signedToken(t *testing.T, origin, nonce string) *AuthToken {
	t.Helper()

	originHash := sha256.Sum256([]byte(origin))
	nonceHash := sha256.Sum256([]byte(nonce))
	signedData := append(originHash[:], nonceHash[:]...)
	digest := sha256.Sum256(signedData)

	r, s, err := ecdsa.Sign(rand.Reader, p.leafKey, digest[:])
	qt.Assert(t, qt.IsNil(err))

	const byteLen = 32
	sig := make([]byte, 2*byteLen)
	r.FillBytes(sig[:byteLen])
	s.FillBytes(sig[byteLen:])

	return &AuthToken{
		UnverifiedCertificate: base64.StdEncoding.EncodeToString(p.leaf.Raw),
		Algorithm:             "ES256",
		Signature:             base64.StdEncoding.EncodeToString(sig),
		Format:                "web-eid:1.0",
		AppVersion:            "https://web-eid.eu/test",
	}
}

func newTestValidator(t *testing.T, pki *testPKI) AuthTokenValidator {
	t.Helper()
	v, err := NewAuthTokenValidatorBuilder().
		WithSiteOrigin(testOrigin).
		WithTrustedCertificateAuthorities(pki.caCert).
		WithoutUserCertificateRevocationCheckWithOcsp().
		Build()
	qt.Assert(t, qt.IsNil(err))
	return v
}

func TestValidateHappyPath(t *testing.T) {
	pki := newTestPKI(t)
	v := newTestValidator(t, pki)
	const nonce = "dGVzdC1ub25jZS13aXRoLWVub3VnaC1lbnRyb3B5LWZvci10ZXN0cw=="

	tok := pki.signedToken(t, testOrigin, nonce)
	cert, err := v.Validate(context.Background(), tok, nonce)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cert.Subject.SerialNumber, "PNOEE-38001085718"))
}

func TestValidateRejectsWrongNonce(t *testing.T) {
	pki := newTestPKI(t)
	v := newTestValidator(t, pki)

	tok := pki.signedToken(t, testOrigin, "nonce-a")
	_, err := v.Validate(context.Background(), tok, "nonce-b")
	qt.Check(t, qt.IsNotNil(err))
}

func TestValidateRejectsWrongOrigin(t *testing.T) {
	pki := newTestPKI(t)
	v := newTestValidator(t, pki)

	tok := pki.signedToken(t, "https://evil.example", "nonce-a")
	_, err := v.Validate(context.Background(), tok, "nonce-a")
	qt.Check(t, qt.IsNotNil(err))
}

func TestValidateRejectsUntrustedCertificate(t *testing.T) {
	pki := newTestPKI(t)
	other := newTestPKI(t)
	// Validator trusts "other" CA, token uses pki's leaf.
	v := newTestValidator(t, other)

	tok := pki.signedToken(t, testOrigin, "nonce-a")
	_, err := v.Validate(context.Background(), tok, "nonce-a")
	qt.Check(t, qt.IsNotNil(err))
}

func TestValidateRejectsTamperedSignature(t *testing.T) {
	pki := newTestPKI(t)
	v := newTestValidator(t, pki)
	const nonce = "nonce-a"

	tok := pki.signedToken(t, testOrigin, nonce)
	raw, _ := base64.StdEncoding.DecodeString(tok.Signature)
	raw[0] ^= 0xff
	tok.Signature = base64.StdEncoding.EncodeToString(raw)

	_, err := v.Validate(context.Background(), tok, nonce)
	qt.Check(t, qt.IsNotNil(err))
}

func TestValidateBuilderRequiresOriginAndCA(t *testing.T) {
	_, err := NewAuthTokenValidatorBuilder().Build()
	qt.Check(t, qt.IsNotNil(err))

	pki := newTestPKI(t)
	_, err = NewAuthTokenValidatorBuilder().
		WithTrustedCertificateAuthorities(pki.caCert).
		Build()
	qt.Check(t, qt.IsNotNil(err))
}

// ensure the marshalled token round-trips through Parse for parity.
func TestSignedTokenParses(t *testing.T) {
	pki := newTestPKI(t)
	tok := pki.signedToken(t, testOrigin, "nonce-a")
	b, err := json.Marshal(tok)
	qt.Assert(t, qt.IsNil(err))
	parsed, err := Parse(b)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(parsed.Algorithm, "ES256"))
}

var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
