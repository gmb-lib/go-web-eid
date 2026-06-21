package ocsp

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
	xocsp "golang.org/x/crypto/ocsp"
)

type mockClient struct {
	response []byte
	err      error
}

func (m *mockClient) Do(context.Context, string, []byte, time.Duration) ([]byte, error) {
	return m.response, m.err
}

type ocspPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	leaf   *x509.Certificate
}

func newOCSPPKI(t *testing.T) *ocspPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
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
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		OCSPServer:   []string{"http://ocsp.example/"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	qt.Assert(t, qt.IsNil(err))
	leaf, err := x509.ParseCertificate(leafDER)
	qt.Assert(t, qt.IsNil(err))

	return &ocspPKI{caCert: caCert, caKey: caKey, leaf: leaf}
}

func (p *ocspPKI) response(t *testing.T, status int) []byte {
	t.Helper()
	tmpl := xocsp.Response{
		Status:       status,
		SerialNumber: p.leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	if status == xocsp.Revoked {
		tmpl.RevokedAt = time.Now().Add(-2 * time.Hour)
		tmpl.RevocationReason = xocsp.Unspecified
	}
	der, err := xocsp.CreateResponse(p.caCert, p.caCert, tmpl, p.caKey)
	qt.Assert(t, qt.IsNil(err))
	return der
}

func TestCheckerGood(t *testing.T) {
	pki := newOCSPPKI(t)
	checker := NewChecker(Options{
		Client:            &mockClient{response: pki.response(t, xocsp.Good)},
		NonceDisabledURLs: []string{"http://ocsp.example/"},
	})
	err := checker.Check(context.Background(), pki.leaf, pki.caCert)
	qt.Check(t, qt.IsNil(err))
}

func TestCheckerRevoked(t *testing.T) {
	pki := newOCSPPKI(t)
	checker := NewChecker(Options{
		Client:            &mockClient{response: pki.response(t, xocsp.Revoked)},
		NonceDisabledURLs: []string{"http://ocsp.example/"},
	})
	err := checker.Check(context.Background(), pki.leaf, pki.caCert)
	qt.Check(t, qt.IsNotNil(err))
}

func TestCheckerStaleResponse(t *testing.T) {
	pki := newOCSPPKI(t)
	tmpl := xocsp.Response{
		Status:       xocsp.Good,
		SerialNumber: pki.leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-48 * time.Hour),
		NextUpdate:   time.Now().Add(-24 * time.Hour),
	}
	der, err := xocsp.CreateResponse(pki.caCert, pki.caCert, tmpl, pki.caKey)
	qt.Assert(t, qt.IsNil(err))

	checker := NewChecker(Options{
		Client:            &mockClient{response: der},
		NonceDisabledURLs: []string{"http://ocsp.example/"},
	})
	err = checker.Check(context.Background(), pki.leaf, pki.caCert)
	qt.Check(t, qt.IsNotNil(err))
}
