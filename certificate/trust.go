package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

// LoadCertificatesFromPEM reads one or more PEM-encoded certificates from r.
func LoadCertificatesFromPEM(r io.Reader) ([]*x509.Certificate, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in PEM data")
	}
	return certs, nil
}

// LoadCertificatesFromDER reads DER-encoded certificates from the given file
// paths (one certificate per file).
func LoadCertificatesFromDER(paths ...string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(paths))
	for _, path := range paths {
		der, err := os.ReadFile(path) //nolint:gosec // caller-controlled trust material
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse DER certificate %q: %w", path, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// LoadCertificatesFromDir loads every.pem/.crt/.cer/.der file from a directory
// as trust anchors. PEM and DER encodings are both accepted.
func LoadCertificatesFromDir(dir string) ([]*x509.Certificate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := fmt.Sprintf("%s/%s", dir, entry.Name())
		data, err := os.ReadFile(path) //nolint:gosec // caller-controlled trust material
		if err != nil {
			return nil, err
		}
		if block, _ := pem.Decode(data); block != nil {
			parsed, err := LoadCertificatesFromPEM(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			certs = append(certs, parsed...)
			continue
		}
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %q: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %q", dir)
	}
	return certs, nil
}

// TrustStore holds the configured intermediate trust anchors and verifies that
// a user certificate chains to one of them.
type TrustStore struct {
	intermediates []*x509.Certificate
	pool          *x509.CertPool
}

// NewTrustStore builds a trust store from intermediate CA certificates.
//
// The anchors are intermediate CAs (e.g. ESTEID2018) rather than roots, so a
// revoked intermediate can be removed without touching the roots.
func NewTrustStore(intermediates ...*x509.Certificate) (*TrustStore, error) {
	if len(intermediates) == 0 {
		return nil, errors.New("at least one trusted CA certificate is required")
	}
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	return &TrustStore{
		intermediates: intermediates,
		pool:          pool,
	}, nil
}

// Intermediates returns the configured intermediate CA certificates.
func (ts *TrustStore) Intermediates() []*x509.Certificate { return ts.intermediates }

// IssuerOf returns the configured intermediate CA that issued the given
// certificate, or nil if none matches. It is used to locate the OCSP issuer.
func (ts *TrustStore) IssuerOf(cert *x509.Certificate) *x509.Certificate {
	for _, ca := range ts.intermediates {
		if err := cert.CheckSignatureFrom(ca); err == nil {
			return ca
		}
	}
	return nil
}

// Verify confirms the certificate chains to a configured trust anchor and is
// valid for the supplied key usages at time now.
func (ts *TrustStore) Verify(cert *x509.Certificate, now time.Time, keyUsages ...x509.ExtKeyUsage) error {
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	opts := x509.VerifyOptions{
		Roots:         ts.pool,
		Intermediates: ts.pool,
		CurrentTime:   now,
		KeyUsages:     keyUsages,
	}
	if _, err := cert.Verify(opts); err != nil {
		return exceptions.Wrap(exceptions.ErrCertificateNotTrusted, err)
	}
	return nil
}
