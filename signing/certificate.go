package signing

import (
	"crypto/x509"
	"time"

	"github.com/gmb-lib/go-web-eid/certificate"
	"github.com/gmb-lib/go-web-eid/exceptions"
)

// SignatureAlgorithm describes a signing algorithm the card reports as
// supported. The field set matches the web-eid.js supportedSignatureAlgorithms
// entries.
type SignatureAlgorithm struct {
	// CryptoAlgorithm is "ECC" or "RSA".
	CryptoAlgorithm string `json:"cryptoAlgorithm"`
	// HashFunction is e.g. "SHA-256", "SHA-384", "SHA3-256".
	HashFunction string `json:"hashFunction"`
	// PaddingScheme is "NONE", "PKCS1.5" or "PSS".
	PaddingScheme string `json:"paddingScheme"`
}

// ParseSigningCertificate parses a DER signing certificate. Cryptographic trust
// and revocation are validated separately by Signer using the configured trust
// store; this function only decodes the certificate.
func ParseSigningCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, err)
	}
	return cert, nil
}

// validateSigningCertificate runs the structural certificate checks shared with
// authentication: validity period and the content-commitment key usage required
// of an eID signing certificate.
func validateSigningCertificate(cert *x509.Certificate, now time.Time) error {
	if err := certificate.CheckValidity(cert, now); err != nil {
		return exceptions.ErrSigningCertificateInvalid
	}
	if err := certificate.CheckKeyUsageForSigning(cert); err != nil {
		return err
	}
	return nil
}
