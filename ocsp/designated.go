package ocsp

import (
	"crypto/x509"
)

// DesignatedServiceConfiguration describes a designated OCSP responder that
// overrides the AIA responder for the issuers it supports.
//
// This mirrors the Java DesignatedOcspServiceConfiguration option.
type DesignatedServiceConfiguration struct {
	// URL is the designated responder endpoint.
	URL string
	// ResponderCertificate is the certificate used to verify responses, when
	// the responder is not the issuer itself.
	ResponderCertificate *x509.Certificate
	// SupportedIssuers are the issuer CA certificates this responder covers.
	// An empty slice means the responder applies to every issuer.
	SupportedIssuers []*x509.Certificate
	// NonceDisabled indicates the responder does not support the OCSP nonce
	// extension and requests must omit it.
	NonceDisabled bool
}

// Supports reports whether the designated responder covers the given issuer.
func (d *DesignatedServiceConfiguration) Supports(issuer *x509.Certificate) bool {
	if d == nil {
		return false
	}
	if len(d.SupportedIssuers) == 0 {
		return true
	}
	for _, ca := range d.SupportedIssuers {
		if ca.Equal(issuer) {
			return true
		}
	}
	return false
}
