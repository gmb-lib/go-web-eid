// Package ocsp implements Web eID OCSP revocation checking: extracting the
// responder URL from a certificate's Authority Information Access extension,
// building nonce-protected OCSP requests, and validating responses (status,
// responder signature, and thisUpdate/nextUpdate freshness).
package ocsp

import (
	"crypto/x509"
	"errors"
)

// errNoOCSPResponder is returned when a certificate has no AIA OCSP URL.
var errNoOCSPResponder = errors.New("certificate has no OCSP responder URL")

// AIAOCSPURL returns the first OCSP responder URL from the certificate's
// Authority Information Access extension (access method 1.3.6.1.5.5.7.48.1),
// which crypto/x509 exposes as OCSPServer.
func AIAOCSPURL(cert *x509.Certificate) (string, error) {
	if len(cert.OCSPServer) == 0 {
		return "", errNoOCSPResponder
	}
	return cert.OCSPServer[0], nil
}
