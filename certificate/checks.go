// Package certificate provides X.509 helpers for the Web eID validation
// pipeline: trust-anchor loading and chain verification, validity / key-usage /
// extended-key-usage / certificate-policy checks, and subject-data extraction.
package certificate

import (
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

// Certificate Policies extension OID (RFC 5280, 2.5.29.32). crypto/x509 does
// not expose policy filtering, so it is parsed manually.
var oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

// DefaultDisallowedPolicies lists the Estonian Mobile-ID certificate policy
// OIDs. Disallowing them by default prevents a Mobile-ID certificate from
// masquerading as a smart-card certificate.
//
// Source: Estonian Mobile-ID policy arcs under 1.3.6.1.4.1.10015.
var DefaultDisallowedPolicies = []asn1.ObjectIdentifier{
	{1, 3, 6, 1, 4, 1, 10015, 1, 3},  // ESTEID Mobile-ID
	{1, 3, 6, 1, 4, 1, 10015, 11, 1}, // ESTEID Mobile-ID (newer arc)
}

// policyInformation models a single PolicyInformation entry of the Certificate
// Policies extension. Only the policy identifier is needed.
type policyInformation struct {
	Policy asn1.ObjectIdentifier
	// Qualifiers are intentionally ignored.
	Qualifiers asn1.RawValue `asn1:"optional"`
}

// CheckValidity verifies the certificate's validity window contains now.
func CheckValidity(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return exceptions.ErrCertificateNotYetValid
	}
	if now.After(cert.NotAfter) {
		return exceptions.ErrCertificateExpired
	}
	return nil
}

// CheckKeyUsageForAuthentication ensures the certificate may be used for client
// authentication: it must assert the digital-signature key usage AND the
// client-authentication extended key usage. Both are required (not merely
// "if present"), matching the reference validators — an eID authentication
// certificate always carries them.
func CheckKeyUsageForAuthentication(cert *x509.Certificate) error {
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return exceptions.ErrUserCertificateWrongPurpose
	}
	if !hasExtKeyUsage(cert, x509.ExtKeyUsageClientAuth) {
		return exceptions.ErrUserCertificateWrongPurpose
	}
	return nil
}

// CheckKeyUsageForSigning ensures the certificate asserts the content-commitment
// (non-repudiation) key usage, as required of an eID signing certificate. The
// usage is required: a certificate that does not assert it is rejected.
func CheckKeyUsageForSigning(cert *x509.Certificate) error {
	if cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		return exceptions.ErrSigningCertificateInvalid
	}
	return nil
}

// hasExtKeyUsage reports whether the certificate explicitly carries the given
// EKU (or the any-EKU wildcard). An empty EKU list is NOT treated as
// permissive: an eID authentication certificate must declare client
// authentication.
func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == want || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// CheckDisallowedPolicies fails if the certificate asserts any of the disallowed
// certificate policy OIDs.
func CheckDisallowedPolicies(cert *x509.Certificate, disallowed []asn1.ObjectIdentifier) error {
	if len(disallowed) == 0 {
		return nil
	}
	policies, err := extractPolicies(cert)
	if err != nil {
		return exceptions.Wrap(exceptions.ErrCertificateDisallowedPolicy, err)
	}
	for _, present := range policies {
		for _, bad := range disallowed {
			if present.Equal(bad) {
				return exceptions.ErrCertificateDisallowedPolicy
			}
		}
	}
	return nil
}

// extractPolicies parses the Certificate Policies extension and returns the
// asserted policy OIDs. A certificate without the extension yields no policies.
func extractPolicies(cert *x509.Certificate) ([]asn1.ObjectIdentifier, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidCertificatePolicies) {
			continue
		}
		var infos []policyInformation
		if _, err := asn1.Unmarshal(ext.Value, &infos); err != nil {
			return nil, err
		}
		oids := make([]asn1.ObjectIdentifier, 0, len(infos))
		for _, info := range infos {
			oids = append(oids, info.Policy)
		}
		return oids, nil
	}
	return nil, nil
}
