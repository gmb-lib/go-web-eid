package certificate

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"

	"encoding/asn1"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

// Well-known ETSI EN 319 411-2 certificate-policy OIDs, useful when gating
// signing certificates by QSCD assurance (Latvian deployment profile).
var (
	// OIDQCPNatural is QCP-n: qualified certificate for a natural person,
	// private key NOT on a QSCD (0.4.0.194112.1.0).
	OIDQCPNatural = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 0}
	// OIDQCPNaturalQSCD is QCP-n-qscd: qualified certificate for a natural
	// person with the private key on a QSCD (0.4.0.194112.1.2) — the policy a
	// QES-grade eID signing certificate asserts.
	OIDQCPNaturalQSCD = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 2}
	// OIDQCPLegalQSCD is QCP-l-qscd: qualified certificate for a legal person
	// with the private key on a QSCD (0.4.0.194112.1.3) — asserted by
	// qualified electronic-seal certificates.
	OIDQCPLegalQSCD = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 3}
)

// LVRTC (eParaksts) certificate-policy OIDs under the official arc
// 1.3.6.1.4.1.32061, per the LVRTC certification-practice policy table.
// "QSCD" marks the policies the CPS lists with QSCD = Jā.
var (
	// OIDLVEIDKarte1 / OIDLVEIDKarte2 — "eID karte" policies, QSCD.
	OIDLVEIDKarte1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32061, 2, 1, 2, 1}
	OIDLVEIDKarte2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32061, 2, 1, 2, 2}
	// OIDLVEIDKarteNoQSCD — "eID karte (bez QSCD)". NOTE: the CPS table also
	// shows this OID under the QSCD "eID karte" row — treat it as NON-QSCD
	// (exclude from QES gates) until LVRTC clarifies the duplication.
	OIDLVEIDKarteNoQSCD = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32061, 2, 1, 2, 3}
	// OIDLVEParaksts — "eParaksts" (cloud-held natural-person QES), QSCD.
	OIDLVEParaksts = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32061, 2, 1, 3, 2}
	// OIDLVEParakstsKarte — "eParaksts karte", QSCD.
	OIDLVEParakstsKarte = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32061, 2, 1, 4, 1}
	// OIDLVEParakstsKartePlus — "eParaksts karte+", QSCD.
	OIDLVEParakstsKartePlus = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32061, 2, 1, 5, 1}
	// OIDLVEZimogs — shared "eZīmogs"/"eZīmogs+" seal policy. NOTE: the CPS
	// lists the same OID for the non-QSCD eZīmogs and the QSCD eZīmogs+, so
	// the policy OID alone cannot distinguish seal QSCD status — use the
	// QcStatements / ETSI QCP-l-qscd where that distinction matters.
	OIDLVEZimogs = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32061, 2, 2, 1, 1}
	// OIDLVEZimogsPlusCloud — "eZīmogs+ mākonī" (cloud qualified seal), QSCD.
	OIDLVEZimogsPlusCloud = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32061, 2, 2, 2, 1}
)

// LVCardQSCDSigningPolicies returns the LVRTC smartcard QSCD signing-product
// policies — the recommended any-of acceptance set for Web eID card signing in
// Latvia (eID karte ×2, eParaksts karte, eParaksts karte+). The ambiguous
// OIDLVEIDKarteNoQSCD is deliberately excluded.
func LVCardQSCDSigningPolicies() []asn1.ObjectIdentifier {
	return []asn1.ObjectIdentifier{
		OIDLVEIDKarte1,
		OIDLVEIDKarte2,
		OIDLVEParakstsKarte,
		OIDLVEParakstsKartePlus,
	}
}

// ParseOID parses a dotted-decimal OID string (e.g. "0.4.0.194112.1.2").
func ParseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q: component %q", s, p)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

// ParseOIDs parses a list of dotted-decimal OID strings.
func ParseOIDs(values []string) ([]asn1.ObjectIdentifier, error) {
	if len(values) == 0 {
		return nil, nil
	}
	oids := make([]asn1.ObjectIdentifier, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		oid, err := ParseOID(v)
		if err != nil {
			return nil, err
		}
		oids = append(oids, oid)
	}
	return oids, nil
}

// CheckAcceptedPolicies fails unless the certificate asserts AT LEAST ONE of
// the accepted certificate-policy OIDs (any-of semantics). An empty accepted
// list passes. Use it to gate signing certificates by assurance: real QTSP
// product families assert one product-specific policy each (e.g. the LVRTC
// QSCD card products below), so an acceptance gate must be any-of — a list of
// every acceptable product policy, optionally alongside the generic ETSI QCP
// OIDs.
func CheckAcceptedPolicies(cert *x509.Certificate, accepted []asn1.ObjectIdentifier) error {
	if len(accepted) == 0 {
		return nil
	}
	present, err := extractPolicies(cert)
	if err != nil {
		return exceptions.Wrap(exceptions.ErrCertificateDisallowedPolicy, err)
	}
	for _, want := range accepted {
		for _, have := range present {
			if have.Equal(want) {
				return nil
			}
		}
	}
	return exceptions.ErrCertificateDisallowedPolicy
}

// naturalPersonIDPrefix is the ETSI EN 319 412-1 semantics identifier prefix
// for natural-person serialNumber values (e.g. "PNOLV-321846-14724",
// "PNOEE-38001085718").
const naturalPersonIDPrefix = "PNO"

// CheckSameNaturalPerson asserts that two certificates belong to the same
// natural person by comparing their subject serialNumber attributes. It is the
// identity-binding check between an authentication certificate and a signing
// certificate.
//
// The comparison is enforced only when BOTH serialNumbers carry the ETSI
// natural-person semantics prefix ("PNO…"): organisational certificates (e.g. a
// smartcard eSeal with an "NTR…" legal-person identifier) are out of scope for
// a person-binding check, so checked=false is returned and the caller decides
// how to authorise the seal. checked=true with a nil error means the binding
// held.
func CheckSameNaturalPerson(a, b *x509.Certificate) (checked bool, err error) {
	if a == nil || b == nil {
		return false, exceptions.ErrIdentityBindingMismatch
	}
	idA := a.Subject.SerialNumber
	idB := b.Subject.SerialNumber
	if !strings.HasPrefix(idA, naturalPersonIDPrefix) || !strings.HasPrefix(idB, naturalPersonIDPrefix) {
		return false, nil
	}
	if idA != idB {
		return true, exceptions.ErrIdentityBindingMismatch
	}
	return true, nil
}
