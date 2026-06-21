package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

func testCert(t *testing.T, serialNumber string, policies []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "TEST PERSON",
			SerialNumber: serialNumber,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	// Go 1.24+ defaults GODEBUG x509usepolicies=1, so CreateCertificate builds
	// the certificatePolicies extension from Policies ([]x509.OID) and ignores
	// the deprecated PolicyIdentifiers. Populate the new field.
	for _, p := range policies {
		ints := make([]uint64, len(p))
		for i, v := range p {
			ints[i] = uint64(v)
		}
		oid, err := x509.OIDFromInts(ints)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.Policies = append(tmpl.Policies, oid)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestParseOID(t *testing.T) {
	oid, err := ParseOID("0.4.0.194112.1.2")
	if err != nil {
		t.Fatal(err)
	}
	if !oid.Equal(OIDQCPNaturalQSCD) {
		t.Fatalf("got %v", oid)
	}
	for _, bad := range []string{"", "1", "a.b.c", "1.-2.3"} {
		if _, err := ParseOID(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestCheckSameNaturalPerson(t *testing.T) {
	auth := testCert(t, "PNOLV-321846-14724", nil)
	signSame := testCert(t, "PNOLV-321846-14724", nil)
	signOther := testCert(t, "PNOLV-999999-00000", nil)
	orgSeal := testCert(t, "NTRLV-40003011203", nil)

	checked, err := CheckSameNaturalPerson(auth, signSame)
	if !checked || err != nil {
		t.Fatalf("same person must bind: checked=%v err=%v", checked, err)
	}

	checked, err = CheckSameNaturalPerson(auth, signOther)
	if !checked || !errors.Is(err, exceptions.ErrIdentityBindingMismatch) {
		t.Fatalf("different persons must mismatch: checked=%v err=%v", checked, err)
	}

	checked, err = CheckSameNaturalPerson(auth, orgSeal)
	if checked || err != nil {
		t.Fatalf("organisational seal must skip the person binding: checked=%v err=%v", checked, err)
	}
}

func TestCheckAcceptedPolicies(t *testing.T) {
	// Real-world shape: each LVRTC card product asserts ITS OWN policy, so the
	// acceptance gate must be any-of across the product family.
	eidKarte := testCert(t, "PNOLV-1", []asn1.ObjectIdentifier{OIDLVEIDKarte1})
	eParKartePlus := testCert(t, "PNOLV-1", []asn1.ObjectIdentifier{OIDLVEParakstsKartePlus})
	nonQSCD := testCert(t, "PNOLV-1", []asn1.ObjectIdentifier{OIDLVEIDKarteNoQSCD, OIDQCPNatural})

	accepted := LVCardQSCDSigningPolicies()

	if err := CheckAcceptedPolicies(eidKarte, accepted); err != nil {
		t.Fatalf("eID karte (QSCD) must pass the any-of gate: %v", err)
	}
	if err := CheckAcceptedPolicies(eParKartePlus, accepted); err != nil {
		t.Fatalf("eParaksts karte+ (QSCD) must pass the any-of gate: %v", err)
	}
	if err := CheckAcceptedPolicies(nonQSCD, accepted); err == nil {
		t.Fatal("non-QSCD card cert must fail the QSCD acceptance gate")
	}
	if err := CheckAcceptedPolicies(nonQSCD, nil); err != nil {
		t.Fatalf("empty acceptance list must pass: %v", err)
	}

	// Generic ETSI gate still works as a single-entry any-of list.
	etsiQSCD := testCert(t, "PNOLV-1", []asn1.ObjectIdentifier{OIDQCPNaturalQSCD})
	if err := CheckAcceptedPolicies(etsiQSCD, []asn1.ObjectIdentifier{OIDQCPNaturalQSCD}); err != nil {
		t.Fatalf("ETSI QCP-n-qscd cert must pass: %v", err)
	}
}
