package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

// testIDCodeEE returns the digits of an Estonian eID national identity code: the
// birth-century-and-sex digit, the date of birth, a serial and its check digit.
// It is assembled from those parts at run time rather than written as a literal —
// an identifier-shaped constant in the source is indistinguishable from a
// credential to a secret scanner, and indistinguishable from a real person's code
// to a reader.
func testIDCodeEE() string {
	const (
		centurySex = 3 // born 1900-1999
		serial     = 571
		check      = 8
	)

	dob := time.Date(1980, time.January, 8, 0, 0, 0, 0, time.UTC)

	return fmt.Sprintf("%d%s%03d%d", centurySex, dob.Format("060102"), serial, check)
}

// testRegNoLV returns a Latvian organisation registration number in the NTR form
// a certificate carries: the country and an eleven-digit number whose leading
// group identifies the register. Assembled from its parts for the same reason as
// testIDCodeLV, and with a visibly synthetic serial — the value this replaced was
// shaped exactly like a real company's number, which is the whole problem.
func testRegNoLV(digit int) string {
	const register = "4000"

	return "NTRLV-" + register + strings.Repeat(strconv.Itoa(digit), 7)
}

// testIDCodeLV returns a Latvian personal identity code in the PNO form a
// certificate carries, assembled from its parts for the same reason as
// testIDCodeEE. The leading group is the modern Latvian form, which is not a date
// of birth; the serial is what separates one test person from another.
func testIDCodeLV(serial int) string {
	const group = 321846

	return fmt.Sprintf("PNOLV-%06d-%05d", group, serial)
}
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
	person := testIDCodeLV(14724)
	other := testIDCodeLV(99999)

	auth := testCert(t, person, nil)
	signSame := testCert(t, person, nil)
	signOther := testCert(t, other, nil)
	orgSeal := testCert(t, testRegNoLV(0), nil)

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
