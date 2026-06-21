package certificate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// bytesReaderHelper wraps a byte slice in an io.Reader for the loaders.
func bytesReaderHelper(b []byte) io.Reader { return bytes.NewReader(b) }

// certOptions configures the test certificate factory.
type certOptions struct {
	notBefore   time.Time
	notAfter    time.Time
	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
	policies    []asn1.ObjectIdentifier
	subject     pkix.Name
	isCA        bool
}

// makeCert builds a self-signed (or CA-signed) certificate for tests.
func makeCert(t *testing.T, opts certOptions, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      opts.subject,
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		KeyUsage:     opts.keyUsage,
		ExtKeyUsage:  opts.extKeyUsage,
	}
	if opts.isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if len(opts.policies) > 0 {
		oids := make([]x509.OID, 0, len(opts.policies))
		for _, p := range opts.policies {
			ints := make([]uint64, len(p))
			for i, v := range p {
				ints[i] = uint64(v)
			}
			oid, err := x509.OIDFromInts(ints)
			qt.Assert(t, qt.IsNil(err))
			oids = append(oids, oid)
		}
		tmpl.Policies = oids
	}

	signer := tmpl
	signerKey := key
	if parent != nil {
		signer = parent
		signerKey = parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, key.Public(), signerKey)
	qt.Assert(t, qt.IsNil(err))
	cert, err := x509.ParseCertificate(der)
	qt.Assert(t, qt.IsNil(err))
	return cert, key
}

func TestCheckValidity(t *testing.T) {
	now := time.Now()

	valid, _ := makeCert(t, certOptions{}, nil, nil)
	qt.Check(t, qt.IsNil(CheckValidity(valid, now)))

	expired, _ := makeCert(t, certOptions{
		notBefore: now.Add(-2 * time.Hour),
		notAfter:  now.Add(-time.Hour),
	}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckValidity(expired, now)))

	future, _ := makeCert(t, certOptions{
		notBefore: now.Add(time.Hour),
		notAfter:  now.Add(2 * time.Hour),
	}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckValidity(future, now)))
}

func TestCheckKeyUsageForAuthentication(t *testing.T) {
	good, _ := makeCert(t, certOptions{
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, nil, nil)
	qt.Check(t, qt.IsNil(CheckKeyUsageForAuthentication(good)))

	wrongUsage, _ := makeCert(t, certOptions{
		keyUsage:    x509.KeyUsageContentCommitment,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckKeyUsageForAuthentication(wrongUsage)))

	wrongEKU, _ := makeCert(t, certOptions{
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckKeyUsageForAuthentication(wrongEKU)))
}

func TestCheckKeyUsageForSigning(t *testing.T) {
	good, _ := makeCert(t, certOptions{keyUsage: x509.KeyUsageContentCommitment}, nil, nil)
	qt.Check(t, qt.IsNil(CheckKeyUsageForSigning(good)))

	bad, _ := makeCert(t, certOptions{keyUsage: x509.KeyUsageDigitalSignature}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckKeyUsageForSigning(bad)))

	// A certificate that does not assert content-commitment is rejected.
	none, _ := makeCert(t, certOptions{}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckKeyUsageForSigning(none)))
}

func TestCheckKeyUsageForAuthenticationStrict(t *testing.T) {
	// No key usage and no EKU at all must be rejected (not permissive).
	noUsage, _ := makeCert(t, certOptions{}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckKeyUsageForAuthentication(noUsage)))

	// digitalSignature but no EKU must be rejected.
	noEKU, _ := makeCert(t, certOptions{keyUsage: x509.KeyUsageDigitalSignature}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckKeyUsageForAuthentication(noEKU)))
}

func TestCheckDisallowedPolicies(t *testing.T) {
	mobileID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 10015, 1, 3}
	other := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 10015, 1, 1}

	withMobileID, _ := makeCert(t, certOptions{policies: []asn1.ObjectIdentifier{mobileID}}, nil, nil)
	qt.Check(t, qt.IsNotNil(CheckDisallowedPolicies(withMobileID, DefaultDisallowedPolicies)))

	withOther, _ := makeCert(t, certOptions{policies: []asn1.ObjectIdentifier{other}}, nil, nil)
	qt.Check(t, qt.IsNil(CheckDisallowedPolicies(withOther, DefaultDisallowedPolicies)))

	noPolicies, _ := makeCert(t, certOptions{}, nil, nil)
	qt.Check(t, qt.IsNil(CheckDisallowedPolicies(noPolicies, DefaultDisallowedPolicies)))

	// Empty disallow list is always a pass.
	qt.Check(t, qt.IsNil(CheckDisallowedPolicies(withMobileID, nil)))
}

func TestSubjectExtraction(t *testing.T) {
	cert, _ := makeCert(t, certOptions{
		subject: pkix.Name{
			CommonName:   "JÕEORG,JAAK-KRISTJAN,38001085718",
			SerialNumber: "PNOEE-38001085718",
			Country:      []string{"EE"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "JAAK-KRISTJAN"}, // givenName
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "JÕEORG"},         // surname
			},
		},
	}, nil, nil)

	cn, err := SubjectCN(cert)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cn, "JÕEORG,JAAK-KRISTJAN,38001085718"))

	id, err := SubjectIDCode(cert)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(id, "PNOEE-38001085718"))

	cc, err := SubjectCountryCode(cert)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cc, "EE"))

	gn, err := SubjectGivenName(cert)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(gn, "JAAK-KRISTJAN"))

	sn, err := SubjectSurname(cert)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sn, "JÕEORG"))
}

func TestSubjectExtractionMissingFields(t *testing.T) {
	cert, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: ""}}, nil, nil)

	_, err := SubjectCN(cert)
	qt.Check(t, qt.IsNotNil(err))
	_, err = SubjectIDCode(cert)
	qt.Check(t, qt.IsNotNil(err))
	_, err = SubjectCountryCode(cert)
	qt.Check(t, qt.IsNotNil(err))
	_, err = SubjectGivenName(cert)
	qt.Check(t, qt.IsNotNil(err))
	_, err = SubjectSurname(cert)
	qt.Check(t, qt.IsNotNil(err))
}

func TestNewTrustStoreAndVerify(t *testing.T) {
	ca, caKey := makeCert(t, certOptions{
		subject: pkix.Name{CommonName: "TEST CA"},
		isCA:    true,
	}, nil, nil)

	leaf, _ := makeCert(t, certOptions{
		subject:     pkix.Name{CommonName: "leaf"},
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca, caKey)

	ts, err := NewTrustStore(ca)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(ts.Intermediates()), 1))

	qt.Check(t, qt.IsNil(ts.Verify(leaf, time.Now(), x509.ExtKeyUsageClientAuth)))
	qt.Check(t, qt.IsTrue(ts.IssuerOf(leaf) != nil))

	// A leaf from a different CA is not trusted.
	otherCA, otherKey := makeCert(t, certOptions{subject: pkix.Name{CommonName: "OTHER"}, isCA: true}, nil, nil)
	otherLeaf, _ := makeCert(t, certOptions{
		subject:     pkix.Name{CommonName: "other-leaf"},
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, otherCA, otherKey)
	qt.Check(t, qt.IsNotNil(ts.Verify(otherLeaf, time.Now(), x509.ExtKeyUsageClientAuth)))
	qt.Check(t, qt.IsTrue(ts.IssuerOf(otherLeaf) == nil))
}

func TestNewTrustStoreRequiresAnchors(t *testing.T) {
	_, err := NewTrustStore()
	qt.Check(t, qt.IsNotNil(err))
}

func TestLoadCertificatesFromPEM(t *testing.T) {
	ca, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "PEM CA"}, isCA: true}, nil, nil)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})

	certs, err := LoadCertificatesFromPEM(bytesReaderHelper(pemBytes))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(certs), 1))

	_, err = LoadCertificatesFromPEM(bytesReaderHelper([]byte("not a pem")))
	qt.Check(t, qt.IsNotNil(err))
}

func TestLoadCertificatesFromDERAndDir(t *testing.T) {
	dir := t.TempDir()
	ca, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "DIR CA"}, isCA: true}, nil, nil)

	derPath := filepath.Join(dir, "ca.der")
	qt.Assert(t, qt.IsNil(os.WriteFile(derPath, ca.Raw, 0o600)))

	certs, err := LoadCertificatesFromDER(derPath)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(certs), 1))

	// A second cert as PEM in the same dir.
	leafCA, _ := makeCert(t, certOptions{subject: pkix.Name{CommonName: "DIR CA 2"}, isCA: true}, nil, nil)
	pemPath := filepath.Join(dir, "ca2.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCA.Raw})
	qt.Assert(t, qt.IsNil(os.WriteFile(pemPath, pemBytes, 0o600)))

	dirCerts, err := LoadCertificatesFromDir(dir)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(dirCerts), 2))
}

func TestLoadCertificatesFromDirEmpty(t *testing.T) {
	_, err := LoadCertificatesFromDir(t.TempDir())
	qt.Check(t, qt.IsNotNil(err))
}
