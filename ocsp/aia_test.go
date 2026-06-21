package ocsp

import (
	"crypto/x509"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestAIAOCSPURL(t *testing.T) {
	cert := &x509.Certificate{OCSPServer: []string{"http://ocsp.example/"}}
	url, err := AIAOCSPURL(cert)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(url, "http://ocsp.example/"))

	_, err = AIAOCSPURL(&x509.Certificate{})
	qt.Check(t, qt.IsNotNil(err))
}

func TestDesignatedSupports(t *testing.T) {
	issuerA := &x509.Certificate{Raw: []byte{1}}
	issuerB := &x509.Certificate{Raw: []byte{2}}

	// Empty SupportedIssuers means it covers every issuer.
	any := &DesignatedServiceConfiguration{URL: "http://ocsp"}
	qt.Check(t, qt.IsTrue(any.Supports(issuerA)))

	// Scoped to issuerA only.
	scoped := &DesignatedServiceConfiguration{
		URL:              "http://ocsp",
		SupportedIssuers: []*x509.Certificate{issuerA},
	}
	qt.Check(t, qt.IsTrue(scoped.Supports(issuerA)))
	qt.Check(t, qt.IsFalse(scoped.Supports(issuerB)))

	// Nil receiver never supports.
	var nilCfg *DesignatedServiceConfiguration
	qt.Check(t, qt.IsFalse(nilCfg.Supports(issuerA)))
}
