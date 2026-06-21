package webeid

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-web-eid/ocsp"
)

// minimalCA returns a self-signed CA usable only to satisfy the trust-anchor
// requirement of Build.
func minimalCA(t *testing.T) *x509.Certificate {
	t.Helper()
	pki := newTestPKI(t)
	return pki.caCert
}

type stubOCSPClient struct{}

func (stubOCSPClient) Do(context.Context, string, []byte, time.Duration) ([]byte, error) {
	return nil, nil
}

func TestBuilderAllOptions(t *testing.T) {
	ca := minimalCA(t)
	policy := asn1.ObjectIdentifier{1, 2, 3, 4}

	v, err := NewAuthTokenValidatorBuilder().
		WithSiteOrigin("https://example.org").
		WithTrustedCertificateAuthorities(ca).
		WithDesignatedOcspServiceConfiguration(&ocsp.DesignatedServiceConfiguration{URL: "http://ocsp"}).
		WithOcspClient(stubOCSPClient{}).
		WithOcspRequestTimeout(3 * time.Second).
		WithDisallowedCertificatePolicies(policy).
		WithNonceDisabledOcspUrls("http://ocsp").
		WithAllowedOcspResponseTimeSkew(time.Minute).
		WithMaxOcspResponseThisUpdateAge(time.Minute).
		Build()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(v))
}

func TestBuilderRejectsNonHTTPSOrigin(t *testing.T) {
	ca := minimalCA(t)
	_, err := NewAuthTokenValidatorBuilder().
		WithSiteOrigin("http://example.org").
		WithTrustedCertificateAuthorities(ca).
		Build()
	qt.Check(t, qt.IsNotNil(err))
}

func TestBuilderRejectsOriginWithPath(t *testing.T) {
	ca := minimalCA(t)
	_, err := NewAuthTokenValidatorBuilder().
		WithSiteOrigin("https://example.org/app").
		WithTrustedCertificateAuthorities(ca).
		Build()
	qt.Check(t, qt.IsNotNil(err))
}
