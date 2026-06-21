package ocsp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/go-quicktest/qt"
	xocsp "golang.org/x/crypto/ocsp"
)

func TestGenerateNonceLength(t *testing.T) {
	n1, err := generateNonce()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(n1), 16))

	n2, err := generateNonce()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(string(n1) == string(n2)))
}

func TestBuildRequestRoundTrips(t *testing.T) {
	pki := newOCSPPKI(t)
	nonce := []byte{1, 2, 3, 4}

	der, err := buildRequest(pki.leaf, pki.caCert, nonce)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(len(der) > 0))

	// The DER must be a well-formed structure that unmarshals back.
	var req ocspRequest
	rest, err := asn1.Unmarshal(der, &req)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(rest), 0))
	qt.Assert(t, qt.Equals(len(req.TBSRequest.RequestExtensions), 1))
	qt.Check(t, qt.IsTrue(req.TBSRequest.RequestExtensions[0].Id.Equal(oidOCSPNonce)))
}

func TestBuildRequestWithoutNonce(t *testing.T) {
	pki := newOCSPPKI(t)
	der, err := buildRequest(pki.leaf, pki.caCert, nil)
	qt.Assert(t, qt.IsNil(err))

	var req ocspRequest
	_, err = asn1.Unmarshal(der, &req)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(req.TBSRequest.RequestExtensions), 0))
}

func TestResponseNonce(t *testing.T) {
	resp := &xocsp.Response{
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{9}},
			{Id: oidOCSPNonce, Value: []byte{7, 7}},
		},
	}
	qt.Check(t, qt.DeepEquals(responseNonce(resp), []byte{7, 7}))

	empty := &xocsp.Response{}
	qt.Check(t, qt.IsNil(responseNonce(empty)))
}
