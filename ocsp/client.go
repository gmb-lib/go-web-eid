package ocsp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is the standard OCSP CertID hash, not a security boundary
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/gmb-lib/go-web-eid/exceptions"
	xocsp "golang.org/x/crypto/ocsp"
)

// oidOCSPNonce is the OCSP nonce extension identifier (1.3.6.1.5.5.7.48.1.2).
var oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// oidSHA1 is the AlgorithmIdentifier OID for SHA-1, used in the OCSP CertID.
var oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

// Client sends an OCSP request for a certificate and returns the responder's
// raw response bytes. It is injectable so callers can supply custom transport
// (for example the Azugo context HTTP client).
type Client interface {
	// Do POSTs an application/ocsp-request body to responderURL and returns the
	// raw application/ocsp-response body.
	Do(ctx context.Context, responderURL string, request []byte, timeout time.Duration) ([]byte, error)
}

// HTTPClient is the default net/http-based OCSP transport.
type HTTPClient struct {
	// Transport is the underlying RoundTripper. If nil, http.DefaultTransport
	// is used.
	Transport http.RoundTripper
}

// Do implements Client.
func (c *HTTPClient) Do(ctx context.Context, responderURL string, request []byte, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, responderURL, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	transport := c.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	resp, err := (&http.Client{Transport: transport}).Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP responder returned HTTP %d", resp.StatusCode)
	}
	// Cap the response body to a sane size to avoid resource exhaustion.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// certID is the ASN.1 CertID used inside an OCSP request.
type certID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// request is the ASN.1 Request entry of a TBSRequest.
type request struct {
	Cert certID
}

// tbsRequest is the to-be-signed portion of an OCSP request.
type tbsRequest struct {
	RequestList       []request
	RequestExtensions []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

// ocspRequest is the top-level OCSP request structure.
type ocspRequest struct {
	TBSRequest tbsRequest
}

// publicKeyInfo extracts the BIT STRING subjectPublicKey from a certificate's
// SubjectPublicKeyInfo, needed for the CertID issuerKeyHash.
type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// buildRequest constructs an OCSP request for cert issued by issuer. When nonce
// is non-nil it is included as a request extension.
func buildRequest(cert, issuer *x509.Certificate, nonce []byte) ([]byte, error) {
	var pki publicKeyInfo
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &pki); err != nil {
		return nil, fmt.Errorf("parse issuer public key info: %w", err)
	}

	nameHash := sha1.Sum(issuer.RawSubject)         //nolint:gosec // OCSP CertID
	keyHash := sha1.Sum(pki.PublicKey.RightAlign()) //nolint:gosec // OCSP CertID

	tbs := tbsRequest{
		RequestList: []request{{
			Cert: certID{
				HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: oidSHA1},
				IssuerNameHash: nameHash[:],
				IssuerKeyHash:  keyHash[:],
				SerialNumber:   cert.SerialNumber,
			},
		}},
	}
	if nonce != nil {
		tbs.RequestExtensions = []pkix.Extension{{
			Id:    oidOCSPNonce,
			Value: nonce,
		}}
	}
	return asn1.Marshal(ocspRequest{TBSRequest: tbs})
}

// generateNonce returns a fresh 16-byte OCSP nonce.
func generateNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// responseNonce returns the nonce extension value from an OCSP response, or nil.
func responseNonce(resp *xocsp.Response) []byte {
	for _, ext := range resp.Extensions {
		if ext.Id.Equal(oidOCSPNonce) {
			return ext.Value
		}
	}
	return nil
}

// wrapOCSPError converts a low-level OCSP failure into the typed error.
func wrapOCSPError(err error) error {
	return exceptions.Wrap(exceptions.ErrOCSPRequestFailed, err)
}
