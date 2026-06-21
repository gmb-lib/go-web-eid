package webeidazugo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	webeid "github.com/gmb-lib/go-web-eid"
	"github.com/gmb-lib/go-web-eid/signing"
)

const testOrigin = "https://example.org"

type azugoPKI struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

func newAzugoPKI(t *testing.T) *azugoPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TEST CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	qt.Assert(t, qt.IsNil(err))
	caCert, err := x509.ParseCertificate(caDER)
	qt.Assert(t, qt.IsNil(err))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "JÕEORG,JAAK-KRISTJAN,38001085718",
			SerialNumber: "PNOEE-38001085718",
			Country:      []string{"EE"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	qt.Assert(t, qt.IsNil(err))
	leaf, err := x509.ParseCertificate(leafDER)
	qt.Assert(t, qt.IsNil(err))

	return &azugoPKI{caCert: caCert, caKey: caKey, leaf: leaf, leafKey: leafKey}
}

func (p *azugoPKI) writeCABundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.caCert.Raw})
	qt.Assert(t, qt.IsNil(os.WriteFile(path, pemBytes, 0o600)))
	return path
}

func (p *azugoPKI) signToken(t *testing.T, origin, nonce string) webeid.AuthToken {
	t.Helper()
	originHash := sha256.Sum256([]byte(origin))
	nonceHash := sha256.Sum256([]byte(nonce))
	signedData := append(originHash[:], nonceHash[:]...)
	digest := sha256.Sum256(signedData)

	r, s, err := ecdsa.Sign(rand.Reader, p.leafKey, digest[:])
	qt.Assert(t, qt.IsNil(err))
	const byteLen = 32
	sig := make([]byte, 2*byteLen)
	r.FillBytes(sig[:byteLen])
	s.FillBytes(sig[byteLen:])

	return webeid.AuthToken{
		UnverifiedCertificate: base64.StdEncoding.EncodeToString(p.leaf.Raw),
		Algorithm:             "ES256",
		Signature:             base64.StdEncoding.EncodeToString(sig),
		Format:                "web-eid:1.0",
		AppVersion:            "https://web-eid.eu/test",
	}
}

func testConfig(t *testing.T, caPath string) *Configuration {
	t.Helper()
	return &Configuration{
		Origin:                testOrigin,
		TrustedCACertsPath:    caPath,
		NonceTTL:              5 * time.Minute,
		OCSPEnabled:           false,
		OCSPRequestTimeout:    5 * time.Second,
		SessionCookieName:     "WEBEID_SESSION",
		SigningHashPreference: []string{"SHA-256", "SHA-384", "SHA-512"},
	}
}

func testApp(t *testing.T, cfg *Configuration) *azugo.TestApp {
	t.Helper()
	h, err := New(cfg)
	qt.Assert(t, qt.IsNil(err))

	app := azugo.NewTestApp()
	qt.Assert(t, qt.IsNil(h.Bind(app.App)))
	app.Start(t)
	t.Cleanup(app.Stop)
	return app
}

// sessionCookie extracts the WEBEID_SESSION cookie value from a response.
func sessionCookie(t *testing.T, resp *fasthttp.Response) string {
	t.Helper()
	raw := string(resp.Header.PeekCookie("WEBEID_SESSION"))
	qt.Assert(t, qt.IsTrue(raw != ""))
	// raw is "WEBEID_SESSION=value; Path=/;..." — take the value.
	_, after, _ := strings.Cut(raw, "=")
	value, _, _ := strings.Cut(after, ";")
	return value
}

func TestChallengeIssuesNonce(t *testing.T) {
	pki := newAzugoPKI(t)
	app := testApp(t, testConfig(t, pki.writeCABundle(t)))

	resp, err := app.TestClient().Get("/auth/challenge")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	var out ChallengeResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	qt.Check(t, qt.IsTrue(len(out.Nonce) >= 44))
	qt.Check(t, qt.IsTrue(string(resp.Header.PeekCookie("WEBEID_SESSION")) != ""))
}

func TestLoginHappyPath(t *testing.T) {
	pki := newAzugoPKI(t)
	app := testApp(t, testConfig(t, pki.writeCABundle(t)))
	tc := app.TestClient()

	chResp, err := tc.Get("/auth/challenge")
	qt.Assert(t, qt.IsNil(err))
	cookie := sessionCookie(t, chResp)
	body, _ := chResp.BodyUncompressed()
	var ch ChallengeResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &ch)))
	fasthttp.ReleaseResponse(chResp)

	token := pki.signToken(t, testOrigin, ch.Nonce)
	loginResp, err := tc.PostJSON("/auth/login", LoginRequest{AuthToken: token},
		tc.WithHeader("Cookie", "WEBEID_SESSION="+cookie))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(loginResp)
	qt.Assert(t, qt.Equals(loginResp.StatusCode(), fasthttp.StatusOK))

	lbody, _ := loginResp.BodyUncompressed()
	var subject SubjectResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(lbody, &subject)))
	qt.Check(t, qt.Equals(subject.IDCode, "PNOEE-38001085718"))
	qt.Check(t, qt.Equals(subject.CountryCode, "EE"))
}

func TestLoginRejectsWithoutChallenge(t *testing.T) {
	pki := newAzugoPKI(t)
	app := testApp(t, testConfig(t, pki.writeCABundle(t)))

	token := pki.signToken(t, testOrigin, "some-nonce")
	resp, err := app.TestClient().PostJSON("/auth/login", LoginRequest{AuthToken: token})
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
}

func TestSigningCertificateEndpoint(t *testing.T) {
	pki := newAzugoPKI(t)
	app := testApp(t, testConfig(t, pki.writeCABundle(t)))

	// A content-commitment signing certificate signed by the trusted CA.
	signCert := newSigningCert(t, pki)
	req := SigningCertificateRequest{
		Certificate: base64.StdEncoding.EncodeToString(signCert),
		SupportedSignatureAlgorithms: []signing.SignatureAlgorithm{
			{CryptoAlgorithm: "ECC", HashFunction: "SHA-384", PaddingScheme: "NONE"},
		},
	}
	resp, err := app.TestClient().PostJSON("/sign/certificate", req)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	body, _ := resp.BodyUncompressed()
	var out SigningCertificateResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	qt.Check(t, qt.Equals(out.HashFunction, "SHA-384"))
}

func TestFinalizeEndpoint(t *testing.T) {
	pki := newAzugoPKI(t)
	app := testApp(t, testConfig(t, pki.writeCABundle(t)))

	req := FinalizeRequest{
		Signature:       base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}),
		AuthCertificate: base64.StdEncoding.EncodeToString(pki.leaf.Raw),
	}
	resp, err := app.TestClient().PostJSON("/sign/finalize", req)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	body, _ := resp.BodyUncompressed()
	var out FinalizeResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	qt.Check(t, qt.Equals(out.Status, "ok"))
}

func TestFinalizeRejectsBadSignature(t *testing.T) {
	pki := newAzugoPKI(t)
	app := testApp(t, testConfig(t, pki.writeCABundle(t)))

	req := FinalizeRequest{
		Signature:       "!!!not-base64!!!",
		AuthCertificate: base64.StdEncoding.EncodeToString(pki.leaf.Raw),
	}
	resp, err := app.TestClient().PostJSON("/sign/finalize", req)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
}

func TestNewRejectsMissingCAPath(t *testing.T) {
	cfg := testConfig(t, filepath.Join(t.TempDir(), "does-not-exist.pem"))
	_, err := New(cfg)
	qt.Check(t, qt.IsNotNil(err))
}

func TestNewRejectsNilConfig(t *testing.T) {
	_, err := New(nil)
	qt.Check(t, qt.IsNotNil(err))
}

// newSigningCert builds a content-commitment certificate signed by the PKI CA.
func newSigningCert(t *testing.T, pki *azugoPKI) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "SIGNER"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.caCert, key.Public(), pki.caKey)
	qt.Assert(t, qt.IsNil(err))
	return der
}
