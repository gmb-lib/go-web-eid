package webeid

import (
	"encoding/json"
	"testing"

	"github.com/go-quicktest/qt"
)

func validTokenJSON(t *testing.T) []byte {
	t.Helper()
	tok := AuthToken{
		UnverifiedCertificate: "MIIBdummy",
		Algorithm:             "ES384",
		Signature:             "c2lnbmF0dXJl",
		Format:                "web-eid:1.0",
		AppVersion:            "https://web-eid.eu/web-eid-app/releases/2.0.0+0",
	}
	b, err := json.Marshal(tok)
	qt.Assert(t, qt.IsNil(err))
	return b
}

func TestParseValid(t *testing.T) {
	tok, err := Parse(validTokenJSON(t))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(tok.Algorithm, "ES384"))
	qt.Check(t, qt.Equals(tok.Format, "web-eid:1.0"))
}

func TestParseRejectsEmpty(t *testing.T) {
	_, err := Parse(nil)
	qt.Assert(t, qt.IsNotNil(err))
}

func TestParseRejectsUnknownAlgorithm(t *testing.T) {
	_, err := Parse([]byte(`{"unverifiedCertificate":"x","algorithm":"HS256","signature":"y","format":"web-eid:1.0"}`))
	qt.Assert(t, qt.IsNotNil(err))
}

func TestParseRejectsUnsupportedFormatMajor(t *testing.T) {
	_, err := Parse([]byte(`{"unverifiedCertificate":"x","algorithm":"ES256","signature":"y","format":"web-eid:2.0"}`))
	qt.Assert(t, qt.IsNotNil(err))
}

func TestParseRejectsMissingCertificate(t *testing.T) {
	_, err := Parse([]byte(`{"algorithm":"ES256","signature":"y","format":"web-eid:1.0"}`))
	qt.Assert(t, qt.IsNotNil(err))
}

// Unknown fields are TOLERATED by design (token-format minor versions may add
// fields) — see TestParse_ToleratesUnknownFields in hardening_internal_test.go.
func TestParseAcceptsUnknownField(t *testing.T) {
	tok, err := Parse([]byte(`{"unverifiedCertificate":"x","algorithm":"ES256","signature":"y","format":"web-eid:1.0","extra":"1"}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(tok.Algorithm, "ES256"))
}

func TestNormalizeOrigin(t *testing.T) {
	got, err := normalizeOrigin("https://example.org", false)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, "https://example.org"))

	_, err = normalizeOrigin("https://example.org/path", false)
	qt.Check(t, qt.IsNotNil(err))

	_, err = normalizeOrigin("http://example.org", false)
	qt.Check(t, qt.IsNotNil(err))
}
