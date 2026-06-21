package webeid

import (
	"strings"
	"testing"
)

// TestParse_ToleratesUnknownFields: the token format's minor version exists so
// official clients can add new ignorable fields — a "web-eid:1.x" token with an
// extra field must parse (W-1).
func TestParse_ToleratesUnknownFields(t *testing.T) {
	tokenJSON := []byte(`{
		"unverifiedCertificate": "QUJD",
		"algorithm": "ES384",
		"signature": "c2ln",
		"format": "web-eid:1.1",
		"appVersion": "https://web-eid.eu/web-eid-app/releases/2.6.0+0",
		"futureInformationalField": "must be ignored"
	}`)

	token, err := Parse(tokenJSON)
	if err != nil {
		t.Fatalf("token with an unknown field must parse, got: %v", err)
	}
	if token.Algorithm != "ES384" || token.Format != "web-eid:1.1" {
		t.Fatalf("known fields not populated: %+v", token)
	}
}

// TestParse_StillRejectsBadStructure: tolerance for unknown fields must not
// weaken the structural checks.
func TestParse_StillRejectsBadStructure(t *testing.T) {
	cases := []string{
		`{"algorithm":"ES384","signature":"c2ln","format":"web-eid:1.0"}`,              // missing certificate
		`{"unverifiedCertificate":"QUJD","algorithm":"XX999","signature":"c2ln","format":"web-eid:1.0"}`, // unknown algorithm
		`{"unverifiedCertificate":"QUJD","algorithm":"ES384","signature":"c2ln","format":"web-eid:2.0"}`, // unsupported major
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c)); err == nil {
			t.Fatalf("expected parse error for %s", c)
		}
	}
}

// TestNormalizeOrigin_InsecureLocalhost covers the development-only http
// localhost allowance (W-2).
func TestNormalizeOrigin_InsecureLocalhost(t *testing.T) {
	cases := []struct {
		origin    string
		allowDev  bool
		wantErr   bool
		want      string
	}{
		{"https://example.org", false, false, "https://example.org"},
		{"http://localhost:5173", false, true, ""},
		{"http://localhost:5173", true, false, "http://localhost:5173"},
		{"http://127.0.0.1", true, false, "http://127.0.0.1"},
		{"http://evil.example", true, true, ""}, // dev flag never opens non-loopback http
		{"https://example.org/path", false, true, ""},
	}
	for _, c := range cases {
		got, err := normalizeOrigin(c.origin, c.allowDev)
		if c.wantErr {
			if err == nil {
				t.Fatalf("normalizeOrigin(%q, %v): expected error, got %q", c.origin, c.allowDev, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizeOrigin(%q, %v): unexpected error: %v", c.origin, c.allowDev, err)
		}
		if !strings.EqualFold(got, c.want) {
			t.Fatalf("normalizeOrigin(%q, %v) = %q, want %q", c.origin, c.allowDev, got, c.want)
		}
	}
}
