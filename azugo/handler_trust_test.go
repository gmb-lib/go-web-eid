package webeidazugo

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestNewFailsOnEmptyTrustDirByDefault(t *testing.T) {
	_, err := New(testConfig(t, t.TempDir()))
	qt.Assert(t, qt.IsNotNil(err))
}

// TestRuntimeTrustReloadsWithoutRestart exercises the runtime-trust lifecycle
// end to end on one handler instance: construction succeeds on a trust
// directory that does not exist yet, a login is refused while the trusted set
// is empty, and after trust material lands on disk a ReloadTrust makes the
// very next login succeed — no reconstruction, the nonce store and session
// machinery untouched.
func TestRuntimeTrustReloadsWithoutRestart(t *testing.T) {
	pki := newAzugoPKI(t)
	trustDir := filepath.Join(t.TempDir(), "trust")

	h, err := New(testConfig(t, trustDir), WithRuntimeTrust())
	qt.Assert(t, qt.IsNil(err))

	app := azugo.NewTestApp()
	qt.Assert(t, qt.IsNil(h.Bind(app.App)))
	app.Start(t)
	t.Cleanup(app.Stop)
	tc := app.TestClient()

	// One session for the whole test — the point is that the SAME running
	// handler flips from refusing to accepting on a trust reload alone.
	var cookie string
	login := func() int {
		var chResp *fasthttp.Response
		var err error
		if cookie == "" {
			chResp, err = tc.Get("/auth/challenge")
			qt.Assert(t, qt.IsNil(err))
			cookie = sessionCookie(t, chResp)
		} else {
			chResp, err = tc.Get("/auth/challenge",
				tc.WithHeader("Cookie", "WEBEID_SESSION="+cookie))
			qt.Assert(t, qt.IsNil(err))
		}
		body, _ := chResp.BodyUncompressed()
		var ch ChallengeResponse
		qt.Assert(t, qt.IsNil(json.Unmarshal(body, &ch)))
		fasthttp.ReleaseResponse(chResp)

		token := pki.signToken(t, testOrigin, ch.Nonce)
		loginResp, err := tc.PostJSON("/auth/login", LoginRequest{AuthToken: token},
			tc.WithHeader("Cookie", "WEBEID_SESSION="+cookie))
		qt.Assert(t, qt.IsNil(err))
		defer fasthttp.ReleaseResponse(loginResp)
		return loginResp.StatusCode()
	}

	// Empty trusted set: the card is refused.
	qt.Assert(t, qt.Equals(login(), fasthttp.StatusUnauthorized))

	// Trust material lands on disk (as a synchronizer would deliver it)…
	qt.Assert(t, qt.IsNil(os.MkdirAll(trustDir, 0o750)))
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.caCert.Raw})
	qt.Assert(t, qt.IsNil(os.WriteFile(filepath.Join(trustDir, "00-trust-anchor.pem"), pemBytes, 0o600)))

	// …and ReloadTrust makes it the set the next validation uses.
	n, err := h.ReloadTrust()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(n, 1))

	qt.Assert(t, qt.Equals(login(), fasthttp.StatusOK))
}

// TestReloadTrustFailureKeepsServingCurrentSet pins the fail-safe: a reload
// against a source that vanished must error out and leave the previous
// trusted set in effect.
func TestReloadTrustFailureKeepsServingCurrentSet(t *testing.T) {
	pki := newAzugoPKI(t)
	caPath := pki.writeCABundle(t)

	h, err := New(testConfig(t, caPath))
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(os.Remove(caPath)))

	_, err = h.ReloadTrust()
	qt.Assert(t, qt.IsNotNil(err))

	// The previous set still verifies the leaf.
	qt.Check(t, qt.IsNil(h.trust.Verify(pki.leaf, timeNow())))
}
