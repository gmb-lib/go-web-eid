package assertion

import (
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func newIssuerVerifier(t *testing.T) (*Issuer, *Verifier) {
	t.Helper()
	key, err := GenerateKey("test-1")
	qt.Assert(t, qt.IsNil(err))
	iss, err := NewIssuer(key, "https://web-eid.test", "svc:auth", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	jwks, err := iss.JWKS()
	qt.Assert(t, qt.IsNil(err))
	keys, err := KeySetFromJWKS(jwks)
	qt.Assert(t, qt.IsNil(err))
	v, err := NewVerifier(keys, "https://web-eid.test", "svc:auth")
	qt.Assert(t, qt.IsNil(err))
	return iss, v
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	iss, v := newIssuerVerifier(t)
	tok, err := iss.Issue(Subject{
		NationalID: "PNOLV-XXXXXXXXXXX",
		Country:    "LV",
		GivenName:  "JANIS",
		FamilyName: "BERZINS",
		LoA:        "high",
	})
	qt.Assert(t, qt.IsNil(err))

	claims, err := v.Verify(tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.NationalID, "PNOLV-XXXXXXXXXXX"))
	qt.Check(t, qt.Equals(claims.Subject, "PNOLV-XXXXXXXXXXX"))
	qt.Check(t, qt.Equals(claims.LoA, "high"))
	qt.Check(t, qt.Equals(claims.LoginMethod, "webEid"))
	qt.Check(t, qt.Not(qt.Equals(claims.JWTID, "")))
}

func TestVerifyRejectsTamper(t *testing.T) {
	iss, v := newIssuerVerifier(t)
	tok, err := iss.Issue(Subject{NationalID: "PNOLV-1", LoA: "high"})
	qt.Assert(t, qt.IsNil(err))

	// Flip a character in the payload segment.
	b := []byte(tok)
	for i := range b {
		if b[i] == '.' { // mutate the byte right after the first dot
			b[i+1] ^= 0x01
			break
		}
	}
	_, err = v.Verify(string(b))
	qt.Check(t, qt.IsNotNil(err))
}

func TestVerifyRejectsExpired(t *testing.T) {
	key, err := GenerateKey("test-exp")
	qt.Assert(t, qt.IsNil(err))
	past := func() time.Time { return time.Now().Add(-10 * time.Minute) }
	iss, err := NewIssuer(key, "https://web-eid.test", "svc:auth", time.Minute, WithClock(past))
	qt.Assert(t, qt.IsNil(err))
	tok, err := iss.Issue(Subject{NationalID: "PNOLV-1", LoA: "high"})
	qt.Assert(t, qt.IsNil(err))

	v, err := NewVerifier(iss.KeySet(), "https://web-eid.test", "svc:auth")
	qt.Assert(t, qt.IsNil(err))
	_, err = v.Verify(tok)
	qt.Check(t, qt.ErrorIs(err, ErrExpired))
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	iss, _ := newIssuerVerifier(t)
	tok, err := iss.Issue(Subject{NationalID: "PNOLV-1", LoA: "high"})
	qt.Assert(t, qt.IsNil(err))
	v, err := NewVerifier(iss.KeySet(), "https://web-eid.test", "svc:other")
	qt.Assert(t, qt.IsNil(err))
	_, err = v.Verify(tok)
	qt.Check(t, qt.ErrorIs(err, ErrAudience))
}

func TestVerifyRejectsUnknownKey(t *testing.T) {
	iss, _ := newIssuerVerifier(t)
	tok, err := iss.Issue(Subject{NationalID: "PNOLV-1", LoA: "high"})
	qt.Assert(t, qt.IsNil(err))
	// Verifier with an unrelated key set.
	other, err := GenerateKey("other")
	qt.Assert(t, qt.IsNil(err))
	ks := NewKeySet()
	ks.Add(other.KID, &other.Key.PublicKey)
	v, err := NewVerifier(ks, "https://web-eid.test", "svc:auth")
	qt.Assert(t, qt.IsNil(err))
	_, err = v.Verify(tok)
	qt.Check(t, qt.ErrorIs(err, ErrUnknownKey))
}
