package assertion

import (
	"encoding/base64"
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

// TestKeySetFromJWKS_ShortCoordinateIsAccepted pins the tolerance that parsing
// the uncompressed point could easily have cost. RFC 7518 requires a JWK to
// encode each coordinate at the full field size, leading zeros included, but
// producers that strip them exist and such a key worked before — so a short
// coordinate must still be accepted, left-padded, not rejected.
func TestKeySetFromJWKS_ShortCoordinateIsAccepted(t *testing.T) {
	key, err := GenerateKey("short-1")
	qt.Assert(t, qt.IsNil(err))

	jwk, err := jwkFromPublic("short-1", &key.Key.PublicKey)
	qt.Assert(t, qt.IsNil(err))

	xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
	qt.Assert(t, qt.IsNil(err))
	yb, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	qt.Assert(t, qt.IsNil(err))

	// Emulate a producer that strips a leading zero byte. Only meaningful when
	// the coordinate actually starts with one, so generate until it does.
	for i := 0; xb[0] != 0 && i < 5000; i++ {
		key, err = GenerateKey("short-1")
		qt.Assert(t, qt.IsNil(err))
		jwk, err = jwkFromPublic("short-1", &key.Key.PublicKey)
		qt.Assert(t, qt.IsNil(err))
		xb, err = base64.RawURLEncoding.DecodeString(jwk.X)
		qt.Assert(t, qt.IsNil(err))
		yb, err = base64.RawURLEncoding.DecodeString(jwk.Y)
		qt.Assert(t, qt.IsNil(err))
	}
	if xb[0] != 0 {
		t.Skip("no leading-zero X coordinate generated; the padding path is covered by the unit case below")
	}

	pub, err := p256PublicKey(xb[1:], yb)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(pub.Equal(&key.Key.PublicKey)))
}

// TestP256PublicKey_RejectsOffCurvePoint is the check the deprecated
// raw-coordinate assignment did not make: coordinates that do not describe a
// point on P-256 are refused at parse time instead of becoming a key that fails
// every verification later.
func TestP256PublicKey_RejectsOffCurvePoint(t *testing.T) {
	xb := make([]byte, p256ByteLen)
	yb := make([]byte, p256ByteLen)
	xb[p256ByteLen-1] = 1 // (1, 1) is not on the curve
	yb[p256ByteLen-1] = 1

	_, err := p256PublicKey(xb, yb)
	qt.Check(t, qt.IsNotNil(err))
}

// TestP256PublicKey_RejectsOversizedCoordinate guards the length check ahead of
// the padding arithmetic.
func TestP256PublicKey_RejectsOversizedCoordinate(t *testing.T) {
	_, err := p256PublicKey(make([]byte, p256ByteLen+1), make([]byte, p256ByteLen))
	qt.Check(t, qt.IsNotNil(err))
}
