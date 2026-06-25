// Package assertion implements the trust boundary between the Web eID service
// and the consuming Identity/Auth service.
//
// After the Web eID service validates an authentication token it mints a short
// lived, signed "verified identity assertion" (a compact JWS, ES256) carrying
// the validated subject. The Auth service fetches the service's JWKS, verifies
// the assertion offline, and maps the subject to an internal identity. The Auth
// service never parses an eID certificate; it only trusts this assertion.
//
// The package depends only on the Go standard library, matching the core
// library's no-heavy-dependency rule. A full JOSE library (e.g. go-jose) is an
// acceptable drop-in if richer algorithm support is later required.
//
// Replay defence: assertions carry a single-use jti and a short exp. The
// CONSUMER (Auth service) must record consumed jti values (e.g. in Redis until
// exp) to reject replays — Verify does not keep state.
//
// Example (service side):
//
//	key, _ := assertion.GenerateKey("2026-06")
//	iss, _ := assertion.NewIssuer(key, "https://web-eid.internal", "svc:auth", 2*time.Minute)
//	tok, _ := iss.Issue(assertion.Subject{NationalID: "PNOLV-XXXXXXXXXXX", LoA: "high"})
//	jwks, _ := iss.JWKS() // publish at /.well-known/jwks.json
//
// Example (Auth service side):
//
//	keys, _ := assertion.KeySetFromJWKS(jwks)
//	v, _ := assertion.NewVerifier(keys, "https://web-eid.internal", "svc:auth")
//	claims, err := v.Verify(tok)
package assertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Sentinel errors returned by Verify and the constructors.
var (
	ErrInvalidToken = errors.New("assertion: malformed token")
	ErrAlgorithm    = errors.New("assertion: unexpected algorithm")
	ErrUnknownKey   = errors.New("assertion: unknown signing key id")
	ErrSignature    = errors.New("assertion: signature verification failed")
	ErrIssuer       = errors.New("assertion: unexpected issuer")
	ErrAudience     = errors.New("assertion: unexpected audience")
	ErrExpired      = errors.New("assertion: assertion has expired")
	ErrNotYetValid  = errors.New("assertion: assertion is not yet valid")
)

// defaultIssuerTTL is used when a non-positive TTL is supplied.
const defaultIssuerTTL = 2 * time.Minute

// p256ByteLen is the coordinate / signature-half length for P-256.
const p256ByteLen = 32

// Subject is the validated identity the service asserts.
type Subject struct {
	NationalID string // e.g. "PNOLV-XXXXXXXXXXX" — the stable subject + linking key
	Country    string // e.g. "LV"
	GivenName  string
	FamilyName string
	LoA        string // e.g. "high"
}

// Claims is the assertion payload. It is a minimal JWT claim set plus the
// validated eID subject fields.
type Claims struct {
	Issuer      string `json:"iss"`
	Audience    string `json:"aud"`
	Subject     string `json:"sub"` // national ID (stable subject)
	IssuedAt    int64  `json:"iat"`
	Expiry      int64  `json:"exp"`
	JWTID       string `json:"jti"`
	NationalID  string `json:"national_id"`
	Country     string `json:"country,omitempty"`
	GivenName   string `json:"given_name,omitempty"`
	FamilyName  string `json:"family_name,omitempty"`
	LoA         string `json:"loa"`
	LoginMethod string `json:"login_method"` // always "webEid"
}

// jwsHeader is the protected JWS header.
type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// SigningKey is an ES256 (P-256) signing key with its key id.
type SigningKey struct {
	KID string
	Key *ecdsa.PrivateKey
}

// GenerateKey creates a fresh P-256 signing key with the given id. Production
// keys should live in Vault/KMS; this is for bootstrapping and tests.
func GenerateKey(kid string) (SigningKey, error) {
	if kid == "" {
		return SigningKey{}, errors.New("assertion: key id is required")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{KID: kid, Key: k}, nil
}

// Issuer mints signed identity assertions.
type Issuer struct {
	key    SigningKey
	iss    string
	aud    string
	ttl    time.Duration
	now    func() time.Time
	genJTI func() (string, error)
}

// IssuerOption customises an Issuer.
type IssuerOption func(*Issuer)

// WithClock overrides the issuer clock (testing).
func WithClock(now func() time.Time) IssuerOption {
	return func(i *Issuer) {
		if now != nil {
			i.now = now
		}
	}
}

// WithJTIGenerator overrides the jti generator (testing).
func WithJTIGenerator(f func() (string, error)) IssuerOption {
	return func(i *Issuer) {
		if f != nil {
			i.genJTI = f
		}
	}
}

// NewIssuer builds an Issuer. The key must be a P-256 key; ttl is the assertion
// lifetime (defaults to 2 minutes when non-positive).
func NewIssuer(key SigningKey, issuerURL, audience string, ttl time.Duration, opts ...IssuerOption) (*Issuer, error) {
	if key.Key == nil {
		return nil, errors.New("assertion: a signing key is required")
	}
	if key.Key.Curve != elliptic.P256() {
		return nil, errors.New("assertion: ES256 requires a P-256 key")
	}
	if key.KID == "" {
		return nil, errors.New("assertion: a key id is required")
	}
	if issuerURL == "" || audience == "" {
		return nil, errors.New("assertion: issuer and audience are required")
	}
	if ttl <= 0 {
		ttl = defaultIssuerTTL
	}
	i := &Issuer{
		key:    key,
		iss:    issuerURL,
		aud:    audience,
		ttl:    ttl,
		now:    time.Now,
		genJTI: randomJTI,
	}
	for _, o := range opts {
		o(i)
	}
	return i, nil
}

// Issue mints a signed assertion for the given subject.
func (i *Issuer) Issue(s Subject) (string, error) {
	if s.NationalID == "" {
		return "", errors.New("assertion: subject national id is required")
	}
	jti, err := i.genJTI()
	if err != nil {
		return "", err
	}
	now := i.now()
	claims := Claims{
		Issuer:      i.iss,
		Audience:    i.aud,
		Subject:     s.NationalID,
		IssuedAt:    now.Unix(),
		Expiry:      now.Add(i.ttl).Unix(),
		JWTID:       jti,
		NationalID:  s.NationalID,
		Country:     s.Country,
		GivenName:   s.GivenName,
		FamilyName:  s.FamilyName,
		LoA:         s.LoA,
		LoginMethod: "webEid",
	}
	return sign(i.key, claims)
}

// KeySet returns the issuer's active public key as a verification key set,
// suitable for publishing as JWKS. During rotation, Add the previous public
// keys to the returned set so in-flight assertions remain verifiable.
func (i *Issuer) KeySet() *KeySet {
	ks := NewKeySet()
	ks.Add(i.key.KID, &i.key.Key.PublicKey)
	return ks
}

// JWKS returns the issuer's active public key as a serialised JWK set.
func (i *Issuer) JWKS() ([]byte, error) {
	return i.KeySet().MarshalJWKS()
}

// sign produces a compact JWS (ES256) over the claims.
func sign(key SigningKey, claims Claims) (string, error) {
	hdr, err := json.Marshal(jwsHeader{Alg: "ES256", Typ: "JWT", Kid: key.KID})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hdr) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key.Key, digest[:])
	if err != nil {
		return "", err
	}
	// JWS ES256 uses fixed-width R||S (P1363), not ASN.1 DER.
	sig := make([]byte, 2*p256ByteLen)
	r.FillBytes(sig[:p256ByteLen])
	s.FillBytes(sig[p256ByteLen:])
	return signingInput + "." + b64(sig), nil
}

// KeySet holds ES256 verification keys by key id.
type KeySet struct {
	keys map[string]*ecdsa.PublicKey
}

// NewKeySet returns an empty key set.
func NewKeySet() *KeySet { return &KeySet{keys: make(map[string]*ecdsa.PublicKey)} }

// Add registers a public key under its key id.
func (ks *KeySet) Add(kid string, pub *ecdsa.PublicKey) {
	if kid != "" && pub != nil {
		ks.keys[kid] = pub
	}
}

func (ks *KeySet) get(kid string) (*ecdsa.PublicKey, bool) {
	p, ok := ks.keys[kid]
	return p, ok
}

// JWK is a single JSON Web Key (EC, P-256).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the set as a serialisable JWKS value.
func (ks *KeySet) JWKS() JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(ks.keys))}
	for kid, pub := range ks.keys {
		out.Keys = append(out.Keys, jwkFromPublic(kid, pub))
	}
	return out
}

// MarshalJWKS serialises the set to JSON suitable for a JWKS endpoint.
func (ks *KeySet) MarshalJWKS() ([]byte, error) { return json.Marshal(ks.JWKS()) }

// KeySetFromJWKS parses a JWKS document into a verification key set, keeping
// only EC P-256 keys.
func KeySetFromJWKS(data []byte) (*KeySet, error) {
	var doc JWKS
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	ks := NewKeySet()
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, ErrInvalidToken
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, ErrInvalidToken
		}
		ks.Add(k.Kid, &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		})
	}
	return ks, nil
}

func jwkFromPublic(kid string, pub *ecdsa.PublicKey) JWK {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := make([]byte, byteLen)
	y := make([]byte, byteLen)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return JWK{
		Kty: "EC", Crv: "P-256",
		X: b64(x), Y: b64(y),
		Kid: kid, Use: "sig", Alg: "ES256",
	}
}

// Verifier verifies identity assertions against a key set, issuer and audience.
type Verifier struct {
	keys   *KeySet
	iss    string
	aud    string
	leeway time.Duration
	now    func() time.Time
}

// VerifierOption customises a Verifier.
type VerifierOption func(*Verifier)

// WithVerifierClock overrides the verifier clock (testing).
func WithVerifierClock(now func() time.Time) VerifierOption {
	return func(v *Verifier) {
		if now != nil {
			v.now = now
		}
	}
}

// WithLeeway sets the allowed clock skew for exp/iat (default 30s).
func WithLeeway(d time.Duration) VerifierOption {
	return func(v *Verifier) {
		if d >= 0 {
			v.leeway = d
		}
	}
}

// NewVerifier builds a Verifier.
func NewVerifier(keys *KeySet, issuerURL, audience string, opts ...VerifierOption) (*Verifier, error) {
	if keys == nil {
		return nil, errors.New("assertion: a key set is required")
	}
	if issuerURL == "" || audience == "" {
		return nil, errors.New("assertion: issuer and audience are required")
	}
	v := &Verifier{
		keys:   keys,
		iss:    issuerURL,
		aud:    audience,
		leeway: 30 * time.Second,
		now:    time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// Verify checks the assertion signature and standard claims, returning the
// validated claims. The caller must additionally enforce single use of
// Claims.JWTID to defend against replay.
func (v *Verifier) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var hdr jwsHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, ErrInvalidToken
	}
	if hdr.Alg != "ES256" {
		return nil, ErrAlgorithm
	}
	pub, ok := v.keys.get(hdr.Kid)
	if !ok {
		return nil, ErrUnknownKey
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 2*p256ByteLen {
		return nil, ErrInvalidToken
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:p256ByteLen])
	s := new(big.Int).SetBytes(sig[p256ByteLen:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, ErrSignature
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if claims.Issuer != v.iss {
		return nil, ErrIssuer
	}
	if claims.Audience != v.aud {
		return nil, ErrAudience
	}
	now := v.now()
	if claims.Expiry != 0 && now.After(time.Unix(claims.Expiry, 0).Add(v.leeway)) {
		return nil, ErrExpired
	}
	if claims.IssuedAt != 0 && now.Add(v.leeway).Before(time.Unix(claims.IssuedAt, 0)) {
		return nil, ErrNotYetValid
	}
	return &claims, nil
}

// b64 is base64url without padding (JOSE encoding).
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// randomJTI returns a 128-bit random token id.
func randomJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
