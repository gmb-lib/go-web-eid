// Package signature implements Web eID signature-algorithm mapping and
// authentication-token signature verification.
//
// The Web eID native application sends ECDSA signatures in raw IEEE P1363
// "r || s" concatenation (not ASN.1 DER), which this package handles
// explicitly. RSA signatures use either PKCS#1 v1.5 (RS*) or PSS (PS*).
package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"strings"

	// Pull in hash implementations so crypto.Hash.New works.
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

// jwaToHash maps each supported JWA algorithm identifier to its hash function.
var jwaToHash = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
	"PS256": crypto.SHA256, "PS384": crypto.SHA384, "PS512": crypto.SHA512,
	"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512,
}

// IsSupportedAlgorithm reports whether the given JWA algorithm identifier is
// one of the nine algorithms the Web eID token format permits.
func IsSupportedAlgorithm(algorithm string) bool {
	_, ok := jwaToHash[algorithm]
	return ok
}

// HashFor returns the crypto.Hash used by the given JWA algorithm and whether
// the algorithm is supported.
func HashFor(algorithm string) (crypto.Hash, bool) {
	h, ok := jwaToHash[algorithm]
	return h, ok
}

// Verify checks an authentication-token signature.
//
// signedData is the concatenation hash(origin) || hash(challenge); the
// signature operation itself hashes signedData again with the algorithm's hash
// function (the "double hash" described in the specification). This matches the
// Java/.NET reference behaviour.
func Verify(cert *x509.Certificate, algorithm string, signedData, signature []byte) error {
	h, ok := jwaToHash[algorithm]
	if !ok {
		return exceptions.ErrTokenUnsupportedFormat
	}
	if !h.Available() {
		return exceptions.Wrap(exceptions.ErrTokenSignatureInvalid, errHashUnavailable(h))
	}

	hasher := h.New()
	hasher.Write(signedData)
	digest := hasher.Sum(nil)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(algorithm, "PS") {
			if err := rsa.VerifyPSS(pub, h, digest, signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       h,
			}); err != nil {
				return exceptions.Wrap(exceptions.ErrTokenSignatureInvalid, err)
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, h, digest, signature); err != nil {
			return exceptions.Wrap(exceptions.ErrTokenSignatureInvalid, err)
		}
		return nil

	case *ecdsa.PublicKey:
		r, s, err := splitP1363(signature, pub)
		if err != nil {
			return exceptions.Wrap(exceptions.ErrTokenSignatureInvalid, err)
		}
		if !ecdsa.Verify(pub, digest, r, s) {
			return exceptions.ErrTokenSignatureInvalid
		}
		return nil

	default:
		return exceptions.Wrap(exceptions.ErrTokenSignatureInvalid, errUnsupportedKey)
	}
}

// splitP1363 splits a raw IEEE P1363 r||s ECDSA signature into its components.
// The signature length must be exactly twice the curve's coordinate size.
func splitP1363(sig []byte, pub *ecdsa.PublicKey) (r, s *big.Int, err error) {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*byteLen {
		return nil, nil, errInvalidP1363Length{got: len(sig), want: 2 * byteLen}
	}
	r = new(big.Int).SetBytes(sig[:byteLen])
	s = new(big.Int).SetBytes(sig[byteLen:])
	return r, s, nil
}
