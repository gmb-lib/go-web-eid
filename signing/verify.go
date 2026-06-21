package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"

	// Register the SHA-2 hash implementations used by RSA verification.
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

// hashNameToCryptoHash maps web-eid.js hash-function names to crypto.Hash for
// RSA verification (the DigestInfo encoding needs the hash identity; ECDSA
// verification is hash-agnostic and takes the digest directly).
var hashNameToCryptoHash = map[string]crypto.Hash{
	"SHA-224": crypto.SHA224,
	"SHA-256": crypto.SHA256,
	"SHA-384": crypto.SHA384,
	"SHA-512": crypto.SHA512,
}

var (
	errUnsupportedRSAHash = errors.New("hash function is not supported for RSA signature verification")
	errDigestLength       = errors.New("digest length does not match the hash function")
	errUnsupportedPubKey  = errors.New("unsupported public key type in signing certificate")
)

// VerifySignatureValue verifies the card-produced raw signature value against
// the digest that was sent to the card, using the signing certificate's public
// key — the "verified finalize" integrity check. The signature encoding follows
// the Web eID native-application conventions: ECDSA arrives as raw IEEE P1363
// r‖s, RSA as PKCS#1 v1.5 or PSS per the algorithm's padding scheme.
//
// algo is the SignatureAlgorithm negotiated at the prepare step (as echoed by
// web-eid.js sign()); its HashFunction must name the hash that produced digest.
func VerifySignatureValue(cert *x509.Certificate, algo SignatureAlgorithm, digest, signatureValue []byte) error {
	if cert == nil || len(digest) == 0 || len(signatureValue) == 0 {
		return exceptions.Wrap(exceptions.ErrSignatureValueInvalid, errEmptySignature)
	}

	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		if len(signatureValue) != 2*byteLen {
			return exceptions.Wrap(exceptions.ErrSignatureValueInvalid,
				errors.New("ECDSA signature value is not raw P1363 r||s of the expected length"))
		}
		r := new(big.Int).SetBytes(signatureValue[:byteLen])
		s := new(big.Int).SetBytes(signatureValue[byteLen:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return exceptions.ErrSignatureValueInvalid
		}
		return nil

	case *rsa.PublicKey:
		h, ok := hashNameToCryptoHash[strings.ToUpper(algo.HashFunction)]
		if !ok {
			return exceptions.Wrap(exceptions.ErrSignatureValueInvalid, errUnsupportedRSAHash)
		}
		if h.Size() != len(digest) {
			return exceptions.Wrap(exceptions.ErrSignatureValueInvalid, errDigestLength)
		}
		if strings.EqualFold(algo.PaddingScheme, "PSS") {
			if err := rsa.VerifyPSS(pub, h, digest, signatureValue, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       h,
			}); err != nil {
				return exceptions.Wrap(exceptions.ErrSignatureValueInvalid, err)
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, h, digest, signatureValue); err != nil {
			return exceptions.Wrap(exceptions.ErrSignatureValueInvalid, err)
		}
		return nil

	default:
		return exceptions.Wrap(exceptions.ErrSignatureValueInvalid, errUnsupportedPubKey)
	}
}
