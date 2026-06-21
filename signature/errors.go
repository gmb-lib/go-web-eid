package signature

import (
	"crypto"
	"errors"
	"fmt"
)

// errUnsupportedKey is returned when a certificate carries a public key type
// that the Web eID token format does not support.
var errUnsupportedKey = errors.New("unsupported public key type")

// errInvalidP1363Length is returned when a raw ECDSA signature does not have
// the expected r||s length for the certificate's curve.
type errInvalidP1363Length struct {
	got, want int
}

func (e errInvalidP1363Length) Error() string {
	return fmt.Sprintf("invalid ECDSA P1363 signature length: got %d, want %d", e.got, e.want)
}

// errHashUnavailable wraps an unavailable crypto.Hash into an error value.
func errHashUnavailable(h crypto.Hash) error {
	return fmt.Errorf("hash function %v is not available", h)
}
