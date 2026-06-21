// Package signing implements the Web eID card-operations subsystem: signing
// certificate validation, signature-algorithm negotiation, configuration-driven
// hash-function selection, and relaying a caller-supplied digest-to-sign to the
// card.
//
// The library is a clean Web eID card adapter. It never builds or validates a
// signature container and never sees document bytes — those responsibilities
// belong to the integrating back end.
package signing

import (
	"strings"

	"github.com/gmb-lib/go-web-eid/exceptions"
)

// SupportedHashFunctions lists every hash function value the Web eID client may
// report, in the canonical spelling used by web-eid.js.
var SupportedHashFunctions = []string{
	"SHA-224", "SHA-256", "SHA-384", "SHA-512",
	"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
}

// IsSupportedHashFunction reports whether name is a recognised hash function.
func IsSupportedHashFunction(name string) bool {
	for _, h := range SupportedHashFunctions {
		if h == name {
			return true
		}
	}
	return false
}

// SelectHashFunction returns the first hash function in the configured ordered
// preference list that the card reports in its supported algorithms.
//
// Nothing is hard-coded: when no preference entry is offered by the card it
// returns ErrNoSupportedHashFunction.
func SelectHashFunction(preference []string, supported []SignatureAlgorithm) (string, error) {
	offered := make(map[string]struct{}, len(supported))
	for _, s := range supported {
		offered[strings.ToUpper(s.HashFunction)] = struct{}{}
	}
	for _, want := range preference {
		if _, ok := offered[strings.ToUpper(want)]; ok {
			return want, nil
		}
	}
	return "", exceptions.ErrNoSupportedHashFunction
}
