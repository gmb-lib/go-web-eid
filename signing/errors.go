package signing

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel causes wrapped into the typed signing errors.
var (
	errNoPreference   = errors.New("hash preference list is empty")
	errEmptySignature = errors.New("signature value is empty")
)

// errUnknownHash describes an unrecognised hash-function preference entry.
func errUnknownHash(name string) error {
	return fmt.Errorf("unknown hash function %q", name)
}

// equalFoldHash compares hash-function names case-insensitively.
func equalFoldHash(a, b string) bool {
	return strings.EqualFold(a, b)
}
