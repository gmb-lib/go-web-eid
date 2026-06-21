package webeid

import (
	"errors"
	"fmt"
)

// errEmptyToken is returned when Parse is given an empty document.
var errEmptyToken = errors.New("authentication token is empty")

// errMissingField builds an error describing a missing mandatory token field.
func errMissingField(name string) error {
	return fmt.Errorf("mandatory token field %q is missing", name)
}

// errUnknownAlgorithm builds an error for an unsupported signature algorithm.
func errUnknownAlgorithm(algorithm string) error {
	return fmt.Errorf("unsupported signature algorithm %q", algorithm)
}

// errBadFormat builds an error for a malformed or unsupported format string.
func errBadFormat(format string) error {
	return fmt.Errorf("unsupported token format %q", format)
}
