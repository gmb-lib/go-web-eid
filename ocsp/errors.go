package ocsp

import "errors"

// Sentinel errors describing OCSP failure causes. They are wrapped into the
// typed exceptions.ErrOCSPRequestFailed / ErrCertificateRevoked errors before
// reaching the caller, so they are used for server-side logging only.
var (
	errNonceMismatch      = errors.New("OCSP response nonce does not match request")
	errUnknownStatus      = errors.New("OCSP responder returned unknown certificate status")
	errThisUpdateInFuture = errors.New("OCSP response thisUpdate is in the future")
	errResponseExpired    = errors.New("OCSP response nextUpdate has passed")
	errThisUpdateTooOld   = errors.New("OCSP response thisUpdate is too old")
)
