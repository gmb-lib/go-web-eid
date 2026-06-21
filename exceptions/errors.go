// Package exceptions defines the typed error values used throughout the
// go-web-eid library. The set mirrors the Java AuthTokenException hierarchy so
// that error reporting matches the official reference implementations.
//
// Every error carries an HTTP status code (via StatusCode) and a safe,
// non-revealing client message (via SafeError). The Azugo integration layer
// uses these interfaces to translate errors into HTTP responses without ever
// echoing attacker-controlled certificate contents.
package exceptions

import "fmt"

// Error is a typed Web eID error.
//
// It implements the error interface as well as the StatusCode and SafeError
// interfaces understood by the Azugo error handler.
type Error struct {
	// Code is a stable, machine-readable identifier (e.g. "TOKEN_PARSE").
	Code string
	// Message is the safe, client-facing description.
	Message string
	// HTTPStatus is the HTTP status the Azugo layer maps this error to.
	HTTPStatus int
	// Err is an optional wrapped cause. It is never exposed to clients.
	Err error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("webeid: %s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("webeid: %s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped cause, if any.
func (e *Error) Unwrap() error { return e.Err }

// StatusCode returns the HTTP status code for this error. It satisfies the
// Azugo ResponseStatusCode interface.
func (e *Error) StatusCode() int { return e.HTTPStatus }

// SafeError returns a message safe to return to the client. It satisfies the
// Azugo SafeError interface.
func (e *Error) SafeError() string { return e.Message }

// withCause returns a copy of the error with the given wrapped cause.
func (e *Error) withCause(cause error) *Error {
	clone := *e
	clone.Err = cause
	return &clone
}

// newError is a small constructor helper.
func newError(code, message string, status int) *Error {
	return &Error{Code: code, Message: message, HTTPStatus: status}
}

// Token / nonce errors.
var (
	// ErrTokenParse indicates the authentication token JSON was malformed.
	ErrTokenParse = newError("TOKEN_PARSE", "authentication token is malformed", 400)
	// ErrTokenUnsupportedFormat indicates an unknown token format major version.
	ErrTokenUnsupportedFormat = newError("TOKEN_UNSUPPORTED_FORMAT", "authentication token format is not supported", 400)
	// ErrTokenSignatureInvalid indicates signature verification failed.
	ErrTokenSignatureInvalid = newError("TOKEN_SIGNATURE_INVALID", "authentication token signature is invalid", 401)

	// ErrChallengeNonceExpired indicates the nonce is past its TTL.
	ErrChallengeNonceExpired = newError("CHALLENGE_NONCE_EXPIRED", "challenge nonce has expired", 401)
	// ErrChallengeNonceNotFound indicates no nonce exists for the session or it was reused.
	ErrChallengeNonceNotFound = newError("CHALLENGE_NONCE_NOT_FOUND", "challenge nonce was not found", 401)
)

// Certificate errors.
var (
	// ErrCertificateExpired indicates the certificate validity period has ended.
	ErrCertificateExpired = newError("CERTIFICATE_EXPIRED", "user certificate has expired", 401)
	// ErrCertificateNotYetValid indicates the certificate validity period has not started.
	ErrCertificateNotYetValid = newError("CERTIFICATE_NOT_YET_VALID", "user certificate is not yet valid", 401)
	// ErrCertificateNotTrusted indicates the chain is not anchored to a trusted CA.
	ErrCertificateNotTrusted = newError("CERTIFICATE_NOT_TRUSTED", "user certificate is not trusted", 401)
	// ErrCertificateRevoked indicates an OCSP "revoked" status.
	ErrCertificateRevoked = newError("CERTIFICATE_REVOKED", "user certificate has been revoked", 401)
	// ErrCertificateDisallowedPolicy indicates a disallowed certificate policy (e.g. Mobile-ID).
	ErrCertificateDisallowedPolicy = newError("CERTIFICATE_DISALLOWED_POLICY", "user certificate policy is not allowed", 401)
	// ErrUserCertificateWrongPurpose indicates a key usage / EKU mismatch.
	ErrUserCertificateWrongPurpose = newError("USER_CERTIFICATE_WRONG_PURPOSE", "user certificate has wrong key usage", 401)
	// ErrSigningCertificateInvalid indicates signing-certificate validation failed.
	ErrSigningCertificateInvalid = newError("SIGNING_CERTIFICATE_INVALID", "signing certificate is invalid", 422)
)

// OCSP / signing errors.
var (
	// ErrOCSPRequestFailed indicates the OCSP responder was unreachable or returned an invalid response.
	ErrOCSPRequestFailed = newError("OCSP_REQUEST_FAILED", "certificate revocation check failed", 502)
	// ErrNoSupportedHashFunction indicates no configured hash is offered by the card.
	ErrNoSupportedHashFunction = newError("NO_SUPPORTED_HASH_FUNCTION", "no supported hash function available", 422)
	// ErrSignatureValueInvalid indicates the card's signature value did not
	// verify against the digest and signing certificate (verified finalize).
	ErrSignatureValueInvalid = newError("SIGNATURE_VALUE_INVALID", "signature value does not verify against the digest", 422)
	// ErrIdentityBindingMismatch indicates the authentication and signing
	// certificates belong to different natural persons.
	ErrIdentityBindingMismatch = newError("IDENTITY_BINDING_MISMATCH", "authentication and signing certificates belong to different persons", 422)
)

// Wrap returns a copy of the given typed error carrying the supplied cause.
// The cause is used for server-side logging only and never exposed to clients.
func Wrap(base *Error, cause error) *Error {
	if base == nil {
		return nil
	}
	return base.withCause(cause)
}
