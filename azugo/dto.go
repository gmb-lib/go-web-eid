package webeidazugo

import (
	"azugo.io/azugo"

	webeid "github.com/gmb-lib/go-web-eid"
	"github.com/gmb-lib/go-web-eid/signing"
)

// ChallengeResponse is returned by GET /auth/challenge.
type ChallengeResponse struct {
	Nonce string `json:"nonce"`
}

// LoginRequest is the body of POST /auth/login.
type LoginRequest struct {
	AuthToken webeid.AuthToken `json:"authToken" validate:"required"`
}

// Validate implements azugo.Validator.
func (r *LoginRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// ValidateRequest is the body of the STATELESS POST /auth/validate. Unlike
// /auth/login, the challenge nonce is supplied in the body by the consuming Auth
// service (which owns the challenge + session), so no cookie session is needed.
// Intended for server-to-server use.
type ValidateRequest struct {
	AuthToken webeid.AuthToken `json:"authToken" validate:"required"`
	Nonce     string           `json:"nonce" validate:"required"`
}

// Validate implements azugo.Validator.
func (r *ValidateRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// SubjectResponse is the validated identity returned by POST /auth/login.
type SubjectResponse struct {
	CommonName  string `json:"commonName,omitempty"`
	IDCode      string `json:"idCode,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	GivenName   string `json:"givenName,omitempty"`
	Surname     string `json:"surname,omitempty"`
}

// AssertionResponse is returned by POST /auth/login when the handler is
// configured with an assertion issuer (WithAssertionIssuer). The Assertion is a
// short-lived signed JWS the consuming Auth service verifies via the service's
// JWKS and maps to an internal identity.
type AssertionResponse struct {
	Assertion string          `json:"assertion"`
	Subject   SubjectResponse `json:"subject"`
}

// SigningCertificateRequest is the body of POST /sign/certificate.
type SigningCertificateRequest struct {
	// Certificate is the base64-encoded DER signing certificate.
	Certificate string `json:"certificate" validate:"required"`
	// SupportedSignatureAlgorithms are the algorithms the card reported.
	SupportedSignatureAlgorithms []signing.SignatureAlgorithm `json:"supportedSignatureAlgorithms" validate:"required,min=1"`
}

// Validate implements azugo.Validator.
func (r *SigningCertificateRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// SigningCertificateResponse is returned by POST /sign/certificate.
type SigningCertificateResponse struct {
	SignatureAlgorithm signing.SignatureAlgorithm `json:"signatureAlgorithm"`
	HashFunction       string                     `json:"hashFunction"`
}

// FinalizeRequest is the body of POST /sign/finalize.
//
// Digest and SigningCertificate are OPTIONAL and enable the "verified
// finalize": when both are present the service verifies the card's signature
// value against the digest with the signing certificate's public key, and
// asserts the auth ↔ signing certificate identity binding (same natural
// person; organisational seal certificates skip the person binding). Supplying
// only one of the two is an error.
type FinalizeRequest struct {
	// Signature is the base64-encoded raw card signature value (signed digest).
	Signature string `json:"signature" validate:"required"`
	// SignatureAlgorithm is the algorithm the card used.
	SignatureAlgorithm signing.SignatureAlgorithm `json:"signatureAlgorithm"`
	// AuthCertificate is the base64-encoded DER authentication certificate.
	AuthCertificate string `json:"authCertificate" validate:"required"`
	// Digest is the base64-encoded digest that was sent to the card (optional —
	// enables verified finalize together with SigningCertificate).
	Digest string `json:"digest,omitempty"`
	// SigningCertificate is the base64-encoded DER signing certificate
	// (optional — enables verified finalize together with Digest).
	SigningCertificate string `json:"signingCertificate,omitempty"`
}

// Validate implements azugo.Validator.
func (r *FinalizeRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// FinalizeResponse is returned by POST /sign/finalize. It echoes the card's
// signed digest (the raw signature value) and the parsed authentication
// certificate (base64 DER) so the integrating back end can assemble and
// validate its signature container. This library never builds the container.
type FinalizeResponse struct {
	Status string `json:"status"`
	// Signature is the base64-encoded raw card signature value (signed digest).
	Signature string `json:"signature,omitempty"`
	// AuthCertificate is the base64-encoded DER authentication certificate.
	AuthCertificate string `json:"authCertificate,omitempty"`
	// SignatureVerified is true when the verified-finalize inputs were supplied
	// and the card's signature value verified against the digest.
	SignatureVerified bool `json:"signatureVerified"`
	// IdentityBound is true when the auth and signing certificates were
	// confirmed to belong to the same natural person; false when the check was
	// skipped (no verified-finalize inputs, or an organisational seal
	// certificate). A binding MISMATCH fails the request instead.
	IdentityBound bool `json:"identityBound"`
}
