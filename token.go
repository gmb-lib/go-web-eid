// Package webeid implements the framework-agnostic core of the Web eID
// authentication-token validation and eID-card signing-operations back end.
//
// It is wire-compatible with the unmodified Web eID client components
// (web-eid.js, the browser extension and the native application) and mirrors
// the public API of the official Java reference library so existing RIA
// documentation maps directly onto it.
//
// The core depends only on the Go standard library and golang.org/x/crypto;
// the Azugo HTTP integration lives in the sub-package
// github.com/gmb-lib/go-web-eid/azugo.
package webeid

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/gmb-lib/go-web-eid/exceptions"
	"github.com/gmb-lib/go-web-eid/signature"
)

// supportedTokenMajorVersion is the only token format major version this
// library understands. A bump in the major version is a breaking protocol
// change and must be rejected.
const supportedTokenMajorVersion = 1

// AuthToken is the Web eID authentication token as received from web-eid.js.
//
// The certificate and claims contained in the token are UNTRUSTED until the
// token has been processed by AuthTokenValidator.Validate. The structure is a
// special-purpose JSON document and deliberately not a JWT — its fields must
// never be trusted on their own.
type AuthToken struct {
	// UnverifiedCertificate is the base64-encoded DER authentication
	// certificate. It is UNTRUSTED until validated.
	UnverifiedCertificate string `json:"unverifiedCertificate"`
	// Algorithm is the JWA signature algorithm: one of
	// ES256/384/512, PS256/384/512, RS256/384/512.
	Algorithm string `json:"algorithm"`
	// Signature is the base64-encoded signature over hash(origin)+hash(challenge).
	Signature string `json:"signature"`
	// Format is the token type and version, e.g. "web-eid:1.0".
	Format string `json:"format"`
	// AppVersion is the informational URL of the issuing app.
	AppVersion string `json:"appVersion"`
}

// Parse decodes and structurally validates an authentication-token JSON
// document. It rejects empty mandatory fields, unknown algorithms and
// unsupported format major versions, but performs no cryptographic checks —
// those are the responsibility of AuthTokenValidator.Validate.
//
// Unknown JSON fields are tolerated by design: the token format's MINOR
// version exists so official clients can add new (ignorable) fields without a
// breaking change — a "web-eid:1.x" token with extra fields is spec-valid and
// must not be rejected. Only the known fields are validated.
func Parse(tokenJSON []byte) (*AuthToken, error) {
	if len(tokenJSON) == 0 {
		return nil, exceptions.Wrap(exceptions.ErrTokenParse, errEmptyToken)
	}

	dec := json.NewDecoder(strings.NewReader(string(tokenJSON)))

	var token AuthToken
	if err := dec.Decode(&token); err != nil {
		return nil, exceptions.Wrap(exceptions.ErrTokenParse, err)
	}

	if err := token.validateStructure(); err != nil {
		return nil, err
	}
	return &token, nil
}

// validateStructure performs the strict, non-cryptographic field checks.
func (t *AuthToken) validateStructure() error {
	if t.UnverifiedCertificate == "" {
		return exceptions.Wrap(exceptions.ErrTokenParse, errMissingField("unverifiedCertificate"))
	}
	if t.Signature == "" {
		return exceptions.Wrap(exceptions.ErrTokenParse, errMissingField("signature"))
	}
	if t.Algorithm == "" {
		return exceptions.Wrap(exceptions.ErrTokenParse, errMissingField("algorithm"))
	}
	if !signature.IsSupportedAlgorithm(t.Algorithm) {
		return exceptions.Wrap(exceptions.ErrTokenParse, errUnknownAlgorithm(t.Algorithm))
	}
	if err := t.validateFormat(); err != nil {
		return err
	}
	return nil
}

// validateFormat checks the "web-eid:<major>.<minor>" format string and
// enforces the supported major version.
func (t *AuthToken) validateFormat() error {
	if t.Format == "" {
		return exceptions.Wrap(exceptions.ErrTokenParse, errMissingField("format"))
	}
	const prefix = "web-eid:"
	if !strings.HasPrefix(t.Format, prefix) {
		return exceptions.Wrap(exceptions.ErrTokenUnsupportedFormat, errBadFormat(t.Format))
	}
	version := strings.TrimPrefix(t.Format, prefix)
	majorStr, _, _ := strings.Cut(version, ".")
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return exceptions.Wrap(exceptions.ErrTokenUnsupportedFormat, errBadFormat(t.Format))
	}
	if major != supportedTokenMajorVersion {
		return exceptions.Wrap(exceptions.ErrTokenUnsupportedFormat, errBadFormat(t.Format))
	}
	return nil
}

// decodeCertificate decodes the base64 DER authentication certificate bytes.
func (t *AuthToken) decodeCertificate() ([]byte, error) {
	der, err := base64.StdEncoding.DecodeString(t.UnverifiedCertificate)
	if err != nil {
		return nil, exceptions.Wrap(exceptions.ErrTokenParse, err)
	}
	return der, nil
}

// decodeSignature decodes the base64 signature bytes.
func (t *AuthToken) decodeSignature() ([]byte, error) {
	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil {
		return nil, exceptions.Wrap(exceptions.ErrTokenParse, err)
	}
	return sig, nil
}
