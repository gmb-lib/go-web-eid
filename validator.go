package webeid

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/gmb-lib/go-web-eid/certificate"
	"github.com/gmb-lib/go-web-eid/exceptions"
	"github.com/gmb-lib/go-web-eid/ocsp"
	"github.com/gmb-lib/go-web-eid/signature"
)

// errOriginRequired is returned when no site origin was configured.
var errOriginRequired = errors.New("site origin is required")

// AuthTokenValidator validates Web eID authentication tokens.
type AuthTokenValidator interface {
	// Validate runs the full validation pipeline against the token using the
	// expected challenge nonce. On success it returns the trusted user
	// certificate.
	//
	// The caller is responsible for retrieving currentChallengeNonce from the
	// ChallengeNonceStore (single-use GetAndRemove) and for enforcing nonce
	// expiry before calling Validate.
	Validate(ctx context.Context, token *AuthToken, currentChallengeNonce string) (*x509.Certificate, error)
}

// authTokenValidator is the default AuthTokenValidator.
type authTokenValidator struct {
	origin             string
	trust              *certificate.TrustStore
	ocspEnabled        bool
	ocspChecker        *ocsp.Checker
	disallowedPolicies []asn1.ObjectIdentifier
	now                func() time.Time
}

// Validate implements AuthTokenValidator. The step order matches the Java/.NET
// reference implementations so error reporting is consistent.
func (v *authTokenValidator) Validate(ctx context.Context, token *AuthToken, currentChallengeNonce string) (*x509.Certificate, error) {
	if token == nil {
		return nil, exceptions.Wrap(exceptions.ErrTokenParse, errEmptyToken)
	}
	if currentChallengeNonce == "" {
		return nil, exceptions.ErrChallengeNonceNotFound
	}

	// 1. Decode the certificate.
	der, err := token.decodeCertificate()
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, exceptions.Wrap(exceptions.ErrTokenParse, err)
	}

	now := v.now()

	// 2. Validity period.
	if err := certificate.CheckValidity(cert, now); err != nil {
		return nil, err
	}
	// 3. Key usage / EKU = client authentication.
	if err := certificate.CheckKeyUsageForAuthentication(cert); err != nil {
		return nil, err
	}
	// 4. No disallowed certificate policies.
	if err := certificate.CheckDisallowedPolicies(cert, v.disallowedPolicies); err != nil {
		return nil, err
	}
	// 5. Trust: chain to a configured intermediate CA.
	if err := v.trust.Verify(cert, now, x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	// 6. OCSP revocation check (unless disabled).
	if v.ocspEnabled {
		issuer := v.trust.IssuerOf(cert)
		if issuer == nil {
			return nil, exceptions.ErrCertificateNotTrusted
		}
		if err := v.ocspChecker.Check(ctx, cert, issuer); err != nil {
			return nil, err
		}
	}
	// 8. Signature over hash(origin) || hash(challenge).
	if err := v.verifySignature(token, cert, currentChallengeNonce); err != nil {
		return nil, err
	}
	// 9. Subject sanity check.
	if _, err := certificate.SubjectCN(cert); err != nil {
		return nil, exceptions.Wrap(exceptions.ErrTokenParse, err)
	}
	return cert, nil
}

// verifySignature reconstructs the signed datagram and verifies the token
// signature with the certificate's public key.
func (v *authTokenValidator) verifySignature(token *AuthToken, cert *x509.Certificate, challengeNonce string) error {
	h, ok := signature.HashFor(token.Algorithm)
	if !ok {
		return exceptions.ErrTokenUnsupportedFormat
	}
	if !h.Available() {
		return exceptions.ErrTokenSignatureInvalid
	}

	originHasher := h.New()
	originHasher.Write([]byte(v.origin))
	signedData := originHasher.Sum(nil)

	nonceHasher := h.New()
	nonceHasher.Write([]byte(challengeNonce))
	signedData = append(signedData, nonceHasher.Sum(nil)...)

	sig, err := token.decodeSignature()
	if err != nil {
		return err
	}
	return signature.Verify(cert, token.Algorithm, signedData, sig)
}

// normalizeOrigin validates and canonicalises a site origin: scheme://host[:port]
// with no path, query or trailing slash. Only https is accepted — except that,
// when allowInsecureLocalhost is set, http is additionally accepted for
// localhost loopback hosts so developers can test against the real Web eID
// extension without local TLS (the official extension permits http://localhost
// for development). Never enable it outside development.
func normalizeOrigin(origin string, allowInsecureLocalhost bool) (string, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return "", errors.Join(errOriginRequired, err)
	}
	if u.Scheme != "https" {
		if !(allowInsecureLocalhost && u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
			return "", errors.New("site origin must use https")
		}
	}
	if u.Host == "" {
		return "", errOriginRequired
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("site origin must not contain a path, query or fragment")
	}
	return strings.TrimSuffix(u.Scheme+"://"+u.Host, "/"), nil
}

// isLoopbackHost reports whether host names the local loopback.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
