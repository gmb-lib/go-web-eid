package signing

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/gmb-lib/go-web-eid/certificate"
	"github.com/gmb-lib/go-web-eid/exceptions"
	"github.com/gmb-lib/go-web-eid/ocsp"
)

// Signer drives the Web eID card-facing signing operations. It validates the
// signing certificate, negotiates the signature algorithm and hash function,
// and surfaces the authentication certificate for the integrator's finalization
// step.
//
// The Signer never builds or validates a signature container and never computes
// a document digest. The digest-to-sign is supplied by the integrating back
// end, and the actual card signature is produced client-side by web-eid.js.
type Signer struct {
	hashPreference   []string
	trust            *certificate.TrustStore
	ocspChecker      *ocsp.Checker
	acceptedPolicies []asn1.ObjectIdentifier
	now              func() time.Time
}

// Options configures a Signer.
type Options struct {
	// HashPreference is the ordered hash-function preference list.
	HashPreference []string
	// Trust, when set, is used to validate the signing certificate chain.
	Trust *certificate.TrustStore
	// OCSPChecker, when set, checks signing-certificate revocation.
	OCSPChecker *ocsp.Checker
	// AcceptedPolicies, when set, are certificate-policy OIDs of which the
	// signing certificate must assert AT LEAST ONE (any-of) — e.g.
	// certificate.LVCardQSCDSigningPolicies() to accept only LVRTC QSCD card
	// products, or certificate.OIDQCPNaturalQSCD for the generic ETSI gate.
	AcceptedPolicies []asn1.ObjectIdentifier
	// Now overrides the clock (primarily for testing).
	Now func() time.Time
}

// NewSigner constructs a Signer.
func NewSigner(opts Options) (*Signer, error) {
	if len(opts.HashPreference) == 0 {
		return nil, exceptions.Wrap(exceptions.ErrNoSupportedHashFunction, errNoPreference)
	}
	for _, h := range opts.HashPreference {
		if !IsSupportedHashFunction(h) {
			return nil, exceptions.Wrap(exceptions.ErrNoSupportedHashFunction, errUnknownHash(h))
		}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Signer{
		hashPreference:   opts.HashPreference,
		trust:            opts.Trust,
		ocspChecker:      opts.OCSPChecker,
		acceptedPolicies: opts.AcceptedPolicies,
		now:              now,
	}, nil
}

// PrepareSigning validates the signing certificate and negotiates the algorithm
// and hash function. It does NOT build a container or compute a document digest.
func (s *Signer) PrepareSigning(ctx context.Context, signingCertDER []byte, supported []SignatureAlgorithm) (cert *x509.Certificate, algo SignatureAlgorithm, hashFn string, err error) {
	cert, err = ParseSigningCertificate(signingCertDER)
	if err != nil {
		return nil, SignatureAlgorithm{}, "", err
	}

	now := s.now()
	if err = validateSigningCertificate(cert, now); err != nil {
		return nil, SignatureAlgorithm{}, "", err
	}

	if err = certificate.CheckAcceptedPolicies(cert, s.acceptedPolicies); err != nil {
		return nil, SignatureAlgorithm{}, "", err
	}

	if s.trust != nil {
		if err = s.trust.Verify(cert, now); err != nil {
			return nil, SignatureAlgorithm{}, "", exceptions.ErrSigningCertificateInvalid
		}
		if s.ocspChecker != nil {
			issuer := s.trust.IssuerOf(cert)
			if issuer == nil {
				return nil, SignatureAlgorithm{}, "", exceptions.ErrSigningCertificateInvalid
			}
			if err = s.ocspChecker.Check(ctx, cert, issuer); err != nil {
				return nil, SignatureAlgorithm{}, "", err
			}
		}
	}

	hashFn, err = SelectHashFunction(s.hashPreference, supported)
	if err != nil {
		return nil, SignatureAlgorithm{}, "", err
	}

	algo = pickAlgorithmForHash(hashFn, supported)
	return cert, algo, hashFn, nil
}

// Finalize completes the card-operations flow. The caller supplies the card's
// raw signature value (the signed digest produced client-side by web-eid.js)
// and the authentication certificate; Finalize parses and returns the
// authentication certificate so the integrator can finalize its container.
//
// The signature value is returned unchanged: this library does not assemble or
// validate the signature container.
func (s *Signer) Finalize(signatureValue, authCertDER []byte) (authCert *x509.Certificate, signed []byte, err error) {
	if len(signatureValue) == 0 {
		return nil, nil, exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, errEmptySignature)
	}
	authCert, err = x509.ParseCertificate(authCertDER)
	if err != nil {
		return nil, nil, exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, err)
	}
	return authCert, signatureValue, nil
}

// pickAlgorithmForHash returns the first supported SignatureAlgorithm that uses
// the chosen hash function.
func pickAlgorithmForHash(hashFn string, supported []SignatureAlgorithm) SignatureAlgorithm {
	for _, s := range supported {
		if equalFoldHash(s.HashFunction, hashFn) {
			return s
		}
	}
	return SignatureAlgorithm{HashFunction: hashFn}
}
