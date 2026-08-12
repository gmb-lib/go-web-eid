package webeidazugo

import (
	"crypto/x509"
	"errors"
	"net/http"
	"os"

	webeid "github.com/gmb-lib/go-web-eid"
	"github.com/gmb-lib/go-web-eid/assertion"
	"github.com/gmb-lib/go-web-eid/certificate"
	"github.com/gmb-lib/go-web-eid/ocsp"
	"github.com/gmb-lib/go-web-eid/signing"
)

// Handler wires the go-web-eid core into Azugo routes. Construct it with New
// and register its endpoints with Bind.
type Handler struct {
	config    *Configuration
	validator webeid.AuthTokenValidator
	generator webeid.ChallengeNonceGenerator
	store     webeid.ChallengeNonceStore
	signer    *signing.Signer

	// trust is the one trusted-CA store shared by the validator and the
	// signer; ReloadTrust refreshes it in place so both always agree.
	trust *certificate.TrustStore

	// runtimeTrust (WithRuntimeTrust) lets construction succeed on an empty
	// or missing trust directory: the store starts empty (every check fails)
	// and is expected to be filled by ReloadTrust once material arrives.
	runtimeTrust bool

	// ocspTransport, when set (WithOCSPTransport), is the RoundTripper used for
	// OCSP responder requests — e.g. an instrumented transport injected by the
	// hosting service. Library stays dependency-pure: just a stdlib RoundTripper.
	ocspTransport http.RoundTripper

	// assertionIssuer, when set, makes /auth/login return a signed identity
	// assertion; publishedKeys backs the JWKS endpoint.
	assertionIssuer *assertion.Issuer
	publishedKeys   *assertion.KeySet
}

// Option customises a Handler at construction.
type Option func(*Handler)

// WithNonceStore overrides the default in-process nonce store. Supply a
// Redis-backed store (see package redisstore) for clustered, multi-pod
// deployments where challenge and login may land on different instances.
func WithNonceStore(store webeid.ChallengeNonceStore) Option {
	return func(h *Handler) {
		if store != nil {
			h.store = store
		}
	}
}

// WithAssertionIssuer enables signed identity assertions on POST /auth/login
// and publishes the issuer's verification keys at /.well-known/jwks.json. When
// set, /auth/login returns an AssertionResponse instead of a bare subject.
func WithAssertionIssuer(iss *assertion.Issuer) Option {
	return func(h *Handler) {
		h.assertionIssuer = iss
		if iss != nil && h.publishedKeys == nil {
			h.publishedKeys = iss.KeySet()
		}
	}
}

// WithPublishedJWKS overrides the key set published at /.well-known/jwks.json.
// Use it to publish previous keys alongside the active one during rotation.
func WithPublishedJWKS(keys *assertion.KeySet) Option {
	return func(h *Handler) {
		if keys != nil {
			h.publishedKeys = keys
		}
	}
}

// WithRuntimeTrust lets the handler start with an empty or missing trusted-CA
// source instead of failing construction. Every certificate check fails until
// ReloadTrust loads material — use this only when something at runtime (e.g.
// a trust-list synchronizer) delivers the trust directory's content and calls
// ReloadTrust; a statically provisioned deployment should keep the default
// fail-at-start behaviour so a misconfigured path is caught at boot.
func WithRuntimeTrust() Option {
	return func(h *Handler) {
		h.runtimeTrust = true
	}
}

// WithOCSPTransport injects a custom http.RoundTripper for OCSP responder
// requests — e.g. an OpenTelemetry-instrumented transport supplied by the
// hosting service so OCSP exchanges appear as client spans. Only used when OCSP
// is enabled. Keeps this library dependency-pure: it takes a stdlib
// RoundTripper, never a tracing package.
func WithOCSPTransport(rt http.RoundTripper) Option {
	return func(h *Handler) {
		h.ocspTransport = rt
	}
}

// New builds a Handler from configuration, loading the trusted intermediate CA
// certificates and wiring the validator, nonce generator and signer. Options
// may override the nonce store and enable assertion issuance.
func New(cfg *Configuration, opts ...Option) (*Handler, error) {
	if cfg == nil {
		return nil, errors.New("webeid: configuration is required")
	}

	h := &Handler{config: cfg}
	// Default in-process nonce store; overridable via WithNonceStore.
	h.store = NewSessionStore(cfg)

	// Apply options BEFORE loading trust material and building the
	// validator/signer/OCSP checker so runtime-trust mode, a custom OCSP
	// transport (WithOCSPTransport) and a store override are honoured.
	for _, o := range opts {
		o(h)
	}

	// One shared trust store feeds both the validator and the signer, so a
	// ReloadTrust refresh reaches every certificate check at once.
	trust := certificate.NewRuntimeTrustStore()
	cas, err := loadTrustedCAs(cfg.TrustedCACertsPath)
	switch {
	case err == nil:
		if err := trust.Reload(cas...); err != nil {
			return nil, err
		}
	case h.runtimeTrust && emptyTrustSource(err):
		// Runtime-managed trust: start empty (every check fails) and wait
		// for ReloadTrust. A statically provisioned deployment keeps the
		// error below so a bad path is caught at boot.
	default:
		return nil, err
	}
	h.trust = trust

	validator, err := buildValidator(cfg, trust)
	if err != nil {
		return nil, err
	}
	h.validator = validator

	acceptedPolicies, err := certificate.ParseOIDs(cfg.SigningAcceptedPolicyOIDs)
	if err != nil {
		return nil, err
	}

	signerOpts := signing.Options{
		HashPreference:   cfg.SigningHashPreference,
		Trust:            trust,
		AcceptedPolicies: acceptedPolicies,
	}
	if cfg.OCSPEnabled {
		ocspOpts := ocsp.Options{
			RequestTimeout:       cfg.OCSPRequestTimeout,
			Designated:           designatedConfig(cfg),
			NonceDisabledURLs:    cfg.OCSPNonceDisabledURLs,
			AllowedResponderURLs: cfg.OCSPAllowedResponderURLs,
		}
		if h.ocspTransport != nil {
			ocspOpts.Client = &ocsp.HTTPClient{Transport: h.ocspTransport}
		}
		signerOpts.OCSPChecker = ocsp.NewChecker(ocspOpts)
	}
	signer, err := signing.NewSigner(signerOpts)
	if err != nil {
		return nil, err
	}
	h.signer = signer

	// The generator binds to the (possibly overridden) store.
	generator, err := webeid.NewChallengeNonceGeneratorBuilder().
		WithChallengeNonceStore(h.store).
		WithNonceTTL(cfg.NonceTTL).
		Build()
	if err != nil {
		return nil, err
	}
	h.generator = generator

	return h, nil
}

// ReloadTrust re-reads the trusted CA material from the configured path and
// replaces the set used by both authentication-token validation and
// signing-certificate checks. Safe to call while requests are in flight — a
// check that already started finishes against the set it started with. On
// error the previous set stays in effect. Returns the number of certificates
// now trusted.
//
// Call it whenever the trust source changes underneath a running handler,
// e.g. after a trust-list synchronizer rewrites the trust directory.
func (h *Handler) ReloadTrust() (int, error) {
	cas, err := loadTrustedCAs(h.config.TrustedCACertsPath)
	if err != nil {
		return 0, err
	}
	if err := h.trust.Reload(cas...); err != nil {
		return 0, err
	}
	return len(cas), nil
}

// emptyTrustSource reports whether loading trust material failed only because
// there was nothing there yet: a missing path or a source without a single
// certificate.
func emptyTrustSource(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, certificate.ErrNoCertificatesFound)
}

// buildValidator constructs the auth-token validator from configuration,
// verifying against the shared trust store.
func buildValidator(cfg *Configuration, trust *certificate.TrustStore) (webeid.AuthTokenValidator, error) {
	b := webeid.NewAuthTokenValidatorBuilder().
		WithSiteOrigins(cfg.Origins...).
		WithTrustStore(trust).
		WithOcspRequestTimeout(cfg.OCSPRequestTimeout).
		WithNonceDisabledOcspUrls(cfg.OCSPNonceDisabledURLs...).
		WithAllowedOcspResponderURLs(cfg.OCSPAllowedResponderURLs...)
	if cfg.AllowInsecureLocalhost {
		b.WithAllowInsecureLocalhostOrigin()
	}
	if len(cfg.DisallowedPolicyOIDs) > 0 {
		oids, err := certificate.ParseOIDs(cfg.DisallowedPolicyOIDs)
		if err != nil {
			return nil, err
		}
		b.WithDisallowedCertificatePolicies(oids...)
	}
	if !cfg.OCSPEnabled {
		b.WithoutUserCertificateRevocationCheckWithOcsp()
	}
	if d := designatedConfig(cfg); d != nil {
		b.WithDesignatedOcspServiceConfiguration(d)
	}
	return b.Build()
}

// designatedConfig returns the designated OCSP responder configuration, if set.
func designatedConfig(cfg *Configuration) *ocsp.DesignatedServiceConfiguration {
	if cfg.DesignatedOCSPURL == "" {
		return nil
	}
	return &ocsp.DesignatedServiceConfiguration{URL: cfg.DesignatedOCSPURL}
}

// loadTrustedCAs loads intermediate CA certificates from a file or directory.
func loadTrustedCAs(path string) ([]*x509.Certificate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return certificate.LoadCertificatesFromDir(path)
	}
	f, err := os.Open(path) //nolint:gosec // operator-controlled trust material
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return certificate.LoadCertificatesFromPEM(f)
}
