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

	cas, err := loadTrustedCAs(cfg.TrustedCACertsPath)
	if err != nil {
		return nil, err
	}
	trust, err := certificate.NewTrustStore(cas...)
	if err != nil {
		return nil, err
	}

	validator, err := buildValidator(cfg, cas)
	if err != nil {
		return nil, err
	}

	acceptedPolicies, err := certificate.ParseOIDs(cfg.SigningAcceptedPolicyOIDs)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		config:    cfg,
		validator: validator,
	}
	// Default in-process nonce store; overridable via WithNonceStore.
	h.store = NewSessionStore(cfg)

	// Apply options BEFORE building the signer/OCSP checker so a custom OCSP
	// transport (WithOCSPTransport) and store override are honoured.
	for _, o := range opts {
		o(h)
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

// buildValidator constructs the auth-token validator from configuration.
func buildValidator(cfg *Configuration, cas []*x509.Certificate) (webeid.AuthTokenValidator, error) {
	b := webeid.NewAuthTokenValidatorBuilder().
		WithSiteOrigin(cfg.Origin).
		WithTrustedCertificateAuthorities(cas...).
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
