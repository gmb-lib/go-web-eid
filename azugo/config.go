// Package webeidazugo provides the Azugo HTTP integration for the go-web-eid
// core library: configuration, a session-backed challenge-nonce store with
// pre-auth cookie middleware, an authentication middleware, and the four
// endpoints the web-eid.js flow expects.
package webeidazugo

import (
	"time"

	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration holds the Web eID settings for an Azugo deployment. It follows
// the Azugo sub-package configuration pattern (own Bind/Validate).
type Configuration struct {
	// Origin is the site origin the token is bound to, https://host[:port].
	Origin string `mapstructure:"origin" validate:"required,url"`
	// TrustedCACertsPath is a directory or file containing intermediate CA certs.
	TrustedCACertsPath string `mapstructure:"trusted_ca_certs_path" validate:"required"`
	// NonceTTL is the challenge-nonce lifetime.
	NonceTTL time.Duration `mapstructure:"nonce_ttl" validate:"required,gt=0"`
	// OCSPEnabled toggles OCSP revocation checking.
	OCSPEnabled bool `mapstructure:"ocsp_enabled"`
	// OCSPRequestTimeout bounds a single OCSP exchange.
	OCSPRequestTimeout time.Duration `mapstructure:"ocsp_request_timeout" validate:"required,gt=0"`
	// DesignatedOCSPURL optionally overrides the AIA responder URL.
	DesignatedOCSPURL string `mapstructure:"designated_ocsp_url" validate:"omitempty,url"`
	// OCSPNonceDisabledURLs lists responder URLs that do not support the OCSP
	// nonce extension; requests to them omit the nonce.
	OCSPNonceDisabledURLs []string `mapstructure:"ocsp_nonce_disabled_urls"`
	// SessionCookieName is the pre-auth session cookie name.
	SessionCookieName string `mapstructure:"session_cookie_name" validate:"required"`
	// SigningHashPreference is the ordered hash-function preference list.
	SigningHashPreference []string `mapstructure:"signing_hash_preference" validate:"required,min=1,dive,oneof=SHA-224 SHA-256 SHA-384 SHA-512 SHA3-224 SHA3-256 SHA3-384 SHA3-512"`
	// AllowInsecureLocalhost additionally accepts an http:// Origin for
	// localhost loopback hosts — DEVELOPMENT ONLY (mirrors the official
	// extension's localhost allowance). Never enable in production.
	AllowInsecureLocalhost bool `mapstructure:"allow_insecure_localhost"`
	// EnforceHostHeader rejects requests whose Host header does not match the
	// configured Origin's host (defence-in-depth against DNS-rebinding /
	// host-spoofing; default true). Disable only behind a proxy that rewrites
	// Host away from the public origin.
	EnforceHostHeader bool `mapstructure:"enforce_host_header"`
	// OCSPAllowedResponderURLs, when non-empty, restricts AIA-derived OCSP
	// responder URLs to this allowlist (full URLs or bare hosts) — an SSRF
	// guard; the responder URL comes from the user-supplied certificate.
	OCSPAllowedResponderURLs []string `mapstructure:"ocsp_allowed_responder_urls"`
	// DisallowedPolicyOIDs overrides the default disallowed certificate-policy
	// OIDs (Estonian Mobile-ID arcs) with a deployment-specific list of
	// dotted-decimal OIDs. Empty = keep the library default.
	DisallowedPolicyOIDs []string `mapstructure:"disallowed_policy_oids"`
	// SigningAcceptedPolicyOIDs lists certificate-policy OIDs (dotted decimal)
	// of which the SIGNING certificate must assert AT LEAST ONE (any-of) — the
	// acceptance gate for QSCD/QES-grade products. For Latvia list the LVRTC
	// QSCD card-product policies (1.3.6.1.4.1.32061.2.1.2.1,.2.1.2.2,
	//.2.1.4.1,.2.1.5.1) and/or the generic ETSI QCP-n-qscd "0.4.0.194112.1.2".
	SigningAcceptedPolicyOIDs []string `mapstructure:"signing_accepted_policy_oids"`
}

// Bind registers defaults and environment-variable bindings with viper.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".nonce_ttl", 5*time.Minute)
	v.SetDefault(prefix+".ocsp_enabled", true)
	v.SetDefault(prefix+".ocsp_request_timeout", 5*time.Second)
	v.SetDefault(prefix+".session_cookie_name", "WEBEID_SESSION")
	v.SetDefault(prefix+".signing_hash_preference", []string{"SHA-256", "SHA-384", "SHA-512"})
	v.SetDefault(prefix+".allow_insecure_localhost", false)
	v.SetDefault(prefix+".enforce_host_header", true)

	_ = v.BindEnv(prefix+".origin", "WEBEID_ORIGIN")
	_ = v.BindEnv(prefix+".trusted_ca_certs_path", "WEBEID_TRUSTED_CA_CERTS_PATH")
	_ = v.BindEnv(prefix+".nonce_ttl", "WEBEID_NONCE_TTL")
	_ = v.BindEnv(prefix+".ocsp_enabled", "WEBEID_OCSP_ENABLED")
	_ = v.BindEnv(prefix+".ocsp_request_timeout", "WEBEID_OCSP_REQUEST_TIMEOUT")
	_ = v.BindEnv(prefix+".designated_ocsp_url", "WEBEID_DESIGNATED_OCSP_URL")
	_ = v.BindEnv(prefix+".ocsp_nonce_disabled_urls", "WEBEID_OCSP_NONCE_DISABLED_URLS")
	_ = v.BindEnv(prefix+".session_cookie_name", "WEBEID_SESSION_COOKIE_NAME")
	_ = v.BindEnv(prefix+".signing_hash_preference", "WEBEID_SIGNING_HASH_PREFERENCE")
	_ = v.BindEnv(prefix+".allow_insecure_localhost", "WEBEID_ALLOW_INSECURE_LOCALHOST")
	_ = v.BindEnv(prefix+".enforce_host_header", "WEBEID_ENFORCE_HOST_HEADER")
	_ = v.BindEnv(prefix+".ocsp_allowed_responder_urls", "WEBEID_OCSP_ALLOWED_RESPONDERS")
	_ = v.BindEnv(prefix+".disallowed_policy_oids", "WEBEID_DISALLOWED_POLICY_OIDS")
	_ = v.BindEnv(prefix+".signing_accepted_policy_oids", "WEBEID_SIGNING_ACCEPTED_POLICY_OIDS")
}

// Validate validates the configuration.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}
