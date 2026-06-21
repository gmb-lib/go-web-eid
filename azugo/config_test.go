package webeidazugo

import (
	"testing"
	"time"

	"azugo.io/core/validation"
	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

func TestConfigurationBindDefaults(t *testing.T) {
	v := viper.New()
	cfg := &Configuration{}
	cfg.Bind("webeid", v)

	qt.Check(t, qt.Equals(v.GetDuration("webeid.nonce_ttl"), 5*time.Minute))
	qt.Check(t, qt.IsTrue(v.GetBool("webeid.ocsp_enabled")))
	qt.Check(t, qt.Equals(v.GetDuration("webeid.ocsp_request_timeout"), 5*time.Second))
	qt.Check(t, qt.Equals(v.GetString("webeid.session_cookie_name"), "WEBEID_SESSION"))
	qt.Check(t, qt.DeepEquals(v.GetStringSlice("webeid.signing_hash_preference"),
		[]string{"SHA-256", "SHA-384", "SHA-512"}))
}

func TestConfigurationValidate(t *testing.T) {
	valid := validation.New()

	good := &Configuration{
		Origin:                "https://example.org",
		TrustedCACertsPath:    "/etc/webeid/ca.pem",
		NonceTTL:              5 * time.Minute,
		OCSPRequestTimeout:    5 * time.Second,
		SessionCookieName:     "WEBEID_SESSION",
		SigningHashPreference: []string{"SHA-256"},
	}
	qt.Check(t, qt.IsNil(good.Validate(valid)))

	missingOrigin := *good
	missingOrigin.Origin = ""
	qt.Check(t, qt.IsNotNil(missingOrigin.Validate(valid)))

	badHash := *good
	badHash.SigningHashPreference = []string{"MD5"}
	qt.Check(t, qt.IsNotNil(badHash.Validate(valid)))
}
