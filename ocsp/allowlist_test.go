package ocsp

import "testing"

func TestIsResponderAllowed(t *testing.T) {
	c := NewChecker(Options{
		AllowedResponderURLs: []string{
			"http://ocsp.prep.eparaksts.lv",      // full URL
			"ocsp.eparaksts.lv",                  // bare host
			"https://aia.demo.sk.ee/esteid2018/", // trailing slash tolerated
		},
	})

	allowed := []string{
		"http://ocsp.prep.eparaksts.lv",
		"http://ocsp.prep.eparaksts.lv/", // trailing slash
		"http://OCSP.PREP.EPARAKSTS.LV",  // case-insensitive
		"http://ocsp.eparaksts.lv/path",  // host entry matches any path/scheme
		"https://aia.demo.sk.ee/esteid2018",
	}
	for _, u := range allowed {
		if !c.isResponderAllowed(u) {
			t.Fatalf("%q must be allowed", u)
		}
	}

	denied := []string{
		"http://attacker.internal/ocsp",
		"http://169.254.169.254/latest/meta-data", // SSRF probe via crafted AIA
		"http://ocsp.prep.eparaksts.lv.evil.example",
	}
	for _, u := range denied {
		if c.isResponderAllowed(u) {
			t.Fatalf("%q must be denied", u)
		}
	}

	// Empty allowlist = unrestricted (backward compatible).
	open := NewChecker(Options{})
	if !open.isResponderAllowed("http://anything.example") {
		t.Fatal("empty allowlist must not restrict")
	}
}
