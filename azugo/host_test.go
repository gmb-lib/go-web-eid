package webeidazugo

import "testing"

func TestHostMatches(t *testing.T) {
	origin := originHostname("https://sign.example.lv:8443")
	if origin != "sign.example.lv" {
		t.Fatalf("originHostname = %q", origin)
	}

	match := []string{
		"sign.example.lv",
		"sign.example.lv:8443",
		"SIGN.EXAMPLE.LV",
		" sign.example.lv ",
	}
	for _, h := range match {
		if !hostMatches(h, origin) {
			t.Fatalf("%q must match origin host", h)
		}
	}

	mismatch := []string{
		"",
		"evil.example",
		"sign.example.lv.evil.example",
	}
	for _, h := range mismatch {
		if hostMatches(h, origin) {
			t.Fatalf("%q must not match origin host", h)
		}
	}

	// IPv6 origins.
	v6 := originHostname("http://[::1]:5173")
	if !hostMatches("[::1]:5173", v6) || !hostMatches("[::1]", v6) {
		t.Fatal("IPv6 loopback host must match")
	}
}
