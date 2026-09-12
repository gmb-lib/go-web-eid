# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency — what changed, and what it means for code that already
uses it.

## v0.15.4

Dependency maintenance with one thing to act on: **this library now needs Go 1.27**. No source
changed here, and every dependency that moved was checked against what this library actually
uses — none of it reaches your code.

### Changed

- **The module declares `go 1.27.0`** (was `1.26.6`), so your own module has to be on Go 1.27
  before it can build against this one. A dependency's `go` line does **not** make the go command
  fetch a newer toolchain for you — measured both ways: a consumer whose own `go` directive is
  lower stops with a `requires go >= 1.27.0 (running go 1.26.6)` error, and it stops there with
  `GOTOOLCHAIN` on its `auto` default just as it does under `local`. Raise your own `go` directive
  to `1.27.0` first; from there the go command downloads and uses the 1.27 toolchain by itself.
  CI that reads `go-version-file: go.mod` follows the bump with no workflow edit — a workflow
  naming a Go version in the YAML needs that line changed.

### Notes

- **`golang.org/x/crypto` → v0.57.0** (was v0.55.0). This library uses exactly one package from it,
  `x/crypto/ocsp`, and that package is **byte-identical** between the two versions (compared file by
  file in the module cache). Nothing about how an OCSP response is parsed or checked changes.

- **`azugo.io/azugo` and `azugo.io/core` → v0.38.1** (was v0.38.0). Between those two releases
  `azugo` changes one file, `middleware/metrics.go`, and `core` changes one, `cache/options.go` —
  and that one only drops a lint directive. This library has no metrics code and imports only
  `core/validation`, so neither touches it. The metrics change is real but arrives in a service
  through whatever binds azugo's metrics configuration, not through here: from azugo v0.38.1 the
  metrics endpoint stops negotiating OpenMetrics and always answers
  `text/plain; version=0.0.4; charset=utf-8` with no `# EOF` terminator. **Check your scrape
  configuration before you deploy** if it demands the OpenMetrics content type.

- **`github.com/valyala/fasthttp` → v1.74.0** (was v1.73.0), which swaps the brotli implementation
  underneath: `github.com/andybalholm/brotli` leaves the dependency graph and
  `github.com/molecule-man/go-brrr` v1.1.0 takes its place. This library touches fasthttp only in
  the azugo session handling and compresses nothing. Also moved indirectly:
  `go-playground/validator/v10` → v10.30.4, `klauspost/compress` → v1.20.0, `golang.org/x/sys` →
  v0.48.0, `golang.org/x/text` → v0.42.0.

- The wider fasthttp and x/crypto releases change a great many files upstream. What is written
  above is what was read and measured against *this* library — not a review of those releases.

- The gate is green on the new set: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`, and
  `go test -race` across all nine packages with **0 races**; `govulncheck` reports nothing this
  library calls.

## v0.15.3

Repository housekeeping only. No library code changed, so a bump from v0.15.2 asks nothing of you.
*(Written after the fact — the tag went out without an entry.)*

### Notes

- The repository gained a code of conduct, and the advisory DCO workflow was removed now that the
  sign-off is enforced by the organisation's app together with a branch ruleset. What a
  contribution has to carry is unchanged.

## v0.15.2

### Changed

- **`azugo.io/azugo` and `azugo.io/core` → v0.38.0.** Nothing in this library's own surface
  changes with them: build, vet, tests, linter and `go mod tidy -diff` all pass unchanged.

  One thing in that framework release is worth knowing if you use it directly too: `user.Basic`'s
  `MarshalJSON` **moved to a pointer receiver**, so a `Basic` *value* no longer satisfies
  `json.Marshaler` and marshalling one by value silently produces default field JSON instead of the
  custom form — no compile error. This library only ever holds the pointer that `user.New` returns,
  so its own behaviour is unaffected.

### Notes

- The repository gained the open-source kit it was missing — `SECURITY.md`, `CONTRIBUTING.md`,
  a secret-scan configuration and the README sections pointing at them — plus this file. No code
  changed with any of it.

---

The entries below were **reconstructed from git history** rather than written at the time, so they
say what each tag contains, not why it was decided. They cover what a consumer would have to act on;
releases that only moved dependencies are named as such.

## v0.15.1

- **JWKS key parsing now validates the point.** A P-256 key from a JWKS is built by parsing the SEC 1
  uncompressed encoding instead of assigning the raw coordinates, so **a point that is not on the
  curve is rejected** at parse time rather than becoming a key that silently fails every
  verification afterwards. **An oversized coordinate is rejected** too. A coordinate shorter than 32
  bytes — a producer that stripped leading zeros, which RFC 7518 says it should not — is still
  accepted and left-padded; that was already true, and dropping it would have been a behaviour
  change rather than a fix.

## v0.15.0

- Dependency update only.

## v0.14.0

- **Trust can be reloaded at runtime, without restarting the process.** New: `NewRuntimeTrustStore`
  (a store that starts empty), `TrustStore.Reload`, the `WithRuntimeTrust()` option and
  `Handler.ReloadTrust()`. A reload swaps an atomic snapshot; it refuses to leave the store empty,
  and a failed reload keeps the current set serving rather than dropping it.
- `TrustStore.Intermediates()` and the other readers are unchanged in signature and now read through
  that snapshot, so they stay correct while a reload is in flight.
- **New exported error: `ErrNoCertificatesFound`.** A trust source that was readable but held no
  certificates already failed; the failure can now be matched with `errors.Is` instead of by its
  message.

## v0.13.2 · v0.13.1

- Dependency updates only.

## v0.13.0

- **Breaking: `KeySet.JWKS()` now returns `(JWKS, error)`** — it was `JWKS` alone. A key that cannot
  be encoded as a JWK now surfaces as an error instead of being silently dropped from the set an
  endpoint publishes. `MarshalJWKS` is unchanged for callers.
- `azugo.io/*` → v0.35.1.

## v0.12.0

- **Breaking: `Configuration.Origin string` became `Configuration.Origins []string`.** The same
  engine can now validate tokens from more than one front-end origin, and a token verifies against
  whichever listed origin the browser actually used. The environment variable keeps its name,
  `WEBEID_ORIGIN`, and accepts a comma-separated list. Code that sets the field in Go must be
  updated; a deployment setting a single origin needs no change.

## v0.11.0

- **`AuthTokenValidatorBuilder.WithSiteOrigins(origins ...string)`** — the validator half of the
  same multiple-origin support.

## v0.10.0 and earlier

- Not reconstructed. See the git history and the tag list.
