# go-web-eid

A native Go implementation of the [Web eID](https://www.id.ee/en/article/web-eid/)
authentication-token validation and eID-card signing-operations back end.

`go-web-eid` is wire-compatible with the unmodified Web eID client components
(`web-eid.js`, the browser extension and the native application) and mirrors the
public API of the official Java reference library, so existing RIA documentation
maps onto it directly.

The library is split into:

- a **framework-agnostic core** (`github.com/gmb-lib/go-web-eid`) that depends
  only on the Go standard library and `golang.org/x/crypto`; and
- a thin **Azugo HTTP integration** (`github.com/gmb-lib/go-web-eid/azugo`) that
  exposes the four endpoints the `web-eid.js` flow expects.

## Scope

In scope: challenge-nonce generation/storage, authentication-token parsing and
validation (chain, validity, key usage, policies, OCSP, signature), and the
card-operations signing flow (signing-certificate validation, algorithm/hash
negotiation, digest relay, auth-certificate surfacing). **As of v0.9.0 also
"verified finalize"** — optional signature-value verification
(`signing.VerifySignatureValue`) + authentication↔signing **identity binding**
(`certificate.CheckSameNaturalPerson`, `certificate/policy.go`) + an OCSP
responder allowlist; `/sign/finalize` returns `sigVerified`/`identityBound` when
given `digest`+`signingCertificate`. ECDSA signature bytes are still surfaced as
raw P1363 (no DER re-encoding).

Out of scope: signature-container assembly and validation (XAdES/ASiC-E,
PAdES, …). Those belong to the integrating back end, which can plug in any tool
it prefers (e.g. EU DSS, DigiDoc). The library never builds or validates a
container and never sees document bytes.

## Installation

```sh
go get github.com/gmb-lib/go-web-eid
```

## Quickstart — authentication-token validation (core)

```go
import (
    webeid "github.com/gmb-lib/go-web-eid"
    "github.com/gmb-lib/go-web-eid/certificate"
)

// Load intermediate CA trust anchors (use intermediates, not roots).
cas, _ := certificate.LoadCertificatesFromDir("/etc/webeid/cacerts")

validator, _ := webeid.NewAuthTokenValidatorBuilder().
    WithSiteOrigin("https://example.org").            // https://host[:port], no trailing slash
    WithTrustedCertificateAuthorities(cas...).
    Build()                                            // OCSP on, Mobile-ID policies disallowed

// Issue a challenge nonce per request.
store := webeid.NewInMemoryStore(sessionKeyFunc, 5*time.Minute)
gen, _ := webeid.NewChallengeNonceGeneratorBuilder().
    WithChallengeNonceStore(store).
    Build()
nonce, _ := gen.GenerateAndStoreNonce(ctx)

// Later, validate the token returned by web-eid.js authenticate().
token, _ := webeid.Parse(rawTokenJSON)
stored, _ := store.GetAndRemove(ctx)                   // single-use
cert, err := validator.Validate(ctx, token, stored.Base64EncodedNonce)
```

The signed datagram is `hash(origin) ‖ hash(challenge)`, hashed again by the
signature algorithm (the double-hash described in the specification). ECDSA
signatures are accepted in raw IEEE P1363 `r ‖ s` form, as emitted by the native
application.

## Quickstart — Azugo integration

```go
import webeidazugo "github.com/gmb-lib/go-web-eid/azugo"

cfg := &webeidazugo.Configuration{
    Origin:                "https://example.org",
    TrustedCACertsPath:    "/etc/webeid/cacerts",
    NonceTTL:              5 * time.Minute,
    OCSPEnabled:           true,
    OCSPRequestTimeout:    5 * time.Second,
    SessionCookieName:     "WEBEID_SESSION",
    SigningHashPreference: []string{"SHA-256", "SHA-384", "SHA-512"},
}

h, _ := webeidazugo.New(cfg)
_ = h.Bind(router) // registers the endpoints below
```

| Method & path | Purpose |
|---|---|
| `GET /auth/challenge` | issue a challenge nonce |
| `POST /auth/login` | validate the authentication token, log in |
| `POST /sign/certificate` | validate the signing certificate, negotiate algorithm/hash |
| `POST /sign/finalize` | return the card's signed digest + auth certificate to the caller |

Each route runs behind the `EnsureSession` pre-auth cookie middleware (HttpOnly,
Secure, SameSite=Strict). Enable CSRF protection on the `POST` routes in your
application.

## Configuration (environment variables)

| Variable | Default | Notes |
|---|---|---|
| `WEBEID_ORIGIN` | – | `https://host[:port]`, no trailing slash |
| `WEBEID_TRUSTED_CA_CERTS_PATH` | – | file or directory of intermediate CA certs |
| `WEBEID_NONCE_TTL` | `5m` | challenge-nonce lifetime |
| `WEBEID_OCSP_ENABLED` | `true` | toggle OCSP revocation checks |
| `WEBEID_OCSP_REQUEST_TIMEOUT` | `5s` | per-request OCSP timeout |
| `WEBEID_DESIGNATED_OCSP_URL` | – | optional designated responder URL |
| `WEBEID_SESSION_COOKIE_NAME` | `WEBEID_SESSION` | pre-auth session cookie |
| `WEBEID_SIGNING_HASH_PREFERENCE` | `SHA-256,SHA-384,SHA-512` | ordered hash preference |

## Security

- Nonce: ≥ 256-bit entropy, single-use (`GetAndRemove`), TTL-checked, session-bound.
- Certificate chain is always verified to a configured **intermediate** CA and
  checked with OCSP; the `unverifiedCertificate` is never trusted before validation.
- Standard-library crypto only; no cgo.
- HTTPS-only origin; the extension also enforces this client-side.

## License

See [LICENSE](LICENSE).
