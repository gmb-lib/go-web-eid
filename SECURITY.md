# Security policy

This library is a native Go implementation of the Web eID authentication-token validation and
eID-card signing-operations back end. It decides whether a person holding a national eID card is
who the card says they are, and it drives the operation in which that card produces a legally
meaningful signature. Both answers are acted on directly: a false accept logs in the wrong person,
and a mis-driven signing operation puts a real signature on something the cardholder did not
intend to sign.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/gmb-lib/go-web-eid/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the configuration it needs — trust anchors, policies, OCSP settings — if it only appears under
  particular settings;
- whether you have told anyone else, and whether a disclosure date already binds you.

Please do not send us real certificates or tokens belonging to an identifiable person. A test card,
a redacted token, or the shape of one, is enough to explain almost any finding here.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

Two failures are unacceptable: authenticating someone who is not the cardholder, and signing
something other than what the cardholder was shown. The classes that matter most:

- An authentication token accepted that should have been refused — an untrusted or unverified
  certificate chain, an expired or not-yet-valid certificate, wrong key usage, a certificate policy
  that is not in the accepted set, a signature that does not verify, or a revocation check that was
  skipped, failed open, or answered by a responder that was not verified.
- A challenge nonce that can be replayed, guessed, or used by a session other than the one it was
  issued to; a nonce store that another session can read or overwrite; a nonce accepted after it
  should have expired.
- An OCSP responder outside the allowlist being trusted, or its answer accepted without checking
  that it is signed by a responder authorised for that issuer.
- The signing flow relaying a digest that does not belong to the document the operation was started
  for, or negotiating an algorithm or hash weaker than the one that was agreed.
- A signing certificate accepted that is not the one the operation was started for.
- `sigVerified` or `identityBound` reported true when the signature value does not verify, or when
  the authentication and signing certificates are not the same natural person. A false *true* here
  is worse than an error, because a caller stops checking.
- The Azugo endpoints exposing more than the flow needs — a certificate, nonce, digest or token
  reaching a party that should not see it.

Denial of service and findings that need an already-compromised host are in scope but lower
priority. Reports about outdated dependencies are welcome where you can show the vulnerable path
is actually reachable.

## Scope

This policy covers the code in this repository. It does not cover the Web eID browser extension,
native application or `web-eid.js` (report those to their maintainers), the certification
authorities and OCSP responders whose answers are being checked, or the applications that consume
this library. Which trust anchors, policies and responders a deployment accepts is the deploying
application's configuration — but a report that a *default* is unsafe is very much in scope.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward. This module is pre-1.0: the API may change between minor versions,
and a security fix may arrive alongside such a change.
