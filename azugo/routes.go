package webeidazugo

import (
	"encoding/base64"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"

	"github.com/gmb-lib/go-web-eid/assertion"
	"github.com/gmb-lib/go-web-eid/certificate"
	"github.com/gmb-lib/go-web-eid/exceptions"
	"github.com/gmb-lib/go-web-eid/signing"
)

// Bind registers the four Web eID endpoints on the given router, each behind
// the EnsureSession pre-auth cookie middleware.
//
// CSRF protection must be enabled separately on the POST routes by the
// integrating application.
func (h *Handler) Bind(g azugo.Router) error {
	auth := g.Group("/auth")
	auth.Use(EnsureSession(h.config))
	auth.Get("/challenge", h.challenge)
	auth.Post("/login", h.login)

	// Stateless validation: the nonce is in the request body
	// (the consuming Auth service owns the challenge/session), so this route is
	// registered WITHOUT EnsureSession. It is still subject to whatever auth the
	// integrator gates the router with (the engine puts it behind service auth).
	g.Post("/auth/validate", h.validate)

	sign := g.Group("/sign")
	sign.Use(EnsureSession(h.config))
	sign.Post("/certificate", h.signingCertificate)
	sign.Post("/finalize", h.finalize)

	// Publish the assertion verification keys when assertion issuance is enabled.
	if h.publishedKeys != nil {
		g.Get("/.well-known/jwks.json", h.jwks)
	}
	return nil
}

// jwks publishes the identity-assertion verification keys (JWKS).
//
// @operationId WebEidJWKS
// @title Assertion verification keys
// @success 200 {object} assertion.JWKS "JWKS"
// @resource WebEID
// @route /.well-known/jwks.json [get].
func (h *Handler) jwks(ctx *azugo.Context) {
	ctx.JSON(h.publishedKeys.JWKS())
}

// challenge issues a fresh challenge nonce bound to the session.
//
// @operationId WebEidChallenge
// @title Issue challenge nonce
// @success 200 ChallengeResponse response.ChallengeResponse "Challenge nonce"
// @resource WebEID
// @route /auth/challenge [get].
func (h *Handler) challenge(ctx *azugo.Context) {
	nonce, err := h.generator.GenerateAndStoreNonce(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(ChallengeResponse{Nonce: nonce.Base64EncodedNonce})
}

// login validates the authentication token and establishes the user.
//
// @operationId WebEidLogin
// @title Validate authentication token
// @param LoginRequest body request.LoginRequest true "Authentication token"
// @success 200 SubjectResponse response.SubjectResponse "Authenticated subject"
// @failure 401 {empty} "Unauthorized"
// @resource WebEID
// @route /auth/login [post].
func (h *Handler) login(ctx *azugo.Context) {
	var req LoginRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}

	stored, err := h.store.GetAndRemove(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}
	if stored.Expired(timeNow(), h.config.NonceTTL) {
		ctx.Error(exceptions.ErrChallengeNonceExpired)
		return
	}

	cert, err := h.validator.Validate(ctx, &req.AuthToken, stored.Base64EncodedNonce)
	if err != nil {
		ctx.Error(err)
		return
	}

	subject := subjectFromCertificate(cert)
	ctx.SetUser(user.New(map[string]token.ClaimStrings{
		"sub":         {subject.IDCode},
		"given_name":  {subject.GivenName},
		"family_name": {subject.Surname},
		"name":        {certificate.TitleCase(subject.GivenName + " " + subject.Surname)},
	}))

	// When configured as the external Web eID service, return a signed identity
	// assertion the consuming Auth service verifies and maps. Otherwise return
	// the bare validated subject (standalone / library use).
	if h.assertionIssuer != nil {
		tok, err := h.assertionIssuer.Issue(assertion.Subject{
			NationalID: subject.IDCode,
			Country:    subject.CountryCode,
			GivenName:  subject.GivenName,
			FamilyName: subject.Surname,
			LoA:        "high", // physical eID smart card + QSCD → eIDAS "high"
		})
		if err != nil {
			ctx.Error(err)
			return
		}
		ctx.JSON(AssertionResponse{Assertion: tok, Subject: subject})
		return
	}
	ctx.JSON(subject)
}

// validate is the STATELESS authentication-token validation:
// the challenge nonce is supplied in the request body by the consuming Auth
// service (which owns the challenge/session), so there is no cookie session.
// It returns the validated subject (or a signed assertion when an issuer is
// configured), exactly like login. Intended for server-to-server use.
//
// @operationId WebEidValidate
// @title Validate authentication token (stateless)
// @param ValidateRequest body request.ValidateRequest true "Auth token + challenge nonce"
// @success 200 SubjectResponse response.SubjectResponse "Authenticated subject"
// @failure 401 {empty} "Unauthorized"
// @resource WebEID
// @route /auth/validate [post].
func (h *Handler) validate(ctx *azugo.Context) {
	var req ValidateRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}
	if err := req.Validate(ctx); err != nil {
		ctx.Error(err)
		return
	}

	cert, err := h.validator.Validate(ctx, &req.AuthToken, req.Nonce)
	if err != nil {
		ctx.Error(err)
		return
	}

	subject := subjectFromCertificate(cert)
	ctx.SetUser(user.New(map[string]token.ClaimStrings{
		"sub":         {subject.IDCode},
		"given_name":  {subject.GivenName},
		"family_name": {subject.Surname},
		"name":        {certificate.TitleCase(subject.GivenName + " " + subject.Surname)},
	}))

	if h.assertionIssuer != nil {
		tok, err := h.assertionIssuer.Issue(assertion.Subject{
			NationalID: subject.IDCode,
			Country:    subject.CountryCode,
			GivenName:  subject.GivenName,
			FamilyName: subject.Surname,
			LoA:        "high", // physical eID smart card + QSCD → eIDAS "high"
		})
		if err != nil {
			ctx.Error(err)
			return
		}
		ctx.JSON(AssertionResponse{Assertion: tok, Subject: subject})
		return
	}
	ctx.JSON(subject)
}

// signingCertificate validates the signing certificate and negotiates the
// signature algorithm and hash function.
//
// @operationId WebEidSigningCertificate
// @title Validate signing certificate
// @param SigningCertificateRequest body request.SigningCertificateRequest true "Signing certificate"
// @success 200 SigningCertificateResponse response.SigningCertificateResponse "Negotiated algorithm"
// @failure 422 {empty} "Unprocessable entity"
// @resource WebEID
// @route /sign/certificate [post].
func (h *Handler) signingCertificate(ctx *azugo.Context) {
	var req SigningCertificateRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}
	der, err := base64.StdEncoding.DecodeString(req.Certificate)
	if err != nil {
		ctx.Error(exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, err))
		return
	}
	_, algo, hashFn, err := h.signer.PrepareSigning(ctx, der, req.SupportedSignatureAlgorithms)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(SigningCertificateResponse{SignatureAlgorithm: algo, HashFunction: hashFn})
}

// finalize returns the card's signed digest and authentication certificate to
// the caller for container finalization.
//
// @operationId WebEidFinalize
// @title Finalize signing
// @param FinalizeRequest body request.FinalizeRequest true "Signature value"
// @success 200 FinalizeResponse response.FinalizeResponse "OK"
// @failure 422 {empty} "Unprocessable entity"
// @resource WebEID
// @route /sign/finalize [post].
func (h *Handler) finalize(ctx *azugo.Context) {
	var req FinalizeRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		ctx.Error(exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, err))
		return
	}
	authDER, err := base64.StdEncoding.DecodeString(req.AuthCertificate)
	if err != nil {
		ctx.Error(exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, err))
		return
	}
	authCert, signed, err := h.signer.Finalize(sig, authDER)
	if err != nil {
		ctx.Error(err)
		return
	}

	// Verified finalize: when the caller supplies the digest and the signing
	// certificate, verify the card's signature value and the identity binding
	// before echoing anything back.
	var (
		sigVerified   bool
		identityBound bool
	)
	if req.Digest != "" || req.SigningCertificate != "" {
		if req.Digest == "" || req.SigningCertificate == "" {
			ctx.Error(exceptions.Wrap(exceptions.ErrSignatureValueInvalid,
				errVerifiedFinalizeNeedsBoth))
			return
		}
		digest, derr := base64.StdEncoding.DecodeString(req.Digest)
		if derr != nil {
			ctx.Error(exceptions.Wrap(exceptions.ErrSignatureValueInvalid, derr))
			return
		}
		signDER, derr := base64.StdEncoding.DecodeString(req.SigningCertificate)
		if derr != nil {
			ctx.Error(exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, derr))
			return
		}
		signCert, derr := signing.ParseSigningCertificate(signDER)
		if derr != nil {
			ctx.Error(derr)
			return
		}
		if verr := signing.VerifySignatureValue(signCert, req.SignatureAlgorithm, digest, sig); verr != nil {
			ctx.Error(verr)
			return
		}
		sigVerified = true

		checked, berr := certificate.CheckSameNaturalPerson(authCert, signCert)
		if berr != nil {
			ctx.Error(berr)
			return
		}
		// checked=false: organisational seal certificate (or non-PNO subject) —
		// person binding does not apply; the integrator authorises seal use.
		identityBound = checked
	}

	ctx.JSON(FinalizeResponse{
		Status:            "ok",
		Signature:         base64.StdEncoding.EncodeToString(signed),
		AuthCertificate:   base64.StdEncoding.EncodeToString(authCert.Raw),
		SignatureVerified: sigVerified,
		IdentityBound:     identityBound,
	})
}

// errVerifiedFinalizeNeedsBoth signals a partial verified-finalize request.
var errVerifiedFinalizeNeedsBoth = errPartialVerifiedFinalize{}

type errPartialVerifiedFinalize struct{}

func (errPartialVerifiedFinalize) Error() string {
	return "verified finalize requires both digest and signingCertificate"
}
