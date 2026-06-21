package webeidazugo

import (
	"crypto/x509"
	"time"

	"github.com/gmb-lib/go-web-eid/certificate"
)

// timeNow is the clock used for nonce-expiry checks; a variable so tests can
// override it.
var timeNow = time.Now

// subjectFromCertificate extracts the validated subject fields into the
// response DTO. Missing optional fields are left empty.
func subjectFromCertificate(cert *x509.Certificate) SubjectResponse {
	var s SubjectResponse
	if cn, err := certificate.SubjectCN(cert); err == nil {
		s.CommonName = cn
	}
	if id, err := certificate.SubjectIDCode(cert); err == nil {
		s.IDCode = id
	}
	if cc, err := certificate.SubjectCountryCode(cert); err == nil {
		s.CountryCode = cc
	}
	if gn, err := certificate.SubjectGivenName(cert); err == nil {
		s.GivenName = gn
	}
	if sn, err := certificate.SubjectSurname(cert); err == nil {
		s.Surname = sn
	}
	return s
}
