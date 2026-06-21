package certificate

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"unicode"
)

// errSubjectFieldMissing is returned when a requested subject field is absent.
var errSubjectFieldMissing = errors.New("certificate subject field is missing")

// OID for the X.520 surname attribute (2.5.4.4) which crypto/x509 does not map
// onto a named pkix.Name field.
var oidSurname = asn1.ObjectIdentifier{2, 5, 4, 4}

// SubjectCN returns the certificate subject common name, e.g.
// "JÕEORG,JAAK-KRISTJAN,38001085718".
func SubjectCN(c *x509.Certificate) (string, error) {
	if c.Subject.CommonName == "" {
		return "", errSubjectFieldMissing
	}
	return c.Subject.CommonName, nil
}

// SubjectIDCode returns the subject serialNumber attribute, e.g.
// "PNOEE-38001085718".
func SubjectIDCode(c *x509.Certificate) (string, error) {
	if c.Subject.SerialNumber == "" {
		return "", errSubjectFieldMissing
	}
	return c.Subject.SerialNumber, nil
}

// SubjectCountryCode returns the subject country attribute, e.g. "EE".
func SubjectCountryCode(c *x509.Certificate) (string, error) {
	if len(c.Subject.Country) == 0 || c.Subject.Country[0] == "" {
		return "", errSubjectFieldMissing
	}
	return c.Subject.Country[0], nil
}

// SubjectGivenName returns the subject givenName attribute, e.g.
// "JAAK-KRISTJAN".
func SubjectGivenName(c *x509.Certificate) (string, error) {
	for _, name := range c.Subject.Names {
		// givenName OID is 2.5.4.42.
		if name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 42}) {
			if s, ok := name.Value.(string); ok && s != "" {
				return s, nil
			}
		}
	}
	return "", errSubjectFieldMissing
}

// SubjectSurname returns the subject surname attribute, e.g. "JÕEORG".
func SubjectSurname(c *x509.Certificate) (string, error) {
	for _, name := range c.Subject.Names {
		if name.Type.Equal(oidSurname) {
			if s, ok := name.Value.(string); ok && s != "" {
				return s, nil
			}
		}
	}
	return "", errSubjectFieldMissing
}

// TitleCase converts an upper-case eID name into title case, e.g.
// "JAAK-KRISTJAN" -> "Jaak-Kristjan" and "JÕEORG" -> "Jõeorg". Word boundaries
// are spaces, hyphens and apostrophes.
func TitleCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevBoundary := true
	for _, r := range strings.ToLower(s) {
		if prevBoundary {
			b.WriteRune(unicode.ToUpper(r))
		} else {
			b.WriteRune(r)
		}
		prevBoundary = r == ' ' || r == '-' || r == '\''
	}
	return b.String()
}
