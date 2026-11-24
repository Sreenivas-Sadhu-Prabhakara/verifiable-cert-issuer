// Package cert issues and verifies tamper-proof skill certificates for small
// training institutes.
//
// A certificate is a fixed set of eight fields. The institute holds an Ed25519
// private key; signing produces a detached 64-byte signature over a canonical,
// unambiguous encoding of those eight fields. Anyone holding the institute's
// public key can verify a certificate offline, with no network access and
// without contacting the institute.
//
// Everything in this package is a pure function over its arguments, apart from
// key generation (which reads the system random source) and the two key-file
// helpers (which touch the local filesystem).
package cert

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// DateLayout is the only accepted date form: a zero-padded calendar date.
const DateLayout = "2006-01-02"

// MaxHours is the largest course duration the issuer will accept. It is a
// sanity bound on typing mistakes, not a rule from any authority.
const MaxHours = 100000

// Field length caps. They keep a certificate code short enough to paste into
// an email or a chat message.
const (
	MaxNameLen   = 120
	MaxCourseLen = 160
	MaxGradeLen  = 40
	MaxIDLen     = 60
)

// Certificate is the signed field set. Changing any field changes the canonical
// bytes and so invalidates an existing signature.
type Certificate struct {
	ID           string `json:"id"`
	LearnerName  string `json:"learnerName"`
	Course       string `json:"course"`
	Hours        int    `json:"hours"`
	Grade        string `json:"grade"`
	IssuedOn     string `json:"issuedOn"`
	IssuerName   string `json:"issuerName"`
	IssuerPubKey string `json:"issuerPubKey"`
}

// Clean trims surrounding whitespace and collapses internal runs of whitespace
// in every text field. The issuer applies it once, before signing, so that the
// bytes carried in the certificate code are exactly the bytes that were signed.
// Clean is idempotent: Clean(Clean(c)) == Clean(c).
func Clean(c Certificate) Certificate {
	c.ID = squash(c.ID)
	c.LearnerName = squash(c.LearnerName)
	c.Course = squash(c.Course)
	c.Grade = squash(c.Grade)
	c.IssuedOn = squash(c.IssuedOn)
	c.IssuerName = squash(c.IssuerName)
	c.IssuerPubKey = strings.TrimSpace(c.IssuerPubKey)
	return c
}

func squash(s string) string {
	return strings.Join(strings.FieldsFunc(s, unicode.IsSpace), " ")
}

// Validate reports every problem with a certificate, in a stable order, so the
// UI can show them all at once. An empty slice means the certificate can be
// signed. Grade is optional; every other field is required.
func Validate(c Certificate) []string {
	var problems []string

	if c.ID == "" {
		problems = append(problems, "Certificate number is required.")
	} else if len(c.ID) > MaxIDLen {
		problems = append(problems, fmt.Sprintf("Certificate number is longer than %d characters.", MaxIDLen))
	}

	if c.LearnerName == "" {
		problems = append(problems, "Learner name is required.")
	} else if len(c.LearnerName) > MaxNameLen {
		problems = append(problems, fmt.Sprintf("Learner name is longer than %d characters.", MaxNameLen))
	}

	if c.Course == "" {
		problems = append(problems, "Course name is required.")
	} else if len(c.Course) > MaxCourseLen {
		problems = append(problems, fmt.Sprintf("Course name is longer than %d characters.", MaxCourseLen))
	}

	switch {
	case c.Hours < 0:
		problems = append(problems, "Course hours cannot be negative.")
	case c.Hours > MaxHours:
		problems = append(problems, fmt.Sprintf("Course hours cannot exceed %d.", MaxHours))
	}

	if len(c.Grade) > MaxGradeLen {
		problems = append(problems, fmt.Sprintf("Grade is longer than %d characters.", MaxGradeLen))
	}

	if c.IssuedOn == "" {
		problems = append(problems, "Issue date is required.")
	} else if err := ValidateDate(c.IssuedOn); err != nil {
		problems = append(problems, "Issue date: "+err.Error())
	}

	if c.IssuerName == "" {
		problems = append(problems, "Institute name is required.")
	} else if len(c.IssuerName) > MaxNameLen {
		problems = append(problems, fmt.Sprintf("Institute name is longer than %d characters.", MaxNameLen))
	}

	if c.IssuerPubKey == "" {
		problems = append(problems, "Institute public key is required; set up the institute first.")
	} else if _, err := ParsePublicKey(c.IssuerPubKey); err != nil {
		problems = append(problems, "Institute public key: "+err.Error())
	}

	return problems
}

// ValidateDate accepts only a real, zero-padded calendar date. It rejects
// 2023-02-29 (not a leap year) and 1900-02-29 (a century year that is not
// divisible by 400) while accepting 2024-02-29 and 2000-02-29.
func ValidateDate(s string) error {
	t, err := time.Parse(DateLayout, s)
	if err != nil {
		return fmt.Errorf("%q is not a date in YYYY-MM-DD form", s)
	}
	// time.Parse tolerates unpadded months and days; require the canonical form
	// so that the same calendar day always produces the same signed bytes.
	if t.Format(DateLayout) != s {
		return fmt.Errorf("%q must be written as %s", s, t.Format(DateLayout))
	}
	return nil
}

// IssuerCode derives a short uppercase prefix for certificate numbers from the
// institute's name: the first ASCII letter of up to three words. Names with no
// usable ASCII letters fall back to "CERT", so the prefix is always printable
// and safe inside a certificate number.
func IssuerCode(name string) string {
	var b strings.Builder
	for _, word := range strings.Fields(name) {
		for _, r := range word {
			if r >= 'a' && r <= 'z' {
				r -= 32
			}
			if r >= 'A' && r <= 'Z' {
				b.WriteRune(r)
				break
			}
		}
		if b.Len() == 3 {
			break
		}
	}
	if b.Len() == 0 {
		return "CERT"
	}
	return b.String()
}

// FormatID builds a certificate number such as "ASI-2026-00007". The sequence
// is zero-padded to five digits and widens beyond that rather than wrapping.
func FormatID(prefix string, year, seq int) string {
	if prefix == "" {
		prefix = "CERT"
	}
	if seq < 1 {
		seq = 1
	}
	return prefix + "-" + strconv.Itoa(year) + "-" + fmt.Sprintf("%05d", seq)
}
