package cert

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// CanonicalHeader tags the encoding version. A future field set gets a new tag,
// so an old verifier refuses a new payload instead of misreading it.
const CanonicalHeader = "omsme-cert/v1\n"

// Field names a signed field. The verify screen lists these so the reader can
// see exactly which claims the signature covers — and which it does not.
type Field struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type fieldSpec struct {
	Field
	get func(Certificate) string
	set func(*Certificate, string) error
}

// fieldSpecs is the single source of truth for the signed field set and its
// order. The encoder, the decoder and CoveredFields all read it, so the three
// can never drift apart.
var fieldSpecs = []fieldSpec{
	{
		Field: Field{Key: "id", Label: "Certificate number"},
		get:   func(c Certificate) string { return c.ID },
		set:   func(c *Certificate, v string) error { c.ID = v; return nil },
	},
	{
		Field: Field{Key: "learner_name", Label: "Learner name"},
		get:   func(c Certificate) string { return c.LearnerName },
		set:   func(c *Certificate, v string) error { c.LearnerName = v; return nil },
	},
	{
		Field: Field{Key: "course", Label: "Course"},
		get:   func(c Certificate) string { return c.Course },
		set:   func(c *Certificate, v string) error { c.Course = v; return nil },
	},
	{
		Field: Field{Key: "hours", Label: "Course hours"},
		get:   func(c Certificate) string { return strconv.Itoa(c.Hours) },
		set: func(c *Certificate, v string) error {
			n, err := parseStrictInt(v)
			if err != nil {
				return err
			}
			c.Hours = n
			return nil
		},
	},
	{
		Field: Field{Key: "grade", Label: "Grade or result"},
		get:   func(c Certificate) string { return c.Grade },
		set:   func(c *Certificate, v string) error { c.Grade = v; return nil },
	},
	{
		Field: Field{Key: "issued_on", Label: "Issue date"},
		get:   func(c Certificate) string { return c.IssuedOn },
		set:   func(c *Certificate, v string) error { c.IssuedOn = v; return nil },
	},
	{
		Field: Field{Key: "issuer_name", Label: "Institute name"},
		get:   func(c Certificate) string { return c.IssuerName },
		set:   func(c *Certificate, v string) error { c.IssuerName = v; return nil },
	},
	{
		Field: Field{Key: "issuer_pubkey", Label: "Institute public key"},
		get:   func(c Certificate) string { return c.IssuerPubKey },
		set:   func(c *Certificate, v string) error { c.IssuerPubKey = v; return nil },
	},
}

// CoveredFields returns the signed field set, in canonical order.
func CoveredFields() []Field {
	out := make([]Field, 0, len(fieldSpecs))
	for _, f := range fieldSpecs {
		out = append(out, f.Field)
	}
	return out
}

// Canonicalise produces the exact bytes that get signed.
//
// The encoding is a version header followed by one line per field, in a fixed
// order read from fieldSpecs, written as:
//
//	<key>=<byte length>:<value>\n
//
// Nothing iterates over a map, so the output never depends on Go's map
// ordering: the same certificate always produces the same bytes, in this
// process and in any other.
//
// The length prefix is what makes the encoding unambiguous. Naive
// concatenation would let one field's tail move into the next field's head —
// learner "AB" with course "C" would collide with learner "A" with course
// "BC". Here they encode as "...=2:AB\n...=1:C\n" and "...=1:A\n...=2:BC\n",
// which differ, so no two distinct field sets can share a signature. The
// prefix also means a value may itself contain ':' or a newline without
// confusing the decoder.
func Canonicalise(c Certificate) []byte {
	var b bytes.Buffer
	b.WriteString(CanonicalHeader)
	for _, f := range fieldSpecs {
		v := f.get(c)
		b.WriteString(f.Key)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// DecodeCanonical is the exact inverse of Canonicalise. It is strict on
// purpose: any deviation — a missing field, fields out of order, a length that
// does not match, a padded number, trailing bytes — is an error rather than a
// best guess, because a payload that decodes two ways could be presented two
// ways under one signature.
func DecodeCanonical(b []byte) (Certificate, error) {
	rest, ok := bytes.CutPrefix(b, []byte(CanonicalHeader))
	if !ok {
		return Certificate{}, errors.New("payload is not a version 1 certificate (wrong or missing header)")
	}

	var c Certificate
	for _, f := range fieldSpecs {
		rest, ok = bytes.CutPrefix(rest, []byte(f.Key+"="))
		if !ok {
			return Certificate{}, fmt.Errorf("field %q is missing or out of order", f.Key)
		}
		colon := bytes.IndexByte(rest, ':')
		if colon < 1 {
			return Certificate{}, fmt.Errorf("field %q has no length prefix", f.Key)
		}
		n, err := parseStrictInt(string(rest[:colon]))
		if err != nil {
			return Certificate{}, fmt.Errorf("field %q length: %w", f.Key, err)
		}
		rest = rest[colon+1:]
		if len(rest) < n+1 {
			return Certificate{}, fmt.Errorf("field %q is truncated", f.Key)
		}
		if rest[n] != '\n' {
			return Certificate{}, fmt.Errorf("field %q is not terminated by a newline", f.Key)
		}
		if err := f.set(&c, string(rest[:n])); err != nil {
			return Certificate{}, fmt.Errorf("field %q: %w", f.Key, err)
		}
		rest = rest[n+1:]
	}
	if len(rest) != 0 {
		return Certificate{}, errors.New("payload has trailing bytes after the last field")
	}
	return c, nil
}

// parseStrictInt accepts only plain decimal digits with no sign and no
// redundant leading zero, so each number has exactly one encoding.
func parseStrictInt(s string) (int, error) {
	if s == "" {
		return 0, errors.New("number is empty")
	}
	if strings.ContainsAny(s, "+-") {
		return 0, fmt.Errorf("number %q must not be signed", s)
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("number %q contains a non-digit", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("number %q has a leading zero", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("number %q is out of range", s)
	}
	return n, nil
}
