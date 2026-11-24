package cert_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sreenivas-sadhu-prabhakara/verifiable-cert-issuer/internal/cert"
)

// zeroKey is a syntactically valid public key string, used where the tests care
// about encoding rather than cryptography.
var zeroKey = strings.Repeat("A", 43)

func baseCert() cert.Certificate {
	return cert.Certificate{
		ID:           "ASI-2026-00001",
		LearnerName:  "Asha Kumari",
		Course:       "Arc Welding Level 2",
		Hours:        120,
		Grade:        "A",
		IssuedOn:     "2026-03-14",
		IssuerName:   "Acme Skills Institute",
		IssuerPubKey: zeroKey,
	}
}

// with returns a copy of baseCert with one or more fields changed.
func with(fns ...func(*cert.Certificate)) cert.Certificate {
	c := baseCert()
	for _, fn := range fns {
		fn(&c)
	}
	return c
}

func TestCanonicaliseIsDeterministic(t *testing.T) {
	// Built twice with the fields assigned in a different source order: the
	// encoder must not depend on construction order, and because it walks a
	// fixed slice rather than a map, repeated calls must be byte-identical.
	a := cert.Certificate{
		IssuerPubKey: zeroKey,
		IssuedOn:     "2026-03-14",
		Hours:        120,
		Course:       "Arc Welding Level 2",
		LearnerName:  "Asha Kumari",
		Grade:        "A",
		IssuerName:   "Acme Skills Institute",
		ID:           "ASI-2026-00001",
	}
	want := cert.Canonicalise(baseCert())
	if got := cert.Canonicalise(a); !bytes.Equal(got, want) {
		t.Fatalf("construction order changed the canonical bytes:\n got %q\nwant %q", got, want)
	}
	for i := 0; i < 500; i++ {
		if got := cert.Canonicalise(baseCert()); !bytes.Equal(got, want) {
			t.Fatalf("call %d produced different bytes:\n got %q\nwant %q", i, got, want)
		}
	}
}

func TestCanonicaliseFieldOrderMatchesCoveredFields(t *testing.T) {
	covered := cert.CoveredFields()
	if len(covered) != 8 {
		t.Fatalf("CoveredFields() returned %d fields, want the 8 signed fields", len(covered))
	}
	body := string(cert.Canonicalise(baseCert()))
	if !strings.HasPrefix(body, cert.CanonicalHeader) {
		t.Fatalf("canonical bytes do not start with the version header: %q", body)
	}
	at := len(cert.CanonicalHeader)
	for _, f := range covered {
		idx := strings.Index(body[at:], f.Key+"=")
		if idx != 0 {
			t.Errorf("field %q is not the next field at offset %d; remaining payload %q", f.Key, at, body[at:])
			continue
		}
		at += len(f.Key) + 1
		at += strings.Index(body[at:], "\n") + 1
	}
	if at != len(body) {
		t.Errorf("canonical bytes have %d unaccounted trailing bytes: %q", len(body)-at, body[at:])
	}
}

// TestCanonicaliseNoFieldSplitCollision is the core unambiguity test: moving a
// character across a field boundary must change the signed bytes, so no two
// distinct field sets can ever share one signature.
func TestCanonicaliseNoFieldSplitCollision(t *testing.T) {
	tests := []struct {
		name string
		a, b cert.Certificate
	}{
		{
			name: "learner AB + course C vs learner A + course BC",
			a:    with(func(c *cert.Certificate) { c.LearnerName = "AB"; c.Course = "C" }),
			b:    with(func(c *cert.Certificate) { c.LearnerName = "A"; c.Course = "BC" }),
		},
		{
			name: "id and learner boundary",
			a:    with(func(c *cert.Certificate) { c.ID = "X1"; c.LearnerName = "Y" }),
			b:    with(func(c *cert.Certificate) { c.ID = "X"; c.LearnerName = "1Y" }),
		},
		{
			name: "grade and issued_on boundary",
			a:    with(func(c *cert.Certificate) { c.Grade = "A2"; c.IssuedOn = "026-03-14" }),
			b:    with(func(c *cert.Certificate) { c.Grade = "A"; c.IssuedOn = "2026-03-14" }),
		},
		{
			name: "issuer name and public key boundary",
			a:    with(func(c *cert.Certificate) { c.IssuerName = "Acme" + zeroKey[:1]; c.IssuerPubKey = zeroKey[1:] }),
			b:    with(func(c *cert.Certificate) { c.IssuerName = "Acme"; c.IssuerPubKey = zeroKey }),
		},
		{
			name: "empty vs shifted-left pair",
			a:    with(func(c *cert.Certificate) { c.LearnerName = ""; c.Course = "AB" }),
			b:    with(func(c *cert.Certificate) { c.LearnerName = "A"; c.Course = "B" }),
		},
		{
			name: "whole learner name moved into course",
			a:    with(func(c *cert.Certificate) { c.LearnerName = "Asha Kumari"; c.Course = "" }),
			b:    with(func(c *cert.Certificate) { c.LearnerName = ""; c.Course = "Asha Kumari" }),
		},
		{
			name: "hours digit moved into grade",
			a:    with(func(c *cert.Certificate) { c.Hours = 12; c.Grade = "0" }),
			b:    with(func(c *cert.Certificate) { c.Hours = 120; c.Grade = "" }),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.a == tc.b {
				t.Fatalf("test is malformed: the two certificates are identical")
			}
			ba, bb := cert.Canonicalise(tc.a), cert.Canonicalise(tc.b)
			if bytes.Equal(ba, bb) {
				t.Fatalf("distinct field sets collided onto the same bytes: %q", ba)
			}
		})
	}
}

func TestCanonicaliseRoundTripsAwkwardValues(t *testing.T) {
	tests := []struct {
		name string
		in   cert.Certificate
	}{
		{"plain", baseCert()},
		{"empty grade", with(func(c *cert.Certificate) { c.Grade = "" })},
		{"zero hours", with(func(c *cert.Certificate) { c.Hours = 0 })},
		{"max hours", with(func(c *cert.Certificate) { c.Hours = cert.MaxHours })},
		{"all text empty", cert.Certificate{}},
		{"value holds the separator", with(func(c *cert.Certificate) { c.Course = "Welding: Level 2" })},
		{"value holds an equals sign", with(func(c *cert.Certificate) { c.Grade = "score=88" })},
		{"value holds a newline", with(func(c *cert.Certificate) { c.IssuerName = "Acme\nSkills" })},
		{"value looks like a field line", with(func(c *cert.Certificate) { c.Course = "course=5:fake\n" })},
		{"non-latin script", with(func(c *cert.Certificate) {
			c.LearnerName = "आशा कुमारी"
			c.Course = "वेल्डिंग"
		})},
		{"tagalog name", with(func(c *cert.Certificate) { c.LearnerName = "Niño Dela Cruz" })},
		{"emoji-free symbols", with(func(c *cert.Certificate) { c.Grade = "80–90%" })},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := cert.Canonicalise(tc.in)
			got, err := cert.DecodeCanonical(payload)
			if err != nil {
				t.Fatalf("DecodeCanonical(%q) returned error: %v", payload, err)
			}
			if got != tc.in {
				t.Fatalf("round trip changed the certificate:\n got %+v\nwant %+v", got, tc.in)
			}
			if again := cert.Canonicalise(got); !bytes.Equal(again, payload) {
				t.Fatalf("re-encoding produced different bytes:\n got %q\nwant %q", again, payload)
			}
		})
	}
}

func TestDecodeCanonicalRejectsMalformedPayloads(t *testing.T) {
	good := string(cert.Canonicalise(baseCert()))

	tests := []struct {
		name    string
		payload string
	}{
		{"empty", ""},
		{"header only", cert.CanonicalHeader},
		{"no header", strings.TrimPrefix(good, cert.CanonicalHeader)},
		{"wrong version header", "omsme-cert/v2\n" + strings.TrimPrefix(good, cert.CanonicalHeader)},
		{"truncated mid-field", good[:len(good)-12]},
		{"trailing bytes", good + "extra"},
		{"trailing newline", good + "\n"},
		{"length too large", cert.CanonicalHeader + "id=99:ASI-2026-00001\n"},
		{"length too small", cert.CanonicalHeader + "id=3:ASI-2026-00001\n"},
		{"no length prefix", cert.CanonicalHeader + "id=ASI-2026-00001\n"},
		{"padded length", strings.Replace(good, "id=14:", "id=014:", 1)},
		{"signed length", strings.Replace(good, "id=14:", "id=+14:", 1)},
		{"unknown field name", strings.Replace(good, "grade=", "marks=", 1)},
		{"fields swapped", cert.CanonicalHeader + "learner_name=11:Asha Kumari\nid=14:ASI-2026-00001\n"},
		{"hours not a number", strings.Replace(good, "hours=3:120\n", "hours=4:12.0\n", 1)},
		{"hours negative", strings.Replace(good, "hours=3:120\n", "hours=2:-5\n", 1)},
		{"hours padded", strings.Replace(good, "hours=3:120\n", "hours=4:0120\n", 1)},
		{"field not newline terminated", strings.Replace(good, "grade=1:A\n", "grade=1:A;", 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cert.DecodeCanonical([]byte(tc.payload)); err == nil {
				t.Fatalf("DecodeCanonical(%q) accepted a malformed payload", tc.payload)
			}
		})
	}
}

func TestDecodeCanonicalAcceptsTheGoodPayload(t *testing.T) {
	// Guards the table above: the mutations must be the only reason those cases
	// fail, so the unmutated payload has to decode.
	if _, err := cert.DecodeCanonical(cert.Canonicalise(baseCert())); err != nil {
		t.Fatalf("the reference payload does not decode: %v", err)
	}
	if !strings.Contains(string(cert.Canonicalise(baseCert())), "hours=3:120\n") {
		t.Fatal("the reference payload no longer contains hours=3:120, so the mutation table is stale")
	}
	if !strings.Contains(string(cert.Canonicalise(baseCert())), "id=14:") {
		t.Fatal("the reference payload no longer contains id=14:, so the mutation table is stale")
	}
}
