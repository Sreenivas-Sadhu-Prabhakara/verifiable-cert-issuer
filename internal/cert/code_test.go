package cert_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sreenivas-sadhu-prabhakara/verifiable-cert-issuer/internal/cert"
)

func TestCertCodeRoundTrip(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	tests := []struct {
		name string
		cert cert.Certificate
	}{
		{"typical", with(func(c *cert.Certificate) { c.IssuerPubKey = k.PublicKeyString() })},
		{"no grade", with(func(c *cert.Certificate) { c.Grade = ""; c.IssuerPubKey = k.PublicKeyString() })},
		{"zero hours", with(func(c *cert.Certificate) { c.Hours = 0; c.IssuerPubKey = k.PublicKeyString() })},
		{"max hours", with(func(c *cert.Certificate) { c.Hours = cert.MaxHours; c.IssuerPubKey = k.PublicKeyString() })},
		{"devanagari name", with(func(c *cert.Certificate) {
			c.LearnerName = "आशा कुमारी"
			c.Course = "आर्क वेल्डिंग स्तर २"
			c.IssuerPubKey = k.PublicKeyString()
		})},
		{"filipino name with enye", with(func(c *cert.Certificate) {
			c.LearnerName = "Niño Dela Cruz"
			c.IssuerName = "Barangay Skills Centre"
			c.IssuerPubKey = k.PublicKeyString()
		})},
		{"longest allowed fields", with(func(c *cert.Certificate) {
			c.LearnerName = strings.Repeat("N", cert.MaxNameLen)
			c.Course = strings.Repeat("C", cert.MaxCourseLen)
			c.Grade = strings.Repeat("G", cert.MaxGradeLen)
			c.IssuerName = strings.Repeat("I", cert.MaxNameLen)
			c.IssuerPubKey = k.PublicKeyString()
		})},
		{"values containing separators", with(func(c *cert.Certificate) {
			c.Course = "Welding: Level 2 = advanced\nmodule"
			c.IssuerPubKey = k.PublicKeyString()
		})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := cert.Sign(tc.cert, k.Private)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			code, err := cert.CertCode(tc.cert, sig)
			if err != nil {
				t.Fatalf("CertCode: %v", err)
			}
			if !strings.HasPrefix(code, cert.CodePrefix) {
				t.Fatalf("code %q does not start with the human-readable prefix %q", code, cert.CodePrefix)
			}
			body := strings.TrimPrefix(code, cert.CodePrefix)
			if strings.ContainsAny(body, "+/= \n") {
				t.Fatalf("code body is not unpadded base64url: %q", body)
			}

			gotCert, gotSig, err := cert.ParseCertCode(code)
			if err != nil {
				t.Fatalf("ParseCertCode: %v", err)
			}
			if gotCert != tc.cert {
				t.Fatalf("certificate changed across the code:\n got %+v\nwant %+v", gotCert, tc.cert)
			}
			if string(gotSig) != string(sig) {
				t.Fatal("signature changed across the code")
			}
			if !cert.Verify(gotCert, gotSig, k.Public) {
				t.Fatal("the certificate recovered from the code does not verify")
			}
			// The code is reproducible from the recovered pieces.
			again, err := cert.CertCode(gotCert, gotSig)
			if err != nil {
				t.Fatalf("CertCode: %v", err)
			}
			if again != code {
				t.Fatalf("re-encoding the code changed it:\n got %s\nwant %s", again, code)
			}
		})
	}
}

func TestCertCodeRejectsBadSignatureSize(t *testing.T) {
	tests := []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, 63)},
		{"long", make([]byte, 65)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cert.CertCode(baseCert(), tc.sig); err == nil {
				t.Fatalf("CertCode accepted a %d-byte signature", len(tc.sig))
			}
		})
	}
}

func TestParseCertCodeToleratesTransitDamage(t *testing.T) {
	k, c, sig := signedFixture(t)
	code, err := cert.CertCode(c, sig)
	if err != nil {
		t.Fatalf("CertCode: %v", err)
	}
	mid := len(code) / 2

	tests := []struct {
		name string
		in   string
	}{
		{"exact", code},
		{"leading and trailing spaces", "   " + code + "   "},
		{"wrapped across lines", code[:mid] + "\n" + code[mid:]},
		{"wrapped with indentation", code[:mid] + "\n\t  " + code[mid:]},
		{"lowercase prefix", "cert1-" + strings.TrimPrefix(code, cert.CodePrefix)},
		{"mixed case prefix", "Cert1-" + strings.TrimPrefix(code, cert.CodePrefix)},
		{"trailing newline", code + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotCert, gotSig, err := cert.ParseCertCode(tc.in)
			if err != nil {
				t.Fatalf("ParseCertCode: %v", err)
			}
			if gotCert != c {
				t.Fatalf("certificate changed:\n got %+v\nwant %+v", gotCert, c)
			}
			if !cert.Verify(gotCert, gotSig, k.Public) {
				t.Fatal("the recovered certificate does not verify")
			}
		})
	}
}

func TestParseCertCodeRejectsCorruptCodes(t *testing.T) {
	_, c, sig := signedFixture(t)
	code, err := cert.CertCode(c, sig)
	if err != nil {
		t.Fatalf("CertCode: %v", err)
	}
	body := strings.TrimPrefix(code, cert.CodePrefix)
	payloadOnly := base64.RawURLEncoding.EncodeToString(cert.Canonicalise(c))

	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"only whitespace", "   \n\t "},
		{"no prefix", body},
		{"wrong prefix", "CERT2-" + body},
		{"prefix only", cert.CodePrefix},
		{"prefix with whitespace only", cert.CodePrefix + "   "},
		{"not base64", cert.CodePrefix + "!!! not base64 !!!"},
		{"standard base64 alphabet", cert.CodePrefix + strings.ReplaceAll(body, "_", "/") + "+"},
		{"signature only", cert.CodePrefix + base64.RawURLEncoding.EncodeToString(sig)},
		{"payload without signature", cert.CodePrefix + payloadOnly},
		{"too short to hold anything", cert.CodePrefix + "AAAA"},
		{"body truncated", cert.CodePrefix + body[:len(body)-20]},
		{"body with one character dropped", cert.CodePrefix + body[:10] + body[11:]},
		{"header bytes destroyed", cert.CodePrefix + base64.RawURLEncoding.EncodeToString(
			append([]byte("not-a-header\n"), cert.Canonicalise(c)[len(cert.CanonicalHeader):]...)),
		},
		{"non-canonical payload", cert.CodePrefix + base64.RawURLEncoding.EncodeToString(
			append(nonCanonicalPayload(c), sig...)),
		},
		{"human prose", "Certificate number ASI-2026-00001 issued to Asha Kumari"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotCert, gotSig, err := cert.ParseCertCode(tc.in)
			if err == nil {
				t.Fatalf("ParseCertCode accepted a corrupt code %q (cert %+v)", tc.in, gotCert)
			}
			if gotSig != nil {
				t.Fatalf("a rejected code still returned a signature of %d bytes", len(gotSig))
			}
			if gotCert != (cert.Certificate{}) {
				t.Fatalf("a rejected code still returned certificate details: %+v", gotCert)
			}
		})
	}
}

// nonCanonicalPayload re-encodes the hours field with a redundant leading zero.
// The bytes still describe the same certificate, so a lax decoder would accept
// them; this build refuses them, which is what stops one signature from
// covering two readings of the same payload.
func nonCanonicalPayload(c cert.Certificate) []byte {
	return []byte(strings.Replace(string(cert.Canonicalise(c)), "hours=3:120\n", "hours=4:0120\n", 1))
}

// TestEverySingleCharacterMutationFailsClosed walks the whole code and flips one
// character at a time. Each mutation must either fail to parse or fail to
// verify; none may come back as a pass.
func TestEverySingleCharacterMutationFailsClosed(t *testing.T) {
	k, c, sig := signedFixture(t)
	code, err := cert.CertCode(c, sig)
	if err != nil {
		t.Fatalf("CertCode: %v", err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	mutations := 0
	for i := len(cert.CodePrefix); i < len(code); i++ {
		original := code[i]
		replacement := alphabet[(strings.IndexByte(alphabet, original)+7)%len(alphabet)]
		if replacement == original {
			t.Fatalf("mutation at %d did not change the character", i)
		}
		mutated := code[:i] + string(replacement) + code[i+1:]
		mutations++

		gotCert, gotSig, err := cert.ParseCertCode(mutated)
		if err != nil {
			continue // rejected cleanly, which is the desired outcome
		}
		if cert.Verify(gotCert, gotSig, k.Public) {
			t.Fatalf("a one-character mutation at offset %d still verified; mutated code:\n%s", i, mutated)
		}
	}
	if mutations < 100 {
		t.Fatalf("only %d mutations were tried, expected the whole code to be walked", mutations)
	}
}

func TestSignatureEncodingRoundTrip(t *testing.T) {
	_, _, sig := signedFixture(t)
	encoded := cert.EncodeSignature(sig)
	got, err := cert.DecodeSignature(encoded)
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	if string(got) != string(sig) {
		t.Fatal("signature changed across encode/decode")
	}

	bad := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"not base64", "!!!!"},
		{"too short", base64.RawURLEncoding.EncodeToString(sig[:32])},
		{"too long", base64.RawURLEncoding.EncodeToString(append(append([]byte{}, sig...), 0))},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cert.DecodeSignature(tc.in); err == nil {
				t.Fatalf("DecodeSignature accepted %q", tc.in)
			}
		})
	}
}
