package cert_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/sreenivas-sadhu-prabhakara/verifiable-cert-issuer/internal/cert"
)

// signedFixture returns an institute keypair, a certificate bound to it and a
// valid signature over that certificate.
func signedFixture(t *testing.T) (cert.Keypair, cert.Certificate, []byte) {
	t.Helper()
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	c := with(func(c *cert.Certificate) { c.IssuerPubKey = k.PublicKeyString() })
	sig, err := cert.Sign(c, k.Private)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return k, c, sig
}

func TestSignAndVerifyValidCertificate(t *testing.T) {
	k, c, sig := signedFixture(t)
	if len(sig) != cert.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), cert.SignatureSize)
	}
	if !cert.Verify(c, sig, k.Public) {
		t.Fatal("a freshly signed certificate did not verify")
	}
	// Ed25519 is deterministic, so signing the same bytes twice must give the
	// same signature; that is what makes a reissued certificate code stable.
	again, err := cert.Sign(c, k.Private)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(again) != string(sig) {
		t.Fatal("signing the same certificate twice produced different signatures")
	}
}

// TestVerifyFailsOnAnySingleFieldTamper covers every signed field: changing one
// field and nothing else must break verification.
func TestVerifyFailsOnAnySingleFieldTamper(t *testing.T) {
	tests := []struct {
		field  string
		tamper func(*cert.Certificate)
	}{
		{"id", func(c *cert.Certificate) { c.ID = "ASI-2026-00002" }},
		{"learner name", func(c *cert.Certificate) { c.LearnerName = "Asha Kumar" }},
		{"learner name case only", func(c *cert.Certificate) { c.LearnerName = "asha kumari" }},
		{"learner name extra space", func(c *cert.Certificate) { c.LearnerName = "Asha  Kumari" }},
		{"course", func(c *cert.Certificate) { c.Course = "Arc Welding Level 3" }},
		{"hours", func(c *cert.Certificate) { c.Hours = 480 }},
		{"hours to zero", func(c *cert.Certificate) { c.Hours = 0 }},
		{"grade", func(c *cert.Certificate) { c.Grade = "A+" }},
		{"grade cleared", func(c *cert.Certificate) { c.Grade = "" }},
		{"issue date", func(c *cert.Certificate) { c.IssuedOn = "2026-03-15" }},
		{"issue year", func(c *cert.Certificate) { c.IssuedOn = "2025-03-14" }},
		{"issuer name", func(c *cert.Certificate) { c.IssuerName = "Acme Skills Academy" }},
		{"issuer public key", func(c *cert.Certificate) { c.IssuerPubKey = zeroKey }},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			k, c, sig := signedFixture(t)
			tampered := c
			tc.tamper(&tampered)
			if tampered == c {
				t.Fatal("test is malformed: the tamper changed nothing")
			}
			if cert.Verify(tampered, sig, k.Public) {
				t.Fatalf("verification passed after tampering with the %s", tc.field)
			}
			// The untouched certificate must still verify, so the failure above
			// is attributable to the tamper alone.
			if !cert.Verify(c, sig, k.Public) {
				t.Fatal("the original certificate stopped verifying")
			}
		})
	}
}

func TestVerifyFailsWithADifferentKey(t *testing.T) {
	k, c, sig := signedFixture(t)
	other, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if cert.Verify(c, sig, other.Public) {
		t.Fatal("a signature verified under an unrelated public key")
	}

	// A different institute signing the same learner details produces a
	// signature that must not verify under the first institute's key.
	forged, err := cert.Sign(c, other.Private)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if cert.Verify(c, forged, k.Public) {
		t.Fatal("a signature from another key verified under the institute's key")
	}
	if !cert.Verify(c, forged, other.Public) {
		t.Fatal("the other institute's own signature did not verify under its own key")
	}
}

// TestVerifyRejectsMalformedInputWithoutPanicking matters because the standard
// library's ed25519.Verify panics on a wrong-sized public key, and the verify
// screen is fed arbitrary pasted text.
func TestVerifyRejectsMalformedInputWithoutPanicking(t *testing.T) {
	k, c, sig := signedFixture(t)

	sigTests := []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one byte", []byte{0}},
		{"truncated by one", sig[:cert.SignatureSize-1]},
		{"half length", sig[:32]},
		{"one byte too long", append(append([]byte{}, sig...), 0)},
		{"all zero bytes", make([]byte, cert.SignatureSize)},
		{"garbage of the right length", []byte("garbage-garbage-garbage-garbage-garbage-garbage-garbage-garbage!")},
		{"first byte flipped", flipByte(sig, 0)},
		{"last byte flipped", flipByte(sig, cert.SignatureSize-1)},
		{"middle byte flipped", flipByte(sig, 31)},
	}
	for _, tc := range sigTests {
		t.Run("signature "+tc.name, func(t *testing.T) {
			if cert.Verify(c, tc.sig, k.Public) {
				t.Fatalf("Verify accepted a %s signature", tc.name)
			}
		})
	}

	keyTests := []struct {
		name string
		pub  ed25519.PublicKey
	}{
		{"nil", nil},
		{"empty", ed25519.PublicKey{}},
		{"one byte short", k.Public[:ed25519.PublicKeySize-1]},
		{"one byte", k.Public[:1]},
		{"all zero bytes", make(ed25519.PublicKey, ed25519.PublicKeySize)},
	}
	for _, tc := range keyTests {
		t.Run("public key "+tc.name, func(t *testing.T) {
			if cert.Verify(c, sig, tc.pub) {
				t.Fatalf("Verify accepted a %s public key", tc.name)
			}
		})
	}

	// Garbage of the right length that happens to be a valid-length signature
	// must also fail for a zero-value certificate.
	if cert.Verify(cert.Certificate{}, make([]byte, cert.SignatureSize), make(ed25519.PublicKey, ed25519.PublicKeySize)) {
		t.Fatal("Verify accepted an all-zero certificate, signature and key")
	}
}

func flipByte(b []byte, i int) []byte {
	out := append([]byte{}, b...)
	out[i] ^= 0xff
	return out
}

func TestSignRejectsAnUnusablePrivateKey(t *testing.T) {
	k, c, _ := signedFixture(t)

	tests := []struct {
		name string
		priv ed25519.PrivateKey
	}{
		{"nil", nil},
		{"empty", ed25519.PrivateKey{}},
		{"public key passed as private", ed25519.PrivateKey(k.Public)},
		{"truncated", k.Private[:63]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cert.Sign(c, tc.priv); err == nil {
				t.Fatalf("Sign accepted a %s private key", tc.name)
			}
		})
	}
}
