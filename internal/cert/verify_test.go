package cert_test

import (
	"strings"
	"testing"

	"github.com/sreenivas-sadhu-prabhakara/verifiable-cert-issuer/internal/cert"
)

func TestIssueThenVerifyCodePasses(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	signed, problems := cert.Issue(with(func(c *cert.Certificate) { c.IssuerPubKey = "" }), k)
	if len(problems) > 0 {
		t.Fatalf("Issue reported problems for a good certificate: %v", problems)
	}
	if signed.IssuerPubKey != k.PublicKeyString() {
		t.Errorf("Issue did not stamp the institute public key: got %q", signed.IssuerPubKey)
	}

	res := cert.VerifyCode(signed.Code, k.PublicKeyString())
	if !res.Pass {
		t.Fatalf("a freshly issued certificate did not pass: %s", res.Reason)
	}
	if !res.KeyMatch || !res.SelfConsistent {
		t.Errorf("expected KeyMatch and SelfConsistent on a pass, got %+v", res)
	}
	if res.Certificate == nil || res.Certificate.LearnerName != signed.LearnerName {
		t.Errorf("verification did not return the decoded learner name: %+v", res.Certificate)
	}
	if len(res.Covered) != 8 {
		t.Errorf("verification reported %d covered fields, want 8", len(res.Covered))
	}
	if res.CheckedAgainst != k.PublicKeyString() {
		t.Errorf("CheckedAgainst = %q, want the supplied key", res.CheckedAgainst)
	}
}

func TestVerifyCodeFailureModes(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	forger, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	signed, problems := cert.Issue(baseCert(), k)
	if len(problems) > 0 {
		t.Fatalf("Issue: %v", problems)
	}

	// A certificate the forger signed with their own key, carrying their own
	// public key: internally consistent, but not issued by the institute.
	forged, problems := cert.Issue(with(func(c *cert.Certificate) { c.LearnerName = "Someone Else" }), forger)
	if len(problems) > 0 {
		t.Fatalf("Issue: %v", problems)
	}

	// A code whose learner name was edited after signing.
	tampered := signed.Certificate
	tampered.LearnerName = "Asha Kumar"
	tamperedSig, err := cert.DecodeSignature(signed.Signature)
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	tamperedCode, err := cert.CertCode(tampered, tamperedSig)
	if err != nil {
		t.Fatalf("CertCode: %v", err)
	}

	tests := []struct {
		name            string
		code            string
		key             string
		wantPass        bool
		wantSelf        bool
		wantKeyMatch    bool
		wantCertDecoded bool
		reasonContains  string
	}{
		{
			name: "valid code and matching key", code: signed.Code, key: k.PublicKeyString(),
			wantPass: true, wantSelf: true, wantKeyMatch: true, wantCertDecoded: true,
			reasonContains: "unchanged",
		},
		{
			name: "no key supplied", code: signed.Code, key: "",
			wantSelf: true, wantCertDecoded: true,
			reasonContains: "Paste the institute's published public key",
		},
		{
			name: "key from another institute", code: signed.Code, key: forger.PublicKeyString(),
			wantSelf: true, wantCertDecoded: true,
			reasonContains: "different key",
		},
		{
			name: "forged certificate checked against the real institute key", code: forged.Code, key: k.PublicKeyString(),
			wantSelf: true, wantCertDecoded: true,
			reasonContains: "different key",
		},
		{
			name: "tampered learner name", code: tamperedCode, key: k.PublicKeyString(),
			wantKeyMatch: true, wantCertDecoded: true,
			reasonContains: "altered",
		},
		{
			name: "unreadable code", code: "CERT1-!!!!", key: k.PublicKeyString(),
			reasonContains: "damaged",
		},
		{
			name: "empty code", code: "", key: k.PublicKeyString(),
			reasonContains: "no certificate code",
		},
		{
			name: "unreadable supplied key", code: signed.Code, key: "not-a-key",
			wantSelf: true, wantCertDecoded: true,
			reasonContains: "could not be read",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := cert.VerifyCode(tc.code, tc.key)
			if res.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (reason: %s)", res.Pass, tc.wantPass, res.Reason)
			}
			if res.SelfConsistent != tc.wantSelf {
				t.Errorf("SelfConsistent = %v, want %v", res.SelfConsistent, tc.wantSelf)
			}
			if res.KeyMatch != tc.wantKeyMatch {
				t.Errorf("KeyMatch = %v, want %v", res.KeyMatch, tc.wantKeyMatch)
			}
			if (res.Certificate != nil) != tc.wantCertDecoded {
				t.Errorf("decoded certificate present = %v, want %v", res.Certificate != nil, tc.wantCertDecoded)
			}
			if !strings.Contains(res.Reason, tc.reasonContains) {
				t.Errorf("Reason = %q, want it to mention %q", res.Reason, tc.reasonContains)
			}
		})
	}
}

// TestVerifyCodeNeverPassesOnTheEmbeddedKeyAlone is the honesty guard: a
// forger can always make a self-consistent code, so a self-consistent code
// must never be reported as a pass.
func TestVerifyCodeNeverPassesOnTheEmbeddedKeyAlone(t *testing.T) {
	forger, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	forged, problems := cert.Issue(with(func(c *cert.Certificate) {
		c.IssuerName = "Acme Skills Institute"
		c.LearnerName = "Nobody At All"
	}), forger)
	if len(problems) > 0 {
		t.Fatalf("Issue: %v", problems)
	}
	res := cert.VerifyCode(forged.Code, "")
	if res.Pass {
		t.Fatal("a self-signed certificate passed with no trusted key supplied")
	}
	if !res.SelfConsistent {
		t.Fatal("expected the forged code to be internally consistent")
	}
	// It does pass against the forger's own key, which is the whole point: the
	// key decides, not the name printed on the certificate.
	if ok := cert.VerifyCode(forged.Code, forger.PublicKeyString()); !ok.Pass {
		t.Fatalf("the forged code did not pass against its own key: %s", ok.Reason)
	}
}

func TestIssueRejectsInvalidCertificates(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	tests := []struct {
		name string
		in   cert.Certificate
		key  cert.Keypair
	}{
		{"missing id", with(func(c *cert.Certificate) { c.ID = "" }), k},
		{"missing learner", with(func(c *cert.Certificate) { c.LearnerName = "  " }), k},
		{"missing course", with(func(c *cert.Certificate) { c.Course = "" }), k},
		{"negative hours", with(func(c *cert.Certificate) { c.Hours = -1 }), k},
		{"impossible date", with(func(c *cert.Certificate) { c.IssuedOn = "2026-02-30" }), k},
		{"missing institute", with(func(c *cert.Certificate) { c.IssuerName = "" }), k},
		{"unusable signing key", baseCert(), cert.Keypair{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, problems := cert.Issue(tc.in, tc.key)
			if len(problems) == 0 {
				t.Fatalf("Issue accepted an invalid certificate: %+v", tc.in)
			}
			if signed.Code != "" {
				t.Fatalf("Issue returned a code for an invalid certificate: %s", signed.Code)
			}
		})
	}
}

func TestIssueCleansInputBeforeSigning(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	messy := with(func(c *cert.Certificate) {
		c.LearnerName = "  Asha   Kumari \t"
		c.Course = " Arc  Welding Level 2 "
	})
	signed, problems := cert.Issue(messy, k)
	if len(problems) > 0 {
		t.Fatalf("Issue: %v", problems)
	}
	if signed.LearnerName != "Asha Kumari" {
		t.Errorf("learner name was not cleaned: %q", signed.LearnerName)
	}
	if signed.Course != "Arc Welding Level 2" {
		t.Errorf("course was not cleaned: %q", signed.Course)
	}
	// The code must carry the cleaned values, so what is verified is what is
	// printed on the certificate.
	res := cert.VerifyCode(signed.Code, k.PublicKeyString())
	if !res.Pass {
		t.Fatalf("cleaned certificate did not verify: %s", res.Reason)
	}
	if res.Certificate.LearnerName != "Asha Kumari" {
		t.Errorf("the code carries %q, want the cleaned name", res.Certificate.LearnerName)
	}
}
