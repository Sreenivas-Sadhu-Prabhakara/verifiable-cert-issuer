package cert_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sreenivas-sadhu-prabhakara/verifiable-cert-issuer/internal/cert"
)

func TestKeypairRoundTripsThroughSaveAndLoad(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	path := filepath.Join(t.TempDir(), "institute-key.json")
	if err := cert.SaveKeypair(path, k); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key file mode = %04o, want 0600 (owner read/write only)", got)
	}
	if cert.PermsTooOpen(info.Mode()) {
		t.Errorf("PermsTooOpen reported the freshly saved key file as world-readable")
	}

	loaded, err := cert.LoadKeypair(path)
	if err != nil {
		t.Fatalf("LoadKeypair: %v", err)
	}
	if !bytes.Equal(loaded.Private, k.Private) {
		t.Error("private key changed across save/load")
	}
	if !bytes.Equal(loaded.Public, k.Public) {
		t.Error("public key changed across save/load")
	}
	if loaded.PublicKeyString() != k.PublicKeyString() {
		t.Errorf("published public key changed: got %q want %q", loaded.PublicKeyString(), k.PublicKeyString())
	}

	// The loaded key must be usable: sign with the reloaded private half and
	// verify with the original public half, and the other way round.
	c := with(func(c *cert.Certificate) { c.IssuerPubKey = k.PublicKeyString() })
	sigFromLoaded, err := cert.Sign(c, loaded.Private)
	if err != nil {
		t.Fatalf("Sign with reloaded key: %v", err)
	}
	if !cert.Verify(c, sigFromLoaded, k.Public) {
		t.Error("signature made with the reloaded private key does not verify under the original public key")
	}
	sigFromOriginal, err := cert.Sign(c, k.Private)
	if err != nil {
		t.Fatalf("Sign with original key: %v", err)
	}
	if !cert.Verify(c, sigFromOriginal, loaded.Public) {
		t.Error("signature made with the original private key does not verify under the reloaded public key")
	}
}

func TestSaveKeypairTightensExistingPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "institute-key.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := cert.SaveKeypair(path, k); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("overwriting a 0644 key file left mode %04o, want 0600", got)
	}
	// No temporary files may be left behind in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only the key file in the directory, found %v", names)
	}
}

func TestSaveKeypairRejectsBrokenKeypair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-key.json")
	if err := cert.SaveKeypair(path, cert.Keypair{}); err == nil {
		t.Fatal("SaveKeypair accepted an empty keypair")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a rejected save still created %s", path)
	}
}

func TestLoadKeypairRejectsBadFiles(t *testing.T) {
	good, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	other, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString

	tests := []struct {
		name string
		body string
	}{
		{"empty file", ""},
		{"not json", "this is not a key"},
		{"empty object", "{}"},
		{"wrong format tag", `{"format":"omsme-cert-key/v9","publicKey":"` + b64(good.Public) + `","privateKey":"` + b64(good.Private) + `"}`},
		{"private key not base64", `{"format":"` + cert.KeyFileFormat + `","publicKey":"` + b64(good.Public) + `","privateKey":"!!!!"}`},
		{"private key wrong length", `{"format":"` + cert.KeyFileFormat + `","publicKey":"` + b64(good.Public) + `","privateKey":"` + b64(good.Private[:32]) + `"}`},
		{"public key wrong length", `{"format":"` + cert.KeyFileFormat + `","publicKey":"` + b64(good.Public[:16]) + `","privateKey":"` + b64(good.Private) + `"}`},
		{"halves from different keypairs", `{"format":"` + cert.KeyFileFormat + `","publicKey":"` + b64(other.Public) + `","privateKey":"` + b64(good.Private) + `"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "k.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := cert.LoadKeypair(path); err == nil {
				t.Fatalf("LoadKeypair accepted a bad key file: %s", tc.body)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := cert.LoadKeypair(filepath.Join(t.TempDir(), "absent.json")); err == nil {
			t.Fatal("LoadKeypair accepted a path that does not exist")
		}
	})
}

func TestParsePublicKey(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	unpadded := k.PublicKeyString()
	padded := base64.URLEncoding.EncodeToString(k.Public)
	tooLong := make([]byte, 0, ed25519.PublicKeySize+1)
	tooLong = append(tooLong, k.Public...)
	tooLong = append(tooLong, 0)

	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"unpadded base64url", unpadded, true},
		{"padded base64url", padded, true},
		{"empty", "", false},
		{"not base64", "not a key!!", false},
		{"too short", base64.RawURLEncoding.EncodeToString(k.Public[:31]), false},
		{"too long", base64.RawURLEncoding.EncodeToString(tooLong), false},
		{"standard base64 alphabet", strings.Repeat("+", 43), false},
		{"43 zero bytes worth of A", zeroKey, true},
		// A key is printed on certificates and shown in readable chunks, so the
		// whitespace that survives a copy, a line wrap or a retype must not
		// change what it means.
		{"wrapped across lines", unpadded[:22] + "\n" + unpadded[22:], true},
		{"shown in chunks", unpadded[:11] + " " + unpadded[11:22] + " " + unpadded[22:33] + " " + unpadded[33:], true},
		{"surrounded by whitespace", "  \t" + unpadded + "\n", true},
		{"whitespace only", "   \n\t", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := cert.ParsePublicKey(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("ParsePublicKey(%q) = error %v, want success", tc.in, err)
				}
				if len(pub) != ed25519.PublicKeySize {
					t.Fatalf("parsed key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParsePublicKey(%q) succeeded, want an error", tc.in)
			}
		})
	}

	if got, err := cert.ParsePublicKey(padded); err != nil || !bytes.Equal(got, k.Public) {
		t.Fatalf("padded form did not decode to the same key (err=%v)", err)
	}
}

func TestKeypairValidate(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	other, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	tests := []struct {
		name string
		in   cert.Keypair
		ok   bool
	}{
		{"generated", k, true},
		{"zero value", cert.Keypair{}, false},
		{"short private", cert.Keypair{Private: k.Private[:32], Public: k.Public}, false},
		{"short public", cert.Keypair{Private: k.Private, Public: k.Public[:16]}, false},
		{"mismatched halves", cert.Keypair{Private: k.Private, Public: other.Public}, false},
		{"missing public", cert.Keypair{Private: k.Private}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
		})
	}
}

func TestPermsTooOpen(t *testing.T) {
	tests := []struct {
		mode fs.FileMode
		want bool
	}{
		{0o600, false},
		{0o400, false},
		{0o700, false},
		{0o000, false},
		{0o640, true},
		{0o604, true},
		{0o644, true},
		{0o660, true},
		{0o666, true},
		{0o777, true},
		{fs.ModeDir | 0o600, false},
		{fs.ModeDir | 0o755, true},
	}
	for _, tc := range tests {
		if got := cert.PermsTooOpen(tc.mode); got != tc.want {
			t.Errorf("PermsTooOpen(%v) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestGenerateKeypairProducesDistinctKeys(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		k, err := cert.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair: %v", err)
		}
		if err := k.Validate(); err != nil {
			t.Fatalf("generated keypair is invalid: %v", err)
		}
		s := k.PublicKeyString()
		if seen[s] {
			t.Fatalf("GenerateKeypair returned the same key twice: %s", s)
		}
		seen[s] = true
		if len(s) != 43 {
			t.Fatalf("published public key is %d characters, want 43", len(s))
		}
	}
}
