package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// KeyFileFormat tags the private-key file so a future format can be told apart
// from this one.
const KeyFileFormat = "omsme-cert-key/v1"

// KeyFileMode is the permission the private-key file is created with: readable
// and writable by its owner only. Anyone who can read this file can issue
// certificates in the institute's name.
const KeyFileMode fs.FileMode = 0o600

// Keypair is the institute's signing identity.
type Keypair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// keyFile is the on-disk shape of the private-key file.
type keyFile struct {
	Format     string `json:"format"`
	CreatedOn  string `json:"createdOn"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	Note       string `json:"note"`
}

// GenerateKeypair creates a new Ed25519 signing key from the system random
// source.
func GenerateKeypair() (Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, fmt.Errorf("generate signing key: %w", err)
	}
	return Keypair{Private: priv, Public: pub}, nil
}

// PublicKeyString is the institute's public key as unpadded base64url: the
// single short string an employer needs in order to verify certificates
// without contacting the institute.
func (k Keypair) PublicKeyString() string {
	return EncodePublicKey(k.Public)
}

// EncodePublicKey renders a public key as unpadded base64url.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// ParsePublicKey decodes a published public key. It accepts the unpadded
// base64url form it writes, and tolerates the padded form in case a
// copy-and-paste picked up '=' characters.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := decodeB64(s)
	if err != nil {
		return nil, errors.New("not valid base64url text")
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("a public key must be %d bytes, this one decodes to %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// decodeB64 reads unpadded base64url, falling back to the padded form.
//
// Whitespace is dropped first: a key or a code is printed on paper, wrapped by
// an email client or shown in chunks to make it readable, and none of that
// changes what it means. Both decoders then run in strict mode, which rejects
// an encoding whose unused trailing bits are not zero — without that, two
// different strings could decode to the same key or signature bytes, and a
// certificate code could be altered in a way that still verified.
func decodeB64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.Strict().DecodeString(s)
}

// Validate checks that a keypair is well formed and that the public half
// really belongs to the private half.
func (k Keypair) Validate() error {
	if len(k.Private) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(k.Private))
	}
	if len(k.Public) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(k.Public))
	}
	derived, ok := k.Private.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, k.Public) {
		return errors.New("public key does not match the private key")
	}
	return nil
}

// SaveKeypair writes the private key to path with owner-only permissions. The
// file is written to a temporary file in the same directory and renamed into
// place, so an interrupted write cannot leave a half-written key behind.
func SaveKeypair(path string, k Keypair) error {
	if err := k.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(keyFile{
		Format:     KeyFileFormat,
		CreatedOn:  time.Now().Format(DateLayout),
		PublicKey:  k.PublicKeyString(),
		PrivateKey: base64.RawURLEncoding.EncodeToString(k.Private),
		Note:       "Private signing key. Keep this file private and backed up. Anyone who copies it can issue certificates in this institute's name.",
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode key file: %w", err)
	}
	body = append(body, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keytmp-*")
	if err != nil {
		return fmt.Errorf("create temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(KeyFileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("set key file permissions: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("write key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("flush key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close key file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("move key file into place: %w", err)
	}
	// Rename keeps the temporary file's mode, but set it again so the result is
	// the same even if the destination already existed with wider permissions.
	if err := os.Chmod(path, KeyFileMode); err != nil {
		return fmt.Errorf("set key file permissions: %w", err)
	}
	return nil
}

// LoadKeypair reads a key file written by SaveKeypair and checks that the two
// halves belong together.
func LoadKeypair(path string) (Keypair, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Keypair{}, err
	}
	var kf keyFile
	if err := json.Unmarshal(body, &kf); err != nil {
		return Keypair{}, fmt.Errorf("%s is not a readable key file: %w", path, err)
	}
	if kf.Format != KeyFileFormat {
		return Keypair{}, fmt.Errorf("%s has format %q, expected %q", path, kf.Format, KeyFileFormat)
	}
	priv, err := decodeB64(kf.PrivateKey)
	if err != nil {
		return Keypair{}, fmt.Errorf("%s: private key is not valid base64url text", path)
	}
	pub, err := decodeB64(kf.PublicKey)
	if err != nil {
		return Keypair{}, fmt.Errorf("%s: public key is not valid base64url text", path)
	}
	k := Keypair{Private: ed25519.PrivateKey(priv), Public: ed25519.PublicKey(pub)}
	if err := k.Validate(); err != nil {
		return Keypair{}, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// PermsTooOpen reports whether a key file's mode lets anyone other than the
// owner read or write it.
func PermsTooOpen(mode fs.FileMode) bool {
	return mode.Perm()&0o077 != 0
}
