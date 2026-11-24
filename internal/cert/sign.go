package cert

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// SignatureSize is the length of a detached Ed25519 signature in bytes.
const SignatureSize = ed25519.SignatureSize

// Sign produces a detached signature over the canonical bytes of a
// certificate. The signature covers every field in CoveredFields and nothing
// else.
func Sign(c Certificate, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	return ed25519.Sign(priv, Canonicalise(c)), nil
}

// Verify reports whether sig is a valid signature over c by the holder of pub.
//
// It returns false for every kind of bad input — a short or empty public key, a
// truncated or garbage signature, a certificate whose fields were edited after
// signing — and never panics, so it is safe to call on whatever a stranger
// pasted into the verify box. (The standard library's ed25519.Verify panics on
// a wrong-sized public key, so the sizes are checked here first.)
func Verify(c Certificate, sig []byte, pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(pub, Canonicalise(c), sig)
}

// ErrBadSignatureSize means the signature blob cannot be used at all, as
// distinct from a well-formed signature that simply does not match.
var ErrBadSignatureSize = errors.New("a signature must be exactly 64 bytes")
