package cert

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// CodePrefix is the short human-readable tag in front of every certificate
// code, so a reader can tell at a glance what the long string is and which
// version of the format it uses.
const CodePrefix = "CERT1-"

// CertCode packs the signed payload and its signature into one copy-pasteable
// string: CodePrefix followed by unpadded base64url of the canonical bytes
// concatenated with the 64-byte signature.
//
// The payload is carried literally rather than re-encoded, so a verifier
// checks the signature against exactly the bytes that were signed. The code is
// self-contained: nothing has to be fetched to read it, which is what lets
// verification work offline.
func CertCode(c Certificate, sig []byte) (string, error) {
	if len(sig) != SignatureSize {
		return "", fmt.Errorf("%w, got %d", ErrBadSignatureSize, len(sig))
	}
	payload := Canonicalise(c)
	blob := make([]byte, 0, len(payload)+len(sig))
	blob = append(blob, payload...)
	blob = append(blob, sig...)
	return CodePrefix + base64.RawURLEncoding.EncodeToString(blob), nil
}

// ParseCertCode is the inverse of CertCode. It tolerates the cosmetic damage a
// code picks up in transit — surrounding or embedded whitespace from a wrapped
// email line, a lowercased prefix — and rejects everything else cleanly
// instead of guessing.
func ParseCertCode(code string) (Certificate, []byte, error) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, code)
	if compact == "" {
		return Certificate{}, nil, errors.New("no certificate code was given")
	}
	if len(compact) < len(CodePrefix) || !strings.EqualFold(compact[:len(CodePrefix)], CodePrefix) {
		return Certificate{}, nil, fmt.Errorf("a certificate code must start with %s", CodePrefix)
	}
	body := compact[len(CodePrefix):]
	if body == "" {
		return Certificate{}, nil, errors.New("the certificate code is empty after its prefix")
	}
	blob, err := decodeB64(body)
	if err != nil {
		return Certificate{}, nil, errors.New("the certificate code is damaged: it is not valid base64url text")
	}
	if len(blob) <= SignatureSize {
		return Certificate{}, nil, errors.New("the certificate code is too short to hold a certificate and a signature")
	}
	payload := blob[:len(blob)-SignatureSize]
	sig := blob[len(blob)-SignatureSize:]

	c, err := DecodeCanonical(payload)
	if err != nil {
		return Certificate{}, nil, fmt.Errorf("the certificate code is damaged: %w", err)
	}
	// Re-encode and compare. If the payload were not already in canonical form
	// it could be presented one way and verified another, so a code that does
	// not round-trip exactly is refused.
	if !bytes.Equal(Canonicalise(c), payload) {
		return Certificate{}, nil, errors.New("the certificate code is damaged: its payload is not in canonical form")
	}
	return c, sig, nil
}

// EncodeSignature renders a detached signature as unpadded base64url, for
// storing or publishing alongside a certificate.
func EncodeSignature(sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(sig)
}

// DecodeSignature reads a detached signature from unpadded base64url.
func DecodeSignature(s string) ([]byte, error) {
	raw, err := decodeB64(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("signature is not valid base64url text")
	}
	if len(raw) != SignatureSize {
		return nil, fmt.Errorf("%w, got %d", ErrBadSignatureSize, len(raw))
	}
	return raw, nil
}
