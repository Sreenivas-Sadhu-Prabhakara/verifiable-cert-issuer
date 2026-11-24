package cert

// Result is the outcome of checking a pasted certificate code.
type Result struct {
	// Pass is true only when the code's signature is valid under a public key
	// the verifier supplied. It is never true on the strength of the key
	// carried inside the code alone.
	Pass bool `json:"pass"`
	// Reason is a plain-language explanation of Pass, suitable for showing to
	// whoever pasted the code.
	Reason string `json:"reason"`
	// Certificate holds the decoded details whenever the code could be read at
	// all, even when verification fails, so the reader can see what was
	// claimed.
	Certificate *Certificate `json:"certificate,omitempty"`
	// Covered lists the fields the signature protects.
	Covered []Field `json:"covered,omitempty"`
	// SelfConsistent means the signature matches the public key embedded in the
	// code. On its own this proves nothing about who issued the certificate:
	// anyone can make a key, sign their own text and embed their own key.
	SelfConsistent bool `json:"selfConsistent"`
	// KeyMatch means the public key embedded in the code is the one the
	// verifier supplied.
	KeyMatch bool `json:"keyMatch"`
	// CheckedAgainst is the public key the check was made against, if any.
	CheckedAgainst string `json:"checkedAgainst,omitempty"`
}

// VerifyCode checks a pasted code against a public key the verifier already
// trusts — the key the institute published.
//
// The trusted key is required. A certificate code carries the issuer's public
// key inside it, so checking the signature against that embedded key only
// shows the code is internally consistent; a forger can generate a key, sign
// any text with it and embed it. Authenticity is a comparison against a key
// obtained from the institute by some other route.
func VerifyCode(code, trustedPubKey string) Result {
	c, sig, err := ParseCertCode(code)
	if err != nil {
		return Result{Reason: err.Error()}
	}

	res := Result{Certificate: &c, Covered: CoveredFields()}

	embedded, embErr := ParsePublicKey(c.IssuerPubKey)
	if embErr != nil {
		res.Reason = "The code carries an unreadable institute public key: " + embErr.Error()
		return res
	}
	res.SelfConsistent = Verify(c, sig, embedded)

	if trustedPubKey == "" {
		res.Reason = "No public key was supplied, so this only shows the code is internally consistent. " +
			"Paste the institute's published public key to check that the institute actually issued it."
		return res
	}

	trusted, err := ParsePublicKey(trustedPubKey)
	if err != nil {
		res.Reason = "The public key you supplied could not be read: " + err.Error()
		return res
	}
	res.CheckedAgainst = EncodePublicKey(trusted)
	res.KeyMatch = string(trusted) == string(embedded)

	if !res.KeyMatch {
		res.Reason = "This certificate was signed by a different key from the one you supplied. " +
			"It was not issued by the holder of that public key."
		return res
	}
	if !Verify(c, sig, trusted) {
		res.Reason = "The signature does not match these details. The certificate has been altered since it was issued, or the code is corrupt."
		return res
	}

	res.Pass = true
	res.Reason = "Signed by the holder of this public key and unchanged since it was issued."
	return res
}

// SignedCertificate is a certificate with its detached signature and the code
// that carries both. It is what the issuer stores and what the UI shows.
type SignedCertificate struct {
	Certificate
	Signature string `json:"signature"`
	Code      string `json:"code"`
}

// Issue validates, signs and packs a certificate in one step. The returned
// problems slice is non-empty exactly when nothing was signed.
func Issue(c Certificate, k Keypair) (SignedCertificate, []string) {
	c = Clean(c)
	c.IssuerPubKey = k.PublicKeyString()

	if err := k.Validate(); err != nil {
		return SignedCertificate{}, []string{"Signing key: " + err.Error()}
	}
	if problems := Validate(c); len(problems) > 0 {
		return SignedCertificate{}, problems
	}
	sig, err := Sign(c, k.Private)
	if err != nil {
		return SignedCertificate{}, []string{"Signing key: " + err.Error()}
	}
	code, err := CertCode(c, sig)
	if err != nil {
		return SignedCertificate{}, []string{err.Error()}
	}
	return SignedCertificate{Certificate: c, Signature: EncodeSignature(sig), Code: code}, nil
}
