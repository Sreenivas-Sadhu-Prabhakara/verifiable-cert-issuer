# Tamper-proof skill certificate issuer for training institutes

A single Go binary that lets a small training institute sign the certificates it issues, so
anyone can check them offline. No database, no dependencies, no internet.

## What it does

A certificate produced in a word processor is a file anyone can edit, and the employer reading
it has no way to tell. This tool signs each certificate with the institute's own key and prints
a short **verification code** on it. The code carries the certificate's details and the
signature together, so checking it needs nothing but the code and the institute's published
public key.

- **Set up the institute** once: generate an Ed25519 signing key, saved locally with `0600`
  permissions, and publish the matching public key.
- **Issue a certificate** — learner, course, hours, grade, date — and get a printable
  certificate page with the verification code on it. Certificate numbers are allocated from
  your prefix and the year.
- **Verify** any code against a public key and see pass or fail, the decoded details, and
  exactly which fields the signature covers.
- **Batch issue** a whole class from a CSV exported out of a spreadsheet. Rows with problems are
  reported by line number; the rest still go through.
- **Export the public key** as a text file to email, publish or print, so employers can verify
  without involving you.

Change one character of a signed certificate — a letter of the name, a digit of the hours, the
date, the grade, the certificate number — and the code stops verifying.

## Who it's for

Small training institutes, skilling centres and trade schools in India and the Philippines that
print their own certificates: welding and fitting shops, tailoring and beauty courses, computer
and spoken-English centres, driving schools, barangay and panchayat skilling programmes. It is
equally for the employer, college clerk or agency on the other side, who can run the same binary
in verify mode and get an answer without contacting the institute.

## The rule it implements

**There is no statute behind this tool.** The rule it implements is a cryptographic standard:
**Ed25519**, the signature scheme defined in **RFC 8032**, through the Go standard library's
`crypto/ed25519`.

The signature covers eight fields, in this fixed order:

```
id
learner_name
course
hours
grade
issued_on
issuer_name
issuer_pubkey
```

They are encoded one per line as `name=length:value` after a version header. The length prefix
is what makes the encoding unambiguous: a learner "AB" on course "C" can never produce the same
bytes as a learner "A" on course "BC", so no two different certificates can share one signature.

Fixed parameters, each defined once in `internal/cert`:

| Parameter | Value |
| --- | --- |
| Signature scheme | Ed25519 (RFC 8032) — 32-byte public key, 64-byte private key, 64-byte signature |
| Encoding version header | `omsme-cert/v1` |
| Certificate code prefix | `CERT1-`, then unpadded base64url of the signed bytes plus the signature |
| Key file permissions | `0600` — owner read and write only |
| Date format | `YYYY-MM-DD`, zero padded, rejected unless it is a real calendar date |

These are properties of the signature format, not figures set by an authority, so nothing here
expires. Whether a certificate *counts* — recognition, accreditation, a place on a
qualifications framework — is decided by your awarding body or regulator. Confirm those
requirements with them; this tool neither grants nor affects them.

## Install and run

Requires Go 1.25 or later. Nothing else.

```sh
cd verifiable-cert-issuer
go build -o cert-issuer .
./cert-issuer
```

Then open <http://127.0.0.1:8080/>.

Flags:

```sh
./cert-issuer \
  -addr 127.0.0.1:9000 \
  -data ./certificates.json \
  -key ./institute-key.json
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8080` | address the local web UI listens on |
| `-data` | `./verifiable-cert-issuer-data.json` | file the issued certificates are stored in |
| `-key` | `./verifiable-cert-issuer-key.json` | file the private signing key is stored in |
| `-verify` | — | verify one certificate code and exit |
| `-pubkey` | — | the public key to verify against, or a file containing it |

### Verifying with no user interface

```sh
./cert-issuer -verify CERT1-… -pubkey Uyk5kiJSrdBSyeoiwJPk2s…
```

It prints the verdict and the decoded details, and exits `0` on a pass, `1` on a failure and `2`
if the arguments cannot be used — so it drops straight into a script. `-pubkey` accepts the key
itself or the path of the exported public-key file. Line breaks and spaces inside a code or a
key are ignored, so a code copied off a printed certificate works.

## Where the data is stored

Two files on your own machine:

- **`-data`** — a plain JSON file holding every certificate you have issued, with its signature
  and code. Written through a temporary file and renamed into place, so an interrupted write
  cannot truncate it.
- **`-key`** — the private signing key, in its own file, created with `0600` permissions. The
  tool warns you if those permissions are ever loosened.

Nothing is sent anywhere. There are no outbound network calls, no telemetry, and no external
fonts or scripts; the server binds to `127.0.0.1`, so it is not reachable from the rest of the
network.

## Scope and honesty

**What a pass proves:** the certificate was signed by whoever holds the private key matching the
public key you supplied, and not one character of the signed details has changed since.

**What it does not prove:** that the institute is accredited, registered or recognised by anyone;
that the course was any good; that the learner attended; that the grade was earned. A signature
cannot answer questions about an institute.

**The key decides, not the name.** Anyone can generate a key and sign a certificate naming any
institute at all, producing a code that is internally consistent. The verify screen therefore
refuses to return a pass based on the key carried inside a code, and requires a public key you
supply from somewhere else. Get it from the institute — their website, letterhead or a file they
sent you — not from the certificate you are checking.

**Not implemented, and not pretended:** this is **not** a W3C Verifiable Credential; the codes
are this tool's own format, and no W3C VC serialisation is produced or accepted. **QR codes are
not rendered** — the verification code is text you print, copy or type. There is no revocation
list and no expiry: once issued, a code verifies forever, and nothing here can call it back.

**If the private key is lost**, every certificate already issued stays verifiable — verification
needs only the public key, which you have published. What you lose is the ability to issue any
more under that key: generate a new one, publish it too, and from then on old certificates need
the old public key and new ones the new key.

**If the private key is leaked**, anyone holding it can sign certificates in your institute's
name that verify exactly like yours, and there is no way to tell them apart or to withdraw codes
already in circulation. The only remedy is to generate a new key, publish it, and state plainly
from which date the old key is retired. Guard the key file, and keep a backup somewhere a fire
or a dead disk cannot reach.

## Tests

```sh
go test ./... -count=1
```

The rules live in `internal/cert` as pure functions with table-driven tests: that the canonical
encoding is deterministic and unambiguous, that a save/load round trip preserves a keypair and
its file permissions, that every single-field tamper breaks verification, that a signature from
another key fails, that truncated and garbage signatures fail without panicking, and that every
one-character mutation of a certificate code is either rejected or fails to verify.

MIT licensed.
