// Command verifiable-cert-issuer issues signed skill certificates for a small
// training institute and verifies them.
//
// It runs on the institute's own machine: a local web UI on 127.0.0.1, a
// certificate list in a local JSON file, and a signing key in a second local
// file with owner-only permissions. It makes no outbound network calls.
package main

import (
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sreenivas-sadhu-prabhakara/verifiable-cert-issuer/internal/cert"
)

//go:embed web
var webFiles embed.FS

const (
	defaultAddr    = "127.0.0.1:8080"
	defaultDataFil = "./verifiable-cert-issuer-data.json"
	defaultKeyFile = "./verifiable-cert-issuer-key.json"

	dataFormat   = "omsme-cert-store/v1"
	maxBodyBytes = 4 << 20 // 4 MiB: enough for a large batch file, small enough to bound memory
)

func main() {
	addr := flag.String("addr", defaultAddr, "address to serve the local web UI on")
	dataPath := flag.String("data", defaultDataFil, "file the issued certificates are stored in")
	keyPath := flag.String("key", defaultKeyFile, "file the institute's private signing key is stored in")
	verifyCode := flag.String("verify", "", "verify a certificate code and exit (use with -pubkey)")
	pubKey := flag.String("pubkey", "", "the institute's published public key, or a file containing it")
	flag.Usage = usage
	flag.Parse()

	if *verifyCode != "" {
		os.Exit(runVerify(os.Stdout, *verifyCode, *pubKey))
	}
	if *pubKey != "" {
		fmt.Fprintln(os.Stderr, "-pubkey is only used together with -verify")
		os.Exit(2)
	}

	st, err := openStore(*dataPath, *keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := serve(*addr, st); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, `verifiable-cert-issuer — issue and verify signed skill certificates.

Run the local web UI (the usual way):
    verifiable-cert-issuer
    verifiable-cert-issuer -addr 127.0.0.1:9000 -data ./certs.json

Verify one certificate code with no UI at all (exits 1 if it does not verify):
    verifiable-cert-issuer -verify CERT1-... -pubkey <public key or file>

Flags:
`)
	flag.PrintDefaults()
}

// ---------------------------------------------------------------- CLI verify

// runVerify checks one pasted code and returns the process exit code: 0 when
// the certificate verifies, 1 when it does not, 2 when the arguments cannot be
// used.
func runVerify(w io.Writer, code, pubKeyArg string) int {
	key, err := resolvePublicKey(pubKeyArg)
	if err != nil {
		fmt.Fprintln(w, "ERROR  "+err.Error())
		return 2
	}
	if key == "" {
		fmt.Fprintln(w, "ERROR  -pubkey is required: without the institute's published public key, a code can only be read, not trusted.")
		return 2
	}

	res := cert.VerifyCode(code, key)
	verdict := "FAIL"
	if res.Pass {
		verdict = "PASS"
	}
	if res.Certificate != nil {
		fmt.Fprintf(w, "%s  %s\n", verdict, res.Certificate.ID)
		rows := [][2]string{
			{"Learner", res.Certificate.LearnerName},
			{"Course", res.Certificate.Course},
			{"Hours", fmt.Sprintf("%d", res.Certificate.Hours)},
			{"Grade", res.Certificate.Grade},
			{"Issued on", res.Certificate.IssuedOn},
			{"Institute", res.Certificate.IssuerName},
			{"Signed by key", res.Certificate.IssuerPubKey},
		}
		for _, r := range rows {
			if r[1] == "" {
				r[1] = "—"
			}
			fmt.Fprintf(w, "  %-14s %s\n", r[0], r[1])
		}
		var keys []string
		for _, f := range res.Covered {
			keys = append(keys, f.Key)
		}
		fmt.Fprintf(w, "  %-14s %s\n", "Covers", strings.Join(keys, ", "))
	} else {
		fmt.Fprintf(w, "%s\n", verdict)
	}
	fmt.Fprintf(w, "  %-14s %s\n", "Result", res.Reason)

	if !res.Pass {
		return 1
	}
	return 0
}

// resolvePublicKey accepts the key itself or the path of a file holding it:
// the exported public-key text file, or the institute's own key file.
func resolvePublicKey(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", nil
	}
	info, err := os.Stat(arg)
	if err != nil || info.IsDir() {
		return arg, nil // not a file: treat it as the key itself
	}
	body, err := os.ReadFile(arg)
	if err != nil {
		return "", fmt.Errorf("could not read %s: %w", arg, err)
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "{") {
		k, err := cert.LoadKeypair(arg)
		if err != nil {
			return "", err
		}
		return k.PublicKeyString(), nil
	}
	// A plain text export: take the last whitespace-separated token that parses
	// as a public key, so the surrounding explanation does not get in the way.
	fields := strings.Fields(text)
	for i := len(fields) - 1; i >= 0; i-- {
		if _, err := cert.ParsePublicKey(fields[i]); err == nil {
			return fields[i], nil
		}
	}
	return "", fmt.Errorf("%s does not contain a public key", arg)
}

// -------------------------------------------------------------------- store

// institute is the local setup: who issues, under which key.
type institute struct {
	Name      string `json:"name"`
	IDPrefix  string `json:"idPrefix"`
	PublicKey string `json:"publicKey"`
	KeyFile   string `json:"keyFile"`
	SetUpOn   string `json:"setUpOn"`
}

// storeFile is the shape of the -data file.
type storeFile struct {
	Format       string                   `json:"format"`
	Institute    institute                `json:"institute"`
	NextSeq      int                      `json:"nextSeq"`
	Certificates []cert.SignedCertificate `json:"certificates"`
}

type store struct {
	mu         sync.Mutex
	path       string
	defaultKey string
	data       storeFile
}

func openStore(path, keyFile string) (*store, error) {
	st := &store{path: path, defaultKey: keyFile, data: storeFile{Format: dataFormat, NextSeq: 1}}
	body, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		st.data.Institute.KeyFile = keyFile
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &st.data); err != nil {
		return nil, fmt.Errorf("%s is not a readable certificate store: %w", path, err)
	}
	if st.data.Format != "" && st.data.Format != dataFormat {
		return nil, fmt.Errorf("%s has format %q, expected %q", path, st.data.Format, dataFormat)
	}
	st.data.Format = dataFormat
	if st.data.NextSeq < 1 {
		st.data.NextSeq = 1
	}
	if st.data.Institute.KeyFile == "" {
		st.data.Institute.KeyFile = keyFile
	}
	return st, nil
}

// save writes the store through a temporary file in the same directory, so an
// interrupted write cannot truncate the certificate list.
func (s *store) save() error {
	body, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".datatmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// nextFreeID returns the next unused certificate number and the sequence it
// came from, skipping numbers already present in case the file was edited by
// hand.
func (s *store) nextFreeID(year int) (string, int) {
	taken := make(map[string]bool, len(s.data.Certificates))
	for _, c := range s.data.Certificates {
		taken[c.ID] = true
	}
	seq := s.data.NextSeq
	prefix := s.data.Institute.IDPrefix
	for {
		id := cert.FormatID(prefix, year, seq)
		if !taken[id] {
			return id, seq
		}
		seq++
	}
}

// ------------------------------------------------------------------- server

func serve(addr string, st *store) error {
	sub, err := fs.Sub(webFiles, "web")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/state", st.handleState)
	mux.HandleFunc("/api/institute", st.handleInstitute)
	mux.HandleFunc("/api/issue", st.handleIssue)
	mux.HandleFunc("/api/issue-batch", st.handleIssueBatch)
	mux.HandleFunc("/api/verify", st.handleVerify)
	mux.HandleFunc("/api/pubkey.txt", st.handlePubKeyExport)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("Certificate issuer running at http://%s/\n", ln.Addr().String())
	fmt.Printf("Certificates:  %s\n", st.path)
	fmt.Printf("Signing key:   %s\n", st.data.Institute.KeyFile)
	fmt.Println("Nothing is sent anywhere. Press Ctrl+C to stop.")

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.Serve(ln)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, problems ...string) {
	writeJSON(w, status, map[string]any{"problems": problems})
}

// readJSON enforces POST with a JSON content type. Requiring the content type
// is what keeps another web page open in the same browser from posting to this
// local server: a cross-origin request carrying it needs a preflight, which
// this server never grants.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "This endpoint only accepts POST.")
		return false
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Send application/json.")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "The request could not be read: "+err.Error())
		return false
	}
	return true
}

// keyStatus describes the signing key file without ever revealing its contents.
type keyStatus struct {
	Path         string `json:"path"`
	Exists       bool   `json:"exists"`
	Mode         string `json:"mode,omitempty"`
	PermsTooWide bool   `json:"permsTooWide"`
	Matches      bool   `json:"matches"`
	Problem      string `json:"problem,omitempty"`
}

func (s *store) keyStatus() keyStatus {
	path := s.data.Institute.KeyFile
	if path == "" {
		path = s.defaultKey
	}
	ks := keyStatus{Path: path}
	info, err := os.Stat(path)
	if err != nil {
		return ks
	}
	ks.Exists = true
	ks.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	ks.PermsTooWide = cert.PermsTooOpen(info.Mode())
	k, err := cert.LoadKeypair(path)
	if err != nil {
		ks.Problem = err.Error()
		return ks
	}
	ks.Matches = s.data.Institute.PublicKey == "" || k.PublicKeyString() == s.data.Institute.PublicKey
	if !ks.Matches {
		ks.Problem = "The key file holds a different key from the one this certificate list was issued under."
	}
	return ks
}

func (s *store) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "This endpoint only accepts GET.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Newest first: the list is read far more often than it is appended to.
	list := make([]cert.SignedCertificate, 0, len(s.data.Certificates))
	for i := len(s.data.Certificates) - 1; i >= 0; i-- {
		list = append(list, s.data.Certificates[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"institute":    s.data.Institute,
		"certificates": list,
		"keyStatus":    s.keyStatus(),
		"covered":      cert.CoveredFields(),
		"today":        time.Now().Format(cert.DateLayout),
		"dataFile":     s.path,
		"batchHeader":  strings.Join(cert.BatchHeader, ","),
	})
}

func (s *store) handleInstitute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		IDPrefix   string `json:"idPrefix"`
		KeyFile    string `json:"keyFile"`
		Mode       string `json:"mode"`
		ReplaceKey bool   `json:"replaceKey"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	name := strings.Join(strings.Fields(req.Name), " ")
	if name == "" {
		writeError(w, http.StatusBadRequest, "The institute name is required.")
		return
	}
	if len(name) > cert.MaxNameLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("The institute name is longer than %d characters.", cert.MaxNameLen))
		return
	}
	keyFile := strings.TrimSpace(req.KeyFile)
	if keyFile == "" {
		keyFile = s.data.Institute.KeyFile
	}
	if keyFile == "" {
		keyFile = s.defaultKey
	}

	prefix := strings.ToUpper(strings.Join(strings.Fields(req.IDPrefix), ""))
	if prefix == "" {
		prefix = cert.IssuerCode(name)
	}
	if len(prefix) > 8 {
		writeError(w, http.StatusBadRequest, "The certificate-number prefix must be 8 characters or fewer.")
		return
	}

	var k cert.Keypair
	switch req.Mode {
	case "generate":
		if _, err := os.Stat(keyFile); err == nil && !req.ReplaceKey {
			writeError(w, http.StatusConflict,
				"A key file already exists at "+keyFile+".",
				"Load it instead, or confirm replacement — a new key cannot verify certificates issued under the old one.")
			return
		}
		gen, err := cert.GenerateKeypair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := cert.SaveKeypair(keyFile, gen); err != nil {
			writeError(w, http.StatusInternalServerError, "The key could not be saved: "+err.Error())
			return
		}
		k = gen
	case "load":
		loaded, err := cert.LoadKeypair(keyFile)
		if err != nil {
			writeError(w, http.StatusBadRequest, "The key could not be loaded: "+err.Error())
			return
		}
		k = loaded
	default:
		writeError(w, http.StatusBadRequest, `Set mode to "generate" or "load".`)
		return
	}

	// Changing the key is allowed, but the consequence is spelled out rather
	// than hidden: certificates already issued stay verifiable only under the
	// public key they were signed with.
	var warnings []string
	if old := s.data.Institute.PublicKey; old != "" && old != k.PublicKeyString() && len(s.data.Certificates) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"The institute is now signing with a different key. The %d certificate(s) already issued can only be verified with the previous public key: %s",
			len(s.data.Certificates), old))
	}
	s.data.Institute.PublicKey = k.PublicKeyString()
	s.data.Institute.Name = name
	s.data.Institute.IDPrefix = prefix
	s.data.Institute.KeyFile = keyFile
	if s.data.Institute.SetUpOn == "" {
		s.data.Institute.SetUpOn = time.Now().Format(cert.DateLayout)
	}
	if err := s.save(); err != nil {
		writeError(w, http.StatusInternalServerError, "The setup could not be saved: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"institute": s.data.Institute,
		"keyStatus": s.keyStatus(),
		"warnings":  warnings,
	})
}

func (s *store) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LearnerName string `json:"learnerName"`
		Course      string `json:"course"`
		Hours       int    `json:"hours"`
		Grade       string `json:"grade"`
		IssuedOn    string `json:"issuedOn"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	k, problems := s.signingKey()
	if len(problems) > 0 {
		writeError(w, http.StatusBadRequest, problems...)
		return
	}

	issuedOn := strings.TrimSpace(req.IssuedOn)
	if issuedOn == "" {
		issuedOn = time.Now().Format(cert.DateLayout)
	}
	year := time.Now().Year()
	if t, err := time.Parse(cert.DateLayout, issuedOn); err == nil {
		year = t.Year()
	}
	id, seq := s.nextFreeID(year)

	signed, problems := cert.Issue(cert.Certificate{
		ID:          id,
		LearnerName: req.LearnerName,
		Course:      req.Course,
		Hours:       req.Hours,
		Grade:       req.Grade,
		IssuedOn:    issuedOn,
		IssuerName:  s.data.Institute.Name,
	}, k)
	if len(problems) > 0 {
		writeError(w, http.StatusBadRequest, problems...)
		return
	}

	s.data.Certificates = append(s.data.Certificates, signed)
	s.data.NextSeq = seq + 1
	if err := s.save(); err != nil {
		s.data.Certificates = s.data.Certificates[:len(s.data.Certificates)-1]
		writeError(w, http.StatusInternalServerError, "The certificate could not be saved: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificate": signed, "covered": cert.CoveredFields()})
}

func (s *store) handleIssueBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSV      string `json:"csv"`
		IssuedOn string `json:"issuedOn"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	k, problems := s.signingKey()
	if len(problems) > 0 {
		writeError(w, http.StatusBadRequest, problems...)
		return
	}

	fallback := strings.TrimSpace(req.IssuedOn)
	if fallback == "" {
		fallback = time.Now().Format(cert.DateLayout)
	}
	rows, err := cert.ParseBatchCSV(strings.NewReader(req.CSV), fallback)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	type outcome struct {
		Line        int                     `json:"line"`
		LearnerName string                  `json:"learnerName"`
		Issued      bool                    `json:"issued"`
		Problems    []string                `json:"problems,omitempty"`
		Certificate *cert.SignedCertificate `json:"certificate,omitempty"`
	}

	before := len(s.data.Certificates)
	seq := s.data.NextSeq
	results := make([]outcome, 0, len(rows))
	for _, row := range rows {
		res := outcome{Line: row.Line, LearnerName: row.LearnerName, Problems: row.Problems}
		if !row.OK() {
			results = append(results, res)
			continue
		}
		year := time.Now().Year()
		if t, err := time.Parse(cert.DateLayout, row.IssuedOn); err == nil {
			year = t.Year()
		}
		id, used := s.nextFreeID(year)
		signed, problems := cert.Issue(cert.Certificate{
			ID:          id,
			LearnerName: row.LearnerName,
			Course:      row.Course,
			Hours:       row.Hours,
			Grade:       row.Grade,
			IssuedOn:    row.IssuedOn,
			IssuerName:  s.data.Institute.Name,
		}, k)
		if len(problems) > 0 {
			res.Problems = problems
			results = append(results, res)
			continue
		}
		s.data.Certificates = append(s.data.Certificates, signed)
		seq = used + 1
		s.data.NextSeq = seq
		res.Issued = true
		res.Certificate = &signed
		results = append(results, res)
	}

	if len(s.data.Certificates) > before {
		if err := s.save(); err != nil {
			s.data.Certificates = s.data.Certificates[:before]
			writeError(w, http.StatusInternalServerError, "The batch could not be saved: "+err.Error())
			return
		}
	}
	issued := 0
	for _, r := range results {
		if r.Issued {
			issued++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"issued":  issued,
		"skipped": len(results) - issued,
	})
}

func (s *store) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code      string `json:"code"`
		PublicKey string `json:"publicKey"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, cert.VerifyCode(req.Code, strings.TrimSpace(req.PublicKey)))
}

func (s *store) handlePubKeyExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "This endpoint only accepts GET.")
		return
	}
	s.mu.Lock()
	inst := s.data.Institute
	s.mu.Unlock()

	if inst.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "Set up the institute first, so there is a key to export.")
		return
	}
	var b strings.Builder
	b.WriteString("Public key for verifying skill certificates\n")
	b.WriteString("==========================================\n\n")
	b.WriteString("Institute:  " + inst.Name + "\n")
	b.WriteString("Public key: " + inst.PublicKey + "\n\n")
	b.WriteString("Anyone holding this public key can check a certificate code offline:\n\n")
	b.WriteString("    verifiable-cert-issuer -verify <certificate code> -pubkey " + inst.PublicKey + "\n\n")
	b.WriteString("A valid result means the certificate was signed by the holder of the matching\n")
	b.WriteString("private key and that none of its details have been altered since. It does not\n")
	b.WriteString("say anything about whether the institute is accredited.\n\n")
	b.WriteString("This public key cannot be used to issue certificates. It is safe to publish on\n")
	b.WriteString("a website, print on a certificate, or send to an employer.\n")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="institute-public-key.txt"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, b.String())
}

// signingKey loads the institute's private key for one operation. The key is
// read from disk each time rather than held in memory for the life of the
// process.
func (s *store) signingKey() (cert.Keypair, []string) {
	if s.data.Institute.Name == "" || s.data.Institute.PublicKey == "" {
		return cert.Keypair{}, []string{"Set up the institute and its signing key first."}
	}
	k, err := cert.LoadKeypair(s.data.Institute.KeyFile)
	if err != nil {
		return cert.Keypair{}, []string{"The signing key could not be read: " + err.Error()}
	}
	if k.PublicKeyString() != s.data.Institute.PublicKey {
		return cert.Keypair{}, []string{
			"The key file holds a different key from the one this certificate list was issued under.",
			"Certificates signed with it would not verify against the published public key.",
		}
	}
	return k, nil
}
