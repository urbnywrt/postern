package bootstrap

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/pki"
)

// The files of a join (Global Constraints).
const (
	pkiDir         = "pki"
	tokenHashFile  = "join-token.sha256" //nolint:gosec // a file name; in data/state: the SHA-256 of the token last joined with
	pendingKeyFile = "key.pem"           // in data/run/join, while a join is in flight
	pendingTokFile = "token.sha256"
	commonNameCSR  = "postern-node"
	maxPEM         = 64 << 10
)

// pkiFiles are the files of pki/, as a bundle has them.
var pkiFiles = []string{"bundle.json", "ca.pem", "node.pem", "node-key.pem"}

// The join call of a node without keys: one attempt is bounded by
// callTimeout; a network failure or Unavailable is tried again after each of
// retryDelays. A node with keys (a re-join with a new token) has rejoinTimeout
// and rejoinDelays instead: a lost answer is recovered, but a panel that is
// down holds the start back by seconds only.
var (
	callTimeout   = 30 * time.Second
	retryDelays   = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	rejoinTimeout = 10 * time.Second
	rejoinDelays  = []time.Duration{2 * time.Second, 4 * time.Second}
)

// refusalWait is how long a node without keys waits after the panel refused
// its join, before it exits: Docker starts the container again at once, and a
// dead token must not hammer the panel. A SIGTERM ends the wait.
const refusalWait = 5 * time.Minute

// nodeIDRe is a node id: a ULID.
var nodeIDRe = regexp.MustCompile(`^[0-9A-Z]{26}$`)

// joinStep decides whether the node joins the panel, and joins.
func (b *boot) joinStep(ctx context.Context) error {
	complete := b.pkiComplete()
	var spec *joinSpec
	if v, ok := lookupEnv(b.opt.Env, EnvJoin); ok && v != "" {
		s, err := parseJoin(v)
		if err != nil {
			if !complete {
				return fmt.Errorf("bootstrap: %w", err)
			}
			b.log.Warn("bootstrap: "+EnvJoin+" is not usable; the node starts with the keys it has", "err", err)
		}
		spec = s
	}
	switch {
	case spec == nil && !complete:
		return ErrNoKeys
	case spec == nil:
		return nil
	case complete && b.joinedWith(spec.token):
		b.log.Info("bootstrap: the node joined with this token already; it starts with its keys", "panel", spec.base)
		// A key left pending for this token is of a join that ended after all;
		// it is no longer needed.
		if err := os.RemoveAll(b.path("data", "run", "join")); err != nil {
			b.log.Warn("bootstrap: cannot remove data/run/join", "err", err)
		}
		return nil
	}
	// With keys the node can start, the join is tried three times within
	// seconds: an unreachable panel or a dead token must not hold every start
	// of the container back.
	err := b.join(ctx, spec, !complete)
	switch {
	case err == nil:
		return nil
	case complete:
		b.log.Warn("bootstrap: the join failed; the node starts with the keys it has", "panel", spec.base, "err", err)
		return nil
	case refused(err):
		b.log.Error("bootstrap: the panel refused the join; waiting before exiting, so that restarts do not hammer the panel",
			"panel", spec.base, "wait", refusalWait, "err", err)
		_ = b.opt.Sleep(ctx, refusalWait) // ends early on SIGTERM
	}
	return err
}

// refused tells whether the panel refused a join for good: only a new token,
// or time, changes its answer.
func refused(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated, connect.CodeInvalidArgument, connect.CodeResourceExhausted:
		return true
	}
	return false
}

// pkiComplete tells whether pki/ holds the four files of a bundle.
func (b *boot) pkiComplete() bool {
	for _, f := range pkiFiles {
		st, err := os.Stat(b.path(pkiDir, f))
		if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			return false
		}
	}
	return true
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// joinedWith tells whether data/state/join-token.sha256 names token.
func (b *boot) joinedWith(token string) bool {
	data, err := readSmall(b.path("data", "state", tokenHashFile), 256)
	return err == nil && strings.TrimSpace(string(data)) == tokenHash(token)
}

// join makes or reuses the pending key, has the panel sign it, and installs
// the keys and the node's identity.
func (b *boot) join(ctx context.Context, spec *joinSpec, noKeys bool) error {
	runJoin := b.path("data", "run", "join")
	hash := tokenHash(spec.token)
	key, keyPEM, err := b.pendingKey(runJoin, hash)
	if err != nil {
		return fmt.Errorf("bootstrap: join: the key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonNameCSR}}, key)
	if err != nil {
		return fmt.Errorf("bootstrap: join: the certificate request: %w", err)
	}
	b.log.Info("bootstrap: joining the panel", "panel", spec.base)
	resp, err := b.callJoin(ctx, spec, noKeys, &panelv1.JoinRequest{Token: spec.token, Csr: csr, Arch: b.opt.Arch, Version: b.opt.Version})
	if err != nil {
		return err
	}
	bundle, err := b.checkResponse(resp, key, keyPEM)
	if err != nil {
		return fmt.Errorf("bootstrap: join: the panel's answer: %w", err)
	}
	if err := b.installPKI(bundle); err != nil {
		return fmt.Errorf("bootstrap: join: %w", err)
	}
	if err := b.installIdentity(bundle.NodeID); err != nil {
		return fmt.Errorf("bootstrap: join: %w", err)
	}
	if err := writeFileAtomic(b.path("data", "state", tokenHashFile), []byte(hash+"\n"), 0o600); err != nil {
		return fmt.Errorf("bootstrap: join: %w", err)
	}
	if err := os.RemoveAll(runJoin); err != nil {
		b.log.Warn("bootstrap: cannot remove data/run/join", "err", err)
	}
	b.log.Info("bootstrap: joined the panel", "node", bundle.NodeID, "mgmt_port", bundle.MgmtPort)
	return nil
}

// pendingKey returns the key of the join in flight with this token, or makes a
// new one. Both files are written before any call to the panel, so that a join
// whose answer was lost is made again with the same key, which the panel
// answers with the same certificate.
func (b *boot) pendingKey(dir, hash string) (*ecdsa.PrivateKey, []byte, error) {
	if err := makeDir(dir, 0o700); err != nil {
		return nil, nil, err
	}
	keyPath, tokPath := filepath.Join(dir, pendingKeyFile), filepath.Join(dir, pendingTokFile)
	if have, err := readSmall(tokPath, 256); err == nil && strings.TrimSpace(string(have)) == hash {
		if keyPEM, err := readSmall(keyPath, maxPEM); err == nil {
			if key, err := parseKey(keyPEM); err == nil {
				return key, keyPEM, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(tokPath, []byte(hash+"\n"), 0o600); err != nil {
		return nil, nil, err
	}
	return key, keyPEM, nil
}

func parseKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PKCS#8 PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("not an ECDSA P-256 key")
	}
	return key, nil
}

// httpClient is the client of the join: system roots (or RootCAs), TLS 1.2 or
// later, HTTP/1.1 or HTTP/2, and never a proxy from the environment (ruling
// S5-16).
func (b *boot) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: callTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: b.opt.RootCAs},
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: callTimeout,
			MaxIdleConns:        2,
			IdleConnTimeout:     time.Minute,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// callJoin calls JoinService.Join, and calls again on a network failure or
// Unavailable: without keys (noKeys) after 2, 4, 8 and 16 s, 30 s a call;
// with keys after 2 and 4 s, 10 s a call. The panel's refusals
// (Unauthenticated, InvalidArgument, ResourceExhausted ...) are final.
func (b *boot) callJoin(ctx context.Context, spec *joinSpec, noKeys bool, req *panelv1.JoinRequest) (*panelv1.JoinResponse, error) {
	hc := b.httpClient()
	defer hc.CloseIdleConnections()
	client := panelv1connect.NewJoinServiceClient(hc, spec.apiURL(), connect.WithReadMaxBytes(256<<10))
	timeout, delays := rejoinTimeout, rejoinDelays
	if noKeys {
		timeout, delays = callTimeout, retryDelays
	}
	for attempt := 0; ; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		resp, err := client.Join(cctx, connect.NewRequest(req))
		cancel()
		if err == nil {
			return resp.Msg, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !retryable(err) || attempt == len(delays) {
			return nil, joinError(spec, err)
		}
		d := delays[attempt]
		b.log.Warn("bootstrap: the join did not reach the panel; trying again", "panel", spec.base, "in", d, "err", err)
		if err := b.opt.Sleep(ctx, d); err != nil {
			return nil, err
		}
	}
}

// retryable is a failure that may pass: the network, or a panel that is not
// there for the moment. A certificate the node does not trust is final.
func retryable(err error) bool {
	var verr *tls.CertificateVerificationError
	var uerr x509.UnknownAuthorityError
	var herr x509.HostnameError
	if errors.As(err, &verr) || errors.As(err, &uerr) || errors.As(err, &herr) {
		return false
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded:
		return true
	}
	return false
}

func joinError(spec *joinSpec, err error) error {
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated:
		return fmt.Errorf("bootstrap: the panel at %s refused the token (unknown, expired or used): make a new one on the node's page: %w", spec.base, err)
	case connect.CodeResourceExhausted:
		return fmt.Errorf("bootstrap: the panel at %s refuses joins from this address for a while: %w", spec.base, err)
	}
	return fmt.Errorf("bootstrap: join the panel at %s: %w", spec.base, err)
}

// checkResponse checks the panel's answer against the key that was sent and
// returns the bundle it makes.
func (b *boot) checkResponse(resp *panelv1.JoinResponse, key *ecdsa.PrivateKey, keyPEM []byte) (*pki.Bundle, error) {
	id := resp.GetNodeId()
	if !nodeIDRe.MatchString(id) {
		return nil, fmt.Errorf("the node id %.40q is not a ULID", id)
	}
	port := resp.GetMgmtPort()
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("the management port %d is out of range", port)
	}
	ca, err := parseCert(resp.GetCaPem())
	if err != nil {
		return nil, fmt.Errorf("ca_pem: %w", err)
	}
	cert, err := parseCert(resp.GetCertPem())
	if err != nil {
		return nil, fmt.Errorf("cert_pem: %w", err)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("the certificate is not for the key that was sent")
	}
	if want := strings.ToLower(id); cert.Subject.CommonName != want || len(cert.DNSNames) != 1 || cert.DNSNames[0] != want+".internal" {
		return nil, fmt.Errorf("the certificate names %.40q (%.80q), not node %s", cert.Subject.CommonName, cert.DNSNames, id)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: b.opt.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("the certificate does not chain to the CA: %w", err)
	}
	return &pki.Bundle{NodeID: id, MgmtPort: int(port), CAPEM: resp.GetCaPem(), CertPEM: resp.GetCertPem(), KeyPEM: keyPEM}, nil
}

func parseCert(data []byte) (*x509.Certificate, error) {
	if len(data) == 0 || len(data) > maxPEM {
		return nil, fmt.Errorf("%d bytes, want 1 to %d", len(data), maxPEM)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// installPKI writes the bundle's four files into pki.new-<pid> (bundle.json
// as pki marshals it) and swaps it in: the pki/ that is there becomes pki.old.
func (b *boot) installPKI(bundle *pki.Bundle) error {
	data, err := bundle.MarshalTar()
	if err != nil {
		return err
	}
	stale, _ := filepath.Glob(b.path(pkiDir + ".new-*"))
	for _, s := range stale {
		_ = os.RemoveAll(s)
	}
	tmp := b.path(pkiDir + ".new-" + strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o700); err != nil { //nolint:gosec // a directory: 0700 is the least that lets its owner in
		return err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(tmp, filepath.Base(hdr.Name)), body, 0o600); err != nil {
			return err
		}
	}
	syncDir(tmp)

	cur, old := b.path(pkiDir), b.path(pkiDir+".old")
	moved := false
	if entries, err := os.ReadDir(cur); err == nil {
		if len(entries) == 0 {
			if err := os.Remove(cur); err != nil {
				return err
			}
		} else {
			if err := os.RemoveAll(old); err != nil {
				return err
			}
			if err := os.Rename(cur, old); err != nil {
				return err
			}
			moved = true
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmp, cur); err != nil {
		if moved {
			_ = os.Rename(old, cur)
		}
		return err
	}
	syncDir(b.opt.Home)
	return nil
}

// writeNew writes a file that must not exist yet.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// installIdentity is install.sh install_identity: data/state/node-id names the
// node; state that belongs to another node (or to none that can be told) is
// moved aside to data/state.bak-<unix time>, never deleted.
func (b *boot) installIdentity(nodeID string) error {
	state := b.path("data", "state")
	idFile := filepath.Join(state, "node-id")
	existing := ""
	if data, err := readSmall(idFile, 64); err == nil {
		existing, _, _ = strings.Cut(string(data), "\n")
	}
	if existing != nodeID && stateHasData(state) {
		ts := strconv.FormatInt(b.opt.Now().Unix(), 10)
		bak := b.path("data", "state.bak-"+ts)
		for i := 1; ; i++ {
			if _, err := os.Lstat(bak); os.IsNotExist(err) {
				break
			}
			bak = b.path("data", "state.bak-"+ts+"-"+strconv.Itoa(i))
		}
		if err := os.Rename(state, bak); err != nil {
			return err
		}
		if err := makeDir(state, 0o700); err != nil {
			return err
		}
		rel := "data/" + filepath.Base(bak)
		if nodeIDRe.MatchString(existing) {
			b.log.Info("bootstrap: the state of node "+existing+" is moved to "+rel+"; the panel sends the desired state again when the node connects", "node", nodeID)
		} else {
			b.log.Info("bootstrap: state of unknown origin is moved to "+rel+"; the panel sends the desired state again when the node connects", "node", nodeID)
		}
	}
	return writeFileAtomic(idFile, []byte(nodeID+"\n"), 0o600)
}

// stateHasData tells whether dir holds anything besides node-id.
func stateHasData(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() != "node-id" {
			return true
		}
	}
	return false
}
