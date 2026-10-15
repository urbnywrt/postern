//go:build integration

package acme

// The manager issues with lego against Pebble, the test CA of Let's Encrypt,
// in Docker:
//
//	go test -tags integration -run Pebble ./internal/node/acme/
//
// It needs the docker command and a daemon that can pull the two images below
// (pinned by digest); nothing else of the internet, and it never touches a real
// zone or a real CA. Two containers, on a network of their own, their ports
// published on 127.0.0.1 only:
//
//   - pebble-challtestsrv, the DNS server of Pebble's tests, stands in for
//     Cloudflare and for the public resolvers: the DNS provider of the test
//     writes the TXT records through its management API, and the propagation
//     check asks its DNS-over-HTTPS endpoint, through internal/doh, as both of
//     the resolvers that must see the value;
//   - Pebble, which validates the DNS-01 challenges against that DNS server.
//
// The ACME API and the DNS-over-HTTPS endpoint have the certificate of
// Pebble's test suite, for 127.0.0.1 among others, whose CA the test copies out
// of the image. Every container and the network are labelled
// postern.test=acme and removed at the end.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/node/state"
)

const (
	// Pebble v2.10.1 and its challtestsrv.
	pebbleImage       = "ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
	challtestsrvImage = "ghcr.io/letsencrypt/pebble-challtestsrv@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b"
	// testLabel marks what the test makes in Docker.
	testLabel = "postern.test=acme"
)

// pebble is a running Pebble and its challtestsrv.
type pebble struct {
	acmeURL string         // the ACME directory
	rootURL string         // the root of the certificates Pebble issues, on its management API
	ctsURL  string         // the management API of challtestsrv
	dohURL  string         // the DNS-over-HTTPS endpoint of challtestsrv
	roots   *x509.CertPool // the CA of the certificates of the APIs
}

func TestPebble(t *testing.T) {
	p := startPebble(t)

	t.Run("issue, keep, renew, clean up", func(t *testing.T) {
		const domain = "web.example.com"
		cts := p.provider(t)
		// A record that an earlier attempt left.
		if err := cts.post(t.Context(), "/set-txt", map[string]string{"host": challengeName(domain) + ".", "value": "stale"}); err != nil {
			t.Fatal(err)
		}
		r := p.manager(t, cts)
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
		defer cancel()

		if err := r.m.Issue(ctx, domain, "admin@example.com", CloudflareToken(testToken)); err != nil {
			t.Fatalf("Issue: %v\nlog:\n%s", err, r.log)
		}
		calls := cts.callList()
		if len(calls) != 3 || calls[0] != "stale "+domain || !strings.HasPrefix(calls[1], "present "+domain+" ") ||
			calls[2] != "cleanup "+domain+" "+strings.TrimPrefix(calls[1], "present "+domain+" ") {
			t.Errorf("DNS provider calls = %q, want the stale records removed, the record written, then deleted", calls)
		}
		// Nothing is left at the challenge name: not the stale value, not ours.
		if txts := p.lookupTXT(t, challengeName(domain)); len(txts) != 0 {
			t.Errorf("TXT records left at %s: %q", challengeName(domain), txts)
		}

		dir := filepath.Join(r.m.Paths.CertsDir(), domain)
		chain := readFile(t, filepath.Join(dir, fullchainFile))
		leaf := p.verify(t, chain, domain)
		if _, err := certLeaf(chain, readFile(t, filepath.Join(dir, privkeyFile)), domain); err != nil {
			t.Errorf("the key does not match: %v", err)
		}
		if got := mode(t, filepath.Join(dir, privkeyFile)); got != 0o600 {
			t.Errorf("privkey.pem has mode %v", got)
		}
		var meta map[string]any
		if err := json.Unmarshal(readFile(t, filepath.Join(dir, metaFile)), &meta); err != nil {
			t.Fatal(err)
		}
		if meta["staging"] != true || meta["expiresAt"] != leaf.NotAfter.UTC().Format(jsTimeLayout) {
			t.Errorf("meta.json = %v", meta)
		}
		account := readAccountFile(t, r.m)
		if a := account.Accounts[p.acmeURL]; a.URI == "" || !slices.Equal(a.Contact, []string{"admin@example.com"}) {
			t.Errorf("account.json notes %+v for %s", a, p.acmeURL)
		}
		if got := mode(t, r.m.accountPath()); got != 0o600 {
			t.Errorf("account.json has mode %v", got)
		}
		if st := r.m.Status(domain); !st.Valid || st.Due || !st.Staging || st.Reason() != "" {
			t.Errorf("Status = %+v", st)
		}
		if got := r.events.kinds(); !slices.Equal(got, []string{EventCertIssued}) {
			t.Errorf("events = %q", got)
		}

		// A certificate that is not due: nothing is asked of anyone.
		if err := r.m.Issue(ctx, domain, "admin@example.com", CloudflareToken(testToken)); err != nil {
			t.Fatalf("Issue again: %v", err)
		}
		if n := len(cts.callList()); n != 3 {
			t.Errorf("Issue of a good certificate made %d calls of the DNS provider", n-3)
		}

		// A certificate from the other directory is due: Renew issues a new
		// one, with the same account. (Not by moving the clock of the node:
		// the CA issues by its own, and a new certificate that the clock of
		// the node takes for due at once is a failure.)
		if err := os.WriteFile(filepath.Join(dir, metaFile), []byte(`{"staging":false}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if st := r.m.Status(domain); !st.Valid || !st.Due {
			t.Fatalf("Status = %+v, want a valid certificate that is due", st)
		}
		if err := r.m.Renew(ctx); err != nil {
			t.Fatalf("Renew: %v\nlog:\n%s", err, r.log)
		}
		renewed := readFile(t, filepath.Join(dir, fullchainFile))
		if bytes.Equal(renewed, chain) {
			t.Error("Renew did not replace the certificate")
		}
		if newLeaf := p.verify(t, renewed, domain); newLeaf.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			t.Error("the renewed certificate is the old one")
		}
		again := readAccountFile(t, r.m)
		if again.Key != account.Key || again.Accounts[p.acmeURL].URI != account.Accounts[p.acmeURL].URI {
			t.Error("the renewal used another account")
		}
		evs := r.events.all()
		if len(evs) != 2 || evs[1].GetDetails()["reason"] != "the certificate was from the other ACME directory" {
			t.Errorf("events = %v", evs)
		}
		if n := len(cts.callList()); n != 6 {
			t.Errorf("%d calls of the DNS provider, want 3 more for the renewal", n)
		}
		r.noToken(t)
	})

	t.Run("a record that never shows", func(t *testing.T) {
		const domain = "silent.example.com"
		cts := p.provider(t)
		cts.silent = true // Present writes nothing
		r := p.manager(t, cts)
		r.m.propagationTimeout = 3 * time.Second
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		start := time.Now()
		err := r.m.Issue(ctx, domain, "", CloudflareToken(testToken))
		if err == nil {
			t.Fatal("Issue went through without the record")
		}
		if d := time.Since(start); d < 2*3*time.Second+time.Second {
			t.Errorf("Issue failed after %v: the record was not waited for twice, a second apart", d)
		}
		want := "the TXT record _acme-challenge.silent.example.com was not visible at every resolver within 3s"
		st := r.m.Status(domain)
		if !strings.Contains(st.LastError, want) {
			t.Errorf("LastError = %q, want %q", st.LastError, want)
		}
		evs := r.events.all()
		if len(evs) != 1 || evs[0].GetKind() != EventCertFailed || evs[0].GetDetails()["attempts"] != "2" ||
			!strings.Contains(evs[0].GetDetails()["reason"], want) {
			t.Errorf("events = %v", evs)
		}
		calls := cts.callList()
		if len(calls) != 6 || calls[0] != "stale "+domain || calls[3] != "stale "+domain {
			t.Errorf("DNS provider calls = %q, want two attempts of three steps", calls)
		}
		if _, err := os.Stat(filepath.Join(r.m.Paths.CertsDir(), domain)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a failed issuance left a directory: %v", err)
		}
		r.noToken(t)
	})

	t.Run("the CA refuses the domain", func(t *testing.T) {
		const domain = "blocked-domain.example" // on the block list of Pebble's configuration
		r := p.manager(t, p.provider(t))
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		if err := r.m.Issue(ctx, domain, "", CloudflareToken(testToken)); err == nil {
			t.Fatal("Issue went through")
		}
		st := r.m.Status(domain)
		if !strings.Contains(st.LastError, "rejectedIdentifier") || strings.Contains(st.LastError, "\n") || len(st.LastError) > maxReason {
			t.Errorf("LastError = %q, want the problem of the CA, short, on one line", st.LastError)
		}
	})
}

func TestSweepRemovesTheLeftoversOfARunThatWasKilled(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	name := "postern-test-leftover-" + strings.ToLower(rand.Text())[:10]
	docker(t, ctx, "network", "create", "--label", testLabel, name)
	docker(t, ctx, "create", "--name", name, "--label", testLabel, challtestsrvImage)
	t.Cleanup(func() { dockerQuiet("rm", "-f", name); dockerQuiet("network", "rm", name) })

	sweep(t)
	if out := docker(t, ctx, "ps", "-aq", "--filter", "label="+testLabel); out != "" {
		t.Errorf("containers left: %s", out)
	}
	if out := docker(t, ctx, "network", "ls", "-q", "--filter", "label="+testLabel); out != "" {
		t.Errorf("networks left: %s", out)
	}
}

// ---- the rig --------------------------------------------------------------------

type pebbleRig struct {
	m      *Manager
	events *eventLog
	log    *syncBuffer
}

// manager returns a manager of a node of its own that issues from Pebble,
// writes the records with cts and checks them at challtestsrv. Its clock is
// the real one, as the CA's is.
func (p *pebble) manager(t *testing.T, cts *ctsProvider) *pebbleRig {
	t.Helper()
	r := &pebbleRig{events: &eventLog{}, log: &syncBuffer{}}
	r.m = &Manager{
		Paths:                state.Paths{Home: t.TempDir()},
		Staging:              true,
		Directory:            p.acmeURL,
		RootCAs:              p.roots,
		PropagationEndpoints: [][]string{{p.dohURL}, {p.dohURL}},
		DNS: func(c Credential) (DNSProvider, error) {
			if c.token() != testToken {
				return nil, errors.New("not the credential that Issue was given")
			}
			return cts, nil
		},
		Events:       r.events.add,
		Log:          slog.New(slog.NewTextHandler(r.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		LookupIP:     noLookup, // everything is at 127.0.0.1
		firstPoll:    500 * time.Millisecond,
		pollInterval: 500 * time.Millisecond,
		retryAfter:   time.Second,
	}
	return r
}

// noToken fails the test when the token shows in the log or in an event.
func (r *pebbleRig) noToken(t *testing.T) {
	t.Helper()
	out := r.log.String()
	for _, ev := range r.events.all() {
		out += ev.GetMessage() + fmt.Sprint(ev.GetDetails())
	}
	if strings.Contains(out, testToken) {
		t.Error("the token shows in the log or in an event")
	}
}

// ctsProvider is a DNSProvider of challtestsrv.
type ctsProvider struct {
	base   string
	client *http.Client
	silent bool

	mu    sync.Mutex
	calls []string
}

func (p *pebble) provider(t *testing.T) *ctsProvider {
	t.Helper()
	tr := &http.Transport{Proxy: nil}
	t.Cleanup(tr.CloseIdleConnections)
	return &ctsProvider{base: p.ctsURL, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}}
}

func (c *ctsProvider) note(call string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, call)
}

func (c *ctsProvider) callList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

func (c *ctsProvider) post(ctx context.Context, path string, body map[string]string) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

func (c *ctsProvider) RemoveStale(ctx context.Context, domain string) error {
	c.note("stale " + domain)
	return c.post(ctx, "/clear-txt", map[string]string{"host": challengeName(domain) + "."})
}

func (c *ctsProvider) Present(ctx context.Context, domain, value string) error {
	c.note("present " + domain + " " + value)
	if c.silent {
		return nil
	}
	return c.post(ctx, "/set-txt", map[string]string{"host": challengeName(domain) + ".", "value": value})
}

func (c *ctsProvider) CleanUp(ctx context.Context, domain, value string) error {
	c.note("cleanup " + domain + " " + value)
	return c.post(ctx, "/clear-txt", map[string]string{"host": challengeName(domain) + "."})
}

// lookupTXT asks the DNS-over-HTTPS endpoint of challtestsrv.
func (p *pebble) lookupTXT(t *testing.T, name string) []string {
	t.Helper()
	c := doh.NewWithRoots([]string{p.dohURL}, p.roots)
	defer c.CloseIdleConnections()
	txts, err := c.LookupTXT(t.Context(), name)
	var dnsErr *net.DNSError
	if err != nil && (!errors.As(err, &dnsErr) || !dnsErr.IsNotFound) {
		t.Fatalf("LookupTXT %s: %v", name, err)
	}
	return txts
}

func tlsConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

// verify checks that chain is a chain of Pebble for domain, up to the root it
// issues from, and returns its leaf.
func (p *pebble) verify(t *testing.T, chain []byte, domain string) *x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for rest := chain; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	if len(certs) < 2 {
		t.Fatalf("fullchain.pem holds %d certificates, want the leaf and its intermediate", len(certs))
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: domain, Roots: p.issuingRoots(t), Intermediates: inter}); err != nil {
		t.Errorf("the chain does not verify for %s: %v", domain, err)
	}
	return certs[0]
}

// issuingRoots is the root that Pebble issues from, which it makes when it
// starts.
func (p *pebble) issuingRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig(p.roots)}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get(p.rootURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		t.Fatalf("no root at %s: %s", p.rootURL, body)
	}
	return pool
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readAccountFile(t *testing.T, m *Manager) accountFile {
	t.Helper()
	var f accountFile
	if err := json.Unmarshal(readFile(t, m.accountPath()), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// startPebble starts challtestsrv and Pebble, and waits until they answer.
func startPebble(t *testing.T) *pebble {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("the docker command is not on PATH: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	sweep(t)
	run := strings.ToLower(rand.Text())[:10]
	network := "postern-test-" + run
	docker(t, ctx, "network", "create", "--label", testLabel, network)
	t.Cleanup(func() { dockerQuiet("network", "rm", network) })

	cts := network + "-challtestsrv"
	docker(t, ctx, "run", "-d", "--name", cts, "--network", network, "--label", testLabel,
		"-p", "127.0.0.1::8055", "-p", "127.0.0.1::8443",
		challtestsrvImage,
		"-http01", "", "-https01", "", "-tlsalpn01", "",
		"-doh", ":8443", "-doh-cert", "test/certs/localhost/cert.pem", "-doh-cert-key", "test/certs/localhost/key.pem")
	t.Cleanup(func() { dockerQuiet("rm", "-f", cts) })
	ctsIP := docker(t, ctx, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cts)

	peb := network + "-pebble"
	docker(t, ctx, "run", "-d", "--name", peb, "--network", network, "--label", testLabel,
		"-p", "127.0.0.1::14000", "-p", "127.0.0.1::15000",
		// No random pause before a validation, no random bad nonce, no reuse
		// of an authorization: every issuance solves its challenge.
		"-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0", "-e", "PEBBLE_AUTHZREUSE=0",
		pebbleImage, "-config", "test/config/pebble-config.json", "-dnsserver", ctsIP+":8053")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("pebble log:\n%s", dockerQuiet("logs", "--tail", "50", peb))
		}
		dockerQuiet("rm", "-f", peb)
	})

	certs := t.TempDir()
	docker(t, ctx, "cp", peb+":/test/certs/pebble.minica.pem", filepath.Join(certs, "minica.pem"))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(readFile(t, filepath.Join(certs, "minica.pem"))) {
		t.Fatal("no CA in pebble.minica.pem")
	}
	p := &pebble{
		acmeURL: "https://" + hostPort(t, ctx, peb, "14000/tcp") + "/dir",
		rootURL: "https://" + hostPort(t, ctx, peb, "15000/tcp") + "/roots/0",
		ctsURL:  "http://" + hostPort(t, ctx, cts, "8055/tcp"),
		dohURL:  "https://" + hostPort(t, ctx, cts, "8443/tcp") + "/dns-query",
		roots:   roots,
	}

	// Wait until both answer.
	client := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig(roots)}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	ready := p.provider(t)
	for {
		resp, err := client.Get(p.acmeURL)
		if err == nil {
			_ = resp.Body.Close()
		}
		if err == nil && resp.StatusCode == http.StatusOK && ready.post(ctx, "/clear-txt", map[string]string{"host": "ready.example.com."}) == nil {
			return p
		}
		select {
		case <-ctx.Done():
			t.Fatalf("Pebble did not answer at %s: %v", p.acmeURL, err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// sweep removes what a run that was killed before its clean-up left behind:
// every container and network labelled testLabel. (Two runs at the same time
// would remove each other's.)
func sweep(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if ids := strings.Fields(docker(t, ctx, "ps", "-aq", "--filter", "label="+testLabel)); len(ids) > 0 {
		docker(t, ctx, append([]string{"rm", "-f"}, ids...)...)
	}
	if ids := strings.Fields(docker(t, ctx, "network", "ls", "-q", "--filter", "label="+testLabel)); len(ids) > 0 {
		docker(t, ctx, append([]string{"network", "rm"}, ids...)...)
	}
}

// hostPort is where a port of a container is published.
func hostPort(t *testing.T, ctx context.Context, container, port string) string {
	t.Helper()
	out := docker(t, ctx, "port", container, port)
	return strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
}

func docker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// dockerQuiet runs a docker command of the clean-up, whatever comes of it.
func dockerQuiet(args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out)
}
