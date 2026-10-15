//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
)

// ---- the panel process --------------------------------------------------------

// panel is the panel process.
type panel struct {
	cmd      *exec.Cmd
	data     string   // POSTERN_DATA
	dir      string   // where data and keys are
	env      []string // more of its environment, as startPanel got it
	base     string   // http://127.0.0.1:<port>
	token    string   // the setup token
	setupURL string   // as the panel printed it: the one place where the token may be
	stdout   *tailBuffer
	log      *tailBuffer // stderr
	exited   chan struct{}
	err      error // of the process, once exited is closed
}

// setupURL finds the setup URL in what the panel prints.
var setupURL = regexp.MustCompile(`http://[^\s/]+/setup\?token=[^\s]+`)

// maxPanelOutput bounds what is kept of the stdout and of the log of the
// panel, for the check of the logs; a run writes a small part of it.
const maxPanelOutput = 64 << 20

// startPanel starts postern-panel serve on 127.0.0.1 and a port that it
// picks, with a data and a key directory of its own, and waits for the setup
// URL that it prints on stdout. Its stdout and its log are kept for the check
// of the logs at the end of the run. env is more of its environment
// (NAME=value).
func (e *env) startPanel(env ...string) *panel {
	e.t.Helper()
	dir := e.t.TempDir()
	p, found := e.launchPanel(dir, "127.0.0.1:0", env)
	select {
	case raw := <-found:
		u, err := url.Parse(raw)
		if err != nil {
			e.fatalf("the setup URL the panel printed does not parse: %v", err)
		}
		p.base = "http://" + u.Host
		p.token = u.Query().Get("token")
		p.setupURL = raw
		e.mustNotLeak("the setup token", p.token)
	case <-p.exited:
		e.fatalf("the panel exited before it served (%v)", p.err)
	case <-time.After(60 * time.Second):
		e.fatalf("the panel printed no setup URL within 60 s")
	case <-e.ctx.Done():
		e.fatalf("waiting for the setup URL of the panel: %v", e.ctx.Err())
	}
	e.logf("the panel serves at %s", p.base)
	return p
}

// restartPanel starts the panel that old was again, after old has stopped:
// the same data and key directories, the same address and environment. A
// panel that has been set up prints no setup URL, so it is ready once its
// health check answers. The output of old stays in the check of the logs.
func (e *env) restartPanel(old *panel) *panel {
	e.t.Helper()
	select {
	case <-old.exited:
	default:
		e.fatalf("the panel is restarted while it runs")
	}
	e.pastPanels = append(e.pastPanels, old)
	p, _ := e.launchPanel(old.dir, strings.TrimPrefix(old.base, "http://"), old.env)
	p.base = old.base
	health := old.base + "/api/postern.panel.v1.HealthService/Check"
	deadline := time.Now().Add(60 * time.Second)
	for {
		req, err := http.NewRequestWithContext(e.ctx, http.MethodPost, health, strings.NewReader("{}"))
		if err != nil {
			e.fatalf("%v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-p.exited:
			e.fatalf("the restarted panel exited before it served (%v)", p.err)
		case <-e.ctx.Done():
			e.fatalf("waiting for the restarted panel: %v", e.ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			e.fatalf("the restarted panel does not answer its health check within 60 s")
		}
	}
	e.logf("the panel serves again at %s", p.base)
	return p
}

// launchPanel starts postern-panel serve with its data and key directories in
// dir, listening on listen. found gets the setup URL when the panel prints
// one. The cleanup of the test stops the panel.
func (e *env) launchPanel(dir, listen string, env []string) (p *panel, found chan string) {
	e.t.Helper()
	p = &panel{
		data: filepath.Join(dir, "data"), dir: dir, env: env,
		stdout: newTailBuffer(maxPanelOutput), log: newTailBuffer(maxPanelOutput), exited: make(chan struct{}),
	}
	found = make(chan string, 1)
	p.cmd = exec.Command(e.panelBin, "serve")
	p.cmd.Env = append(os.Environ(),
		"POSTERN_DATA="+p.data,
		"POSTERN_KEYS="+filepath.Join(dir, "keys"),
		"POSTERN_LISTEN="+listen,
		// The panel looks for its country database as soon as it serves: at a
		// port that nothing listens on, and not at DB-IP. The look fails, which
		// the panel notes and goes on with.
		"POSTERN_GEOIP_BASE_URL=http://127.0.0.1:"+strconv.Itoa(e.freePort("127.0.0.1", 41000, 41999)),
	)
	p.cmd.Env = append(p.cmd.Env, env...)
	p.cmd.Stdout = io.MultiWriter(&lineMatcher{re: setupURL, found: found}, p.stdout)
	p.cmd.Stderr = p.log
	if err := p.cmd.Start(); err != nil {
		e.fatalf("starting the panel: %v", err)
	}
	e.panel = p
	go func() {
		p.err = p.cmd.Wait()
		close(p.exited)
	}()
	// Before its directories go (cleanups run last in, first out).
	e.t.Cleanup(func() { _ = p.stop(15 * time.Second) })
	return p, found
}

// stop sends SIGTERM and waits for the panel to exit; it kills it after
// timeout. It returns the outcome of the process: nil for an exit with 0.
func (p *panel) stop(timeout time.Duration) error {
	select {
	case <-p.exited:
		return p.err
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
		return p.err
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		<-p.exited
		return fmt.Errorf("the panel did not stop within %v of SIGTERM and was killed", timeout)
	}
}

// lineMatcher is a writer that sends the first match of re in a line of what
// is written to found, and keeps nothing else.
type lineMatcher struct {
	re      *regexp.Regexp
	found   chan<- string
	partial []byte
	done    bool
}

func (m *lineMatcher) Write(b []byte) (int, error) {
	if m.done {
		return len(b), nil
	}
	m.partial = append(m.partial, b...)
	for {
		i := bytes.IndexByte(m.partial, '\n')
		if i < 0 {
			break
		}
		line := m.partial[:i]
		m.partial = m.partial[i+1:]
		if match := m.re.Find(line); match != nil {
			m.found <- string(match)
			m.done, m.partial = true, nil
			break
		}
	}
	if len(m.partial) > 64<<10 {
		m.partial = nil
	}
	return len(b), nil
}

// tailBuffer keeps the last bytes written to it, and whether it had to drop
// any.
type tailBuffer struct {
	mu      sync.Mutex
	max     int
	data    []byte
	dropped bool
}

func newTailBuffer(max int) *tailBuffer { return &tailBuffer{max: max} }

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	if over := len(b.data) - b.max; over > 0 {
		b.data = slices.Clone(b.data[over:])
		b.dropped = true
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data)
}

// whole reports whether the buffer holds all that was written to it.
func (b *tailBuffer) whole() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.dropped
}

// ---- the API ------------------------------------------------------------------

// api is a client of the panel's API with a session of its own (the cookie).
type api struct {
	base      string
	http      *http.Client
	auth      panelv1connect.AuthServiceClient
	nodes     panelv1connect.NodeServiceClient
	listeners panelv1connect.ListenerServiceClient
	proxies   panelv1connect.ProxyServiceClient
	egresses  panelv1connect.EgressServiceClient
	chains    panelv1connect.ChainServiceClient
	versions  panelv1connect.VersionServiceClient
	metrics   panelv1connect.MetricsServiceClient
	stats     panelv1connect.StatsServiceClient
	probes    panelv1connect.ProbeServiceClient
	diag      panelv1connect.DiagnosticsServiceClient
	settings  panelv1connect.SettingsServiceClient
	geoip     panelv1connect.GeoIPServiceClient
	page      panelv1connect.PublicPageServiceClient
}

func newAPI(base string) *api {
	jar, _ := cookiejar.New(nil) // never fails without options
	hc := &http.Client{Jar: jar, Timeout: time.Minute}
	return &api{
		base:      base,
		http:      hc,
		auth:      panelv1connect.NewAuthServiceClient(hc, base+"/api"),
		nodes:     panelv1connect.NewNodeServiceClient(hc, base+"/api"),
		listeners: panelv1connect.NewListenerServiceClient(hc, base+"/api"),
		proxies:   panelv1connect.NewProxyServiceClient(hc, base+"/api"),
		egresses:  panelv1connect.NewEgressServiceClient(hc, base+"/api"),
		chains:    panelv1connect.NewChainServiceClient(hc, base+"/api"),
		versions:  panelv1connect.NewVersionServiceClient(hc, base+"/api"),
		metrics:   panelv1connect.NewMetricsServiceClient(hc, base+"/api"),
		stats:     panelv1connect.NewStatsServiceClient(hc, base+"/api"),
		probes:    panelv1connect.NewProbeServiceClient(hc, base+"/api"),
		diag:      panelv1connect.NewDiagnosticsServiceClient(hc, base+"/api"),
		settings:  panelv1connect.NewSettingsServiceClient(hc, base+"/api"),
		geoip:     panelv1connect.NewGeoIPServiceClient(hc, base+"/api"),
		page:      panelv1connect.NewPublicPageServiceClient(hc, base+"/api"),
	}
}

// signIn creates the first admin with the setup token and signs in as it.
func (e *env) signIn(a *api, token string) {
	e.t.Helper()
	ctx := e.ctx
	st, err := a.auth.GetSetupStatus(ctx, connect.NewRequest(&panelv1.GetSetupStatusRequest{}))
	if err != nil {
		e.fatalf("GetSetupStatus: %v", err)
	}
	if !st.Msg.GetNeedsSetup() {
		e.fatalf("a new panel does not ask to be set up")
	}
	const user = "admin"
	password := rand.Text()
	e.mustNotLeak("the admin password", password)
	if _, err := a.auth.Setup(ctx, connect.NewRequest(&panelv1.SetupRequest{
		SetupToken: token, Username: user, Password: password,
	})); err != nil {
		e.fatalf("Setup: %v", err)
	}
	login, err := a.auth.Login(ctx, connect.NewRequest(&panelv1.LoginRequest{Username: user, Password: password}))
	if err != nil {
		e.fatalf("Login: %v", err)
	}
	if login.Msg.GetTotpRequired() {
		e.fatalf("Login asks for a TOTP code that the new admin does not have")
	}
	me, err := a.auth.Me(ctx, connect.NewRequest(&panelv1.MeRequest{}))
	if err != nil {
		e.fatalf("Me after Login: %v", err)
	}
	if me.Msg.GetUsername() != user {
		e.fatalf("Me = %q, want %q", me.Msg.GetUsername(), user)
	}
	e.logf("set up with the printed token and signed in as %s", user)
}

// downloadBundle fetches the bundle of a node with the session of a.
func (e *env) downloadBundle(a *api, path string) []byte {
	e.t.Helper()
	req, err := http.NewRequestWithContext(e.ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		e.fatalf("%v", err)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		e.fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		e.fatalf("GET %s: %s", path, resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-tar" {
		e.fatalf("GET %s: Content-Type %q, want application/x-tar", path, ct)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		e.fatalf("GET %s: %v", path, err)
	}
	return data
}

// getNode reads the node with the id from the panel.
func (e *env) getNode(ctx context.Context, a *api, id string) (*panelv1.Node, error) {
	r, err := a.nodes.GetNode(ctx, connect.NewRequest(&panelv1.GetNodeRequest{Id: id}))
	if err != nil {
		return nil, fmt.Errorf("GetNode: %w", err)
	}
	return r.Msg.GetNode(), nil
}

// proxyOf reads the proxy with the id from the panel.
func (e *env) proxyOf(a *api, id string) *panelv1.Proxy {
	e.t.Helper()
	r, err := a.proxies.GetProxy(e.ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: id}))
	if err != nil {
		e.fatalf("GetProxy: %v", err)
	}
	return r.Msg.GetProxy()
}

// waitServing waits until the node reports the proxy serving, for timeout at
// the most; a proxy that failed fails the test. The phase and the reason come
// from the node; waitFor prints them scrubbed, the error as well.
func (e *env) waitServing(a *api, proxyID string, timeout time.Duration) {
	e.t.Helper()
	e.waitFor("proxy "+proxyID, timeout, time.Second, func(ctx context.Context) (bool, string, error) {
		r, err := a.proxies.GetProxy(ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: proxyID}))
		if err != nil {
			return false, "", fmt.Errorf("GetProxy: %w", err)
		}
		st := r.Msg.GetProxy().GetStatus()
		status := st.GetPhase()
		if st.GetReason() != "" {
			status += ": " + st.GetReason()
		}
		switch st.GetPhase() {
		case "serving":
			return true, fmt.Sprintf("serving: telemt %s, instance generation %d", st.GetRunningVersion(), st.GetInstanceGeneration()), nil
		case "failed":
			return false, "", fmt.Errorf("the proxy failed: %s", st.GetReason())
		}
		return false, status, nil
	})
}

// change makes a change of the desired state of the node through the API with
// do, and returns the desired generation of the node after it, which the
// change must have raised.
func (e *env) change(a *api, nodeID, what string, do func(ctx context.Context) error) uint64 {
	e.t.Helper()
	before, err := e.getNode(e.ctx, a, nodeID)
	if err != nil {
		e.fatalf("%v", err)
	}
	if err := do(e.ctx); err != nil {
		e.fatalf("%s: %v", what, err)
	}
	after, err := e.getNode(e.ctx, a, nodeID)
	if err != nil {
		e.fatalf("%v", err)
	}
	if after.GetDesiredGeneration() <= before.GetDesiredGeneration() {
		e.fatalf("%s left the desired generation of the node at %d", what, after.GetDesiredGeneration())
	}
	return after.GetDesiredGeneration()
}

// waitApplied waits until the node is online and has gone all the way through
// a reconcile pass of the desired generation, and the proxy is in the phase,
// with cond true when there is one (it also says what it looked at). A proxy
// that failed fails the test.
func (e *env) waitApplied(a *api, nodeID, proxyID string, desired uint64, phase string, cond func(*panelv1.Proxy) (bool, string)) {
	e.t.Helper()
	e.waitFor(fmt.Sprintf("generation %d on the node, the proxy %s", desired, phase), 2*time.Minute, time.Second,
		func(ctx context.Context) (bool, string, error) {
			n, err := e.getNode(ctx, a, nodeID)
			if err != nil {
				return false, "", err
			}
			r, err := a.proxies.GetProxy(ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: proxyID}))
			if err != nil {
				return false, "", fmt.Errorf("GetProxy: %w", err)
			}
			p := r.Msg.GetProxy()
			st := p.GetStatus()
			if st.GetPhase() == "failed" {
				return false, "", fmt.Errorf("the proxy failed: %s", st.GetReason())
			}
			status := fmt.Sprintf("node %s, generation %d applied; proxy %s", n.GetStatus(), n.GetAppliedGeneration(), st.GetPhase())
			if st.GetReason() != "" {
				status += ": " + st.GetReason()
			}
			done := n.GetStatus() == "online" && n.GetAppliedGeneration() >= desired && st.GetPhase() == phase
			if cond != nil {
				ok, what := cond(p)
				done = done && ok
				status += ", " + what
			}
			return done, status, nil
		})
}

// checkLinks gets the links of the proxy, checks that they lead to the
// listener with the proxy's secret and domain, and returns the secret and the
// domain as a client takes them from the tg:// link.
func (e *env) checkLinks(a *api, proxyID string, port int, secretHex string) (secret []byte, domain string) {
	e.t.Helper()
	return e.checkLinksOf(a, proxyID, port, secretHex, proxyDomain)
}

// checkLinksOf is checkLinks for a proxy with the domain want.
func (e *env) checkLinksOf(a *api, proxyID string, port int, secretHex, want string) (secret []byte, domain string) {
	e.t.Helper()
	return e.checkLinksAt(a, proxyID, linkHost, port, secretHex, want)
}

// checkLinksAt is checkLinksOf for links that lead to host, the link host of
// the listener.
func (e *env) checkLinksAt(a *api, proxyID, host string, port int, secretHex, want string) (secret []byte, domain string) {
	e.t.Helper()
	r, err := a.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: proxyID}))
	if err != nil {
		e.fatalf("GetProxyLinks: %v", err)
	}
	tg, https := r.Msg.GetTg(), r.Msg.GetHttps()
	u, err := url.Parse(tg)
	if err != nil || u.Scheme != "tg" || u.Host != "proxy" {
		e.fatalf("the tg link is not a tg://proxy link (%v)", err)
	}
	if want := "https://t.me/proxy?" + u.RawQuery; https != want {
		e.errorf("the https link does not carry the query of the tg link")
	}
	if !strings.Contains(r.Msg.GetQrSvg(), "<svg") {
		e.errorf("the links come without a QR code")
	}
	q := u.Query()
	if q.Get("server") != host || q.Get("port") != strconv.Itoa(port) {
		e.fatalf("the link leads to %s:%s, want %s:%d", q.Get("server"), q.Get("port"), host, port)
	}
	s := q.Get("secret")
	if len(s) < 2+32+2 || !strings.HasPrefix(s, "ee") {
		e.fatalf("the secret of the link is not that of a fake-TLS proxy (ee, 32 hex digits, the domain in hex)")
	}
	secret, err1 := hex.DecodeString(s[2:34])
	d, err2 := hex.DecodeString(s[34:])
	switch {
	case err1 != nil || err2 != nil:
		e.fatalf("the secret of the link is not hex")
	case !bytes.Equal(secret, mustHex(secretHex)):
		e.fatalf("the link carries another secret than the proxy's")
	case string(d) != want:
		e.fatalf("the link carries the domain %q, want %q", d, want)
	}
	e.logf("the links lead to %s:%d with the proxy's secret and domain", host, port)
	return secret, string(d)
}
