//go:build e2e

// Package e2e is the end-to-end test of Postern: the panel binary as a
// process, a node installed from the panel's bundle as an agent container,
// the edge and the telemt engine that the agent starts, and a fake-TLS client
// that goes through the edge to the engine; and a proxy that goes out through
// an egress chain of Xray egresses, to remote VLESS servers in containers of
// the run, and fails over; and WEB proxies on a tls listener and behind Caddy
// on an http-upstream one; and the statistics, the diagnostics and the public
// page of a node. e2e_test.go, egress_test.go, web_test.go and insights_test.go
// say what is checked; scripts/e2e.sh runs them:
//
//	bash scripts/e2e.sh                    (from Git Bash on Windows: bash scripts/wsl 'bash scripts/e2e.sh')
//	go test -tags e2e ./test/e2e/ -timeout 60m   (on Linux with a local Docker engine)
//
// It needs Docker and access to GitHub, where the panel downloads telemt and
// Xray from; without GitHub the tests are skipped. It needs the datacenters of
// Telegram as well: a new generation of an engine serves only once one of them
// has answered through its egress, and the members of an egress chain are
// checked against them. The WEB proxies need DNS-over-HTTPS and sslip.io,
// whose names resolve to the public address of the node. The agent runs on
// the host network like deploy/node/compose.yaml, so the test has to run in
// the network namespace of the containers on the host network: on a Linux
// engine that is the host's, and on Docker Desktop that of Docker's VM, which
// only a container reaches (scripts/e2e.sh runs the test in one there). One
// run at a time per Docker daemon: the node's containers have fixed names,
// the test refuses to start next to containers of another Postern node, and
// the network of the remote servers takes a fixed prefix (198.51.100.0/24).
//
// The environment:
//
//	POSTERN_E2E_NODE_BIN   postern-node v0.90.0-e2e, for Linux and the architecture of the Docker daemon
//	POSTERN_E2E_PANEL_BIN  postern-panel v0.90.1-e2e, for the machine the test runs on
//	                       (without the two, the test builds both from this repository,
//	                       and the three below, when the go command is there)
//	POSTERN_E2E_NODE_UPDATE_BIN  postern-node v0.90.1-e2e, the update of TestVersions
//	POSTERN_E2E_BADENGINE_BIN    the stand-in engine of TestVersions (testdata/badengine)
//	POSTERN_E2E_RELEASE_KEY      the unencrypted throwaway minisign secret key whose public
//	                             half the four binaries trust (release.extraPublicKeys);
//	                             TestVersions signs the update with it
//	POSTERN_E2E_WORKDIR    where the node's directory is made (default: the temporary
//	                       directory); the Docker daemon must see it at the same path
//	POSTERN_E2E_RUN        the id of the run, in the names and labels of containers
//	                       (default: random)
//	POSTERN_E2E_CONTAINER  the name of the container the test runs in, if any: it has
//	                       the label of the run, and the test leaves it alone
//	POSTERN_E2E_LOGS       when set, the logs of the panel and of the node's containers are
//	                       printed at the end also when the test passes (always when it fails)
//	POSTERN_E2E_ONLINE     1 runs the subtests of TestEgressChainFailover that check what a
//	                       client gets through a proxy from a datacenter of Telegram (L2), and
//	                       WARP, for which the node registers a device with Cloudflare that the
//	                       subtest deletes; and makes the held connections of TestVersions L2
//	                       sessions that ask DC2 every 10 s
//	POSTERN_E2E_TELEMT_VERSION, POSTERN_E2E_MTG_VERSION, POSTERN_E2E_XRAY_VERSION
//	                       an upstream release of the component that the tests run instead
//	                       of their own (overrides.go; the job of the stable list sets them);
//	                       with one set, a test that would be skipped fails
//
// Every container and network that the test creates is labelled
// postern.e2e=<run>; the containers that the agent creates carry
// postern.managed=true and mount the node's directory. The test removes them
// all, and the node's directory, when it ends, also when it fails, and also
// on SIGINT or SIGTERM (a CI job that is cancelled, a Ctrl-C): the signal ends
// what the test waits for, and its cleanup runs.
//
// Everything that the test prints goes through the scrubber (scrub.go): the
// secrets of the run never appear, nor the addresses of the machine. And no
// log of the run may hold one either: at its end the test checks the panel's
// stdout and log, and the logs of every container of the node (logs.go).
//
// The files: helpers.go has the run itself and the waiting and probing,
// scrub.go what is printed, logs.go the logs of the run and their check,
// preconditions.go what the run needs before it starts, panel.go the panel
// process and its API, node.go the node's install and its agent, docker.go the
// Docker daemon and the cleanup; egress_test.go has the remote servers, the
// echo server and the checks of the egress chains; web_test.go the test CA,
// Caddy and the checks of the WEB proxies; versions_test.go the changes of
// versions without downtime, with releasehost.go (a GitHub of the run) and
// flood.go (the accept-queue flood); overrides.go the upstream releases that
// the job of the stable list tries.
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/agent"
	"github.com/urbnywrt/postern/internal/probe"
)

const (
	// runnerImage is the image of every node container (Global Constraints),
	// that of the agent in deploy/node/compose.yaml included.
	runnerImage = agent.RunnerImage

	// labelRun marks the containers that the test creates: the agent and its
	// own helpers.
	labelRun = "postern.e2e"

	// linkHost is the host of the links of the node's proxies: a
	// documentation address that nothing dials.
	linkHost = "203.0.113.10"

	// proxyDomain is the fake-TLS domain of the proxy. The name is reserved
	// and resolves to nothing, so the engine's look-ups of it end at once and
	// no connection goes out to a real site.
	proxyDomain = "e2e.example"

	// nodeVersion is the version of the node binary that a node is installed
	// with, and updateVersion that of the panel and of the node binary that
	// TestVersions updates the node to (scripts/e2e.sh and binaries build
	// them so).
	nodeVersion   = "v0.90.0-e2e"
	updateVersion = "v0.90.1-e2e"

	// nodeBinaryName is the name of the node binary in bin/, as install.sh
	// names it: postern-node-<version>.
	nodeBinaryName = "postern-node-" + nodeVersion
)

// env is one run of the test and what it has made, which cleanup removes.
type env struct {
	t     *testing.T
	ctx   context.Context // ends well before the test's deadline: the cleanup needs time too
	start time.Time

	run      string
	repo     string // the root of the repository
	nodeBin  string
	panelBin string
	// What TestVersions needs as well (versionBinaries): the node binary of
	// updateVersion, the stand-in engine, and the secret key whose public
	// half the binaries trust; "" when the run has none of them.
	updateBin, badEngineBin, releaseKey string
	docker                              dockerapi.Client
	raw                                 *rawDocker

	work  string // the node's directory, made by the test; POSTERN_HOME is work/home
	home  string
	agent string // the ID of the agent container
	// agentUpdates says that the agent may restart into a new binary, with
	// exit code 75, while the test waits (checkAgent).
	agentUpdates bool
	panel        *panel
	pastPanels   []*panel  // that ran before panel, in the order they ran (restartPanel)
	logs         *logWatch // the logs of the node's containers, from watchLogs

	sec *secrets // shared with the env of every subtest (sub)
}

// secrets are the values of a run that are never printed, and those that no
// log of the run may hold. A test and its subtests share them.
type secrets struct {
	mu    sync.Mutex
	scrub []string // what never goes into the output: secrets, the token, the password
	leaks []leak   // what no log of the run may hold (mustNotLeak)
}

// sub is the env of a subtest of e's test: the same run, its failures those of
// t. What the subtest notes as secret is noted for the whole run.
func (e *env) sub(t *testing.T) *env {
	s := *e
	s.t = t
	return &s
}

// newEnv checks what the test needs and prepares the run: the compose file of
// the node, Docker, the network namespace, no other node on the daemon,
// GitHub, the runner image, the binaries and the node's directory. The
// cleanup is registered as soon as there is something to clean up.
func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, ctx: runContext(t), start: time.Now(), sec: &secrets{}}
	e.repo = e.repoRoot()
	e.checkOverrides()
	// It reads a file of the repository: no build and no pull before it.
	e.checkComposeFile()
	e.run = os.Getenv("POSTERN_E2E_RUN")
	if e.run == "" {
		e.run = strings.ToLower(rand.Text())[:10]
	}
	if !regexp.MustCompile(`^[a-z0-9]{1,20}$`).MatchString(e.run) {
		e.fatalf("POSTERN_E2E_RUN=%q: the id of a run is 1 to 20 lowercase letters and digits", e.run)
	}

	e.docker = dockerapi.New("")
	e.raw = newRawDocker(dockerapi.DefaultSocket)
	pingCtx, pingCancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer pingCancel()
	if _, err := e.docker.Ping(pingCtx); err != nil {
		e.fatalf("no usable Docker daemon at %s: %v", dockerapi.DefaultSocket, err)
	}
	e.checkNetworkNamespace()
	e.checkNoOtherNode()
	e.checkGitHub()
	e.ensureRunnerImage()
	e.binaries()

	work, err := os.MkdirTemp(os.Getenv("POSTERN_E2E_WORKDIR"), "postern-e2e-node-")
	if err != nil {
		e.fatalf("making the node's directory: %v", err)
	}
	e.work = work
	e.home = filepath.Join(work, "home")
	t.Cleanup(e.cleanup)
	e.checkSharedHost()
	e.logf("run %s: Docker is ready, the node's directory is %s", e.run, e.home)
	return e
}

// runContext is the context of a run. It ends 90 s before the deadline of the
// test, so that the cleanup has time too, and at once on SIGINT or SIGTERM: a
// CI job that is cancelled, or a Ctrl-C, ends what the test waits for, the test
// fails, and its cleanup removes what it made. Until the test is over, the
// signals do not end the process.
func runContext(t *testing.T) context.Context {
	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(20 * time.Minute)
	}
	signalled, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	t.Cleanup(stop) // registered first, so it runs last: after the cleanup of the run
	ctx, cancel := context.WithDeadline(signalled, deadline.Add(-90*time.Second))
	t.Cleanup(cancel)
	return ctx
}

// repoRoot is the directory of go.mod above the working directory.
func (e *env) repoRoot() string {
	e.t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		e.fatalf("the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			e.fatalf("go.mod not found above the working directory: run the test from the repository")
		}
		dir = parent
	}
}

// ---- waiting and probing ------------------------------------------------------

// waitFor calls check every poll until it reports done, and fails the test
// when timeout passes first, when check fails, or when the agent container
// stops. Every new status is logged. The status and the error of check come
// from the panel and the node: they are printed as everything is, scrubbed.
func (e *env) waitFor(what string, timeout, poll time.Duration, check func(ctx context.Context) (done bool, status string, err error)) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
		done, status, err := check(ctx)
		cancel()
		if err != nil {
			e.fatalf("waiting for %s: %v", what, err)
		}
		if status != last {
			e.logf("%s: %s", what, status)
			last = status
		}
		if done {
			return
		}
		e.checkAgent()
		if time.Now().After(deadline) {
			e.fatalf("waiting for %s: not there after %v (last: %s)", what, timeout, last)
		}
		select {
		case <-e.ctx.Done():
			e.fatalf("waiting for %s: %v", what, e.ctx.Err())
		case <-time.After(poll):
		}
	}
}

// probeUntil runs probe.FakeTLS until it succeeds or within has passed. A
// wrong digest ends it at once: the server answered, without the secret.
func probeUntil(ctx context.Context, addr, sni string, secret []byte, within time.Duration) (attempts int, err error) {
	deadline := time.Now().Add(within)
	for {
		attempts++
		left := time.Until(deadline)
		err = probe.FakeTLS(ctx, addr, sni, secret, probe.Options{Timeout: max(min(left, 10*time.Second), time.Second)})
		if err == nil || errors.Is(err, probe.ErrBadServerDigest) || time.Until(deadline) < 500*time.Millisecond {
			return attempts, err
		}
		select {
		case <-ctx.Done():
			return attempts, err
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// refusal says how a server refused a probe whose secret it does not know, as
// probe.FakeTLS reports it in err: with an answer whose digest is not the
// secret's, with a TLS alert, by closing or resetting the connection after the
// ClientHello, or by not answering until the probe gave up. ok is false for
// any other error, and for nil: an error of connecting (nothing listens, say)
// is not a refusal, since the probe never reached a server, and neither is a
// probe that was canceled.
func refusal(err error) (how string, ok bool) {
	var op *net.OpError
	switch {
	case err == nil, errors.Is(err, context.Canceled):
		return "", false
	case errors.As(err, &op) && op.Op == "dial":
		return "", false
	case errors.Is(err, probe.ErrBadServerDigest):
		return "the server's answer does not prove the secret", true
	case strings.Contains(err.Error(), "the server answered with TLS alert"):
		return "the server answered with a TLS alert", true
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "the server closed the connection after the ClientHello", true
	case errors.As(err, &op) && op.Op == "read" && errors.Is(op.Err, syscall.ECONNRESET):
		return "the server reset the connection after the ClientHello", true
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return "the server did not answer before the probe gave up", true
	}
	return "", false
}

// expectRefused fails the test unless the server at addr refuses a probe with
// the secret, in one of the ways of refusal, and returns how it did. what
// names the probe in the message of a failure.
func (e *env) expectRefused(addr, sni string, secret []byte, what string) string {
	e.t.Helper()
	err := probe.FakeTLS(e.ctx, addr, sni, secret, probe.Options{Timeout: 10 * time.Second})
	how, refused := refusal(err)
	switch {
	case err == nil:
		e.fatalf("%s: the server proved the secret", what)
	case !refused:
		e.fatalf("%s: the probe failed, but not because the server refused the secret: %v", what, err)
	}
	return how
}

// switchWatch probes a proxy with two secrets, the old one and then the new
// one, round after round, until end: while the node moves the proxy from one
// generation of its engine to the next, a client gets through with the one or
// the other at any time. The edge moves the route at one moment, for every
// connection that comes after it; so in a round, either the probe with the old
// secret comes before that moment and gets through, or the probe with the new
// one, which comes after it, does. A round in which neither got through is a
// gap in the service. The counts are for after end.
type switchWatch struct {
	stop, done   chan struct{}
	rounds       int
	oldOK, newOK int      // the rounds in which the old, the new secret got through
	gaps         []string // how both probes failed, for each round in which neither got through
}

const (
	// switchProbeTimeout bounds one probe of a switchWatch. A probe that gets
	// through takes milliseconds; one that telemt refuses can take seconds
	// (it looks the fake-TLS domain up first, which resolves to nothing), and
	// would let few rounds run while the node switches.
	switchProbeTimeout = 2 * time.Second
	// switchRoundsAfter is how many rounds run after end was called.
	switchRoundsAfter = 2
)

// watchSwitch starts the probes of a switchWatch: the first round starts at
// once, so its probe with the old secret comes before any change.
func (e *env) watchSwitch(addr, sni string, oldSecret, newSecret []byte) *switchWatch {
	w := &switchWatch{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		after := 0 // the rounds that started after end was called
		for {
			select {
			case <-w.stop:
				if after == switchRoundsAfter {
					return
				}
				after++
			default:
			}
			errOld := probe.FakeTLS(e.ctx, addr, sni, oldSecret, probe.Options{Timeout: switchProbeTimeout})
			errNew := probe.FakeTLS(e.ctx, addr, sni, newSecret, probe.Options{Timeout: switchProbeTimeout})
			if e.ctx.Err() != nil {
				return // the run ends: the probes were cut off
			}
			w.rounds++
			if errOld == nil {
				w.oldOK++
			}
			if errNew == nil {
				w.newOK++
			}
			if errOld != nil && errNew != nil {
				w.gaps = append(w.gaps, fmt.Sprintf("round %d: the old secret: %v; the new one: %v", w.rounds, errOld, errNew))
			}
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()
	return w
}

// end lets switchRoundsAfter more rounds run, which all come after the switch
// when it has happened, and returns when they are over.
func (w *switchWatch) end() {
	close(w.stop)
	<-w.done
}

// expectOpen fails the test unless conn is open: a read with a deadline of
// wait must end with the deadline, not with the end of the stream, a reset or
// data that nobody sent.
func (e *env) expectOpen(conn net.Conn, wait time.Duration, when string) {
	e.t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		e.fatalf("%s: %v", when, err)
	}
	var b [512]byte
	n, err := conn.Read(b[:])
	switch {
	case n > 0:
		e.fatalf("%s: the connection brought %d bytes that nobody asked for", when, n)
	case errors.Is(err, os.ErrDeadlineExceeded):
	case errors.Is(err, io.EOF):
		e.fatalf("%s: the connection was closed (EOF)", when)
	default:
		e.fatalf("%s: the connection failed: %v", when, err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		e.fatalf("%s: %v", when, err)
	}
}

// freePort is a port of [lo, hi] that nothing listens on at host, as far as
// this moment goes. The test runs in the network namespace of the node, so
// that is the node's view as well.
func (e *env) freePort(host string, lo, hi int) int {
	e.t.Helper()
	for range 500 {
		p := lo + mrand.IntN(hi-lo+1)
		l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err != nil {
			continue
		}
		_ = l.Close()
		return p
	}
	e.fatalf("no free port in %d-%d on %s", lo, hi, host)
	return 0
}

// ---- small things -------------------------------------------------------------

func (e *env) writeFile(path string, data []byte, mode os.FileMode) {
	e.t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		e.fatalf("%v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		e.fatalf("%v", err)
	}
}

// untar returns the regular files of a tar archive by name.
func untar(data []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<10))
		if err != nil {
			return nil, err
		}
		files[strings.TrimPrefix(h.Name, "./")] = b
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ---- a fake-TLS proxy that serves ---------------------------------------------

// fakeTLSSetup says how setUpFakeTLS makes its proxy. The zero value makes the
// proxy of TestPanelToNodeFakeTLS.
type fakeTLSSetup struct {
	// panelEnv is more of the panel's environment (NAME=value).
	panelEnv []string
	// linkHost is the link_host_override of the listener, whose links then
	// lead there and not to linkHost; "" for none.
	linkHost string
	// chain, when set, makes the egress chain of the proxy once the node is
	// there, and returns its id.
	chain func(a *api, node *panelv1.Node) string
}

// fakeTLS is what setUpFakeTLS made.
type fakeTLS struct {
	panel     *panel
	api       *api
	node      *panelv1.Node
	listener  *panelv1.Listener
	proxy     *panelv1.Proxy
	port      int    // of the listener, on 127.0.0.1
	addr      string // 127.0.0.1:port
	secretHex string // as the proxy was created with it
	secret    []byte // and the domain, as a client takes them from the tg:// link
	domain    string
}

// setUpFakeTLS runs steps 1 to 3 of TestPanelToNodeFakeTLS:
//
//  1. the panel (with POSTERN_E2E_TELEMT_VERSION, one that gets that release
//     of telemt from the release host of the run, overrides.go), its first
//     admin, signed in;
//  2. the node (newNode);
//  3. a TLS listener on 127.0.0.1 and a fake-TLS proxy on it, with a secret
//     that only the test knows, whose links are checked; the panel downloads
//     telemt and uploads it to the node first, and the proxy serves.
func (e *env) setUpFakeTLS(o fakeTLSSetup) *fakeTLS {
	e.t.Helper()
	// 1. The panel.
	telemtVersion := overrideOf("telemt")
	panelEnv := slices.Clone(o.panelEnv)
	if telemtVersion != "" {
		h := e.newReleaseHost()
		e.addUpstream(h, "telemt", telemtVersion)
		panelEnv = append(panelEnv, "POSTERN_GITHUB_API="+h.base)
	}
	p := e.startPanel(panelEnv...)
	a := newAPI(p.base)
	e.signIn(a, p.token)

	// 2. The node.
	node := e.newNode(a)
	if telemtVersion != "" {
		e.prepareRelease(a, "telemt", telemtVersion)
	}
	chainID := ""
	if o.chain != nil {
		chainID = o.chain(a, node)
	}

	// 3. The listener and the proxy, with a secret that only the test knows.
	lport := e.freePort("127.0.0.1", 10000, 19999)
	lr, err := a.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{
		NodeId: node.GetId(), Kind: "tls", BindIp: "127.0.0.1", Port: uint32(lport), LinkHostOverride: o.linkHost,
	}))
	if err != nil {
		e.fatalf("CreateListener: %v", err)
	}
	secretHex := hex.EncodeToString(randomBytes(16))
	e.mustNotLeak("the secret of the proxy", secretHex)
	pr, err := a.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: node.GetId(), ListenerId: lr.Msg.GetListener().GetId(), Name: "e2e", Domain: proxyDomain, Secret: secretHex,
		EngineVersion: telemtVersion, // "": the version of the channel
		EgressChainId: chainID,
	}))
	if err != nil {
		e.fatalf("CreateProxy: %v", err)
	}
	proxy := pr.Msg.GetProxy()
	e.logf("listener 127.0.0.1:%d and proxy %s (%s, telemt %s) created", lport, proxy.GetId(), proxy.GetDomain(), proxy.GetEngineVersion())

	// The link is what a client gets: it has to lead to the listener with the
	// secret and the domain of the proxy.
	host := linkHost
	if o.linkHost != "" {
		host = o.linkHost
	}
	secret, domain := e.checkLinksAt(a, proxy.GetId(), host, lport, secretHex, proxyDomain)

	// The panel downloads telemt and uploads it to the node first.
	e.waitServing(a, proxy.GetId(), 8*time.Minute)
	if got := e.proxyOf(a, proxy.GetId()).GetStatus().GetRunningVersion(); telemtVersion != "" && got != telemtVersion {
		e.fatalf("the proxy runs telemt %s, want %s (POSTERN_E2E_TELEMT_VERSION)", got, telemtVersion)
	}
	return &fakeTLS{
		panel: p, api: a, node: node, listener: lr.Msg.GetListener(), proxy: proxy,
		port: lport, addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(lport)),
		secretHex: secretHex, secret: secret, domain: domain,
	}
}
