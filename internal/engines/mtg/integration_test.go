//go:build integration

package mtg

// TestIntegrationMTG runs the real mtg v2.2.8 release in the runner image, the
// way the node agent will, with the config this driver renders, and talks to it
// from the test process:
//
//	go test -tags integration ./internal/engines/mtg/                  a Linux Docker engine
//	bash scripts/wsl 'bash scripts/itest.sh ./internal/engines/mtg'    Docker Desktop
//
// Driver.Ready, the L1 probe probe.FakeTLS and the SOCKS5 server that stands in
// for the edge's SOCKS port (a socks5.Server that records what mtg asks it for)
// all run in this process and reach mtg at 127.0.0.1, and the engine container
// mounts the binary and its config from the test's scratch directory. So the
// test has to run in the network namespace of the Docker daemon's host network,
// and see its scratch directory at the path the daemon sees: on a Linux Docker
// host that is the host itself; Docker Desktop's host network is the network of
// its VM, which only a container reaches, and scripts/itest.sh runs the test
// binary in one. checkSharedHost fails the test at once anywhere else.
//
// It needs network access: the runner image is pulled when it is missing, and
// the release archive for runtime.GOARCH comes from GitHub (the test is skipped
// when GitHub cannot be reached; a download that does not match the pinned
// checksum fails it) and goes through artifacts.Store.Put.
//
// What it checks:
//
//  1. Ready succeeds within 30 s.
//  2. probe.FakeTLS, with a PROXY v2 header from 127.0.0.1:1 and the right
//     secret, succeeds.
//  3. With a wrong secret it fails, and mtg counts the connection as fronted.
//     The fronting connection goes where the config says, to the fronting
//     address 192.0.2.1:443 (the proxy's mask override), straight from mtg's
//     process: a socket of the process connected to it, seen in /proc/net/tcp
//     while the probe runs (or, where the network refuses the address at
//     once, mtg's own report that it could not reach it). The SOCKS port sees
//     nothing of it: mtg v2.2.8 makes its fronting connection directly, not
//     through its [network] proxies (see the package documentation, Ruling
//     S5-10).
//  4. A client that goes on to Telegram (the fake-TLS handshake with the right
//     secret, then the obfuscated2 handshake for DC 1) makes mtg call Telegram
//     through the SOCKS port: the recorder sees a CONNECT to 149.154.175.50:443,
//     the first address of DC 1 that mtg knows, and answers it "host
//     unreachable".
//  5. The container listens on exactly its two loopback ports.
//  6. Its log holds the secret in no form.
//  7. The trial of Driver.Trial passes, in a container made like the node's
//     trial containers (Global Constraints, Trial runs).
//
// TestIntegrationMTGOnlineL2 runs only with POSTERN_E2E_ONLINE=1: the slice-2
// L2 probe (probe.L2) through a real mtg to Telegram's DC 2, with an
// in-process SOCKS5 server as the edge's SOCKS port that dials out directly,
// the way the reconciler's gate checks a new generation's way out.
//
// Every container is named postern-test-<run>-<tag> and labelled
// postern.test=mtg-driver, postern.id=itest-<run> for a random <run>, has the
// restart policy "no" instead of unless-stopped (so that a killed test run
// cannot leave an engine behind that the daemon keeps restarting), is
// force-removed when its test ends, and is only touched by ID. Containers
// with the label postern.test=mtg-driver that a killed run left behind are
// removed when the test starts and when it ends.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/probe"
	"github.com/urbnywrt/postern/internal/socks5"
)

const (
	itestBaseURL = "https://github.com/9seconds/mtg/releases/download/" + DefaultVersion + "/"
	itestDomain  = "www.example.com"
	// itestMask is the fronting target of the test proxy: an address of
	// TEST-NET-1, where nothing answers.
	itestMask = "192.0.2.1"
	// itestDC is the DC the Telegram client of step 4 asks for, and
	// itestDCAddr the first address mtg v2.2.8 knows for it
	// (essentials.TelegramCoreAddresses; IPv4 first with prefer-ipv4).
	itestDC     = 1
	itestDCAddr = "149.154.175.50"
)

// itestSums are the checksums of the release archives, pinned in the plan's
// Global Constraints, by architecture.
var itestSums = map[string]string{
	"amd64": "7ef19d079d85f4e00d4f8334ec1f3f3c8718e3d0ed1f3109ea9a8673138a2102",
	"arm64": "562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644",
}

type itestEnv struct {
	docker dockerapi.Client
	run    string // random id of this run
	base   string // scratch directory of this run
	store  *artifacts.Store
	ref    artifacts.Ref
}

func itestLabels(run string) map[string]string {
	return map[string]string{"postern.test": "mtg-driver", "postern.id": "itest-" + run}
}

func TestIntegrationMTG(t *testing.T) {
	e := newITestEnv(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	drv := New()

	secret := randomBytes(t, 16)
	wrong := bytes.Clone(secret)
	wrong[0] ^= 0xff
	rec := startRecorder(t)
	in := e.instance(t, hex.EncodeToString(secret), rec.port)
	id := e.startEngine(t, ctx, in)
	forms := secretForms(in.Proxy, wrong)
	fatal := func(format string, args ...any) {
		t.Helper()
		t.Fatalf(format+"\nmtg log:\n%s", append(args, e.scrubbedLog(t, id, forms))...)
	}
	addr := loopback(in.ListenPort)
	src := netip.MustParseAddrPort("127.0.0.1:1") // the source the reconciler's probe uses

	// 1. Ready within 30 s.
	start := time.Now()
	if err := e.waitReady(ctx, drv, in, id, 30*time.Second); err != nil {
		fatal("%v", err)
	}
	t.Logf("ready after %v", time.Since(start).Round(time.Millisecond))

	// 2. The right secret.
	if err := probe.FakeTLS(ctx, addr, itestDomain, secret, probe.Options{ProxyHeader: &src, Timeout: 10 * time.Second}); err != nil {
		fatal("probe.FakeTLS with the right secret: %v", err)
	}

	// 3. A wrong secret. mtg takes the connection for one that is not a client's
	// and passes it to its fronting address, 192.0.2.1:443, where nothing
	// answers: the probe ends without an answer. The connection goes there from
	// mtg's own process; the SOCKS port does not see it.
	before, err := frontings(ctx, in.APIPort)
	if err != nil {
		fatal("reading mtg's statistics: %v", err)
	}
	stopWatch := e.watchSockets(t, ctx, id)
	err = probe.FakeTLS(ctx, addr, itestDomain, wrong, probe.Options{ProxyHeader: &src, Timeout: 5 * time.Second})
	seen := stopWatch()
	if err == nil {
		fatal("probe.FakeTLS with a wrong secret succeeded")
	}
	t.Logf("wrong secret: %v", err)
	e.checkFronting(t, id, in.FrontingAddr, seen, forms)
	after := before
	for deadline := time.Now().Add(5 * time.Second); after <= before && time.Now().Before(deadline); {
		time.Sleep(100 * time.Millisecond)
		if after, err = frontings(ctx, in.APIPort); err != nil {
			fatal("reading mtg's statistics: %v", err)
		}
	}
	if after <= before {
		t.Errorf("mtg did not count the wrong secret's connection as fronted (mtg_domain_fronting %v, then %v)", before, after)
	}
	if got := rec.requests(); len(got) != 0 {
		t.Errorf("the SOCKS port was asked for %v before any client went on to Telegram", got)
	} else {
		t.Logf("fronted (mtg_domain_fronting %v -> %v) without a word to the SOCKS port: mtg v2.2.8 makes its fronting connection directly", before, after)
	}

	// 4. A client that goes on to Telegram: mtg calls DC 1 through the SOCKS port.
	err = telegramCall(ctx, addr, src, secret, itestDC, func() {
		for deadline := time.Now().Add(10 * time.Second); len(rec.requests()) == 0 && time.Now().Before(deadline); {
			time.Sleep(50 * time.Millisecond)
		}
	})
	if err != nil {
		fatal("the Telegram client: %v", err)
	}
	reqs := rec.requests()
	switch {
	case len(reqs) == 0:
		fatal("mtg did not call Telegram through the SOCKS port")
	case reqs[0].Host != itestDCAddr || reqs[0].Port != 443:
		t.Errorf("mtg asked the SOCKS port first for %s, want %s (DC %d)", net.JoinHostPort(reqs[0].Host, strconv.Itoa(int(reqs[0].Port))), net.JoinHostPort(itestDCAddr, "443"), itestDC)
	case reqs[0].Username != "":
		t.Errorf("mtg sent the user name %q to the SOCKS port, want none", reqs[0].Username)
	default:
		t.Logf("mtg called DC %d through the SOCKS port: CONNECT %s:%d, answered \"host unreachable\" (%d requests in all)", itestDC, reqs[0].Host, reqs[0].Port, len(reqs))
	}
	if err := e.stillRunning(ctx, id); err != nil {
		fatal("%v", err)
	}

	// 5. The instance listens on its two loopback ports and nothing else.
	got := e.listeners(t, ctx, id)
	want := []string{loopback(in.ListenPort), loopback(in.APIPort)}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("mtg listens on %v, want exactly %v", got, want)
	}

	// 6. Nothing in the log gives a secret away (the log is printed only when it
	// holds none).
	t.Logf("mtg log:\n%s", e.scrubbedLog(t, id, forms))

	// 7. The trial passes.
	tr := drv.Trial(DefaultVersion)
	spec := dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534",
		NetworkMode: "none",
		Entrypoint:  append([]string{binaryMount}, tr.Args...),
		Binds:       []string{in.BinaryPath + ":" + binaryMount + ":ro"},
		MemoryBytes: 64 << 20,
		PidsLimit:   16,
		LogMaxSize:  "1m",
		LogMaxFile:  1,
	}
	exit, out := e.runHelper(t, ctx, "trial", "trial", spec, 30*time.Second)
	if len(out) > 4096 {
		out = out[:4096]
	}
	if exit != tr.ExitCode || !tr.Output.MatchString(out) {
		t.Errorf("the trial failed: mtg %s exited %d (want %d) and printed %q (want a match of %s)", strings.Join(tr.Args, " "), exit, tr.ExitCode, out, tr.Output)
	} else {
		t.Logf("trial: mtg %s exited %d: %s", strings.Join(tr.Args, " "), exit, strings.TrimSpace(out))
	}
}

// TestIntegrationMTGOnlineL2: a client's L2 session through mtg reaches DC 2.
// mtg goes out through its one proxy, the SOCKS server of this test, which
// dials Telegram directly; the probe gets DC 2's answer to its ping back
// through mtg, which proves the whole way: the fake-TLS handshake, the
// obfuscated2 handshake, and mtg's connection through the SOCKS port.
func TestIntegrationMTGOnlineL2(t *testing.T) {
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Skip("reaches Telegram's datacenters: set POSTERN_E2E_ONLINE=1 to run it")
	}
	e := newITestEnv(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	secret := randomBytes(t, 16)
	out := startDialer(t)
	in := e.instance(t, hex.EncodeToString(secret), out.port)
	id := e.startEngine(t, ctx, in)
	forms := secretForms(in.Proxy, secret)
	if err := e.waitReady(ctx, drvOf(t), in, id, 30*time.Second); err != nil {
		t.Fatalf("%v\nmtg log:\n%s", err, e.scrubbedLog(t, id, forms))
	}
	src := netip.MustParseAddrPort("127.0.0.1:1")
	const dc = 2
	start := time.Now()
	if err := probe.L2(ctx, loopback(in.ListenPort), itestDomain, secret, dc, probe.Options{ProxyHeader: &src, Timeout: 20 * time.Second}); err != nil {
		t.Fatalf("probe.L2 to DC %d through mtg: %v (the SOCKS port was asked for %v)\nmtg log:\n%s", dc, err, out.requests(), e.scrubbedLog(t, id, forms))
	}
	reqs := out.requests()
	if len(reqs) == 0 {
		t.Fatal("the L2 probe succeeded, but mtg asked the SOCKS port for nothing")
	}
	t.Logf("L2 to DC %d through mtg in %v; mtg asked the SOCKS port for %s:%d (%d requests)", dc, time.Since(start).Round(time.Millisecond), reqs[0].Host, reqs[0].Port, len(reqs))
	if err := e.stillRunning(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Logf("mtg log:\n%s", e.scrubbedLog(t, id, forms))
}

func drvOf(t *testing.T) *Driver {
	t.Helper()
	return New()
}

// socksDialer is a socks5.Server on a loopback port of the edge's SOCKS range
// that notes every request and dials it out directly, as the edge's SOCKS
// port does for a direct egress.
type socksDialer struct {
	port uint16
	mu   sync.Mutex
	reqs []socks5.Request
}

func startDialer(t *testing.T) *socksDialer {
	t.Helper()
	d := &socksDialer{}
	ln := listenIn(t, 30000, 35000)
	t.Cleanup(func() { _ = ln.Close() })
	d.port = portOf(t, ln.Addr().String())
	srv := &socks5.Server{Dial: d.dial, Logger: slog.New(slog.DiscardHandler)}
	go func() { _ = srv.Serve(ln) }()
	return d
}

func (d *socksDialer) dial(ctx context.Context, req socks5.Request) (net.Conn, error) {
	d.mu.Lock()
	d.reqs = append(d.reqs, req)
	d.mu.Unlock()
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))))
}

func (d *socksDialer) requests() []socks5.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.reqs)
}

// ---- setup --------------------------------------------------------------------

func newITestEnv(t *testing.T) *itestEnv {
	t.Helper()
	sum, ok := itestSums[runtime.GOARCH]
	if !ok {
		t.Skipf("no mtg release is pinned for %s", runtime.GOARCH)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	docker := dockerapi.New("")
	pingCtx, pingCancel := context.WithTimeout(ctx, 15*time.Second)
	defer pingCancel()
	if _, err := docker.Ping(pingCtx); err != nil {
		t.Fatalf("no usable Docker daemon at %s: %v", dockerapi.DefaultSocket, err)
	}
	// What a killed run left behind goes first; and this cleanup, the first
	// one, runs last.
	sweep(t, docker, "left by an earlier run")
	t.Cleanup(func() { sweep(t, docker, "left by this run") })
	if ok, err := docker.ImageExists(ctx, runnerImage); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := docker.Pull(ctx, runnerImage); err != nil {
			t.Fatal(err)
		}
	}

	base, err := os.MkdirTemp("", "postern-itest-mtg-")
	if err != nil {
		t.Fatal(err)
	}
	e := &itestEnv{
		docker: docker,
		run:    strings.ToLower(rand.Text())[:10],
		base:   base,
		store:  &artifacts.Store{Root: filepath.Join(base, "artifacts")},
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Logf("could not remove %s: %v", base, err)
		}
	})
	e.checkSharedHost(t, ctx)

	// The release: download, verify against the pinned checksum, store.
	file, err := New().ArtifactFile(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	e.ref = artifacts.Ref{
		Engine: "mtg", Version: DefaultVersion, Arch: runtime.GOARCH,
		SHA256: sum, FileName: file, Binary: New().BinaryName(),
	}
	e.download(t, ctx)
	if !e.store.Has(e.ref) {
		t.Fatal("the store does not have the artifact it has just stored")
	}
	if info, err := os.Stat(e.store.BinaryPath(e.ref)); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("stored binary: %v, %v", info, err)
	}
	return e
}

// checkSharedHost makes sure that a container on the host network reaches this
// process at 127.0.0.1 and sees the scratch directory at the path this process
// sees: Ready, the probes and the SOCKS recorder talk to mtg on 127.0.0.1, and
// mtg's container mounts its binary and config from the scratch directory. It
// fails at once where they would not, instead of with an engine that never
// becomes ready.
func (e *itestEnv) checkSharedHost(t *testing.T, ctx context.Context) {
	t.Helper()
	want := rand.Text()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, want) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	out := filepath.Join(e.base, "shared-host-check")
	exit, output := e.runHelper(t, ctx, "check", "", dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		NetworkMode: "host",
		Binds:       []string{e.base + ":" + e.base},
		Entrypoint:  []string{"wget", "-q", "-T", "10", "-O", out, "http://" + ln.Addr().String() + "/"},
	}, time.Minute)
	got, err := os.ReadFile(out)
	if exit != 0 || err != nil || string(got) != want {
		t.Fatalf("a container on the host network does not reach this process at 127.0.0.1, or does not see %s at that path "+
			"(wget exit %d: %s; %v). The test talks to mtg from this process: run it where the Docker daemon's host network is, "+
			"directly on a Linux Docker host, or on Docker Desktop with scripts/itest.sh.", e.base, exit, strings.TrimSpace(output), err)
	}
	_ = os.Remove(out)
}

// download fetches the release archive into the store. Network trouble skips
// the test; a checksum that does not match fails it, and so does any failure of
// the store, which is this machine's.
func (e *itestEnv) download(t *testing.T, ctx context.Context) {
	t.Helper()
	url := itestBaseURL + e.ref.FileName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
	if err != nil {
		t.Skipf("cannot download %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	// The whole download first (archives are at most 200 MiB): what breaks off
	// here is the network's.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
	if err != nil {
		t.Skipf("the download of %s did not complete: %v", url, err)
	}
	switch err := e.store.Put(e.ref, bytes.NewReader(body)); {
	case errors.Is(err, artifacts.ErrChecksum):
		t.Fatalf("the download does not match the pinned checksum: %v", err)
	case err != nil:
		t.Fatalf("storing the release: %v", err)
	}
}

// sweep removes the containers of this test, of any run (label
// postern.test=mtg-driver). A run that was killed leaves its containers
// behind, an engine among them.
func sweep(t *testing.T, docker dockerapi.Client, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	list, err := docker.List(ctx, map[string]string{"postern.test": "mtg-driver"}, true)
	if err != nil {
		t.Errorf("listing the containers of the test: %v", err)
		return
	}
	for _, c := range list {
		if err := docker.Remove(ctx, c.ID, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			t.Errorf("removing container %s (%s): %v", c.Name, c.ID[:12], err)
			continue
		}
		t.Logf("removed container %s, %s", c.Name, what)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// pickPort returns a random port of [lo, hi) that is free on the loopback.
func pickPort(t *testing.T, lo, hi int) uint16 {
	t.Helper()
	ln := listenIn(t, lo, hi)
	port := portOf(t, ln.Addr().String())
	_ = ln.Close()
	return port
}

// listenIn listens on a random free loopback port of [lo, hi).
func listenIn(t *testing.T, lo, hi int) net.Listener {
	t.Helper()
	for range 200 {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(lo+mrand.IntN(hi-lo))))
		if err == nil {
			return ln
		}
	}
	t.Fatalf("no free port in %d-%d", lo, hi)
	return nil
}

// ---- the instance -------------------------------------------------------------

// instance renders the config of a fake-TLS proxy with the secret, its mask
// override 192.0.2.1 and the fronting address the agent passes for it
// (192.0.2.1:443), and the SOCKS port of the recorder; writes it into an
// instance directory of its own; and returns the instance.
func (e *itestEnv) instance(t *testing.T, secretHex string, socksPort uint16) engines.Instance {
	t.Helper()
	front, err := ParseMaskTarget(itestMask)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &nodev1.Proxy{
		Id:                 strings.ToUpper("itest" + e.run),
		Type:               nodev1.ProxyType_PROXY_TYPE_FAKETLS,
		Enabled:            true,
		Secret:             secretHex,
		Domain:             itestDomain,
		Engine:             nodev1.Engine_ENGINE_MTG,
		EngineVersion:      DefaultVersion,
		MaskTargetOverride: itestMask,
	}
	dir, err := os.MkdirTemp(e.base, "instance-")
	if err != nil {
		t.Fatal(err)
	}
	// The reconciler makes the directory and the config readable for the
	// engine's group; this test cannot hand them to another owner and opens
	// them up instead.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	in := engines.Instance{
		Proxy:        proxy,
		InstanceID:   proxy.Id + "-g1",
		Generation:   1,
		ListenPort:   pickPort(t, 20000, 25000),
		APIPort:      pickPort(t, 25000, 30000),
		SocksPort:    socksPort,
		APIToken:     strings.ToLower(rand.Text()),
		InstanceDir:  dir,
		BinaryPath:   e.store.BinaryPath(e.ref),
		RunnerImage:  runnerImage,
		FrontingAddr: front,
	}
	files, err := New().Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Docker would create a missing bind source as an empty directory and start
	// the container anyway: make sure both are really there first.
	if err := in.CheckHostPaths(); err != nil {
		t.Fatal(err)
	}
	return in
}

// startEngine creates and starts the container of Driver.Container for the
// instance, with this run's name, labels and restart policy, and returns its ID.
func (e *itestEnv) startEngine(t *testing.T, ctx context.Context, in engines.Instance) string {
	t.Helper()
	spec := New().Container(in)
	spec.Name = "postern-test-" + e.run + "-mtg"
	spec.RestartPolicy = "no"
	spec.Labels = itestLabels(e.run)
	spec.Labels["postern.role"] = "engine"
	spec.Labels["postern.generation"] = "1"
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { e.removeContainer(t, id, spec.Name) })
	if err := e.docker.Start(ctx, id); err != nil {
		t.Fatalf("start: %v", err)
	}
	return id
}

// waitReady polls Driver.Ready until it succeeds, the engine container stops,
// or the time is up.
func (e *itestEnv) waitReady(ctx context.Context, drv *Driver, in engines.Instance, id string, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		last := drv.Ready(ctx, in)
		if last == nil {
			return nil
		}
		if err := e.stillRunning(ctx, id); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Ready did not succeed within %v: %w", limit, last)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (e *itestEnv) stillRunning(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	d, err := e.docker.Inspect(ctx, id)
	if err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
	if d.State != "running" {
		return fmt.Errorf("the engine container is %s (exit code %d)", d.State, d.ExitCode)
	}
	return nil
}

// ---- the edge's SOCKS port, as far as mtg can tell ----------------------------

// socksRecorder is a socks5.Server on a loopback port of the edge's SOCKS range
// that notes every request and answers it "host unreachable".
type socksRecorder struct {
	port uint16
	mu   sync.Mutex
	reqs []socks5.Request
}

func startRecorder(t *testing.T) *socksRecorder {
	t.Helper()
	r := &socksRecorder{}
	ln := listenIn(t, 30000, 35000)
	t.Cleanup(func() { _ = ln.Close() })
	r.port = portOf(t, ln.Addr().String())
	srv := &socks5.Server{Dial: r.dial, Logger: slog.New(slog.DiscardHandler)}
	go func() { _ = srv.Serve(ln) }()
	return r
}

func (r *socksRecorder) dial(_ context.Context, req socks5.Request) (net.Conn, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	return nil, fmt.Errorf("recorder: %w", syscall.EHOSTUNREACH) // reply 0x04, host unreachable
}

func (r *socksRecorder) requests() []socks5.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.reqs)
}

// ---- clients ------------------------------------------------------------------

// frontings reads mtg's count of the connections it passed to its fronting
// target, mtg_domain_fronting, from its statistics.
func frontings(ctx context.Context, apiPort uint16) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+loopback(apiPort)+"/", nil)
	if err != nil {
		return 0, err
	}
	resp, err := statsClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxReadyBody))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && (f[0] == "mtg_domain_fronting" || f[0] == "mtg_domain_fronting_total") {
			return strconv.ParseFloat(f[1], 64)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("no mtg_domain_fronting in the statistics")
}

// telegramCall is a client of the proxy that goes on to Telegram: the fake-TLS
// handshake (with the PROXY header from src), then the obfuscated2 handshake for
// DC dc in an application data record, after a ChangeCipherSpec, as Telegram's
// clients send them. It holds the connection open until wait returns.
func telegramCall(ctx context.Context, addr string, src netip.AddrPort, secret []byte, dc int, wait func()) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := probe.Handshake(conn, itestDomain, secret, probe.Options{ProxyHeader: &src, Timeout: 10 * time.Second}); err != nil {
		return fmt.Errorf("the fake-TLS handshake: %w", err)
	}
	frame, err := obfuscated2Frame(secret, dc)
	if err != nil {
		return err
	}
	msg := []byte{0x14, 3, 3, 0, 1, 1, 0x17, 3, 3, 0, byte(len(frame))}
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(append(msg, frame...)); err != nil {
		return fmt.Errorf("sending the obfuscated2 handshake: %w", err)
	}
	wait()
	return nil
}

// obfuscated2Frame makes the 64-byte obfuscated2 handshake of a client for DC
// dc over the padded intermediate transport (0xdddddddd, the one mtg takes),
// keyed with the proxy secret: random bytes that do not look like another
// transport, the transport tag and the DC in bytes 56 to 61, all of it
// encrypted with AES-256-CTR under SHA-256(bytes 8 to 39 || secret) and IV
// bytes 40 to 55, and then bytes 8 to 55, the key material, put back in the
// clear (https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation;
// mtg's obfuscation.Obfuscator.SendHandshake does the same towards Telegram).
func obfuscated2Frame(secret []byte, dc int) ([]byte, error) {
	f := make([]byte, 64)
	for {
		if _, err := rand.Read(f); err != nil {
			return nil, err
		}
		if f[0] == 0xef { // abridged
			continue
		}
		switch binary.LittleEndian.Uint32(f[:4]) {
		case 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0x02010316, 0xdddddddd, 0xeeeeeeee: // HEAD, POST, GET, OPTI, TLS, the intermediate tags
			continue
		}
		if f[4]|f[5]|f[6]|f[7] == 0 {
			continue
		}
		break
	}
	copy(f[56:60], []byte{0xdd, 0xdd, 0xdd, 0xdd})
	binary.LittleEndian.PutUint16(f[60:62], uint16(dc))

	h := sha256.New()
	h.Write(f[8:40])
	h.Write(secret)
	block, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	enc := make([]byte, 64)
	cipher.NewCTR(block, f[40:56]).XORKeyStream(enc, f)
	copy(enc[8:56], f[8:56])
	return enc, nil
}

// ---- the secret in the log ----------------------------------------------------

// secretFormsOf is a secret in every form in which mtg could print it.
type secretFormsOf struct {
	hex    []string // compared without regard to case
	base64 []string
}

// secretForms lists the forms of the proxy's secret, and of the wrong one, in
// which they could end up in a log: the hex of the secret and of the whole "ee"
// secret, and the base64 encodings of the "ee" secret, which is how mtg prints
// a secret (mtglib.Secret.String).
func secretForms(p *nodev1.Proxy, wrong []byte) secretFormsOf {
	var f secretFormsOf
	ee := links.FakeTLSSecret(p.GetSecret(), p.GetDomain())
	f.hex = []string{p.GetSecret(), hex.EncodeToString(wrong), ee}
	raw, _ := hex.DecodeString(ee)
	key, _ := hex.DecodeString(p.GetSecret())
	for _, b := range [][]byte{raw, key, wrong} {
		for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
			f.base64 = append(f.base64, strings.TrimRight(enc.EncodeToString(b), "="))
		}
	}
	return f
}

// scrubbedLog returns the engine's log, or says that it holds a secret without
// printing it: a log that gives one away must not end up in the test output
// either.
func (e *itestEnv) scrubbedLog(t *testing.T, id string, forms secretFormsOf) string {
	t.Helper()
	log := e.logs(t, id)
	low := strings.ToLower(log)
	for _, s := range forms.hex {
		if strings.Contains(low, strings.ToLower(s)) {
			t.Errorf("the mtg log contains a secret in hex; log withheld")
			return "(withheld)"
		}
	}
	for _, s := range forms.base64 {
		if strings.Contains(log, s) {
			t.Errorf("the mtg log contains a secret in base64; log withheld")
			return "(withheld)"
		}
	}
	if strings.Contains(log, "tg://") {
		t.Errorf("the mtg log contains a tg:// link, which carries the secret; log withheld")
		return "(withheld)"
	}
	if log = strings.TrimSpace(log); log == "" {
		return "(empty)"
	}
	return log
}

// ---- the listening sockets ----------------------------------------------------

// listeners returns the TCP sockets the main process of the container listens
// on, as sorted "ip:port" strings, read from a container that shares its
// process namespace (where it is PID 1) and the host network.
func (e *itestEnv) listeners(t *testing.T, ctx context.Context, id string) []string {
	t.Helper()
	const script = `
inodes=$(ls -l /proc/1/fd 2>/dev/null | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p' | sort -u | tr '\n' ' ')
[ -n "$inodes" ] || { echo "no sockets found for process 1" >&2; exit 3; }
for f in /proc/net/tcp /proc/net/tcp6; do
  awk -v want="$inodes" 'BEGIN { n = split(want, a, " "); for (i = 1; i <= n; i++) w[a[i]] = 1 }
    NR > 1 && $4 == "0A" && ($10 in w) { print FILENAME, $2 }' "$f"
done
`
	exit, out := e.runHelper(t, ctx, "sockets", "", dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534", // the engine's own user: the sockets of a process are for its owner
		NetworkMode: "host",
		PidMode:     "container:" + id,
		Entrypoint:  []string{"/bin/sh", "-c", script},
	}, 30*time.Second)
	if exit != 0 {
		t.Fatalf("reading the listening sockets failed (exit %d): %s", exit, strings.TrimSpace(out))
	}
	var got []string
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		file, addr, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("unexpected line %q", line)
		}
		ap, err := parseProcAddr(addr)
		if err != nil {
			t.Fatalf("%s: %q: %v", file, addr, err)
		}
		got = append(got, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String())
	}
	slices.Sort(got)
	return got
}

// ---- where the fronting connection goes ---------------------------------------

// procSocket is a socket of mtg's process that is not listening, as the
// watcher saw it.
type procSocket struct {
	remote netip.AddrPort // IPv4 in the form of IPv6 as IPv4
	state  string         // the name of its TCP state
}

func (s procSocket) String() string { return s.remote.String() + " " + s.state }

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0B": "CLOSING",
}

// watchSockets starts a helper that looks at the sockets of mtg's process
// every 20 ms, and notes those that are not listening, with the same inode
// mapping as listeners: the helper shares the engine container's process
// namespace (mtg is PID 1 there) and the host network. The function it returns
// stops the helper and returns what it saw, each socket once.
//
// A socket that exists for a moment is caught only by looking all the time:
// mtg holds its fronting connection as long as the client's, and a connection
// to an address where nothing answers is a SYN_SENT socket until mtg's dial
// timeout (5 s); but a network that refuses the address at once takes it away
// within milliseconds. checkFronting allows for that.
func (e *itestEnv) watchSockets(t *testing.T, ctx context.Context, engineID string) func() []procSocket {
	t.Helper()
	const script = `
seen=/tmp/seen
: > $seen
report() { sort -u $seen; exit 0; }
trap report TERM INT
echo watching >&2
while :; do
  inodes=$(ls -l /proc/1/fd 2>/dev/null | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p' | tr '\n' ' ')
  if [ -n "$inodes" ]; then
    awk -v want="$inodes" 'BEGIN { n = split(want, a, " "); for (i = 1; i <= n; i++) w[a[i]] = 1 }
      FNR > 1 && $4 != "0A" && ($10 in w) { print FILENAME, $3, $4 }' /proc/net/tcp /proc/net/tcp6 >> $seen
  fi
  sleep 0.02
done
`
	id := e.startHelper(t, ctx, "watch", "", dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534", // the engine's own user: the sockets of a process are for its owner
		NetworkMode: "host",
		PidMode:     "container:" + engineID,
		Entrypoint:  []string{"/bin/sh", "-c", script},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=8m"},
	})
	for deadline := time.Now().Add(15 * time.Second); !strings.Contains(e.logs(t, id), "watching"); {
		if time.Now().After(deadline) {
			t.Fatalf("the socket watcher did not start:\n%s", e.logs(t, id))
		}
		time.Sleep(50 * time.Millisecond)
	}
	return func() []procSocket {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := e.docker.Stop(ctx, id, 10*time.Second); err != nil {
			t.Fatalf("stop the socket watcher: %v", err)
		}
		var seen []procSocket
		for line := range strings.SplitSeq(e.logs(t, id), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || line == "watching" {
				continue
			}
			if len(f) != 3 || !strings.HasPrefix(f[0], "/proc/net/tcp") {
				t.Fatalf("the socket watcher wrote %q", line)
			}
			remote, err := parseProcAddr(f[1])
			if err != nil {
				t.Fatalf("the socket watcher wrote %q: %v", line, err)
			}
			state, ok := tcpStates[strings.ToUpper(f[2])]
			if !ok {
				state = "state " + f[2]
			}
			seen = append(seen, procSocket{netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()), state})
		}
		return seen
	}
}

// checkFronting fails the test unless mtg's process connected to its fronting
// address front, which the watcher shows as a socket of the process with that
// remote address, in whatever state; or, where the network refuses the
// address before the watcher could look, which mtg reports in its log as a
// dial to that address that failed. A socket to anywhere else outside the
// loopback fails it too: the fronting address is the only place mtg goes to
// on its own.
func (e *itestEnv) checkFronting(t *testing.T, id string, front netip.AddrPort, seen []procSocket, forms secretFormsOf) {
	t.Helper()
	var states []string
	for _, s := range seen {
		switch {
		case s.remote == front:
			states = append(states, s.state)
		case s.remote.Addr().IsLoopback() || s.remote.Addr().IsUnspecified():
			// The probes' connections, and sockets on their way in or out.
		default:
			t.Errorf("mtg's process connected to %s (%s), which is neither on the loopback nor its fronting address %s", s.remote, s.state, front)
		}
	}
	if len(states) > 0 {
		slices.Sort(states)
		t.Logf("mtg connected to its fronting address %s from its own process (%s), not through the SOCKS port", front, strings.Join(slices.Compact(states), ", "))
		return
	}
	log := e.scrubbedLog(t, id, forms)
	if strings.Contains(log, "cannot dial to the fronting domain") && strings.Contains(log, front.String()) {
		t.Logf("the network refused mtg's fronting address %s at once, as mtg's log says; the socket was gone before the watcher looked", front)
		return
	}
	t.Errorf("no socket of mtg's process was connected to its fronting address %s while the probe ran, and mtg reports no failed dial to it; the sockets seen: %v\nmtg log:\n%s", front, seen, log)
}

// parseProcAddr reads an address of /proc/net/tcp or tcp6, "<hex ip>:<hex
// port>", where the address is written as 32-bit words in host (little endian)
// byte order.
func parseProcAddr(s string) (netip.AddrPort, error) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("no colon")
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", ipHex)
	}
	for w := 0; w < len(raw); w += 4 {
		slices.Reverse(raw[w : w+4])
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// ---- containers ---------------------------------------------------------------

// startHelper creates and starts a helper container and returns its ID. The
// container is named for this run and labelled for it (role, when not empty,
// as postern.role), never restarted, without capabilities or new privileges,
// on a read-only root file system, and removed when the test ends.
func (e *itestEnv) startHelper(t *testing.T, ctx context.Context, tag, role string, spec dockerapi.ContainerSpec) string {
	t.Helper()
	spec.Name = "postern-test-" + e.run + "-" + tag + "-" + strings.ToLower(rand.Text())[:6]
	spec.Labels = itestLabels(e.run)
	if role != "" {
		spec.Labels["postern.role"] = role
	}
	spec.RestartPolicy = "no"
	spec.CapDrop = []string{"ALL"}
	spec.SecurityOpt = []string{"no-new-privileges:true"}
	spec.ReadOnly = true
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create helper %s: %v", tag, err)
	}
	t.Cleanup(func() { e.removeContainer(t, id, spec.Name) })
	if err := e.docker.Start(ctx, id); err != nil {
		t.Fatalf("start helper %s: %v", tag, err)
	}
	return id
}

// runHelper runs a short-lived helper container (see startHelper) to completion
// and returns its exit code and output.
func (e *itestEnv) runHelper(t *testing.T, ctx context.Context, tag, role string, spec dockerapi.ContainerSpec, limit time.Duration) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	id := e.startHelper(t, ctx, tag, role, spec)
	for {
		d, err := e.docker.Inspect(ctx, id)
		if err != nil {
			t.Fatalf("inspect helper %s: %v", tag, err)
		}
		if d.State == "exited" || d.State == "dead" {
			return d.ExitCode, e.logs(t, id)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("helper %s did not finish within %v\nhelper log:\n%s", tag, limit, strings.TrimSpace(e.logs(t, id)))
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (e *itestEnv) logs(t *testing.T, id string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc, err := e.docker.Logs(ctx, id, -1, false)
	if err != nil {
		t.Fatalf("logs of %s: %v", id[:12], err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, 1<<20))
	if err != nil {
		t.Fatalf("logs of %s: %v", id[:12], err)
	}
	return string(b)
}

func (e *itestEnv) removeContainer(t *testing.T, id, name string) {
	t.Helper()
	// A fresh context: the test's own is already done when cleanups run.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.docker.Remove(ctx, id, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
		t.Errorf("removing container %s (%s): %v", name, id[:12], err)
	}
}
