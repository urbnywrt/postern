//go:build integration

package probe

// TestIntegrationTelemt probes the real telemt 3.5.13 in the runner image, run
// the way the node agent runs it, with the right secret and with a wrong one:
//
//	go test -tags integration ./internal/probe/...
//
// It needs a Docker daemon at dockerapi.DefaultSocket and network access: the
// runner image is pulled when it is missing, and the telemt release archive
// comes from GitHub (the test is skipped when GitHub cannot be reached; a
// download that does not match the pinned checksum fails it). The engine is
// configured by the real telemt driver, so it listens on 127.0.0.1 and wants a
// PROXY protocol v2 header on every connection: every probe here sends one.
//
// With the right secret the probe succeeds; with a wrong one it fails with
// ErrBadServerDigest, because telemt answers a client it does not recognize in
// the shape of a fake-TLS server when it cannot reach its masking host (it
// would reach it through the edge's SOCKS port, which is not running here).
//
// The probe does not run in the test process. On Docker Desktop the daemon's
// host network is the network of its VM, and a container on it binds a
// 127.0.0.1 that this process cannot reach. So the probe runs in a container
// of its own on the host network (testdata/probecheck, which calls the real
// FakeTLS). On a Linux daemon that is the same thing, only longer. The Docker
// helpers below are a trimmed copy of those of the telemt driver's integration
// test.
//
// Every container is named postern-test-<run>-<tag> and labelled
// postern.test=probe, postern.id=itest-<run> for a random <run>, has the
// restart policy "no" and is force-removed when the test ends. Containers are
// only ever touched by ID.
//
// The tests that reach Telegram's datacenters run only with
// POSTERN_E2E_ONLINE=1:
//
//	POSTERN_E2E_ONLINE=1 go test -tags integration -run 'Integration(DCPing|L2)' ./internal/probe/...
//
// TestIntegrationDCPing pings the five datacenters of the health targets
// straight from the test process, with datacenter 0 in the header as DCPing
// sends it and with other values in the field.
// TestIntegrationL2Telemt runs L2 through a real telemt to DC2: telemt goes out
// through its SOCKS port, which the edge serves in production and the probe
// helper serves here (testdata/probecheck -socks, connecting directly), in a
// container of its own on the host network.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt"
)

const (
	runnerImage   = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
	telemtVersion = "3.5.13"
	telemtBaseURL = "https://github.com/telemt/telemt/releases/download/" + telemtVersion + "/"
	itestDomain   = "www.example.com"
)

// telemtSums are the checksums of the release archives, pinned in the Global
// Constraints, by architecture.
var telemtSums = map[string]string{
	"amd64": "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43",
	"arm64": "f7b5181f1160e9ec73eb28705040bf159782055ec71f54a20214e2c9a6d997cd",
}

func TestIntegrationTelemt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	e := newITest(t, ctx)

	secret := randomBytes(16)
	wrong := bytes.Clone(secret)
	wrong[0] ^= 0xff
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(e.startTelemt(t, ctx, hex.EncodeToString(secret), 0))))

	// 1. The right secret, from the PROXY source the reconciler uses. telemt
	// binds its listener a few seconds after start-up, so the helper retries
	// for a while; a wrong digest ends it at once.
	exit, out := e.probe(t, ctx, "right", addr, "127.0.0.1:1", secret, 60*time.Second)
	if exit != 0 {
		t.Fatalf("FakeTLS with the right secret failed (exit %d): %s\ntelemt log:\n%s", exit, out, e.scrubbedLog(t, secret, wrong))
	}
	t.Logf("right secret: %s", out)

	// 2. A wrong secret, from another source address (telemt keeps track of
	// failed handshakes per client address). telemt does not recognize it and,
	// its masking host being out of reach (through the edge's SOCKS port, not
	// running here), answers like a TLS server itself: ServerHello,
	// ChangeCipherSpec and ApplicationData, then it waits. The shape is right,
	// the digest cannot be.
	exit, out = e.probe(t, ctx, "wrong", addr, "198.51.100.7:40000", wrong, 0)
	switch exit {
	case 0:
		t.Fatalf("FakeTLS with a wrong secret succeeded: %s", out)
	case 3:
		t.Logf("wrong secret: %s", out)
	default:
		t.Fatalf("FakeTLS with a wrong secret failed with exit %d, want 3 (ErrBadServerDigest): %s", exit, out)
	}

	// 3. The right secret again, in a single attempt.
	exit, out = e.probe(t, ctx, "again", addr, "127.0.0.1:1", secret, 0)
	if exit != 0 {
		t.Fatalf("FakeTLS with the right secret failed after the wrong one (exit %d): %s\ntelemt log:\n%s", exit, out, e.scrubbedLog(t, secret, wrong))
	}
	t.Logf("right secret again: %s", out)

	if err := e.stillRunning(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("telemt log:\n%s", e.scrubbedLog(t, secret, wrong))
}

// healthTargets are the datacenters the node checks its egress members against
// (the health defaults of the plan).
var healthTargets = []struct{ name, addr string }{
	{"DC1", "149.154.175.50:443"},
	{"DC2", "149.154.167.51:443"},
	{"DC3", "149.154.175.100:443"},
	{"DC4", "149.154.167.91:443"},
	{"DC5", "91.108.56.130:443"},
}

// online skips a test that needs Telegram's datacenters unless
// POSTERN_E2E_ONLINE=1.
func online(t *testing.T) {
	t.Helper()
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Skip("reaches Telegram's datacenters: set POSTERN_E2E_ONLINE=1 to run it")
	}
}

// TestIntegrationDCPing pings each datacenter of the health targets directly.
// DCPing names datacenter 0 in its header. Only a proxy looks at that field, to
// pick the datacenter; the test shows it by asking each datacenter again, on
// new connections, with 2, -2, 5 and 999 in the field.
func TestIntegrationDCPing(t *testing.T) {
	online(t)
	for _, dc := range healthTargets {
		t.Run(dc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			start := time.Now()
			if err := DCPing(ctx, dial(t, dc.addr)); err != nil {
				t.Fatalf("DCPing to %s: %v", dc.name, err)
			}
			t.Logf("%s answered req_pq_multi with a valid resPQ after %v", dc.name, time.Since(start).Round(time.Millisecond))

			for _, field := range []int16{2, -2, 5, 999} {
				conn := dial(t, dc.addr)
				if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := pingError(ping(conn, conn, tagIntermediate, field, nil, time.Now())); err != nil {
					t.Errorf("%s with datacenter %d in the header: %v", dc.name, field, err)
				}
			}
		})
	}
}

// TestIntegrationL2Telemt runs L2 through the real telemt 3.5.13 to DC2: the
// fake-TLS handshake with the engine, then req_pq_multi through it, which telemt
// passes on through its SOCKS upstream to the datacenter, and the datacenter's
// resPQ back.
func TestIntegrationL2Telemt(t *testing.T) {
	online(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	e := newITest(t, ctx)

	secret := randomBytes(16)
	socks := pickPort(t, 30000, 35000)
	e.startSOCKS(t, ctx, socks)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(e.startTelemt(t, ctx, hex.EncodeToString(secret), socks))))

	// telemt binds its listener a few seconds after start-up: the helper
	// retries for a while; a wrong digest or a wrong answer ends it at once.
	exit, out := e.probe(t, ctx, "l2", addr, "127.0.0.1:1", secret, 90*time.Second, "-l2", "-dc", "2")
	if exit != 0 {
		t.Fatalf("L2 through telemt to DC2 failed (exit %d): %s\ntelemt log:\n%s\nSOCKS log:\n%s",
			exit, out, e.scrubbedLog(t, secret), strings.TrimSpace(e.logs(t, e.socks)))
	}
	t.Logf("%s", out)

	// Once more, in a single attempt, now that telemt is up.
	exit, out = e.probe(t, ctx, "l2-again", addr, "127.0.0.1:1", secret, 0, "-l2", "-dc", "2")
	if exit != 0 {
		t.Fatalf("L2 through telemt to DC2 failed the second time (exit %d): %s\ntelemt log:\n%s\nSOCKS log:\n%s",
			exit, out, e.scrubbedLog(t, secret), strings.TrimSpace(e.logs(t, e.socks)))
	}
	t.Logf("again: %s", out)

	if err := e.stillRunning(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("SOCKS log:\n%s", strings.TrimSpace(e.logs(t, e.socks)))
}

// ---- setup --------------------------------------------------------------------

type itest struct {
	docker     dockerapi.Client
	run        string // random id of this run
	base       string // scratch directory of this run
	store      *artifacts.Store
	ref        artifacts.Ref
	probecheck string // host path of the probe helper, built from testdata/probecheck
	engine     string // ID of the telemt container
	socks      string // ID of the container that serves telemt's SOCKS port, if any
}

func (e *itest) labels() map[string]string {
	return map[string]string{"postern.test": "probe", "postern.id": "itest-" + e.run}
}

func newITest(t *testing.T, ctx context.Context) *itest {
	t.Helper()
	sum, ok := telemtSums[runtime.GOARCH]
	if !ok {
		t.Skipf("no telemt release is pinned for %s", runtime.GOARCH)
	}
	docker := dockerapi.New("")
	pingCtx, pingCancel := context.WithTimeout(ctx, 15*time.Second)
	defer pingCancel()
	if _, err := docker.Ping(pingCtx); err != nil {
		t.Fatalf("no usable Docker daemon at %s: %v", dockerapi.DefaultSocket, err)
	}
	if ok, err := docker.ImageExists(ctx, runnerImage); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := docker.Pull(ctx, runnerImage); err != nil {
			t.Fatal(err)
		}
	}

	base, err := os.MkdirTemp("", "postern-itest-probe-")
	if err != nil {
		t.Fatal(err)
	}
	e := &itest{
		docker: docker,
		run:    strings.ToLower(rand.Text())[:10],
		base:   base,
		store:  &artifacts.Store{Root: filepath.Join(base, "artifacts")},
	}
	t.Cleanup(func() { e.removeTree(t, base) })

	drv := telemt.New()
	file, err := drv.ArtifactFile(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	e.ref = artifacts.Ref{
		Engine: "telemt", Version: telemtVersion, Arch: runtime.GOARCH,
		SHA256: sum, FileName: file, Binary: drv.BinaryName(),
	}
	e.download(t, ctx)
	e.probecheck = buildProbecheck(t, base)
	return e
}

// download fetches the release archive into the store. Network trouble skips
// the test; a checksum that does not match fails it.
func (e *itest) download(t *testing.T, ctx context.Context) {
	t.Helper()
	url := telemtBaseURL + e.ref.FileName
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
	switch err := e.store.Put(e.ref, resp.Body); {
	case errors.Is(err, artifacts.ErrChecksum):
		t.Fatalf("the download does not match the pinned checksum: %v", err)
	case errors.Is(err, artifacts.ErrArchive), errors.Is(err, artifacts.ErrTooLarge):
		t.Fatalf("the download is not a usable release archive: %v", err)
	case err != nil:
		t.Skipf("the download of %s did not complete: %v", url, err)
	}
}

// buildProbecheck builds testdata/probecheck as a static binary for the
// daemon's architecture (a container runs it) and returns its path.
func buildProbecheck(t *testing.T, dir string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("building the probe helper needs the go command on PATH: %v", err)
	}
	out := filepath.Join(dir, "probecheck")
	cmd := exec.CommandContext(t.Context(), goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", out, "./testdata/probecheck")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the probe helper: %v\n%s", err, output)
	}
	return out
}

// pickPort returns a random port of [lo, hi) that is free on this host's
// loopback. Where the daemon's host network is a VM's that check says little,
// but the ranges are wide.
func pickPort(t *testing.T, lo, hi int) uint16 {
	t.Helper()
	for range 200 {
		p := lo + mrand.IntN(hi-lo)
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		_ = l.Close()
		return uint16(p)
	}
	t.Fatalf("no free port in %d-%d", lo, hi)
	return 0
}

// startTelemt starts one telemt instance for a fake-TLS proxy with the given
// secret, configured by the driver, and returns its listen port. telemt goes
// out through the SOCKS port socks, or through a random port of the edge's
// range when socks is 0. It does not wait for the engine to be ready.
func (e *itest) startTelemt(t *testing.T, ctx context.Context, secretHex string, socks uint16) uint16 {
	t.Helper()
	drv := telemt.New()
	proxy := &nodev1.Proxy{
		Id:            strings.ToUpper("itest" + e.run),
		Type:          nodev1.ProxyType_PROXY_TYPE_FAKETLS,
		Enabled:       true,
		Secret:        secretHex,
		Domain:        itestDomain,
		Engine:        nodev1.Engine_ENGINE_TELEMT,
		EngineVersion: telemtVersion,
	}
	dir, err := os.MkdirTemp(e.base, "instance-")
	if err != nil {
		t.Fatal(err)
	}
	// The engine runs as 65534 and writes its caches in here; the reconciler
	// hands the directory to that user, this test opens it up instead.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if socks == 0 {
		socks = pickPort(t, 30000, 35000)
	}
	in := engines.Instance{
		Proxy:       proxy,
		InstanceID:  proxy.Id + "-g1",
		Generation:  1,
		ListenPort:  pickPort(t, 20000, 25000),
		APIPort:     pickPort(t, 25000, 30000),
		SocksPort:   socks,
		APIToken:    strings.ToLower(rand.Text()),
		InstanceDir: dir,
		BinaryPath:  e.store.BinaryPath(e.ref),
		RunnerImage: runnerImage,
	}
	files, err := drv.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		// Readable by the engine's user; the directory is this test's.
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.CheckHostPaths(); err != nil {
		t.Fatal(err)
	}

	spec := drv.Container(in)
	spec.Name = "postern-test-" + e.run + "-telemt"
	spec.RestartPolicy = "no"
	spec.Labels = e.labels()
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { e.removeContainer(t, id, spec.Name) })
	if err := e.docker.Start(ctx, id); err != nil {
		t.Fatalf("start: %v", err)
	}
	e.engine = id
	return in.ListenPort
}

// ---- containers ---------------------------------------------------------------

// probe runs the probe helper against addr with a PROXY header from src, and
// returns its exit status and output. A wait above zero makes it retry until
// it succeeds or the time is up. extra are more flags of the helper: -l2 and
// -dc make it run L2 instead of FakeTLS.
func (e *itest) probe(t *testing.T, ctx context.Context, tag, addr, src string, secret []byte, wait time.Duration, extra ...string) (int, string) {
	t.Helper()
	cmd := []string{"-addr", addr, "-sni", itestDomain, "-proxy-src", src}
	if wait > 0 {
		cmd = append(cmd, "-wait", wait.String())
	}
	cmd = append(cmd, extra...)
	exit, out := e.runHelper(t, ctx, tag, dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534",
		NetworkMode: "host",
		Entrypoint:  []string{"/opt/probecheck"},
		Cmd:         cmd,
		Env:         []string{"PROBE_SECRET=" + hex.EncodeToString(secret)},
		Binds:       []string{e.probecheck + ":/opt/probecheck:ro"},
	}, wait+30*time.Second)
	return exit, strings.TrimSpace(out)
}

// startSOCKS starts the probe helper as the SOCKS5 server on 127.0.0.1:port of
// the host network that telemt goes out through, connecting directly. It runs
// until the test ends.
func (e *itest) startSOCKS(t *testing.T, ctx context.Context, port uint16) {
	t.Helper()
	spec := dockerapi.ContainerSpec{
		Name:          "postern-test-" + e.run + "-socks",
		Image:         runnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "no",
		Entrypoint:    []string{"/opt/probecheck"},
		Cmd:           []string{"-socks", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))},
		Binds:         []string{e.probecheck + ":/opt/probecheck:ro"},
		Labels:        e.labels(),
		CapDrop:       []string{"ALL"},
		SecurityOpt:   []string{"no-new-privileges:true"},
		ReadOnly:      true,
	}
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create the SOCKS helper: %v", err)
	}
	t.Cleanup(func() { e.removeContainer(t, id, spec.Name) })
	if err := e.docker.Start(ctx, id); err != nil {
		t.Fatalf("start the SOCKS helper: %v", err)
	}
	e.socks = id
}

// runHelper runs a short-lived container to completion and returns its exit
// code and output. It fails the test when the engine stops in the meantime.
func (e *itest) runHelper(t *testing.T, ctx context.Context, tag string, spec dockerapi.ContainerSpec, limit time.Duration) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	spec.Name = "postern-test-" + e.run + "-" + tag + "-" + strings.ToLower(rand.Text())[:6]
	spec.Labels = e.labels()
	spec.RestartPolicy = "no"
	spec.CapDrop = []string{"ALL"}
	spec.SecurityOpt = []string{"no-new-privileges:true"}
	spec.ReadOnly = true
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create helper %s: %v", tag, err)
	}
	defer e.removeContainer(t, id, spec.Name)
	if err := e.docker.Start(ctx, id); err != nil {
		t.Fatalf("start helper %s: %v", tag, err)
	}
	for {
		d, err := e.docker.Inspect(ctx, id)
		if err != nil {
			t.Fatalf("inspect helper %s: %v", tag, err)
		}
		if d.State == "exited" || d.State == "dead" {
			return d.ExitCode, e.logs(t, id)
		}
		if err := e.stillRunning(ctx); err != nil {
			t.Fatalf("while waiting for helper %s: %v\nhelper log:\n%s", tag, err, strings.TrimSpace(e.logs(t, id)))
		}
		select {
		case <-ctx.Done():
			t.Fatalf("helper %s did not finish within %v\nhelper log:\n%s", tag, limit, strings.TrimSpace(e.logs(t, id)))
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (e *itest) stillRunning(ctx context.Context) error {
	d, err := e.docker.Inspect(ctx, e.engine)
	if err != nil {
		return fmt.Errorf("inspect the engine: %w", err)
	}
	if d.State != "running" {
		return fmt.Errorf("the engine container is %s (exit code %d)", d.State, d.ExitCode)
	}
	return nil
}

func (e *itest) logs(t *testing.T, id string) string {
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

// scrubbedLog returns the engine's log, or says that it holds one of the
// secrets without printing it.
func (e *itest) scrubbedLog(t *testing.T, secrets ...[]byte) string {
	t.Helper()
	log := e.logs(t, e.engine)
	for _, s := range secrets {
		if strings.Contains(strings.ToLower(log), hex.EncodeToString(s)) {
			t.Errorf("the engine log contains a secret; log withheld")
			return "(withheld)"
		}
	}
	return strings.TrimSpace(log)
}

func (e *itest) removeContainer(t *testing.T, id, name string) {
	t.Helper()
	// A fresh context: the test's own is done when cleanups run.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.docker.Remove(ctx, id, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
		t.Errorf("removing container %s (%s): %v", name, id[:12], err)
	}
}

// removeTree deletes a directory in which a container running as another user
// has created files, by deleting them from a container that runs as root.
func (e *itest) removeTree(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(dir); err == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id, err := e.docker.Create(ctx, dockerapi.ContainerSpec{
		Name:        "postern-test-" + e.run + "-rm-" + strings.ToLower(rand.Text())[:6],
		Image:       runnerImage,
		NetworkMode: "none",
		Entrypoint:  []string{"/bin/sh", "-c", "rm -rf /scratch/* /scratch/.[!.]*"},
		Binds:       []string{dir + ":/scratch"},
		Labels:      e.labels(),
	})
	if err != nil {
		t.Logf("could not remove %s: %v", dir, err)
		return
	}
	defer func() {
		if err := e.docker.Remove(ctx, id, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			t.Logf("removing the cleanup container: %v", err)
		}
	}()
	if err := e.docker.Start(ctx, id); err != nil {
		t.Logf("could not remove %s: %v", dir, err)
		return
	}
	for ctx.Err() == nil {
		d, err := e.docker.Inspect(ctx, id)
		if err != nil || d.State == "exited" || d.State == "dead" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("could not remove %s: %v", dir, err)
	}
}
