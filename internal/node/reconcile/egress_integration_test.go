//go:build integration

package reconcile

// This test lets the reconciler start a provider instance with the real Docker
// daemon and the real Xray:
//
//	CGO_ENABLED=0 go test -tags integration -run Provider ./internal/node/reconcile/
//
// (POSTERN_E2E_ONLINE=1 for the part that talks to Telegram). It needs a Docker
// daemon at dockerapi.DefaultSocket, the Go toolchain (it builds the node binary
// for the edge) and GitHub (the Xray v26.3.27 release, verified against the
// SHA2-256 line of its .dgst file; the test is skipped when GitHub cannot be
// reached).
//
//   - A VLESS server: the same Xray, without TLS, on the loopback, out to
//     anywhere.
//   - The reconciler, with a desired state whose default chain is one XRAY_URI
//     egress that points at that server, makes its pass: it creates the edge
//     (the real node binary) and the provider's container, waits until its
//     member answers the SOCKS5 greeting, and gives the edge the member.
//   - A probe on the host network carries data through the member to an echo
//     server of its own.
//   - With POSTERN_E2E_ONLINE=1 only: the edge, started again from the
//     configuration the reconciler made, checks the member against Telegram's
//     datacenters (req_pq_multi → resPQ through it, probe.DCPing) and reports
//     it up.
//
// With Docker Desktop the host network of the containers is a VM, out of reach
// of the test process and of the reconciler: the readiness of the provider and
// the probes run in a container on that network, the test binary itself
// (POSTERN_RECONCILE_PROBE=1, see probeMain), which must therefore be static
// (CGO_ENABLED=0: the runner image is Alpine), and the reconciler talks to a
// stand-in of the edge's control socket that writes the edge's configuration
// file. The server of the member is named vless-server.test, which a hosts file
// in the provider's container maps to 127.0.0.1 (the driver refuses the
// loopback as a literal, and names are what Xray resolves).
//
// The reconciler sees only the containers of this run: its Docker client adds
// the label postern.test=reconcile-egress-<run> to every container it creates
// and to every list, so that it can neither adopt nor remove anything else on
// the daemon. Every container of the run is force-removed at the end, and those
// of a run that was killed at the start.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/edge/control"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/probe"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/xray"
	"github.com/urbnywrt/postern/internal/socks5"
)

const (
	itestXrayVersion = "v26.3.27"
	itestXrayBase    = "https://github.com/XTLS/Xray-core/releases/download/" + itestXrayVersion + "/"
	// itestProbeEnv makes the test binary the probe.
	itestProbeEnv = "POSTERN_RECONCILE_PROBE"
	// itestLabel marks the containers of these tests.
	itestLabel = "postern.test"
	// itestDC is Telegram's DC2 (Global Constraints).
	itestDC = "149.154.167.51:443"
)

func TestMain(m *testing.M) {
	if os.Getenv(itestProbeEnv) == "1" {
		os.Exit(probeMain(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func TestIntegrationProviderStartedByTheReconciler(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	e := newEgressITest(t, ctx)

	paths := state.Paths{Home: e.dir("home", 0o755)}
	// The edge runs as root without CAP_DAC_OVERRIDE: its directories must be
	// writable for it as they are on a node, where root owns them.
	for _, d := range []string{paths.EdgeDir(), paths.RunDir(), paths.CertsDir()} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	arts := &artifacts.Store{Root: paths.ArtifactsDir()}
	xrayRef := e.downloadXray(ctx, arts)
	nodeBin := e.build(ctx, "postern-node", "../../../cmd/node")
	e.probe = e.copySelf()

	// 1. The VLESS server.
	uuid := newTestUUID(t)
	serverPort := 41000 + mrand.IntN(1000)
	srvDir := e.dir("vless-server", 0o755)
	writeReadable(t, filepath.Join(srvDir, "server.json"), fmt.Sprintf(`{
  "log": {"loglevel": "warning", "access": "none"},
  "inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
    "settings": {"clients": [{"id": %q}], "decryption": "none"},
    "streamSettings": {"network": "raw", "security": "none"}}],
  "outbounds": [{"protocol": "freedom"}]
}
`, serverPort, uuid))
	srvID := e.start(ctx, "vless-server", dockerapi.ContainerSpec{
		Image: runnerImage, User: "65534:65534", NetworkMode: "host",
		Entrypoint: []string{"/opt/engine/xray", "run", "-c", "/etc/egress/server.json"},
		Binds:      []string{arts.BinaryPath(xrayRef) + ":/opt/engine/xray:ro", srvDir + ":/etc/egress:ro"},
	})
	hosts := filepath.Join(e.base, "hosts")
	writeReadable(t, hosts, "127.0.0.1 localhost\n127.0.0.1 vless-server.test\n")

	// 2. The reconciler's pass.
	egressID := "itest-" + e.run
	link := fmt.Sprintf("vless://%s@vless-server.test:%d?type=tcp&security=none#itest", uuid, serverPort)
	st := &nodev1.NodeState{
		Generation: 1,
		Settings:   &nodev1.NodeSettings{DefaultChainId: "default", DnsMode: state.DNSModeSystem},
		Egresses:   []*nodev1.Egress{{Id: egressID, Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_URI, ParamsJson: `{"uri":` + strconv.Quote(link) + `}`}},
		Chains:     []*nodev1.EgressChain{{Id: "default", MemberEgressIds: []string{egressID}}},
		Artifacts: []*nodev1.ArtifactRef{{
			Engine: xrayRef.Engine, Version: xrayRef.Version, Arch: xrayRef.Arch, Sha256: xrayRef.SHA256,
			FileName: xrayRef.FileName, Binary: xrayRef.Binary,
		}},
	}
	store := &state.Store{Paths: paths}
	if err := store.SaveDesired(st); err != nil {
		t.Fatal(err)
	}
	edge := &itestEdge{configPath: paths.EdgeConfigPath(1)}
	docker := &itestDocker{Client: e.docker, label: e.label(), hosts: hosts, paths: paths}
	r := &Reconciler{
		Docker:    docker,
		Store:     store,
		Artifacts: arts,
		Drivers:   map[nodev1.Engine]engines.Driver{nodev1.Engine_ENGINE_TELEMT: telemt.New()},
		Providers: map[nodev1.EgressKind]providers.Driver{
			nodev1.EgressKind_EGRESS_KIND_XRAY_URI: &probedProvider{Driver: xray.New(), e: e, ctx: ctx},
		},
		EdgeFactory: func(uint64) EdgeClient { return edge },
		Probe:       func(context.Context, string, string, []byte, netip.AddrPort) error { return errors.New("no proxy") },
		L2: func(context.Context, string, string, []byte, int16, netip.AddrPort) error {
			return errors.New("no proxy")
		},
		MEConfigURLs:   []string{},
		RunnerImage:    runnerImage,
		NodeBinaryPath: nodeBin,
		Arch:           runtime.GOARCH,
		Log:            slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	r.egressReadyTimeout = 3 * time.Minute
	r.readyPoll = 2 * time.Second
	if err := r.reconcileOnce(ctx, nil); err != nil {
		t.Fatalf("the pass: %v", err)
	}

	rt, err := store.LoadRuntime()
	if err != nil {
		t.Fatal(err)
	}
	rec := rt.Egresses[egressID]
	if rec.Generation != 1 || len(rec.Members) != 1 {
		t.Fatalf("egress record = %+v\nprovider log:\n%s", rec, e.logs(providers.ContainerName(egressID, 1)))
	}
	member := rec.Members[0]
	name := providers.ContainerName(egressID, 1)
	if d, err := e.docker.Inspect(ctx, name); err != nil || d.State != "running" {
		t.Fatalf("the provider's container %s: %+v, %v\nlog:\n%s", name, d, err, e.logs(name))
	}
	cfg := edge.last()
	want := &edgev1.ChainMember{Key: egressID + "/" + member.Key, Kind: "socks5", Addr: loopback(member.Port)}
	if len(cfg.GetChains()) != 1 || len(cfg.GetChains()[0].GetMembers()) != 1 || !protoEqual(cfg.GetChains()[0].GetMembers()[0], want) {
		t.Fatalf("the chains of the edge = %v, want the member %v", cfg.GetChains(), want)
	}
	t.Logf("generation 1 of %s serves: member %s on %s", egressID, member.Key, loopback(member.Port))

	// 3. Data through the member.
	exit, out := e.runProbe(ctx, "probe-echo", 2*time.Minute, "-ports", strconv.Itoa(int(member.Port)), "-wait", "60s", "-echo")
	if exit != 0 {
		t.Fatalf("the probe through the member failed (exit %d):\n%s\nprovider log:\n%s\nserver log:\n%s", exit, out, e.logs(name), e.logs(srvID))
	}
	t.Logf("probe:\n%s", strings.TrimSpace(out))
	if log := e.logs(name); strings.Contains(log, uuid) {
		t.Error("the provider's log holds the id of the server's user")
	}

	// 4. Online: the edge checks the member with the datacenters.
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Log("set POSTERN_E2E_ONLINE=1 to have the edge check the member with Telegram's datacenters")
		return
	}
	exit, out = e.runProbe(ctx, "probe-dc", 2*time.Minute, "-ports", strconv.Itoa(int(member.Port)), "-wait", "10s", "-dc", itestDC)
	t.Logf("probe:\n%s", strings.TrimSpace(out))
	if exit != 0 {
		t.Fatalf("DCPing through the member failed (exit %d)\nprovider log:\n%s", exit, e.logs(name))
	}
	edgeName := edgeContainerName(1)
	if err := e.docker.Stop(ctx, edgeName, 35*time.Second); err != nil {
		t.Fatalf("stopping the edge: %v", err)
	}
	if err := e.docker.Start(ctx, edgeName); err != nil {
		t.Fatalf("starting the edge again: %v", err)
	}
	upLine := "member=" + want.GetKey()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		log := e.logs(edgeName)
		if i := strings.Index(log, `"egress: member is up"`); i >= 0 && strings.Contains(log[i:], upLine) {
			t.Logf("the edge: %s", firstLineWith(log[i:], "member is up"))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the edge did not report the member up within 2 minutes:\n%s", log)
		}
		time.Sleep(2 * time.Second)
	}
}

// ---- the rig --------------------------------------------------------------------

type egressITest struct {
	t      *testing.T
	docker dockerapi.Client
	run    string // random id of this run
	base   string // scratch directory of this run
	probe  string // host path of the probe, a copy of this test binary
}

func newEgressITest(t *testing.T, ctx context.Context) *egressITest {
	t.Helper()
	docker := dockerapi.New("")
	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := docker.Ping(pingCtx); err != nil {
		t.Fatalf("no usable Docker daemon at %s: %v", dockerapi.DefaultSocket, err)
	}
	e := &egressITest{t: t, docker: docker, run: strings.ToLower(rand.Text())[:8]}
	e.sweep(ctx)
	if ok, err := docker.ImageExists(ctx, runnerImage); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := docker.Pull(ctx, runnerImage); err != nil {
			t.Fatal(err)
		}
	}
	base, err := os.MkdirTemp("", "postern-itest-egress-")
	if err != nil {
		t.Fatal(err)
	}
	e.base = base
	t.Cleanup(func() {
		e.removeAll()
		e.removeTree(base)
	})
	return e
}

// label is the value of itestLabel of this run; every run's starts with the
// same prefix, for sweep.
func (e *egressITest) label() string { return "reconcile-egress-" + e.run }

// sweep removes the containers that runs of this test left behind.
func (e *egressITest) sweep(ctx context.Context) {
	all, err := e.docker.List(ctx, nil, true)
	if err != nil {
		e.t.Fatalf("listing containers: %v", err)
	}
	for _, c := range all {
		if strings.HasPrefix(c.Labels[itestLabel], "reconcile-egress-") {
			_ = e.docker.Remove(ctx, c.Name, true)
			e.t.Logf("removed %s, left by an earlier run", c.Name)
		}
	}
}

// removeAll force-removes the containers of this run.
func (e *egressITest) removeAll() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	list, err := e.docker.List(ctx, map[string]string{itestLabel: e.label()}, true)
	if err != nil {
		e.t.Errorf("listing the containers of the run: %v", err)
		return
	}
	for _, c := range list {
		if err := e.docker.Remove(ctx, c.Name, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			e.t.Errorf("removing %s: %v", c.Name, err)
		}
	}
}

func (e *egressITest) dir(name string, mode os.FileMode) string {
	e.t.Helper()
	d := filepath.Join(e.base, name)
	if err := os.MkdirAll(d, mode); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Chmod(d, mode); err != nil {
		e.t.Fatal(err)
	}
	return d
}

// start creates and starts a container of the test, removed at the end.
func (e *egressITest) start(ctx context.Context, tag string, spec dockerapi.ContainerSpec) string {
	e.t.Helper()
	spec.Name = "postern-test-" + e.run + "-" + tag
	spec.Labels = map[string]string{itestLabel: e.label()}
	spec.RestartPolicy = "no"
	if _, err := e.docker.Create(ctx, spec); err != nil {
		e.t.Fatalf("create %s: %v", tag, err)
	}
	if err := e.docker.Start(ctx, spec.Name); err != nil {
		e.t.Fatalf("start %s: %v", tag, err)
	}
	return spec.Name
}

// runProbe runs the probe in a container on the host network with args, to
// its end, and returns its exit code and output.
func (e *egressITest) runProbe(ctx context.Context, tag string, limit time.Duration, args ...string) (int, string) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	name := e.start(ctx, tag+"-"+strings.ToLower(rand.Text())[:4], dockerapi.ContainerSpec{
		Image: runnerImage, User: "65534:65534", NetworkMode: "host", ReadOnly: true,
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
		Entrypoint: append([]string{"/opt/probe"}, args...),
		Env:        []string{itestProbeEnv + "=1"},
		Binds:      []string{e.probe + ":/opt/probe:ro"},
	})
	defer func() { _ = e.docker.Remove(context.WithoutCancel(ctx), name, true) }()
	for {
		d, err := e.docker.Inspect(ctx, name)
		if err != nil {
			e.t.Fatalf("inspect %s: %v", tag, err)
		}
		if d.State == "exited" || d.State == "dead" {
			return d.ExitCode, e.logs(name)
		}
		select {
		case <-ctx.Done():
			e.t.Fatalf("%s did not finish within %v:\n%s", tag, limit, e.logs(name))
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (e *egressITest) logs(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc, err := e.docker.Logs(ctx, name, -1, false)
	if err != nil {
		return fmt.Sprintf("(no log: %v)", err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
	return strings.TrimSpace(string(b))
}

// build builds a static binary of pkg for the daemon's architecture.
func (e *egressITest) build(ctx context.Context, name, pkg string) string {
	e.t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		e.t.Fatalf("the go tool is not on PATH: %v", err)
	}
	out := filepath.Join(e.base, name)
	cmd := exec.CommandContext(ctx, goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("building %s: %v\n%s", pkg, err, output)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// copySelf copies this test binary into the scratch directory, from where the
// probe containers mount it.
func (e *egressITest) copySelf() string {
	e.t.Helper()
	self, err := os.Executable()
	if err != nil {
		e.t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		e.t.Fatal(err)
	}
	dst := filepath.Join(e.base, "probe")
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		e.t.Fatal(err)
	}
	return dst
}

// downloadXray stores the release of this architecture, verified against its
// .dgst, in arts. Network trouble skips the test; a mismatch fails it.
func (e *egressITest) downloadXray(ctx context.Context, arts *artifacts.Store) artifacts.Ref {
	e.t.Helper()
	file, err := xray.New().ArtifactFile(runtime.GOARCH)
	if err != nil {
		e.t.Skipf("no Xray release for %s: %v", runtime.GOARCH, err)
	}
	dgst := e.get(ctx, itestXrayBase+file+".dgst", 64<<10)
	sum := ""
	for line := range strings.SplitSeq(string(dgst), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "SHA2-256="); ok {
			sum = strings.ToLower(strings.TrimSpace(v))
		}
	}
	if b, err := hex.DecodeString(sum); err != nil || len(b) != 32 {
		e.t.Fatalf("%s.dgst has no SHA2-256 line", file)
	}
	ref := artifacts.Ref{Engine: "xray", Version: itestXrayVersion, Arch: runtime.GOARCH, SHA256: sum, FileName: file, Binary: "xray"}
	body := e.get(ctx, itestXrayBase+file, 512<<20)
	if err := arts.Put(ref, bytes.NewReader(body)); err != nil {
		e.t.Fatalf("storing %s: %v", file, err)
	}
	return ref
}

func (e *egressITest) get(ctx context.Context, url string, limit int64) []byte {
	e.t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		e.t.Skipf("cannot download %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		e.t.Skipf("cannot download %s: %v", url, err)
	}
	return b
}

// removeTree deletes the scratch directory; what root left in it (the edge's
// socket) goes with it, the directories being the test's.
func (e *egressITest) removeTree(dir string) {
	if err := os.RemoveAll(dir); err == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	name := "postern-test-" + e.run + "-rm"
	if _, err := e.docker.Create(ctx, dockerapi.ContainerSpec{
		Name: name, Image: runnerImage, NetworkMode: "none", Labels: map[string]string{itestLabel: e.label()}, RestartPolicy: "no",
		Entrypoint: []string{"/bin/sh", "-c", "rm -rf /scratch/* /scratch/.[!.]*"},
		Binds:      []string{dir + ":/scratch"},
	}); err != nil {
		e.t.Logf("could not remove %s: %v", dir, err)
		return
	}
	defer func() { _ = e.docker.Remove(context.Background(), name, true) }()
	if err := e.docker.Start(ctx, name); err == nil {
		for ctx.Err() == nil {
			if d, err := e.docker.Inspect(ctx, name); err != nil || d.State == "exited" {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		e.t.Logf("could not remove %s: %v", dir, err)
	}
}

// itestDocker is the reconciler's Docker client in the test: it sees and makes
// the containers of the run only, gives the provider's containers the hosts
// file that names the VLESS server, and makes the edge's configuration file
// readable for the edge, which runs as root without CAP_DAC_OVERRIDE (the test
// is not root, and the file is the test's).
type itestDocker struct {
	dockerapi.Client
	label string
	hosts string
	paths state.Paths
}

func (d *itestDocker) List(ctx context.Context, labels map[string]string, all bool) ([]dockerapi.Container, error) {
	scoped := map[string]string{itestLabel: d.label}
	for k, v := range labels {
		scoped[k] = v
	}
	return d.Client.List(ctx, scoped, all)
}

func (d *itestDocker) Create(ctx context.Context, spec dockerapi.ContainerSpec) (string, error) {
	labels := map[string]string{itestLabel: d.label}
	for k, v := range spec.Labels {
		labels[k] = v
	}
	spec.Labels = labels
	switch spec.Labels[labelRole] {
	case roleEgress:
		spec.Binds = append(slices.Clone(spec.Binds), d.hosts+":/etc/hosts:ro")
		// On a node the agent runs as root and gives the files to the group
		// 65534 of the container's user (Ruling 14); the test cannot, so they
		// are made readable for others.
		for _, b := range spec.Binds {
			if src, ok := strings.CutSuffix(b, ":"+providers.InstanceMount+":ro"); ok {
				if err := openUp(src); err != nil {
					return "", err
				}
			}
		}
	case roleEdge:
		gen, _ := strconv.ParseUint(spec.Labels[labelGeneration], 10, 64)
		if err := os.Chmod(d.paths.EdgeConfigPath(gen), 0o644); err != nil {
			return "", err
		}
	}
	return d.Client.Create(ctx, spec)
}

// openUp makes the directory dir and its files readable for others.
func openUp(dir string) error {
	return filepath.WalkDir(dir, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if de.IsDir() {
			mode = 0o755
		}
		return os.Chmod(path, mode)
	})
}

// probedProvider is a provider whose readiness is checked from the host
// network of the containers: by the probe, in a container.
type probedProvider struct {
	providers.Driver
	e   *egressITest
	ctx context.Context
}

func (p *probedProvider) Ready(_ context.Context, in providers.Instance) error {
	var ports []string
	for _, m := range in.Members {
		ports = append(ports, strconv.Itoa(int(m.Port)))
	}
	exit, out := p.e.runProbe(p.ctx, "ready", 2*time.Minute, "-ports", strings.Join(ports, ","), "-wait", "60s")
	if exit != 0 {
		return fmt.Errorf("the probe says (exit %d): %s", exit, strings.TrimSpace(out))
	}
	return nil
}

// itestEdge stands in for the control socket of the edge: it answers for
// generation 1 and writes every configuration to the edge's file, readable for
// the edge, which takes it when it starts.
type itestEdge struct {
	configPath string
	cfg        *edgev1.EdgeConfig
}

func (e *itestEdge) SetConfig(_ context.Context, cfg *edgev1.EdgeConfig) ([]*edgev1.ListenerFailure, error) {
	if err := control.SaveConfig(e.configPath, cfg); err != nil {
		return nil, err
	}
	e.cfg = cfg
	return nil, os.Chmod(e.configPath, 0o644)
}

func (e *itestEdge) Snapshot(context.Context) (*edgev1.SnapshotResponse, error) {
	return &edgev1.SnapshotResponse{Generation: 1}, nil
}

func (e *itestEdge) Health(context.Context) (*edgev1.HealthResponse, error) {
	return &edgev1.HealthResponse{Generation: 1, Listening: true}, nil
}

func (e *itestEdge) Drain(context.Context, uint32) error { return nil }

func (e *itestEdge) last() *edgev1.EdgeConfig { return e.cfg }

// ---- the probe ----------------------------------------------------------------

// probeMain is the probe: it waits up to -wait until every port of -ports
// answers the SOCKS5 greeting (providers.CheckSOCKS, what the provider's Ready
// does), and then, through the first port, sends 64 KiB to an echo server of
// its own and wants them back (-echo), or exchanges req_pq_multi/resPQ with a
// datacenter (-dc, probe.DCPing). It prints "ok <check>: ..." or "FAIL
// <check>: ..." and exits 1 when a check failed.
func probeMain(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	portList := fs.String("ports", "", "member ports, comma-separated")
	wait := fs.Duration("wait", time.Minute, "how long to wait for the greeting")
	echo := fs.Bool("echo", false, "echo through the first port")
	dc := fs.String("dc", "", "a datacenter to ping through the first port")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var members []providers.Member
	for i, p := range strings.Split(*portList, ",") {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			fmt.Printf("FAIL ports: %q\n", p)
			return 2
		}
		members = append(members, providers.Member{Key: "m" + strconv.Itoa(i), Port: uint16(n)})
	}
	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()
	start := time.Now()
	for {
		err := providers.CheckSOCKS(ctx, members)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			fmt.Printf("FAIL ready: not ready after %v: %v\n", time.Since(start).Round(time.Millisecond), err)
			return 1
		}
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Printf("ok ready: the ports answer the SOCKS5 greeting (after %v)\n", time.Since(start).Round(time.Millisecond))
	member := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(members[0].Port)))
	if *echo {
		if err := probeEcho(member); err != nil {
			fmt.Printf("FAIL echo: %v\n", err)
			return 1
		}
		fmt.Println("ok echo: 64 KiB back through the member")
	}
	if *dc != "" {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := socks5.Dial(ctx, member, "", "", *dc)
		if err == nil {
			err = probe.DCPing(ctx, conn)
			_ = conn.Close()
		}
		if err != nil {
			fmt.Printf("FAIL dc: %s: %v\n", *dc, err)
			return 1
		}
		fmt.Printf("ok dc: resPQ from %s through the member in %v\n", *dc, time.Since(start).Round(time.Millisecond))
	}
	return 0
}

func probeEcho(member string) error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := socks5.Dial(ctx, member, "", "", l.Addr().String())
	if err != nil {
		return fmt.Errorf("CONNECT: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	payload := make([]byte, 64<<10)
	_, _ = rand.Read(payload)
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("reading the echo: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return errors.New("the echo differs from what was sent")
	}
	return nil
}

// ---- small helpers ------------------------------------------------------------

func newTestUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func writeReadable(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func firstLineWith(text, what string) string {
	for line := range strings.SplitSeq(text, "\n") {
		if strings.Contains(line, what) {
			return line
		}
	}
	return ""
}

func protoEqual(a, b *edgev1.ChainMember) bool {
	return a.GetKey() == b.GetKey() && a.GetKind() == b.GetKind() && a.GetAddr() == b.GetAddr()
}

// testWriter sends the reconciler's log to the test's.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
