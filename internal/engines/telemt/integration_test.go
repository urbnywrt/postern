//go:build integration

package telemt

// These tests run the real telemt release in the runner image, the way the node
// agent will:
//
//	go test -tags integration ./internal/engines/telemt/...
//
// They need a Docker daemon at dockerapi.DefaultSocket and network access: the
// runner image is pulled when it is missing, and the telemt 3.5.13 release
// archive comes from GitHub (the test is skipped when GitHub cannot be reached;
// a download that does not match the pinned checksum fails it).
//
// What they check: the archive goes through artifacts.Store.Put with the pinned
// checksum; the rendered config (as a strict copy: config_strict = true, so that
// telemt refuses a key it does not know) starts telemt in a container made from
// Driver.Container; Driver.Ready succeeds within 60 s; the API refuses a wrong
// token; the container log holds none of the secrets; telemt itself says that
// STUN probing is off and does not fall back to an HTTP lookup of its address;
// the only sockets the instance listens on are the two loopback ports of its
// config; and, watched from before it starts, it never holds a socket connected
// outside the loopback.
//
// Every container is named postern-test-<run>-<tag> and labelled
// postern.test=telemt-driver, postern.id=itest-<run> for a random <run>, is
// force-removed when its test ends, and is never found by prefix: containers
// are only touched by ID. The restart policy is "no" here instead of
// unless-stopped, so that a killed test run cannot leave an engine behind that
// the daemon keeps restarting.
//
// A note for those who write more tests like these. On Docker Desktop the
// daemon's host network is the network of its VM, not that of the shell the test
// runs in: a container on the host network binds 127.0.0.1 where this process
// cannot connect. So nothing here connects to the engine from the test process:
// the readiness check runs in a container of its own on the host network (the
// real Driver.Ready, built into testdata/readycheck), and the listening
// sockets are read from a container that shares the engine's process and
// network namespaces. On a Linux daemon that is the same thing, only longer.

import (
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
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
)

const (
	itestVersion = "3.5.13"
	itestBaseURL = "https://github.com/telemt/telemt/releases/download/" + itestVersion + "/"
)

// itestSums are the checksums of the release archives, pinned in the Global
// Constraints, by architecture.
var itestSums = map[string]string{
	"amd64": "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43",
	"arm64": "f7b5181f1160e9ec73eb28705040bf159782055ec71f54a20214e2c9a6d997cd",
}

type itestEnv struct {
	docker dockerapi.Client
	run    string // random id of this run
	base   string // scratch directory of this run
	store  *artifacts.Store
	ref    artifacts.Ref
	ready  string // host path of the readiness helper, built from testdata/readycheck
}

func itestLabels(run string) map[string]string {
	return map[string]string{"postern.test": "telemt-driver", "postern.id": "itest-" + run}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestIntegrationTelemt(t *testing.T) {
	env := newITestEnv(t)

	// The plain fake-TLS proxy of slice 1: direct mode, no promo tag.
	t.Run("fake tls", func(t *testing.T) {
		env.testInstance(t, instanceCase{tag: "plain"})
	})
	// Every optional part of the config at once: if telemt takes this, it takes
	// each variant that TestRenderVariants only checks as text.
	t.Run("every option", func(t *testing.T) {
		env.testInstance(t, instanceCase{tag: "options", edit: func(p *nodev1.Proxy) {
			p.UseMiddleProxy = true
			p.AdTag = randomHex(t, 16)
			p.NatIp = "203.0.113.10"
			p.MaskTargetOverride = "mask.example.com:8443"
		}})
	})
	// Every engine override of the whitelist at once (package overrides, which
	// the rendered config gets them from): if telemt 3.5.13 takes the config, it
	// takes the types and the values of the whitelist, as the reference and the
	// source of that release say it does. (Every case runs a strict copy of its
	// config, see strictConfig, so a key in the wrong table fails here as well.)
	t.Run("every override", func(t *testing.T) {
		env.testInstance(t, instanceCase{tag: "overrides", edit: func(p *nodev1.Proxy) {
			p.EngineOverridesJson = allOverrides
		}})
	})
	// The same with the middle proxies on, so that the keys that only they read
	// are in play. This test has no way to Telegram for them: the SOCKS port of
	// the edge is not there. With me2dc_fallback = false that is fatal: telemt
	// then runs its middle-proxy start-up synchronously and gives up after
	// me_init_retry_attempts failed attempts to start the pool, so it does not
	// come up (src/maestro/me_startup.rs). With me2dc_fallback = true it goes on
	// with direct routing, and moves to the middle proxies when they are ready.
	// So this case is allOverrides but for me2dc_fallback = true.
	t.Run("every override with the middle proxies", func(t *testing.T) {
		env.testInstance(t, instanceCase{tag: "overridesme", edit: func(p *nodev1.Proxy) {
			p.UseMiddleProxy = true
			p.AdTag = randomHex(t, 16)
			p.NatIp = "203.0.113.10"
			p.EngineOverridesJson = withOverride(t, allOverrides, "me2dc_fallback", "true")
		}})
	})
	// telemt looks up its own public address at every start, unless told not to:
	// first with STUN, UDP to public servers, and when that does not work, over
	// HTTPS from a public lookup service. Both go out directly, around the SOCKS
	// port. The rendered config tells it not to do either, and telemt has to say
	// that it took the hint. (Every case also has the watcher of testInstance, which
	// looks at the sockets themselves.) Its log is at the silent level in the other
	// cases, as in production; here RUST_LOG, which wins over the config, raises
	// it, so that the lines become visible while the config under test stays what
	// the driver rendered.
	t.Run("address discovery is off", func(t *testing.T) {
		env.testInstance(t, instanceCase{
			tag:      "lookup",
			env:      []string{"RUST_LOG=telemt=info"},
			checkLog: checkNoAddressDiscovery,
		})
	})
}

// checkNoAddressDiscovery is the log check of the "address discovery is off"
// case: telemt says that STUN is disabled, and neither probes with STUN nor falls
// back to the HTTP lookup.
func checkNoAddressDiscovery(t *testing.T, log string) {
	t.Helper()
	log = stripANSI(log) // telemt colours its log, also when it is not a terminal
	const stunOff = "STUN probe is disabled by network.stun_use=false"
	if !strings.Contains(log, stunOff) {
		t.Errorf("telemt does not say %q; its lines about the lookup of its address:\n%s", stunOff, discoveryLines(log))
	}
	for _, did := range []string{
		"STUN-Quorum",       // a STUN probe that worked
		"STUN probe failed", // one that did not
		"HTTP public IP",    // "using HTTP public IPv4 fallback": the lookup over HTTPS
	} {
		if strings.Contains(log, did) {
			t.Errorf("telemt looked up its own address all the same (the log says %q); its lines about it:\n%s", did, discoveryLines(log))
		}
	}
	// Not the whole log: at this level it can name the public address of the
	// machine the test runs on.
	if !t.Failed() {
		t.Logf("telemt: %q, and no HTTP lookup", stunOff)
	}
}

// ---- setup --------------------------------------------------------------------

func newITestEnv(t *testing.T) *itestEnv {
	t.Helper()
	sum, ok := itestSums[runtime.GOARCH]
	if !ok {
		t.Skipf("no telemt release is pinned for %s", runtime.GOARCH)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

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

	base, err := os.MkdirTemp("", "postern-itest-telemt-")
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

	// The release: download, verify against the pinned checksum, store.
	file, err := New().ArtifactFile(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	e.ref = artifacts.Ref{
		Engine: "telemt", Version: itestVersion, Arch: runtime.GOARCH,
		SHA256: sum, FileName: file, Binary: New().BinaryName(),
	}
	e.download(t, ctx)
	if !e.store.Has(e.ref) {
		t.Fatal("the store does not have the artifact it has just stored")
	}
	if info, err := os.Stat(e.store.BinaryPath(e.ref)); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("stored binary: %v, %v", info, err)
	}

	e.ready = buildReadycheck(t, base)
	return e
}

// download fetches the release archive into the store. Network trouble skips
// the test; a checksum that does not match fails it.
func (e *itestEnv) download(t *testing.T, ctx context.Context) {
	t.Helper()
	url := itestBaseURL + e.ref.FileName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Do(req)
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

// buildReadycheck builds testdata/readycheck as a static binary for the
// daemon's architecture (a container runs it) and returns its path.
func buildReadycheck(t *testing.T, dir string) string {
	t.Helper()
	// go test puts the toolchain's bin directory on the test's PATH.
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	out := filepath.Join(dir, "readycheck")
	cmd := exec.CommandContext(t.Context(), goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", out, "./testdata/readycheck")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the readiness helper: %v\n%s", err, output)
	}
	return out
}

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

// ---- one instance -------------------------------------------------------------

// instanceCase describes one engine instance the integration test runs.
type instanceCase struct {
	tag  string              // part of every name of the case
	edit func(*nodev1.Proxy) // changes the proxy; nil keeps the plain fake-TLS one
	env  []string            // added to the environment of the engine container
	// checkLog, when set, checks the engine's log (known to hold no secret) and
	// takes the place of printing it.
	checkLog func(t *testing.T, log string)
}

func (e *itestEnv) testInstance(t *testing.T, c instanceCase) {
	tag := c.tag
	drv := New()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()

	secret, token := randomHex(t, 16), strings.ToLower(rand.Text())
	proxy := &nodev1.Proxy{
		Id:            strings.ToUpper("itest" + e.run + tag),
		Type:          nodev1.ProxyType_PROXY_TYPE_FAKETLS,
		Enabled:       true,
		Secret:        secret,
		Domain:        "www.example.com",
		Engine:        nodev1.Engine_ENGINE_TELEMT,
		EngineVersion: itestVersion,
	}
	if c.edit != nil {
		c.edit(proxy)
	}

	dir, err := os.MkdirTemp(e.base, tag+"-")
	if err != nil {
		t.Fatal(err)
	}
	// Whatever telemt leaves in there belongs to uid 65534 and cannot be removed
	// by this user: the cleanup of the directory goes through a container.
	t.Cleanup(func() { e.removeTree(t, dir) })
	// The reconciler hands the directory to 65534; this test cannot, so it opens
	// it up instead. Rendered files are readable for the same reason.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}

	in := engines.Instance{
		Proxy:       proxy,
		InstanceID:  proxy.Id + "-g1",
		Generation:  1,
		ListenPort:  pickPort(t, 20000, 25000),
		APIPort:     pickPort(t, 25000, 30000),
		SocksPort:   pickPort(t, 30000, 35000),
		APIToken:    token,
		InstanceDir: dir,
		BinaryPath:  e.store.BinaryPath(e.ref),
		RunnerImage: runnerImage,
	}

	files, err := drv.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if name == configFile {
			// telemt ignores a key that it does not know, so a key that is misspelt or
			// in the wrong table would go through unseen: the config that runs here is
			// a strict copy of the rendered one, which telemt refuses at start-up
			// when it has such a key. (The config of a node is not strict.)
			content = strictConfig(t, content)
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Docker would create a missing bind source as an empty directory and start
	// the container anyway: make sure both are really there first.
	if err := in.CheckHostPaths(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{in.BinaryPath, filepath.Join(dir, "config.toml")} {
		if info, err := os.Stat(p); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("%s is not a file: %v, %v", p, info, err)
		}
	}

	spec := drv.Container(in)
	spec.Name = "postern-test-" + e.run + "-" + tag
	spec.RestartPolicy = "no"
	spec.Labels = itestLabels(e.run)
	spec.Labels["postern.role"] = "engine"
	spec.Labels["postern.generation"] = "1"
	spec.Env = append(spec.Env, c.env...)
	// The watcher finds the engine process by this marker in its environment.
	marker := "itest-" + e.run + "-" + tag
	spec.Env = append(spec.Env, "POSTERN_ITEST_MARK="+marker)

	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { e.removeContainer(t, id, spec.Name) })
	// The watcher is running before the engine is: what telemt does in its first
	// moments is what it is there for.
	watchID := e.startWatch(t, ctx, tag, marker)
	if err := e.docker.Start(ctx, id); err != nil {
		t.Fatalf("start: %v", err)
	}

	// 1. Ready succeeds within 60 s: the real Driver.Ready, run on the daemon's
	// host network.
	exit, out := e.runHelper(t, ctx, "ready", dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534",
		NetworkMode: "host",
		Entrypoint:  []string{"/opt/readycheck"},
		Cmd:         []string{"-wait", "60s"},
		Env:         []string{"TELEMT_API_PORT=" + strconv.Itoa(int(in.APIPort)), "TELEMT_API_TOKEN=" + token},
		Binds:       []string{e.ready + ":/opt/readycheck:ro"},
	}, 90*time.Second, func(ctx context.Context) error { return e.stillRunning(ctx, id) })
	if exit != 0 {
		t.Fatalf("Ready did not succeed within 60 s (exit %d): %s\ntelemt log:\n%s", exit, strings.TrimSpace(out), e.scrubbedLog(t, id, secret, token, proxy.AdTag))
	}
	t.Logf("telemt 3.5.13: %s", strings.TrimSpace(out))

	// 2. The API wants the token it was given.
	exit, out = e.runHelper(t, ctx, "wrongtoken", dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534",
		NetworkMode: "host",
		Entrypoint:  []string{"/opt/readycheck"},
		Cmd:         []string{"-once"},
		Env:         []string{"TELEMT_API_PORT=" + strconv.Itoa(int(in.APIPort)), "TELEMT_API_TOKEN=" + token + "x"},
		Binds:       []string{e.ready + ":/opt/readycheck:ro"},
	}, 30*time.Second, nil)
	if exit == 0 || !strings.Contains(out, "401") {
		t.Errorf("with a wrong token Ready gave exit %d and %q, want a failure that says 401", exit, strings.TrimSpace(out))
	}

	// 3. Still running; nothing in the log gives a secret away.
	if err := e.stillRunning(ctx, id); err != nil {
		t.Fatal(err)
	}
	log := e.scrubbedLog(t, id, secret, token, proxy.AdTag)
	if c.checkLog != nil {
		c.checkLog(t, log)
	} else {
		t.Logf("telemt log:\n%s", log)
	}

	// 4. The instance listens on its two loopback ports and nothing else: in
	// particular not on [server] port, which would default to 443.
	got := e.listeners(t, ctx, id)
	want := []string{
		net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.ListenPort))),
		net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.APIPort))),
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("telemt listens on %v, want exactly %v", got, want)
	}

	// 5. From its first moment on, it held no socket connected outside the
	// loopback. (Its own lookup of its public address is the one thing that would.)
	checkWatch(t, e.endWatch(t, ctx, watchID), want)
}

// scrubbedLog returns the container log, or says that it holds a secret
// without printing it: a log that gives one away must not end up in the test
// output either.
func (e *itestEnv) scrubbedLog(t *testing.T, id string, secrets ...string) string {
	t.Helper()
	log := e.logs(t, id)
	for _, s := range secrets {
		if s != "" && strings.Contains(strings.ToLower(log), strings.ToLower(s)) {
			t.Errorf("the container log contains a secret (%d characters of it); log withheld", len(s))
			return "(withheld)"
		}
	}
	if strings.Contains(log, "tg://") {
		t.Errorf("the container log contains a tg:// link, which carries the proxy secret; log withheld")
		return "(withheld)"
	}
	return strings.TrimSpace(log)
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

func (e *itestEnv) stillRunning(ctx context.Context, id string) error {
	d, err := e.docker.Inspect(ctx, id)
	if err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
	if d.State != "running" {
		return fmt.Errorf("the engine container is %s (exit code %d)", d.State, d.ExitCode)
	}
	return nil
}

// listeners returns the TCP sockets the main process of the container listens
// on, as sorted "ip:port" strings, read from a container that shares its
// process and network namespaces. The process is PID 1 there.
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
	exit, out := e.runHelper(t, ctx, "sockets", dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534", // the engine's own user: the sockets of a process are for its owner
		NetworkMode: "host",
		PidMode:     "container:" + id,
		Entrypoint:  []string{"/bin/sh", "-c", script},
	}, 30*time.Second, nil)
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
		got = append(got, ap.String())
	}
	slices.Sort(got)
	return got
}

// ---- watching the engine's connections ------------------------------------------

// watchScript is run by the watcher container, which is on the host's process
// and network namespaces. It waits for the process whose environment carries
// the marker of the engine under test (the engine container exists but has not
// been started yet), says "found <pid>", and then, every 20 ms or so, notes all
// the sockets that process holds. It runs until it is told to stop, or until the
// process is gone, and then prints each distinct "<file> <local> <remote> <state>" once.
//
// A socket that exists for a moment is caught only by sampling it from the very
// start, which is why this runs beside the engine from before it starts: the
// lookup of its own address that telemt makes, if it is not told otherwise, is
// over in 400 ms, and nothing looking afterwards would know.
const watchScript = `
pid=
until [ -n "$pid" ]; do
  f=$(grep -a -l -s "POSTERN_ITEST_MARK=$MARK" /proc/[0-9]*/environ 2>/dev/null | head -n 1)
  if [ -n "$f" ]; then f=${f#/proc/}; pid=${f%%/*}; else sleep 0.02; fi
done
echo "found $pid"
seen=/tmp/seen
: > $seen
report() { sort -u $seen; exit 0; }
trap report TERM INT
while [ -d /proc/$pid ]; do
  inodes=$(ls -l /proc/$pid/fd 2>/dev/null | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p' | tr '\n' ' ')
  if [ -n "$inodes" ]; then
    awk -v want="$inodes" 'BEGIN { n = split(want, a, " "); for (i = 1; i <= n; i++) w[a[i]] = 1 } FNR > 1 && ($10 in w) { print FILENAME, $2, $3, $4 }' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 >> $seen
  fi
  sleep 0.02
done
report
`

// startWatch starts the watcher for the engine container whose environment has
// the marker, and returns its ID. The caller starts the engine afterwards.
func (e *itestEnv) startWatch(t *testing.T, ctx context.Context, tag, marker string) string {
	t.Helper()
	spec := e.helperSpec("watch-"+tag, dockerapi.ContainerSpec{
		Image: runnerImage,
		// The engine's own user: the sockets of a process are for its owner.
		User:        "65534:65534",
		NetworkMode: "host",
		PidMode:     "host",
		Entrypoint:  []string{"/bin/sh", "-c", watchScript},
		Env:         []string{"MARK=" + marker},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=8m"},
	})
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create the watcher: %v", err)
	}
	t.Cleanup(func() { e.removeContainer(t, id, spec.Name) })
	if err := e.docker.Start(ctx, id); err != nil {
		t.Fatalf("start the watcher: %v", err)
	}
	return id
}

// endWatch stops the watcher and returns what it saw.
func (e *itestEnv) endWatch(t *testing.T, ctx context.Context, id string) watchReport {
	t.Helper()
	if err := e.docker.Stop(ctx, id, 10*time.Second); err != nil {
		t.Fatalf("stop the watcher: %v", err)
	}
	report, err := parseWatchReport(e.logs(t, id))
	if err != nil {
		t.Fatalf("the watcher's report cannot be read: %v", err)
	}
	return report
}

// checkWatch fails the test when the watcher saw a socket of the engine that is
// connected outside the loopback. Whatever telemt is to reach outside goes
// through the edge's SOCKS port, which is on the loopback; what it does not go
// through is a lookup of its own address, STUN or HTTP, that it makes at every
// start unless told not to.
func checkWatch(t *testing.T, r watchReport, wantListening []string) {
	t.Helper()
	if !r.Found {
		t.Error("the watcher never found the engine process, so it watched nothing")
		return
	}
	// The two listeners of this instance (ports that no other instance has) are
	// the proof that the watcher really looked at the engine, and not at nothing
	// or at something else: both are open by the time the engine is ready.
	var listening []string
	for _, ap := range r.Listening {
		listening = append(listening, ap.String())
	}
	for _, want := range wantListening {
		if !slices.Contains(listening, want) {
			t.Errorf("the watcher did not see the engine listen on %s (it saw %v): it did not look at the right process", want, listening)
		}
	}
	if len(r.Outside) > 0 {
		t.Errorf("the engine connected outside the loopback while it started and ran:\n  %s", strings.Join(r.Outside, "\n  "))
		return
	}
	if !t.Failed() {
		t.Logf("watched the engine from before it started: it listened on %s, and held no connection outside the loopback", strings.Join(listening, " and "))
	}
}

// ---- containers ---------------------------------------------------------------

// helperSpec makes a helper container of a spec: named for this run, labelled
// for it, and locked down: no restarts, no capabilities, no new privileges, a
// read-only root file system.
func (e *itestEnv) helperSpec(tag string, spec dockerapi.ContainerSpec) dockerapi.ContainerSpec {
	spec.Name = "postern-test-" + e.run + "-" + tag + "-" + strings.ToLower(rand.Text())[:6]
	spec.Labels = itestLabels(e.run)
	spec.RestartPolicy = "no"
	spec.CapDrop = []string{"ALL"}
	spec.SecurityOpt = []string{"no-new-privileges:true"}
	spec.ReadOnly = true
	return spec
}

// runHelper runs a short-lived container to completion and returns its exit code
// and output. abort, when given, is polled while waiting; an error from it stops
// the wait and fails the test.
func (e *itestEnv) runHelper(t *testing.T, ctx context.Context, tag string, spec dockerapi.ContainerSpec, limit time.Duration, abort func(context.Context) error) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	spec = e.helperSpec(tag, spec)
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
		if abort != nil {
			if err := abort(ctx); err != nil {
				t.Fatalf("while waiting for helper %s: %v\nhelper log:\n%s", tag, err, strings.TrimSpace(e.logs(t, id)))
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("helper %s did not finish within %v\nhelper log:\n%s", tag, limit, strings.TrimSpace(e.logs(t, id)))
		case <-time.After(250 * time.Millisecond):
		}
	}
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

// removeTree deletes a directory in which a container running as another user
// has created files, by deleting them from a container that runs as root.
func (e *itestEnv) removeTree(t *testing.T, dir string) {
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
		Entrypoint:  []string{"/bin/sh", "-c", "rm -rf /inst/* /inst/.[!.]*"},
		Binds:       []string{dir + ":/inst"},
		Labels:      itestLabels(e.run),
	})
	if err != nil {
		t.Logf("could not remove %s: %v", dir, err)
		return
	}
	defer func() {
		if err := e.docker.Remove(ctx, id, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			t.Logf("removing cleanup container: %v", err)
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
