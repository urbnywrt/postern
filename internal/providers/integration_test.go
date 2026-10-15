//go:build integration

package providers_test

// These tests run the pinned Xray release in the runner image, the way the node
// agent will. From a checkout:
//
//	go test -tags integration ./internal/providers/
//
// or as one self-contained binary, for a Linux server with Docker (run as root,
// or as a user of the docker group; nothing else is needed beside the binary):
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags integration -o providers-integration.test ./internal/providers
//	POSTERN_E2E_ONLINE=1 ./providers-integration.test -test.run '^TestIntegrationWARPOnline$' -test.v -test.timeout 20m
//
// They need a Docker daemon at dockerapi.DefaultSocket and network access: the
// runner image is pulled when it is missing, and the Xray v26.3.27 release
// archive comes from GitHub, verified against the SHA2-256 line of the release's
// .dgst file and stored with artifacts.Store (zip extraction). A test is skipped
// when GitHub cannot be reached; a download that does not match its checksum
// fails it.
//
// What they check:
//
//   - TestIntegrationXray/configs: Xray takes every config the driver renders
//     (the golden files of package xray, embedded in the binary, and every value
//     the driver accepts) and refuses each value the driver refuses, with
//     `xray run -test`, which builds the whole instance (handlers included)
//     without starting it. This is what ties the driver's checks to the pinned
//     binary.
//   - TestIntegrationXray/vless: a member pointing at a local Xray VLESS server
//     (the same binary, a generated server config, no TLS) carries a SOCKS
//     CONNECT to a local echo server; the member's port is on the loopback only;
//     the log holds no credential. The member names the server by a name under
//     .test that a hosts file of the client container maps to 127.0.0.1: the
//     driver refuses the loopback as a literal (CheckServerAddress), and names
//     are what Xray resolves.
//   - TestIntegrationWARPOnline (POSTERN_E2E_ONLINE=1 only): registers a WARP
//     device with Cloudflare (warp.LoadOrRegister), runs the WARP member as the
//     agent will, and through it connects to Telegram's DC2 and exchanges
//     req_pq_multi/resPQ (unencrypted MTProto over the intermediate transport;
//     probe.DCPing is not on this branch yet), and completes a TLS handshake
//     with example.com, its certificate checked. It deletes the device at the
//     end, also when it fails, and prints a short summary that never holds the
//     private key or the token.
//
// Nothing connects to a member from the test process (with Docker Desktop the
// daemon's host network is a VM, out of reach): the checks run in a container
// on the host network, the probe, which is this test binary run with
// POSTERN_PROVIDERS_PROBE=1 (see probe_integration_test.go).
//
// Every container is named postern-test-<run>-<tag>-<random>, labelled
// postern.test=providers and postern.id=itest-<run>, has the restart policy
// "no", and is force-removed when its test ends, also when it fails; the
// containers of an earlier run that was killed are removed at the start.
// Member ports come from the egress range 35000-39999. Run one at a time.

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/warp"
	"github.com/urbnywrt/postern/internal/providers/xray"
)

const (
	xrayVersion = "v26.3.27"
	xrayBaseURL = "https://github.com/XTLS/Xray-core/releases/download/" + xrayVersion + "/"
	runnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
	// dc2 is Telegram's DC2 (Global Constraints).
	dc2 = "149.154.167.51:443"
	// httpsSite is the site of the TLS check through WARP.
	httpsSite = "example.com:443"
	// testLabel marks every container of these tests.
	testLabel = "postern.test"
)

// goldenFiles are the golden configs of package xray, embedded so that the test
// binary needs no checkout.
//
//go:embed xray/testdata/*.json
var goldenFiles embed.FS

type itest struct {
	docker dockerapi.Client
	run    string // random id of this run
	base   string // scratch directory of this run (0700)
	xray   string // host path of the verified xray binary
	probe  string // host path of the probe: a copy of this test binary
}

// ---- setup --------------------------------------------------------------------------

func newITest(t *testing.T) *itest {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	docker := dockerapi.New("")
	pingCtx, pingCancel := context.WithTimeout(ctx, 15*time.Second)
	defer pingCancel()
	if _, err := docker.Ping(pingCtx); err != nil {
		t.Fatalf("no usable Docker daemon at %s: %v", dockerapi.DefaultSocket, err)
	}
	e := &itest{docker: docker, run: strings.ToLower(rand.Text())[:10]}
	e.sweep(t, ctx)
	if ok, err := docker.ImageExists(ctx, runnerImage); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := docker.Pull(ctx, runnerImage); err != nil {
			t.Fatal(err)
		}
	}

	base, err := os.MkdirTemp("", "postern-itest-providers-")
	if err != nil {
		t.Fatal(err)
	}
	e.base = base
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Logf("could not remove %s: %v", base, err)
		}
	})
	e.xray = e.downloadXray(t, ctx)
	e.probe = e.copyProbe(t)
	return e
}

// sweep removes the containers an earlier run left behind when it was killed
// before its cleanup (by a timeout, say). Only containers with the label of
// these tests are touched.
func (e *itest) sweep(t *testing.T, ctx context.Context) {
	t.Helper()
	left, err := e.docker.List(ctx, map[string]string{testLabel: "providers"}, true)
	if err != nil {
		t.Fatalf("listing the containers of earlier runs: %v", err)
	}
	for _, c := range left {
		if err := e.docker.Remove(ctx, c.ID, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			t.Fatalf("removing %s, left by an earlier run: %v", c.Name, err)
		}
		t.Logf("removed %s, left by an earlier run", c.Name)
	}
}

// downloadXray fetches the release archive of this architecture and its .dgst,
// stores the archive with the checksum of the .dgst, and returns the path of
// the binary. Network trouble skips the test; a mismatch fails it.
func (e *itest) downloadXray(t *testing.T, ctx context.Context) string {
	t.Helper()
	file, err := xray.New().ArtifactFile(runtime.GOARCH)
	if err != nil {
		t.Skipf("no Xray release for %s: %v", runtime.GOARCH, err)
	}
	dgst := fetch(t, ctx, xrayBaseURL+file+".dgst", 64<<10)
	sum, err := sha256OfDgst(dgst)
	if err != nil {
		t.Fatalf("%s.dgst: %v", file, err)
	}
	ref := artifacts.Ref{
		Engine: "xray", Version: xrayVersion, Arch: runtime.GOARCH,
		SHA256: sum, FileName: file, Binary: xray.New().BinaryName(),
	}
	store := &artifacts.Store{Root: filepath.Join(e.base, "artifacts")}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, xrayBaseURL+file, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		t.Skipf("cannot download %s: %v", file, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", file, resp.Status)
	}
	switch err := store.Put(ref, resp.Body); {
	case errors.Is(err, artifacts.ErrChecksum):
		t.Fatalf("the download does not match its .dgst: %v", err)
	case errors.Is(err, artifacts.ErrArchive), errors.Is(err, artifacts.ErrTooLarge):
		t.Fatalf("the download is not a usable release archive: %v", err)
	case err != nil:
		t.Skipf("the download of %s did not complete: %v", file, err)
	}
	bin := store.BinaryPath(ref)
	if info, err := os.Stat(bin); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("stored binary: %v, %v", info, err)
	}
	t.Logf("Xray %s: %s, sha256 %s (from its .dgst), extracted from the zip", xrayVersion, file, sum)
	return bin
}

func fetch(t *testing.T, ctx context.Context, url string, limit int64) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		t.Skipf("cannot download %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		t.Skipf("cannot download %s: %v", url, err)
	}
	return b
}

// sha256OfDgst reads the "SHA2-256= <hex>" line of a release .dgst file.
func sha256OfDgst(dgst []byte) (string, error) {
	for line := range strings.SplitSeq(string(dgst), "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "SHA2-256=")
		if !ok {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if b, err := hex.DecodeString(v); err != nil || len(b) != 32 {
			return "", errors.New("the SHA2-256 line is not 64 hex digits")
		}
		return v, nil
	}
	return "", errors.New("no SHA2-256 line")
}

func TestSHA256OfDgst(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	got, err := sha256OfDgst([]byte("MD5= 00\nSHA1= 11\nSHA2-256= " + strings.ToUpper(sum) + "\r\nSHA2-512= 22\n"))
	if err != nil || got != sum {
		t.Errorf("sha256OfDgst = %q, %v", got, err)
	}
	for _, bad := range []string{"", "SHA1= 11\n", "SHA2-256= 1234\n", "SHA2-256=" + strings.Repeat("zz", 32)} {
		if _, err := sha256OfDgst([]byte(bad)); err == nil {
			t.Errorf("sha256OfDgst(%q) succeeded", bad)
		}
	}
}

// copyProbe copies this test binary into the scratch directory, from where the
// probe containers mount it.
func (e *itest) copyProbe(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(e.base, "probe")
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
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

// newDir makes a directory the containers (user 65534) can read. It is inside
// the scratch directory, which is 0700: others cannot get at what is in it on
// the host; a container sees only what is mounted into it.
func (e *itest) newDir(t *testing.T, tag string) string {
	t.Helper()
	dir, err := os.MkdirTemp(e.base, tag+"-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	// 0644: the container's user (65534) is not the owner. The agent writes
	// these 0600 and gives them to 65534.
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---- Xray, offline ----------------------------------------------------------------------

func TestIntegrationXray(t *testing.T) {
	e := newITest(t)
	t.Run("configs", e.testConfigs)
	t.Run("vless", e.testVLESS)
	t.Run("crashers", e.testCrashers)
}

func newUUID(t *testing.T) string {
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

// testVLESS runs a member that carries data: a VLESS server and the member in
// front of it, and the probe's echo through the member.
func (e *itest) testVLESS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	uuid := newUUID(t)
	serverPort := pickPort(t, 40000, 41000)
	memberPort := pickPort(t, providers.MinPort, providers.MaxPort+1)

	// The server: the same binary, VLESS without TLS on the loopback, out to
	// anywhere (the echo server is on the loopback too).
	srvDir := e.newDir(t, "server")
	serverConfig := fmt.Sprintf(`{
  "log": {"loglevel": "warning", "access": "none"},
  "inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
    "settings": {"clients": [{"id": %q}], "decryption": "none"},
    "streamSettings": {"network": "raw", "security": "none"}}],
  "outbounds": [{"protocol": "freedom"}]
}
`, serverPort, uuid)
	writeFile(t, filepath.Join(srvDir, "server.json"), []byte(serverConfig))
	srvID := e.startContainer(t, ctx, "vless-server", dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534",
		NetworkMode: "host",
		Entrypoint:  []string{"/opt/engine/xray", "run", "-c", "/etc/egress/server.json"},
		Binds:       []string{e.xray + ":/opt/engine/xray:ro", srvDir + ":/etc/egress:ro"},
	})

	// The member, as the agent will make it.
	server := &egressuri.Server{
		Protocol: "vless", Address: "vless-server.test", Port: serverPort, ID: uuid, Network: "tcp", Security: "none",
	}
	cliDir := e.newDir(t, "client")
	in := providers.Instance{
		EgressID:    "ITEST" + strings.ToUpper(e.run),
		Generation:  1,
		Kind:        nodev1.EgressKind_EGRESS_KIND_XRAY_URI,
		Members:     []providers.Member{{Key: server.Key(), Port: memberPort, Server: server}},
		InstanceDir: cliDir,
		BinaryPath:  e.xray,
		RunnerImage: runnerImage,
	}
	// The loopback itself is refused as a server address.
	literal := *server
	literal.Address = "127.0.0.1"
	lit := in
	lit.Members = []providers.Member{{Key: server.Key(), Port: memberPort, Server: &literal}}
	if _, err := xray.New().Render(lit); len(providers.MemberErrors(err)) != 1 {
		t.Fatalf("Render of a server on 127.0.0.1 = %v, want a member error", err)
	}

	files, err := xray.New().Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		writeFile(t, filepath.Join(cliDir, name), data)
	}
	if err := in.CheckHostPaths(); err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(e.base, "hosts")
	writeFile(t, hosts, []byte("127.0.0.1 localhost\n127.0.0.1 vless-server.test\n"))

	spec := xray.New().Container(in)
	spec.Binds = append(spec.Binds, hosts+":/etc/hosts:ro")
	cliID := e.startContainer(t, ctx, "vless-client", spec)

	exit, out := e.runProbe(t, ctx, "probe-vless", 2*time.Minute,
		"-ports", strconv.Itoa(int(memberPort)), "-wait", "60s", "-echo", "-loopback-only")
	if exit != 0 {
		t.Fatalf("the probe failed (exit %d):\n%s\nclient log:\n%s\nserver log:\n%s", exit, out, e.logs(t, cliID), e.logs(t, srvID))
	}
	t.Logf("probe:\n%s", strings.TrimSpace(out))

	for _, id := range []string{cliID, srvID} {
		if err := e.stillRunning(ctx, id); err != nil {
			t.Error(err)
		}
	}
	if log := e.logs(t, cliID); strings.Contains(log, uuid) {
		t.Error("the client log holds the id of the server's user")
	} else {
		t.Logf("client log (%d bytes): %s", len(log), strings.TrimSpace(log))
	}
}

// ---- WARP, online ---------------------------------------------------------------------

// warpSummary is what TestIntegrationWARPOnline reports, without credentials.
type warpSummary struct {
	registered, endpoint, xray, dc, tls, device string
}

func (s warpSummary) String() string {
	or := func(v string) string {
		if v == "" {
			return "not reached"
		}
		return v
	}
	return fmt.Sprintf("WARP online check (Xray %s):\n"+
		"  registered:   %s\n"+
		"  endpoint:     %s\n"+
		"  xray member:  %s\n"+
		"  telegram dc:  %s\n"+
		"  https site:   %s\n"+
		"  device:       %s",
		xrayVersion, or(s.registered), or(s.endpoint), or(s.xray), or(s.dc), or(s.tls), or(s.device))
}

// fill takes the results of the probe's checks ("ok <check>: ..." or
// "FAIL <check>: ...") into the summary.
func (s *warpSummary) fill(out string, port uint16) {
	for line := range strings.SplitSeq(out, "\n") {
		verdict, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
		check, msg, _ := strings.Cut(rest, ": ")
		result := strings.ToLower(verdict) + ": " + msg
		switch check {
		case "ready":
			s.xray = result + fmt.Sprintf(" (127.0.0.1:%d)", port)
		case "dc":
			s.dc = result
		case "tls":
			s.tls = result
		}
	}
}

func TestWARPSummary(t *testing.T) {
	var s warpSummary
	s.registered, s.endpoint = "yes", "warp.example.com:2408"
	s.fill("ok ready: every member port answers the SOCKS5 greeting (after 1s)\n"+
		"FAIL dc: CONNECT to 149.154.167.51:443 acknowledged, but no answer came back: i/o timeout\n"+
		"garbage line\n", 35123)
	got := s.String()
	for _, want := range []string{
		"registered:   yes", "endpoint:     warp.example.com:2408",
		"xray member:  ok: every member port answers the SOCKS5 greeting (after 1s) (127.0.0.1:35123)",
		"telegram dc:  fail: CONNECT to 149.154.167.51:443 acknowledged, but no answer came back: i/o timeout",
		"https site:   not reached", "device:       not reached",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary lacks %q:\n%s", want, got)
		}
	}
}

// TestIntegrationWARPOnline registers a WARP device, runs a WARP member on it,
// and goes through it to a Telegram datacenter and to an HTTPS site. Only with
// POSTERN_E2E_ONLINE=1: it talks to Cloudflare's API and makes a device there
// (deleted at the end).
func TestIntegrationWARPOnline(t *testing.T) {
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Skip("set POSTERN_E2E_ONLINE=1 to register a WARP device and go through it")
	}
	e := newITest(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	var sum warpSummary
	var acct *warp.Account
	acctPath := filepath.Join(e.base, "warp-account.json")
	// Runs on a failure too (t.Fatal ends the test function through its
	// deferred calls): the device is deleted (also one whose registration
	// stopped half-way and was kept in the file), then the summary is printed.
	// The containers go in the cleanups of the test, after this.
	defer func() {
		if acct == nil {
			acct = keptRegistration(acctPath)
		}
		if acct != nil {
			sum.device = deleteWARPDevice(acct)
		}
		t.Logf("\n%s", sum)
	}()

	a, created, err := warp.LoadOrRegister(ctx, nil, acctPath)
	if err != nil {
		sum.registered = "no: " + err.Error() // never holds a credential
		t.Fatalf("WARP registration: %v", err)
	}
	acct = a
	sum.registered = "yes"
	sum.endpoint = acct.Endpoint
	if !created {
		t.Fatal("LoadOrRegister found an account file in a fresh directory")
	}

	dir := e.newDir(t, "warp")
	in := providers.Instance{
		EgressID:    "ITESTWARP" + strings.ToUpper(e.run),
		Generation:  1,
		Kind:        nodev1.EgressKind_EGRESS_KIND_WARP,
		Members:     []providers.Member{{Key: "warp", Port: pickPort(t, providers.MinPort, providers.MaxPort+1), WARP: acct}},
		InstanceDir: dir,
		BinaryPath:  e.xray,
		RunnerImage: runnerImage,
	}
	files, err := xray.New().Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		writeFile(t, filepath.Join(dir, name), data)
	}
	if err := in.CheckHostPaths(); err != nil {
		t.Fatal(err)
	}
	id := e.startContainer(t, ctx, "warp", xray.New().Container(in))

	exit, out := e.runProbe(t, ctx, "probe-warp", 3*time.Minute,
		"-ports", strconv.Itoa(int(in.Members[0].Port)), "-wait", "60s", "-dc", dc2, "-tls", httpsSite)
	sum.fill(out, in.Members[0].Port)
	log := e.logs(t, id)
	for _, secret := range []string{acct.PrivateKey, acct.Token} {
		if strings.Contains(log, secret) || strings.Contains(out, secret) {
			t.Error("the Xray log or the probe holds a credential of the WARP account; log withheld")
			log = "(withheld)"
		}
	}
	if exit != 0 {
		// A network that drops WireGuard, or UDP to the endpoint, shows here as
		// timeouts: Xray acknowledges the CONNECT and its handshake with the
		// endpoint never completes (visible only at loglevel debug).
		t.Fatalf("the probe through WARP failed (exit %d); timeouts mean no data came back through the tunnel "+
			"(is WireGuard to the WARP endpoint blocked on this network?):\n%s\nxray log:\n%s", exit, out, log)
	}
}

// deleteWARPDevice deletes the test's device (warp.Delete) and says how it went.
func deleteWARPDevice(a *warp.Account) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := warp.Delete(ctx, nil, a); err != nil {
		return "not deleted: " + err.Error() // never holds the token
	}
	return "deleted"
}

// keptRegistration is the device that a LoadOrRegister which stopped half-way
// kept in the account file, or nil.
func keptRegistration(path string) *warp.Account {
	a, err := warp.LoadRegistration(path)
	if err != nil {
		return nil
	}
	return a
}

// ---- containers -----------------------------------------------------------------------

func (e *itest) labels() map[string]string {
	return map[string]string{testLabel: "providers", "postern.id": "itest-" + e.run}
}

func (e *itest) name(tag string) string {
	return "postern-test-" + e.run + "-" + tag + "-" + strings.ToLower(rand.Text())[:6]
}

// startContainer creates and starts a long-running container, removed when the
// test ends, also when it fails.
func (e *itest) startContainer(t *testing.T, ctx context.Context, tag string, spec dockerapi.ContainerSpec) string {
	t.Helper()
	spec.Name = e.name(tag)
	spec.Labels = e.labels()
	spec.RestartPolicy = "no"
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create %s: %v", tag, err)
	}
	t.Cleanup(func() { e.remove(t, id, spec.Name) })
	if err := e.docker.Start(ctx, id); err != nil {
		t.Fatalf("start %s: %v", tag, err)
	}
	return id
}

// runProbe runs the probe (this test binary, see probe_integration_test.go) in
// a container on the host network with args, and returns its exit code and
// output.
func (e *itest) runProbe(t *testing.T, ctx context.Context, tag string, limit time.Duration, args ...string) (int, string) {
	t.Helper()
	return e.runHelper(t, ctx, tag, dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534",
		NetworkMode: "host",
		Entrypoint:  append([]string{"/opt/probe"}, args...),
		Env:         []string{probeEnv + "=1"},
		Binds:       []string{e.probe + ":/opt/probe:ro"},
	}, limit)
}

// runHelper runs a short-lived, locked-down container to its end and returns
// its exit code and output.
func (e *itest) runHelper(t *testing.T, ctx context.Context, tag string, spec dockerapi.ContainerSpec, limit time.Duration) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	spec.Name = e.name(tag)
	spec.Labels = e.labels()
	spec.RestartPolicy = "no"
	spec.CapDrop = []string{"ALL"}
	spec.SecurityOpt = []string{"no-new-privileges:true"}
	spec.ReadOnly = true
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create helper %s: %v", tag, err)
	}
	defer e.remove(t, id, spec.Name)
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
		select {
		case <-ctx.Done():
			t.Fatalf("helper %s did not finish within %v\n%s", tag, limit, e.logs(t, id))
		case <-time.After(250 * time.Millisecond):
		}
	}
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
	b, err := io.ReadAll(io.LimitReader(rc, 4<<20))
	if err != nil {
		t.Fatalf("logs of %s: %v", id[:12], err)
	}
	return string(b)
}

func (e *itest) stillRunning(ctx context.Context, id string) error {
	d, err := e.docker.Inspect(ctx, id)
	if err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
	if d.State != "running" {
		return fmt.Errorf("container %s is %s (exit code %d)", d.Name, d.State, d.ExitCode)
	}
	return nil
}

func (e *itest) remove(t *testing.T, id, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.docker.Remove(ctx, id, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
		t.Errorf("removing container %s (%s): %v", name, id[:12], err)
	}
}
