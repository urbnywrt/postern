//go:build integration

package reconcile

// This test runs the DNS of a node with the real Docker daemon:
//
//	go test -tags integration -run DNS ./internal/node/reconcile/
//
// It needs a Docker daemon at dockerapi.DefaultSocket and the Go toolchain (it
// builds the node binary and a helper); it does not need the internet. Three
// containers on the host network:
//
//   - a DNS-over-HTTPS endpoint, testdata/fakedoh, on 127.0.0.1 with a
//     certificate for that address, signed by a CA of the test; it answers from
//     a zone of its own;
//   - the real edge, the node binary in the container of edgeSpec (root without
//     capabilities but NET_BIND_SERVICE, a read-only root file system), with a
//     configuration whose forwarder asks that endpoint, and whose fallback is a
//     port where nothing answers: no answer can come from the host's
//     nameservers, as on a node where UDP port 53 is blocked. SSL_CERT_FILE
//     makes it trust the CA of the test;
//   - a container made as the reconciler makes an engine's: the spec of the
//     telemt driver with the resolv.conf the reconciler writes, mounted at
//     /etc/resolv.conf, running musl's resolver (getent) instead of telemt.
//
// It checks that the edge binds 127.0.0.2:53 in its container, that Docker
// honours the bind mount at /etc/resolv.conf on the host network, and that the
// engine's container resolves names through the forwarder: an answer that fits
// UDP, and one that does not, which musl asks for again over TCP.
//
// Every container is named postern-test-<run>-<tag>, labelled
// postern.test=dns-forwarder, and force-removed at the end; the restart policy
// is "no".
//
// The test needs 127.0.0.2:53 of the daemon's host network for itself. When
// something holds it already, the edge of a node that runs on the Docker host
// for instance, the test is skipped: its edge would join the reuseport group of
// that one (both run as root) and share its queries, and the test would talk to
// a forwarder that is not the one under test.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/edge/control"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/node/state"
)

type dnsITest struct {
	t      *testing.T
	docker dockerapi.Client
	run    string
	base   string
}

func TestIntegrationEngineResolvesThroughTheForwarder(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	e := newDNSITest(t, ctx)
	e.skipWhenTheForwarderAddressIsTaken(ctx)

	// The binaries, for the daemon's architecture.
	nodeBin := e.build(ctx, "postern-node", "../../../cmd/node")
	dohBin := e.build(ctx, "fakedoh", "./testdata/fakedoh")

	// The CA of the test, and the certificate of the endpoint for 127.0.0.1.
	certs := e.dir("certs", 0o755)
	writeTestPKI(t, certs)

	// The node's layout. The edge runs as root without capabilities, so without
	// CAP_DAC_OVERRIDE: its directories must be writable for it as they are on
	// a node, where root owns them.
	paths := state.Paths{Home: e.dir("home", 0o755)}
	for _, d := range []string{paths.EdgeDir(), paths.RunDir(), paths.CertsDir()} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
	}

	dohPort := 40000 + mrand.IntN(500)
	deadPort := 40500 + mrand.IntN(500) // nothing listens there: the fallback gets no answer
	dohURL := fmt.Sprintf("https://127.0.0.1:%d/dns-query", dohPort)

	// 1. The DNS-over-HTTPS endpoint.
	e.start(ctx, "doh", dockerapi.ContainerSpec{
		Image: runnerImage, User: "65534:65534", NetworkMode: "host", ReadOnly: true,
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
		Entrypoint: []string{"/opt/fakedoh", "-listen", "127.0.0.1:" + strconv.Itoa(dohPort),
			"-cert", "/opt/certs/cert.pem", "-key", "/opt/certs/key.pem"},
		Binds: []string{dohBin + ":/opt/fakedoh:ro", certs + ":/opt/certs:ro"},
	})

	// 2. The edge, from its configuration file, as the reconciler makes it.
	cfg := &edgev1.EdgeConfig{
		Generation: 1,
		Dns: &edgev1.Dns{
			Enabled:  true,
			DohUrls:  []string{dohURL},
			Fallback: []string{"127.0.0.1:" + strconv.Itoa(deadPort)},
		},
	}
	if err := control.SaveConfig(paths.EdgeConfigPath(1), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.EdgeConfigPath(1), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{Store: &state.Store{Paths: paths}, NodeBinaryPath: nodeBin, RunnerImage: runnerImage}
	edgeSpec := r.edgeSpec(1, false, r.NodeBinaryPath)
	edgeSpec.Env = append(edgeSpec.Env, "SSL_CERT_FILE=/opt/certs/ca.pem")
	edgeSpec.Binds = append(edgeSpec.Binds, certs+":/opt/certs:ro")
	edgeID := e.start(ctx, "edge", edgeSpec)

	// 3. The resolv.conf, as a pass in DNS mode doh writes it.
	// The pass knows that the forwarder runs, as it does once the edge has said
	// so (Health dns); the test cannot ask it itself: on Docker Desktop the
	// socket of the edge is in another machine.
	p := &pass{
		r:  r,
		st: &nodev1.NodeState{Settings: &nodev1.NodeSettings{DnsMode: "doh"}},
		rt: &state.Runtime{EdgeDNS: true},
	}
	if err := p.prepareDNS(); err != nil {
		t.Fatalf("prepareDNS: %v", err)
	}
	resolvConf := p.resolvConf()
	if resolvConf != paths.ResolvConfPath() {
		t.Fatalf("resolvConf = %q", resolvConf)
	}

	// 4. A container as the reconciler makes an engine's, with musl's resolver
	// in place of telemt.
	inst := engines.Instance{
		Proxy:       &nodev1.Proxy{Id: "ITEST" + strings.ToUpper(e.run)},
		InstanceID:  "itest",
		Generation:  1,
		InstanceDir: e.dir("instance", 0o755),
		BinaryPath:  e.file("telemt", 0o755),
		RunnerImage: runnerImage,
	}
	engSpec := withResolvConf(telemt.New().Container(inst), resolvConf)
	engSpec.Entrypoint = []string{"/bin/sh", "-c", `
i=0
until getent hosts www.example.com > /tmp/www; do
  i=$((i+1)); [ $i -lt 100 ] || { echo "www.example.com does not resolve"; exit 3; }
  sleep 0.2
done
echo "www: $(cat /tmp/www)"
echo "big: $(getent ahosts big.example.com | awk '{print $1}' | sort -u | wc -l)"
if getent hosts missing.example.com; then echo "missing: resolved"; else echo "missing: not found"; fi
echo "resolv.conf: $(tr '\n' '|' < /etc/resolv.conf)"
`}
	exit, out := e.runToEnd(ctx, "engine", engSpec, 2*time.Minute)
	edgeLog := e.logs(edgeID)
	t.Logf("engine container (exit %d):\n%s", exit, out)
	if exit != 0 {
		t.Fatalf("the engine container could not resolve (exit %d)\nedge log:\n%s\nendpoint log:\n%s", exit, edgeLog, e.logsByTag("doh"))
	}

	if !strings.Contains(out, "www: 192.0.2.10") {
		t.Errorf("www.example.com did not resolve to the endpoint's 192.0.2.10:\n%s", out)
	}
	if !strings.Contains(out, "big: 40") {
		t.Errorf("big.example.com did not resolve to its 40 addresses (over TCP after a truncated UDP answer):\n%s", out)
	}
	if !strings.Contains(out, "missing: not found") {
		t.Errorf("a name that does not exist resolved:\n%s", out)
	}
	if want := "resolv.conf: nameserver 127.0.0.2|options timeout:2 attempts:2|"; !strings.Contains(out, want) {
		t.Errorf("the container does not see the resolv.conf of the reconciler at /etc/resolv.conf (Docker did not honour the bind mount?):\n%s", out)
	}
	if !strings.Contains(edgeLog, "dns: forwarder listening") || !strings.Contains(edgeLog, "addr=127.0.0.2:53") {
		t.Errorf("the edge does not say that its forwarder listens on 127.0.0.2:53:\n%s", edgeLog)
	}
	dohLog := e.logsByTag("doh")
	if !strings.Contains(dohLog, "big.example.com.") {
		t.Errorf("the endpoint was not asked for big.example.com:\n%s", dohLog)
	}
	t.Logf("edge log:\n%s", edgeLog)
	t.Logf("endpoint log:\n%s", dohLog)
}

// ---- the rig ------------------------------------------------------------------

// skipWhenTheForwarderAddressIsTaken skips the test when a socket of the
// daemon's host network holds 127.0.0.2:53, or port 53 of every address, UDP or
// TCP, IPv4 or IPv6: it looks at /proc/net from a container on that network.
func (e *dnsITest) skipWhenTheForwarderAddressIsTaken(ctx context.Context) {
	e.t.Helper()
	exit, out := e.runToEnd(ctx, "probe", dockerapi.ContainerSpec{
		Image: runnerImage, User: "65534:65534", NetworkMode: "host", ReadOnly: true,
		CapDrop: []string{"ALL"}, Entrypoint: []string{"/bin/sh", "-c", forwarderPortProbe},
	}, time.Minute)
	if exit != 0 {
		e.t.Fatalf("looking at the sockets of the host network failed (exit %d): %s", exit, out)
	}
	if strings.TrimSpace(out) != "" {
		e.t.Skipf("127.0.0.2:53 (or port 53 of every address) is taken on the daemon's host network, by the edge of a node that runs there perhaps; the test needs it for its own edge:\n%s", out)
	}
}

// forwarderPortProbe prints the sockets in /proc/net that hold port 53 of
// 127.0.0.2: TCP sockets that listen (st 0A) and UDP sockets that are bound and
// not connected (st 07), on that address, on every address, IPv4 or IPv6 (a
// socket on every IPv6 address takes the IPv4 ones too unless it is IPv6 only,
// which the files do not tell), or on 127.0.0.2 mapped into IPv6. Sockets in
// other states, such as the connections of an earlier test, take nothing. The
// files write the local address as hex in the byte order of the host; amd64 and
// arm64 are little-endian: 127.0.0.2:53 is 0200007F:0035. A file that is not
// there (a host without IPv6) is left out.
const forwarderPortProbe = `set --
for f in /proc/net/tcp /proc/net/udp /proc/net/tcp6 /proc/net/udp6; do
	if [ -r "$f" ]; then set -- "$@" "$f"; fi
done
awk 'FNR > 1 && ((FILENAME ~ /tcp/ && $4 == "0A") || (FILENAME ~ /udp/ && $4 == "07")) &&
	($2 == "0200007F:0035" || $2 == "00000000:0035" ||
	 $2 == "0000000000000000FFFF00000200007F:0035" || $2 == "00000000000000000000000000000000:0035") { print FILENAME, $2, $4 }' "$@"
`

func newDNSITest(t *testing.T, ctx context.Context) *dnsITest {
	t.Helper()
	docker := dockerapi.New("")
	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
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
	base, err := os.MkdirTemp("", "postern-itest-dns-")
	if err != nil {
		t.Fatal(err)
	}
	e := &dnsITest{t: t, docker: docker, run: strings.ToLower(rand.Text())[:10], base: base}
	t.Cleanup(func() { e.removeTree(base) })
	return e
}

func (e *dnsITest) labels() map[string]string {
	return map[string]string{"postern.test": "dns-forwarder", "postern.id": "itest-" + e.run}
}

func (e *dnsITest) name(tag string) string { return "postern-test-" + e.run + "-" + tag }

func (e *dnsITest) dir(name string, mode os.FileMode) string {
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

func (e *dnsITest) file(name string, mode os.FileMode) string {
	e.t.Helper()
	p := filepath.Join(e.base, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), mode); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		e.t.Fatal(err)
	}
	return p
}

// build builds a static binary of pkg for the daemon's architecture.
func (e *dnsITest) build(ctx context.Context, name, pkg string) string {
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

// start creates and starts a container that runs until the end of the test.
func (e *dnsITest) start(ctx context.Context, tag string, spec dockerapi.ContainerSpec) string {
	e.t.Helper()
	spec.Name, spec.Labels, spec.RestartPolicy = e.name(tag), e.labels(), "no"
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		e.t.Fatalf("create %s: %v", tag, err)
	}
	e.t.Cleanup(func() { e.remove(id, spec.Name) })
	if err := e.docker.Start(ctx, id); err != nil {
		e.t.Fatalf("start %s: %v", tag, err)
	}
	return id
}

// runToEnd runs a container until it exits, and returns its exit code and log.
func (e *dnsITest) runToEnd(ctx context.Context, tag string, spec dockerapi.ContainerSpec, limit time.Duration) (int, string) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	id := e.start(ctx, tag, spec)
	for {
		d, err := e.docker.Inspect(ctx, id)
		if err != nil {
			e.t.Fatalf("inspect %s: %v", tag, err)
		}
		if d.State == "exited" || d.State == "dead" {
			return d.ExitCode, e.logs(id)
		}
		select {
		case <-ctx.Done():
			e.t.Fatalf("%s did not finish within %v:\n%s", tag, limit, e.logs(id))
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (e *dnsITest) logs(id string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc, err := e.docker.Logs(ctx, id, -1, false)
	if err != nil {
		return fmt.Sprintf("(no log: %v)", err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
	return strings.TrimSpace(string(b))
}

func (e *dnsITest) logsByTag(tag string) string { return e.logs(e.name(tag)) }

func (e *dnsITest) remove(id, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.docker.Remove(ctx, id, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
		e.t.Errorf("removing container %s: %v", name, err)
	}
}

// removeTree deletes the scratch directory; what root left in it (the edge's
// socket) goes with it, the directories being the test's.
func (e *dnsITest) removeTree(dir string) {
	if err := os.RemoveAll(dir); err == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id, err := e.docker.Create(ctx, dockerapi.ContainerSpec{
		Name: e.name("rm"), Image: runnerImage, NetworkMode: "none", Labels: e.labels(), RestartPolicy: "no",
		Entrypoint: []string{"/bin/sh", "-c", "rm -rf /scratch/* /scratch/.[!.]*"},
		Binds:      []string{dir + ":/scratch"},
	})
	if err != nil {
		e.t.Logf("could not remove %s: %v", dir, err)
		return
	}
	defer e.remove(id, e.name("rm"))
	if err := e.docker.Start(ctx, id); err == nil {
		for ctx.Err() == nil {
			if d, err := e.docker.Inspect(ctx, id); err != nil || d.State == "exited" {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		e.t.Logf("could not remove %s: %v", dir, err)
	}
}

// writeTestPKI writes ca.pem, and cert.pem and key.pem of a server certificate
// for 127.0.0.1 signed by it, readable by the containers.
func writeTestPKI(t *testing.T, dir string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "postern integration test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"ca.pem":   {Type: "CERTIFICATE", Bytes: caDER},
		"cert.pem": {Type: "CERTIFICATE", Bytes: der},
		"key.pem":  {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
