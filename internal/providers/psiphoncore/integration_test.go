//go:build integration

package psiphoncore

// TestIntegrationPsiphonOnline runs the Psiphon client that a release of
// Postern builds, as the agent runs it: in the runner image, on the host
// network, as 65534, with a read-only root, the container of Driver.Container
// and the psiphon.json of Driver.Render. It waits for Driver.Ready and then
// fetches the exit address through the SOCKS5 port, the host name resolved by
// the tunnel (as curl --socks5-hostname does).
//
//	bash scripts/psiphon-core.sh /tmp/psiphon-core
//	POSTERN_E2E_ONLINE=1 POSTERN_ITEST_PSIPHON_CORE=/tmp/psiphon-core \
//	  bash scripts/itest.sh ./internal/providers/psiphoncore -test.run TestIntegrationPsiphonOnline
//
// It is skipped without POSTERN_E2E_ONLINE=1 or POSTERN_ITEST_PSIPHON_CORE (the
// directory of the build). It needs a Docker daemon at dockerapi.DefaultSocket;
// with Docker Desktop, scripts/itest.sh runs it in a container on the daemon's
// host network.

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/providers"
)

func TestIntegrationPsiphonOnline(t *testing.T) {
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Skip("POSTERN_E2E_ONLINE=1 runs it: it needs the Internet and Psiphon")
	}
	dir := os.Getenv("POSTERN_ITEST_PSIPHON_CORE")
	if dir == "" {
		t.Skip("set POSTERN_ITEST_PSIPHON_CORE to the directory of scripts/psiphon-core.sh")
	}
	file, err := Driver{}.ArtifactFile(runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	docker := dockerapi.New("")
	if _, err := docker.Ping(ctx); err != nil {
		t.Fatalf("no usable Docker daemon at %s: %v", dockerapi.DefaultSocket, err)
	}
	if ok, err := docker.ImageExists(ctx, runnerImage); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := docker.Pull(ctx, runnerImage); err != nil {
			t.Fatal(err)
		}
	}

	// The host paths, readable (the cache writable) by 65534, as the agent makes them.
	// Not t.TempDir: the container leaves files of 65534 that the test cannot
	// remove; scripts/itest.sh removes its scratch directory as root.
	work, err := os.MkdirTemp("", "psiphon-itest-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	if err := os.Chmod(work, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(work, Binary)
	data, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	instance, cache := filepath.Join(work, "g1"), filepath.Join(work, "cache-g1")
	for _, d := range []string{instance, cache} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(cache, 0o777); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	in := providers.Instance{
		EgressID: "itest-" + strings.ToLower(rand.Text()[:8]), Generation: 1, Kind: nodev1.EgressKind_EGRESS_KIND_PSIPHON, Country: "DE",
		Members:     []providers.Member{{Key: "psiphon", Port: providers.MinPort}},
		InstanceDir: instance, CacheDir: cache, BinaryPath: bin, RunnerImage: runnerImage,
	}
	// Render checks the port range of the agent; the test takes a free port.
	files, err := Driver{}.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	conf := strings.Replace(string(files[ConfigFile]), `"LocalSocksProxyPort": 35000`, `"LocalSocksProxyPort": `+strconv.Itoa(int(port)), 1)
	in.Members[0].Port = port
	if err := os.WriteFile(filepath.Join(instance, ConfigFile), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := in.CheckHostPaths(); err != nil {
		t.Fatal(err)
	}

	spec := Driver{}.Container(in)
	spec.Name = "postern-test-" + in.EgressID
	spec.RestartPolicy = "no"
	spec.Labels["postern.test"] = "psiphon"
	id, err := docker.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if t.Failed() {
			t.Logf("psiphon.json:\n%s", conf)
			rc, err := docker.Logs(context.Background(), id, 200, false)
			if err != nil {
				t.Logf("no logs: %v", err)
			} else {
				out, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
				_ = rc.Close()
				t.Logf("client output (last lines):\n%s", out)
			}
		}
		_ = docker.Remove(context.Background(), id, true)
	}()
	if err := docker.Start(ctx, id); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	var last error
	for {
		if last = (Driver{}).Ready(ctx, in); last == nil {
			break
		}
		if d, err := docker.Inspect(ctx, id); err == nil && d.State != "running" {
			t.Fatalf("the container is %s (exit code %d)", d.State, d.ExitCode)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no tunnel after %v: %v", time.Since(start).Round(time.Second), last)
		case <-time.After(time.Second):
		}
	}
	t.Logf("tunnel up after %v, in the runner image", time.Since(start).Round(time.Second))
	if err := socksConnect(ctx, port, ProbeAddr); err != nil {
		t.Errorf("the CONNECT of Ready to %s through the tunnel: %v", ProbeAddr, err)
	}

	exit, err := exitAddress(ctx, port, "api.ipify.org")
	if err != nil {
		t.Fatalf("the exit address through the tunnel: %v", err)
	}
	class := "public"
	if exit.IsPrivate() || exit.IsLoopback() || exit.IsUnspecified() {
		class = "not public"
	}
	t.Logf("exit address class: %s (IPv%d)", class, map[bool]int{true: 4, false: 6}[exit.To4() != nil])
	if class != "public" {
		t.Error("the exit address is not a public one")
	}
}

// exitAddress asks host for the address that it sees, over plain HTTP, through
// the SOCKS5 port: a CONNECT by name, which the tunnel resolves.
func exitAddress(ctx context.Context, port uint16, host string) (net.IP, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := SOCKSConnect(conn, append([]byte{3, byte(len(host))}, host...), 80); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil {
		return nil, errors.New("the answer is not an address")
	}
	return ip, nil
}
