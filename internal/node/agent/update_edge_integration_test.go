//go:build integration

package agent

// This test rolls a real edge to another agent build through UpdateEdge while a
// relayed connection is held, with the real Docker daemon:
//
//	mkdir -p /tmp/pn && for v in v9.9.8 v9.9.9; do
//	  CGO_ENABLED=0 go build -trimpath -ldflags "-X github.com/urbnywrt/postern/internal/version.Version=$v" \
//	    -o /tmp/pn/postern-node-$v ./cmd/node
//	done
//	POSTERN_ITEST_ROOT=1 POSTERN_ITEST_NODE_BINARIES=/tmp/pn \
//	  bash scripts/itest.sh ./internal/node/agent -test.run TestIntegrationUpdateEdge
//
// Without POSTERN_ITEST_NODE_BINARIES the test builds the two binaries itself,
// which needs the Go toolchain where it runs. It must run as root: the edge
// runs as root, and its control socket is root's (0600).
//
// The agent runs in the test process with a desired state of one listener on
// 127.0.0.1 whose strangers are masked to an echo server of the test. The
// agent starts edge generation 1 on v9.9.8. A client sends a TLS ClientHello
// with a name no proxy has (a stranger), so the edge relays the connection to
// the echo server, and then exchanges a byte every second. UpdateEdge(v9.9.9)
// rolls the edge: generation 2 starts beside 1 on bin/postern-node-v9.9.9,
// takes over, and 1 drains. The held connection must not break, and a new
// connection goes through generation 2.
//
// The edge containers are named postern-edge-g<N> as on a node: the test is
// skipped when such a container exists (another test or a node on the Docker
// host), and removes its own at the end.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/node/selfupdate/selfupdatetest"
	"github.com/urbnywrt/postern/internal/node/state"
)

func TestIntegrationUpdateEdge(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (the edge's control socket is root's): POSTERN_ITEST_ROOT=1 bash scripts/itest.sh ./internal/node/agent")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	docker := dockerapi.New("")
	if _, err := docker.Ping(ctx); err != nil {
		t.Fatalf("no usable Docker daemon: %v", err)
	}
	edges, err := docker.List(ctx, map[string]string{"postern.role": "edge"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) > 0 {
		t.Skipf("edge containers exist on this Docker host (%s ...): the test's would take their names", edges[0].Name)
	}
	if ok, err := docker.ImageExists(ctx, RunnerImage); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := docker.Pull(ctx, RunnerImage); err != nil {
			t.Fatalf("pulling the runner image: %v", err)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, name := range []string{"postern-edge-g1", "postern-edge-g2", "postern-edge-g3"} {
			if err := docker.Remove(ctx, name, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
				t.Logf("removing %s: %v", name, err)
			}
		}
	})

	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	bin := filepath.Join(home, "bin")
	old := filepath.Join(bin, "postern-node-v9.9.8")
	nodeBinaries(t, ctx, map[string]string{"v9.9.8": old, "v9.9.9": filepath.Join(bin, "postern-node-v9.9.9")})
	// v9.9.9 as UpdateSelf leaves it: signed by a release key of the agent's, the
	// signature kept beside it.
	signer := selfupdatetest.NewSigner(t)
	newData, err := os.ReadFile(filepath.Join(bin, "postern-node-v9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	sig := signer.Meta(t, newData, "v9.9.9", runtime.GOARCH).GetSignature()
	if err := os.WriteFile(filepath.Join(bin, ".postern-node-v9.9.9.minisig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}

	echo := tcpEchoServer(t)
	port := freePort(t, 41000, 60999)
	st := &nodev1.NodeState{
		Generation: 1,
		Settings:   &nodev1.NodeSettings{DefaultChainId: "default"},
		Listeners: []*nodev1.Listener{{
			Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "127.0.0.1", Port: uint32(port),
			StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_MASK, MaskTarget: echo,
		}},
		Egresses: []*nodev1.Egress{{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT}},
		Chains:   []*nodev1.EgressChain{{Id: "default", MemberEgressIds: []string{"direct"}}},
	}
	if err := (&state.Store{Paths: state.Paths{Home: home}}).SaveDesired(st); err != nil {
		t.Fatal(err)
	}

	stderr := &syncBuffer{}
	addr := make(chan net.Addr, 1)
	done := make(chan error, 1)
	actx, stop := context.WithCancel(ctx)
	go func() {
		done <- Run(actx, Options{
			Home: home, MgmtListen: "127.0.0.1:0", Stderr: stderr,
			osRelease:    []string{filepath.Join(home, "no-os-release")},
			addrs:        func() ([]net.Addr, error) { return []net.Addr{ipNet("203.0.113.10/24")}, nil },
			echoURLs:     []string{},
			meConfigURLs: []string{},
			nodeBinary:   old,
			releaseKeys:  signer.Keys,
			listening:    func(a net.Addr) { addr <- a },
			diagChecks:   []diag.Check{},
		})
	}()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the agent did not stop")
		}
		if t.Failed() {
			t.Logf("agent log:\n%s", stderr.String())
		}
	})
	var c interface {
		GetInfo(context.Context, *connect.Request[nodev1.GetInfoRequest]) (*connect.Response[nodev1.GetInfoResponse], error)
		UpdateEdge(context.Context, *connect.Request[nodev1.UpdateEdgeRequest]) (*connect.Response[nodev1.UpdateEdgeResponse], error)
	}
	select {
	case a := <-addr:
		c = p.client(t, a.String(), p.clientCert, p.clientKey)
	case err := <-done:
		t.Fatalf("the agent stopped: %v\n%s", err, stderr.String())
	case <-ctx.Done():
		t.Fatal("the agent did not listen")
	}

	// Generation 1 runs v9.9.8.
	waitUntilIT(t, ctx, "edge generation 1 on v9.9.8", func() bool {
		info, err := c.GetInfo(ctx, connect.NewRequest(&nodev1.GetInfoRequest{}))
		return err == nil && info.Msg.GetEdgeVersion() == "v9.9.8"
	})

	// A relayed connection, held across the roll.
	held := relayedConn(t, port)
	var (
		mu        sync.Mutex
		exchanged int
		broken    error
	)
	stopTalk := make(chan struct{})
	talked := make(chan struct{})
	go func() {
		defer close(talked)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		b := []byte{0}
		for i := 0; ; i++ {
			select {
			case <-stopTalk:
				return
			case <-tick.C:
			}
			b[0] = byte(i)
			_ = held.SetDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, 1)
			_, err := held.Write(b)
			if err == nil {
				_, err = io.ReadFull(held, got)
			}
			if err == nil && got[0] != b[0] {
				err = fmt.Errorf("byte %d came back as %d", b[0], got[0])
			}
			mu.Lock()
			if err != nil {
				broken = fmt.Errorf("exchange %d: %w", i, err)
				mu.Unlock()
				return
			}
			exchanged++
			mu.Unlock()
		}
	}()
	time.Sleep(3 * time.Second)

	resp, err := c.UpdateEdge(ctx, connect.NewRequest(&nodev1.UpdateEdgeRequest{Version: "v9.9.9"}))
	if err != nil {
		t.Fatalf("UpdateEdge: %v", err)
	}
	if resp.Msg.GetGeneration() != 2 || resp.Msg.GetVersion() != "v9.9.9" {
		t.Errorf("UpdateEdge = %v, want generation 2 on v9.9.9", resp.Msg)
	}
	mu.Lock()
	before := exchanged
	mu.Unlock()
	time.Sleep(5 * time.Second) // generation 1 drains with the held connection
	close(stopTalk)
	<-talked
	mu.Lock()
	defer mu.Unlock()
	if broken != nil {
		t.Fatalf("the held connection broke after %d exchanges: %v", exchanged, broken)
	}
	if exchanged <= before || exchanged < 6 {
		t.Errorf("exchanged %d bytes (%d before the answer), want them going on across the roll", exchanged, before)
	}
	info, err := c.GetInfo(ctx, connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil || info.Msg.GetEdgeVersion() != "v9.9.9" {
		t.Errorf("GetInfo = %v, %v; want the edge on v9.9.9", info, err)
	}
	// A new connection goes through generation 2.
	fresh := relayedConn(t, port)
	if _, err := fresh.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1)
	_ = fresh.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(fresh, got); err != nil || got[0] != 42 {
		t.Errorf("a new connection after the roll: %v, %v", got, err)
	}
	t.Logf("held connection: %d exchanges, %d of them after UpdateEdge answered", exchanged, exchanged-before)
}

// nodeBinaries puts the agent binaries of the versions at their paths: copied
// from POSTERN_ITEST_NODE_BINARIES/postern-node-<version>, or built.
func nodeBinaries(t *testing.T, ctx context.Context, want map[string]string) {
	t.Helper()
	dir := os.Getenv("POSTERN_ITEST_NODE_BINARIES")
	for v, path := range want {
		if dir != "" {
			data, err := os.ReadFile(filepath.Join(dir, "postern-node-"+v))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		goBin, err := exec.LookPath("go")
		if err != nil {
			t.Fatalf("no Go toolchain to build the node binaries, and POSTERN_ITEST_NODE_BINARIES is not set: %v", err)
		}
		cmd := exec.CommandContext(ctx, goBin, "build", "-trimpath",
			"-ldflags=-s -w -X github.com/urbnywrt/postern/internal/version.Version="+v, "-o", path, "../../../cmd/node")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building postern-node %s: %v\n%s", v, err, out)
		}
	}
}

// tcpEchoServer echoes every connection on a port of 127.0.0.1 outside the
// node's internal ports, and returns its address.
func tcpEchoServer(t *testing.T) string {
	t.Helper()
	port := freePort(t, 41000, 60999)
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// freePort is a port of 127.0.0.1 in [lo, hi] that nothing listens on now.
func freePort(t *testing.T, lo, hi int) int {
	t.Helper()
	for range 100 {
		port := lo + mrand.IntN(hi-lo+1)
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err == nil {
			_ = ln.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

// relayedConn connects to the listener and sends a ClientHello for a name that
// no proxy has: the edge masks the connection to the echo server, which sends
// the ClientHello back.
func relayedConn(t *testing.T, port int) net.Conn {
	t.Helper()
	hello := clientHello(t, "stranger.example.net")
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(hello))
	if _, err := io.ReadFull(conn, back); err != nil {
		t.Fatalf("the ClientHello did not come back through the edge: %v", err)
	}
	if !bytes.Equal(back, hello) {
		t.Fatal("the ClientHello came back changed")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

// clientHello is the first flight of a TLS client for server name sni.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}).Handshake()
		_ = client.Close()
	}()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	n := int(buf[3])<<8 | int(buf[4])
	rest := make([]byte, n)
	if _, err := io.ReadFull(server, rest); err != nil {
		t.Fatal(err)
	}
	return append(buf, rest...)
}

func waitUntilIT(t *testing.T, ctx context.Context, what string, cond func() bool) {
	t.Helper()
	for !cond() {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
