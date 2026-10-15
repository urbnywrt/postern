//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
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
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/probe"
	"github.com/urbnywrt/postern/internal/providers/warp"
	"github.com/urbnywrt/postern/internal/socks5"
)

// TestEgressChainFailover runs a proxy that goes out to Telegram through an
// egress chain of two Xray egresses, and the failover of the chain:
//
//  1. two "remote" VLESS servers, a and b, run in containers of the run on a
//     network of their own, on a documentation prefix (testSubnet): the Xray
//     release that the panel pins, downloaded and checked against the pinned
//     SHA-256, with a server configuration of the test and no TLS. They reach
//     the Internet through the network, and an echo server of this process on
//     its gateway, which answers every connection with the address that it
//     came from;
//  2. the panel and a node, as TestPanelToNodeFakeTLS has them;
//  3. an xray-uri egress for each server, the chain [a, b], whose check runs
//     every 5 seconds, and a proxy on the chain: the panel downloads telemt and
//     Xray and uploads them to the node, which runs the two egresses and the
//     engine. The proxy serves only once a datacenter of Telegram has answered
//     through the chain (Ruling S2-16), that is through a;
//  4. the L1 probe through the edge; the node reports a and b up; a CONNECT
//     through the SOCKS port of the proxy (the way out of its engine) reaches
//     the echo server from a;
//  5. a stops: a new CONNECT through the SOCKS port reaches the echo server
//     from b within fail_threshold × interval and the time that one check of a
//     takes, which is when the edge takes a down (failover); then the node
//     reports a down and b up;
//  6. the panel stops, and no log of the run holds a secret of it, the ids of
//     the users of the VLESS servers among them.
//
// With POSTERN_E2E_ONLINE=1, subtests check what a client gets: L2 through the
// proxy to a datacenter of Telegram over a, and over b after the failover; and
// WARP: a second proxy on a chain of a WARP egress serves, its member is up, a
// datacenter answers req_pq_multi through it, and L2 passes. The node registers
// a WARP device with Cloudflare for the egress, which the subtest deletes at its
// end, also when it fails, as the tests of the providers do.
//
// The member checks go to the datacenters of Telegram, and so does the check of
// a new engine generation: the run needs them through the Internet, as the
// first test does.
func TestEgressChainFailover(t *testing.T) {
	e := newEnv(t)

	// 1. The remote servers and the echo server. The network comes first: a
	// prefix that a killed run left taken fails the run before any download.
	network := e.createNetwork()
	xray := e.xrayBinary()
	echo := e.startEcho()
	srvA := e.startVLESS("a", network, xray)
	srvB := e.startVLESS("b", network, xray)

	// 2. The panel and the node; with POSTERN_E2E_XRAY_VERSION, the node runs
	// that release of the provider (overrides.go).
	panelEnv, providers := e.providerOverrides()
	p := e.startPanel(panelEnv...)
	a := newAPI(p.base)
	e.signIn(a, p.token)
	node := e.newNode(a)
	e.rollProviders(a, node.GetId(), providers)

	// 3. The egresses, the chain and the proxy.
	egA := e.createVLESSEgress(a, node.GetId(), srvA)
	egB := e.createVLESSEgress(a, node.GetId(), srvB)
	names := map[string]string{egA: "a", egB: "b"}
	cr, err := a.chains.CreateChain(e.ctx, connect.NewRequest(&panelv1.CreateChainRequest{
		Name: "a-then-b", NodeId: node.GetId(), MemberIds: []string{egA, egB},
		Check: &panelv1.ChainCheck{
			IntervalSeconds:  uint32(checkInterval / time.Second),
			TimeoutSeconds:   uint32(checkTimeout / time.Second),
			FailThreshold:    failThreshold,
			RecoverThreshold: recoverThreshold,
		},
	}))
	if err != nil {
		e.fatalf("CreateChain: %v", err)
	}
	chain := cr.Msg.GetChain()
	lport := e.freePort("127.0.0.1", 10000, 19999)
	lr, err := a.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{
		NodeId: node.GetId(), Kind: "tls", BindIp: "127.0.0.1", Port: uint32(lport),
	}))
	if err != nil {
		e.fatalf("CreateListener: %v", err)
	}
	listenerID := lr.Msg.GetListener().GetId()
	secretHex := hex.EncodeToString(randomBytes(16))
	e.mustNotLeak("the secret of the proxy", secretHex)
	pr, err := a.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: node.GetId(), ListenerId: listenerID, Name: "e2e-chain", Domain: proxyDomain, Secret: secretHex,
		EgressChainId: chain.GetId(),
	}))
	if err != nil {
		e.fatalf("CreateProxy: %v", err)
	}
	proxy := pr.Msg.GetProxy()
	if proxy.GetEgressChainId() != chain.GetId() {
		e.fatalf("the proxy goes out through chain %q, want %s", proxy.GetEgressChainId(), chain.GetId())
	}
	e.logf("chain %s [a, b]: a check every %v, %v for one, down after %d failures in a row, up after %d successes; "+
		"proxy %s on it, on the listener 127.0.0.1:%d", chain.GetId(), checkInterval, checkTimeout, failThreshold,
		recoverThreshold, proxy.GetId(), lport)
	secret, domain := e.checkLinks(a, proxy.GetId(), lport, secretHex)
	// The panel downloads telemt and Xray and uploads them to the node first.
	e.waitServing(a, proxy.GetId(), 8*time.Minute)

	// 4. The proxy serves, through a.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(lport))
	attempts, err := probeUntil(e.ctx, addr, domain, secret, 30*time.Second)
	if err != nil {
		e.fatalf("L1: probe.FakeTLS through the edge: %v (%d attempts)", err, attempts)
	}
	e.logf("L1: probe.FakeTLS through the edge: the engine proved the secret (attempt %d)", attempts)
	e.waitMembers(a, node.GetId(), chain.GetId(), names, map[string]string{egA: "up", egB: "up"}, 2*time.Minute)
	socks := e.proxySocks(proxy.GetId())
	from, err := echoVia(e.ctx, socks, echo.addr(), 10*time.Second)
	switch {
	case err != nil:
		e.fatalf("a CONNECT to the echo server through the SOCKS port of the proxy, %s: %v", socks, err)
	case from != srvA.ip:
		e.fatalf("a CONNECT through the SOCKS port of the proxy reached the echo server from %s, want a (%s)", from, srvA.ip)
	}
	e.logf("a CONNECT through the SOCKS port of the proxy, %s, reaches the echo server from a (%s)", socks, srvA.ip)
	e.online("L2 over a", func(e *env) { e.l2(addr, domain, secret, "over a") })

	// 5. Server a stops.
	e.failover(socks, echo, srvA, srvB)
	e.waitMembers(a, node.GetId(), chain.GetId(), names, map[string]string{egA: "down", egB: "up"}, 2*time.Minute)
	e.online("L2 over b", func(e *env) { e.l2(addr, domain, secret, "over b") })

	e.online("WARP", func(e *env) { e.warpEgress(a, node.GetId(), listenerID, lport) })

	// 6. The logs: the panel stops first, so that its output is all there.
	if err := p.stop(15 * time.Second); err != nil {
		e.errorf("the panel did not stop cleanly with a node connected: %v", err)
	}
	e.logf("the echo server was reached from %s", echo.summary(map[string]string{srvA.ip: "a", srvB.ip: "b"}))
	// The logs of the egresses are among them, or the scan for the ids of the
	// VLESS users proves nothing.
	e.checkLogs("egress")
}

const (
	// testSubnet is the network of the remote servers, and testGateway its
	// gateway, an address of the network namespace that the test runs in (the
	// host network of the Docker daemon). A documentation prefix: the addresses
	// are allowed in the repository and shown by the scrubber, and the edge lets
	// an engine go to them as to any public address, unlike a private one
	// (SocksPorts).
	testSubnet  = "198.51.100.0/24"
	testGateway = "198.51.100.1"

	// vlessPort is the port of the VLESS servers in their containers.
	vlessPort = 8443

	// The check of the chain: a round every 5 seconds, 2 seconds for a
	// datacenter, a member down after 3 failures in a row and up again after 2
	// successes. A round of a member that does not work takes twice the timeout
	// at the most, 4 seconds, which fits in the interval: the rounds keep their
	// pace while a is down. A round also waits for the exit address of every
	// member that passed, which the edge asks the echo services for
	// (api.ipify.org, ifconfig.me and icanhazip.com, in order, each request
	// twice the timeout at the most): through b, and directly for the direct
	// member of the node's own chain. Where they answer slowly, the rounds
	// stretch beyond the interval and the failover comes later than its bound,
	// although the edge does what it should; timerSlack is the margin for that.
	checkInterval    = 5 * time.Second
	checkTimeout     = 2 * time.Second
	failThreshold    = 3
	recoverThreshold = 2

	// A CONNECT to the echo server comes every echoEvery while the test waits for
	// the failover, each within echoTimeout; timers may fire a little late, by
	// timerSlack at the most in all. On a busy Docker host (other e2e runs at
	// the same time) a health round stretches by a few seconds: one run saw the
	// failover 22.8 s after the stop, so the slack is generous.
	echoEvery   = 250 * time.Millisecond
	echoTimeout = time.Second
	timerSlack  = 4 * time.Second

	// dc2 is Telegram's DC2 (Global Constraints), the datacenter of the online
	// checks.
	dc2 = "149.154.167.51:443"
	// warpDomain is the fake-TLS domain of the proxy of the WARP subtest.
	warpDomain = "warp.e2e.example"
)

// online runs f in a subtest that needs POSTERN_E2E_ONLINE=1: what a client
// gets through the proxy from a datacenter of Telegram, and WARP, which goes to
// Cloudflare. The subtest has an env of its own on the run (sub).
func (e *env) online(name string, f func(e *env)) {
	e.t.Helper()
	e.t.Run(name, func(t *testing.T) {
		s := e.sub(t)
		if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
			s.skipf("set POSTERN_E2E_ONLINE=1 for the checks of a client through the proxy, and for WARP")
		}
		f(s)
	})
}

// ---- the remote servers ---------------------------------------------------------

// xrayBinary downloads the Xray release that the panel pins for the
// architecture of the Docker daemon, checks it against the SHA-256 that the
// panel pins, and takes the binary out of the archive as a node stores it
// (artifacts.Store). It returns the path of the binary, in the work directory
// of the run. (The panel downloads the same release for the node on its own.)
func (e *env) xrayBinary() string {
	e.t.Helper()
	ref, ok := proxies.BuiltinRef(proxies.EngineXray, proxies.DefaultXrayVersion, runtime.GOARCH)
	if !ok {
		e.fatalf("the panel pins no release of Xray %s for %s", proxies.DefaultXrayVersion, runtime.GOARCH)
	}
	aref := artifacts.Ref{
		Engine: ref.GetEngine(), Version: ref.GetVersion(), Arch: ref.GetArch(),
		SHA256: ref.GetSha256(), FileName: ref.GetFileName(), Binary: ref.GetBinary(),
	}
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.GetUrl(), nil)
	if err != nil {
		e.fatalf("%v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.fatalf("downloading Xray %s: %v", ref.GetVersion(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		e.fatalf("GET %s: %s", ref.GetUrl(), resp.Status)
	}
	store := &artifacts.Store{Root: filepath.Join(e.work, "artifacts")}
	if err := store.Put(aref, resp.Body); err != nil {
		e.fatalf("Xray %s from GitHub: %v", ref.GetVersion(), err) // artifacts.ErrChecksum: not what the panel pins
	}
	e.logf("Xray %s for %s: %s downloaded, checked against the SHA-256 that the panel pins, and the binary taken out",
		ref.GetVersion(), ref.GetArch(), ref.GetFileName())
	return store.BinaryPath(aref)
}

// createNetwork makes the network of the remote servers, a bridge of the
// Docker daemon on testSubnet with the label of the run (cleanup removes it),
// and returns its name.
func (e *env) createNetwork() string {
	e.t.Helper()
	name := "postern-e2e-" + e.run
	ctx, cancel := context.WithTimeout(e.ctx, time.Minute)
	defer cancel()
	body := map[string]any{
		"Name":   name,
		"Driver": "bridge",
		"IPAM":   map[string]any{"Config": []map[string]string{{"Subnet": testSubnet, "Gateway": testGateway}}},
		"Labels": map[string]string{labelRun: e.run},
	}
	if err := e.raw.do(ctx, http.MethodPost, "/networks/create", body, nil); err != nil {
		e.fatalf("creating the network %s on %s: %v (a run that was killed may have left one on the prefix: "+
			"docker network ls --filter label=%s)", name, testSubnet, err, labelRun)
	}
	e.logf("network %s on %s", name, testSubnet)
	return name
}

// vlessServer is a remote VLESS server of the test.
type vlessServer struct {
	name string
	id   string // the ID of its container
	ip   string // its address on the network of the test
	uri  string // the share link of its user, which holds the id of the user
}

// vlessConfig is the configuration of a VLESS server of the test, as the
// integration test of the providers has it: VLESS without TLS, one user, and
// out to anywhere. The arguments are the port and the id of the user.
const vlessConfig = `{
  "log": {"loglevel": "warning", "access": "none"},
  "inbounds": [{"listen": "0.0.0.0", "port": %d, "protocol": "vless",
    "settings": {"clients": [{"id": %q}], "decryption": "none"},
    "streamSettings": {"network": "raw", "security": "none"}}],
  "outbounds": [{"protocol": "freedom"}]
}
`

// startVLESS starts a VLESS server with the binary xray in a container of the
// run on the network, and waits until it listens. The id of its user is a
// secret of the run.
func (e *env) startVLESS(name, network, xray string) *vlessServer {
	e.t.Helper()
	uuid := newUUID()
	e.mustNotLeak("the id of the user of VLESS server "+name, uuid)
	dir := filepath.Join(e.work, "vless-"+name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		e.fatalf("%v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // whatever the umask took away: the server runs as 65534
		e.fatalf("%v", err)
	}
	e.writeFile(filepath.Join(dir, "server.json"), fmt.Appendf(nil, vlessConfig, vlessPort, uuid), 0o644)

	ctx, cancel := context.WithTimeout(e.ctx, time.Minute)
	defer cancel()
	id, err := e.docker.Create(ctx, dockerapi.ContainerSpec{
		Name:          "postern-e2e-" + e.run + "-vless-" + name,
		Image:         runnerImage,
		User:          "65534:65534",
		NetworkMode:   network,
		RestartPolicy: "no",
		ReadOnly:      true,
		CapDrop:       []string{"ALL"},
		Entrypoint:    []string{"/opt/xray/xray", "run", "-c", "/etc/xray/server.json"},
		Binds:         []string{xray + ":/opt/xray/xray:ro", dir + ":/etc/xray:ro"},
		Labels:        map[string]string{labelRun: e.run},
	})
	if err != nil {
		e.fatalf("creating VLESS server %s: %v", name, err)
	}
	if err := e.docker.Start(ctx, id); err != nil {
		e.fatalf("starting VLESS server %s: %v", name, err)
	}
	ip, err := e.raw.containerIP(ctx, id, network)
	if err != nil {
		e.fatalf("VLESS server %s: %v", name, err)
	}
	hostPort := net.JoinHostPort(ip, strconv.Itoa(vlessPort))
	s := &vlessServer{
		name: name, id: id, ip: ip,
		uri: "vless://" + uuid + "@" + hostPort + "?encryption=none&security=none&type=tcp#" + name,
	}
	// The network is a bridge of the network namespace of the test, which
	// reaches the server directly.
	e.waitFor("VLESS server "+name+" at "+hostPort, 30*time.Second, 250*time.Millisecond,
		func(ctx context.Context) (bool, string, error) {
			d, err := e.docker.Inspect(ctx, id)
			if err != nil {
				return false, "", err
			}
			if d.State != "running" {
				return false, "", fmt.Errorf("its container is %s (exit code %d): %s", d.State, d.ExitCode, e.containerLog(ctx, id))
			}
			c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", hostPort)
			if err != nil {
				return false, "not listening yet", nil
			}
			_ = c.Close()
			return true, "listening", nil
		})
	return s
}

// createVLESSEgress makes an xray-uri egress of the node with the share link of
// the server, and returns its id. The panel keeps the link sealed and never
// returns it; the egress shows the scheme, the host and the port.
func (e *env) createVLESSEgress(a *api, nodeID string, s *vlessServer) string {
	e.t.Helper()
	r, err := a.egresses.CreateEgress(e.ctx, connect.NewRequest(&panelv1.CreateEgressRequest{
		Name: "vless-" + s.name, Kind: "xray-uri", NodeId: nodeID, Params: &panelv1.EgressParams{Uri: s.uri},
	}))
	if err != nil {
		e.fatalf("CreateEgress for VLESS server %s: %v", s.name, err)
	}
	eg := r.Msg.GetEgress()
	if eg.GetParams().GetUri() != "" {
		e.errorf("the panel returned the share link of the egress of VLESS server %s", s.name)
	}
	if want := "vless://" + net.JoinHostPort(s.ip, strconv.Itoa(vlessPort)); eg.GetMasked() != want {
		e.errorf("the egress of VLESS server %s shows %q, want %q", s.name, eg.GetMasked(), want)
	}
	e.logf("egress %s (xray-uri, %s) of VLESS server %s", eg.GetId(), eg.GetMasked(), s.name)
	return eg.GetId()
}

// newUUID is a random UUID (version 4), the id of a VLESS user.
func newUUID() string {
	b := randomBytes(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// containerLog is the end of the log of a container, for a message.
func (e *env) containerLog(ctx context.Context, id string) string {
	rc, err := e.docker.Logs(ctx, id, 50, false)
	if err != nil {
		return err.Error()
	}
	defer func() { _ = rc.Close() }()
	data, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
	return strings.TrimSpace(string(data))
}

// ---- the echo server -----------------------------------------------------------

// echoServer answers every connection with the address that it came from: it
// reads a line and writes back "<address> <line>". It listens on the gateway of
// the network of the remote servers, which they reach without NAT, so the
// address is that of the server that made the connection.
type echoServer struct {
	ln net.Listener

	mu   sync.Mutex
	from map[string]int // the connections by the address that they came from
}

func (e *env) startEcho() *echoServer {
	e.t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(testGateway, "0"))
	if err != nil {
		e.fatalf("the echo server cannot listen on the gateway of the network of the test, %s: %v", testGateway, err)
	}
	s := &echoServer{ln: ln, from: map[string]int{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serve()
	}()
	e.t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	e.logf("the echo server listens at %s", ln.Addr())
	return s
}

func (s *echoServer) addr() string { return s.ln.Addr().String() }

func (s *echoServer) serve() {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		wg.Go(func() { s.answer(c) })
	}
}

func (s *echoServer) answer(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	from := "?"
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		from = ap.Addr().Unmap().String()
	}
	s.mu.Lock()
	s.from[from]++
	s.mu.Unlock()
	line, err := bufio.NewReader(io.LimitReader(c, 256)).ReadString('\n')
	if err != nil {
		return
	}
	_, _ = io.WriteString(c, from+" "+strings.TrimSpace(line)+"\n")
}

// summary says how often the echo server was reached from each address, with
// the names of the addresses that names has: "a (198.51.100.2) ×1".
func (s *echoServer) summary(names map[string]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var parts []string
	for _, from := range slices.Sorted(maps.Keys(s.from)) {
		what := from
		if name, ok := names[from]; ok {
			what = name + " (" + from + ")"
		}
		parts = append(parts, fmt.Sprintf("%s ×%d", what, s.from[from]))
	}
	if len(parts) == 0 {
		return "nowhere"
	}
	return strings.Join(parts, ", ")
}

// echoVia connects to the echo server at target through the SOCKS5 port socks,
// as an engine does (without a user name), sends a random line and returns the
// address that the echo server says the connection came from. within bounds
// all of it.
func echoVia(ctx context.Context, socks, target string, within time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	conn, err := socks5.Dial(ctx, socks, "", "", target)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(randomBytes(8))
	if _, err := io.WriteString(conn, nonce+"\n"); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 256)).ReadString('\n')
	if err != nil {
		return "", err
	}
	from, got, ok := strings.Cut(strings.TrimSpace(line), " ")
	if !ok || got != nonce {
		return "", fmt.Errorf("the echo server answered %q", line)
	}
	return from, nil
}

// echoFailure says in a few words why a CONNECT to the echo server failed.
func echoFailure(err error) string {
	var re *socks5.ReplyError
	switch {
	case errors.As(err, &re):
		return "refused by the SOCKS port: " + re.Error()
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed after the CONNECT"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return "no answer in time"
	}
	return err.Error()
}

// outcomes are what a series of attempts met, in runs: "closed after the
// CONNECT ×12, through b".
type outcomes struct {
	runs []outcomeRun
}

type outcomeRun struct {
	what string
	n    int
}

func (o *outcomes) add(what string) {
	if l := len(o.runs); l > 0 && o.runs[l-1].what == what {
		o.runs[l-1].n++
		return
	}
	o.runs = append(o.runs, outcomeRun{what: what, n: 1})
}

func (o *outcomes) String() string {
	parts := make([]string, 0, len(o.runs))
	for _, r := range o.runs {
		if r.n == 1 {
			parts = append(parts, r.what)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s ×%d", r.what, r.n))
	}
	return strings.Join(parts, ", ")
}

// ---- the failover ----------------------------------------------------------------

// failover stops server a and waits until a CONNECT through the SOCKS port of
// the proxy (socks) reaches the echo server from b: the edge has taken a down,
// and dials b, the next member of the chain. Xray acknowledges a CONNECT before
// it has reached its server, so until then the CONNECTs go to a and come to
// nothing.
//
// The edge takes a down at the end of its fail_threshold-th round in a row that
// fails: the first may begin an interval after the stop, each begins an
// interval after the one before, and the check of a member takes twice the
// timeout at the most (edge/egress/health.go). A CONNECT comes every echoEvery
// and takes echoTimeout at the most, and sees the change that much later, give
// or take the timers (timerSlack).
func (e *env) failover(socks string, echo *echoServer, a, b *vlessServer) {
	e.t.Helper()
	bound := failThreshold*checkInterval + 2*checkTimeout
	seen := echoEvery + echoTimeout + timerSlack
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	err := e.docker.Stop(ctx, a.id, 5*time.Second)
	cancel()
	if err != nil {
		e.fatalf("stopping VLESS server a: %v", err)
	}
	stopped := time.Now()
	e.logf("VLESS server a stopped")
	var met outcomes
	for {
		from, err := echoVia(e.ctx, socks, echo.addr(), echoTimeout)
		took := time.Since(stopped)
		switch {
		case err == nil && from == b.ip:
			met.add("through b")
			if took > bound+seen {
				e.errorf("a CONNECT through the SOCKS port of the proxy reached the echo server from b %.1fs after server a "+
					"stopped, later than fail_threshold × interval + 2 × timeout = %v (and %v for the CONNECTs to see it); "+
					"the CONNECTs met: %s", took.Seconds(), bound, seen, &met)
				return
			}
			e.logf("failover: %.1fs after server a stopped, a CONNECT through the SOCKS port of the proxy reached the echo "+
				"server from b (%s): within fail_threshold × interval + 2 × timeout = %v (and %v for the CONNECTs to see "+
				"it); the CONNECTs met: %s", took.Seconds(), b.ip, bound, seen, &met)
			return
		case err == nil:
			e.fatalf("%.1fs after server a stopped, a CONNECT through the SOCKS port of the proxy reached the echo server "+
				"from %s, not from b (%s)", took.Seconds(), from, b.ip)
		}
		met.add(echoFailure(err))
		if took > bound+seen+30*time.Second {
			e.fatalf("%v after server a stopped, no CONNECT through the SOCKS port of the proxy has reached the echo "+
				"server from b; they met: %s", took.Round(time.Second), &met)
		}
		select {
		case <-e.ctx.Done():
			e.fatalf("waiting for the failover: %v; the CONNECTs met: %s", e.ctx.Err(), &met)
		case <-time.After(echoEvery):
		}
	}
}

// ---- the node --------------------------------------------------------------------

// waitMembers waits until the node reports the members of the chain in the
// statuses of want, by egress id, in a report that is not stale; names name
// the egresses in what is printed. What the node reports is the health of the
// members as its edge has it (Snapshot), with every pass of its reconciler:
// every 30 seconds at the most.
func (e *env) waitMembers(a *api, nodeID, chainID string, names, want map[string]string, timeout time.Duration) {
	e.t.Helper()
	e.waitFor("chain "+chainID+" with "+describeMembers(want, names), timeout, time.Second,
		func(ctx context.Context) (bool, string, error) {
			r, err := a.egresses.GetNodeEgressHealth(ctx, connect.NewRequest(&panelv1.GetNodeEgressHealthRequest{NodeId: nodeID}))
			if err != nil {
				return false, "", fmt.Errorf("GetNodeEgressHealth: %w", err)
			}
			have := map[string]string{}
			for _, m := range r.Msg.GetMembers() {
				if m.GetChainId() == chainID {
					have[m.GetEgressId()] = m.GetStatus()
				}
			}
			status := "the node reports " + describeMembers(have, names)
			if r.Msg.GetStale() {
				status += " (stale)"
			}
			return !r.Msg.GetStale() && maps.Equal(have, want), status, nil
		})
}

// describeMembers says the statuses of members by the names of their egresses:
// "a up, b down".
func describeMembers(statuses, names map[string]string) string {
	if len(statuses) == 0 {
		return "no member"
	}
	parts := make([]string, 0, len(statuses))
	for id, status := range statuses {
		name := names[id]
		if name == "" {
			name = id
		}
		parts = append(parts, name+" "+status)
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}

// proxySocks is the address of the SOCKS port of the edge for the engine that
// serves the proxy, its way out (SocksPorts), as the runtime record of the node
// has it.
func (e *env) proxySocks(proxyID string) string {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, time.Minute)
	defer cancel()
	// state.Store keeps the runtime record as runtime.json, of root alone.
	path, remove, err := e.copyNodeFile(ctx, filepath.Join(state.Paths{Home: e.home}.StateDir(), "runtime.json"))
	if err != nil {
		e.fatalf("the runtime record of the node: %v", err)
	}
	defer remove()
	data, err := os.ReadFile(path)
	if err != nil {
		e.fatalf("the runtime record of the node: %v", err)
	}
	var rt state.Runtime
	if err := json.Unmarshal(data, &rt); err != nil {
		e.fatalf("the runtime record of the node: %v", err)
	}
	rec := rt.Instances[proxyID]
	if rec.Generation == 0 || rec.SocksPort == 0 {
		e.fatalf("the runtime record of the node has no engine that serves proxy %s", proxyID)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(rec.SocksPort)))
}

// copyNodeFile copies a file of the node's directory that only root may read
// (the agent keeps its state 0600 in directories of 0700) for this process,
// into a directory of its own in the work directory, through a container of the
// run, which says nothing of what the file holds. It returns the path of the
// copy and a func that removes it. The error wraps fs.ErrNotExist when there is
// no such file.
func (e *env) copyNodeFile(ctx context.Context, path string) (string, func(), error) {
	dir, err := os.MkdirTemp(e.work, "copy-")
	if err != nil {
		return "", nil, err
	}
	remove := func() { _ = os.RemoveAll(dir) }
	dst := filepath.Join(dir, filepath.Base(path))
	owner := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	const script = `[ -f "$1" ] || exit 3; cp "$1" "$2" && chown "$3" "$2" && chmod 0600 "$2"`
	switch code, out := e.runHelperCtx(ctx, "copy", "none", []string{"sh", "-c", script, "sh", path, dst, owner}); code {
	case 0:
		return dst, remove, nil
	case 3:
		remove()
		return "", nil, fmt.Errorf("%s: %w", filepath.Base(path), fs.ErrNotExist)
	default:
		remove()
		return "", nil, fmt.Errorf("copying %s out of the node's directory: exit %d: %s", filepath.Base(path), code, out)
	}
}

// ---- online ----------------------------------------------------------------------

// l2 runs the L2 probe through the proxy at addr to DC2, as a client of its
// link: the fake-TLS handshake with the secret, then req_pq_multi, whose resPQ
// comes back from the datacenter through the engine and its chain (over says
// which way that is). It tries for a minute.
func (e *env) l2(addr, sni string, secret []byte, over string) {
	e.t.Helper()
	deadline := time.Now().Add(time.Minute)
	for attempt := 1; ; attempt++ {
		start := time.Now()
		err := probe.L2(e.ctx, addr, sni, secret, 2, probe.Options{Timeout: 15 * time.Second})
		if err == nil {
			e.logf("L2 through the proxy to DC2 %s: the datacenter's resPQ came back after %v (attempt %d)",
				over, time.Since(start).Round(time.Millisecond), attempt)
			return
		}
		if time.Now().After(deadline) || e.ctx.Err() != nil {
			e.fatalf("L2 through the proxy to DC2 %s: %v (%d attempts)", over, err, attempt)
		}
		e.logf("L2 through the proxy to DC2 %s, attempt %d: %v", over, attempt, err)
		select {
		case <-e.ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

// warpEgress is the WARP subtest: a WARP egress of the node, a chain of it,
// and a second proxy on the listener, on that chain. The proxy serves once a
// datacenter has answered through WARP (the check of a new engine generation);
// then the node reports the member up, DC2 answers req_pq_multi through the
// SOCKS port of the proxy, and L2 passes. The node registers a WARP device with
// Cloudflare for the egress, which the subtest deletes at its end, also when it
// fails.
func (e *env) warpEgress(a *api, nodeID, listenerID string, port int) {
	e.t.Helper()
	var egressID string
	e.t.Cleanup(func() { e.deleteWARPDevice(egressID) })
	r, err := a.egresses.CreateEgress(e.ctx, connect.NewRequest(&panelv1.CreateEgressRequest{
		Name: "warp", Kind: "warp", NodeId: nodeID,
	}))
	if err != nil {
		e.fatalf("CreateEgress of kind warp: %v", err)
	}
	egressID = r.Msg.GetEgress().GetId()
	// Without a check of its own: the node runs that of chain a-then-b.
	cr, err := a.chains.CreateChain(e.ctx, connect.NewRequest(&panelv1.CreateChainRequest{
		Name: "warp", NodeId: nodeID, MemberIds: []string{egressID},
	}))
	if err != nil {
		e.fatalf("CreateChain of the WARP egress: %v", err)
	}
	chainID := cr.Msg.GetChain().GetId()
	secretHex := hex.EncodeToString(randomBytes(16))
	e.mustNotLeak("the secret of the WARP proxy", secretHex)
	pr, err := a.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: nodeID, ListenerId: listenerID, Name: "e2e-warp", Domain: warpDomain, Secret: secretHex, EgressChainId: chainID,
	}))
	if err != nil {
		e.fatalf("CreateProxy on the WARP chain: %v", err)
	}
	proxyID := pr.Msg.GetProxy().GetId()
	e.logf("WARP egress %s, chain %s of it, and proxy %s on the chain", egressID, chainID, proxyID)
	e.waitServing(a, proxyID, 5*time.Minute)
	// The credentials of the device are secrets of the run from now on.
	if _, err := e.warpAccount(e.ctx, egressID); err != nil {
		e.errorf("the account of the WARP device of the node: %v", err)
	}
	e.waitMembers(a, nodeID, chainID, map[string]string{egressID: "warp"}, map[string]string{egressID: "up"}, 2*time.Minute)

	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	socks := e.proxySocks(proxyID)
	start := time.Now()
	conn, err := socks5.Dial(ctx, socks, "", "", dc2)
	if err != nil {
		e.fatalf("CONNECT to DC2 through the SOCKS port of the WARP proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := probe.DCPing(ctx, conn); err != nil {
		e.fatalf("req_pq_multi to DC2 through the SOCKS port of the WARP proxy: %v", err)
	}
	e.logf("DC2 answered req_pq_multi through the SOCKS port of the WARP proxy, over WARP, after %v",
		time.Since(start).Round(time.Millisecond))
	e.l2(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), warpDomain, mustHex(secretHex), "over WARP")
}

// warpAccount reads the account of the WARP device that the node registered
// for the egress, which the agent keeps in its state directory, also a
// registration that stopped half-way, and notes its credentials as secrets of
// the run. The error wraps fs.ErrNotExist when the node registered none.
func (e *env) warpAccount(ctx context.Context, egressID string) (*warp.Account, error) {
	// The agent keeps it as warp-account.json (reconcile/egress.go).
	path, remove, err := e.copyNodeFile(ctx, filepath.Join(state.Paths{Home: e.home}.EgressStateDir(egressID), "warp-account.json"))
	if err != nil {
		return nil, err
	}
	defer remove()
	acct, err := warp.LoadRegistration(path)
	if err != nil {
		return nil, err
	}
	e.mustNotLeak("the token of the WARP device", acct.Token)
	e.mustNotLeak("the private key of the WARP device", acct.PrivateKey)
	return acct, nil
}

const (
	// warpAccountWait is how long the deletion of the WARP device waits for the
	// account of the node to be there: a registration that is under way when
	// the subtest ends (it failed early, or the run was cut short) writes it a
	// moment later.
	warpAccountWait = 15 * time.Second
	// warpDeleteAttempts is how often the deletion of the device is tried: once
	// the node's directory is gone, with the account in it, nothing can delete
	// the device any more.
	warpDeleteAttempts = 3
)

// deleteWARPDevice deletes the WARP device that the node registered for the
// egress at Cloudflare (warp.Delete), as the tests of the providers delete
// theirs, with the account that the node keeps. It waits warpAccountWait for
// the account before it takes it that the node registered none, and tries the
// deletion warpDeleteAttempts times. It works when the run is cut short as
// well.
func (e *env) deleteWARPDevice(egressID string) {
	if egressID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	since := time.Now()
	var acct *warp.Account
	for acct == nil {
		a, err := e.warpAccount(ctx, egressID)
		switch {
		case err == nil:
			acct = a
			continue
		case !errors.Is(err, fs.ErrNotExist):
			e.errorf("the WARP device of egress %s cannot be deleted: %v", egressID, err)
			return
		case time.Since(since) >= warpAccountWait:
			e.logf("the node registered no WARP device for egress %s (no account within %v): there is none to delete",
				egressID, warpAccountWait)
			return
		}
		select {
		case <-ctx.Done():
			e.errorf("waiting for the account of the WARP device of egress %s: %v", egressID, ctx.Err())
			return
		case <-time.After(time.Second):
		}
	}
	var err error
	for attempt := 1; attempt <= warpDeleteAttempts; attempt++ {
		err = warp.Delete(ctx, nil, acct)
		switch {
		case err == nil:
			e.logf("the WARP device of egress %s was deleted at Cloudflare (attempt %d)", egressID, attempt)
			return
		case errors.Is(err, warp.ErrDeviceGone): // an attempt before went through, or the node deleted it
			e.logf("the WARP device of egress %s is gone at Cloudflare (attempt %d)", egressID, attempt)
			return
		}
		if attempt < warpDeleteAttempts {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
	e.errorf("deleting the WARP device of egress %s at Cloudflare: %v (%d attempts)", egressID, err, warpDeleteAttempts)
}
