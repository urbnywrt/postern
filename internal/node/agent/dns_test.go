package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/dns"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/state"
)

// fakeForwarder stands in for the DNS forwarder of the edge: a DNS server on a
// UDP port of 127.0.0.1 that answers every A question with 127.0.0.1, and notes
// the names.
type fakeForwarder struct {
	pc    net.PacketConn
	mu    sync.Mutex
	names []string
}

func startFakeForwarder(t *testing.T) *fakeForwarder {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeForwarder{pc: pc}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			f.mu.Lock()
			f.names = append(f.names, strings.ToLower(q.Questions[0].Name.String()))
			f.mu.Unlock()
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true},
				Questions: q.Questions,
			}
			if q.Questions[0].Type == dnsmessage.TypeA {
				resp.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
				}}
			}
			if b, err := resp.Pack(); err == nil {
				_, _ = pc.WriteTo(b, from)
			}
		}
	}()
	return f
}

func (f *fakeForwarder) addr() string { return f.pc.LocalAddr().String() }

func (f *fakeForwarder) asked(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.names, name)
}

// echoServer answers every request with addr, as an echo service of the public
// address does, and returns its port.
func echoServer(t *testing.T, addr string) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, addr)
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

// The requests of the agent to the echo services resolve their names with the
// resolver they are given.
func TestEchoServicesAreResolvedWithTheAgentsResolver(t *testing.T) {
	fwd := startFakeForwarder(t)
	port := echoServer(t, "198.51.100.23")
	sw := dns.NewSwitch()
	sw.Use(fwd.addr())
	h := &hostInfo{
		addrs:    func() ([]net.Addr, error) { return []net.Addr{ipNet("10.1.2.3/8")}, nil },
		echoURLs: []string{fmt.Sprintf("http://echo.test:%d/ip", port)},
		resolver: sw.Resolver(),
		now:      time.Now,
		log:      discardLog(),
	}
	if got := h.publicIPs(context.Background()); !slices.Equal(got, []string{"198.51.100.23"}) {
		t.Errorf("publicIPs = %v", got)
	}
	if !fwd.asked("echo.test.") {
		t.Error("the resolver was not asked for the echo service")
	}
}

// dnsEdge is an edge whose Health says whether its DNS forwarder runs, and that
// keeps the configurations it is given. One stands for every generation; its
// Health fails for every generation while fail is set, and for failGen.
type dnsEdge struct {
	up      atomic.Bool
	fail    atomic.Bool
	failGen uint64
	mu      sync.Mutex
	configs []*edgev1.EdgeConfig
}

type dnsEdgeGen struct {
	e   *dnsEdge
	gen uint64
}

func (g dnsEdgeGen) SetConfig(_ context.Context, cfg *edgev1.EdgeConfig) ([]*edgev1.ListenerFailure, error) {
	g.e.mu.Lock()
	defer g.e.mu.Unlock()
	g.e.configs = append(g.e.configs, proto.Clone(cfg).(*edgev1.EdgeConfig))
	return nil, nil
}

func (g dnsEdgeGen) Snapshot(context.Context) (*edgev1.SnapshotResponse, error) {
	return &edgev1.SnapshotResponse{Generation: g.gen}, nil
}

func (g dnsEdgeGen) Health(context.Context) (*edgev1.HealthResponse, error) {
	if g.e.fail.Load() || g.gen == g.e.failGen {
		return nil, errors.New("edge Health: context deadline exceeded")
	}
	return &edgev1.HealthResponse{Generation: g.gen, Listening: true, Dns: g.e.up.Load()}, nil
}

func (g dnsEdgeGen) Drain(context.Context, uint32) error { return nil }

func (e *dnsEdge) last() *edgev1.EdgeConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.configs) == 0 {
		return nil
	}
	return e.configs[len(e.configs)-1]
}

// The agent resolves its own names through the forwarder of the edge while the
// edge says that it runs, and with the host's nameservers otherwise. It asks
// the edge it finds in the runtime record already at its start, before it looks
// up its public address. The host's nameservers go to the edge as the fallback
// of the forwarder.
func TestAgentResolvesThroughTheForwarderOfTheEdge(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	st := validState(1)
	st.Proxies = nil
	if err := (&storeFor{home}).save(st); err != nil {
		t.Fatal(err)
	}
	rt := state.NewRuntime()
	rt.EdgeGeneration = 1
	if err := (&state.Store{Paths: state.Paths{Home: home}}).SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	resolvConf := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolvConf, []byte("nameserver 127.0.0.2\nnameserver 192.0.2.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fwd := startFakeForwarder(t)
	port := echoServer(t, "198.51.100.23")
	edge := &dnsEdge{}
	edge.up.Store(true)
	sw := dns.NewSwitch()
	passes := make(chan error, 16)

	a := startAgent(t, home, p, func(o *Options) {
		o.addrs = func() ([]net.Addr, error) { return []net.Addr{ipNet("10.1.2.3/8")}, nil }
		o.echoURLs = []string{fmt.Sprintf("http://echo.test:%d/ip", port)}
		o.edge = func(gen uint64) reconcile.EdgeClient { return dnsEdgeGen{e: edge, gen: gen} }
		o.resolvConf = resolvConf
		o.dnsForwarder = fwd.addr()
		o.dnsSwitch = sw
		o.passed = func(err error) {
			select {
			case passes <- err:
			default:
			}
		}
	})
	c := a.client()
	nextPass := func() {
		t.Helper()
		select {
		case err := <-passes:
			if err != nil {
				t.Fatalf("reconcile pass: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("no reconcile pass")
		}
	}
	nextPass()

	// At its start the agent asked the edge of the record, and then the echo
	// service by name, through the forwarder.
	info, err := c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Msg.GetPublicIps(); !slices.Equal(got, []string{"198.51.100.23"}) {
		t.Errorf("public IPs = %v, want the echo service's answer through the forwarder", got)
	}
	if !fwd.asked("echo.test.") {
		t.Error("the forwarder was not asked for the echo service")
	}
	if sw.Target() != fwd.addr() {
		t.Errorf("the agent resolves through %q, want the forwarder %s", sw.Target(), fwd.addr())
	}
	cfg := edge.last()
	if want := (&edgev1.Dns{Enabled: true, Fallback: []string{"192.0.2.53"}}); cfg == nil || !cfg.GetDns().GetEnabled() || !slices.Equal(cfg.GetDns().GetFallback(), want.GetFallback()) {
		t.Errorf("edge dns = %v, want the forwarder with the host's nameserver 192.0.2.53", cfg.GetDns())
	}

	apply := func(gen uint64) {
		t.Helper()
		next := validState(gen)
		next.Proxies = nil
		if resp, err := c.ApplyState(context.Background(), connect.NewRequest(&nodev1.ApplyStateRequest{State: next})); err != nil || !resp.Msg.GetAccepted() {
			t.Fatalf("ApplyState = %v, %v", resp, err)
		}
	}

	// The edge does not answer: that tells nothing, and the agent stays with the
	// forwarder (ruling S2-8).
	edge.fail.Store(true)
	for len(passes) > 0 {
		<-passes
	}
	apply(2)
	for {
		if err := <-passes; err == nil {
			break
		}
	}
	if sw.Target() != fwd.addr() {
		t.Errorf("after a Health error the agent resolves through %q, want still the forwarder", sw.Target())
	}

	// The forwarder goes: after the next pass the agent uses the host's
	// nameservers.
	edge.fail.Store(false)
	edge.up.Store(false)
	apply(3)
	waitFor(t, "the agent to leave the forwarder", func() bool { return sw.Target() == "" })
	if !strings.Contains(a.stderr.String(), "DNS forwarder of the edge") {
		t.Errorf("the switch is not logged:\n%s", a.stderr.String())
	}
}

// The public address that the start could not find, because the edge did not
// answer and the host's nameservers could not resolve the echo services, is
// looked up again when the edge first says that its forwarder runs, once; it
// goes to the reconciler and to GetInfo.
func TestAgentLooksUpItsAddressAgainWhenTheForwarderComesUp(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	st := validState(1)
	st.Proxies = nil
	if err := (&storeFor{home}).save(st); err != nil {
		t.Fatal(err)
	}
	rt := state.NewRuntime()
	rt.EdgeGeneration = 1
	if err := (&state.Store{Paths: state.Paths{Home: home}}).SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	fwd := startFakeForwarder(t)
	var asked atomic.Int32
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = fmt.Fprint(w, "198.51.100.23")
	}))
	t.Cleanup(echo.Close)
	port := echo.Listener.Addr().(*net.TCPAddr).Port
	edge := &dnsEdge{failGen: 1} // the edge of the record does not answer; the new one does
	edge.up.Store(true)
	sw := dns.NewSwitch()
	passes := make(chan error, 16)

	a := startAgent(t, home, p, func(o *Options) {
		o.addrs = func() ([]net.Addr, error) { return []net.Addr{ipNet("10.1.2.3/8")}, nil }
		o.echoURLs = []string{fmt.Sprintf("http://echo.test:%d/ip", port)}
		o.edge = func(gen uint64) reconcile.EdgeClient { return dnsEdgeGen{e: edge, gen: gen} }
		o.resolvConf = filepath.Join(t.TempDir(), "missing-resolv.conf")
		o.dnsForwarder = fwd.addr()
		o.dnsSwitch = sw
		o.passed = func(err error) {
			select {
			case passes <- err:
			default:
			}
		}
	})
	c := a.client()
	waitFor(t, "the late public address", func() bool {
		return strings.Contains(a.stderr.String(), "public IPv4 address is known now")
	})
	if !strings.Contains(a.stderr.String(), "public IPv4 address is not known") {
		t.Errorf("the start did not miss the address, the test proves nothing:\n%s", a.stderr.String())
	}
	info, err := c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Msg.GetPublicIps(); !slices.Equal(got, []string{"198.51.100.23"}) {
		t.Errorf("public IPs = %v, want the address looked up late", got)
	}
	// More passes, more answers of the edge: no more lookups.
	for range 2 {
		select {
		case <-passes:
		case <-time.After(20 * time.Second):
			t.Fatal("no reconcile pass")
		}
	}
	if n := asked.Load(); n != 1 {
		t.Errorf("the echo service was asked %d times, want once", n)
	}
}
