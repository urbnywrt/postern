package diag

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/state"
)

// fakeProbes stands for probe.FakeTLS and probe.L2 against a fake test
// listener: it records where each probe went and answers as set.
type fakeProbes struct {
	mu       sync.Mutex
	l1, l2   error
	l1Addrs  []string
	l2Addrs  []string
	sni      string
	secret   []byte
	dc       int16
	probes   []*nodev1.ProbeResult
	l2Called int
}

func (f *fakeProbes) L1(_ context.Context, addr, sni string, secret []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.l1Addrs = append(f.l1Addrs, addr)
	f.sni, f.secret = sni, secret
	return f.l1
}

func (f *fakeProbes) L2(ctx context.Context, addr, sni string, secret []byte, dc int16) error {
	if strings.HasPrefix(sni, "hang.") {
		<-ctx.Done()
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.l2Addrs = append(f.l2Addrs, addr)
	f.sni, f.secret, f.dc = sni, secret, dc
	f.l2Called++
	return f.l2
}

func (f *fakeProbes) add(p *nodev1.ProbeResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes = append(f.probes, p)
}

// e2eEnv: P1 (fake TLS, serving) on L1, whose test listener is on 127.0.0.1:
// 24001; W1 a WEB proxy; P2 enabled and serving on L2, which has no test
// listener; P3 disabled.
func e2eEnv(f *fakeProbes) *Env {
	st := &nodev1.NodeState{Proxies: []*nodev1.Proxy{
		{Id: "P1", ListenerId: "L1", Enabled: true, Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Secret: testSecret, Domain: "example.com"},
		{Id: "W1", ListenerId: "L1", Enabled: true, Type: nodev1.ProxyType_PROXY_TYPE_WEB, Secret: testSecret, Domain: "web.example.com"},
		{Id: "P2", ListenerId: "L2", Enabled: true, Secret: testSecret, Domain: "example.net"},
		{Id: "P3", ListenerId: "L1", Secret: testSecret, Domain: "example.org"},
	}}
	rt := state.NewRuntime()
	rt.Ports[state.TestListenerPortKey("L1")] = 24001
	for _, id := range []string{"P1", "W1", "P2", "P3"} {
		rt.Instances[id] = state.InstanceRecord{Generation: 1, ListenPort: 20001, SocksPort: 20002}
	}
	return &Env{Desired: st, Runtime: rt, L1: f.L1, L2: f.L2, AddProbe: f.add, Scrub: NewScrubber(st, rt, nil),
		Now: func() time.Time { return time.Unix(1_790_000_000, 0) }}
}

func TestE2ETargets(t *testing.T) {
	env := e2eEnv(&fakeProbes{})
	if got := strings.Join(e2eTargets(env), " "); got != "proxy:P1 proxy:P2" {
		t.Errorf("targets = %q, want the enabled fake-TLS proxies", got)
	}
}

func TestE2EL1(t *testing.T) {
	f := &fakeProbes{}
	env := e2eEnv(f)
	rs := byTarget(checkL1(context.Background(), env))
	if len(rs) != 2 {
		t.Fatalf("results = %+v", rs)
	}
	if r := rs["proxy:P1"]; r.Status != OK {
		t.Errorf("L1 passing: %+v", r)
	}
	if r := rs["proxy:P2"]; r.Status != Skip {
		t.Errorf("no test listener: %+v", r)
	}
	want, _ := hex.DecodeString(testSecret)
	if len(f.l1Addrs) != 1 || f.l1Addrs[0] != "127.0.0.1:24001" || f.sni != "example.com" || !bytes.Equal(f.secret, want) {
		t.Errorf("L1 went to %v with %q", f.l1Addrs, f.sni)
	}
	f.l1 = errors.New("probe: server digest mismatch")
	env.Only = "proxy:P1"
	if r := one(t, checkL1(context.Background(), env)); r.Status != Fail || r.Fix != FixRecreateInstance || !strings.Contains(r.Evidence, "digest") {
		t.Errorf("L1 failing: %+v", r)
	}
	delete(env.Runtime.Instances, "P1")
	if r := one(t, checkL1(context.Background(), env)); r.Status != Skip {
		t.Errorf("not serving: %+v", r)
	}
}

// e2e.l2: one L2 per run, to DC 2, through the test listener; its result goes
// to the statistics as a probe of kind l2. A failing L2 is classified by L1:
// the way out (change_egress) when L1 passes.
func TestE2EL2(t *testing.T) {
	f := &fakeProbes{}
	env := e2eEnv(f)
	env.Only = "proxy:P1"
	if r := one(t, checkL2(context.Background(), env)); r.Status != OK || r.Fix != "" {
		t.Errorf("L2 passing: %+v", r)
	}
	if f.l2Called != 1 || len(f.l1Addrs) != 0 || f.l2Addrs[0] != "127.0.0.1:24001" || f.dc != 2 {
		t.Errorf("L2 %d× to %v DC%d, L1 %v", f.l2Called, f.l2Addrs, f.dc, f.l1Addrs)
	}
	if len(f.probes) != 1 || f.probes[0].GetKind() != "l2" || !f.probes[0].GetOk() || f.probes[0].GetProxyId() != "P1" || f.probes[0].GetAtUnix() != 1_790_000_000 {
		t.Errorf("probes = %v", f.probes)
	}

	f.l2 = errors.New("probe: bad resPQ: EOF from 192.0.2.77:443 secret " + testSecret)
	r := one(t, checkL2(context.Background(), env))
	if r.Status != Fail || r.Fix != FixChangeEgress || f.l2Called != 2 || len(f.l1Addrs) != 1 {
		t.Errorf("L2 failing while L1 passes: %+v (L2 %d×, L1 %d×)", r, f.l2Called, len(f.l1Addrs))
	}
	p := f.probes[1]
	if p.GetOk() || p.GetError() == "" || strings.Contains(p.GetError(), testSecret) || strings.Contains(p.GetError(), "192.0.2.77") {
		t.Errorf("failed probe = %v, want an error without the secret or the address", p)
	}

	f.l1 = errors.New("connection refused")
	if r := one(t, checkL2(context.Background(), env)); r.Status != Fail || r.Fix != "" || !strings.Contains(r.Hint, IDE2EL1) {
		t.Errorf("L2 and L1 failing: %+v", r)
	}

	// Without a test listener there is nothing to probe, and no probe result.
	env.Only = "proxy:P2"
	n := len(f.probes)
	if r := one(t, checkL2(context.Background(), env)); r.Status != Skip || len(f.probes) != n {
		t.Errorf("no test listener: %+v, probes %d → %d", r, n, len(f.probes))
	}
}

// With the real probes (Env.L1 unset), L1 goes to the test listener without
// a PROXY header: the first bytes are a TLS handshake record.
func TestE2EL1RealProbeWithoutProxyHeader(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	first := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		b := make([]byte, 12)
		_, _ = io.ReadFull(c, b)
		first <- b
		_ = c.Close()
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	n, _ := strconv.Atoi(port)
	env := e2eEnv(&fakeProbes{})
	env.L1, env.L2 = nil, nil
	env.Runtime.Ports[state.TestListenerPortKey("L1")] = uint16(n)
	env.Only = "proxy:P1"
	if r := one(t, checkL1(context.Background(), env)); r.Status != Fail || r.Fix != FixRecreateInstance {
		t.Errorf("a listener that closes: %+v", r)
	}
	select {
	case b := <-first:
		if b[0] != 0x16 || bytes.HasPrefix(b, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
			t.Errorf("first bytes %x, want a TLS handshake record and no PROXY header", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the probe never reached the test listener")
	}
}

// Two proxies whose L2 hangs past the check's time do not make the others
// fail: the proxies are probed at once, each under its own deadline; the
// hanging ones are "not checked in time" and give the statistics no row.
func TestE2EL2HangingProxies(t *testing.T) {
	f := &fakeProbes{}
	env := e2eEnv(f)
	env.Desired.Proxies = append([]*nodev1.Proxy{
		{Id: "H1", ListenerId: "L1", Enabled: true, Secret: testSecret, Domain: "hang.one.example"},
		{Id: "H2", ListenerId: "L1", Enabled: true, Secret: testSecret, Domain: "hang.two.example"},
	}, env.Desired.Proxies...)
	env.Desired.Proxies = append(env.Desired.Proxies, &nodev1.Proxy{Id: "P4", ListenerId: "L1", Enabled: true, Secret: testSecret, Domain: "example.info"})
	for _, id := range []string{"H1", "H2", "P4"} {
		env.Runtime.Instances[id] = state.InstanceRecord{Generation: 1, ListenPort: 20001}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rs := byTarget(checkL2(ctx, env))
	for _, id := range []string{"proxy:H1", "proxy:H2"} {
		if r := rs[id]; r.Status != Skip || r.Summary != notInTime {
			t.Errorf("%s hanging: %+v", id, r)
		}
	}
	for _, id := range []string{"proxy:P1", "proxy:P4"} {
		if r := rs[id]; r.Status != OK {
			t.Errorf("%s after the hanging ones: %+v", id, r)
		}
	}
	for _, p := range f.probes {
		if !p.GetOk() || strings.HasPrefix(p.GetProxyId(), "H") {
			t.Errorf("probe row %v", p)
		}
	}
	if len(f.probes) != 2 {
		t.Errorf("probe rows = %d, want 2", len(f.probes))
	}
}
