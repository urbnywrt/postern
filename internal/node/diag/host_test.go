package diag

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/node/state"
)

// fakeEdge answers Health and Snapshot as the test sets them.
type fakeEdge struct {
	mu     sync.Mutex
	health *edgev1.HealthResponse
	snap   *edgev1.SnapshotResponse
	err    error
}

func (e *fakeEdge) Health(context.Context) (*edgev1.HealthResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.health, e.err
}

func (e *fakeEdge) Snapshot(context.Context) (*edgev1.SnapshotResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snap, e.err
}

func edgeEnv(e *fakeEdge, st *nodev1.NodeState) *Env {
	rt := state.NewRuntime()
	rt.EdgeGeneration = 3
	return &Env{Desired: st, Runtime: rt, Edge: func(uint64) EdgeClient { return e }}
}

func one(t *testing.T, rs []Result) Result {
	t.Helper()
	if len(rs) != 1 {
		t.Fatalf("results = %+v, want one", rs)
	}
	return rs[0]
}

// ---- host.clock -------------------------------------------------------------------

// dateServer is a TLS server that answers 415 with a Date off by offset, after
// a handshake that takes delay.
func dateServer(t *testing.T, offset, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", time.Now().Add(offset).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusUnsupportedMediaType)
	}))
	if delay > 0 {
		srv.Listener = slowListener{srv.Listener, delay}
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the unverified case fails handshakes
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

type slowListener struct {
	net.Listener
	delay time.Duration
}

func (l slowListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		time.Sleep(l.delay)
	}
	return c, err
}

func clockEnv(srvs ...*httptest.Server) *Env {
	env := &Env{}
	for _, s := range srvs {
		env.ClockURLs = append(env.ClockURLs, s.URL+"/dns-query")
		env.ClockTLS = s.Client().Transport.(*http.Transport).TLSClientConfig
	}
	return env
}

func TestClock(t *testing.T) {
	ok := dateServer(t, 0, 0)
	cases := []struct {
		name string
		env  *Env
		want nodev1.CheckStatus
	}{
		{"on time", clockEnv(ok, dateServer(t, 0, 0), dateServer(t, 0, 0)), OK},
		{"3 s off", clockEnv(dateServer(t, 3500*time.Millisecond, 0), dateServer(t, 3500*time.Millisecond, 0), ok), Warn},
		{"40 s off", clockEnv(dateServer(t, -40*time.Second, 0), dateServer(t, -40*time.Second, 0)), Fail},
		{"slow handshake", clockEnv(dateServer(t, 0, 1500*time.Millisecond), dateServer(t, 0, 1500*time.Millisecond)), OK},
	}
	for _, c := range cases {
		r := one(t, checkClock(context.Background(), c.env))
		if r.Status != c.want {
			t.Errorf("%s: %v %q\n%s", c.name, r.Status, r.Summary, r.Evidence)
		}
	}

	// Too few answers: one, and a port nobody listens on.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "https://" + ln.Addr().String() + "/dns-query"
	_ = ln.Close()
	env := clockEnv(ok)
	env.ClockURLs = append(env.ClockURLs, dead)
	if r := one(t, checkClock(context.Background(), env)); r.Status != Skip {
		t.Errorf("one answer: %v %q, want skip", r.Status, r.Summary)
	}
	// An endpoint whose certificate does not verify does not count.
	env = clockEnv(ok, dateServer(t, 0, 0))
	env.ClockTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	if r := one(t, checkClock(context.Background(), env)); r.Status != Skip {
		t.Errorf("unverified endpoints: %v %q, want skip", r.Status, r.Summary)
	}
}

func TestDateSkew(t *testing.T) {
	d := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		local time.Time
		rtt   time.Duration
		want  time.Duration
	}{
		{d.Add(500 * time.Millisecond), 0, 0},
		{d.Add(1200 * time.Millisecond), 400 * time.Millisecond, 0},
		{d.Add(3 * time.Second), 0, 2 * time.Second},
		{d.Add(3 * time.Second), time.Second, time.Second},
		{d.Add(-2 * time.Second), time.Second, 2 * time.Second},
		{d.Add(5 * time.Second), -time.Second, 4 * time.Second},
	}
	for _, c := range cases {
		if got := dateSkew(c.local, d, c.rtt); got != c.want {
			t.Errorf("dateSkew(%s, rtt %s) = %s, want %s", c.local.Sub(d), c.rtt, got, c.want)
		}
	}
}

func FuzzDateSkew(f *testing.F) {
	f.Add(int64(0), int64(0), int64(0))
	f.Add(int64(1<<62), int64(-1<<62), int64(1<<40))
	f.Add(int64(-1<<63), int64(1<<63-1), int64(-1))
	f.Fuzz(func(t *testing.T, local, date, rtt int64) {
		l, d := time.Unix(0, local), time.Unix(0, date)
		if s := dateSkew(l, d, time.Duration(rtt)); s < 0 {
			t.Fatalf("dateSkew(%d, %d, %d) = %d", local, date, rtt, s)
		}
		if s := dateSkew(time.Unix(local, 0), time.Unix(date, 0), time.Duration(rtt)); s < 0 {
			t.Fatalf("dateSkew in seconds (%d, %d, %d) = %d", local, date, rtt, s)
		}
	})
}

// ---- host.dns ---------------------------------------------------------------------

// answer makes the answer to query: NXDOMAIN, or the A record forged.
func answer(t testing.TB, query []byte, forged string) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		t.Error(err)
		return nil
	}
	q, err := p.Question()
	if err != nil {
		t.Error(err)
		return nil
	}
	h.Response, h.RCode = true, dnsmessage.RCodeNameError
	if forged != "" {
		h.RCode = dnsmessage.RCodeSuccess
	}
	b := dnsmessage.NewBuilder(nil, h)
	_ = b.StartQuestions()
	_ = b.Question(q)
	if forged != "" {
		_ = b.StartAnswers()
		_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: netip.MustParseAddr(forged).As4()})
	}
	msg, err := b.Finish()
	if err != nil {
		t.Error(err)
	}
	return msg
}

// udpServer answers DNS over UDP: "agree" with NXDOMAIN, "forge" with an A
// record, "drop" never.
func udpServer(t *testing.T, mode string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			switch mode {
			case "agree":
				_, _ = pc.WriteTo(answer(t, buf[:n], ""), from)
			case "forge":
				_, _ = pc.WriteTo(answer(t, buf[:n], "198.18.0.66"), from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

type fakeDoH struct {
	t   testing.TB
	err error
}

func (d fakeDoH) Exchange(_ context.Context, q []byte) ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	return answer(d.t, q, ""), nil
}

func TestDNS(t *testing.T) {
	agree, drop, forge := udpServer(t, "agree"), udpServer(t, "drop"), udpServer(t, "forge")
	type c struct {
		mode    string
		fwd     bool
		servers []string
		doh     error
		want    nodev1.CheckStatus
		fix     string
	}
	cases := map[string]c{
		"doh agreeing":          {state.DNSModeDoH, true, []string{agree, agree}, nil, OK, ""},
		"doh timing out":        {state.DNSModeDoH, true, []string{agree, drop}, nil, Warn, ""},
		"doh forged":            {state.DNSModeDoH, true, []string{forge, agree}, nil, Warn, ""},
		"doh forwarder down":    {state.DNSModeDoH, false, []string{agree, agree}, nil, Fail, ""},
		"doh no doh":            {state.DNSModeDoH, true, []string{agree, agree}, errors.New("refused"), Warn, ""},
		"system agreeing":       {state.DNSModeSystem, false, []string{agree, agree}, nil, OK, ""},
		"system timing out":     {state.DNSModeSystem, false, []string{drop, agree}, nil, Fail, FixDNSModeDoH},
		"system forged":         {state.DNSModeSystem, false, []string{agree, forge}, nil, Fail, FixDNSModeDoH},
		"default mode is doh":   {"", true, []string{agree, agree}, nil, OK, ""},
		"system without doh ok": {state.DNSModeSystem, false, []string{agree, agree}, errors.New("x"), Warn, ""},
	}
	for name, cs := range cases {
		e := &fakeEdge{health: &edgev1.HealthResponse{Dns: cs.fwd}}
		env := edgeEnv(e, &nodev1.NodeState{Settings: &nodev1.NodeSettings{DnsMode: cs.mode}})
		env.DNSServers, env.DoH = cs.servers, fakeDoH{t: t, err: cs.doh}
		start := time.Now()
		r := one(t, checkDNS(context.Background(), env))
		if r.Status != cs.want || r.Fix != cs.fix {
			t.Errorf("%s: %v fix %q %q\n%s", name, r.Status, r.Fix, r.Summary, r.Evidence)
		}
		if d := time.Since(start); d > SlowTimeout {
			t.Errorf("%s took %s", name, d)
		}
		if name == "doh forged" && !strings.Contains(r.Evidence, "hijacked") {
			t.Errorf("forged evidence: %s", r.Evidence)
		}
		if name == "doh timing out" && !strings.Contains(r.Evidence, "blocked (timeout)") {
			t.Errorf("timeout evidence: %s", r.Evidence)
		}
	}
}

// fakeAllDoH is a DoH client of four endpoints, asked all at once; silent
// names the ones that give no answer.
type fakeAllDoH struct {
	t      testing.TB
	silent map[string]bool
}

var fakeEndpoints = []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"}

func (d fakeAllDoH) Exchange(context.Context, []byte) ([]byte, error) {
	d.t.Error("Exchange called; host.dns must ask every endpoint")
	return nil, errors.New("not this way")
}

func (d fakeAllDoH) ExchangeAll(_ context.Context, q []byte) ([]byte, []error, error) {
	var failed []error
	for _, ep := range fakeEndpoints {
		if d.silent[ep] {
			failed = append(failed, fmt.Errorf("%s: context deadline exceeded", ep))
		}
	}
	if len(failed) == len(fakeEndpoints) {
		return nil, failed, &doh.Error{Attempts: failed}
	}
	return answer(d.t, q, ""), failed, nil
}

func TestDNSAsksEveryDoHEndpoint(t *testing.T) {
	agree := udpServer(t, "agree")
	run := func(silent ...string) Result {
		e := &fakeEdge{health: &edgev1.HealthResponse{Dns: true}}
		env := edgeEnv(e, &nodev1.NodeState{Settings: &nodev1.NodeSettings{DnsMode: state.DNSModeDoH}})
		s := map[string]bool{}
		for _, ep := range silent {
			s[ep] = true
		}
		env.DNSServers, env.DoH = []string{agree}, fakeAllDoH{t: t, silent: s}
		return one(t, checkDNS(context.Background(), env))
	}

	r := run("1.1.1.1", "1.0.0.1")
	if r.Status != OK || strings.Contains(r.Summary, "does not answer") {
		t.Errorf("Cloudflare silent, Google answering: %v %q", r.Status, r.Summary)
	}
	for _, ep := range []string{"1.1.1.1", "1.0.0.1"} {
		if !strings.Contains(r.Evidence, "no answer from "+ep+": context deadline exceeded") {
			t.Errorf("the evidence does not name %s:\n%s", ep, r.Evidence)
		}
	}
	if strings.Contains(r.Evidence, "8.8.8.8:") || !strings.Contains(r.Summary, "2 DNS-over-HTTPS endpoint(s) did not answer") {
		t.Errorf("summary %q, evidence:\n%s", r.Summary, r.Evidence)
	}

	r = run(fakeEndpoints...)
	if r.Status != Warn || r.Summary != "DNS over HTTPS does not answer" {
		t.Errorf("all silent: %v %q", r.Status, r.Summary)
	}
	for _, ep := range fakeEndpoints {
		if !strings.Contains(r.Evidence, ep+": context deadline exceeded") {
			t.Errorf("the evidence does not name %s:\n%s", ep, r.Evidence)
		}
	}
}

// ---- host.ports -------------------------------------------------------------------

func TestPorts(t *testing.T) {
	st := &nodev1.NodeState{Listeners: []*nodev1.Listener{
		{Id: "a", BindIp: "203.0.113.10", Port: 443},
		{Id: "b", BindIp: "0.0.0.0", Port: 8443},
		{Id: "c", BindIp: "203.0.113.10", Port: 9443},
		{Id: "d", BindIp: "203.0.113.10", Port: 7443},
	}}
	owners := []SocketOwner{
		// Two SO_REUSEPORT sockets on a: the edge's and a stranger's.
		{Bind: "203.0.113.10", Port: 443, PID: 10, Owner: "postern-edge-g3", Known: true},
		{Bind: "203.0.113.10", Port: 443, PID: 900, Owner: "nginx (pid 900)", Known: true},
		// b: two generations of the edge.
		{Bind: "0.0.0.0", Port: 8443, PID: 10, Owner: "postern-edge-g3", Known: true},
		{Bind: "0.0.0.0", Port: 8443, PID: 11, Owner: "postern-edge-g4", Known: true},
		// c: an owner that cannot be read.
		{Bind: "0.0.0.0", Port: 9443, Known: false},
		// Elsewhere: the agent's and a stranger's on other ports.
		{Bind: "0.0.0.0", Port: 7000, PID: 1, Owner: OwnerAgent, Known: true},
		{Bind: "127.0.0.1", Port: 7443, PID: 901, Owner: "other (pid 901)", Known: true},
	}
	env := &Env{Desired: st, PortOwners: func(context.Context) []SocketOwner { return owners }}
	got := map[string]Result{}
	for _, r := range checkPorts(context.Background(), env) {
		got[r.Target] = r
	}
	if r := got["listener:a"]; r.Status != Fail || !strings.Contains(r.Evidence, "nginx (pid 900)") {
		t.Errorf("a = %+v, want fail naming nginx", r)
	}
	if r := got["listener:b"]; r.Status != OK {
		t.Errorf("b = %+v, want ok: both are the edge's", r)
	}
	if r := got["listener:c"]; r.Status != Warn || !strings.Contains(r.Summary, "owner unknown") {
		t.Errorf("c = %+v, want warn: owner unknown", r)
	}
	if r := got["listener:d"]; r.Status != OK {
		t.Errorf("d = %+v, want ok: 127.0.0.1 is another address", r)
	}
}

// ---- host.public_ips --------------------------------------------------------------

func TestPublicIPs(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	var ips []netip.Addr
	st := &nodev1.NodeState{Listeners: []*nodev1.Listener{{Id: "a", BindIp: "0.0.0.0", Port: 443}, {Id: "b", BindIp: "203.0.113.10", Port: 8443}}}
	env := &Env{Desired: st, Now: func() time.Time { return now }, PublicIPs: func(context.Context) []netip.Addr { return ips }}
	h := &publicIPHistory{}
	step := func(want nodev1.CheckStatus, list ...string) Result {
		t.Helper()
		ips = nil
		for _, s := range list {
			ips = append(ips, netip.MustParseAddr(s))
		}
		r := one(t, h.run(context.Background(), env))
		if r.Status != want {
			t.Errorf("%v: %v %q %q, want %v", list, r.Status, r.Summary, r.Evidence, want)
		}
		return r
	}
	step(OK, "203.0.113.10")
	step(Fail) // none known
	now = now.Add(time.Hour)
	step(OK, "203.0.113.10") // an echo service that did not answer changes nothing
	r := step(Warn, "203.0.113.10", "2001:db8::10")
	if !strings.Contains(r.Evidence, "before: 203.0.113.10") || !strings.Contains(r.Evidence, "now: 203.0.113.10, 2001:db8::10") {
		t.Errorf("evidence = %q", r.Evidence)
	}
	now = now.Add(25 * time.Hour)
	step(OK, "2001:db8::10", "203.0.113.10")
	r = step(Fail, "198.51.100.1")
	if !strings.Contains(r.Evidence, "listener b binds 203.0.113.10") {
		t.Errorf("evidence = %q", r.Evidence)
	}
}

// ---- host.disk, host.memory, host.reserved_ports -----------------------------------

func TestDisk(t *testing.T) {
	cases := []struct {
		total, avail uint64
		want         nodev1.CheckStatus
	}{
		{100 * gib, 50 * gib, OK},
		{100 * gib, 4 * gib, Warn}, // under 5 %
		{4 * gib, 900 * mib, Warn}, // under 1 GiB
		{4 * gib, 200 * mib, Fail}, // under 256 MiB
		{0, 0, Skip},
	}
	for _, c := range cases {
		env := &Env{DiskPath: "/opt/postern", DiskSpace: func(string) (uint64, uint64, error) { return c.total, c.avail, nil }}
		if r := one(t, checkDisk(context.Background(), env)); r.Status != c.want {
			t.Errorf("%d of %d: %v %q, want %v", c.avail, c.total, r.Status, r.Summary, c.want)
		}
	}
}

func TestMemory(t *testing.T) {
	cases := []struct {
		meminfo string
		want    nodev1.CheckStatus
	}{
		{"MemTotal: 2048000 kB\nMemFree: 100 kB\nMemAvailable: 1024000 kB\n", OK},
		{"MemTotal: 2048000 kB\nMemAvailable: 150000 kB\n", Warn},
		{"MemTotal: 512000 kB\nMemAvailable: 60000 kB\n", Fail},
		{"MemTotal: 8000000 kB\nMemFree: 2000000 kB\n", OK}, // no MemAvailable: MemFree
		{"garbage", Skip},
	}
	for _, c := range cases {
		env := &Env{Proc: fstest.MapFS{"meminfo": {Data: []byte(c.meminfo)}}}
		if r := one(t, checkMemory(context.Background(), env)); r.Status != c.want {
			t.Errorf("%q: %v %q, want %v", c.meminfo, r.Status, r.Summary, c.want)
		}
	}
}

func TestReservedPorts(t *testing.T) {
	cases := map[string]nodev1.CheckStatus{
		"20000-40999\n":                OK,
		"8080,20000-30000,30001-40999": OK,
		"10000-50000":                  OK,
		"20000-40998":                  Warn,
		"":                             Warn,
		"20000-30000,30002-40999":      Warn,
	}
	for v, want := range cases {
		env := &Env{Proc: fstest.MapFS{"sys/net/ipv4/ip_local_reserved_ports": {Data: []byte(v)}}}
		if r := one(t, checkReservedPorts(context.Background(), env)); r.Status != want {
			t.Errorf("%q: %v, want %v", v, r.Status, want)
		}
	}
	if r := one(t, checkReservedPorts(context.Background(), &Env{Proc: fstest.MapFS{}})); r.Status != Skip {
		t.Errorf("unreadable: %v", r.Status)
	}
}

// ---- host.edge_caps, host.docker, host.stats ----------------------------------------

func TestEdgeCaps(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	e := &fakeEdge{snap: &edgev1.SnapshotResponse{}}
	env := edgeEnv(e, nil)
	env.Now = func() time.Time { return now }
	c := &edgeCaps{}
	step := func(prehello, total, evicted uint64, want nodev1.CheckStatus) Result {
		t.Helper()
		e.snap = &edgev1.SnapshotResponse{RefusedPrehello: prehello, RefusedTotal: total, EvictedPrehello: evicted}
		r := one(t, c.run(context.Background(), env))
		if r.Status != want {
			t.Errorf("at %s with %d/%d/%d: %v %q, want %v", now.Format(time.TimeOnly), prehello, total, evicted, r.Status, r.Summary, want)
		}
		return r
	}
	step(0, 0, 0, OK)
	now = now.Add(10 * time.Minute)
	r := step(3, 1, 2, Warn)
	if !strings.Contains(r.Evidence, "refused before the ClientHello 3, refused at the connection cap 1, evicted before the ClientHello 2") {
		t.Errorf("evidence = %q", r.Evidence)
	}
	now = now.Add(5 * time.Minute)
	step(3, 1, 2, Warn) // within 10 minutes of the refusals
	now = now.Add(6 * time.Minute)
	step(3, 1, 2, OK) // 10 minutes after them: none since
	e.err = errors.New("gone")
	if r := one(t, c.run(context.Background(), env)); r.Status != Skip {
		t.Errorf("no answer: %v", r.Status)
	}
}

func TestDockerAndStats(t *testing.T) {
	d := dockerapi.NewFake()
	if r := one(t, checkDocker(context.Background(), &Env{Docker: d})); r.Status != OK {
		t.Errorf("docker = %+v", r)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	var minute time.Time
	n := 0
	env := &Env{Now: func() time.Time { return now }, StatsOverflow: func() (time.Time, int) { return minute, n }}
	if r := one(t, checkStats(context.Background(), env)); r.Status != OK {
		t.Errorf("no overflow: %+v", r)
	}
	minute, n = now.Add(-2*time.Minute), 1234
	if r := one(t, checkStats(context.Background(), env)); r.Status != Warn || !strings.Contains(r.Summary, "1234") {
		t.Errorf("overflow: %+v", r)
	}
	now = now.Add(time.Hour)
	if r := one(t, checkStats(context.Background(), env)); r.Status != OK {
		t.Errorf("old overflow: %+v", r)
	}
}

// ---- ingress.bound ----------------------------------------------------------------

func TestBound(t *testing.T) {
	st := &nodev1.NodeState{Listeners: []*nodev1.Listener{{Id: "a", BindIp: "0.0.0.0", Port: 443}, {Id: "b", BindIp: "203.0.113.10", Port: 8443}}}
	e := &fakeEdge{health: &edgev1.HealthResponse{
		Bound:            []string{"203.0.113.10:8443"},
		ListenerFailures: []*edgev1.ListenerFailure{{ListenerId: "a", Reason: "listen tcp 0.0.0.0:443: bind: address already in use"}},
	}}
	got := map[string]Result{}
	for _, r := range checkBound(context.Background(), edgeEnv(e, st)) {
		got[r.Target] = r
	}
	if r := got["listener:a"]; r.Status != Fail || !strings.Contains(r.Evidence, "address already in use") {
		t.Errorf("a = %+v", r)
	}
	if r := got["listener:b"]; r.Status != OK {
		t.Errorf("b = %+v", r)
	}
	e.err = errors.New("dial unix: no such file")
	for _, r := range checkBound(context.Background(), edgeEnv(e, st)) {
		if r.Status != Fail {
			t.Errorf("edge down: %+v", r)
		}
	}
	env := edgeEnv(e, st)
	env.Runtime.EdgeGeneration = 0
	if rs := checkBound(context.Background(), env); len(rs) != 2 || rs[0].Status != Fail {
		t.Errorf("no edge: %+v", rs)
	}
}

// Without root no owner can be read: one note, not a warning per listener.
func TestPortsWithoutRoot(t *testing.T) {
	st := &nodev1.NodeState{Listeners: []*nodev1.Listener{{Id: "a", BindIp: "0.0.0.0", Port: 443}, {Id: "b", BindIp: "0.0.0.0", Port: 8443}}}
	owners := []SocketOwner{{Bind: "0.0.0.0", Port: 443}, {Bind: "0.0.0.0", Port: 8443}, {Bind: "127.0.0.1", Port: 20001}}
	env := &Env{Desired: st, PortOwners: func(context.Context) []SocketOwner { return owners }}
	r := one(t, checkPorts(context.Background(), env))
	if r.Status != Warn || r.Target != "" || !strings.Contains(r.Hint, "root") {
		t.Errorf("result = %+v", r)
	}
}
