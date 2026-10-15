package agent

import (
	"context"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// modeIf is modeFull when full is set, else modeOff.
func modeIf(full bool) ipMode {
	if full {
		return modeFull
	}
	return modeOff
}

// minuteAt is 12:mm:ss on a fixed day, UTC.
func minuteAt(mm, ss int) time.Time {
	return time.Date(2026, 10, 4, 12, mm, ss, 0, time.UTC)
}

func pc(id string, up, down, conns uint64, active, devices uint32) *edgev1.ProxyCounters {
	return &edgev1.ProxyCounters{ProxyId: id, BytesUp: up, BytesDown: down, ConnsTotal: conns, ConnsActive: active, DevicesActive: devices}
}

func snap(gen uint64, proxies ...*edgev1.ProxyCounters) *edgev1.SnapshotResponse {
	return &edgev1.SnapshotResponse{Generation: gen, Proxies: proxies}
}

func snaps(s ...*edgev1.SnapshotResponse) map[uint64]*edgev1.SnapshotResponse {
	m := map[uint64]*edgev1.SnapshotResponse{}
	for _, x := range s {
		m[x.GetGeneration()] = x
	}
	return m
}

func proxyMinute(b *nodev1.StatsBatch, id string) *nodev1.ProxyMinute {
	for _, p := range b.GetProxies() {
		if p.GetProxyId() == id {
			return p
		}
	}
	return nil
}

func mustNoBatch(t *testing.T, b *nodev1.StatsBatch) {
	t.Helper()
	if b != nil {
		t.Fatalf("a batch came out early: %v", b)
	}
}

func checkMinute(t *testing.T, got *nodev1.ProxyMinute, want *nodev1.ProxyMinute) {
	t.Helper()
	if !proto.Equal(got, want) {
		t.Errorf("proxy minute = %v\nwant %v", got, want)
	}
}

// What the edge counted before the agent started is not this minute's
// traffic: the first snapshot only sets the baseline.
func TestAggregatorBaselinesWhatRanBeforeTheAgent(t *testing.T) {
	a := newAggregator()
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(snap(1, pc("p1", 1000, 2000, 50, 3, 2))), nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(snap(1, pc("p1", 1100, 2300, 52, 4, 2))), nil, false, modeOff))
	b := a.observe(minuteAt(1, 5), snaps(snap(1, pc("p1", 1150, 2300, 52, 1, 1))), nil, false, modeOff)
	if b == nil {
		t.Fatal("no batch at the start of the next minute")
	}
	if b.GetMinuteUnix() != minuteAt(0, 0).Unix() {
		t.Errorf("minute = %d, want %d", b.GetMinuteUnix(), minuteAt(0, 0).Unix())
	}
	checkMinute(t, proxyMinute(b, "p1"), &nodev1.ProxyMinute{
		ProxyId: "p1", Up: 100, Down: 300, ConnsNew: 2, ConnsPeak: 4, Devices: 2, ConnsActive: 4,
	})
	// The next minute has what came after.
	b = a.observe(minuteAt(2, 5), snaps(snap(1, pc("p1", 1150, 2300, 52, 0, 0))), nil, false, modeOff)
	checkMinute(t, proxyMinute(b, "p1"), &nodev1.ProxyMinute{
		ProxyId: "p1", Up: 50, Down: 0, ConnsNew: 0, ConnsPeak: 1, Devices: 1, ConnsActive: 1,
	})
}

// A new edge generation starts its counters from zero, the old one goes on
// with its own until it is gone; the minute has the increments of both.
func TestAggregatorSumsIncrementsAcrossAnEdgeGenerationChange(t *testing.T) {
	a := newAggregator()
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(snap(1, pc("p1", 1000, 2000, 50, 5, 3))), nil, false, modeOff))
	// Generation 2 appeared after the agent started: all it counted is new.
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(
		snap(1, pc("p1", 1100, 2100, 51, 2, 2)),
		snap(2, pc("p1", 30, 40, 1, 4, 2)),
	), nil, false, modeOff))
	// Generation 1 drained and exited.
	mustNoBatch(t, a.observe(minuteAt(0, 25), snaps(snap(2, pc("p1", 80, 90, 2, 5, 3))), nil, false, modeOff))
	b := a.observe(minuteAt(1, 5), snaps(snap(2, pc("p1", 80, 90, 2, 5, 3))), nil, false, modeOff)
	checkMinute(t, proxyMinute(b, "p1"), &nodev1.ProxyMinute{
		ProxyId: "p1",
		Up:      100 + 30 + 50, Down: 100 + 40 + 50, ConnsNew: 1 + 1 + 1,
		ConnsPeak: 6, Devices: 4, ConnsActive: 5,
	})
	// The socket of generation 1 is back: its container was started again,
	// and all the new process counted is new, also when it is more than the
	// old process had counted when it went.
	mustNoBatch(t, a.observe(minuteAt(1, 15), snaps(snap(1, pc("p1", 2000, 3000, 60, 0, 0)), snap(2, pc("p1", 80, 90, 2, 0, 0))), nil, false, modeOff))
	b = a.observe(minuteAt(2, 5), snaps(snap(1, pc("p1", 2000, 3000, 60, 0, 0)), snap(2, pc("p1", 90, 90, 2, 0, 0))), nil, false, modeOff)
	if got := proxyMinute(b, "p1"); got.GetUp() != 2000 || got.GetDown() != 3000 || got.GetConnsNew() != 60 {
		t.Errorf("minute = %v, want 2000 up, 3000 down, 60 new connections", got)
	}
}

// An edge whose process restarts within its generation starts its counters
// from zero again; that is never a negative increment.
func TestAggregatorEdgeRestartIsNeverNegative(t *testing.T) {
	a := newAggregator()
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(snap(1,
		pc("p1", 1000, 2000, 50, 1, 1), pc("p2", 500, 500, 5, 0, 0), pc("p3", 100, 5000, 40, 0, 0))), nil, false, modeOff))
	// Restarted: p1 has counted a little since, p2 nothing (so it is not
	// there), p3 already more bytes up than before (the other counters show
	// the restart).
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(snap(1, pc("p1", 100, 50, 3, 1, 1), pc("p3", 300, 10, 1, 0, 0))), nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 25), snaps(snap(1, pc("p1", 150, 80, 4, 1, 1), pc("p2", 7, 9, 1, 1, 1), pc("p3", 300, 10, 1, 0, 0))), nil, false, modeOff))
	b := a.observe(minuteAt(1, 5), snaps(snap(1, pc("p1", 150, 80, 4, 0, 0), pc("p2", 7, 9, 1, 0, 0), pc("p3", 300, 10, 1, 0, 0))), nil, false, modeOff)
	checkMinute(t, proxyMinute(b, "p1"), &nodev1.ProxyMinute{ProxyId: "p1", Up: 150, Down: 80, ConnsNew: 4, ConnsPeak: 1, Devices: 1, ConnsActive: 1})
	checkMinute(t, proxyMinute(b, "p2"), &nodev1.ProxyMinute{ProxyId: "p2", Up: 7, Down: 9, ConnsNew: 1, ConnsPeak: 1, Devices: 1, ConnsActive: 1})
	checkMinute(t, proxyMinute(b, "p3"), &nodev1.ProxyMinute{ProxyId: "p3", Up: 300, Down: 10, ConnsNew: 1})
	for _, p := range b.GetProxies() {
		if p.GetUp() > math.MaxInt64 || p.GetDown() > math.MaxInt64 {
			t.Errorf("an increment went negative: %v", p)
		}
	}
}

// A generation that was there when the agent started but did not answer its
// first snapshot is still one that ran before the agent: its first answer is
// a baseline, not traffic.
func TestAggregatorUnansweredGenerationStillGetsABaseline(t *testing.T) {
	a := newAggregator()
	mustNoBatch(t, a.observe(minuteAt(0, 5), map[uint64]*edgev1.SnapshotResponse{1: nil}, nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(snap(1, pc("p1", 5000, 5000, 70, 0, 0))), nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 25), map[uint64]*edgev1.SnapshotResponse{1: nil}, nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 35), snaps(snap(1, pc("p1", 5100, 5000, 70, 0, 0))), nil, false, modeOff))
	b := a.observe(minuteAt(1, 5), snaps(snap(1, pc("p1", 5100, 5000, 70, 0, 0))), nil, false, modeOff)
	if got := proxyMinute(b, "p1").GetUp(); got != 100 {
		t.Errorf("up = %d, want 100 (the baseline is the first answer)", got)
	}
}

func TestAggregatorReportsClientAddressesOnlyUnderTheFullPolicy(t *testing.T) {
	withIPs := func(ss *edgev1.SnapshotResponse, ips ...*edgev1.IpCounters) *edgev1.SnapshotResponse {
		ss.Ips = ips
		return ss
	}
	ipc := func(ip string, active uint32, seen int64, bytes uint64) *edgev1.IpCounters {
		return &edgev1.IpCounters{ProxyId: "p1", Ip: ip, ConnsActive: active, LastSeenUnix: seen, Bytes: bytes}
	}
	run := func(full bool) *nodev1.StatsBatch {
		a := newAggregator()
		mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 1, 1)),
			ipc("203.0.113.1", 1, minuteAt(0, 5).Unix(), 1000),
			ipc("203.0.113.9", 0, minuteAt(0, 5).Add(-time.Hour).Unix(), 99))), nil, full, modeIf(full)))
		mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(withIPs(snap(1, pc("p1", 0, 0, 1, 2, 2)),
			ipc("203.0.113.1", 1, minuteAt(0, 15).Unix(), 1500),
			ipc("203.0.113.9", 0, minuteAt(0, 5).Add(-time.Hour).Unix(), 99),
			ipc("2001:db8::2", 1, minuteAt(0, 15).Unix(), 300))), nil, full, modeIf(full)))
		return a.observe(minuteAt(1, 5), snaps(withIPs(snap(1, pc("p1", 0, 0, 1, 0, 0)),
			ipc("203.0.113.1", 0, minuteAt(0, 20).Unix(), 1500),
			ipc("2001:db8::2", 0, minuteAt(0, 20).Unix(), 300))), nil, full, modeIf(full))
	}
	if b := run(false); len(b.GetIps()) != 0 {
		t.Errorf("sightings without the full policy: %v", b.GetIps())
	}
	b := run(true)
	got := map[string]*nodev1.IpSighting{}
	for _, s := range b.GetIps() {
		got[s.GetIp()] = s
	}
	if len(got) != 2 {
		t.Fatalf("sightings = %v, want 203.0.113.1 and 2001:db8::2", b.GetIps())
	}
	if s := got["203.0.113.1"]; s.GetBytes() != 500 || s.GetFirstSeen() != minuteAt(0, 5).Unix() || s.GetLastSeen() != minuteAt(0, 15).Unix() || s.GetProxyId() != "p1" {
		t.Errorf("203.0.113.1 = %v", s)
	}
	if s := got["2001:db8::2"]; s.GetBytes() != 300 || s.GetFirstSeen() != minuteAt(0, 15).Unix() {
		t.Errorf("2001:db8::2 = %v (a new address in a known generation counts from zero)", s)
	}
}

// A clock that goes back never makes a minute twice.
func TestAggregatorClockGoingBackDoesNotRepeatAMinute(t *testing.T) {
	a := newAggregator()
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(snap(1, pc("p1", 0, 0, 0, 0, 0))), nil, false, modeOff))
	if b := a.observe(minuteAt(1, 5), snaps(snap(1, pc("p1", 10, 0, 0, 0, 0))), nil, false, modeOff); b.GetMinuteUnix() != minuteAt(0, 0).Unix() {
		t.Fatalf("first batch = %v", b)
	}
	mustNoBatch(t, a.observe(minuteAt(0, 50), snaps(snap(1, pc("p1", 20, 0, 0, 0, 0))), nil, false, modeOff))
	b := a.observe(minuteAt(2, 5), snaps(snap(1, pc("p1", 30, 0, 0, 0, 0))), nil, false, modeOff)
	if b.GetMinuteUnix() != minuteAt(1, 0).Unix() {
		t.Fatalf("second batch is for %d, want %d", b.GetMinuteUnix(), minuteAt(1, 0).Unix())
	}
	// The 12:01:05 and the 12:00:50 ticks, 10 each; the 12:02:05 one is the
	// next minute's.
	if got := proxyMinute(b, "p1").GetUp(); got != 20 {
		t.Errorf("up = %d, want 20", got)
	}
}

func TestAggregatorNodeMinute(t *testing.T) {
	a := newAggregator()
	h := func(busy, total, rx, tx uint64) *hostSample {
		return &hostSample{
			cpuBusy: busy, cpuTotal: total,
			memTotal: 16 << 20, memUsed: 12 << 20,
			load1: 0.5, diskTotal: 100 << 30, diskUsed: 40 << 30,
			net: map[string]netCounters{"eth0": {rx: rx, tx: tx}},
		}
	}
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(snap(1, pc("p1", 0, 0, 0, 3, 1))), h(100, 1000, 5000, 7000), false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(snap(1, pc("p1", 0, 0, 0, 7, 1))), h(180, 1100, 6000, 7500), false, modeOff))
	last := h(200, 1200, 6500, 8000)
	last.load1 = 0.75
	mustNoBatch(t, a.observe(minuteAt(0, 25), snaps(snap(1, pc("p1", 0, 0, 0, 2, 1))), last, false, modeOff))
	b := a.observe(minuteAt(1, 5), snaps(snap(1, pc("p1", 0, 0, 0, 0, 0))), h(300, 1300, 6500, 8000), false, modeOff)
	want := &nodev1.NodeMinute{
		Cpu:      50, // 80 + 20 busy of 200 over the minute
		MemUsed:  12 << 20,
		MemTotal: 16 << 20,
		Load1:    0.75,
		DiskUsed: 40 << 30, DiskTotal: 100 << 30,
		NetRx: 1500, NetTx: 1000,
		Conns: 7,
	}
	if !proto.Equal(b.GetNode(), want) {
		t.Errorf("node minute = %v\nwant %v", b.GetNode(), want)
	}
}

func TestReadHostSample(t *testing.T) {
	proc := fstest.MapFS{
		"stat":    {Data: []byte("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 100 0 50 800 50 0 0 0 0 0\nintr 1\n")},
		"meminfo": {Data: []byte("MemTotal:       16384 kB\nMemFree:          1024 kB\nMemAvailable:    4096 kB\n")},
		"loadavg": {Data: []byte("0.52 0.58 0.59 1/389 12345\n")},
		"net/dev": {Data: []byte("Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"    lo:  999999     10    0    0    0     0          0         0   999999      10    0    0    0     0       0          0\n" +
			"  eth0:    1000     10    0    0    0     0          0         0     2000      20    0    0    0     0       0          0\n" +
			"vethab12:   500      5    0    0    0     0          0         0      500       5    0    0    0     0       0          0\n" +
			"docker0:    700      7    0    0    0     0          0         0      700       7    0    0    0     0       0          0\n" +
			"br-1a2b:    800      8    0    0    0     0          0         0      800       8    0    0    0     0       0          0\n" +
			"  ens5:      30      1    0    0    0     0          0         0       40       1    0    0    0     0       0          0\n")},
	}
	s := readHostSample(proc, t.TempDir())
	if s.cpuBusy != 150 || s.cpuTotal != 1000 {
		t.Errorf("cpu = %d of %d, want 150 of 1000", s.cpuBusy, s.cpuTotal)
	}
	if s.memTotal != 16384*1024 || s.memUsed != (16384-4096)*1024 {
		t.Errorf("memory = %d used of %d", s.memUsed, s.memTotal)
	}
	if s.load1 != 0.52 {
		t.Errorf("load1 = %v", s.load1)
	}
	if len(s.net) != 2 || s.net["eth0"] != (netCounters{rx: 1000, tx: 2000}) || s.net["ens5"] != (netCounters{rx: 30, tx: 40}) {
		t.Errorf("net = %v, want eth0 and ens5 only", s.net)
	}
	if s.diskTotal == 0 || s.diskUsed > s.diskTotal {
		t.Errorf("disk = %d used of %d", s.diskUsed, s.diskTotal)
	}

	// Missing files leave their fields empty.
	empty := readHostSample(fstest.MapFS{}, filepath.Join(t.TempDir(), "missing"))
	if empty.cpuTotal != 0 || empty.memTotal != 0 || len(empty.net) != 0 || empty.diskTotal != 0 {
		t.Errorf("sample of nothing = %+v", empty)
	}
}

// The counters of the client IPs are asked for only while the policy keeps
// them (M4). When they are asked for again, what the edge counted for an
// address meanwhile is not this minute's traffic: their first answer is a
// baseline. An address that comes later is new, and counts from zero.
func TestAggregatorCountsTheIPsFromWhenTheyAreAskedFor(t *testing.T) {
	ip := func(addr string, bytes uint64) *edgev1.IpCounters {
		return &edgev1.IpCounters{ProxyId: "p1", Ip: addr, ConnsActive: 1, LastSeenUnix: minuteAt(0, 30).Unix(), Bytes: bytes}
	}
	withIPs := func(ss *edgev1.SnapshotResponse, ips ...*edgev1.IpCounters) *edgev1.SnapshotResponse {
		ss.Ips = ips
		return ss
	}
	a := newAggregator()
	// Watched without the addresses: the policy did not keep them.
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(snap(1, pc("p1", 0, 0, 0, 1, 1))), nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(snap(1, pc("p1", 0, 0, 0, 1, 1))), nil, false, modeOff))
	// The policy is full now: the first answer with the addresses.
	mustNoBatch(t, a.observe(minuteAt(0, 25), snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 1, 1)), ip("203.0.113.1", 5000))), nil, true, modeFull))
	mustNoBatch(t, a.observe(minuteAt(0, 35), snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 2, 2)),
		ip("203.0.113.1", 5300), ip("203.0.113.2", 100))), nil, true, modeFull))
	b := a.observe(minuteAt(1, 5), snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 2, 2)), ip("203.0.113.1", 5300), ip("203.0.113.2", 100))), nil, true, modeFull)
	got := map[string]uint64{}
	for _, s := range b.GetIps() {
		got[s.GetIp()] = s.GetBytes()
	}
	if got["203.0.113.1"] != 300 || got["203.0.113.2"] != 100 || len(got) != 2 {
		t.Errorf("bytes of the minute by address = %v, want 300 for 203.0.113.1 (counted since it was asked for) and 100 for 203.0.113.2", got)
	}
}

// The edge is asked for the counters of the client IPs on the ticks when the
// IP policy keeps them, and only then (M4).
func TestStatsCollectorAsksForTheIPsOnlyUnderTheFullPolicy(t *testing.T) {
	clock := newTestClock()
	buf := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	src := &fakeSnapshots{queue: []map[uint64]*edgev1.SnapshotResponse{snaps(snap(1, pc("p1", 0, 0, 0, 0, 0)))}}
	var full atomic.Bool
	c := &statsCollector{source: src, agg: newAggregator(), journal: newJournal(buf, discardLog(), clock.Now),
		proc: fstest.MapFS{}, mode: func() ipMode { return modeIf(full.Load()) }, log: discardLog()}
	c.tick(context.Background(), minuteAt(0, 5))
	full.Store(true)
	c.tick(context.Background(), minuteAt(0, 15))
	full.Store(false)
	c.tick(context.Background(), minuteAt(0, 25))
	src.mu.Lock()
	defer src.mu.Unlock()
	if want := []bool{false, true, false}; !slices.Equal(src.asked, want) {
		t.Errorf("IPs asked for = %v, want %v", src.asked, want)
	}
}

// The control socket of an edge is asked for the IPs as the caller says.
func TestSocketSnapshotsAskForTheIPsAsTold(t *testing.T) {
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ctl := serveEdgeControl(t, filepath.Join(dir, "edge-g3.sock"), snap(3, pc("p1", 1, 2, 3, 0, 0)))
	src := newSocketSnapshots(dir, time.Second)
	src.take(context.Background(), false)
	src.take(context.Background(), true)
	if got := ctl.askedIPs(); !slices.Equal(got, []bool{false, true}) {
		t.Errorf("include_ips of the requests = %v, want [false true]", got)
	}
}

// fakeEdgeControl answers Snapshot with a fixed response, and notes whether
// each request asked for the counters of the IPs.
type fakeEdgeControl struct {
	edgev1connect.UnimplementedEdgeControlServiceHandler
	resp *edgev1.SnapshotResponse

	mu    sync.Mutex
	asked []bool
}

func (f *fakeEdgeControl) Snapshot(_ context.Context, req *connect.Request[edgev1.SnapshotRequest]) (*connect.Response[edgev1.SnapshotResponse], error) {
	f.mu.Lock()
	f.asked = append(f.asked, req.Msg.GetIncludeIps())
	f.mu.Unlock()
	return connect.NewResponse(proto.Clone(f.resp).(*edgev1.SnapshotResponse)), nil
}

func (f *fakeEdgeControl) askedIPs() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

func serveEdgeControl(t *testing.T, socket string, resp *edgev1.SnapshotResponse) *fakeEdgeControl {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctl := &fakeEdgeControl{resp: resp}
	mux := http.NewServeMux()
	mux.Handle(edgev1connect.NewEdgeControlServiceHandler(ctl))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ctl
}

// The edge generations are found by their control sockets; one that does not
// answer is there, without a snapshot.
func TestSocketSnapshotsFindsEveryEdgeGeneration(t *testing.T) {
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	serveEdgeControl(t, filepath.Join(dir, "edge-g3.sock"), snap(3, pc("p1", 1, 2, 3, 0, 0)))
	serveEdgeControl(t, filepath.Join(dir, "edge-g4.sock"), snap(4, pc("p1", 4, 5, 6, 0, 0)))
	// A socket nobody listens on any more (an edge that was killed).
	ln, err := net.Listen("unix", filepath.Join(dir, "edge-g2.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	for _, name := range []string{"edge-gx.sock", "other.sock", "edge-g5.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	src := newSocketSnapshots(dir, time.Second)
	got := src.take(context.Background(), false)
	if len(got) != 3 {
		t.Fatalf("generations = %v, want 2, 3 and 4", got)
	}
	if got[2] != nil {
		t.Errorf("generation 2 = %v, want no snapshot", got[2])
	}
	if got[3].GetProxies()[0].GetBytesUp() != 1 || got[4].GetProxies()[0].GetBytesUp() != 4 {
		t.Errorf("snapshots = %v", got)
	}
}

// The collector turns ticks into minutes and hands them to the journal.
func TestStatsCollectorPublishesMinutes(t *testing.T) {
	clock := newTestClock()
	buf := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	j := newJournal(buf, discardLog(), clock.Now)
	src := &fakeSnapshots{queue: []map[uint64]*edgev1.SnapshotResponse{
		snaps(snap(1, pc("p1", 10, 10, 1, 0, 0))),
		snaps(snap(1, pc("p1", 25, 10, 1, 0, 0))),
		snaps(snap(1, pc("p1", 25, 10, 1, 0, 0))),
	}}
	c := &statsCollector{
		source:  src,
		agg:     newAggregator(),
		journal: j,
		proc:    fstest.MapFS{},
		mode:    func() ipMode { return modeOff },
		log:     discardLog(),
	}
	ticks := make(chan time.Time, 3)
	ticks <- minuteAt(0, 5)
	ticks <- minuteAt(0, 15)
	ticks <- minuteAt(1, 5)
	close(ticks)
	c.run(context.Background(), ticks)
	recs, err := buf.After(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].GetStats() == nil {
		t.Fatalf("records = %v, want one stats batch", kindsOf(recs))
	}
	if got := proxyMinute(recs[0].GetStats(), "p1").GetUp(); got != 15 {
		t.Errorf("up = %d, want 15", got)
	}
}

// fakeSnapshots hands out the snapshots of one tick per take, in order; the
// last ones again when the queue is empty.
type fakeSnapshots struct {
	mu    sync.Mutex
	queue []map[uint64]*edgev1.SnapshotResponse
	last  map[uint64]*edgev1.SnapshotResponse
	asked []bool // whether each take asked for the counters of the IPs
}

func (f *fakeSnapshots) take(_ context.Context, ips bool) map[uint64]*edgev1.SnapshotResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, ips)
	if len(f.queue) > 0 {
		f.last, f.queue = f.queue[0], f.queue[1:]
	}
	return f.last
}
