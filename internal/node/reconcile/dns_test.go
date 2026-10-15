package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/doh"
)

const wantResolvConf = "nameserver 127.0.0.2\noptions timeout:2 attempts:2\n"

func (h *harness) resolvConfBind() string {
	return h.paths.ResolvConfPath() + ":/etc/resolv.conf:ro"
}

// mounts reports whether the engine container spec mounts the resolv.conf of
// the forwarder.
func (h *harness) mounts(spec dockerapi.ContainerSpec) bool {
	return slices.Contains(spec.Binds, h.resolvConfBind())
}

// lastEngine is the spec of the engine container created last.
func (h *harness) lastEngine() dockerapi.ContainerSpec {
	h.t.Helper()
	engines := h.creates("engine")
	if len(engines) == 0 {
		h.t.Fatal("no engine container was created")
	}
	return engines[len(engines)-1]
}

func (h *harness) generation() uint64 { return h.runtime().Instances[proxyID].Generation }

// In DNS mode doh, with an edge whose forwarder runs: the resolv.conf that
// names the forwarder is written before any engine starts, the engines mount it
// at /etc/resolv.conf, and the edge gets the forwarder with the default
// endpoints and the host's nameservers. On a new node the edge comes up with its
// forwarder in the pass that starts the first engine, which mounts the
// resolv.conf at once. The edge keeps the host's resolv.conf.
func TestEnginesMountTheResolvConfWhileTheForwarderRuns(t *testing.T) {
	h := newHarness(t)
	h.r.HostNameservers = func() []string { return []string{"192.0.2.53", "127.0.0.53"} }
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	var fileAtEngineStart string
	h.docker.onCreate = func(spec dockerapi.ContainerSpec) {
		if spec.Labels["postern.role"] == "engine" {
			b, _ := os.ReadFile(h.paths.ResolvConfPath())
			fileAtEngineStart = string(b)
		}
	}
	h.pass()

	if fileAtEngineStart != wantResolvConf {
		t.Errorf("resolv.conf when the engine was created = %q, want %q", fileAtEngineStart, wantResolvConf)
	}
	fi, err := os.Stat(h.paths.ResolvConfPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 || !fi.Mode().IsRegular() {
		t.Errorf("resolv.conf mode = %v, want a regular file 0644 (engines run as 65534)", fi.Mode())
	}
	if eng := h.creates("engine"); len(eng) != 1 || !h.mounts(eng[0]) {
		t.Fatalf("engines created = %d, binds of the first %v; want one, with %q", len(eng), eng[0].Binds, h.resolvConfBind())
	}
	if !h.runtime().EdgeDNS {
		t.Error("the runtime record does not know that the forwarder runs")
	}
	for _, b := range h.creates("edge")[0].Binds {
		if strings.Contains(b, "resolv.conf") {
			t.Errorf("the edge mounts %q: it keeps the host's resolver", b)
		}
	}

	want := &edgev1.Dns{Enabled: true, DohUrls: doh.DefaultEndpoints, Fallback: []string{"192.0.2.53", "127.0.0.53"}}
	if got := h.fakeEdge(1).lastConfig(t).GetDns(); !proto.Equal(got, want) {
		t.Errorf("edge dns = %v, want %v", got, want)
	}
	data, err := os.ReadFile(h.paths.EdgeConfigPath(1))
	if err != nil {
		t.Fatal(err)
	}
	var file edgev1.EdgeConfig
	if err := protojson.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(file.GetDns(), want) {
		t.Errorf("the config file of the edge has dns %v, want %v", file.GetDns(), want)
	}
}

// While the edge says that its forwarder does not run, the engines keep the
// host's resolver. The mount comes and goes with the forwarder once its new
// state has held for 60 s, with one new generation each time.
func TestTheMountFollowsTheForwarder(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if h.mounts(h.lastEngine()) {
		t.Fatal("the engine mounts the resolv.conf of a forwarder that does not run")
	}
	if _, err := os.Stat(h.paths.ResolvConfPath()); err != nil {
		t.Errorf("the resolv.conf is not there for the time the forwarder runs: %v", err)
	}
	if d := h.fakeEdge(1).lastConfig(t).GetDns(); !d.GetEnabled() {
		t.Errorf("edge dns = %v, want the forwarder enabled", d)
	}

	h.fakeEdge(1).setDNS(true)
	h.pass()
	h.passAfter(60 * time.Second)
	if g := h.generation(); g != 2 || !h.mounts(h.lastEngine()) {
		t.Fatalf("after the forwarder came up: g%d (mount %v), want g2 with the mount", g, h.mounts(h.lastEngine()))
	}
	h.passAfter(time.Minute)
	if g := h.generation(); g != 2 {
		t.Errorf("another pass made g%d", g)
	}

	h.fakeEdge(1).setDNS(false)
	h.pass()
	h.passAfter(60 * time.Second)
	if g := h.generation(); g != 3 || h.mounts(h.lastEngine()) {
		t.Errorf("after the forwarder went: g%d (mount %v), want g3 without the mount", g, h.mounts(h.lastEngine()))
	}
}

// passAfter moves the clock on by d and makes a pass.
func (h *harness) passAfter(d time.Duration) {
	h.t.Helper()
	h.clock.Advance(d)
	h.pass()
}

// mounted reports whether the serving engine was made with the mount: the last
// engine container created.
func (h *harness) mounted() bool { return h.mounts(h.lastEngine()) }

// The first state that the edge answers applies at once: on a new node the
// first engine mounts the resolv.conf in the pass that starts it, without a
// wait and without a second generation.
func TestTheFirstDNSStateAppliesAtOnce(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	if g := h.generation(); g != 1 || !h.mounted() {
		t.Errorf("g%d (mount %v), want g1 with the mount", g, h.mounted())
	}
	if rt := h.runtime(); !rt.EdgeDNS || !rt.EdgeDNSKnown || !rt.EdgeDNSChangeSince.IsZero() {
		t.Errorf("runtime = dns %v, known %v, change since %v; want true, true, none", rt.EdgeDNS, rt.EdgeDNSKnown, rt.EdgeDNSChangeSince)
	}
}

// A forwarder that comes and goes every 10 s rolls no engine (ruling S2-11).
func TestAFlappingForwarderRollsNothing(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	up := true
	for range 18 { // three minutes
		up = !up
		h.fakeEdge(1).setDNS(up)
		h.passAfter(10 * time.Second)
	}
	if n := len(h.creates("engine")); n != 1 || !h.mounted() {
		t.Errorf("%d engines created (mount %v), want the first one only, with the mount", n, h.mounted())
	}
}

// A change that holds for 60 s, in every answer of the edge, rolls the engines
// once: in the pass that sees it hold.
func TestAChangeThatHolds60SecondsRollsOnce(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	start := h.clock.Now()
	h.fakeEdge(1).setDNS(false)
	for i := 1; i <= 12; i++ {
		h.passAfter(10 * time.Second)
		elapsed := h.clock.Now().Sub(start)
		switch g := h.generation(); {
		case elapsed < 70*time.Second && g != 1: // the change began with the answer at 10 s
			t.Fatalf("%v after the change began: g%d, want g1 until it has held 60 s", elapsed-10*time.Second, g)
		case elapsed >= 70*time.Second && (g != 2 || h.mounted()):
			t.Fatalf("%v after the change began: g%d (mount %v), want g2 without the mount", elapsed-10*time.Second, g, h.mounted())
		}
	}
	if n := len(h.creates("engine")); n != 2 {
		t.Errorf("%d engines created, want 2: exactly one roll", n)
	}
}

// The time the change began is in the runtime record: a restart of the agent
// does not start the 60 s over. A Health that fails tells nothing: it neither
// breaks the change nor confirms it.
func TestARestartKeepsTheTimeOfTheChange(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	h.fakeEdge(1).setDNS(false)
	h.passAfter(10 * time.Second)
	began := h.clock.Now()
	if since := h.runtime().EdgeDNSChangeSince; !since.Equal(began) {
		t.Fatalf("change since %v in the record, want %v", since, began)
	}

	h.clock.Advance(30 * time.Second)
	h.r = h.newReconciler() // the agent starts again, 30 s into the change
	e := h.fakeEdge(1)
	e.mu.Lock()
	e.healthErr = errors.New("edge Health: context deadline exceeded")
	e.mu.Unlock()
	h.pass()
	if g := h.generation(); g != 1 || !h.runtime().EdgeDNSChangeSince.Equal(began) {
		t.Fatalf("after a restart and a Health error: g%d, change since %v; want g1 and %v", g, h.runtime().EdgeDNSChangeSince, began)
	}

	e.mu.Lock()
	e.healthErr = nil
	e.mu.Unlock()
	h.passAfter(20 * time.Second) // 50 s into the change
	if g := h.generation(); g != 1 {
		t.Fatalf("50 s into the change: g%d, want g1", g)
	}
	h.passAfter(10 * time.Second) // 60 s since it began, 30 s since the restart
	if g := h.generation(); g != 2 || h.mounted() {
		t.Errorf("60 s into the change: g%d (mount %v), want g2 without the mount", g, h.mounted())
	}
}

// An edge that does not answer tells nothing of its forwarder: the known state
// stays, no engine is rolled, the agent is not told, nothing is reported. The
// known state is in the runtime record, so a new agent process keeps it too.
func TestAHealthErrorKeepsTheKnownState(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var told []bool
	onDNS := func(up bool) {
		mu.Lock()
		defer mu.Unlock()
		told = append(told, up)
	}
	h.r.OnEdgeDNS = onDNS
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	if g := h.generation(); g != 1 || !h.mounts(h.lastEngine()) {
		t.Fatalf("g%d (mount %v), want g1 with the mount", g, h.mounts(h.lastEngine()))
	}
	mu.Lock()
	before := len(told)
	mu.Unlock()

	e := h.fakeEdge(1)
	e.mu.Lock()
	e.healthErr = errors.New("edge Health: context deadline exceeded")
	e.mu.Unlock()
	h.pass()
	mu.Lock()
	after := len(told)
	mu.Unlock()
	if g := h.generation(); g != 1 || after != before || len(h.eventsOf("dns_unavailable")) != 0 {
		t.Errorf("after a Health error: g%d, told %d more times, %d events; want g1, nothing told, no event",
			g, after-before, len(h.eventsOf("dns_unavailable")))
	}

	h.r = h.newReconciler() // the agent starts again; the edge still does not answer
	h.r.OnEdgeDNS = onDNS
	h.pass()
	if g := h.generation(); g != 1 {
		t.Errorf("after a restart of the agent: g%d, want g1", g)
	}
}

// In DNS mode system: no forwarder, no resolv.conf, nothing mounted, whatever
// the edge says.
func TestSystemModeMountsNothing(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	st := h.baseState(1)
	st.Settings.DnsMode = "system"
	h.apply(st)
	h.pass()
	if _, err := os.Stat(h.paths.ResolvConfPath()); !os.IsNotExist(err) {
		t.Errorf("resolv.conf: %v, want none in mode system", err)
	}
	if h.mounts(h.lastEngine()) {
		t.Error("the engine mounts the resolv.conf in mode system")
	}
	if d := h.fakeEdge(1).lastConfig(t).GetDns(); d != nil {
		t.Errorf("edge dns = %v, want none", d)
	}
}

// The mount follows the DNS mode while the forwarder runs: a change makes a new
// generation; "doh" and empty are one mode. While it does not run, the mode
// changes nothing of the engines.
func TestTheMountFollowsTheDNSMode(t *testing.T) {
	gen := uint64(0)
	next := func(h *harness, mode string) {
		gen++
		st := h.baseState(gen)
		st.Settings.DnsMode = mode
		h.apply(st)
		h.pass()
	}

	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	next(h, "")
	next(h, "system")
	if g := h.generation(); g != 2 || h.mounts(h.lastEngine()) {
		t.Errorf("doh to system: g%d (mount %v), want g2 without the mount", g, h.mounts(h.lastEngine()))
	}
	next(h, "doh")
	if g := h.generation(); g != 3 || !h.mounts(h.lastEngine()) {
		t.Errorf("system to doh: g%d (mount %v), want g3 with the mount", g, h.mounts(h.lastEngine()))
	}
	next(h, "")
	if g := h.generation(); g != 3 {
		t.Errorf("doh to empty: g%d, want g3", g)
	}

	gen = 0
	h = newHarness(t) // a forwarder that does not run
	next(h, "doh")
	next(h, "system")
	next(h, "doh")
	if g := h.generation(); g != 1 {
		t.Errorf("mode changes without a forwarder: g%d, want g1", g)
	}
}

// A DNS mode that has just become doh again tells nothing of the forwarder,
// which the edge gets only with the configuration of the pass: after doh,
// system and doh again inside the 60 s of the debounce, no engine mounts the
// resolv.conf until the edge answers that its forwarder runs, and then the
// engines mount it at once. Answers given while the mode was system do not
// count, also not one of a forwarder that ran on until the edge had the
// configuration without it.
func TestAModeBackToDoHWaitsForTheForwarder(t *testing.T) {
	h := newHarness(t)
	e := h.fakeEdge(1)
	// The edge runs its forwarder as the configuration it was last given says,
	// unless the forwarder cannot start.
	var mu sync.Mutex
	broken := false
	e.onSet = func(cfg *edgev1.EdgeConfig) {
		mu.Lock()
		defer mu.Unlock()
		e.setDNS(cfg.GetDns().GetEnabled() && !broken)
	}
	setBroken := func(b bool) {
		mu.Lock()
		defer mu.Unlock()
		broken = b
	}
	h.docker.onCreate = func(spec dockerapi.ContainerSpec) {
		if spec.Labels["postern.role"] == "engine" && h.mounts(spec) && !e.dnsUp() {
			t.Errorf("engine %s mounts the resolv.conf of a forwarder that does not run", spec.Name)
		}
	}
	mode := func(gen uint64, m string) {
		st := h.baseState(gen)
		st.Settings.DnsMode = m
		h.apply(st)
	}
	e.setDNS(true) // its configuration file has the forwarder
	mode(1, "doh")
	h.pass()
	if g := h.generation(); g != 1 || !h.mounted() {
		t.Fatalf("g%d (mount %v), want g1 with the mount", g, h.mounted())
	}

	// Mode system: the forwarder runs until the edge has the configuration of
	// the pass.
	mode(2, "system")
	h.passAfter(10 * time.Second)
	if g := h.generation(); g != 2 || h.mounted() || e.dnsUp() {
		t.Fatalf("doh to system: g%d (mount %v, forwarder %v), want g2 without the mount, no forwarder", g, h.mounted(), e.dnsUp())
	}

	// Mode doh again, 10 s on: the forwarder starts with the configuration of
	// the pass, after the plans; the engines mount it in the next pass.
	mode(3, "doh")
	h.passAfter(10 * time.Second)
	if g := h.generation(); g != 2 || !e.dnsUp() {
		t.Fatalf("back to doh: g%d (forwarder %v), want g2 and the forwarder running", g, e.dnsUp())
	}
	h.passAfter(10 * time.Second)
	if g := h.generation(); g != 3 || !h.mounted() {
		t.Fatalf("the forwarder runs: g%d (mount %v), want g3 with the mount", g, h.mounted())
	}

	// Again, and the forwarder cannot start for a while: nothing mounts, also
	// after the 60 s; once it runs, the mount comes at once.
	mode(4, "system")
	h.passAfter(10 * time.Second)
	setBroken(true)
	mode(5, "doh")
	h.passAfter(10 * time.Second)
	h.passAfter(time.Minute)
	if g := h.generation(); g != 4 || h.mounted() {
		t.Fatalf("the forwarder does not start: g%d (mount %v), want g4 without the mount", g, h.mounted())
	}
	setBroken(false)
	e.setDNS(true)
	h.passAfter(10 * time.Second)
	if g := h.generation(); g != 5 || !h.mounted() {
		t.Errorf("the forwarder runs at last: g%d (mount %v), want g5 with the mount", g, h.mounted())
	}
	if n := len(h.creates("engine")); n != 5 {
		t.Errorf("%d engines created, want 5", n)
	}
}

// dnsUp is what Health says of the DNS forwarder.
func (e *fakeEdge) dnsUp() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dns
}

// A pass in mode system that a newer desired state cuts short before the edge
// has the configuration without the forwarder leaves the state of the
// forwarder, which still runs, as it was: a quick change back to doh rolls no
// engine, also when the edge does not answer Health in that pass.
func TestAnInterruptedSystemPassKeepsTheForwarder(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	if g := h.generation(); g != 1 || !h.mounted() {
		t.Fatalf("g%d (mount %v), want g1 with the mount", g, h.mounted())
	}

	st := h.baseState(2)
	st.Settings.DnsMode = "system"
	h.apply(st)
	pushed := h.fakeEdge(1).setCount()
	newer := make(chan struct{}, 1)
	newer <- struct{}{} // a newer state waits: the pass stops at its first step boundary
	if err := h.r.reconcileOnce(context.Background(), &kicks{ch: newer}); !errors.Is(err, errInterrupted) {
		t.Fatalf("pass = %v, want it cut short", err)
	}
	if n := h.fakeEdge(1).setCount() - pushed; n != 0 {
		t.Fatalf("the cut pass pushed %d configurations, want none", n)
	}
	if rt := h.runtime(); !rt.EdgeDNS || rt.EdgeDNSAwaitUp {
		t.Errorf("after the cut pass: dns %v, await %v; want the forwarder still known to run", rt.EdgeDNS, rt.EdgeDNSAwaitUp)
	}

	h.apply(h.baseState(3)) // doh again, and Health fails for a while
	e := h.fakeEdge(1)
	e.mu.Lock()
	e.healthErr = errors.New("edge Health: context deadline exceeded")
	e.mu.Unlock()
	h.passAfter(10 * time.Second)
	if g, n := h.generation(), len(h.creates("engine")); g != 1 || n != 1 || !h.mounted() {
		t.Errorf("back to doh: g%d, %d engines created (mount %v); want g1 alone, with the mount", g, n, h.mounted())
	}
}

// slice1Hash is instanceHash as slice 1 computed it, before there was a
// forwarder to mount.
func slice1Hash(engine, version, artifactSHA, runnerImage string, pr *nodev1.Proxy, files map[string][]byte) string {
	h := sha256.New()
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	field("postern-engine-instance-v2")
	field(engine)
	field(version)
	field(artifactSHA)
	field(runnerImage)
	field(strconv.FormatBool(pr.GetUseMiddleProxy()))
	field(pr.GetNatIp())
	for _, name := range slices.Sorted(maps.Keys(files)) {
		field(name)
		field(string(files[name]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// An engine without the mount keeps the hash of slice 1: the update of the
// agent rolls no engine of a node whose edge has no forwarder yet.
func TestEnginesWithoutTheMountKeepTheirHash(t *testing.T) {
	pr := &nodev1.Proxy{UseMiddleProxy: true, NatIp: "203.0.113.9"}
	files := map[string][]byte{"config.toml": []byte("a"), "x": []byte("b")}
	old := slice1Hash("telemt", "3.5.13", "abc", runnerImage, pr, files)
	if got := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, nil, pr, files); got != old {
		t.Errorf("without the mount: %s, want the hash of slice 1 %s", got, old)
	}
	if got := instanceHash("telemt", "3.5.13", "abc", runnerImage, true, nil, pr, files); got == old {
		t.Error("the mount does not change the hash")
	}
}

// The resolv.conf is put right when it is not what it must be: other content,
// another mode, or an empty directory that Docker made at its place.
func TestResolvConfIsPutRight(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"other content": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("nameserver 192.0.2.1\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"private": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(wantResolvConf), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			if err := os.MkdirAll(h.paths.RunDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			spoil(t, h.paths.ResolvConfPath())
			h.apply(h.baseState(1))
			h.pass()
			b, err := os.ReadFile(h.paths.ResolvConfPath())
			fi, serr := os.Stat(h.paths.ResolvConfPath())
			if err != nil || serr != nil || string(b) != wantResolvConf || fi.Mode().Perm() != 0o644 {
				t.Errorf("resolv.conf = %q (%v, %v), mode %v", b, err, serr, fi.Mode())
			}
		})
	}
}

// Only addresses go to the edge as nameservers of the host, 16 at the most,
// never the forwarder itself: a configuration the edge would refuse would stop
// the node.
func TestHostNameserversAreSanitized(t *testing.T) {
	h := newHarness(t)
	h.r.HostNameservers = func() []string {
		return []string{"192.0.2.53", "ns.example.com", "127.0.0.2", "", "192.0.2.53", "2001:db8::53", "192.0.2.54:53"}
	}
	h.apply(h.baseState(1))
	h.pass()
	if got := h.fakeEdge(1).lastConfig(t).GetDns().GetFallback(); !slices.Equal(got, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Errorf("fallback = %q", got)
	}

	var many []string
	for i := range 20 {
		many = append(many, fmt.Sprintf("192.0.2.%d", i+1))
	}
	if got := sanitizeNameservers(many); len(got) != 16 || !slices.Equal(got, many[:16]) {
		t.Errorf("sanitizeNameservers of 20 addresses = %d of them, want the first 16", len(got))
	}
}

// The agent is told what the edge answers; in mode doh a forwarder that the
// edge says does not run is reported once, and again after it ran in between,
// but not within 10 minutes of the last report (ruling S2-12).
func TestEdgeDNSIsReported(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var told []bool
	h.r.OnEdgeDNS = func(up bool) {
		mu.Lock()
		defer mu.Unlock()
		told = append(told, up)
	}
	last := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(told) > 0 && told[len(told)-1]
	}
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	if !last() {
		t.Errorf("told %v, want the forwarder up", told)
	}
	h.fakeEdge(1).setDNS(false)
	h.pass()
	h.pass()
	if last() {
		t.Errorf("told %v, want the forwarder down at last", told)
	}
	if evs := h.eventsOf("dns_unavailable"); len(evs) != 1 || evs[0].GetSeverity() != "warning" {
		t.Errorf("dns_unavailable events = %v, want one warning", evs)
	}

	h.fakeEdge(1).setDNS(true)
	h.pass()
	h.fakeEdge(1).setDNS(false)
	h.pass()
	if n := len(h.eventsOf("dns_unavailable")); n != 1 {
		t.Errorf("%d dns_unavailable events, want 1: the second comes 10 minutes after the first", n)
	}
	h.passAfter(10 * time.Minute)
	if n := len(h.eventsOf("dns_unavailable")); n != 2 {
		t.Errorf("10 minutes on, the forwarder still down: %d dns_unavailable events, want 2", n)
	}
	h.passAfter(10 * time.Minute)
	if n := len(h.eventsOf("dns_unavailable")); n != 2 {
		t.Errorf("%d dns_unavailable events, want 2: a forwarder that stays down is reported once", n)
	}
}

// A forwarder that comes and goes is reported once in 10 minutes, not at every
// pass that finds it down (ruling S2-12). A new edge generation is another
// edge: its forwarder is reported at once.
func TestAFlappingForwarderIsReportedOnceIn10Minutes(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	up := true
	flap := func(n int) {
		for range n { // every 10 s
			up = !up
			h.fakeEdge(1).setDNS(up)
			h.passAfter(10 * time.Second)
		}
	}
	flap(60) // down at 10 s, 30 s, ..., 590 s
	if n := len(h.eventsOf("dns_unavailable")); n != 1 {
		t.Fatalf("10 minutes of flapping: %d dns_unavailable events, want 1", n)
	}
	flap(1) // down at 610 s: 10 minutes after the first event
	if n := len(h.eventsOf("dns_unavailable")); n != 2 {
		t.Fatalf("10 minutes after the first event: %d dns_unavailable events, want 2", n)
	}

	// The edge is replaced 10 s later: generation 2, whose forwarder does not
	// run either.
	if err := h.docker.Stop(context.Background(), "postern-edge-g1", 0); err != nil {
		t.Fatal(err)
	}
	h.passAfter(10 * time.Second)
	evs := h.eventsOf("dns_unavailable")
	if len(evs) != 3 || evs[2].GetDetails()["generation"] != "2" {
		t.Errorf("events %v, want a third, for edge generation 2", evs)
	}
}

func TestNoDNSEventInSystemMode(t *testing.T) {
	h := newHarness(t)
	var told []bool
	h.r.OnEdgeDNS = func(up bool) { told = append(told, up) }
	st := h.baseState(1)
	st.Settings.DnsMode = "system"
	h.apply(st)
	h.pass()
	if len(h.eventsOf("dns_unavailable")) != 0 {
		t.Error("a forwarder that is not wanted is reported missing")
	}
	if len(told) == 0 || slices.Contains(told, true) {
		t.Errorf("OnEdgeDNS was told %v, want only false", told)
	}
}

// The edge spec is what it was: the edge resolves through its own forwarder
// in its process, not through a resolv.conf.
func TestEdgeSpecHasNoResolvConf(t *testing.T) {
	h := newHarness(t)
	spec := h.r.edgeSpec(1, false, h.nodeBinary)
	for _, b := range spec.Binds {
		if strings.Contains(b, "resolv") {
			t.Errorf("edge bind %q", b)
		}
	}
}

// The public address that the agent learns late reaches the engines of the
// proxies that use the middle proxy without a NAT address of their own: a new
// generation.
func TestALatePublicAddressRollsTheMiddleProxyEngines(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Proxies[0].UseMiddleProxy = true
	h.apply(st)
	h.pass()
	if g := h.generation(); g != 1 {
		t.Fatalf("g%d, want g1", g)
	}
	h.pass()
	if g := h.generation(); g != 1 {
		t.Fatalf("another pass: g%d, want g1", g)
	}
	h.r.SetNodePublicIPv4("203.0.113.9")
	h.pass()
	if g := h.generation(); g != 2 {
		t.Errorf("after the address came: g%d, want g2", g)
	}
	b, err := os.ReadFile(h.paths.InstancesDir() + "/eng-01j9zzproxy0000000000000p1-g2/config.toml")
	if err != nil || !strings.Contains(string(b), "203.0.113.9") {
		t.Errorf("the config of g2 does not name the address: %v", err)
	}
}
