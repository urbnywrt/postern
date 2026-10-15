package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/edge"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/socks5"
	"github.com/urbnywrt/postern/internal/version"
)

// ---------------------------------------------------------------------------
// SetConfig, Snapshot, Health
// ---------------------------------------------------------------------------

func TestSetConfigAppliesAndPersists(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	cfg := routeConfig(7, port, be)

	r.mustSet(cfg)

	snap := r.snapshot()
	if snap.GetGeneration() != 7 {
		t.Errorf("Snapshot generation = %d, want 7", snap.GetGeneration())
	}
	if proxyCounters(snap, "p1") == nil {
		t.Errorf("Snapshot lists no counters for the proxy of the route: %v", snap)
	}
	h := r.health()
	if h.GetGeneration() != 7 || !h.GetListening() || !slices.Equal(h.GetBound(), []string{addr(port)}) {
		t.Errorf("Health = %v, want generation 7, listening, bound to %s", h, addr(port))
	}
	if got := r.savedConfig(); !proto.Equal(got, cfg) {
		t.Errorf("the saved configuration is %v, want %v", got, cfg)
	}
	if got := modeOf(t, r.cfgPath); got != 0o600 {
		t.Errorf("mode of the configuration file = %o, want 600", got)
	}
	// The edge is configured for real, not only on paper.
	relay(t, port, "proxy.example.com")
}

func TestHealthAndSnapshotBeforeAnyConfig(t *testing.T) {
	r := newRig(t)
	h := r.health()
	if h.GetGeneration() != 0 || h.GetListening() || len(h.GetBound()) != 0 {
		t.Errorf("Health = %v, want the zero value", h)
	}
	snap := r.snapshot()
	if snap.GetGeneration() != 0 || len(snap.GetProxies()) != 0 || len(snap.GetHealth()) != 0 {
		t.Errorf("Snapshot = %v, want it empty", snap)
	}
	if snap.GetTsUnixNano() == 0 {
		t.Error("Snapshot has no timestamp")
	}
}

// Snapshot has the counters of the client IPs when the request asks for them,
// and only then (M4).
func TestSnapshotHasTheIPsOnlyWhenAsked(t *testing.T) {
	r := newRig(t)
	port := freePorts(t, 1)[0]
	r.mustSet(routeConfig(7, port, echoBackend(t)))
	c := relay(t, port, "proxy.example.com")
	roundTrip(t, c, "counted")
	snapshot := func(ips bool) *edgev1.SnapshotResponse {
		t.Helper()
		ctx, cancel := callCtx()
		defer cancel()
		resp, err := r.client.Snapshot(ctx, connect.NewRequest(&edgev1.SnapshotRequest{IncludeIps: ips}))
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		return resp.Msg
	}
	if s := snapshot(false); len(s.GetIps()) != 0 || proxyCounters(s, "p1").GetConnsTotal() != 1 {
		t.Errorf("Snapshot without the IPs = %v, want the proxy and no IP", s)
	}
	if s := snapshot(true); len(s.GetIps()) != 1 || s.GetIps()[0].GetIp() != "127.0.0.1" {
		t.Errorf("Snapshot with the IPs = %v, want the IP of the client", s.GetIps())
	}
}

// Health says which binary the edge process runs, before any configuration and
// after: the agent tells an edge that runs an older binary than its own by it
// (Ruling 38).
func TestHealthReportsTheVersionOfTheBinary(t *testing.T) {
	r := newRig(t)
	if got := r.health().GetVersion(); got != version.Version || got == "" {
		t.Errorf("Health version before a configuration = %q, want %q", got, version.Version)
	}
	r.mustSet(routeConfig(3, freePorts(t, 1)[0], echoBackend(t)))
	if got := r.health().GetVersion(); got != version.Version {
		t.Errorf("Health version = %q, want %q", got, version.Version)
	}
}

// The agent sends the same configuration every pass, and the generation it
// carries is that of the edge container: it never changes in the life of the
// process.
func TestSetConfigRepeatedSameGeneration(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	cfg := routeConfig(3, port, be)
	r.mustSet(cfg)
	c := relay(t, port, "proxy.example.com")
	before := proxyCounters(r.snapshot(), "p1")
	if before.GetBytesUp() == 0 || before.GetConnsTotal() != 1 {
		t.Fatalf("counters before = %v, want traffic and one connection", before)
	}

	r.mustSet(cfg)
	changed := routeConfig(3, port, be)
	changed.MaskDomains = []string{"mask.example.com"}
	for range 5 {
		r.mustSet(changed)
	}

	after := proxyCounters(r.snapshot(), "p1")
	if after.GetConnsTotal() != 1 || after.GetBytesUp() < before.GetBytesUp() || after.GetBytesDown() < before.GetBytesDown() {
		t.Errorf("counters after = %v, want them kept from %v", after, before)
	}
	if after.GetConnsActive() != 1 {
		t.Errorf("active connections = %d, want the one that was open", after.GetConnsActive())
	}
	roundTrip(t, c, "after the new configuration")
	if got := r.savedConfig(); !proto.Equal(got, changed) {
		t.Errorf("the saved configuration is %v, want the last one", got)
	}
	if h := r.health(); h.GetGeneration() != 3 {
		t.Errorf("Health generation = %d, want 3", h.GetGeneration())
	}
}

func TestSetConfigRejectsOtherGeneration(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	ports := freePorts(t, 2)
	cfg := routeConfig(7, ports[0], be)
	r.mustSet(cfg)
	saved := r.savedBytes()

	for _, gen := range []uint64{8, 6, 0} {
		reason := r.mustRefuse(routeConfig(gen, ports[1], be))
		for _, want := range []string{"generation", "7"} {
			if !strings.Contains(reason, want) {
				t.Errorf("the reason for generation %d, %q, does not say %q", gen, reason, want)
			}
		}
	}
	if h := r.health(); h.GetGeneration() != 7 || !slices.Equal(h.GetBound(), []string{addr(ports[0])}) {
		t.Errorf("Health = %v after the refusals, want it unchanged", h)
	}
	if portOpen(ports[1]) {
		t.Error("the listener of a refused configuration is bound")
	}
	if !bytes.Equal(r.savedBytes(), saved) {
		t.Error("the configuration file changed after a refusal")
	}
	r.mustSet(cfg) // the process takes its own generation as before
}

func TestSetConfigWithoutConfig(t *testing.T) {
	r := newRig(t)
	if reason := r.mustRefuse(nil); !strings.Contains(reason, "configuration") {
		t.Errorf("the reason, %q, does not say what is missing", reason)
	}
	if got := r.savedBytes(); got != nil {
		t.Errorf("a file was written for a request without configuration: %s", got)
	}
	r.mustSet(routeConfig(1, freePorts(t, 1)[0], echoBackend(t))) // and the edge is still free to start
}

func TestSetConfigInvalidKeepsPreviousState(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	good := routeConfig(7, port, be)
	r.mustSet(good)
	saved := r.savedBytes()
	c := relay(t, port, "proxy.example.com")

	reason := r.mustRefuse(duplicateListener(routeConfig(7, port, be)))

	if !strings.Contains(reason, "l2") {
		t.Errorf("the reason, %q, does not name the listener that is wrong", reason)
	}
	if !bytes.Equal(r.savedBytes(), saved) {
		t.Error("the previous configuration file was touched")
	}
	if h := r.health(); h.GetGeneration() != 7 || !slices.Equal(h.GetBound(), []string{addr(port)}) {
		t.Errorf("Health = %v, want it unchanged", h)
	}
	roundTrip(t, c, "the connection that was open")
	relay(t, port, "proxy.example.com") // and the old route takes new ones
}

// A part that was applied before another one failed is put back: the router
// and the SOCKS ports are not left with what the refused configuration had.
func TestSetConfigRefusalRestoresEgress(t *testing.T) {
	be := echoBackend(t)
	bad := map[string]func(t *testing.T, ports []uint32) *edgev1.EdgeConfig{
		"the edge part is invalid": func(t *testing.T, ports []uint32) *edgev1.EdgeConfig {
			return duplicateListener(withEgress(routeConfig(7, ports[0], be), "c2", "m2", ports[2]))
		},
		"a SOCKS port cannot be bound": func(t *testing.T, ports []uint32) *edgev1.EdgeConfig {
			// Something that does not share its port (no SO_REUSEPORT) holds it.
			ln, err := net.Listen("tcp4", addr(ports[2]))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			return withEgress(routeConfig(7, ports[0], be), "c2", "m2", ports[2])
		},
		"the chains are invalid": func(t *testing.T, ports []uint32) *edgev1.EdgeConfig {
			cfg := withEgress(routeConfig(7, ports[0], be), "c2", "m2", ports[2])
			cfg.Chains[0].Members[0].Kind = "carrier-pigeon"
			return cfg
		},
	}
	for name, makeBad := range bad {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			ports := freePorts(t, 3) // the listener, the SOCKS port that is there, the one that is not to come
			r.mustSet(withEgress(routeConfig(7, ports[0], be), "c1", "m1", ports[1]))
			saved := r.savedBytes()

			r.mustRefuse(makeBad(t, ports))

			h := r.snapshot().GetHealth()
			if len(h) != 1 || h[0].GetChainId() != "c1" || h[0].GetMemberKey() != "m1" {
				t.Errorf("egress health = %v, want the member of chain c1 only", h)
			}
			ctx, cancel := callCtx()
			defer cancel()
			if c, via, err := r.router.Dial(ctx, "c1", be.String()); err != nil || via != "m1" {
				t.Errorf("a dial through c1 = %v, via %q: want it to work through m1", err, via)
			} else {
				_ = c.Close()
			}
			if _, _, err := r.router.Dial(ctx, "c2", be.String()); !errors.Is(err, egress.ErrUnknownChain) {
				t.Errorf("a dial through c2 = %v, want ErrUnknownChain: the chain of the refused configuration is still there", err)
			}
			if !portOpen(ports[1]) {
				t.Error("the SOCKS port that was there is gone")
			}
			if name != "a SOCKS port cannot be bound" && portOpen(ports[2]) {
				t.Error("the SOCKS port of the refused configuration was left open")
			}
			if !bytes.Equal(r.savedBytes(), saved) {
				t.Error("the configuration file was touched")
			}
			if h := r.health(); !slices.Equal(h.GetBound(), []string{addr(ports[0])}) {
				t.Errorf("bound = %v, want the old listener only", h.GetBound())
			}
		})
	}
}

// When the file cannot be written the configuration is not in effect either:
// what runs is always what a restart would come up with.
func TestSetConfigSaveFailureUndoesEverything(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	ports := freePorts(t, 4)
	r.mustSet(withEgress(routeConfig(7, ports[0], be), "c1", "m1", ports[1]))

	// A directory takes the place of the file, so that it cannot be replaced.
	if err := os.Remove(r.cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r.cfgPath, 0o700); err != nil {
		t.Fatal(err)
	}
	next := withEgress(routeConfig(7, ports[0], be), "c2", "m2", ports[2])
	next.Listeners = append(next.Listeners, &edgev1.EdgeListener{
		Id: "l9", BindIp: "127.0.0.1", Port: ports[3], Kind: "tls", StrangerAction: "drop", NonTlsAction: "drop",
	})

	reason := r.mustRefuse(next)

	if !strings.Contains(reason, "save") {
		t.Errorf("the reason, %q, does not say that the file could not be saved", reason)
	}
	if h := r.health(); !slices.Equal(h.GetBound(), []string{addr(ports[0])}) {
		t.Errorf("bound = %v, want the old listener only", h.GetBound())
	}
	if portOpen(ports[3]) {
		t.Error("the listener of the refused configuration is still open")
	}
	if portOpen(ports[2]) || !portOpen(ports[1]) {
		t.Error("the SOCKS ports are not the old ones")
	}
	ctx, cancel := callCtx()
	defer cancel()
	if _, _, err := r.router.Dial(ctx, "c2", be.String()); !errors.Is(err, egress.ErrUnknownChain) {
		t.Errorf("a dial through c2 = %v, want ErrUnknownChain", err)
	}
	relay(t, ports[0], "proxy.example.com")
}

func TestSnapshotHasEgressHealth(t *testing.T) {
	r := newRig(t)
	cfg := routeConfig(2, freePorts(t, 1)[0], echoBackend(t))
	cfg.Chains = []*edgev1.Chain{
		{Id: "c1", Members: []*edgev1.ChainMember{
			{Key: "m1", Kind: "direct"},
			{Key: "m2", Kind: "socks5", Addr: "127.0.0.1:1", Username: "u", Password: "p"},
		}},
		{Id: "c2", Members: []*edgev1.ChainMember{{Key: "m3", Kind: "direct", BindIp: "127.0.0.1"}}},
	}
	r.mustSet(cfg)

	var got []string
	for _, h := range r.snapshot().GetHealth() {
		got = append(got, h.GetChainId()+"/"+h.GetMemberKey()+"="+h.GetStatus())
	}
	want := []string{"c1/m1=unknown", "c1/m2=unknown", "c2/m3=unknown"}
	if !slices.Equal(got, want) {
		t.Errorf("egress health = %v, want %v (in the order of the configuration; nothing has been probed)", got, want)
	}
}

// The caps of the edge on connections are those of its public listeners: the
// SOCKS ports of the engines and the control socket are neither counted nor
// refused, and the control socket reports the refusals.
func TestConnCapsSpareSocksAndControl(t *testing.T) {
	r := newRigWith(t, slog.LevelDebug, edge.Options{ClientHelloTimeout: 3 * time.Second, MaxConns: 2})
	be := echoBackend(t)
	ports := freePorts(t, 2)
	r.mustSet(withEgress(routeConfig(7, ports[0], be), "c1", "m1", ports[1]))

	// Connections held open on the SOCKS port take no place of the public ones.
	for range 3 {
		c, err := net.DialTimeout("tcp4", addr(ports[1]), 3*time.Second)
		if err != nil {
			t.Fatalf("connecting to the SOCKS port: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	relay(t, ports[0], "proxy.example.com")
	relay(t, ports[0], "proxy.example.com")

	// The edge holds as many connections as it may: the next one is closed at
	// accept.
	c, err := net.DialTimeout("tcp4", addr(ports[0]), 3*time.Second)
	if err != nil {
		t.Fatalf("connecting to the edge: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if !closedSoon(c, time.Second) {
		t.Error("a connection over the cap of the edge was not closed at accept")
	}

	// The SOCKS port serves on: it answers the requests of an engine (with a
	// refusal here, a loopback destination being none of an engine's business).
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := socks5.Dial(ctx, addr(ports[1]), "", "", be.String())
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		var re *socks5.ReplyError
		if !errors.As(err, &re) {
			t.Errorf("a SOCKS request with the edge at its cap: %v, want the answer of the port", err)
		}
	}

	// So does the control socket, which counts the refusal.
	snap := r.snapshot()
	if snap.GetRefusedTotal() != 1 || snap.GetRefusedPrehello() != 0 {
		t.Errorf("Snapshot counts %d refused over the total and %d before the hello, want 1 and 0",
			snap.GetRefusedTotal(), snap.GetRefusedPrehello())
	}
}

// The configuration holds the passwords of the egress members. They are in the
// file and nowhere else: not in a log, not in an answer.
func TestNoSecretsInLogsOrAnswers(t *testing.T) {
	// A marker to look for, made here so that the source holds no string that a
	// secret scanner would take for a credential.
	secret := fmt.Sprintf("pw-marker-%x", time.Now().UnixNano())
	r := newRig(t)
	be := echoBackend(t)
	port := freePorts(t, 1)[0]

	good := routeConfig(1, port, be)
	good.Chains = []*edgev1.Chain{{Id: "c1", Members: []*edgev1.ChainMember{
		{Key: "m1", Kind: "socks5", Addr: "127.0.0.1:1", Username: "user", Password: secret},
	}}}
	r.mustSet(good)

	badChains := routeConfig(1, port, be)
	badChains.Chains = []*edgev1.Chain{good.Chains[0], good.Chains[0]} // the same chain twice
	badEdge := duplicateListener(routeConfig(1, port, be))
	badEdge.Chains = good.Chains
	for _, cfg := range []*edgev1.EdgeConfig{badChains, badEdge} {
		if reason := r.mustRefuse(cfg); strings.Contains(reason, secret) {
			t.Errorf("a refusal carries the password: %s", reason)
		}
	}
	_ = r.snapshot()
	_ = r.health()
	if logs := r.logs.String(); strings.Contains(logs, secret) {
		t.Errorf("the password is in the log:\n%s", logs)
	}
	if !bytes.Contains(r.savedBytes(), []byte(secret)) {
		t.Error("the password is not in the configuration file: a restart would lose the member's credentials")
	}
}

func TestApplyForStartup(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	cfg := routeConfig(4, port, be)

	if err := r.srv.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if h := r.health(); h.GetGeneration() != 4 || !slices.Equal(h.GetBound(), []string{addr(port)}) {
		t.Errorf("Health = %v, want generation 4 and the listener", h)
	}
	relay(t, port, "proxy.example.com")
	if got := r.savedBytes(); got != nil {
		t.Errorf("Apply wrote the file: the process starts from it, it has nothing to save:\n%s", got)
	}

	// The generation of the process is the one Apply fixed.
	if err := r.srv.Apply(routeConfig(5, port, be)); err == nil {
		t.Error("Apply took another generation")
	}
	r.mustRefuse(routeConfig(5, port, be))
	r.mustSet(routeConfig(4, port, be))
}

func TestApplyFailureReturnsTheError(t *testing.T) {
	r := newRig(t)
	port := freePorts(t, 1)[0]
	err := r.srv.Apply(duplicateListener(routeConfig(1, port, echoBackend(t))))
	if err == nil || !strings.Contains(err.Error(), "l2") {
		t.Errorf("Apply error = %v, want one that names listener l2", err)
	}
	if h := r.health(); h.GetListening() {
		t.Errorf("Health = %v after a failed first Apply, want nothing bound", h)
	}
	// A failed first configuration does not fix the generation.
	r.mustSet(routeConfig(9, port, echoBackend(t)))
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

func TestDrainClosesListenersAndKeepsConnections(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	ports := freePorts(t, 2)
	r.mustSet(withEgress(routeConfig(7, ports[0], be), "c1", "m1", ports[1]))
	c := relay(t, ports[0], "proxy.example.com")
	if !portOpen(ports[0]) || !portOpen(ports[1]) {
		t.Fatal("the listener and the SOCKS port are not open before the drain")
	}

	start := time.Now()
	r.drain(30)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Drain took %v, it has to answer at once", d)
	}

	// When it answers, nothing is accepted any more.
	if portOpen(ports[0]) {
		t.Error("the listener still accepts when Drain has answered")
	}
	if portOpen(ports[1]) {
		t.Error("the SOCKS port still accepts when Drain has answered")
	}
	select {
	case <-r.srv.Draining():
	default:
		t.Error("Draining() is not closed")
	}

	// The connection lives on after the call is over: the drain does not run in
	// the context of the call, which is cancelled when the call ends.
	aliveFor(t, c, 500*time.Millisecond)
	if r.drained() {
		t.Error("Drained() is closed with a connection still open")
	}

	// The agent still asks how the edge is doing while it drains.
	h := r.health()
	if h.GetListening() || len(h.GetBound()) != 0 || h.GetGeneration() != 7 {
		t.Errorf("Health while draining = %v, want generation 7, not listening, nothing bound", h)
	}
	if p := proxyCounters(r.snapshot(), "p1"); p.GetConnsActive() != 1 {
		t.Errorf("Snapshot while draining = %v, want the connection that is open", p)
	}
	if reason := r.mustRefuse(routeConfig(7, ports[0], be)); !strings.Contains(reason, "drain") {
		t.Errorf("the reason for refusing a configuration while draining, %q, does not say so", reason)
	}
	if portOpen(ports[0]) {
		t.Error("a configuration was taken while draining: its listener is open")
	}

	_ = c.Close()
	if !r.waitDrained(3 * time.Second) {
		t.Error("Drained() is not closed after the last connection ended")
	}
}

func TestDrainWithNothingOpen(t *testing.T) {
	r := newRig(t)
	r.mustSet(routeConfig(7, freePorts(t, 1)[0], echoBackend(t)))
	r.drain(30)
	if !r.waitDrained(2 * time.Second) {
		t.Error("an idle edge does not finish its drain")
	}

	// Also an edge that never had a configuration.
	r2 := newRig(t)
	r2.drain(30)
	if !r2.waitDrained(2 * time.Second) {
		t.Error("an unconfigured edge does not finish its drain")
	}
}

func TestDrainHonorsMaxSeconds(t *testing.T) {
	r := newRig(t)
	port := freePorts(t, 1)[0]
	r.mustSet(routeConfig(7, port, echoBackend(t)))
	c := relay(t, port, "proxy.example.com")

	r.drain(1)
	if r.waitDrained(500 * time.Millisecond) {
		t.Error("the drain ended before max_seconds with a connection open")
	}
	if !r.waitDrained(5 * time.Second) {
		t.Fatal("the drain did not end at max_seconds")
	}
	if !closedSoon(c, 2*time.Second) {
		t.Error("the connection that was left was not closed at the end of the drain")
	}
}

// With max_seconds 0 the proto3 default is not "cut everything now".
func TestDrainZeroTakesTheDefault(t *testing.T) {
	r := newRig(t)
	port := freePorts(t, 1)[0]
	r.mustSet(routeConfig(7, port, echoBackend(t)))
	c := relay(t, port, "proxy.example.com")

	r.drain(0)
	aliveFor(t, c, 600*time.Millisecond)
	if r.drained() {
		t.Error("max_seconds 0 ended the drain at once")
	}
}

func TestDrainDeadlineOnlyGetsShorter(t *testing.T) {
	t.Run("a later, shorter one wins", func(t *testing.T) {
		r := newRig(t)
		port := freePorts(t, 1)[0]
		r.mustSet(routeConfig(7, port, echoBackend(t)))
		c := relay(t, port, "proxy.example.com")

		r.drain(3600)
		aliveFor(t, c, 100*time.Millisecond)
		r.drain(1)
		if !r.waitDrained(5 * time.Second) {
			t.Fatal("a second Drain with a shorter time did not shorten the first")
		}
		if !closedSoon(c, 2*time.Second) {
			t.Error("the connection was not closed")
		}
	})
	t.Run("a later, longer one does not extend", func(t *testing.T) {
		r := newRig(t)
		port := freePorts(t, 1)[0]
		r.mustSet(routeConfig(7, port, echoBackend(t)))
		_ = relay(t, port, "proxy.example.com")

		r.srv.BeginDrain(300 * time.Millisecond)
		r.srv.BeginDrain(time.Hour)
		r.drain(3600)
		if !r.waitDrained(5 * time.Second) {
			t.Fatal("a later Drain with a longer time extended the first")
		}
	})
	t.Run("zero is at once", func(t *testing.T) {
		r := newRig(t)
		port := freePorts(t, 1)[0]
		r.mustSet(routeConfig(7, port, echoBackend(t)))
		c := relay(t, port, "proxy.example.com")

		r.srv.BeginDrain(time.Hour)
		r.srv.BeginDrain(0)
		if !r.waitDrained(3 * time.Second) {
			t.Fatal("BeginDrain(0) did not end the drain")
		}
		if !closedSoon(c, 2*time.Second) {
			t.Error("the connection was not closed")
		}
	})
}

// A call that is cancelled does not stop the drain: it is the agent's call that
// times out after 15 s, and the drain goes on for up to an hour.
func TestDrainSurvivesCancelledCall(t *testing.T) {
	r := newRig(t)
	port := freePorts(t, 1)[0]
	r.mustSet(routeConfig(7, port, echoBackend(t)))
	c := relay(t, port, "proxy.example.com")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = r.srv.Drain(ctx, connect.NewRequest(&edgev1.DrainRequest{MaxSeconds: 30}))

	waitFor(t, "the listener to close", func() bool { return !portOpen(port) })
	aliveFor(t, c, 500*time.Millisecond)
	if r.drained() {
		t.Error("the drain ended with the call cancelled and a connection open")
	}
	_ = c.Close()
	if !r.waitDrained(3 * time.Second) {
		t.Error("the drain did not finish after the connection ended")
	}
}

func TestDrainCalledTwice(t *testing.T) {
	r := newRig(t)
	port := freePorts(t, 1)[0]
	r.mustSet(routeConfig(7, port, echoBackend(t)))
	c := relay(t, port, "proxy.example.com")
	r.drain(30)
	r.drain(30) // the agent calls it once per process of its own
	aliveFor(t, c, 200*time.Millisecond)
	_ = c.Close()
	if !r.waitDrained(3 * time.Second) {
		t.Error("the drain did not finish")
	}
}

func TestBeginDrainConcurrently(t *testing.T) {
	r := newRig(t)
	port := freePorts(t, 1)[0]
	r.mustSet(routeConfig(7, port, echoBackend(t)))
	c := relay(t, port, "proxy.example.com")

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.srv.BeginDrain(time.Duration(i+1) * 50 * time.Millisecond)
		}()
	}
	wg.Wait()
	if !r.waitDrained(5 * time.Second) {
		t.Fatal("the drain did not finish")
	}
	if !closedSoon(c, 2*time.Second) {
		t.Error("the connection was not closed")
	}
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

// A panic in a handler is logged with its stack and answered with an error that
// reveals nothing; the server goes on.
func TestHandlerRecoversFromPanic(t *testing.T) {
	checkGoroutines(t)
	logs := &logBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	srv := NewServer(nil, nil, nil, "", log) // Health calls the edge, which is nil: a panic
	sock := filepath.Join(shortDir(t), "s.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = hs.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		<-served
	})
	client := NewClient(sock)

	for i := range 2 { // the second call shows that the server is still there
		ctx, cancel := callCtx()
		_, err := client.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{}))
		cancel()
		var ce *connect.Error
		if !errors.As(err, &ce) || ce.Code() != connect.CodeInternal {
			t.Fatalf("call %d: error = %v, want CodeInternal", i, err)
		}
		if strings.Contains(ce.Message(), "nil") || strings.Contains(ce.Message(), "runtime") {
			t.Errorf("the error that the client gets, %q, tells of the inside", ce.Message())
		}
	}
	if out := logs.String(); !strings.Contains(out, "panic") || !strings.Contains(out, "goroutine") {
		t.Errorf("the log does not have the panic and its stack:\n%s", out)
	}
}

// Everything at once, for the race detector; and the file at the end is what
// is in effect.
func TestConcurrentCalls(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	ports := freePorts(t, 2)
	a := routeConfig(5, ports[0], be)
	b := withEgress(routeConfig(5, ports[0], be), "c1", "m1", ports[1])
	b.MaskDomains = []string{"mask.example.com"}
	r.mustSet(a)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					f()
				}
			}
		}()
	}
	// The goroutines report with t.Errorf: t.Fatal is for the goroutine of the test.
	for _, cfg := range []*edgev1.EdgeConfig{a, b} {
		run(func() {
			ctx, cancel := callCtx()
			defer cancel()
			resp, err := r.client.SetConfig(ctx, connect.NewRequest(&edgev1.SetConfigRequest{Config: cfg}))
			if err != nil {
				t.Errorf("SetConfig: %v", err)
			} else if !resp.Msg.GetApplied() {
				t.Errorf("SetConfig refused a good configuration: %s", resp.Msg.GetError())
			}
		})
	}
	run(func() {
		ctx, cancel := callCtx()
		defer cancel()
		if _, err := r.client.Snapshot(ctx, connect.NewRequest(&edgev1.SnapshotRequest{})); err != nil {
			t.Errorf("Snapshot: %v", err)
		}
	})
	run(func() {
		ctx, cancel := callCtx()
		defer cancel()
		if _, err := r.client.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{})); err != nil {
			t.Errorf("Health: %v", err)
		}
	})
	run(func() {
		c, err := net.DialTimeout("tcp4", addr(ports[0]), 3*time.Second)
		if err != nil {
			t.Errorf("connecting to the edge: %v", err)
			return
		}
		defer func() { _ = c.Close() }()
		hello := helloRecord("proxy.example.com")
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(hello); err != nil {
			t.Errorf("writing the hello: %v", err)
			return
		}
		if _, err := io.ReadFull(c, make([]byte, len(hello))); err != nil {
			t.Errorf("reading the echo of the hello: %v", err)
		}
	})

	time.Sleep(700 * time.Millisecond)
	close(stop)
	wg.Wait()

	saved := r.savedConfig()
	if !proto.Equal(saved, a) && !proto.Equal(saved, b) {
		t.Fatalf("the saved configuration is neither of those sent: %v", saved)
	}
	if got, want := portOpen(ports[1]), len(saved.GetSocks()) == 1; got != want {
		t.Errorf("SOCKS port open = %v, but the saved configuration has %d SOCKS ports", got, len(saved.GetSocks()))
	}
	if got := len(r.snapshot().GetHealth()); got != len(saved.GetChains()) {
		t.Errorf("egress health has %d members, the saved configuration has %d chains", got, len(saved.GetChains()))
	}
}

// The router comes first: an engine that connects to a SOCKS port before the
// chain it leads into exists gets a failure. The SOCKS ports follow, and the
// edge, which takes the public ports, is last. The three say what they do in
// their logs, and the order of those lines is the only trace of the order.
func TestApplyOrder(t *testing.T) {
	r := newRig(t)
	ports := freePorts(t, 2)
	r.mustSet(withEgress(routeConfig(1, ports[0], echoBackend(t)), "c1", "m1", ports[1]))

	logs := r.logs.String()
	chains := strings.Index(logs, "egress: chains applied")
	socks := strings.Index(logs, "egress: SOCKS port opened")
	listeners := strings.Index(logs, "edge: listening")
	if chains < 0 || socks < 0 || listeners < 0 {
		t.Fatalf("the log lacks a line of the parts (chains %d, SOCKS ports %d, edge %d):\n%s", chains, socks, listeners, logs)
	}
	if chains >= socks || socks >= listeners {
		t.Errorf("the parts were applied in the order chains %d, SOCKS ports %d, edge %d; want that order:\n%s", chains, socks, listeners, logs)
	}
}

// A request is bounded, and what is too large changes nothing.
func TestRequestSizeLimit(t *testing.T) {
	r := newRig(t)
	huge := routeConfig(1, freePorts(t, 1)[0], echoBackend(t))
	huge.MaskDomains = []string{strings.Repeat("a", maxRequestBytes+1<<20)}
	ctx, cancel := callCtx()
	defer cancel()
	resp, err := r.client.SetConfig(ctx, connect.NewRequest(&edgev1.SetConfigRequest{Config: huge}))
	if err == nil {
		t.Fatalf("a request of %d bytes was answered: %v", maxRequestBytes+1<<20, resp.Msg)
	}
	if h := r.health(); h.GetGeneration() != 0 || h.GetListening() {
		t.Errorf("Health = %v after the refused request, want nothing configured", h)
	}
	r.mustSet(routeConfig(1, freePorts(t, 1)[0], echoBackend(t))) // the server goes on
}

// A save that fails after the new file is in place, in the sync of the
// directory, leaves the new content in the file; the previous configuration is
// written back, so that the file is what is in effect.
func TestSetConfigWritesBackTheFileAfterALateSaveFailure(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	ports := freePorts(t, 2)
	prev := routeConfig(7, ports[0], be)
	r.mustSet(prev)

	syncs := 0
	stubDisk(t, nil, nil, func(string) error {
		syncs++
		if syncs == 1 {
			return errors.New("injected")
		}
		return nil
	})
	// Not through the socket: the stub is read by the goroutines of the server, and
	// the race detector cannot see the order that a socket gives.
	err := r.srv.set(routeConfig(7, ports[1], be))
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("set error = %v, want the failure of the sync", err)
	}
	if got := r.savedConfig(); !proto.Equal(got, prev) {
		t.Errorf("the file holds %v, want the configuration that is in effect", got)
	}
	if h := r.health(); !slices.Equal(h.GetBound(), []string{addr(ports[0])}) {
		t.Errorf("bound = %v, want the listener of the previous configuration only", h.GetBound())
	}
	if portOpen(ports[1]) {
		t.Error("the listener of the configuration that was not kept is open")
	}
}

// The agent sends the same configuration every pass; that is not news, and the
// log of the edge, which the agent keeps in a ring of 2000 lines, does not say
// it again.
func TestRepeatedConfigIsNotNews(t *testing.T) {
	r := newRigLevel(t, slog.LevelInfo)
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	cfg := routeConfig(3, port, be)
	for range 5 {
		r.mustSet(cfg)
	}
	const line = "control: configuration applied"
	if n := strings.Count(r.logs.String(), line); n != 1 {
		t.Errorf("%q is in the log %d times after five identical configurations, want once:\n%s", line, n, r.logs.String())
	}
	changed := routeConfig(3, port, be)
	changed.MaskDomains = []string{"mask.example.com"}
	r.mustSet(changed)
	if n := strings.Count(r.logs.String(), line); n != 2 {
		t.Errorf("%q is in the log %d times after a configuration that changed, want twice", line, n)
	}
}

// When Drain answers, the SOCKS ports and the listeners are closed already: the
// answer is the news that nothing is accepted any more. Looked at without a
// socket in between, which would give the drain time to catch up.
func TestDrainAnswersAfterTheClosing(t *testing.T) {
	r := newRig(t)
	ports := freePorts(t, 2)
	r.mustSet(withEgress(routeConfig(7, ports[0], echoBackend(t)), "c1", "m1", ports[1]))

	if _, err := r.srv.Drain(context.Background(), connect.NewRequest(&edgev1.DrainRequest{MaxSeconds: 30})); err != nil {
		t.Fatal(err)
	}
	if bound := r.edge.Bound(); len(bound) != 0 {
		t.Errorf("the edge still listens on %v when Drain has answered", bound)
	}
	if err := r.socks.Apply(nil); !errors.Is(err, egress.ErrClosed) {
		t.Errorf("Apply of the SOCKS ports after Drain = %v, want ErrClosed: they were not closed when Drain answered", err)
	}
}
