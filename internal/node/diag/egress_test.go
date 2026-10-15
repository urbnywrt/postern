package diag

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/probe/probetest"
	"github.com/urbnywrt/postern/internal/socks5"
)

// egressState is a node with chain C1 of a SOCKS5 member s1 and a subscription
// sub (two members a, b served by generation 4), the default chain C2 of a
// WARP egress w that no instance serves, and proxy P1 on C1 with the middle
// proxies, P2 on the default chain without them, P3 disabled.
func egressState() (*nodev1.NodeState, *state.Runtime) {
	st := &nodev1.NodeState{
		Settings: &nodev1.NodeSettings{DefaultChainId: "C2"},
		Egresses: []*nodev1.Egress{
			{Id: "s1", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"192.0.2.50:1080"}`},
			{Id: "sub", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION},
			{Id: "w", Kind: nodev1.EgressKind_EGRESS_KIND_WARP},
		},
		Chains: []*nodev1.EgressChain{
			{Id: "C1", MemberEgressIds: []string{"s1", "sub"}},
			{Id: "C2", MemberEgressIds: []string{"w"}},
			{Id: "C9", MemberEgressIds: []string{"s1"}}, // used by nobody
		},
		Proxies: []*nodev1.Proxy{
			{Id: "P1", ListenerId: "L1", Enabled: true, Secret: testSecret, Domain: "example.com", EgressChainId: "C1", UseMiddleProxy: true},
			{Id: "P2", ListenerId: "L1", Enabled: true, Secret: testSecret, Domain: "example.net"},
			{Id: "P3", ListenerId: "L1", Secret: testSecret, Domain: "example.org", EgressChainId: "C9"},
		},
	}
	rt := state.NewRuntime()
	rt.EdgeGeneration = 3
	rt.Egresses["sub"] = state.EgressRecord{Generation: 4, Members: []state.EgressMember{{Key: "a", Port: 21001}, {Key: "b", Port: 21002}}}
	return st, rt
}

func memberHealth(chain, key, status string, checked time.Time) *edgev1.MemberHealth {
	return &edgev1.MemberHealth{ChainId: chain, MemberKey: key, Status: status, LatencyMs: 42, ExitIp: "198.51.100.9", CheckedUnix: checked.Unix()}
}

func byTarget(rs []Result) map[string]Result {
	out := map[string]Result{}
	for _, r := range rs {
		out[r.Target] = r
	}
	return out
}

func TestMemberTargets(t *testing.T) {
	st, rt := egressState()
	env := &Env{Desired: st, Runtime: rt}
	got := memberTargets(env)
	want := []string{"member:C1/s1", "member:C1/sub/a", "member:C1/sub/b", "member:C2/w"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("targets = %v, want %v", got, want)
	}
}

// egress.member: up, down while a sibling is up, every member down, unknown,
// not reported, a provider with no instance; the subscription's fix.
func TestEgressMember(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	st, rt := egressState()
	snap := &edgev1.SnapshotResponse{Health: []*edgev1.MemberHealth{
		memberHealth("C1", "s1", "up", now.Add(-40*time.Second)),
		memberHealth("C1", "sub/a", "down", now.Add(-10*time.Second)),
		memberHealth("C1", "sub/b", "unknown", time.Time{}),
	}}
	e := &fakeEdge{snap: snap}
	env := edgeEnv(e, st)
	env.Runtime = rt
	env.Now = func() time.Time { return now }
	rs := byTarget((&memberCheck{}).run(context.Background(), env))
	if r := rs["member:C1/s1"]; r.Status != OK || !strings.Contains(r.Summary, "42 ms") || !strings.Contains(r.Summary, "198.51.100.9") || !strings.Contains(r.Summary, "40s ago") || r.Fix != "" {
		t.Errorf("up: %+v", r)
	}
	if r := rs["member:C1/sub/a"]; r.Status != Warn || r.Fix != FixRefreshSubscription {
		t.Errorf("down with a sibling up: %+v", r)
	}
	if r := rs["member:C1/sub/b"]; r.Status != Skip {
		t.Errorf("unknown: %+v", r)
	}
	if r := rs["member:C2/w"]; r.Status != Warn || r.Fix != "" || !strings.Contains(r.Summary, "yet") {
		t.Errorf("a provider just seen without an instance: %+v", r)
	}

	// Every member of C1 down: fail; the SOCKS5 member offers no fix.
	snap.Health[0].Status = "down"
	rs = byTarget((&memberCheck{}).run(context.Background(), env))
	if r := rs["member:C1/s1"]; r.Status != Fail || r.Fix != "" {
		t.Errorf("all down, socks member: %+v", r)
	}
	if r := rs["member:C1/sub/a"]; r.Status != Fail || r.Fix != FixRefreshSubscription || !strings.Contains(r.Evidence, "sub/b") {
		t.Errorf("all down, subscription member: %+v", r)
	}

	// A member the edge has not reported, and a light run of one target.
	snap.Health = snap.Health[:1]
	env.Only = "member:C1/sub/b"
	if r := one(t, (&memberCheck{}).run(context.Background(), env)); r.Status != Skip || r.Target != "member:C1/sub/b" {
		t.Errorf("not reported: %+v", r)
	}

	// No edge, or an edge that does not answer: skip.
	env.Only = ""
	e.err = errors.New("unavailable")
	for _, r := range (&memberCheck{}).run(context.Background(), env) {
		if r.Status != Skip {
			t.Errorf("edge down: %+v", r)
		}
	}
}

// The exit IP a member reports is not a client's address: it survives the
// redactor, while other addresses do not.
func TestEgressMemberExitIPSurvivesTheRedactor(t *testing.T) {
	now := time.Now()
	st, rt := egressState()
	env := edgeEnv(&fakeEdge{snap: &edgev1.SnapshotResponse{Health: []*edgev1.MemberHealth{
		memberHealth("C1", "s1", "up", now),
		memberHealth("C1", "sub/a", "down", now),
	}}}, st)
	env.Runtime = rt
	env.Scrub = NewScrubber(st, rt, nil)
	env.Only = "member:C1/s1"
	budget := MaxRunEvidence
	c := Check{ID: IDEgressMember, Layer: LayerEgress}
	r := finalize(c, one(t, (&memberCheck{}).run(context.Background(), env)), env, &budget)
	if !strings.Contains(r.Summary, "198.51.100.9") {
		t.Errorf("exit IP redacted: %q", r.Summary)
	}
	r = finalize(c, Result{Status: Fail, Summary: "from 198.51.100.9 and 203.0.113.77"}, env, &budget)
	if strings.Contains(r.Summary, "198.51.100.9") || strings.Contains(r.Summary, "203.0.113.77") {
		t.Errorf("a result without the exit IP keeps addresses: %q", r.Summary)
	}
}

// startSOCKS is a SOCKS5 server on the loopback whose CONNECTs go to to, or,
// when to is "", are acknowledged and then closed at once (a dead member).
func startSOCKS(t *testing.T, to string) uint16 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := &socks5.Server{
		Dial: func(ctx context.Context, _ socks5.Request) (net.Conn, error) {
			if to == "" {
				a, b := net.Pipe()
				_ = b.Close()
				return a, nil
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", to)
		},
		Logger: slog.New(slog.DiscardHandler),
	}
	go func() { _ = srv.Serve(l) }()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	n, _ := strconv.Atoi(port)
	return uint16(n)
}

// egress.dc and egress.me through the serving instance's SOCKS port, with the
// gate's checks: a datacenter behind the port answers; a member that
// acknowledges early and closes fails both, with the fix change_egress.
func TestEgressDCAndME(t *testing.T) {
	dc, err := probetest.NewServer(probetest.Answers, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dc.Close() })
	st, rt := egressState()
	good, dead := startSOCKS(t, dc.Addr()), startSOCKS(t, "")
	rt.Instances["P1"] = state.InstanceRecord{Generation: 2, SocksPort: dead}
	rt.Instances["P2"] = state.InstanceRecord{Generation: 5, SocksPort: good}
	var socksSeen []string
	env := &Env{Desired: st, Runtime: rt, PingDC: reconcile.PingDC, ProxyDCs: reconcile.ProxyDCs,
		ProxySecret: func(ctx context.Context, socks string) error {
			socksSeen = append(socksSeen, socks)
			if socks == "127.0.0.1:"+strconv.Itoa(int(good)) {
				return nil
			}
			return reconcile.ProxySecretCheck(ctx, socks)
		}}

	rs := byTarget(checkEgressDC(context.Background(), env))
	if len(rs) != 2 {
		t.Fatalf("egress.dc results = %+v, want P1 and P2", rs)
	}
	if r := rs["proxy:P2"]; r.Status != OK || !strings.Contains(r.Summary, "149.154.175.50:443") {
		t.Errorf("egress.dc through a working member: %+v", r)
	}
	if r := rs["proxy:P1"]; r.Status != Fail || r.Fix != FixChangeEgress || !strings.Contains(r.Evidence, "EOF") {
		t.Errorf("egress.dc through a dead member: %+v", r)
	}

	// Only P1 uses the middle proxies.
	r := one(t, checkEgressME(context.Background(), env))
	if r.Target != "proxy:P1" || r.Status != Fail || r.Fix != FixChangeEgress {
		t.Errorf("egress.me through a dead member: %+v", r)
	}
	if len(socksSeen) != 1 || socksSeen[0] != "127.0.0.1:"+strconv.Itoa(int(dead)) {
		t.Errorf("egress.me asked through %v", socksSeen)
	}
	rt.Instances["P1"] = state.InstanceRecord{Generation: 2, SocksPort: good}
	if r := one(t, checkEgressME(context.Background(), env)); r.Status != OK {
		t.Errorf("egress.me through a working member: %+v", r)
	}

	// No serving engine, or no SOCKS port: skip; a run of one proxy's scope
	// asks only for that proxy.
	delete(rt.Instances, "P2")
	sc, _ := parseScope("proxy:P2", st)
	env.scope = sc
	if r := one(t, checkEgressDC(context.Background(), env)); r.Status != Skip || r.Target != "proxy:P2" {
		t.Errorf("not serving: %+v", r)
	}
}

// The checks read only: nothing they do changes the desired state or the
// runtime record.
func TestEgressChecksDoNotMutate(t *testing.T) {
	st, rt := egressState()
	before := len(rt.Instances) + len(rt.Egresses) + len(rt.Ports)
	env := edgeEnv(&fakeEdge{snap: &edgev1.SnapshotResponse{}}, st)
	env.Runtime = rt
	_ = (&memberCheck{}).run(context.Background(), env)
	_ = checkEgressDC(context.Background(), env)
	if after := len(rt.Instances) + len(rt.Egresses) + len(rt.Ports); after != before {
		t.Errorf("runtime record changed: %d → %d", before, after)
	}
}

// A provider's egress without an instance warns for two minutes (its instance
// may be starting), then fails alone in its chain; once an instance serves
// it, the grace starts over the next time it has none.
func TestEgressMemberInstanceGrace(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	st, rt := egressState()
	env := edgeEnv(&fakeEdge{snap: &edgev1.SnapshotResponse{}}, st)
	env.Runtime = rt
	env.Now = func() time.Time { return now }
	env.Only = "member:C2/w"
	c := &memberCheck{}
	if r := one(t, c.run(context.Background(), env)); r.Status != Warn || !strings.Contains(r.Summary, "for 0s") {
		t.Errorf("at first: %+v", r)
	}
	now = now.Add(119 * time.Second)
	if r := one(t, c.run(context.Background(), env)); r.Status != Warn || !strings.Contains(r.Summary, "1m59s") {
		t.Errorf("within the grace: %+v", r)
	}
	now = now.Add(time.Second)
	if r := one(t, c.run(context.Background(), env)); r.Status != Fail || !strings.Contains(r.Summary, "no member of the chain is up") {
		t.Errorf("after the grace: %+v", r)
	}
	// An instance comes up (its member up), then goes away: a new grace.
	rt.Egresses["w"] = state.EgressRecord{Generation: 1, Members: []state.EgressMember{{Key: "warp", Port: 21003}}}
	env.Only = ""
	_ = c.run(context.Background(), env)
	delete(rt.Egresses, "w")
	env.Only = "member:C2/w"
	now = now.Add(time.Hour)
	if r := one(t, c.run(context.Background(), env)); r.Status != Warn {
		t.Errorf("gone again: %+v", r)
	}
}

// F3 of the real-server pass: an egress whose instance cannot start because
// the provider's binary is not on the node says so at once (no "it may be
// starting" grace), names the artifact, and hints at its delivery.
func TestEgressMemberNamesTheMissingArtifact(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	st, rt := egressState()
	env := edgeEnv(&fakeEdge{snap: &edgev1.SnapshotResponse{}}, st)
	env.Runtime = rt
	env.Now = func() time.Time { return now }
	env.Only = "member:C2/w"
	const why = "artifact missing: psiphon-core 20261005-c4a09096ab for amd64 is not on the node (or does not match its checksum)"
	env.EgressReason = func(id string) string {
		if id == "w" {
			return why
		}
		return ""
	}
	r := one(t, (&memberCheck{}).run(context.Background(), env))
	if r.Status != Fail || !strings.Contains(r.Summary, why) || strings.Contains(r.Summary, "may be starting") ||
		!strings.Contains(r.Hint, "release bundle") {
		t.Errorf("artifact missing: %+v", r)
	}
	// Another reason is named too, with the usual hint.
	env.EgressReason = func(string) string { return "the trial of the binary failed" }
	r = one(t, (&memberCheck{}).run(context.Background(), env))
	if r.Status != Fail || !strings.Contains(r.Summary, "the trial of the binary failed") || r.Hint != hintMember {
		t.Errorf("another reason: %+v", r)
	}
}

// egress.dc: a proxy whose way out hangs past the check's time is "not
// checked in time" (skip, no fix), and does not hold the others back.
func TestEgressDCOutOfTime(t *testing.T) {
	st, rt := egressState()
	rt.Instances["P1"] = state.InstanceRecord{Generation: 2, SocksPort: 1}
	rt.Instances["P2"] = state.InstanceRecord{Generation: 5, SocksPort: 2}
	env := &Env{Desired: st, Runtime: rt, PingDC: func(ctx context.Context, socks, _ string) error {
		if socks == "127.0.0.1:1" {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	rs := byTarget(checkEgressDC(ctx, env))
	if r := rs["proxy:P1"]; r.Status != Skip || r.Fix != "" || r.Summary != notInTime {
		t.Errorf("hanging past the check's time: %+v", r)
	}
	if r := rs["proxy:P2"]; r.Status != OK {
		t.Errorf("the other proxy: %+v", r)
	}
}

// eachUnit: every unit under its own deadline; one that runs out of its own
// time fails (a real failure), one cut by the check's time is a skip, and a
// unit never started for lack of time is a skip too.
func TestEachUnit(t *testing.T) {
	fn := func(ctx context.Context, u string) Result {
		if u == "hang" {
			<-ctx.Done()
			return Result{Status: Fail, Summary: "hung"}
		}
		return Result{Status: OK}
	}
	id := func(u string) string { return "proxy:" + u }
	rs := byTarget(eachUnit(context.Background(), []string{"hang", "hang2", "a", "b"}, 4, 50*time.Millisecond, id,
		func(ctx context.Context, u string) Result { return fn(ctx, strings.TrimSuffix(u, "2")) }))
	if rs["proxy:hang"].Status != Fail || rs["proxy:hang2"].Status != Fail || rs["proxy:a"].Status != OK || rs["proxy:b"].Status != OK {
		t.Errorf("own deadlines: %+v", rs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	rs = byTarget(eachUnit(ctx, []string{"hang", "a"}, 1, time.Minute, id, fn))
	if r := rs["proxy:hang"]; r.Status != Skip || r.Summary != notInTime {
		t.Errorf("cut by the check's time: %+v", r)
	}
	if r := rs["proxy:a"]; r.Status != Skip {
		t.Errorf("never started: %+v", r)
	}
}
