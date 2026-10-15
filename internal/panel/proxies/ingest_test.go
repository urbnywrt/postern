package proxies

import (
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func statsRec(seq uint64, minute time.Time, proxies []*nodev1.ProxyMinute, node *nodev1.NodeMinute) *nodev1.WatchResponse {
	return &nodev1.WatchResponse{Seq: seq, TsUnix: minute.Unix() + 61, Payload: &nodev1.WatchResponse_Stats{Stats: &nodev1.StatsBatch{
		MinuteUnix: minute.Unix(), Proxies: proxies, Node: node,
	}}}
}

func stateRec(seq uint64, ts time.Time, proxies ...*nodev1.ProxyStatus) *nodev1.WatchResponse {
	return &nodev1.WatchResponse{Seq: seq, TsUnix: ts.Unix(), Payload: &nodev1.WatchResponse_State{State: &nodev1.StateReport{
		AppliedGeneration: 1, Proxies: proxies,
	}}}
}

func eventRec(seq uint64, ts time.Time, ev *nodev1.NodeEvent) *nodev1.WatchResponse {
	return &nodev1.WatchResponse{Seq: seq, TsUnix: ts.Unix(), Payload: &nodev1.WatchResponse_Event{Event: ev}}
}

// ingest hands a record to the ingestor of the env and fails the test on an
// error.
func (e *env) ingestRec(nodeID string, rec *nodev1.WatchResponse) {
	e.t.Helper()
	if err := e.ingest.OnWatch(e.ctx, nodeID, rec); err != nil {
		e.t.Fatalf("OnWatch(%v): %v", rec, err)
	}
}

// twoNodes is a node with a proxy, and a second node with a proxy of its own.
func (e *env) twoNodes() (n *store.Node, p *panelv1.Proxy, other *store.Node, otherProxy *panelv1.Proxy) {
	e.t.Helper()
	n, l := e.nodeWithListener()
	p = e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	other = e.addNode("n2", "203.0.113.20")
	ol := e.createListener(&panelv1.CreateListenerRequest{NodeId: other.ID, Port: 443})
	otherProxy = e.createProxy(&panelv1.CreateProxyRequest{NodeId: other.ID, ListenerId: ol.GetId()})
	return n, p, other, otherProxy
}

func (e *env) proxySeries(id string, from, to time.Time) []store.ProxyStat {
	e.t.Helper()
	s, err := e.db.ProxySeries(e.ctx, id, from, to, store.DefaultStatsSettings().Retention())
	if err != nil {
		e.t.Fatalf("ProxySeries: %v", err)
	}
	return s
}

func (e *env) nodeSeries(id string, from, to time.Time) []store.NodeStat {
	e.t.Helper()
	s, err := e.db.NodeSeries(e.ctx, id, from, to, store.DefaultStatsSettings().Retention())
	if err != nil {
		e.t.Fatalf("NodeSeries: %v", err)
	}
	return s
}

func TestIngestStoresMinutes(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	from, to := minute.Add(-time.Hour), minute.Add(time.Minute)

	rec := statsRec(10, minute,
		[]*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 1000, Down: 5000, ConnsNew: 3, ConnsPeak: 2, Devices: 2, ConnsActive: 1}},
		&nodev1.NodeMinute{Cpu: 12.5, MemUsed: 1 << 30, MemTotal: 4 << 30, Load1: 0.5, DiskUsed: 10 << 30, DiskTotal: 40 << 30, NetRx: 6000, NetTx: 1200, Conns: 7})
	e.ingestRec(n.ID, rec)

	wantProxy := []store.ProxyStat{{ProxyID: p.GetId(), TS: minute, Up: 1000, Down: 5000, ConnsNew: 3, ConnsPeak: 2, Devices: 2}}
	wantNode := []store.NodeStat{{NodeID: n.ID, TS: minute, CPU: 12.5, MemUsed: 1 << 30, MemTotal: 4 << 30, Load1: 0.5,
		DiskUsed: 10 << 30, DiskTotal: 40 << 30, NetRx: 6000, NetTx: 1200, Conns: 7}}
	check := func(when string) {
		t.Helper()
		if got := e.proxySeries(p.GetId(), from, to); len(got) != 1 || got[0] != wantProxy[0] {
			t.Errorf("%s: proxy minutes = %+v, want %+v", when, got, wantProxy)
		}
		if got := e.nodeSeries(n.ID, from, to); len(got) != 1 || got[0] != wantNode[0] {
			t.Errorf("%s: node minutes = %+v, want %+v", when, got, wantNode)
		}
	}
	check("first delivery")

	// The same record again, as after a reconnect, changes nothing.
	e.ingestRec(n.ID, proto.Clone(rec).(*nodev1.WatchResponse))
	check("second delivery")
}

// A batch of statistics is stored in one transaction: the database syncs
// every commit to the disk, and a batch that fails leaves nothing behind (the
// record is offered again, whole).
func TestIngestStoresABatchInOneTransaction(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	l := e.storedProxy(p.GetId()).ListenerID
	q := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l})
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	from, to := minute.Add(-time.Hour), minute.Add(time.Hour)

	e.exec(`CREATE TRIGGER refuse_node_minutes BEFORE INSERT ON stats_node_1m BEGIN SELECT RAISE(ABORT, 'refused by the test'); END`)
	rec := statsRec(30, minute, []*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 1}, {ProxyId: q.GetId(), Up: 2}}, &nodev1.NodeMinute{Conns: 1})
	if err := e.ingest.OnWatch(e.ctx, n.ID, rec); err == nil {
		t.Fatal("OnWatch of a batch whose node minute the database refuses: no error")
	}
	for _, id := range []string{p.GetId(), q.GetId()} {
		if got := e.proxySeries(id, from, to); len(got) != 0 {
			t.Errorf("proxy %s has %d minutes of a batch that failed, want none", id, len(got))
		}
	}
	if m, ok := e.ingest.minuteOf(n.ID, p.GetId()); ok {
		t.Errorf("the live minute of a batch that failed: %+v", m)
	}

	e.exec(`DROP TRIGGER refuse_node_minutes`)
	e.ingestRec(n.ID, proto.Clone(rec).(*nodev1.WatchResponse))
	for _, id := range []string{p.GetId(), q.GetId()} {
		if got := e.proxySeries(id, from, to); len(got) != 1 {
			t.Errorf("proxy %s has %d minutes after the batch came again, want 1", id, len(got))
		}
	}
	if got := e.nodeSeries(n.ID, from, to); len(got) != 1 {
		t.Errorf("%d node minutes, want 1", len(got))
	}
}

func TestIngestSkipsReadingsItCannotTrust(t *testing.T) {
	e := newEnv(t)
	n, p, _, otherProxy := e.twoNodes()
	l := e.storedProxy(p.GetId()).ListenerID
	q := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l})
	minute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	from, to := minute.Add(-time.Hour), minute.Add(time.Hour)

	const tooMuch = 10 << 30 * 60 // more than 10 GiB/s over the minute
	e.ingestRec(n.ID, statsRec(1, minute, []*nodev1.ProxyMinute{
		{ProxyId: p.GetId(), Up: tooMuch + 1},           // implausible
		{ProxyId: q.GetId(), Up: 10, Down: 20},          // fine
		{ProxyId: otherProxy.GetId(), Up: 10},           // a proxy of another node
		{ProxyId: "01K6Y00000000000000000000Z", Up: 10}, // a proxy that is gone
		{ProxyId: strings.Repeat("x", 1000), Up: 10},    // not an id
	}, &nodev1.NodeMinute{NetRx: tooMuch + 1}))

	if got := e.proxySeries(p.GetId(), from, to); len(got) != 0 {
		t.Errorf("an implausible minute was stored: %+v", got)
	}
	if got := e.proxySeries(q.GetId(), from, to); len(got) != 1 || got[0].Up != 10 || got[0].Down != 20 {
		t.Errorf("the plausible minute next to it: %+v", got)
	}
	if got := e.proxySeries(otherProxy.GetId(), from, to); len(got) != 0 {
		t.Errorf("a node wrote the statistics of a proxy of another node: %+v", got)
	}
	if got := e.nodeSeries(n.ID, from, to); len(got) != 0 {
		t.Errorf("an implausible node minute was stored: %+v", got)
	}

	// A minute from the future, or of the start of 1970 (minute_unix 0), is
	// left out. (Ranges of up to 48 hours read the minutes.)
	future := time.Now().Add(2 * time.Hour).Truncate(time.Minute)
	for _, m := range []time.Time{future, time.Unix(0, 0)} {
		e.ingestRec(n.ID, statsRec(2, m, []*nodev1.ProxyMinute{{ProxyId: q.GetId(), Up: 1}}, &nodev1.NodeMinute{Cpu: 1}))
	}
	recent, epoch := [2]time.Time{minute.Add(-time.Hour), future.Add(time.Hour)}, [2]time.Time{time.Unix(-3600, 0), time.Unix(3600, 0)}
	if got := e.proxySeries(q.GetId(), recent[0], recent[1]); len(got) != 1 {
		t.Errorf("recent minutes of q = %+v, want only the plausible one of above", got)
	}
	if got := e.proxySeries(q.GetId(), epoch[0], epoch[1]); len(got) != 0 {
		t.Errorf("minutes of q around 1970 = %+v, want none", got)
	}
	for _, r := range [][2]time.Time{recent, epoch} {
		if got := e.nodeSeries(n.ID, r[0], r[1]); len(got) != 0 {
			t.Errorf("node minutes in %v = %+v, want none", r, got)
		}
	}

	// A node that is gone is no error either: the record is done with.
	if err := e.ingest.OnWatch(e.ctx, "01K6Y00000000000000000000Z", statsRec(3, minute, nil, &nodev1.NodeMinute{Cpu: 1})); err != nil {
		t.Errorf("OnWatch for a node that is gone: %v", err)
	}
	// No node at all owns no proxy (an empty filter of the store selects all).
	e.ingestRec("", statsRec(4, minute.Add(-5*time.Minute), []*nodev1.ProxyMinute{{ProxyId: q.GetId(), Up: 99}}, nil))
	if got := e.proxySeries(q.GetId(), recent[0], recent[1]); len(got) != 1 {
		t.Errorf("minutes of q after a record of no node = %+v", got)
	}
}

// A node buffers its records for 7 days, so a minute older than maxRecordAge is
// not a reading of it, and is left out, however far back it says it is.
func TestIngestLeavesOutAMinuteThatIsTooOld(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Minute)
	for _, tc := range []struct {
		name   string
		minute time.Time
		taken  bool
	}{
		{"the oldest that a node keeps, 7 days", now.Add(-7 * 24 * time.Hour), true},
		{"a little inside the bound", now.Add(-maxRecordAge + 2*time.Minute), true},
		{"a little outside the bound", now.Add(-maxRecordAge - 2*time.Minute), false},
		{"a month", now.Add(-30 * 24 * time.Hour), false},
		{"a year", now.Add(-365 * 24 * time.Hour), false},
		{"the start of 1971", time.Unix(31536000, 0), false},
		{"the future, over the bound", now.Add(maxMinuteAhead + 2*time.Minute), false},
		{"the future, within the bound", now.Add(maxMinuteAhead - 2*time.Minute), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n, p, _, _ := e.twoNodes()
			e.ingestRec(n.ID, statsRec(1, tc.minute,
				[]*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 5, Down: 6}}, &nodev1.NodeMinute{NetRx: 9}))

			from, to := tc.minute.Add(-time.Hour), tc.minute.Add(time.Hour)
			proxyMinutes, nodeMinutes := e.proxySeries(p.GetId(), from, to), e.nodeSeries(n.ID, from, to)
			live, err := e.stats.ProxyLive(e.ctx, connect.NewRequest(&panelv1.ProxyLiveRequest{ProxyId: p.GetId()}))
			if err != nil {
				t.Fatalf("ProxyLive: %v", err)
			}
			want := 0
			if tc.taken {
				want = 1
			}
			if len(proxyMinutes) != want || len(nodeMinutes) != want {
				t.Errorf("%d minutes of the proxy and %d of the node were stored, want %d of each", len(proxyMinutes), len(nodeMinutes), want)
			}
			if got := live.Msg.GetMinute() != nil; got != tc.taken {
				t.Errorf("the proxy has a live minute: %v, want %v", got, tc.taken)
			}
			if !tc.taken && !strings.Contains(e.logs.String(), "cannot be") {
				t.Errorf("the minute was left out without a word in the log: %q", e.logs.String())
			}
		})
	}
}

// The store keeps a minute under the start of it, so the minute that is live is
// the start of it as well: a reading that is stamped in the middle of a minute is
// that minute, and a second one of the same minute replaces the first, whichever
// second it is stamped with, in memory as in the store.
func TestIngestKeepsTheLiveMinuteAsTheStoreKeepsIt(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	minute := time.Now().UTC().Truncate(time.Minute).Add(-5 * time.Minute)
	from, to := minute.Add(-time.Hour), minute.Add(time.Hour)

	live := func() *panelv1.LiveMinute {
		t.Helper()
		resp, err := e.stats.ProxyLive(e.ctx, connect.NewRequest(&panelv1.ProxyLiveRequest{ProxyId: p.GetId()}))
		if err != nil {
			t.Fatalf("ProxyLive: %v", err)
		}
		return resp.Msg.GetMinute()
	}
	// checkMinute says that both the live minute and the stored one are the
	// minute, with this much up.
	checkMinute := func(when string, up uint64) {
		t.Helper()
		if got := live(); got.GetMinuteUnix() != minute.Unix() || got.GetUp() != up {
			t.Errorf("%s: live minute %d with up %d, want %d with up %d", when, got.GetMinuteUnix(), got.GetUp(), minute.Unix(), up)
		}
		stored := e.proxySeries(p.GetId(), from, to)
		if len(stored) != 1 || !stored[0].TS.Equal(minute) || stored[0].Up != up {
			t.Errorf("%s: stored minutes %+v, want one at %v with up %d", when, stored, minute, up)
		}
	}

	e.ingestRec(n.ID, statsRec(1, minute.Add(37*time.Second), []*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 1}}, nil))
	checkMinute("a reading 37 s into its minute", 1)

	e.ingestRec(n.ID, statsRec(2, minute.Add(5*time.Second), []*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 2}}, nil))
	checkMinute("a second reading of the minute, stamped earlier in it", 2)

	// The minute before, delivered late, is not the live one.
	e.ingestRec(n.ID, statsRec(3, minute.Add(-time.Minute+59*time.Second), []*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 9}}, nil))
	if got := live(); got.GetMinuteUnix() != minute.Unix() || got.GetUp() != 2 {
		t.Errorf("a reading of the minute before replaced the live minute: %v", got)
	}

	// The next minute is.
	e.ingestRec(n.ID, statsRec(4, minute.Add(time.Minute+1*time.Second), []*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 3}}, nil))
	if got := live(); got.GetMinuteUnix() != minute.Add(time.Minute).Unix() || got.GetUp() != 3 {
		t.Errorf("the next minute is not the live one: %v", got)
	}
}

func TestIngestKeepsTheStatusOfProxies(t *testing.T) {
	e := newEnv(t)
	n, p, other, otherProxy := e.twoNodes()
	now := time.Now().Truncate(time.Second)

	status := func(id string) *panelv1.ProxyStatus {
		t.Helper()
		resp, err := e.proxies.GetProxy(e.ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: id}))
		if err != nil {
			t.Fatalf("GetProxy: %v", err)
		}
		live, err := e.stats.ProxyLive(e.ctx, connect.NewRequest(&panelv1.ProxyLiveRequest{ProxyId: id}))
		if err != nil {
			t.Fatalf("ProxyLive: %v", err)
		}
		if !proto.Equal(resp.Msg.GetProxy().GetStatus(), live.Msg.GetStatus()) {
			t.Errorf("GetProxy and ProxyLive disagree: %v and %v", resp.Msg.GetProxy().GetStatus(), live.Msg.GetStatus())
		}
		return resp.Msg.GetProxy().GetStatus()
	}
	if got := status(p.GetId()); got.GetPhase() != "unknown" || got.GetReportedUnix() != 0 {
		t.Errorf("status before any report = %v", got)
	}

	e.ingestRec(n.ID, stateRec(10, now, &nodev1.ProxyStatus{
		ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT,
		RunningVersion: "3.5.13", InstanceGeneration: 2,
	}))
	want := &panelv1.ProxyStatus{Phase: "serving", RunningVersion: "3.5.13", InstanceGeneration: 2, ReportedUnix: now.Unix(), RunningEngine: "telemt"}
	if got := status(p.GetId()); !proto.Equal(got, want) {
		t.Errorf("status = %v, want %v", got, want)
	}

	// A node cannot report on the proxies of another node.
	e.ingestRec(other.ID, stateRec(5, now, &nodev1.ProxyStatus{
		ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reason: "lies",
	}, &nodev1.ProxyStatus{ProxyId: otherProxy.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_PAUSED}))
	if got := status(p.GetId()); !proto.Equal(got, want) {
		t.Errorf("status after another node reported on it = %v, want %v", got, want)
	}
	if got := status(otherProxy.GetId()); got.GetPhase() != "paused" {
		t.Errorf("status of the proxy of the other node = %v", got)
	}
	if evs := e.eventsOfKind(other.ID, "proxy.failed"); len(evs) != 0 {
		t.Errorf("events about a proxy of another node: %+v", evs)
	}

	// Failing is an event, once.
	failed := stateRec(11, now.Add(time.Second), &nodev1.ProxyStatus{
		ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reason: "artifact missing: telemt 3.5.13 for amd64 is not on the node",
		InstanceGeneration: 2,
	})
	e.ingestRec(n.ID, failed)
	if got := status(p.GetId()); got.GetPhase() != "failed" || !strings.HasPrefix(got.GetReason(), "artifact missing") {
		t.Errorf("status = %v, want failed with the reason", got)
	}
	evs := e.eventsOfKind(n.ID, "proxy.failed")
	if len(evs) != 1 {
		t.Fatalf("%d proxy.failed events, want 1", len(evs))
	}
	if ev := evs[0]; ev.ProxyID != p.GetId() || ev.Severity != "error" || !strings.HasPrefix(ev.Message, "artifact missing") ||
		!ev.TS.Equal(now.Add(time.Second).UTC()) {
		t.Errorf("event = %+v", ev)
	}
	e.ingestRec(n.ID, stateRec(12, now.Add(2*time.Second), &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reason: "still"}))
	if evs := e.eventsOfKind(n.ID, "proxy.failed"); len(evs) != 1 {
		t.Errorf("%d proxy.failed events after a second report of the failure, want 1", len(evs))
	}

	// The same record once more, as a panel that restarted gets it again, is
	// not a second failure.
	again := NewIngestor(e.db, e.log)
	if err := again.OnWatch(e.ctx, n.ID, proto.Clone(failed).(*nodev1.WatchResponse)); err != nil {
		t.Fatal(err)
	}
	if evs := e.eventsOfKind(n.ID, "proxy.failed"); len(evs) != 1 {
		t.Errorf("%d proxy.failed events after a replay, want 1", len(evs))
	}

	// Recovering and failing again is a new event.
	e.ingestRec(n.ID, stateRec(13, now.Add(3*time.Second), &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING}))
	e.ingestRec(n.ID, stateRec(14, now.Add(4*time.Second), &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED}))
	evs = e.eventsOfKind(n.ID, "proxy.failed")
	if len(evs) != 2 {
		t.Fatalf("%d proxy.failed events, want 2", len(evs))
	}
	if evs[1].Message == "" {
		t.Error("an event without a reason has no message")
	}

	// A proxy that a report leaves out has no status any more.
	e.ingestRec(n.ID, stateRec(15, now.Add(5*time.Second)))
	if got := status(p.GetId()); got.GetPhase() != "unknown" {
		t.Errorf("status after a report without the proxy = %v", got)
	}
}

// The opening report of a Watch from an agent that has not been through a pass
// yet lists no proxy, and has no number: it says nothing about the proxies, and
// the statuses that the panel knows stay. A numbered report without a proxy is
// news: the node has none.
func TestIngestKeepsTheStatusesThroughAnEmptyOpeningReport(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	now := time.Now().Truncate(time.Second)
	phase := func() string {
		t.Helper()
		resp, err := e.proxies.GetProxy(e.ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: p.GetId()}))
		if err != nil {
			t.Fatalf("GetProxy: %v", err)
		}
		return resp.Msg.GetProxy().GetStatus().GetPhase()
	}

	e.ingestRec(n.ID, stateRec(10, now, &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING}))
	e.ingestRec(n.ID, stateRec(0, now.Add(time.Second)))
	if got := phase(); got != "serving" {
		t.Errorf("phase after an empty opening report = %q, want it kept: serving", got)
	}

	// An opening report that lists the proxies replaces the statuses as any.
	e.ingestRec(n.ID, stateRec(0, now.Add(2*time.Second), &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_PENDING}))
	if got := phase(); got != "pending" {
		t.Errorf("phase after an opening report = %q, want pending", got)
	}
	e.ingestRec(n.ID, stateRec(11, now.Add(3*time.Second)))
	if got := phase(); got != "unknown" {
		t.Errorf("phase after a numbered report without the proxy = %q, want unknown", got)
	}
}

// A failure is an event when the panel sees the proxy fail: from a status that
// it knows and that is not failed. A panel that has just started knows none, and
// a proxy that failed before it started is not news; the node's own events say
// what happened while the panel was away.
func TestIngestRecordsAFailureOnlyFromAKnownStatus(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	now := time.Now().Truncate(time.Second)
	failed := &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reason: "artifact missing", InstanceGeneration: 2}

	e.ingestRec(n.ID, stateRec(10, now, failed))
	e.ingestRec(n.ID, stateRec(11, now.Add(time.Second), &nodev1.ProxyStatus{ProxyId: p.GetId()})) // a phase that is not set
	e.ingestRec(n.ID, stateRec(12, now.Add(2*time.Second), failed))
	if evs := e.eventsOfKind(n.ID, "proxy.failed"); len(evs) != 0 {
		t.Fatalf("%d proxy.failed events for a proxy that was never seen working, want none", len(evs))
	}

	e.ingestRec(n.ID, stateRec(13, now.Add(3*time.Second), &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_STARTING}))
	e.ingestRec(n.ID, stateRec(14, now.Add(4*time.Second), failed))
	if evs := e.eventsOfKind(n.ID, "proxy.failed"); len(evs) != 1 {
		t.Fatalf("%d proxy.failed events after starting and failing, want 1", len(evs))
	}

	// A panel that restarts and is told of the failure again records nothing.
	again := NewIngestor(e.db, e.log)
	if err := again.OnWatch(e.ctx, n.ID, stateRec(0, now.Add(5*time.Second), failed)); err != nil {
		t.Fatal(err)
	}
	if evs := e.eventsOfKind(n.ID, "proxy.failed"); len(evs) != 1 {
		t.Errorf("%d proxy.failed events after a restart of the panel, want 1", len(evs))
	}
}

// A record without a number has an id made of what it says, never a random one:
// one that comes again, as the opening report of every Watch does, or as a
// record does that is offered again, makes no second event.
func TestIngestGivesRecordsWithoutANumberStableIDs(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	now := time.Now().Truncate(time.Second)
	serving := &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING}
	failed := &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reason: "the engine exited", InstanceGeneration: 3}

	// The panel reconnects twice while the proxy fails; each opening report is
	// another record, of another time, that says the same.
	for i := range 2 {
		in := NewIngestor(e.db, e.log)
		if err := in.OnWatch(e.ctx, n.ID, stateRec(20, now, serving)); err != nil {
			t.Fatal(err)
		}
		if err := in.OnWatch(e.ctx, n.ID, stateRec(0, now.Add(time.Duration(i+1)*time.Minute), failed)); err != nil {
			t.Fatal(err)
		}
	}
	if evs := e.eventsOfKind(n.ID, "proxy.failed"); len(evs) != 1 {
		t.Errorf("%d proxy.failed events from opening reports that say the same, want 1", len(evs))
	}

	// An event that the node could not buffer comes without a number.
	ev := eventRec(0, now, &nodev1.NodeEvent{Kind: "reconcile_failed", Severity: "error", Message: "docker: the daemon does not answer"})
	e.ingestRec(n.ID, ev)
	e.ingestRec(n.ID, proto.Clone(ev).(*nodev1.WatchResponse))
	if evs := e.eventsOfKind(n.ID, "reconcile_failed"); len(evs) != 1 {
		t.Errorf("%d events from one record without a number given twice, want 1", len(evs))
	}
	// The same words at another time are another event.
	e.ingestRec(n.ID, eventRec(0, now.Add(time.Minute), &nodev1.NodeEvent{Kind: "reconcile_failed", Severity: "error", Message: "docker: the daemon does not answer"}))
	if evs := e.eventsOfKind(n.ID, "reconcile_failed"); len(evs) != 2 {
		t.Errorf("%d events, want 2: the second came at another time", len(evs))
	}
	for _, ev := range e.events(n.ID) {
		if !strings.HasPrefix(ev.ID, "w") {
			t.Errorf("event %+v has an id that is not made of its record", ev)
		}
	}
}

func TestIngestStoresNodeEvents(t *testing.T) {
	e := newEnv(t)
	n, p, _, otherProxy := e.twoNodes()
	ts := time.Now().Add(-time.Minute).Truncate(time.Second)

	rec := eventRec(20, ts, &nodev1.NodeEvent{
		Kind: "upgrade_aborted", Severity: "warning", Message: "the new generation did not get ready",
		ProxyId: p.GetId(), Details: map[string]string{"generation": "3"},
	})
	e.ingestRec(n.ID, rec)
	e.ingestRec(n.ID, proto.Clone(rec).(*nodev1.WatchResponse)) // delivered twice
	evs := e.eventsOfKind(n.ID, "upgrade_aborted")
	if len(evs) != 1 {
		t.Fatalf("%d events, want 1", len(evs))
	}
	if ev := evs[0]; ev.ProxyID != p.GetId() || ev.Severity != "warn" || ev.Message != "the new generation did not get ready" ||
		ev.Details["generation"] != "3" || !ev.TS.Equal(ts.UTC()) || ev.NodeID != n.ID {
		t.Errorf("event = %+v", ev)
	}

	// What a node says is bounded and cleaned.
	e.ingestRec(n.ID, eventRec(21, time.Unix(1, 0), &nodev1.NodeEvent{
		Kind:     "",
		Severity: "catastrophic",
		Message:  strings.Repeat("m", 5000) + "\xff",
		ProxyId:  otherProxy.GetId(), // a proxy of another node
		Details:  map[string]string{"k": strings.Repeat("v", 5000)},
	}))
	evs = e.eventsOfKind(n.ID, "node.event")
	if len(evs) != 1 {
		t.Fatalf("%d node.event events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Severity != "info" || len(ev.Message) > 1024 || ev.ProxyID != "" || len(ev.Details["k"]) > 256 {
		t.Errorf("event = %+v (message %d bytes)", ev, len(ev.Message))
	}
	if d := time.Since(ev.TS); d < 0 || d > time.Minute {
		t.Errorf("an event of 1970 got the time %v, want the time it came", ev.TS)
	}

	// Two events with the same number and another time are two events: the
	// node was installed again and counts from the start.
	e.ingestRec(n.ID, eventRec(20, ts.Add(time.Hour), &nodev1.NodeEvent{Kind: "upgrade_aborted", Severity: "error"}))
	if evs := e.eventsOfKind(n.ID, "upgrade_aborted"); len(evs) != 2 {
		t.Errorf("%d events, want 2", len(evs))
	}
}
