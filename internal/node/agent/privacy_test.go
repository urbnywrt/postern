package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// statsWith is a statistics record of minute with a sighting of each
// address and a country minute.
func statsWith(minute int64, ips ...string) *nodev1.WatchResponse {
	rec := statsRecord(minute, ips...)
	rec.GetStats().Countries = []*nodev1.CountryMinute{{ProxyId: "p1", Country: "DE", Ips: 1, Bytes: 10}}
	return rec
}

func openWatchPolicy(t *testing.T, r *rig, cursor uint64, policy nodev1.IpPolicy) *connect.ServerStreamForClient[nodev1.WatchResponse] {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	stream, err := r.client.Watch(ctx, connect.NewRequest(&nodev1.WatchRequest{Cursor: cursor, IpPolicy: policy}))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	return stream
}

// receiveStats skips records until a statistics record.
func receiveStats(t *testing.T, stream *connect.ServerStreamForClient[nodev1.WatchResponse]) *nodev1.StatsBatch {
	t.Helper()
	for {
		if rec := receive(t, stream); rec.GetStats() != nil {
			return rec.GetStats()
		}
	}
}

// The node sends sightings only when its policy and the stream's are both
// full, and country minutes only when neither is off; buffered records are
// filtered by the policy in force when they go out (R6-5).
func TestWatchFiltersByTheNodeAndTheStreamPolicy(t *testing.T) {
	r := newRig(t)
	if resp := r.apply(withPolicy(validState(1), nodev1.IpPolicy_IP_POLICY_FULL)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	appendAll(t, r.buf, statsWith(60, "203.0.113.7"))

	for _, tc := range []struct {
		stream         nodev1.IpPolicy
		ips, countries int
	}{
		{nodev1.IpPolicy_IP_POLICY_UNSPECIFIED, 1, 1}, // the node's own: full
		{nodev1.IpPolicy_IP_POLICY_FULL, 1, 1},
		{nodev1.IpPolicy_IP_POLICY_COUNTRIES, 0, 1},
		{nodev1.IpPolicy_IP_POLICY_OFF, 0, 0},
	} {
		b := receiveStats(t, openWatchPolicy(t, r, 0, tc.stream))
		if len(b.GetIps()) != tc.ips || len(b.GetCountries()) != tc.countries {
			t.Errorf("node full, stream %v: %d sightings, %d countries; want %d and %d", tc.stream, len(b.GetIps()), len(b.GetCountries()), tc.ips, tc.countries)
		}
	}

	// A record buffered under full and replayed after the node went to
	// countries: no sighting, also for a panel that still says full. (The
	// buffer is scrubbed too; the filter does not rely on it.)
	if resp := r.apply(withPolicy(validState(2), nodev1.IpPolicy_IP_POLICY_COUNTRIES)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	r.j.stats(statsWith(120, "203.0.113.8").GetStats())
	stream := openWatchPolicy(t, r, 0, nodev1.IpPolicy_IP_POLICY_FULL)
	for range 2 {
		if b := receiveStats(t, stream); len(b.GetIps()) != 0 || len(b.GetCountries()) != 1 {
			t.Errorf("after the node went to countries: %v", b)
		}
	}
	if resp := r.apply(withPolicy(validState(3), nodev1.IpPolicy_IP_POLICY_OFF)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	if b := receiveStats(t, openWatchPolicy(t, r, 0, nodev1.IpPolicy_IP_POLICY_COUNTRIES)); len(b.GetCountries()) != 0 {
		t.Errorf("node off: %v", b)
	}
}

// Leaving full drops the sightings of the open minute before ApplyState
// answers; its countries stay.
func TestApplyStateLeavingFullDropsTheOpenMinutesSightings(t *testing.T) {
	r := newRig(t)
	src := &fakeSnapshots{}
	seen := minuteAt(0, 5).Unix()
	src.queue = []map[uint64]*edgev1.SnapshotResponse{
		snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 1, 1)), ipc("p1", "203.0.113.1", 1, seen, 100))),
		snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 1, 1)), ipc("p1", "203.0.113.1", 1, seen, 300))),
	}
	svc := r.newService()
	c := &statsCollector{source: src, agg: newAggregator(), journal: r.j, proc: fstest.MapFS{}, mode: svc.ipMode, log: discardLog()}
	svc.stats = c
	apply := func(st *nodev1.NodeState) {
		t.Helper()
		resp, err := svc.ApplyState(context.Background(), connect.NewRequest(&nodev1.ApplyStateRequest{State: st}))
		if err != nil || !resp.Msg.GetAccepted() {
			t.Fatalf("ApplyState = %v, %v", resp, err)
		}
	}
	apply(withPolicy(validState(1), nodev1.IpPolicy_IP_POLICY_FULL))
	c.tick(context.Background(), minuteAt(0, 5))
	c.tick(context.Background(), minuteAt(0, 15))
	c.mu.Lock()
	open := len(c.agg.cur.ips)
	c.mu.Unlock()
	if open != 1 {
		t.Fatalf("open minute has %d sightings, want 1", open)
	}
	apply(withPolicy(validState(2), nodev1.IpPolicy_IP_POLICY_COUNTRIES))
	c.mu.Lock()
	open, addrs := len(c.agg.cur.ips), len(c.agg.cur.addrs)
	c.mu.Unlock()
	if open != 0 || addrs != 1 {
		t.Errorf("after leaving full: %d sightings, %d addresses for the countries; want 0 and 1", open, addrs)
	}
	c.tick(context.Background(), minuteAt(1, 5))
	recs, err := r.buf.After(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var got *nodev1.StatsBatch
	for _, rec := range recs {
		if rec.GetStats() != nil {
			got = rec.GetStats()
		}
	}
	if got == nil || len(got.GetIps()) != 0 || len(got.GetCountries()) != 1 || got.GetCountries()[0].GetBytes() != 200 {
		t.Errorf("published minute = %v", got)
	}
}

// Watch delivers a minute with its countries and members.
func TestWatchDeliversCountriesAndMembers(t *testing.T) {
	r := newRig(t)
	if resp := r.apply(withPolicy(validState(1), nodev1.IpPolicy_IP_POLICY_COUNTRIES)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	last, _ := r.buf.LastSeq()
	stream := openWatchPolicy(t, r, last, nodev1.IpPolicy_IP_POLICY_COUNTRIES)
	want := &nodev1.StatsBatch{
		MinuteUnix: 120,
		Countries:  []*nodev1.CountryMinute{{ProxyId: "p1", Country: "FR", Ips: 3, Bytes: 999}},
		Members:    []*nodev1.MemberMinute{{ChainId: "c1", MemberKey: "m1", Status: "up", LatencyMs: 40, ExitIp: "198.51.100.9"}},
		Node:       &nodev1.NodeMinute{RefusedPrehello: 2, RefusedTotal: 1, EvictedPrehello: 4},
		Probes:     []*nodev1.ProbeResult{{ProxyId: "p1", Kind: "l2", Ok: true, LatencyMs: 80, AtUnix: 100}},
	}
	r.j.stats(want)
	if got := receiveStats(t, stream); !proto.Equal(got, want) {
		t.Errorf("minute = %v\nwant %v", got, want)
	}
}

// A state report that differs from the last buffered one only in the
// latency of egress members goes to the open streams only.
func TestJournalIgnoresMemberLatency(t *testing.T) {
	clock := newTestClock()
	buf := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	j := newJournal(buf, discardLog(), clock.Now)
	rep := func(latency uint32, status string) *nodev1.StateReport {
		return &nodev1.StateReport{AppliedGeneration: 1, Egress: []*nodev1.EgressMemberHealth{
			{ChainId: "c1", MemberKey: "m1", Status: status, LatencyMs: latency, ExitIp: "198.51.100.9"}}}
	}
	j.state(rep(40, "up"))
	j.state(rep(45, "up"))
	j.state(rep(50, "up"))
	j.state(rep(50, "down"))
	recs, err := buf.After(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].GetState().GetEgress()[0].GetLatencyMs() != 40 || recs[1].GetState().GetEgress()[0].GetStatus() != "down" {
		t.Errorf("buffered = %v, want the first report and the one where the status changed", recs)
	}
}

// ScrubIPsBefore removes the sightings of the records before t, and the
// next call starts where it stopped.
func TestBufferScrubIPsBefore(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	t0 := clock.Now().Unix()
	rec := func(ts int64, ip string) *nodev1.WatchResponse {
		r := statsWith(ts-ts%60, ip)
		r.TsUnix = ts
		return r
	}
	seqs := appendAll(t, b, rec(t0, "203.0.113.1"), eventRecord("e"), rec(t0+3600, "203.0.113.2"), rec(t0+7200, "203.0.113.3"))
	n, err := b.ScrubIPsBefore(time.Unix(t0+5400, 0))
	if err != nil || n != 2 {
		t.Fatalf("ScrubIPsBefore = %d, %v, want 2", n, err)
	}
	recs, _ := b.After(0, 10)
	if len(recs[0].GetStats().GetIps()) != 0 || len(recs[2].GetStats().GetIps()) != 0 || len(recs[3].GetStats().GetIps()) != 1 {
		t.Errorf("after the scrub: %v", recs)
	}
	if len(recs[0].GetStats().GetCountries()) != 1 {
		t.Errorf("the countries went too: %v", recs[0])
	}

	// The resume point: an address put back into the first record by hand is
	// not read again; the newer record is scrubbed when its time comes.
	planted, _ := proto.Marshal(rec(t0, "203.0.113.99"))
	if _, err := b.db.Exec(`UPDATE events SET payload = ? WHERE seq = ?`, planted, seqs[0]); err != nil {
		t.Fatal(err)
	}
	n, err = b.ScrubIPsBefore(time.Unix(t0+9000, 0))
	if err != nil || n != 1 {
		t.Fatalf("second ScrubIPsBefore = %d, %v, want 1", n, err)
	}
	recs, _ = b.After(0, 10)
	if len(recs[0].GetStats().GetIps()) != 1 || len(recs[3].GetStats().GetIps()) != 0 {
		t.Errorf("after the second scrub: %v", recs)
	}
}

// Over the payload budget, the oldest statistics lose their addresses
// first, then the oldest records go.
func TestBufferMaintainKeepsThePayloadBudget(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	many := func(minute int64) *nodev1.WatchResponse {
		var ips []string
		for i := range 100 {
			ips = append(ips, "2001:db8::"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		}
		return statsWith(minute, ips...)
	}
	appendAll(t, b, many(60), many(61), many(62)) // records of one size
	total, err := b.payloadSize()
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := b.After(0, 10)
	clean := proto.Clone(recs[0]).(*nodev1.WatchResponse)
	clean.GetStats().Ips = nil
	clean.Seq = 0
	cleanSize, _ := proto.Marshal(clean)
	dirtySize := total / 3

	// Room for one record with its addresses and two without: the first two
	// are scrubbed.
	b.maxPayload = dirtySize + 2*int64(len(cleanSize))
	m, err := b.Maintain(time.Hour * 1000)
	if err != nil || m.budgetScrubs != 2 || m.budgetDeletes != 0 {
		t.Fatalf("Maintain = %+v, %v; want 2 scrubbed, none deleted", m, err)
	}
	recs, _ = b.After(0, 10)
	if len(recs) != 3 || len(recs[0].GetStats().GetIps()) != 0 || len(recs[1].GetStats().GetIps()) != 0 || len(recs[2].GetStats().GetIps()) != 100 {
		t.Errorf("after the scrub: %d records", len(recs))
	}

	// Room for one record without addresses: the last one is scrubbed, then
	// the oldest go.
	b.maxPayload = int64(len(cleanSize))
	m, err = b.Maintain(time.Hour * 1000)
	if err != nil || m.budgetScrubs != 1 || m.budgetDeletes != 2 {
		t.Fatalf("Maintain = %+v, %v; want 1 scrubbed, 2 deleted", m, err)
	}
	recs, _ = b.After(0, 10)
	if len(recs) != 1 || recs[0].GetStats().GetMinuteUnix() != 62 || len(recs[0].GetStats().GetIps()) != 0 {
		t.Errorf("left: %v", kindsOf(recs))
	}
}

// Maintain scrubs what is older than the IP retention.
func TestBufferMaintainScrubsByRetention(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	appendAll(t, b, statsWith(60, "203.0.113.1"))
	clock.Advance(2 * time.Hour)
	appendAll(t, b, statsWith(7260, "203.0.113.2"))
	m, err := b.Maintain(time.Hour)
	if err != nil || m.scrubbed != 1 {
		t.Fatalf("Maintain = %+v, %v; want 1 scrubbed", m, err)
	}
}

// With secure_delete on and the log emptied, a scrubbed address is gone
// from stats.db and from its -wal file.
func TestBufferScrubLeavesNoAddressOnDisk(t *testing.T) {
	clock := newTestClock()
	path := filepath.Join(t.TempDir(), "stats.db")
	b := openTestBuffer(t, path, testNodeID, clock)
	var on int
	if err := b.db.QueryRow(`PRAGMA secure_delete`).Scan(&on); err != nil || on != 1 {
		t.Fatalf("secure_delete = %d, %v", on, err)
	}
	const planted = "203.0.113.77"
	appendAll(t, b, statsWith(60, planted), eventRecord("after"))
	onDisk := func() bool {
		for _, f := range []string{path, path + "-wal"} {
			data, err := os.ReadFile(f)
			if err == nil && bytes.Contains(data, []byte(planted)) {
				return true
			}
		}
		return false
	}
	if !onDisk() {
		t.Fatal("the planted address is not on the disk before the scrub: the test proves nothing")
	}
	if n, err := b.ScrubIPs(); err != nil || n != 1 {
		t.Fatalf("ScrubIPs = %d, %v", n, err)
	}
	if err := b.checkpoint(); err != nil {
		t.Fatal(err)
	}
	if onDisk() {
		t.Error("the scrubbed address is still in stats.db or its -wal file")
	}
}
