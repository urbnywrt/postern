package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
)

// testCountries is the country database of the tests: 203.0.113.0/25 is DE,
// 198.51.100.0/24 FR; 192.0.2.0/24 is unknown.
var testCountries = map[string]string{"203.0.113.0/25": "DE", "198.51.100.0/24": "FR"}

func openTestCountries(t *testing.T, networks map[string]string) *geoip.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "countries.mmdb")
	if err := geoiptest.Write(path, networks); err != nil {
		t.Fatal(err)
	}
	db, err := geoip.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func ipc(proxy, ip string, active uint32, seen int64, bytes uint64) *edgev1.IpCounters {
	return &edgev1.IpCounters{ProxyId: proxy, Ip: ip, ConnsActive: active, LastSeenUnix: seen, Bytes: bytes}
}

func withIPs(s *edgev1.SnapshotResponse, ips ...*edgev1.IpCounters) *edgev1.SnapshotResponse {
	s.Ips = ips
	return s
}

func countriesOf(b *nodev1.StatsBatch) map[string]string {
	out := map[string]string{}
	for _, c := range b.GetCountries() {
		out[c.GetProxyId()+"/"+c.GetCountry()] = fmt.Sprintf("%d ips %d bytes", c.GetIps(), c.GetBytes())
	}
	return out
}

// Under countries the edge is asked for the addresses and the minute has
// country minutes only; under full also the sightings; under off neither,
// and the edge is not asked. Two countries and an unknown address; the bytes
// are increments from the first answer on.
func TestStatsCollectorCountriesByPolicy(t *testing.T) {
	seen := minuteAt(0, 10).Unix()
	ticks := []map[uint64]*edgev1.SnapshotResponse{
		snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 1, 1)),
			ipc("p1", "203.0.113.1", 1, seen, 1000), ipc("p1", "203.0.113.2", 0, seen, 500),
			ipc("p1", "198.51.100.1", 1, seen, 200), ipc("p1", "192.0.2.1", 1, seen, 50))),
		snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 1, 1)),
			ipc("p1", "203.0.113.1", 1, seen, 1600), ipc("p1", "203.0.113.2", 0, seen, 500),
			ipc("p1", "198.51.100.1", 1, seen, 500), ipc("p1", "192.0.2.1", 1, seen, 80))),
		snaps(withIPs(snap(1, pc("p1", 0, 0, 0, 0, 0)))),
	}
	db := openTestCountries(t, testCountries)
	run := func(mode ipMode) (*nodev1.StatsBatch, []bool) {
		clock := newTestClock()
		buf := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
		src := &fakeSnapshots{queue: slices.Clone(ticks)}
		agg := newAggregator()
		agg.country = func(ip string) string { return countryOf(db, ip) }
		c := &statsCollector{source: src, agg: agg, journal: newJournal(buf, discardLog(), clock.Now),
			proc: fstest.MapFS{}, mode: func() ipMode { return mode }, log: discardLog()}
		for _, at := range []time.Time{minuteAt(0, 5), minuteAt(0, 15), minuteAt(1, 5)} {
			c.tick(context.Background(), at)
		}
		recs, err := buf.After(0, 10)
		if err != nil || len(recs) != 1 {
			t.Fatalf("records = %v, %v", recs, err)
		}
		return recs[0].GetStats(), src.asked
	}

	want := map[string]string{"p1/": "1 ips 30 bytes", "p1/DE": "2 ips 600 bytes", "p1/FR": "1 ips 300 bytes"}
	b, asked := run(modeCountries)
	if got := countriesOf(b); !mapsEqual(got, want) || len(b.GetIps()) != 0 {
		t.Errorf("countries: countries = %v, sightings = %v; want %v and none", got, b.GetIps(), want)
	}
	if !slices.Equal(asked, []bool{true, true, true}) {
		t.Errorf("countries: asked = %v", asked)
	}
	b, _ = run(modeFull)
	if got := countriesOf(b); !mapsEqual(got, want) || len(b.GetIps()) != 4 {
		t.Errorf("full: countries = %v, sightings = %v", got, b.GetIps())
	}
	b, asked = run(modeOff)
	if len(b.GetCountries()) != 0 || len(b.GetIps()) != 0 || slices.Contains(asked, true) {
		t.Errorf("off: countries = %v, sightings = %v, asked = %v", b.GetCountries(), b.GetIps(), asked)
	}
}

func countryOf(db *geoip.DB, ip string) string {
	g := &geoStore{}
	g.db.Store(db)
	return g.country(ip)
}

// full and countries share the baseline of the IP counters: a switch
// between them counts increments; off in between makes the next answer a
// baseline again.
func TestAggregatorSwitchingBetweenFullAndCountriesMakesNoSpike(t *testing.T) {
	ip := func(bytes uint64) *edgev1.SnapshotResponse {
		return withIPs(snap(1, pc("p1", 0, 0, 0, 1, 1)), ipc("p1", "203.0.113.1", 1, minuteAt(0, 0).Unix(), bytes))
	}
	a := newAggregator()
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(ip(1000)), nil, true, modeFull))       // baseline
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(ip(1500)), nil, true, modeCountries)) // +500
	mustNoBatch(t, a.observe(minuteAt(0, 25), snaps(ip(1700)), nil, true, modeFull))      // +200
	b := a.observe(minuteAt(1, 5), snaps(ip(1700)), nil, true, modeCountries)
	if got := countriesOf(b)["p1/"]; got != "1 ips 700 bytes" {
		t.Errorf("country minute = %q, want 1 ips 700 bytes", got)
	}
	if len(b.GetIps()) != 1 || b.GetIps()[0].GetBytes() != 200 {
		t.Errorf("sightings = %v, want 203.0.113.1 with the 200 bytes of the full observation", b.GetIps())
	}

	// off in between: the counters were not received, so they come back as
	// a baseline.
	mustNoBatch(t, a.observe(minuteAt(1, 15), snaps(snap(1, pc("p1", 0, 0, 0, 1, 1))), nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(1, 25), snaps(ip(9000)), nil, true, modeFull))
	mustNoBatch(t, a.observe(minuteAt(1, 35), snaps(ip(9100)), nil, true, modeFull))
	b = a.observe(minuteAt(2, 5), snaps(ip(9100)), nil, true, modeFull)
	if got := countriesOf(b)["p1/"]; got != "1 ips 100 bytes" {
		t.Errorf("after off: country minute = %q, want 1 ips 100 bytes", got)
	}
}

// The refusal counters of the edge go into the node minute as increments
// per edge generation: a generation there at the start is a baseline, a new
// one counts from zero, a restart within a generation is a fresh start.
func TestAggregatorRefusalCounters(t *testing.T) {
	ref := func(s *edgev1.SnapshotResponse, pre, total, evicted uint64) *edgev1.SnapshotResponse {
		s.RefusedPrehello, s.RefusedTotal, s.EvictedPrehello = pre, total, evicted
		return s
	}
	a := newAggregator()
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(ref(snap(1), 10, 20, 5)), nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(ref(snap(1), 12, 20, 6), ref(snap(2), 3, 1, 0)), nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 25), snaps(ref(snap(1), 1, 0, 0), ref(snap(2), 4, 1, 2)), nil, false, modeOff))
	b := a.observe(minuteAt(1, 5), snaps(ref(snap(2), 4, 1, 2)), nil, false, modeOff)
	n := b.GetNode()
	// gen 1: +2 +0 +1, then restarted: +1 +0 +0; gen 2: new 3 1 0, then +1 +0 +2.
	if n.GetRefusedPrehello() != 7 || n.GetRefusedTotal() != 1 || n.GetEvictedPrehello() != 3 {
		t.Errorf("node minute = %v, want refused_prehello 7, refused_total 1, evicted_prehello 3", n)
	}
	mustNoBatch(t, a.observe(minuteAt(1, 15), snaps(ref(snap(2), 4, 1, 2)), nil, false, modeOff))
	if b := a.observe(minuteAt(2, 5), snaps(ref(snap(2), 4, 1, 2)), nil, false, modeOff); b.GetNode().GetRefusedPrehello() != 0 {
		t.Errorf("a quiet minute = %v", b.GetNode())
	}
}

// Member minutes come from the health of the newest edge generation: the
// last status, the latency while up, the last exit IP; sorted.
func TestAggregatorMemberMinutes(t *testing.T) {
	health := func(s *edgev1.SnapshotResponse, h ...*edgev1.MemberHealth) *edgev1.SnapshotResponse {
		s.Health = h
		return s
	}
	mh := func(chain, member, status string, latency uint32, exit string) *edgev1.MemberHealth {
		return &edgev1.MemberHealth{ChainId: chain, MemberKey: member, Status: status, LatencyMs: latency, ExitIp: exit}
	}
	a := newAggregator()
	old := health(snap(1), mh("old", "x", "up", 5, "203.0.113.90"))
	mustNoBatch(t, a.observe(minuteAt(0, 5), snaps(old, health(snap(2),
		mh("c1", "m2", "down", 0, ""), mh("c1", "m1", "up", 50, "203.0.113.50"))), nil, false, modeOff))
	mustNoBatch(t, a.observe(minuteAt(0, 15), snaps(old, health(snap(2),
		mh("c1", "m1", "down", 70, ""), mh("c1", "m2", "up", 30, "198.51.100.5"))), nil, false, modeOff))
	b := a.observe(minuteAt(1, 5), snaps(health(snap(2))), nil, false, modeOff)
	want := []*nodev1.MemberMinute{
		{ChainId: "c1", MemberKey: "m1", Status: "down", ExitIp: "203.0.113.50"},
		{ChainId: "c1", MemberKey: "m2", Status: "up", LatencyMs: 30, ExitIp: "198.51.100.5"},
	}
	if len(b.GetMembers()) != len(want) {
		t.Fatalf("members = %v", b.GetMembers())
	}
	for i := range want {
		if !proto.Equal(b.GetMembers()[i], want[i]) {
			t.Errorf("member %d = %v, want %v", i, b.GetMembers()[i], want[i])
		}
	}
}

// Probe results go into the open minute (the first one when none is open
// yet), at most 1,000 a minute.
func TestStatsCollectorProbes(t *testing.T) {
	clock := newTestClock()
	buf := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	c := &statsCollector{source: &fakeSnapshots{}, agg: newAggregator(), journal: newJournal(buf, discardLog(), clock.Now),
		proc: fstest.MapFS{}, mode: func() ipMode { return modeOff }, log: discardLog()}
	c.addProbe(&nodev1.ProbeResult{ProxyId: "early", Kind: "l2", Ok: true})
	c.tick(context.Background(), minuteAt(0, 5))
	for i := range maxMinuteProbes + 5 {
		c.addProbe(&nodev1.ProbeResult{ProxyId: fmt.Sprint("p", i), Kind: "l2", AtUnix: minuteAt(0, 6).Unix()})
	}
	c.tick(context.Background(), minuteAt(1, 5))
	c.addProbe(&nodev1.ProbeResult{ProxyId: "next", Kind: "l2"})
	c.tick(context.Background(), minuteAt(2, 5))
	recs, err := buf.After(0, 10)
	if err != nil || len(recs) != 2 {
		t.Fatalf("records = %v, %v", recs, err)
	}
	first := recs[0].GetStats().GetProbes()
	if len(first) != maxMinuteProbes || first[0].GetProxyId() != "early" || first[1].GetProxyId() != "p0" {
		t.Errorf("first minute: %d probes, starting %v", len(first), first[:min(2, len(first))])
	}
	if second := recs[1].GetStats().GetProbes(); len(second) != 1 || second[0].GetProxyId() != "next" {
		t.Errorf("second minute probes = %v", second)
	}
}

// A proxy names at most 50 countries, those of the most bytes; the rest are
// summed under "".
func TestCountryMinutesCap(t *testing.T) {
	addrs := map[ipKey]uint64{}
	codes := map[string]string{}
	for i := range 60 {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		codes[ip] = fmt.Sprintf("%c%c", 'A'+i/26, 'A'+i%26)
		addrs[ipKey{"p1", ip}] = uint64(1000 + i) // the first ten have the fewest bytes
	}
	addrs[ipKey{"p1", "192.0.2.1"}] = 7 // unknown
	addrs[ipKey{"p2", "198.51.100.1"}] = 3
	out := countryMinutes(addrs, func(ip string) string { return codes[ip] })
	var p1 []*nodev1.CountryMinute
	for _, c := range out {
		if c.GetProxyId() == "p1" {
			p1 = append(p1, c)
		}
	}
	if len(p1) != maxCountries {
		t.Fatalf("p1 has %d countries, want %d", len(p1), maxCountries)
	}
	rest := p1[0]
	// 11 countries of 1000..1010 bytes and the unknown address.
	if rest.GetCountry() != "" || rest.GetIps() != 12 || rest.GetBytes() != 11*1000+55+7 {
		t.Errorf("the rest = %v", rest)
	}
	if !slices.IsSortedFunc(out, func(x, y *nodev1.CountryMinute) int {
		if x.GetProxyId() != y.GetProxyId() {
			return compareStrings(x.GetProxyId(), y.GetProxyId())
		}
		return compareStrings(x.GetCountry(), y.GetCountry())
	}) {
		t.Errorf("not sorted: %v", out)
	}
	if last := out[len(out)-1]; last.GetProxyId() != "p2" || last.GetCountry() != "AA" {
		t.Errorf("p2 = %v", last)
	}
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
