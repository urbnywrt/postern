package proxies

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// count runs a query that counts rows, on a connection of its own.
func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%q: %v", query, err)
	}
	return n
}

// insightsBatch is a batch of a minute with one of everything of slice 6 for
// the proxy p, and the same for the proxy of another node, foreign.
func insightsBatch(seq uint64, minute time.Time, p, foreign string) *nodev1.WatchResponse {
	at := minute.Add(30 * time.Second).Unix()
	return &nodev1.WatchResponse{Seq: seq, TsUnix: minute.Unix() + 61, Payload: &nodev1.WatchResponse_Stats{Stats: &nodev1.StatsBatch{
		MinuteUnix: minute.Unix(),
		Proxies:    []*nodev1.ProxyMinute{{ProxyId: p, Up: 10, Down: 20}},
		Node:       &nodev1.NodeMinute{NetRx: 5, RefusedPrehello: 3, RefusedTotal: 4, EvictedPrehello: 2},
		Countries: []*nodev1.CountryMinute{
			{ProxyId: p, Country: "DE", Ips: 2, Bytes: 100},
			{ProxyId: foreign, Country: "FR", Ips: 1, Bytes: 50},
		},
		Members: []*nodev1.MemberMinute{{ChainId: "c1", MemberKey: "m1", Status: "up", LatencyMs: 40, ExitIp: "203.0.113.9"}},
		Ips: []*nodev1.IpSighting{
			{ProxyId: p, Ip: "192.0.2.7", FirstSeen: at, LastSeen: at, Bytes: 70},
			{ProxyId: foreign, Ip: "192.0.2.8", FirstSeen: at, LastSeen: at, Bytes: 70},
			{ProxyId: p, Ip: "not an address", FirstSeen: at, LastSeen: at, Bytes: 70},
		},
		Probes: []*nodev1.ProbeResult{
			{ProxyId: p, Kind: "l2", Ok: false, LatencyMs: 9, Error: strings.Repeat("x", 300), AtUnix: at},
			{ProxyId: p, Kind: "l1", Ok: true, AtUnix: at},
			{ProxyId: foreign, Kind: "l2", Ok: true, AtUnix: at},
		},
	}}}
}

func TestIngestInsightsByPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy               string
		countries, sightings int
	}{
		{store.IPPolicyFull, 1, 1},
		{store.IPPolicyCountries, 1, 0},
		{store.IPPolicyOff, 0, 0},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			e := newEnv(t)
			n, p, _, foreign := e.twoNodes()
			e.applyStats(tc.policy, 7)
			var looked []netip.Addr
			e.ingest.SetGeoIP(GeoIP{Country: func(a netip.Addr) string { looked = append(looked, a); return "NL" }})
			minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
			rec := insightsBatch(5, minute, p.GetId(), foreign.GetId())
			e.ingestRec(n.ID, rec)
			// Delivered twice, as after a reconnect: nothing doubles.
			e.ingestRec(n.ID, proto.Clone(rec).(*nodev1.WatchResponse))

			if got := e.count(`SELECT count(*) FROM stats_country_1m`); got != tc.countries {
				t.Errorf("country minutes = %d, want %d (the foreign proxy's dropped)", got, tc.countries)
			}
			if got := e.count(`SELECT count(*) FROM ip_sightings WHERE proxy_id = ? AND ip = '192.0.2.7' AND country = 'NL' AND bytes = 70`, p.GetId()); got != tc.sightings {
				t.Errorf("sightings of the proxy = %d, want %d, with the country of the panel and the bytes once", got, tc.sightings)
			}
			if got := e.count(`SELECT count(*) FROM ip_sightings`); got != tc.sightings {
				t.Errorf("sightings = %d, want %d", got, tc.sightings)
			}
			if tc.policy != store.IPPolicyFull && len(looked) != 0 {
				t.Errorf("addresses were looked up under %s: %v", tc.policy, looked)
			}
			if got := e.count(`SELECT count(*) FROM egress_health_1m WHERE node_id = ? AND chain_id = 'c1' AND status = 'up'`, n.ID); got != 1 {
				t.Errorf("member minutes = %d, want 1", got)
			}
			if got := e.count(`SELECT count(*) FROM stats_node_1m WHERE node_id = ? AND refused_prehello = 3 AND refused_total = 4 AND evicted_prehello = 2`, n.ID); got != 1 {
				t.Errorf("node minutes with the refusals = %d, want 1", got)
			}
			if got := e.count(`SELECT count(*) FROM probes`); got != 1 {
				t.Errorf("probes = %d, want 1 (l1 and the foreign proxy's dropped)", got)
			}
			if got := e.count(`SELECT count(*) FROM probes WHERE proxy_id = ? AND vantage = 'node' AND kind = 'l2' AND ok = 0 AND length(error) = 256 AND ts = ?`,
				p.GetId(), minute.Add(30*time.Second).Unix()); got != 1 {
				t.Errorf("the probe is not stored as node l2, failed, with its error clipped to 256 bytes at its time")
			}
		})
	}
}

func TestIngestInsightsCaps(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	// More member minutes than are taken: 2,000 of them are.
	var members []*nodev1.MemberMinute
	for i := range maxStatsMembers + 5 {
		members = append(members, &nodev1.MemberMinute{ChainId: "c", MemberKey: "m" + string(rune('a'+i%26)) + strings.Repeat("x", i/26), Status: "up"})
	}
	// Countries beyond the cap are not looked at: the one after it is not stored.
	countries := make([]*nodev1.CountryMinute, maxStatsCountries+1)
	for i := range countries {
		countries[i] = &nodev1.CountryMinute{ProxyId: "gone", Country: "DE", Ips: 1}
	}
	countries[maxStatsCountries] = &nodev1.CountryMinute{ProxyId: p.GetId(), Country: "DE", Ips: 1}
	e.ingestRec(n.ID, &nodev1.WatchResponse{Seq: 1, Payload: &nodev1.WatchResponse_Stats{Stats: &nodev1.StatsBatch{
		MinuteUnix: minute.Unix(), Members: members, Countries: countries,
		Probes: []*nodev1.ProbeResult{{ProxyId: p.GetId(), Kind: "web", Ok: true, AtUnix: 1}}, // a time that cannot be: the minute
	}}})
	if got := e.count(`SELECT count(*) FROM egress_health_1m`); got != maxStatsMembers {
		t.Errorf("member minutes = %d, want %d", got, maxStatsMembers)
	}
	if got := e.count(`SELECT count(*) FROM stats_country_1m`); got != 0 {
		t.Errorf("a country past the cap was stored")
	}
	if got := e.count(`SELECT count(*) FROM probes WHERE kind = 'web' AND ts = ? AND error = ''`, minute.Unix()); got != 1 {
		t.Errorf("the web probe is not stored at the minute of the batch")
	}
}

func TestIngestDiagnosticsHook(t *testing.T) {
	e := newEnv(t)
	n, _, _, _ := e.twoNodes()
	ts := time.Now().Add(-time.Minute).Truncate(time.Second)
	rep := &nodev1.DiagnosticsReport{Results: []*nodev1.DiagnosticResult{{Id: "host.docker", Status: nodev1.CheckStatus_CHECK_STATUS_OK}}}
	rec := &nodev1.WatchResponse{Seq: 3, TsUnix: ts.Unix(), Payload: &nodev1.WatchResponse_Diagnostics{Diagnostics: rep}}

	// None set: ignored.
	e.ingestRec(n.ID, rec)

	var gotNode string
	var gotAt time.Time
	var got *nodev1.DiagnosticsReport
	boom := errors.New("boom")
	fail := false
	e.ingest.OnDiagnostics(func(_ context.Context, nodeID string, at time.Time, r *nodev1.DiagnosticsReport) error {
		gotNode, gotAt, got = nodeID, at, r
		if fail {
			return boom
		}
		return nil
	})
	e.ingestRec(n.ID, rec)
	if gotNode != n.ID || !gotAt.Equal(ts) || !proto.Equal(got, rep) {
		t.Errorf("hook got (%s, %v, %v), want (%s, %v, %v)", gotNode, gotAt, got, n.ID, ts, rep)
	}
	fail = true
	if err := e.ingest.OnWatch(e.ctx, n.ID, rec); !errors.Is(err, boom) {
		t.Errorf("the error of the hook = %v, want it returned, so that the record is offered again", err)
	}
}

func TestIngestServingChangeHook(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	type call struct {
		node, proxy string
		from, to    uint64
	}
	var calls []call
	e.ingest.OnServingChange(func(nodeID, proxyID string, from, to uint64) {
		calls = append(calls, call{nodeID, proxyID, from, to})
	})
	ts := time.Now()
	report := func(seq uint64, phase nodev1.ProxyPhase, gen uint64) {
		e.ingestRec(n.ID, stateRec(seq, ts, &nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: phase, InstanceGeneration: gen}))
	}
	report(1, nodev1.ProxyPhase_PROXY_PHASE_SERVING, 3) // the first one the panel sees: nothing
	report(2, nodev1.ProxyPhase_PROXY_PHASE_SERVING, 3) // the same
	report(3, nodev1.ProxyPhase_PROXY_PHASE_STARTING, 4)
	report(4, nodev1.ProxyPhase_PROXY_PHASE_SERVING, 4) // moved to 4
	report(5, nodev1.ProxyPhase_PROXY_PHASE_SERVING, 4)
	want := []call{{n.ID, p.GetId(), 3, 4}}
	if len(calls) != len(want) || calls[0] != want[0] {
		t.Errorf("calls = %+v, want %+v", calls, want)
	}
	e.ingest.ForgetNode(n.ID)
	report(6, nodev1.ProxyPhase_PROXY_PHASE_SERVING, 5) // forgotten: the first again
	if len(calls) != 1 {
		t.Errorf("a forgotten node made calls %+v", calls[1:])
	}
}
