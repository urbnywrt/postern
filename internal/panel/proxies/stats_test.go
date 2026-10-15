package proxies

import (
	"maps"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestProxyLive(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	live := func() *panelv1.ProxyLiveResponse {
		t.Helper()
		resp, err := e.stats.ProxyLive(e.ctx, connect.NewRequest(&panelv1.ProxyLiveRequest{ProxyId: p.GetId()}))
		if err != nil {
			t.Fatalf("ProxyLive: %v", err)
		}
		return resp.Msg
	}
	if got := live(); got.GetMinute() != nil || got.GetStatus().GetPhase() != "unknown" {
		t.Errorf("ProxyLive before any report = %v", got)
	}

	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	pm := &nodev1.ProxyMinute{ProxyId: p.GetId(), Up: 100, Down: 200, ConnsNew: 3, ConnsPeak: 4, Devices: 5, ConnsActive: 6}
	e.ingestRec(n.ID, statsRec(1, minute, []*nodev1.ProxyMinute{pm}, nil))
	want := &panelv1.LiveMinute{MinuteUnix: minute.Unix(), Up: 100, Down: 200, ConnsNew: 3, ConnsPeak: 4, Devices: 5, ConnsActive: 6}
	if got := live().GetMinute(); !proto.Equal(got, want) {
		t.Errorf("minute = %v, want %v", got, want)
	}

	// An older minute, delivered late, does not replace the latest one.
	e.ingestRec(n.ID, statsRec(2, minute.Add(-5*time.Minute), []*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 1}}, nil))
	if got := live().GetMinute(); !proto.Equal(got, want) {
		t.Errorf("minute after a late one = %v, want %v", got, want)
	}
	e.ingestRec(n.ID, statsRec(3, minute.Add(time.Minute), []*nodev1.ProxyMinute{{ProxyId: p.GetId(), Up: 7, ConnsActive: 1}}, nil))
	if got := live().GetMinute(); got.GetMinuteUnix() != minute.Add(time.Minute).Unix() || got.GetUp() != 7 || got.GetConnsActive() != 1 {
		t.Errorf("minute after a newer one = %v", got)
	}

	_, err := e.stats.ProxyLive(e.ctx, connect.NewRequest(&panelv1.ProxyLiveRequest{ProxyId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestProxySeries(t *testing.T) {
	e := newEnv(t)
	n, p, _, _ := e.twoNodes()
	now := time.Now().UTC()
	for i, m := range []time.Time{now.Add(-10 * time.Minute), now.Add(-5 * time.Minute), now.Add(-3 * time.Hour)} {
		e.ingestRec(n.ID, statsRec(uint64(i+1), m.Truncate(time.Minute), []*nodev1.ProxyMinute{
			{ProxyId: p.GetId(), Up: uint64(10 * (i + 1)), Down: 1, ConnsNew: 1, ConnsPeak: uint32(i + 1), Devices: 1},
		}, nil))
	}
	if err := e.db.RollupStats(e.ctx, now, store.DefaultStatsSettings().Retention()); err != nil {
		t.Fatal(err)
	}

	series := func(r string) *panelv1.ProxySeriesResponse {
		t.Helper()
		resp, err := e.stats.ProxySeries(e.ctx, connect.NewRequest(&panelv1.ProxySeriesRequest{ProxyId: p.GetId(), Range: r}))
		if err != nil {
			t.Fatalf("ProxySeries(%q): %v", r, err)
		}
		return resp.Msg
	}

	for _, tc := range []struct {
		rng    string
		span   time.Duration
		step   uint32
		points int
	}{
		{"1h", time.Hour, 60, 2},
		{"24h", 24 * time.Hour, 60, 3},
		{"", 24 * time.Hour, 60, 3},
	} {
		got := series(tc.rng)
		if got.GetStepSeconds() != tc.step || len(got.GetPoints()) != tc.points {
			t.Errorf("range %q: step %d and %d points, want %d and %d", tc.rng, got.GetStepSeconds(), len(got.GetPoints()), tc.step, tc.points)
		}
		if span := got.GetToUnix() - got.GetFromUnix(); span != int64(tc.span/time.Second) {
			t.Errorf("range %q spans %d s, want %v", tc.rng, span, tc.span)
		}
		if got.GetToUnix() < now.Unix() || got.GetToUnix()%int64(tc.step) != 0 {
			t.Errorf("range %q ends at %d: not at the end of the current period (now %d)", tc.rng, got.GetToUnix(), now.Unix())
		}
		pts := got.GetPoints()
		for i := 1; i < len(pts); i++ {
			if pts[i].GetTsUnix() <= pts[i-1].GetTsUnix() {
				t.Errorf("range %q: points are not oldest first", tc.rng)
			}
		}
	}
	last := series("1h").GetPoints()[1]
	if want := (&panelv1.SeriesPoint{TsUnix: now.Add(-5 * time.Minute).Truncate(time.Minute).Unix(), Up: 20, Down: 1, ConnsNew: 1, ConnsPeak: 2, Devices: 1}); !proto.Equal(last, want) {
		t.Errorf("latest point = %v, want %v", last, want)
	}

	// Hours for the long ranges: the hour of three hours ago is rolled up.
	for _, rng := range []string{"7d", "30d"} {
		got := series(rng)
		if got.GetStepSeconds() != 3600 {
			t.Errorf("range %s: step %d, want 3600", rng, got.GetStepSeconds())
		}
		hour := now.Add(-3 * time.Hour).Truncate(time.Hour).Unix()
		found := false
		for _, pt := range got.GetPoints() {
			if pt.GetTsUnix() == hour {
				found = true
				if pt.GetUp() != 30 {
					t.Errorf("range %s: the hour has up %d, want 30", rng, pt.GetUp())
				}
			}
		}
		if !found {
			t.Errorf("range %s: no point for the hour of three hours ago in %v", rng, got.GetPoints())
		}
	}

	// Days beyond the hours that are kept: 90 days fit the default 90 days of
	// hours, a year does not.
	for _, tc := range []struct {
		rng  string
		span time.Duration
		step uint32
	}{{"90d", 90 * 24 * time.Hour, 3600}, {"1y", 365 * 24 * time.Hour, 86400}} {
		got := series(tc.rng)
		if got.GetStepSeconds() != tc.step || got.GetToUnix()-got.GetFromUnix() != int64(tc.span/time.Second) ||
			got.GetToUnix()%int64(tc.step) != 0 || got.GetToUnix() < now.Unix() {
			t.Errorf("range %s: step %d over [%d, %d), want step %d over %v", tc.rng, got.GetStepSeconds(),
				got.GetFromUnix(), got.GetToUnix(), tc.step, tc.span)
		}
	}
	// The day of a year's series is made of the hours that are rolled up.
	if pts := series("1y").GetPoints(); len(pts) == 0 || pts[len(pts)-1].GetUp() == 0 {
		t.Errorf("range 1y: points %v, want the hours of today summed into a day", pts)
	}

	// A shorter retention of minutes switches a day's series to hours.
	short := store.DefaultStatsSettings()
	short.MinutesHours = 6
	if _, err := e.db.ApplyStatsSettings(e.ctx, short); err != nil {
		t.Fatal(err)
	}
	if got := series("24h"); got.GetStepSeconds() != 3600 || got.GetToUnix()%3600 != 0 {
		t.Errorf("range 24h with 6 hours of minutes: step %d, to %d; want hours", got.GetStepSeconds(), got.GetToUnix())
	}
	if got := series("1h"); got.GetStepSeconds() != 60 {
		t.Errorf("range 1h with 6 hours of minutes: step %d, want 60", got.GetStepSeconds())
	}

	_, err := e.stats.ProxySeries(e.ctx, connect.NewRequest(&panelv1.ProxySeriesRequest{ProxyId: p.GetId(), Range: "2w"}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.stats.ProxySeries(e.ctx, connect.NewRequest(&panelv1.ProxySeriesRequest{ProxyId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestPhaseCounts(t *testing.T) {
	e := newEnv(t)
	n, p, other, otherProxy := e.twoNodes()
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443})
	q := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	if got := e.ingest.PhaseCounts(n.ID, nil); len(got) != 0 {
		t.Errorf("PhaseCounts before any report = %v, want none", got)
	}
	now := time.Now()
	e.ingestRec(n.ID, stateRec(1, now,
		&nodev1.ProxyStatus{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING},
		&nodev1.ProxyStatus{ProxyId: q.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED}))
	e.ingestRec(other.ID, stateRec(1, now,
		&nodev1.ProxyStatus{ProxyId: otherProxy.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING}))
	if got, want := e.ingest.PhaseCounts(n.ID, nil), map[string]int{"serving": 1, "failed": 1}; !maps.Equal(got, want) {
		t.Errorf("PhaseCounts = %v, want %v", got, want)
	}
	if got := (*Ingestor)(nil).PhaseCounts(n.ID, nil); len(got) != 0 {
		t.Errorf("PhaseCounts of no ingestor = %v", got)
	}
}
