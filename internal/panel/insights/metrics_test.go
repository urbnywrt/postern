package insights

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// phases is a PhaseCounter of fixed phases: by node, the phase of each proxy.
type phases map[string]map[string]string

func (p phases) PhaseCounts(nodeID string, known func(proxyID string) bool) map[string]int {
	out := map[string]int{}
	for id, phase := range p[nodeID] {
		if known == nil || known(id) {
			out[phase]++
		}
	}
	return out
}

// A metricsEnv is the MetricsService on the database of an env, at a fixed
// time, with a client that has signed in and one that has not.
type metricsEnv struct {
	*env
	now    time.Time
	phases phases
	month  string
	m      *MetricsService
	api    panelv1connect.MetricsServiceClient
	anon   panelv1connect.MetricsServiceClient
}

func newMetricsEnv(t *testing.T) *metricsEnv {
	t.Helper()
	e := &metricsEnv{env: newEnv(t), now: time.Now().UTC().Truncate(time.Minute), phases: phases{}, month: "2026-09"}
	e.m = NewMetricsService(e.db, e.phases, func() string { return e.month }, nil)
	e.m.now = func() time.Time { return e.now }

	var key seal.Key
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(e.db, key, nil)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewMetricsServiceHandler(e.m))
	srv := httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	login := panelv1connect.NewAuthServiceClient(web, srv.URL)
	if _, err := login.Login(e.ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	e.api = panelv1connect.NewMetricsServiceClient(web, srv.URL)
	e.anon = panelv1connect.NewMetricsServiceClient(&http.Client{Timeout: 30 * time.Second}, srv.URL)
	return e
}

// proxy stores a proxy of a node on a listener of its own.
func (e *metricsEnv) proxy(n *store.Node, name string, port uint32, enabled bool) *store.Proxy {
	e.t.Helper()
	l := &store.Listener{NodeID: n.ID, Port: port}
	if err := e.db.CreateListener(e.ctx, l); err != nil {
		e.t.Fatalf("CreateListener: %v", err)
	}
	p := &store.Proxy{NodeID: n.ID, ListenerID: l.ID, Name: name, Enabled: enabled, SecretEnc: []byte("sealed")}
	if err := e.db.CreateProxy(e.ctx, p); err != nil {
		e.t.Fatalf("CreateProxy: %v", err)
	}
	return p
}

// ingest stores a minute of a node.
func (e *metricsEnv) ingest(b store.MinuteBatch) {
	e.t.Helper()
	if _, err := e.db.IngestMinute(e.ctx, b); err != nil {
		e.t.Fatalf("IngestMinute: %v", err)
	}
}

// rollup makes the hours and days of the minutes, at the time of the env.
func (e *metricsEnv) rollup() {
	e.t.Helper()
	s, _, err := e.db.StatsSettings(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.RollupStats(e.ctx, e.now, s.Retention()); err != nil {
		e.t.Fatalf("RollupStats: %v", err)
	}
}

func (e *metricsEnv) policy(p string) {
	e.t.Helper()
	s, _, err := e.db.StatsSettings(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	s.IPPolicy = p
	if _, err := e.db.ApplyStatsSettings(e.ctx, s); err != nil {
		e.t.Fatalf("ApplyStatsSettings: %v", err)
	}
}

func wantCode(t *testing.T, err error, code connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != code {
		t.Errorf("error %v, want code %v", err, code)
	}
}

func TestMetricsRefuseCallsWithoutASession(t *testing.T) {
	e := newMetricsEnv(t)
	ctx := e.ctx
	for name, call := range map[string]func() error{
		"Overview": func() error {
			_, err := e.anon.Overview(ctx, connect.NewRequest(&panelv1.OverviewRequest{}))
			return err
		},
		"NodeSeries": func() error {
			_, err := e.anon.NodeSeries(ctx, connect.NewRequest(&panelv1.NodeSeriesRequest{}))
			return err
		},
		"TopProxies": func() error {
			_, err := e.anon.TopProxies(ctx, connect.NewRequest(&panelv1.TopProxiesRequest{}))
			return err
		},
		"Countries": func() error {
			_, err := e.anon.Countries(ctx, connect.NewRequest(&panelv1.CountriesRequest{}))
			return err
		},
		"ListIpSightings": func() error {
			_, err := e.anon.ListIpSightings(ctx, connect.NewRequest(&panelv1.ListIpSightingsRequest{}))
			return err
		},
		"EgressHistory": func() error {
			_, err := e.anon.EgressHistory(ctx, connect.NewRequest(&panelv1.EgressHistoryRequest{}))
			return err
		},
	} {
		if err := call(); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s without a session: %v, want unauthenticated", name, err)
		}
	}
	// The service itself refuses a context without an admin, too.
	_, err := e.m.Overview(ctx, connect.NewRequest(&panelv1.OverviewRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
}

func TestOverview(t *testing.T) {
	e := newMetricsEnv(t)
	a, b, quiet := e.node("b-node", nil), e.node("a-node", nil), e.node("c-quiet", nil)
	p1, p2 := e.proxy(a, "p1", 443, true), e.proxy(a, "p2", 8443, false)
	p3 := e.proxy(b, "p3", 443, true)
	_ = e.proxy(a, "p4", 9443, false)
	// paused is the disabled proxies, not the phase; a proxy that the store no
	// longer knows (deleted since the node reported it) is not counted.
	e.phases[a.ID] = map[string]string{p1.ID: "serving", p2.ID: "failed", "p-deleted": "serving", "p-deleted-2": "paused"}

	m := e.now.Add(-2 * time.Minute)
	e.ingest(store.MinuteBatch{NodeID: a.ID, Minute: m,
		Proxies: []store.ProxyStat{{ProxyID: p1.ID, Up: 10, Down: 20}, {ProxyID: p2.ID, Up: 1, Down: 2}},
		Node:    &store.NodeStat{CPU: 12.5, MemUsed: 100, MemTotal: 400, Load1: 0.5, DiskUsed: 7, DiskTotal: 70, Conns: 9}})
	// A minute older than 3 minutes is not the latest of b; its traffic counts.
	e.ingest(store.MinuteBatch{NodeID: b.ID, Minute: e.now.Add(-10 * time.Minute),
		Proxies: []store.ProxyStat{{ProxyID: p3.ID, Up: 5, Down: 6}}, Node: &store.NodeStat{CPU: 99}})
	// Before since: not counted.
	e.ingest(store.MinuteBatch{NodeID: a.ID, Minute: e.now.Add(-50 * time.Minute),
		Proxies: []store.ProxyStat{{ProxyID: p1.ID, Up: 1000}}})

	since := e.now.Add(-30 * time.Minute)
	resp, err := e.api.Overview(e.ctx, connect.NewRequest(&panelv1.OverviewRequest{SinceUnix: since.Unix()}))
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	got := resp.Msg
	if got.GetSinceUnix() != since.Unix() || got.GetNowUnix() != e.now.Unix() {
		t.Errorf("since %d, now %d; want %d, %d", got.GetSinceUnix(), got.GetNowUnix(), since.Unix(), e.now.Unix())
	}
	want := []*panelv1.NodeOverview{
		{NodeId: b.ID, Up: 5, Down: 6, Proxies: 1},
		{NodeId: a.ID, MinuteUnix: m.Unix(), Cpu: 12.5, MemUsed: 100, MemTotal: 400, Load1: 0.5, DiskUsed: 7, DiskTotal: 70,
			Conns: 9, Up: 11, Down: 22, Proxies: 3, Serving: 1, Failed: 1, Paused: 2},
		{NodeId: quiet.ID},
	}
	if len(got.GetNodes()) != len(want) {
		t.Fatalf("nodes = %v", got.GetNodes())
	}
	for i := range want {
		if !proto.Equal(got.GetNodes()[i], want[i]) {
			t.Errorf("node %d = %v, want %v", i, got.GetNodes()[i], want[i])
		}
	}

	// 0 is the last 24 hours.
	resp, err = e.api.Overview(e.ctx, connect.NewRequest(&panelv1.OverviewRequest{}))
	if err != nil || resp.Msg.GetSinceUnix() != e.now.Add(-24*time.Hour).Unix() || resp.Msg.GetNodes()[1].GetUp() != 1011 {
		t.Errorf("Overview(0) = %v, %v", resp.Msg, err)
	}
	for _, s := range []time.Time{e.now.Add(time.Minute), e.now.Add(-367 * 24 * time.Hour)} {
		_, err = e.api.Overview(e.ctx, connect.NewRequest(&panelv1.OverviewRequest{SinceUnix: s.Unix()}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
}

func TestNodeSeries(t *testing.T) {
	e := newMetricsEnv(t)
	n, other := e.node("n", nil), e.node("o", nil)
	p, q := e.proxy(n, "p", 443, true), e.proxy(n, "q", 8443, true)
	r := e.proxy(other, "r", 443, true)

	m1, m2 := e.now.Add(-5*time.Minute), e.now.Add(-3*time.Minute)
	e.ingest(store.MinuteBatch{NodeID: n.ID, Minute: m1,
		Proxies: []store.ProxyStat{{ProxyID: p.ID, Up: 1, Down: 2, Devices: 3}, {ProxyID: q.ID, Up: 10, Down: 20, Devices: 4}},
		Node: &store.NodeStat{CPU: 50, MemUsed: 1, MemTotal: 2, Load1: 1.5, DiskUsed: 3, DiskTotal: 4, NetRx: 5, NetTx: 6, Conns: 7,
			RefusedPreHello: 8, RefusedTotal: 9, EvictedPreHello: 10}})
	// A minute with traffic and no load, and the traffic of another node.
	e.ingest(store.MinuteBatch{NodeID: n.ID, Minute: m2, Proxies: []store.ProxyStat{{ProxyID: p.ID, Up: 100, Devices: 1}}})
	e.ingest(store.MinuteBatch{NodeID: other.ID, Minute: m1, Proxies: []store.ProxyStat{{ProxyID: r.ID, Up: 5000, Devices: 50}}})

	series := func(rng string) *panelv1.NodeSeriesResponse {
		t.Helper()
		resp, err := e.api.NodeSeries(e.ctx, connect.NewRequest(&panelv1.NodeSeriesRequest{NodeId: n.ID, Range: rng}))
		if err != nil {
			t.Fatalf("NodeSeries(%q): %v", rng, err)
		}
		return resp.Msg
	}
	got := series("1h")
	if got.GetStepSeconds() != 60 || got.GetToUnix() != e.now.Add(time.Minute).Unix() || got.GetFromUnix() != got.GetToUnix()-3600 {
		t.Errorf("1h: step %d over [%d, %d)", got.GetStepSeconds(), got.GetFromUnix(), got.GetToUnix())
	}
	want := []*panelv1.NodePoint{
		{TsUnix: m1.Unix(), Cpu: 50, MemUsed: 1, MemTotal: 2, Load1: 1.5, DiskUsed: 3, DiskTotal: 4, NetRx: 5, NetTx: 6, Conns: 7,
			RefusedPrehello: 8, RefusedTotal: 9, EvictedPrehello: 10, Up: 11, Down: 22, DevicesSum: 7},
		{TsUnix: m2.Unix(), Up: 100, DevicesSum: 1},
	}
	if len(got.GetPoints()) != len(want) {
		t.Fatalf("1h: points %v", got.GetPoints())
	}
	for i := range want {
		if !proto.Equal(got.GetPoints()[i], want[i]) {
			t.Errorf("1h: point %d = %v, want %v", i, got.GetPoints()[i], want[i])
		}
	}

	// The resolution follows the retention: 24 hours are minutes by default,
	// hours with 6 hours of minutes; a year is days.
	for _, tc := range []struct {
		rng          string
		minutesHours uint32
		step         uint32
	}{{"24h", 48, 60}, {"7d", 48, 3600}, {"90d", 48, 3600}, {"1y", 48, 86400}, {"24h", 6, 3600}, {"1h", 6, 60}} {
		s, _, err := e.db.StatsSettings(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		s.MinutesHours = tc.minutesHours
		if _, err := e.db.ApplyStatsSettings(e.ctx, s); err != nil {
			t.Fatal(err)
		}
		got := series(tc.rng)
		if got.GetStepSeconds() != tc.step || got.GetToUnix()%int64(tc.step) != 0 || got.GetToUnix() <= e.now.Unix() {
			t.Errorf("%s with %d hours of minutes: step %d, to %d; want step %d", tc.rng, tc.minutesHours,
				got.GetStepSeconds(), got.GetToUnix(), tc.step)
		}
	}

	for _, rng := range []string{"2w", "1d", "365d"} {
		_, err := e.api.NodeSeries(e.ctx, connect.NewRequest(&panelv1.NodeSeriesRequest{NodeId: n.ID, Range: rng}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	_, err := e.api.NodeSeries(e.ctx, connect.NewRequest(&panelv1.NodeSeriesRequest{NodeId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestNodeSeriesOfHoursMergesTheTrafficOfTheHour(t *testing.T) {
	e := newMetricsEnv(t)
	n := e.node("n", nil)
	p, q := e.proxy(n, "p", 443, true), e.proxy(n, "q", 8443, true)
	hour := e.now.Truncate(time.Hour).Add(-2 * time.Hour)
	for i := range 2 {
		e.ingest(store.MinuteBatch{NodeID: n.ID, Minute: hour.Add(time.Duration(i) * time.Minute),
			Proxies: []store.ProxyStat{{ProxyID: p.ID, Up: 1, Devices: uint32(2 + i)}, {ProxyID: q.ID, Down: 4, Devices: 5}},
			Node:    &store.NodeStat{CPU: float64(10 * (i + 1)), Conns: uint32(i)}})
	}
	e.rollup()
	resp, err := e.api.NodeSeries(e.ctx, connect.NewRequest(&panelv1.NodeSeriesRequest{NodeId: n.ID, Range: "7d"}))
	if err != nil {
		t.Fatal(err)
	}
	pts := resp.Msg.GetPoints()
	if len(pts) != 1 {
		t.Fatalf("points %v, want the one hour", pts)
	}
	// devices_sum is the sum of each proxy's highest minute: 3 + 5.
	if want := (&panelv1.NodePoint{TsUnix: hour.Unix(), Cpu: 15, Conns: 1, Up: 2, Down: 8, DevicesSum: 8}); !proto.Equal(pts[0], want) {
		t.Errorf("hour = %v, want %v", pts[0], want)
	}
}

func TestTopProxies(t *testing.T) {
	e := newMetricsEnv(t)
	n, other := e.node("n", nil), e.node("o", nil)
	p, q := e.proxy(n, "busy", 443, true), e.proxy(n, "calm", 8443, true)
	r := e.proxy(other, "elsewhere", 443, true)
	m := e.now.Add(-3 * time.Minute)
	e.ingest(store.MinuteBatch{NodeID: n.ID, Minute: m, Proxies: []store.ProxyStat{
		{ProxyID: p.ID, Up: 100, Down: 100, ConnsNew: 3, Devices: 4}, {ProxyID: q.ID, Up: 1, ConnsNew: 1, Devices: 1}}})
	e.ingest(store.MinuteBatch{NodeID: other.ID, Minute: m, Proxies: []store.ProxyStat{{ProxyID: r.ID, Up: 50}}})

	top := func(req *panelv1.TopProxiesRequest) *panelv1.TopProxiesResponse {
		t.Helper()
		resp, err := e.api.TopProxies(e.ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatalf("TopProxies(%v): %v", req, err)
		}
		return resp.Msg
	}
	got := top(&panelv1.TopProxiesRequest{Range: "24h"})
	want := []*panelv1.ProxyTotal{
		{ProxyId: p.ID, Name: "busy", NodeId: n.ID, Up: 100, Down: 100, ConnsNew: 3, DevicesPeak: 4},
		{ProxyId: r.ID, Name: "elsewhere", NodeId: other.ID, Up: 50},
		{ProxyId: q.ID, Name: "calm", NodeId: n.ID, Up: 1, ConnsNew: 1, DevicesPeak: 1},
	}
	if len(got.GetProxies()) != 3 {
		t.Fatalf("proxies %v", got.GetProxies())
	}
	for i := range want {
		if !proto.Equal(got.GetProxies()[i], want[i]) {
			t.Errorf("proxy %d = %v, want %v", i, got.GetProxies()[i], want[i])
		}
	}
	if got.GetToUnix() != e.now.Unix() || got.GetFromUnix() != e.now.Add(-24*time.Hour).Unix() {
		t.Errorf("range [%d, %d)", got.GetFromUnix(), got.GetToUnix())
	}
	if got := top(&panelv1.TopProxiesRequest{NodeId: n.ID, Limit: 1}).GetProxies(); len(got) != 1 || got[0].GetProxyId() != p.ID {
		t.Errorf("the top proxy of n = %v", got)
	}
	if got := top(&panelv1.TopProxiesRequest{NodeId: other.ID, Range: "1y"}).GetProxies(); len(got) != 1 || got[0].GetProxyId() != r.ID {
		t.Errorf("the proxies of o over a year = %v", got)
	}
	_, err := e.api.TopProxies(e.ctx, connect.NewRequest(&panelv1.TopProxiesRequest{Limit: 51}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.api.TopProxies(e.ctx, connect.NewRequest(&panelv1.TopProxiesRequest{Range: "1m"}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.api.TopProxies(e.ctx, connect.NewRequest(&panelv1.TopProxiesRequest{NodeId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestCountries(t *testing.T) {
	e := newMetricsEnv(t)
	n, other := e.node("n", nil), e.node("o", nil)
	p, q := e.proxy(n, "p", 443, true), e.proxy(n, "q", 8443, true)
	r := e.proxy(other, "r", 443, true)
	m := e.now.Add(-3 * time.Minute)
	e.ingest(store.MinuteBatch{NodeID: n.ID, Minute: m, Proxies: []store.ProxyStat{{ProxyID: p.ID}, {ProxyID: q.ID}},
		Countries: []store.CountryStat{
			{ProxyID: p.ID, Country: "DE", IPs: 2, Bytes: 100}, {ProxyID: q.ID, Country: "DE", IPs: 3, Bytes: 50},
			{ProxyID: q.ID, Country: "NL", IPs: 1, Bytes: 500}}})
	e.ingest(store.MinuteBatch{NodeID: other.ID, Minute: m, Proxies: []store.ProxyStat{{ProxyID: r.ID}},
		Countries: []store.CountryStat{{ProxyID: r.ID, Country: "FI", IPs: 9, Bytes: 9}}})

	countries := func(req *panelv1.CountriesRequest) *panelv1.CountriesResponse {
		t.Helper()
		resp, err := e.api.Countries(e.ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatalf("Countries(%v): %v", req, err)
		}
		return resp.Msg
	}
	got := countries(&panelv1.CountriesRequest{NodeId: n.ID})
	want := &panelv1.CountriesResponse{
		Countries: []*panelv1.CountryTotal{{Country: "NL", Bytes: 500, IpsPeak: 1}, {Country: "DE", Bytes: 150, IpsPeak: 5}},
		Policy:    store.IPPolicyCountries, GeoipMonth: "2026-09",
		Attribution: geoip.Attribution, AttributionUrl: geoip.AttributionURL,
		FromUnix: e.now.Add(-24 * time.Hour).Unix(), ToUnix: e.now.Unix(),
	}
	if !proto.Equal(got, want) {
		t.Errorf("Countries(node) = %v, want %v", got, want)
	}
	if got := countries(&panelv1.CountriesRequest{ProxyId: p.ID, Range: "7d"}).GetCountries(); len(got) != 1 || got[0].GetBytes() != 100 {
		t.Errorf("Countries(proxy) = %v", got)
	}
	if got := countries(&panelv1.CountriesRequest{Range: "1y"}).GetCountries(); len(got) != 3 {
		t.Errorf("Countries(all, 1y) = %v", got)
	}

	// Under off nothing is kept, and the policy says so.
	e.month = ""
	e.policy(store.IPPolicyOff)
	if got := countries(&panelv1.CountriesRequest{}); len(got.GetCountries()) != 0 || got.GetPolicy() != store.IPPolicyOff ||
		got.GetGeoipMonth() != "" || got.GetAttribution() != geoip.Attribution {
		t.Errorf("Countries under off = %v", got)
	}

	_, err := e.api.Countries(e.ctx, connect.NewRequest(&panelv1.CountriesRequest{ProxyId: p.ID, NodeId: n.ID}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.api.Countries(e.ctx, connect.NewRequest(&panelv1.CountriesRequest{Range: "5y"}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.api.Countries(e.ctx, connect.NewRequest(&panelv1.CountriesRequest{ProxyId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = e.api.Countries(e.ctx, connect.NewRequest(&panelv1.CountriesRequest{NodeId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestListIpSightings(t *testing.T) {
	e := newMetricsEnv(t)
	n := e.node("n", nil)
	p, q := e.proxy(n, "p", 443, true), e.proxy(n, "q", 8443, true)
	list := func(req *panelv1.ListIpSightingsRequest) (*panelv1.ListIpSightingsResponse, error) {
		resp, err := e.api.ListIpSightings(e.ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	// The default policy, countries, keeps no address: refused.
	_, err := list(&panelv1.ListIpSightingsRequest{ProxyId: p.ID})
	wantCode(t, err, connect.CodeFailedPrecondition)
	if ce := new(connect.Error); !errors.As(err, &ce) || ce.Message() != "the IP policy keeps no addresses" {
		t.Errorf("refusal = %v", err)
	}

	e.policy(store.IPPolicyFull)
	m := e.now.Add(-3 * time.Minute)
	e.ingest(store.MinuteBatch{NodeID: n.ID, Minute: m, Sightings: []store.Sighting{
		{ProxyID: p.ID, IP: "192.0.2.1", Country: "DE", FirstSeen: m.Add(-time.Hour), LastSeen: m, Bytes: 10},
		{ProxyID: p.ID, IP: "192.0.2.2", Country: "NL", FirstSeen: m, LastSeen: m.Add(-time.Minute), Bytes: 20},
		{ProxyID: p.ID, IP: "2001:db8::1", Country: "DE", FirstSeen: m, LastSeen: m.Add(-2 * time.Minute), Bytes: 30},
		{ProxyID: q.ID, IP: "198.51.100.1", Country: "DE", FirstSeen: m, LastSeen: m, Bytes: 40},
	}})
	got, err := list(&panelv1.ListIpSightingsRequest{ProxyId: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetTotal() != 3 || len(got.GetSightings()) != 3 {
		t.Fatalf("sightings of p = %v", got)
	}
	if want := (&panelv1.IpSighting{Ip: "192.0.2.1", Country: "DE", FirstSeenUnix: m.Add(-time.Hour).Unix(), LastSeenUnix: m.Unix(), Bytes: 10}); !proto.Equal(got.GetSightings()[0], want) {
		t.Errorf("the one seen last = %v, want %v", got.GetSightings()[0], want)
	}
	got, err = list(&panelv1.ListIpSightingsRequest{ProxyId: p.ID, Country: "de", Limit: 1, Offset: 1})
	if err != nil || got.GetTotal() != 2 || len(got.GetSightings()) != 1 || got.GetSightings()[0].GetIp() != "2001:db8::1" {
		t.Errorf("the second of DE = %v, %v", got, err)
	}

	for _, req := range []*panelv1.ListIpSightingsRequest{
		{ProxyId: p.ID, Limit: 201}, {ProxyId: p.ID, Country: "DEU"}, {ProxyId: p.ID, Country: "1A"}, {},
	} {
		_, err := list(req)
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	_, err = list(&panelv1.ListIpSightingsRequest{ProxyId: "01K6Y00000000000000000000Z"})
	wantCode(t, err, connect.CodeNotFound)

	// Leaving full refuses again (and the store has deleted them).
	e.policy(store.IPPolicyOff)
	_, err = list(&panelv1.ListIpSightingsRequest{ProxyId: p.ID})
	wantCode(t, err, connect.CodeFailedPrecondition)
}

func TestEgressHistory(t *testing.T) {
	e := newMetricsEnv(t)
	n, other := e.node("n", nil), e.node("o", nil)
	h1 := e.now.Truncate(time.Hour).Add(-3 * time.Hour)
	h2 := h1.Add(time.Hour)
	ingest := func(node *store.Node, at time.Time, ms ...store.MemberStat) {
		e.ingest(store.MinuteBatch{NodeID: node.ID, Minute: at, Members: ms})
	}
	ingest(n, h1, store.MemberStat{ChainID: "c2", MemberKey: "a", Status: "down"},
		store.MemberStat{ChainID: "c1", MemberKey: "b", Status: "up", LatencyMS: 40, ExitIP: "203.0.113.5"})
	ingest(n, h1.Add(time.Minute), store.MemberStat{ChainID: "c1", MemberKey: "b", Status: "up", LatencyMS: 60})
	ingest(n, h2, store.MemberStat{ChainID: "c1", MemberKey: "b", Status: "unknown"})
	ingest(other, h1, store.MemberStat{ChainID: "c1", MemberKey: "b", Status: "down"})
	e.rollup()

	resp, err := e.api.EgressHistory(e.ctx, connect.NewRequest(&panelv1.EgressHistoryRequest{NodeId: n.ID}))
	if err != nil {
		t.Fatal(err)
	}
	got := resp.Msg
	want := &panelv1.EgressHistoryResponse{
		Members: []*panelv1.MemberHistory{
			{ChainId: "c1", MemberKey: "b", Hours: []*panelv1.MemberHour{
				{TsUnix: h1.Unix(), UpMinutes: 2, LatencyAvgMs: 50, LatencyMaxMs: 60, ExitIp: "203.0.113.5"},
				{TsUnix: h2.Unix(), UnknownMinutes: 1},
			}},
			{ChainId: "c2", MemberKey: "a", Hours: []*panelv1.MemberHour{{TsUnix: h1.Unix(), DownMinutes: 1}}},
		},
		FromUnix: e.now.Truncate(time.Hour).Add(time.Hour - 24*time.Hour).Unix(),
		ToUnix:   e.now.Truncate(time.Hour).Add(time.Hour).Unix(),
	}
	if !proto.Equal(got, want) {
		t.Errorf("EgressHistory = %v, want %v", got, want)
	}
	resp, err = e.api.EgressHistory(e.ctx, connect.NewRequest(&panelv1.EgressHistoryRequest{NodeId: n.ID, Range: "1h"}))
	if err != nil || len(resp.Msg.GetMembers()) != 0 {
		t.Errorf("the last hour = %v, %v; want no member (the hours are older)", resp.Msg, err)
	}

	for _, rng := range []string{"90d", "1y", "x"} {
		_, err := e.api.EgressHistory(e.ctx, connect.NewRequest(&panelv1.EgressHistoryRequest{NodeId: n.ID, Range: rng}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	_, err = e.api.EgressHistory(e.ctx, connect.NewRequest(&panelv1.EgressHistoryRequest{NodeId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}
