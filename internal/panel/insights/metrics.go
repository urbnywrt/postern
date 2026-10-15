package insights

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// The bounds of the statistics API.
const (
	// latestWithin is how recent the latest minute of a node must be for the
	// Overview to show its load: an older one is of a node that stopped
	// reporting.
	latestWithin = 3 * time.Minute
	// overviewDefault is what since_unix 0 counts from; overviewMax is the
	// furthest back that it may reach.
	overviewDefault = 24 * time.Hour
	overviewMax     = 366 * 24 * time.Hour

	topDefault, topMax             = 10, 50
	sightingsDefault, sightingsMax = 50, 200
	// egressMax is the longest range of EgressHistory: hours of the members
	// are kept for 30 days.
	egressMax = 30 * 24 * time.Hour
)

// errNoAddresses is the refusal of ListIpSightings under a policy that keeps
// no addresses.
var errNoAddresses = errors.New("the IP policy keeps no addresses")

// A PhaseCounter tells how many proxies of a node are in each phase, by the
// name of the phase in the API, of those that known holds of (all with nil):
// proxies.Ingestor.
type PhaseCounter interface {
	PhaseCounts(nodeID string, known func(proxyID string) bool) map[string]int
}

// MetricsService is the MetricsService of the panel: the statistics of the
// nodes, of the proxies taken together, of the countries, of where addresses
// were seen, and of the members of egress chains, read from the store.
type MetricsService struct {
	db       *store.DB
	phases   PhaseCounter
	geoMonth func() string
	log      *slog.Logger
	now      func() time.Time // the clock, replaced by tests
}

var _ panelv1connect.MetricsServiceHandler = (*MetricsService)(nil)

// NewMetricsService returns the service. phases (nil: no proxy counts as
// serving or failed) tells the phases of the proxies; geoMonth (nil: none)
// the month of the country database of the panel, "" while there is none. A
// nil log discards the log.
func NewMetricsService(db *store.DB, phases PhaseCounter, geoMonth func() string, log *slog.Logger) *MetricsService {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if geoMonth == nil {
		geoMonth = func() string { return "" }
	}
	return &MetricsService{db: db, phases: phases, geoMonth: geoMonth, log: log, now: time.Now}
}

func invalid(msg string) error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New(msg))
}

// readError is the error of a read of a row that the caller names: NOT_FOUND
// when it does not exist.
func (m *MetricsService) readError(what string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, errors.New(what+" not found"))
	}
	return fail(m.log, "could not read the "+what, err)
}

// settings returns the stored statistics settings.
func (m *MetricsService) settings(ctx context.Context) (store.StatsSettings, error) {
	s, _, err := m.db.StatsSettings(ctx)
	if err != nil {
		return store.StatsSettings{}, fail(m.log, "could not read the statistics settings", err)
	}
	return s, nil
}

// node checks that a node exists.
func (m *MetricsService) node(ctx context.Context, id string) error {
	if _, err := m.db.NodeByID(ctx, id); err != nil {
		return m.readError("node", err)
	}
	return nil
}

// Overview returns every node at a glance: its latest minute of the last 3
// minutes, what its proxies carried since since_unix (to the minute: the
// partial hours come from the minutes), how many proxies it has, how many of
// them it last reported serving and failed, and how many are disabled
// (paused).
func (m *MetricsService) Overview(ctx context.Context, req *connect.Request[panelv1.OverviewRequest]) (*connect.Response[panelv1.OverviewResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	now := m.now().UTC()
	since := now.Add(-overviewDefault)
	if s := req.Msg.GetSinceUnix(); s != 0 {
		since = time.Unix(s, 0).UTC()
		if since.After(now) || since.Before(now.Add(-overviewMax)) {
			return nil, invalid("since_unix must be in the last year and not in the future")
		}
	}
	nodes, err := m.db.ListNodes(ctx)
	if err != nil {
		return nil, fail(m.log, "could not list the nodes", err)
	}
	latest, err := m.db.LatestNodeMinutes(ctx, now, latestWithin)
	if err != nil {
		return nil, fail(m.log, "could not read the latest minutes of the nodes", err)
	}
	traffic, err := m.db.TrafficSince(ctx, since, now)
	if err != nil {
		return nil, fail(m.log, "could not read the traffic of the nodes", err)
	}
	all, err := m.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, fail(m.log, "could not list the proxies", err)
	}
	type counts struct{ proxies, paused uint32 }
	byNode := map[string]counts{}
	// The node may report a proxy that was deleted since: it is not counted.
	known := make(map[string]bool, len(all))
	for _, p := range all {
		known[p.ID] = true
		c := byNode[p.NodeID]
		c.proxies++
		if !p.Enabled {
			c.paused++
		}
		byNode[p.NodeID] = c
	}
	slices.SortFunc(nodes, func(a, b *store.Node) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	out := make([]*panelv1.NodeOverview, 0, len(nodes))
	for _, n := range nodes {
		o := &panelv1.NodeOverview{NodeId: n.ID, Proxies: byNode[n.ID].proxies, Paused: byNode[n.ID].paused}
		if l, ok := latest[n.ID]; ok {
			o.MinuteUnix = l.TS.Unix()
			o.Cpu, o.MemUsed, o.MemTotal, o.Load1 = l.CPU, l.MemUsed, l.MemTotal, l.Load1
			o.DiskUsed, o.DiskTotal, o.Conns = l.DiskUsed, l.DiskTotal, l.Conns
		}
		if t, ok := traffic[n.ID]; ok {
			o.Up, o.Down = t.Up, t.Down
		}
		if m.phases != nil {
			ph := m.phases.PhaseCounts(n.ID, func(id string) bool { return known[id] })
			o.Serving, o.Failed = uint32(ph["serving"]), uint32(ph["failed"])
		}
		out = append(out, o)
	}
	return connect.NewResponse(&panelv1.OverviewResponse{Nodes: out, SinceUnix: since.Unix(), NowUnix: now.Unix()}), nil
}

// NodeSeries returns the load of a node over a range, with the traffic of its
// proxies (up, down and the sum of their unique IPs) merged into the points of
// the same period. A period that has only one of them has a point.
func (m *MetricsService) NodeSeries(ctx context.Context, req *connect.Request[panelv1.NodeSeriesRequest]) (*connect.Response[panelv1.NodeSeriesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	span, err := proxies.SeriesSpan(req.Msg.GetRange())
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetNodeId()
	if err := m.node(ctx, id); err != nil {
		return nil, err
	}
	s, err := m.settings(ctx)
	if err != nil {
		return nil, err
	}
	r := s.Retention()
	from, to, step := proxies.SeriesWindow(span, m.now(), r)
	load, err := m.db.NodeSeries(ctx, id, from, to, r)
	if err != nil {
		return nil, fail(m.log, "could not read the statistics of a node", err)
	}
	traffic, err := m.db.NodeTraffic(ctx, id, from, to, r)
	if err != nil {
		return nil, fail(m.log, "could not read the traffic of a node", err)
	}
	points := map[int64]*panelv1.NodePoint{}
	point := func(ts time.Time) *panelv1.NodePoint {
		p, ok := points[ts.Unix()]
		if !ok {
			p = &panelv1.NodePoint{TsUnix: ts.Unix()}
			points[ts.Unix()] = p
		}
		return p
	}
	for _, l := range load {
		p := point(l.TS)
		p.Cpu, p.MemUsed, p.MemTotal, p.Load1 = l.CPU, l.MemUsed, l.MemTotal, l.Load1
		p.DiskUsed, p.DiskTotal, p.NetRx, p.NetTx, p.Conns = l.DiskUsed, l.DiskTotal, l.NetRx, l.NetTx, l.Conns
		p.RefusedPrehello, p.RefusedTotal, p.EvictedPrehello = l.RefusedPreHello, l.RefusedTotal, l.EvictedPreHello
	}
	for _, t := range traffic {
		p := point(t.TS)
		p.Up, p.Down, p.DevicesSum = t.Up, t.Down, t.DevicesSum
	}
	out := make([]*panelv1.NodePoint, 0, len(points))
	for _, p := range points {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *panelv1.NodePoint) int { return cmp.Compare(a.GetTsUnix(), b.GetTsUnix()) })
	return connect.NewResponse(&panelv1.NodeSeriesResponse{
		StepSeconds: uint32(step / time.Second),
		FromUnix:    from.Unix(),
		ToUnix:      to.Unix(),
		Points:      out,
	}), nil
}

// TopProxies returns the proxies that carried the most from the start of the
// range to now, of a node or of every node, with their names.
func (m *MetricsService) TopProxies(ctx context.Context, req *connect.Request[panelv1.TopProxiesRequest]) (*connect.Response[panelv1.TopProxiesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	span, err := proxies.SeriesSpan(req.Msg.GetRange())
	if err != nil {
		return nil, err
	}
	limit := int(req.Msg.GetLimit())
	switch {
	case limit == 0:
		limit = topDefault
	case limit > topMax:
		return nil, invalid("limit must be at most 50")
	}
	nodeID := req.Msg.GetNodeId()
	if nodeID != "" {
		if err := m.node(ctx, nodeID); err != nil {
			return nil, err
		}
	}
	to := m.now().UTC()
	from := to.Add(-span)
	totals, err := m.db.TopProxies(ctx, nodeID, from, to, limit)
	if err != nil {
		return nil, fail(m.log, "could not read the totals of the proxies", err)
	}
	list, err := m.db.ListProxies(ctx, store.ProxyFilter{NodeID: nodeID})
	if err != nil {
		return nil, fail(m.log, "could not list the proxies", err)
	}
	byID := make(map[string]*store.Proxy, len(list))
	for _, p := range list {
		byID[p.ID] = p
	}
	out := make([]*panelv1.ProxyTotal, 0, len(totals))
	for _, t := range totals {
		pt := &panelv1.ProxyTotal{ProxyId: t.ProxyID, Up: t.Up, Down: t.Down, ConnsNew: t.ConnsNew, DevicesPeak: t.DevicesPeak}
		if p, ok := byID[t.ProxyID]; ok {
			pt.Name, pt.NodeId = p.Name, p.NodeID
		}
		out = append(out, pt)
	}
	return connect.NewResponse(&panelv1.TopProxiesResponse{Proxies: out, FromUnix: from.Unix(), ToUnix: to.Unix()}), nil
}

// Countries returns the countries of the clients from the start of the range
// to now, of a proxy, of the proxies of a node, or of every proxy, with the IP
// policy, the month of the country database and DB-IP's attribution.
func (m *MetricsService) Countries(ctx context.Context, req *connect.Request[panelv1.CountriesRequest]) (*connect.Response[panelv1.CountriesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	span, err := proxies.SeriesSpan(req.Msg.GetRange())
	if err != nil {
		return nil, err
	}
	f := store.CountryFilter{ProxyID: req.Msg.GetProxyId(), NodeID: req.Msg.GetNodeId()}
	switch {
	case f.ProxyID != "" && f.NodeID != "":
		return nil, invalid("name a proxy or a node, not both")
	case f.ProxyID != "":
		if _, err := m.db.ProxyByID(ctx, f.ProxyID); err != nil {
			return nil, m.readError("proxy", err)
		}
	case f.NodeID != "":
		if err := m.node(ctx, f.NodeID); err != nil {
			return nil, err
		}
	}
	s, err := m.settings(ctx)
	if err != nil {
		return nil, err
	}
	to := m.now().UTC()
	from := to.Add(-span)
	totals, err := m.db.CountryTotals(ctx, f, from, to)
	if err != nil {
		return nil, fail(m.log, "could not read the countries", err)
	}
	out := make([]*panelv1.CountryTotal, 0, len(totals))
	for _, c := range totals {
		out = append(out, &panelv1.CountryTotal{Country: c.Country, Bytes: c.Bytes, IpsPeak: c.IPsPeak})
	}
	return connect.NewResponse(&panelv1.CountriesResponse{
		Countries:      out,
		Policy:         s.IPPolicy,
		GeoipMonth:     m.geoMonth(),
		Attribution:    geoip.Attribution,
		AttributionUrl: geoip.AttributionURL,
		FromUnix:       from.Unix(),
		ToUnix:         to.Unix(),
	}), nil
}

// ListIpSightings returns where client addresses were seen on a proxy, the
// ones seen last first. The store keeps them only under the IP policy full,
// and does not check the policy when it lists them (store.DB.ListSightings):
// this is the gate. Under any other policy the call fails with
// FAILED_PRECONDITION, whatever the table holds.
func (m *MetricsService) ListIpSightings(ctx context.Context, req *connect.Request[panelv1.ListIpSightingsRequest]) (*connect.Response[panelv1.ListIpSightingsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	s, err := m.settings(ctx)
	if err != nil {
		return nil, err
	}
	if s.IPPolicy != store.IPPolicyFull {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errNoAddresses)
	}
	msg := req.Msg
	if msg.GetProxyId() == "" {
		return nil, invalid("proxy_id is required")
	}
	limit := int(msg.GetLimit())
	switch {
	case limit == 0:
		limit = sightingsDefault
	case limit > sightingsMax:
		return nil, invalid("limit must be at most 200")
	}
	country := strings.ToUpper(msg.GetCountry())
	if country != "" && !isCountryCode(country) {
		return nil, invalid("country must be a code of two letters")
	}
	if _, err := m.db.ProxyByID(ctx, msg.GetProxyId()); err != nil {
		return nil, m.readError("proxy", err)
	}
	list, total, err := m.db.ListSightings(ctx, msg.GetProxyId(), country, limit, int(msg.GetOffset()))
	if err != nil {
		return nil, fail(m.log, "could not list where addresses were seen", err)
	}
	out := make([]*panelv1.IpSighting, 0, len(list))
	for _, x := range list {
		out = append(out, &panelv1.IpSighting{
			Ip: x.IP, Country: x.Country, FirstSeenUnix: x.FirstSeen.Unix(), LastSeenUnix: x.LastSeen.Unix(), Bytes: x.Bytes,
		})
	}
	return connect.NewResponse(&panelv1.ListIpSightingsResponse{Sightings: out, Total: uint32(total)}), nil
}

// isCountryCode reports whether c is two upper-case letters A–Z.
func isCountryCode(c string) bool {
	return len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z'
}

// EgressHistory returns the hours of the members of the chains of a node over
// a range of at most 30 days that ends at the end of the current hour, by
// member, each oldest first.
func (m *MetricsService) EgressHistory(ctx context.Context, req *connect.Request[panelv1.EgressHistoryRequest]) (*connect.Response[panelv1.EgressHistoryResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	span, err := proxies.SeriesSpan(req.Msg.GetRange())
	if err != nil {
		return nil, err
	}
	if span > egressMax {
		return nil, invalid("range must be 1h, 24h, 7d or 30d: the hours of the members are kept for 30 days")
	}
	id := req.Msg.GetNodeId()
	if err := m.node(ctx, id); err != nil {
		return nil, err
	}
	to := m.now().UTC().Truncate(time.Hour).Add(time.Hour)
	from := to.Add(-span)
	hours, err := m.db.EgressHistory(ctx, id, from, to)
	if err != nil {
		return nil, fail(m.log, "could not read the history of the egress members", err)
	}
	type key struct{ chain, member string }
	byMember := map[key]*panelv1.MemberHistory{}
	var out []*panelv1.MemberHistory
	for _, h := range hours {
		k := key{h.ChainID, h.MemberKey}
		mh, ok := byMember[k]
		if !ok {
			mh = &panelv1.MemberHistory{ChainId: h.ChainID, MemberKey: h.MemberKey}
			byMember[k] = mh
			out = append(out, mh)
		}
		mh.Hours = append(mh.Hours, &panelv1.MemberHour{
			TsUnix: h.TS.Unix(), UpMinutes: h.Up, DownMinutes: h.Down, UnknownMinutes: h.Unknown,
			LatencyAvgMs: h.LatencyAvgMS, LatencyMaxMs: h.LatencyMaxMS, ExitIp: h.ExitIP,
		})
	}
	slices.SortFunc(out, func(a, b *panelv1.MemberHistory) int {
		return cmp.Or(cmp.Compare(a.GetChainId(), b.GetChainId()), cmp.Compare(a.GetMemberKey(), b.GetMemberKey()))
	})
	return connect.NewResponse(&panelv1.EgressHistoryResponse{Members: out, FromUnix: from.Unix(), ToUnix: to.Unix()}), nil
}
