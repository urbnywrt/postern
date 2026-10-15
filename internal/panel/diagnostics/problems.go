package diagnostics

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/geodb"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// The severities of problems: errors are listed first.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// The kinds of problems.
const (
	KindNodeOffline       = "node.offline"
	KindNodeError         = "node.error"
	KindNodeStateRejected = "node.state_rejected"
	KindNodeLastError     = "node.last_error"
	KindProxyFailed       = "proxy.failed"
	KindProxyDown         = "proxy.down"
	KindCheck             = "check"
	KindGeoIPMissing      = "geoip.missing"
	KindGeoIPStale        = "geoip.stale"
	KindEdgeOutdated      = "edge.outdated"
)

// eventLookback bounds how far back the feed reads the events of a node or a
// proxy: the events are kept 30 days.
const eventLookback = 30 * 24 * time.Hour

// probeHistory is how far back the feed looks for the start of a proxy's
// failing probes that it has not seen itself: the probes are kept 7 days.
const probeHistory = 7 * 24 * time.Hour

// FeedConfig is what the problem feed reads.
type FeedConfig struct {
	DB *store.DB
	// ProxyReport is what the node last reported about a proxy
	// (proxies.Ingestor.ProxyReport); nil leaves failed proxies out.
	ProxyReport func(nodeID, proxyID string) (proxies.ProxyReport, bool)
	// Down says whether the panel's probes find a proxy down
	// (probes.Scheduler.Down); nil leaves them out.
	Down func(proxyID string) bool
	// GeoIP tells about the country database; nil leaves it out.
	GeoIP func(ctx context.Context) (geodb.Status, error)
	// Key opens the proxies' secrets, which are taken out of the text that
	// nodes wrote; nil takes out the client addresses only.
	Key *seal.Key
	// Log notes a secret that does not open; nil discards it.
	Log *slog.Logger
	Now func() time.Time
}

// downStreak is the start of a proxy's failing panel probes, and the error of
// the newest.
type downStreak struct {
	since time.Time
	err   string
}

// Feed composes the problems of the fleet from what the panel knows now: the
// node rows, the light checks that the nodes reported (their hysteresis is
// the node's: the feed lists them as they are), the proxies' reports, the
// panel's probes and the country database.
type Feed struct {
	cfg FeedConfig

	mu      sync.Mutex
	streaks map[string]downStreak // by proxy
	failed  map[string]time.Time  // by proxy: when List first saw it failed

	// hides serializes Visible and Hide, so that a settle of the hides from
	// a listing older than a hide cannot delete it.
	hides sync.Mutex
}

// NewFeed returns a feed. Give OnProbe to probes.Scheduler.OnResult.
func NewFeed(cfg FeedConfig) *Feed {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Feed{cfg: cfg, streaks: map[string]downStreak{}, failed: map[string]time.Time{}}
}

// OnProbe follows the panel's probes of each proxy: since when they fail.
func (f *Feed) OnProbe(p store.Probe) {
	if p.Vantage != VantagePanel {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.OK {
		delete(f.streaks, p.ProxyID)
		return
	}
	s, ok := f.streaks[p.ProxyID]
	if !ok {
		s.since = p.TS
	}
	s.err = p.Error
	f.streaks[p.ProxyID] = s
}

// failedSince is since when a failed proxy has failed: the time of its newest
// proxy.failed event, which the panel records when it sees the proxy fail;
// else, when the proxy failed while the panel was away, the time when the
// feed first saw it failed.
func (f *Feed) failedSince(ctx context.Context, proxyID string) (time.Time, error) {
	now := f.cfg.Now()
	es, err := f.cfg.DB.ListEventsFiltered(ctx, store.EventFilter{ProxyID: proxyID, Kind: KindProxyFailed,
		From: now.Add(-eventLookback), Limit: 1})
	if err != nil {
		return time.Time{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	first, seen := f.failed[proxyID]
	if !seen {
		first = now
		f.failed[proxyID] = first
	}
	if len(es) > 0 {
		return es[0].TS, nil
	}
	return first, nil
}

func (f *Feed) forgetFailed(proxyID string) {
	f.mu.Lock()
	delete(f.failed, proxyID)
	f.mu.Unlock()
}

// streak is the start of a down proxy's failing probes: the one OnProbe saw,
// or else the one in the stored probes, which is kept for the next time.
func (f *Feed) streak(ctx context.Context, proxyID string) (downStreak, error) {
	f.mu.Lock()
	s, ok := f.streaks[proxyID]
	f.mu.Unlock()
	if ok {
		return s, nil
	}
	now := f.cfg.Now()
	ps, err := f.cfg.DB.Probes(ctx, proxyID, VantagePanel, now.Add(-probeHistory), now.Add(time.Second))
	if err != nil {
		return downStreak{}, err
	}
	for _, p := range ps { // oldest first
		switch {
		case p.OK:
			s = downStreak{}
		case s.since.IsZero():
			s = downStreak{since: p.TS, err: p.Error}
		default:
			s.err = p.Error
		}
	}
	if !s.since.IsZero() {
		f.mu.Lock()
		if _, ok := f.streaks[proxyID]; !ok {
			f.streaks[proxyID] = s
		}
		f.mu.Unlock()
	}
	return s, nil
}

// List returns the problems, worst first, then newest first; those of a node
// (and its proxies) when nodeID is set, those of a proxy when proxyID is.
func (f *Feed) List(ctx context.Context, nodeID, proxyID string) ([]*panelv1.Problem, error) {
	nodes, err := f.cfg.DB.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	all, err := f.cfg.DB.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, err
	}
	byNode := map[string][]*store.Proxy{}
	byID := map[string]*store.Proxy{}
	for _, p := range all {
		byNode[p.NodeID] = append(byNode[p.NodeID], p)
		byID[p.ID] = p
	}
	txt := newTexts(f.cfg.DB, f.cfg.Key, f.cfg.Log)
	var out []*panelv1.Problem
	for _, n := range nodes {
		if nodeID != "" && n.ID != nodeID {
			continue
		}
		sc, err := txt.scrubber(ctx, n.ID, n.PublicIPs)
		if err != nil {
			return nil, err
		}
		ps, err := f.ofNode(ctx, n, byNode[n.ID], byID, sc.Clean)
		if err != nil {
			return nil, err
		}
		out = append(out, ps...)
	}
	if nodeID == "" && proxyID == "" {
		if p := f.geoip(ctx); p != nil {
			out = append(out, p)
		}
	}
	if proxyID != "" {
		out = slices.DeleteFunc(out, func(p *panelv1.Problem) bool { return p.ProxyId != proxyID })
	}
	for _, p := range out {
		p.Key = problemKey(p)
	}
	slices.SortStableFunc(out, func(a, b *panelv1.Problem) int {
		return cmp.Or(
			cmp.Compare(rankOf(b.Severity), rankOf(a.Severity)),
			cmp.Compare(b.SinceUnix, a.SinceUnix),
			strings.Compare(a.NodeName, b.NodeName), strings.Compare(a.NodeId, b.NodeId),
			strings.Compare(a.Kind, b.Kind), strings.Compare(a.ProxyName, b.ProxyName), strings.Compare(a.ProxyId, b.ProxyId),
			strings.Compare(a.CheckId, b.CheckId), strings.Compare(a.Target, b.Target))
	})
	return out, nil
}

func rankOf(severity string) int {
	if severity == SeverityError {
		return 1
	}
	return 0
}

func unixOr0(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// ofNode is the problems of a node and of its proxies.
func (f *Feed) ofNode(ctx context.Context, n *store.Node, ps []*store.Proxy, byID map[string]*store.Proxy, clean func(string) string) ([]*panelv1.Problem, error) {
	if n.Status == store.NodeStatusProvisioning {
		return nil, nil
	}
	mk := func(severity, kind, summary, hint string, since time.Time) *panelv1.Problem {
		return &panelv1.Problem{Severity: severity, Kind: kind, NodeId: n.ID, NodeName: n.Name,
			Summary: clip(summary, maxSummary), Hint: clip(hint, maxHint), SinceUnix: unixOr0(since)}
	}
	var out []*panelv1.Problem
	switch n.Status {
	case store.NodeStatusOffline:
		var since time.Time
		if n.LastSeenAt != nil {
			since = *n.LastSeenAt
		}
		out = append(out, mk(SeverityError, KindNodeOffline, "the node is offline",
			"look at the node's host: the agent's container, its network, the management port", since))
	case store.NodeStatusError:
		summary, since := "the panel cannot talk to the node", time.Time{}
		es, err := f.cfg.DB.ListEventsFiltered(ctx, store.EventFilter{NodeID: n.ID, Kind: KindNodeError,
			From: f.cfg.Now().Add(-eventLookback), Limit: 1})
		if err != nil {
			return nil, err
		}
		if len(es) > 0 {
			since = es[0].TS
			if es[0].Message != "" {
				summary += ": " + clean(es[0].Message)
			}
		}
		out = append(out, mk(SeverityError, KindNodeError, summary, "see the node's events in the journal", since))
	}
	if n.StateRejection != "" {
		var since time.Time
		if at, behind, err := f.cfg.DB.NodeBehindSince(ctx, n.ID); err != nil {
			return nil, err
		} else if behind {
			since = at
		}
		out = append(out, mk(SeverityError, KindNodeStateRejected, "the node refused its desired state: "+clean(n.StateRejection),
			"correct what the node names, or update the node's agent", since))
	}
	if n.LastError != "" && n.Status != store.NodeStatusError {
		out = append(out, mk(SeverityWarning, KindNodeLastError, "the node's last reconcile pass failed: "+clean(n.LastError),
			"see the node's events and its light checks", time.Time{}))
	}
	if n.Status != store.NodeStatusOnline {
		// What the node reported last is not news of now.
		return out, nil
	}
	caps := n.HostInfo.Capabilities
	if n.EdgeVersion != "" && n.AgentVersion != "" && n.EdgeVersion != n.AgentVersion {
		p := mk(SeverityWarning, KindEdgeOutdated, "the edge runs "+n.EdgeVersion+", the agent "+n.AgentVersion,
			"roll the edge to the agent's version", time.Time{})
		// The check of the full runs that offers the same fix: ApplyFix
		// takes it from the feed with no offered run (see offered).
		p.CheckId = checkVersions
		p.Fix = fixRollEdge
		p.FixAvailable, p.FixUnavailableReason = FixAvailable(fixRollEdge, "", caps)
		out = append(out, p)
	}
	for _, p := range ps {
		if !p.Enabled {
			f.forgetFailed(p.ID)
			continue
		}
		if f.cfg.ProxyReport != nil {
			r, ok := f.cfg.ProxyReport(n.ID, p.ID)
			if !ok || r.Phase != nodev1.ProxyPhase_PROXY_PHASE_FAILED {
				f.forgetFailed(p.ID)
			} else {
				since, err := f.failedSince(ctx, p.ID)
				if err != nil {
					return nil, err
				}
				summary := "the proxy failed"
				if r.Reason != "" {
					summary += ": " + clean(r.Reason)
				}
				x := mk(SeverityError, KindProxyFailed, summary, "see the proxy's events and its engine checks", since)
				x.ProxyId, x.ProxyName = p.ID, p.Name
				out = append(out, x)
			}
		}
		if f.cfg.Down != nil && f.cfg.Down(p.ID) {
			s, err := f.streak(ctx, p.ID)
			if err != nil {
				return nil, err
			}
			summary := "the panel's probes of the proxy fail"
			if s.err != "" {
				summary += ": " + clean(s.err)
			}
			x := mk(SeverityError, KindProxyDown, summary, "run a check of the proxy: ingress.external says where it breaks", s.since)
			x.ProxyId, x.ProxyName = p.ID, p.Name
			out = append(out, x)
		}
	}
	checks, err := f.cfg.DB.NodeChecks(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	for _, c := range checks {
		var severity string
		switch c.Status {
		case StatusFail:
			severity = SeverityError
		case StatusWarn:
			severity = SeverityWarning
		default:
			continue
		}
		x := mk(severity, KindCheck, c.Summary, c.Hint, c.Since)
		x.CheckId, x.Target, x.Fix = c.CheckID, c.Target, c.Fix
		x.FixAvailable, x.FixUnavailableReason = FixAvailable(c.Fix, c.Target, caps)
		if id, ok := strings.CutPrefix(c.Target, "proxy:"); ok {
			x.ProxyId = id
			if p := byID[id]; p != nil {
				x.ProxyName = p.Name
			}
		}
		out = append(out, x)
	}
	return out, nil
}

// geoip is the country database missing or stale while the IP policy uses
// countries, as panel.geoip finds it; nil when it is fine.
func (f *Feed) geoip(ctx context.Context) *panelv1.Problem {
	if f.cfg.GeoIP == nil {
		return nil
	}
	x := geoipStatus(ctx, f.cfg.DB, f.cfg.GeoIP, f.cfg.Now(), "panel.geoip")
	p := &panelv1.Problem{Summary: x.Summary, Hint: x.Hint, CheckId: x.CheckID}
	switch x.Status {
	case StatusFail:
		p.Severity, p.Kind = SeverityError, KindGeoIPMissing
	case StatusWarn:
		p.Severity, p.Kind = SeverityWarning, KindGeoIPStale
	default:
		return nil
	}
	return p
}

// ListProblems returns what is wrong now, worst first, then newest first,
// without the problems that an admin hid unless the request includes them.
func (s *Service) ListProblems(ctx context.Context, req *connect.Request[panelv1.ListProblemsRequest]) (*connect.Response[panelv1.ListProblemsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.feed == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("the panel has no problem feed"))
	}
	nodeID, proxyID := req.Msg.GetNodeId(), req.Msg.GetProxyId()
	if nodeID != "" && proxyID != "" {
		return nil, invalid("node_id and proxy_id cannot both be set")
	}
	ps, err := s.feed.Visible(ctx, nodeID, proxyID, req.Msg.GetIncludeHidden())
	if err != nil {
		return nil, s.fail("could not list the problems", err)
	}
	return connect.NewResponse(&panelv1.ListProblemsResponse{Problems: ps}), nil
}
