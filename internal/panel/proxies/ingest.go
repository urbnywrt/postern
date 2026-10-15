package proxies

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// Bounds on what the panel takes from a node. A node is trusted with its own
// proxies, not with anything else, and what it says is clipped.
const (
	// maxBytesPerMinute is the most traffic that a proxy or a node can have
	// had in a minute: 10 GiB/s. More is not a reading but a fault (a counter
	// that went backwards, read as a huge unsigned number), and is left out.
	maxBytesPerMinute = 10 << 30 * 60

	maxReportProxies   = 10000 // statuses taken from one state report
	maxReportMembers   = 4096  // egress members taken from one state report
	maxReportInstances = 1000  // egress instances taken from one state report
	maxInstanceIDLen   = 256   // the egress id and the provider of an instance
	maxPhaseLen        = 16
	maxMemberFieldLen  = 256 // the chain and the key of a member
	maxStatusLen       = 16
	maxExitIPLen       = 64    // the longest IPv6 address has 45 characters
	maxStatsProxies    = 10000 // proxy minutes taken from one batch
	maxStatsCountries  = 10000 // country minutes taken from one batch
	maxStatsMembers    = 2000  // member minutes taken from one batch
	maxStatsSightings  = 10000 // sightings taken from one batch, as many as a node sends
	maxStatsProbes     = 10000 // probes taken from one batch
	maxProbeErrorLen   = 256
	maxReasonLen       = 1024
	maxVersionLen      = 64
	maxKindLen         = 64
	maxMessageLen      = 1024
	maxDetails         = 32
	maxDetailKeyLen    = 64
	maxDetailValueLen  = 256

	// A minute up to this far ahead of the clock of the panel is taken: the
	// clocks of the node and the panel may differ a little.
	maxMinuteAhead = 10 * time.Minute
	// The time of the last check of an egress member is taken as at most this
	// far ahead of the clock of the panel.
	maxCheckAhead = time.Minute
	// The time of a record is taken as the time of its event when it is
	// within these bounds of the clock of the panel; the node buffers its
	// records for 7 days.
	maxRecordAge   = 8 * 24 * time.Hour
	maxRecordAhead = 5 * time.Minute
)

// The events that the ingestor records itself.
const (
	eventProxyFailed = "proxy.failed"
	eventNode        = "node.event" // the kind of a node event that has none
)

// ProxyReport is what a node last reported about one of its proxies: its
// phase and why, the engine and the version of the instance that serves it,
// the engine and the version that the last change could not bring up (empty
// when it went through), the generation of the serving instance, when the
// node reported it, and ReportGeneration, the applied_generation of the state
// report it came in.
type ProxyReport struct {
	Phase                       nodev1.ProxyPhase
	Reason                      string
	RunningVersion              string
	FailedVersion               string
	RunningEngine, FailedEngine nodev1.Engine
	InstanceGeneration          uint64
	Reported                    time.Time
	ReportGeneration            uint64
}

// EgressReport is one provider instance of a node as it last reported it: the
// egress it serves, the provider and the version it runs, its phase and why,
// the version the last change could not bring up, its generation, and the
// applied_generation of the state report it came in.
type EgressReport struct {
	EgressID, Provider, Version, Phase, Reason, FailedVersion string
	Generation, ReportGeneration                              uint64
}

// liveMinute is the latest minute that a node reported about a proxy.
type liveMinute struct {
	minute                                    time.Time
	up, down                                  uint64
	connsNew, connsPeak, devices, connsActive uint32
}

// Ingestor takes the records that nodes stream (see the Watch call of the
// node) and keeps what they say: the status of every proxy in memory, the
// minutes of statistics in the database, and the events of the nodes, and a
// failure of a proxy, as events. It is the Ingestor of the node manager.
//
// A record may come more than once, so taking it is idempotent: a minute is
// stored again over itself, and an event has an id made of the record (or of
// what the event says, for a record without a number), which the database
// refuses a second time.
type Ingestor struct {
	db  *store.DB
	log *slog.Logger
	now func() time.Time

	mu        sync.Mutex
	statuses  map[string]map[string]ProxyReport // node id → proxy id → status; replaced as a whole
	minutes   map[string]map[string]liveMinute  // node id → proxy id → latest minute
	egress    map[string]egressReport           // node id → the health of its egress members
	instances map[string][]EgressReport         // node id → its provider instances; replaced as a whole
	serving   map[string]map[string]uint64      // node id → proxy id → the generation of its serving instance

	geo           GeoIP
	onDiagnostics func(ctx context.Context, nodeID string, at time.Time, rep *nodev1.DiagnosticsReport) error
	onServing     func(nodeID, proxyID string, fromGen, toGen uint64)
}

// SetGeoIP gives the ingestor the country database, which gives the country
// of the addresses that the nodes saw (under the IP policy full).
func (in *Ingestor) SetGeoIP(g GeoIP) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.geo = g
}

// OnDiagnostics sets what is given the light checks that a node reports
// (WatchResponse.diagnostics), with the time of the record. Without it they
// are ignored. An error is one of the database, and the record is offered
// again.
func (in *Ingestor) OnDiagnostics(fn func(ctx context.Context, nodeID string, at time.Time, rep *nodev1.DiagnosticsReport) error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.onDiagnostics = fn
}

// OnServingChange sets what is told that a node reports a proxy served by an
// instance of another generation than the one it reported last: the instance
// was replaced, by a blue-green of the node or of a change. It is called on
// the goroutine of the node, after the report is taken; the first report of a
// proxy since the panel started tells nothing.
func (in *Ingestor) OnServingChange(fn func(nodeID, proxyID string, fromGen, toGen uint64)) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.onServing = fn
}

// egressReport is what a node last reported of the health of the members of
// its chains, and when.
type egressReport struct {
	members  []*nodev1.EgressMemberHealth
	reported time.Time
}

// NewIngestor returns an ingestor that stores into db. A nil log discards the
// log.
func NewIngestor(db *store.DB, log *slog.Logger) *Ingestor {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Ingestor{
		db:        db,
		log:       log,
		now:       time.Now,
		statuses:  map[string]map[string]ProxyReport{},
		minutes:   map[string]map[string]liveMinute{},
		egress:    map[string]egressReport{},
		instances: map[string][]EgressReport{},
		serving:   map[string]map[string]uint64{},
	}
}

// OnWatch takes one record of the Watch stream of a node:
//
//   - a state report replaces the statuses of the proxies of the node (only
//     proxies of that node count; an opening report without a number and
//     without a proxy says nothing of them, and leaves them), and records an
//     event when a proxy changes to failed from a status that the panel knew;
//   - a batch of statistics stores, in one transaction (store.IngestMinute),
//     the minutes of the proxies of the node and of the node with its
//     refusals, each under the start of its minute; the countries of its
//     proxies (not under the IP policy off), the health of its egress members,
//     where addresses were seen (only under full, with the country from the
//     database of the panel) and the node's probes (l2 and web); implausible
//     readings (too much traffic, a minute older than a node keeps its records
//     or a good way ahead of the clock of the panel) and proxies that are gone
//     or of another node are left out, and every list is capped;
//   - a node event is stored as an event, clipped;
//   - a diagnostics report goes to the OnDiagnostics hook, if one is set.
//
// A state report in which a serving proxy runs another instance generation
// than before tells the OnServingChange hook.
//
// An error is one of the database, and the record may be offered again.
func (in *Ingestor) OnWatch(ctx context.Context, nodeID string, ev *nodev1.WatchResponse) error {
	switch p := ev.GetPayload().(type) {
	case *nodev1.WatchResponse_State:
		return in.onState(ctx, nodeID, ev, p.State)
	case *nodev1.WatchResponse_Stats:
		return in.onStats(ctx, nodeID, p.Stats)
	case *nodev1.WatchResponse_Event:
		return in.onEvent(ctx, nodeID, ev, p.Event)
	case *nodev1.WatchResponse_Diagnostics:
		in.mu.Lock()
		fn := in.onDiagnostics
		in.mu.Unlock()
		if fn == nil {
			return nil
		}
		return fn(ctx, nodeID, in.recordTime(ev), p.Diagnostics)
	}
	return nil // a record that this version does not know
}

// proxiesOf returns the ids of the proxies of a node, none for a node that is
// gone.
func (in *Ingestor) proxiesOf(ctx context.Context, nodeID string) (map[string]bool, error) {
	if nodeID == "" {
		return map[string]bool{}, nil // an empty filter would select every proxy
	}
	ps, err := in.db.ListProxies(ctx, store.ProxyFilter{NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ps))
	for _, p := range ps {
		out[p.ID] = true
	}
	return out, nil
}

func (in *Ingestor) onState(ctx context.Context, nodeID string, ev *nodev1.WatchResponse, report *nodev1.StateReport) error {
	in.mu.Lock()
	prev := in.statuses[nodeID]
	in.mu.Unlock()
	// The opening report of a Watch from an agent that has not been through a
	// pass yet lists no proxy: an agent older than the report of the proxies
	// it has on disk had no statuses before its first pass. It says nothing
	// about them, so the statuses that the panel knows stay. (Every report
	// that the node numbers is whole: one without a proxy means none.)
	if ev.GetSeq() == 0 && len(report.GetProxies()) == 0 && len(prev) > 0 {
		return nil
	}
	owned, err := in.proxiesOf(ctx, nodeID)
	if err != nil {
		return err
	}
	at := in.recordTime(ev)
	next := map[string]ProxyReport{}
	for i, ps := range report.GetProxies() {
		if i >= maxReportProxies {
			break
		}
		if !owned[ps.GetProxyId()] {
			continue
		}
		next[ps.GetProxyId()] = ProxyReport{
			Phase:              ps.GetPhase(),
			Reason:             clip(ps.GetReason(), maxReasonLen),
			RunningVersion:     clip(ps.GetRunningVersion(), maxVersionLen),
			FailedVersion:      clip(ps.GetFailedVersion(), maxVersionLen),
			RunningEngine:      ps.GetEngine(),
			FailedEngine:       ps.GetFailedEngine(),
			InstanceGeneration: ps.GetInstanceGeneration(),
			Reported:           at,
			ReportGeneration:   report.GetAppliedGeneration(),
		}
	}
	instances := make([]EgressReport, 0, min(len(report.GetEgressInstances()), maxReportInstances))
	for i, inst := range report.GetEgressInstances() {
		if i >= maxReportInstances {
			break
		}
		instances = append(instances, EgressReport{
			EgressID:         clip(inst.GetEgressId(), maxInstanceIDLen),
			Provider:         clip(inst.GetProvider(), maxInstanceIDLen),
			Version:          clip(inst.GetVersion(), maxVersionLen),
			Phase:            clip(inst.GetPhase(), maxPhaseLen),
			Reason:           clip(inst.GetReason(), maxReasonLen),
			FailedVersion:    clip(inst.GetFailedVersion(), maxVersionLen),
			Generation:       inst.GetGeneration(),
			ReportGeneration: report.GetAppliedGeneration(),
		})
	}

	// The events go first: a record whose events cannot be stored is offered
	// again, and must find the statuses as they were.
	for _, id := range slices.Sorted(maps.Keys(next)) {
		s := next[id]
		if s.Phase != nodev1.ProxyPhase_PROXY_PHASE_FAILED {
			continue
		}
		// A failure is an event when the panel sees the proxy fail: from a
		// status that it knows and that is not failed. A panel that has just
		// started knows no status, and a proxy that failed before is no
		// news; the node's own events (instance_failed, artifact_missing)
		// say what happened while the panel was away.
		old, known := prev[id]
		if !known || old.Phase == nodev1.ProxyPhase_PROXY_PHASE_UNSPECIFIED || old.Phase == nodev1.ProxyPhase_PROXY_PHASE_FAILED {
			continue
		}
		msg := s.Reason
		if msg == "" {
			msg = "the proxy failed"
		}
		var details map[string]string
		if s.InstanceGeneration != 0 {
			details = map[string]string{"instance_generation": strconv.FormatUint(s.InstanceGeneration, 10)}
		}
		e := &store.Event{
			// Without a number, the failure is known by what it is: the same
			// failure that opening reports tell again is one event.
			ID:       watchEventID(nodeID, ev, eventProxyFailed+":"+id, strconv.FormatUint(s.InstanceGeneration, 10), s.Reason),
			TS:       at,
			NodeID:   nodeID,
			ProxyID:  id,
			Kind:     eventProxyFailed,
			Severity: "error",
			Message:  msg,
			Details:  details,
		}
		if err := in.appendEvent(ctx, e); err != nil {
			return err
		}
	}

	// A time of a check ahead of the clock of the panel is believed by a minute
	// at the most: the clocks differ a little, and a time in the future would
	// make old health look fresh.
	latestCheck := in.now().Add(maxCheckAhead).Unix()
	members := make([]*nodev1.EgressMemberHealth, 0, min(len(report.GetEgress()), maxReportMembers))
	for i, h := range report.GetEgress() {
		if i >= maxReportMembers {
			break
		}
		members = append(members, &nodev1.EgressMemberHealth{
			ChainId:     clip(h.GetChainId(), maxMemberFieldLen),
			MemberKey:   clip(h.GetMemberKey(), maxMemberFieldLen),
			Status:      clip(h.GetStatus(), maxStatusLen),
			LatencyMs:   h.GetLatencyMs(),
			ExitIp:      clip(h.GetExitIp(), maxExitIPLen),
			CheckedUnix: max(min(h.GetCheckedUnix(), latestCheck), 0),
		})
	}

	type change struct {
		proxyID        string
		fromGen, toGen uint64
	}
	var changes []change
	in.mu.Lock()
	in.statuses[nodeID] = next
	in.egress[nodeID] = egressReport{members: members, reported: at}
	in.instances[nodeID] = instances
	for id := range in.minutes[nodeID] {
		if !owned[id] {
			delete(in.minutes[nodeID], id)
		}
	}
	serving := in.serving[nodeID]
	if serving == nil {
		serving = map[string]uint64{}
		in.serving[nodeID] = serving
	}
	for id := range serving {
		if !owned[id] {
			delete(serving, id)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(next)) {
		s := next[id]
		if s.Phase != nodev1.ProxyPhase_PROXY_PHASE_SERVING || s.InstanceGeneration == 0 {
			continue
		}
		if last, ok := serving[id]; ok && last != s.InstanceGeneration {
			changes = append(changes, change{id, last, s.InstanceGeneration})
		}
		serving[id] = s.InstanceGeneration
	}
	fn := in.onServing
	in.mu.Unlock()
	if fn != nil {
		for _, c := range changes {
			fn(nodeID, c.proxyID, c.fromGen, c.toGen)
		}
	}
	return nil
}

// ForgetNode lets go of what the ingestor keeps of a node in memory: the
// statuses of its proxies, their latest minutes and the health of its egress
// members. The node manager calls it when a node is deleted
// (nodes.NodeForgetter).
func (in *Ingestor) ForgetNode(nodeID string) {
	if in == nil {
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	delete(in.statuses, nodeID)
	delete(in.minutes, nodeID)
	delete(in.egress, nodeID)
	delete(in.instances, nodeID)
	delete(in.serving, nodeID)
}

// EgressReports returns the provider instances that a node last reported, as
// it listed them (at most 1000); nil for a node that has not reported since
// the panel started.
func (in *Ingestor) EgressReports(nodeID string) []EgressReport {
	if in == nil {
		return nil
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	return slices.Clone(in.instances[nodeID])
}

// EgressHealth returns what a node last reported of the health of the members
// of its chains, as the node keys them (EgressMemberHealth: the chain, and the
// egress, with the key of the member within it after a slash for an egress of
// several), and when it reported it. ok is false when it has not reported
// since the panel started. The members are copies.
func (in *Ingestor) EgressHealth(nodeID string) (members []*nodev1.EgressMemberHealth, reported time.Time, ok bool) {
	if in == nil {
		return nil, time.Time{}, false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	r, ok := in.egress[nodeID]
	if !ok {
		return nil, time.Time{}, false
	}
	out := make([]*nodev1.EgressMemberHealth, 0, len(r.members))
	for _, m := range r.members {
		out = append(out, proto.Clone(m).(*nodev1.EgressMemberHealth))
	}
	return out, r.reported, true
}

func (in *Ingestor) onStats(ctx context.Context, nodeID string, batch *nodev1.StatsBatch) error {
	now := in.now()
	ts := time.Unix(batch.GetMinuteUnix(), 0).UTC()
	// A minute is taken when it is within what a node can have kept (it buffers
	// its records for 7 days, so none is older than maxRecordAge) and not far
	// ahead of the clock of the panel. Without a lower bound a node could write
	// minutes of any age, 1970 included, which only the pruning would remove.
	if batch.GetMinuteUnix() <= 0 || ts.After(now.Add(maxMinuteAhead)) || ts.Before(now.Add(-maxRecordAge)) {
		in.log.Warn("a node reported statistics of a minute that cannot be (older than a node keeps its records, or ahead of the clock of the panel); they are left out",
			"node", nodeID, "minute", batch.GetMinuteUnix())
		return nil
	}
	// The store keeps a minute under the start of the minute, so the live minute
	// is the start of it too: two readings within one minute are then one minute,
	// the later one in place of the earlier, here as there.
	ts = ts.Truncate(time.Minute)
	owned, err := in.proxiesOf(ctx, nodeID)
	if err != nil {
		return err
	}
	var (
		rows []store.ProxyStat
		live []liveMinute // of each row
	)
	for i, pm := range batch.GetProxies() {
		if i >= maxStatsProxies {
			break
		}
		id := pm.GetProxyId()
		if !owned[id] {
			continue // gone, or not a proxy of this node
		}
		if pm.GetUp() > maxBytesPerMinute || pm.GetDown() > maxBytesPerMinute {
			in.log.Warn("a node reported more traffic of a proxy than it can have had; the minute is left out",
				"node", nodeID, "proxy", id, "minute", batch.GetMinuteUnix())
			continue
		}
		rows = append(rows, store.ProxyStat{
			ProxyID:   id,
			TS:        ts,
			Up:        pm.GetUp(),
			Down:      pm.GetDown(),
			ConnsNew:  pm.GetConnsNew(),
			ConnsPeak: pm.GetConnsPeak(),
			Devices:   pm.GetDevices(),
		})
		live = append(live, liveMinute{
			minute:      ts,
			up:          pm.GetUp(),
			down:        pm.GetDown(),
			connsNew:    pm.GetConnsNew(),
			connsPeak:   pm.GetConnsPeak(),
			devices:     pm.GetDevices(),
			connsActive: pm.GetConnsActive(),
		})
	}

	var node *store.NodeStat
	if nm := batch.GetNode(); nm != nil {
		if plausibleNodeMinute(nm) {
			node = &store.NodeStat{
				NodeID:          nodeID,
				TS:              ts,
				CPU:             nm.GetCpu(),
				MemUsed:         nm.GetMemUsed(),
				MemTotal:        nm.GetMemTotal(),
				Load1:           nm.GetLoad1(),
				DiskUsed:        nm.GetDiskUsed(),
				DiskTotal:       nm.GetDiskTotal(),
				NetRx:           nm.GetNetRx(),
				NetTx:           nm.GetNetTx(),
				Conns:           nm.GetConns(),
				RefusedPreHello: nm.GetRefusedPrehello(),
				RefusedTotal:    nm.GetRefusedTotal(),
				EvictedPreHello: nm.GetEvictedPrehello(),
			}
		} else {
			in.log.Warn("a node reported a minute of itself that cannot be; it is left out",
				"node", nodeID, "minute", batch.GetMinuteUnix())
		}
	}

	b := store.MinuteBatch{NodeID: nodeID, Minute: ts, Proxies: rows, Node: node}
	policy := in.ipPolicy(ctx)
	if policy != store.IPPolicyOff {
		b.Countries = countryRows(batch.GetCountries(), owned)
	}
	b.Members = memberRows(batch.GetMembers())
	if policy == store.IPPolicyFull {
		in.mu.Lock()
		geo := in.geo
		in.mu.Unlock()
		b.Sightings = sightingRows(batch.GetIps(), owned, geo)
	}
	b.Probes = in.probeRows(batch.GetProbes(), owned, ts)
	if len(rows) == 0 && node == nil && len(b.Countries) == 0 && len(b.Members) == 0 && len(b.Sightings) == 0 && len(b.Probes) == 0 {
		return nil
	}
	// One transaction for the whole batch; what is gone since (a proxy
	// deleted, the node itself) is skipped. The store applies the IP policy
	// again, in the transaction.
	gone, err := in.db.IngestMinute(ctx, b)
	if errors.Is(err, store.ErrMinuteTooOld) {
		in.log.Warn("a node reported statistics of a minute that is older than the panel takes; they are left out",
			"node", nodeID, "minute", batch.GetMinuteUnix())
		return nil
	}
	if err != nil {
		return err
	}
	for i, r := range rows {
		if !slices.Contains(gone, r.ProxyID) {
			in.setMinute(nodeID, r.ProxyID, live[i])
		}
	}
	return nil
}

// ipPolicy is the IP policy of the panel; off when it cannot be read.
func (in *Ingestor) ipPolicy(ctx context.Context) string {
	st, _, err := in.db.StatsSettings(ctx)
	if err != nil {
		in.log.Error("could not read the IP policy; the addresses and countries of the batch are left out", "err", err)
		return store.IPPolicyOff
	}
	return st.IPPolicy
}

// countryRows are the country minutes of a batch that are of proxies of the
// node and within the bounds: at most 10,000, bytes within the limit of a
// minute. The store checks the codes and keeps 50 a proxy.
func countryRows(list []*nodev1.CountryMinute, owned map[string]bool) []store.CountryStat {
	var out []store.CountryStat
	for i, c := range list {
		if i >= maxStatsCountries {
			break
		}
		if !owned[c.GetProxyId()] || c.GetBytes() > maxBytesPerMinute {
			continue
		}
		out = append(out, store.CountryStat{ProxyID: c.GetProxyId(), Country: c.GetCountry(), IPs: c.GetIps(), Bytes: c.GetBytes()})
	}
	return out
}

// memberRows are the member minutes of a batch, at most 2,000, with their
// fields clipped.
func memberRows(list []*nodev1.MemberMinute) []store.MemberStat {
	var out []store.MemberStat
	for i, m := range list {
		if i >= maxStatsMembers {
			break
		}
		chain, key := clip(m.GetChainId(), maxMemberFieldLen), clip(m.GetMemberKey(), maxMemberFieldLen)
		if chain == "" || key == "" {
			continue
		}
		out = append(out, store.MemberStat{
			ChainID: chain, MemberKey: key, Status: clip(m.GetStatus(), maxStatusLen),
			LatencyMS: m.GetLatencyMs(), ExitIP: clip(m.GetExitIp(), maxExitIPLen),
		})
	}
	return out
}

// sightingRows are the addresses that a batch saw on proxies of the node, at
// most 10,000, each an IP address, with its country from the database of the
// panel. Times out of order are put in order.
func sightingRows(list []*nodev1.IpSighting, owned map[string]bool, geo GeoIP) []store.Sighting {
	var out []store.Sighting
	for i, ip := range list {
		if i >= maxStatsSightings {
			break
		}
		a, err := netip.ParseAddr(ip.GetIp())
		if !owned[ip.GetProxyId()] || err != nil || a.Zone() != "" || ip.GetBytes() > maxBytesPerMinute {
			continue
		}
		a = a.Unmap()
		first, last := ip.GetFirstSeen(), ip.GetLastSeen()
		if first <= 0 || last <= 0 {
			continue
		}
		if last < first {
			first, last = last, first
		}
		out = append(out, store.Sighting{
			ProxyID: ip.GetProxyId(), IP: a.String(), Country: geo.country(a),
			FirstSeen: time.Unix(first, 0).UTC(), LastSeen: time.Unix(last, 0).UTC(), Bytes: ip.GetBytes(),
		})
	}
	return out
}

// The kinds of probes of a node that are stored: L2, and the probe of a WEB
// proxy. L1 classifies a failed L2 and is not stored.
var storedProbeKinds = []string{"l2", "web"}

// probeRows are the probes that a node ran on its own proxies, at most 10,000,
// of a kind that is stored, with the error clipped to 256 bytes. A probe whose
// time is not plausible takes the minute of the batch.
func (in *Ingestor) probeRows(list []*nodev1.ProbeResult, owned map[string]bool, minute time.Time) []store.Probe {
	now := in.now()
	var out []store.Probe
	for i, p := range list {
		if i >= maxStatsProbes {
			break
		}
		if !owned[p.GetProxyId()] || !slices.Contains(storedProbeKinds, p.GetKind()) {
			continue
		}
		at := time.Unix(p.GetAtUnix(), 0).UTC()
		if p.GetAtUnix() <= 0 || at.Before(now.Add(-maxRecordAge)) || at.After(now.Add(maxRecordAhead)) {
			at = minute
		}
		errText := ""
		if !p.GetOk() {
			errText = clip(p.GetError(), maxProbeErrorLen)
		}
		out = append(out, store.Probe{
			ProxyID: p.GetProxyId(), TS: at, Vantage: "node", Kind: p.GetKind(),
			OK: p.GetOk(), LatencyMS: p.GetLatencyMs(), Error: errText,
		})
	}
	return out
}

// plausibleNodeMinute reports whether the minute of a node can be: traffic
// within the limit, and no negative or infinite load. (A CPU or load that is
// not a number is stored as 0.)
func plausibleNodeMinute(nm *nodev1.NodeMinute) bool {
	for _, f := range []float64{nm.GetCpu(), nm.GetLoad1()} {
		if f < 0 || math.IsInf(f, 0) {
			return false
		}
	}
	return nm.GetNetRx() <= maxBytesPerMinute && nm.GetNetTx() <= maxBytesPerMinute
}

// setMinute keeps the latest minute of a proxy; a minute that comes late does
// not replace a newer one.
func (in *Ingestor) setMinute(nodeID, proxyID string, m liveMinute) {
	in.mu.Lock()
	defer in.mu.Unlock()
	byProxy := in.minutes[nodeID]
	if byProxy == nil {
		byProxy = map[string]liveMinute{}
		in.minutes[nodeID] = byProxy
	}
	if old, ok := byProxy[proxyID]; ok && old.minute.After(m.minute) {
		return
	}
	byProxy[proxyID] = m
}

func (in *Ingestor) onEvent(ctx context.Context, nodeID string, ev *nodev1.WatchResponse, ne *nodev1.NodeEvent) error {
	proxyID := ne.GetProxyId()
	if proxyID != "" {
		if !validID(proxyID) {
			proxyID = ""
		} else {
			p, err := in.db.ProxyByID(ctx, proxyID)
			switch {
			case errors.Is(err, store.ErrNotFound):
				// A proxy that is gone: events are history.
			case err != nil:
				return err
			case p.NodeID != nodeID:
				proxyID = "" // not a proxy of this node
			}
		}
	}
	kind := clip(ne.GetKind(), maxKindLen)
	if kind == "" {
		kind = eventNode
	}
	e := &store.Event{
		TS:       in.recordTime(ev),
		NodeID:   nodeID,
		ProxyID:  proxyID,
		Kind:     kind,
		Severity: severityOf(ne.GetSeverity()),
		Message:  clip(ne.GetMessage(), maxMessageLen),
		Details:  clipDetails(ne.GetDetails()),
	}
	// Without a number, the event is known by its time and what it says.
	what := []string{strconv.FormatInt(ev.GetTsUnix(), 10), e.Kind, e.Severity, e.Message, e.ProxyID}
	for _, k := range slices.Sorted(maps.Keys(e.Details)) {
		what = append(what, k, e.Details[k])
	}
	e.ID = watchEventID(nodeID, ev, "", what...)
	return in.appendEvent(ctx, e)
}

// appendEvent stores an event. One that is stored already, because its record
// came again, is no error.
func (in *Ingestor) appendEvent(ctx context.Context, e *store.Event) error {
	err := in.db.AppendEvent(ctx, e)
	if errors.Is(err, store.ErrConflict) {
		return nil
	}
	return err
}

// watchEventID is the id of an event that a record of a node makes: the same
// for the same record and event, so that a record that comes again does not
// make the event again (the database refuses an id twice). A numbered record is
// known by its node, its number and its time (a node that is installed again
// counts from the start, at another time), and by what tells apart the events
// of one record. A record without a number is the opening state report of a
// Watch, a state report that changes nothing, or a record that the node could
// not buffer: it is sent to every stream that is open, and again after a
// reconnect, never with a number to tell it by. Its event is known by its node,
// what and the content, what the event says.
func watchEventID(nodeID string, ev *nodev1.WatchResponse, what string, content ...string) string {
	h := sha256.New()
	if ev.GetSeq() != 0 {
		_, _ = fmt.Fprintf(h, "postern watch event\x00%s\x00%d\x00%d\x00%s", nodeID, ev.GetSeq(), ev.GetTsUnix(), what)
	} else {
		_, _ = fmt.Fprintf(h, "postern unnumbered watch event\x00%s\x00%s", nodeID, what)
		for _, c := range content {
			_, _ = fmt.Fprintf(h, "\x00%d:%s", len(c), c) // the lengths keep "a"+"bc" apart from "ab"+"c"
		}
	}
	return "w" + hex.EncodeToString(h.Sum(nil))[:25]
}

// recordTime is when the event of a record happened: the time of the record,
// unless it is far off the clock of the panel, which is then the time.
func (in *Ingestor) recordTime(ev *nodev1.WatchResponse) time.Time {
	now := in.now()
	if ev.GetTsUnix() <= 0 {
		return now
	}
	t := time.Unix(ev.GetTsUnix(), 0)
	if t.Before(now.Add(-maxRecordAge)) || t.After(now.Add(maxRecordAhead)) {
		return now
	}
	return t
}

// severityOf maps the severity of a node event to info, warn or error.
func severityOf(s string) string {
	switch strings.ToLower(s) {
	case "warn", "warning":
		return "warn"
	case "error", "err", "fatal", "critical":
		return "error"
	}
	return "info"
}

// clipDetails bounds the details of an event: at most 32 of them, the first by
// key, with keys and values clipped.
func clipDetails(d map[string]string) map[string]string {
	if len(d) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, k := range slices.Sorted(maps.Keys(d)) {
		if len(out) >= maxDetails {
			break
		}
		key := clip(k, maxDetailKeyLen)
		if key == "" {
			continue
		}
		out[key] = clip(d[k], maxDetailValueLen)
	}
	return out
}

// clip returns s as valid UTF-8 of at most n bytes.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ProxyReport returns what the node of a proxy last reported about it, and
// whether it has reported since the panel started.
func (in *Ingestor) ProxyReport(nodeID, proxyID string) (ProxyReport, bool) {
	if in == nil {
		return ProxyReport{}, false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	s, ok := in.statuses[nodeID][proxyID]
	return s, ok
}

// PhaseCounts returns how many proxies the node last reported in each phase,
// by the name of the phase in the API ("serving", "failed", ...); a phase that
// none is in is not in the map. Proxies the node has not reported since the
// panel started are not counted, nor those that known does not hold of (a
// proxy deleted since the node reported it), when known is set.
func (in *Ingestor) PhaseCounts(nodeID string, known func(proxyID string) bool) map[string]int {
	out := map[string]int{}
	if in == nil {
		return out
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	for id, s := range in.statuses[nodeID] {
		if known == nil || known(id) {
			out[phaseName(s.Phase)]++
		}
	}
	return out
}

// minuteOf returns the latest minute that the node of a proxy reported about
// it.
func (in *Ingestor) minuteOf(nodeID, proxyID string) (liveMinute, bool) {
	if in == nil {
		return liveMinute{}, false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	m, ok := in.minutes[nodeID][proxyID]
	return m, ok
}

// phaseName is the name of a phase in the API of the panel.
func phaseName(p nodev1.ProxyPhase) string {
	switch p {
	case nodev1.ProxyPhase_PROXY_PHASE_PENDING:
		return "pending"
	case nodev1.ProxyPhase_PROXY_PHASE_STARTING:
		return "starting"
	case nodev1.ProxyPhase_PROXY_PHASE_READY:
		return "ready"
	case nodev1.ProxyPhase_PROXY_PHASE_SERVING:
		return "serving"
	case nodev1.ProxyPhase_PROXY_PHASE_DRAINING:
		return "draining"
	case nodev1.ProxyPhase_PROXY_PHASE_FAILED:
		return "failed"
	case nodev1.ProxyPhase_PROXY_PHASE_PAUSED:
		return "paused"
	}
	return "unknown"
}
