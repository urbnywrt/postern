package diagnostics

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// eventEvery is how often a light check of a node and target may record an
// event of a change of its status.
const eventEvery = 10 * time.Minute

// Lights keeps the light checks that the nodes report (WatchResponse
// .diagnostics): it replaces a node's checks with each report and records the
// changes of their status as events, check.failed, check.warning and
// check.recovered, at most one per node, check and target every 10 minutes.
type Lights struct {
	db  *store.DB
	log *slog.Logger
	now func() time.Time

	mu   sync.Mutex
	last map[lightKey]time.Time // when an event of a check was recorded last
	// onChanges is told of the changes of a node's checks (OnChanges).
	onChanges func(nodeID string, changes []store.CheckChange)
}

// OnChanges sets what is told of the changes of the status of a node's light
// checks, after they are stored: Changes.OnLightChanges.
func (l *Lights) OnChanges(fn func(nodeID string, changes []store.CheckChange)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onChanges = fn
}

type lightKey struct{ node, check, target string }

// NewLights returns the keeper of the light checks. A nil log discards the
// log; a nil now is time.Now.
func NewLights(db *store.DB, log *slog.Logger, now func() time.Time) *Lights {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return &Lights{db: db, log: log, now: now, last: map[lightKey]time.Time{}}
}

// OnDiagnostics takes a report of a node's light checks made at at: the
// signature of proxies.Ingestor.OnDiagnostics. An error is one of the
// database, and the record is offered again.
func (l *Lights) OnDiagnostics(ctx context.Context, nodeID string, at time.Time, rep *nodev1.DiagnosticsReport) error {
	b := budget{left: maxRunEvidence}
	checks := make([]store.NodeCheck, 0, len(rep.GetResults()))
	results := rep.GetResults()
	if len(results) > maxResults {
		l.log.Warn("a light report has more results than are kept; the rest are dropped", "node", nodeID, "results", len(results), "kept", maxResults)
		results = results[:maxResults]
	}
	for _, m := range results {
		x := fromNode(m)
		checks = append(checks, store.NodeCheck{
			CheckID: x.CheckID, Target: x.Target, Layer: x.Layer, Status: x.Status,
			Summary: x.Summary, Evidence: b.take(x.Status, x.Evidence),
			Hint: x.Hint, Fix: x.Fix, CheckedAt: cmpTime(x.CheckedAt, at),
		})
	}
	changes, err := l.db.ReplaceNodeChecks(ctx, nodeID, checks, at)
	if err != nil {
		return err
	}
	for _, c := range changes {
		l.event(ctx, nodeID, c)
	}
	l.mu.Lock()
	fn := l.onChanges
	l.mu.Unlock()
	if fn != nil && len(changes) > 0 {
		fn(nodeID, changes)
	}
	return nil
}

func cmpTime(t, def time.Time) time.Time {
	if t.IsZero() {
		return def
	}
	return t
}

// event records the event of a change of a check's status, if it calls for
// one and the rate allows it.
func (l *Lights) event(ctx context.Context, nodeID string, c store.CheckChange) {
	var kind, severity, verb string
	switch {
	case c.Check.Status == StatusFail:
		kind, severity, verb = "check.failed", "error", "fails"
	case c.Check.Status == StatusWarn:
		kind, severity, verb = "check.warning", "warning", "warns"
	case c.Check.Status == StatusOK && (c.From == StatusFail || c.From == StatusWarn):
		kind, severity, verb = "check.recovered", "info", "passes again"
	default:
		return
	}
	if !l.allow(lightKey{nodeID, c.Check.CheckID, c.Check.Target}) {
		return
	}
	e := &store.Event{
		NodeID: nodeID, Kind: kind, Severity: severity,
		Message: clip(fmt.Sprintf("%s %s: %s", checkLabel(c.Check.CheckID, c.Check.Target), verb, c.Check.Summary), 1024),
		Details: map[string]string{"check_id": c.Check.CheckID, "target": c.Check.Target, "from": c.From, "to": c.Check.Status},
	}
	if id, ok := strings.CutPrefix(c.Check.Target, "proxy:"); ok {
		e.ProxyID = id
	}
	if err := l.db.AppendEvent(ctx, e); err != nil {
		l.log.Error("could not record the change of a check", "node", nodeID, "check", c.Check.CheckID, "err", err)
	}
}

// allow takes the turn of a check for an event, if 10 minutes have passed
// since its last one.
func (l *Lights) allow(k lightKey) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if t, ok := l.last[k]; ok && now.Sub(t) < eventEvery {
		return false
	}
	if len(l.last) > 4096 { // forget the turns that are over
		for key, t := range l.last {
			if now.Sub(t) >= eventEvery {
				delete(l.last, key)
			}
		}
	}
	l.last[k] = now
	return true
}

// A fixSpec is what a fix needs: the capability of the node ("" for none) and
// the kind of target ("" for the node itself, else the prefix of the target).
type fixSpec struct{ capability, target string }

var fixSpecs = map[string]fixSpec{
	"recreate_instance":    {"restart-nonce", "proxy:"},
	"roll_edge":            {"edge-roll-nonce", ""},
	"change_egress":        {"", "proxy:"},
	"refresh_subscription": {"egress-xray", "member:"},
	"set_dns_mode_doh":     {"dns-forwarder", ""},
	"reissue_cert":         {"web-diagnostics", "proxy:"},
}

// FixAvailable says whether a fix can be applied to a target of a node with
// these capabilities, and why not when it cannot. No fix is not available,
// with no reason.
func FixAvailable(fix, target string, capabilities []string) (bool, string) {
	if fix == "" {
		return false, ""
	}
	s, ok := fixSpecs[fix]
	switch {
	case !ok:
		return false, "the panel does not know the fix " + fix
	case s.target == "" && target != "":
		return false, "the fix " + fix + " applies to the node, not to " + target
	case s.target != "" && (!strings.HasPrefix(target, s.target) || len(target) == len(s.target)):
		return false, "the fix " + fix + " does not apply to this target"
	case s.capability != "" && !slices.Contains(capabilities, s.capability):
		return false, "the node's agent cannot apply it (it lacks the capability " + s.capability + "): update the node"
	}
	return true, ""
}
