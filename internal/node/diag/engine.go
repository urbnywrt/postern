package diag

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/state"
)

// Ids of the engine checks.
const (
	IDEngineContainer = "engine.container"
	IDEngineReady     = "engine.ready"
	IDEngineDCs       = "engine.dcs"
	IDEngineLog       = "engine.log"
	IDEngineVersion   = "engine.version"
)

// Fixes the engine checks offer.
const (
	FixRecreateInstance = "recreate_instance"
	FixChangeEgress     = "change_egress"
)

const (
	// restartWindow is how far back engine.container looks for restarts; a
	// crash loop is crashLoop restarts or more within it.
	restartWindow = 10 * time.Minute
	crashLoop     = 3
	// containerLogLines and maxContainerLog bound the log a failed container
	// shows.
	containerLogLines = 20
	maxContainerLog   = MaxEvidence - 128
	// versionGrace is how long the running engine may differ from the desired
	// one (a roll under way) before engine.version warns.
	versionGrace = 10 * time.Minute
	// maxLogRead bounds what one run of engine.log reads; logWindow is how
	// long a known line it found keeps counting, firstLogRead how far back the
	// first read of a container goes.
	maxLogRead   = 64 << 10
	logWindow    = 5 * time.Minute
	firstLogRead = 10 * time.Minute
	// staleState is how long the state of a container nobody asks about is
	// kept.
	staleState = time.Hour

	hintEgressME = "the middle proxies are reached through the proxy's egress: see egress.me, and the proxy's NAT IP"
)

// EngineChecks are the checks of the engines, each with its own state (the
// restart counts engine.container keeps, the read position of engine.log).
func EngineChecks() []Check {
	rs := &restartHistory{byName: map[string][]restartSample{}}
	logs := &engineLogs{byName: map[string]*logState{}}
	return []Check{
		{ID: IDEngineContainer, Layer: LayerEngine, Light: true, Every: time.Minute, Targets: engineTargets, Run: rs.run},
		{ID: IDEngineReady, Layer: LayerEngine, Light: true, Every: time.Minute, Targets: engineTargets, Run: checkEngineReady},
		{ID: IDEngineDCs, Layer: LayerEngine, Light: true, Every: time.Minute, Targets: engineTargets, Run: checkEngineDCs},
		{ID: IDEngineLog, Layer: LayerEngine, Light: true, Every: time.Minute, Targets: engineTargets, Run: logs.run},
		{ID: IDEngineVersion, Layer: LayerEngine, Run: checkEngineVersion},
	}
}

// engineTargets are the proxies the engine checks look at: the enabled ones.
func engineTargets(env *Env) []string {
	var out []string
	for _, p := range env.Desired.GetProxies() {
		if p.GetEnabled() {
			out = append(out, ProxyTarget(p.GetId()))
		}
	}
	return out
}

// engineUnit is the serving engine of a proxy, as the runtime record has it.
type engineUnit struct {
	proxy   *nodev1.Proxy
	target  string
	rec     state.InstanceRecord
	serving bool // the record names a serving generation
	driver  engines.Driver
	name    string // its container
	in      engines.Instance
}

// engineUnits are the enabled proxies the run wants, with their serving
// engines.
func (e *Env) engineUnits() []engineUnit {
	var out []engineUnit
	for _, p := range e.Desired.GetProxies() {
		target := ProxyTarget(p.GetId())
		if !p.GetEnabled() || !e.Wants(target) {
			continue
		}
		u := engineUnit{proxy: p, target: target}
		if e.Runtime != nil {
			u.rec, u.serving = e.Runtime.Instances[p.GetId()]
			u.serving = u.serving && u.rec.Generation > 0
		}
		eng := p.GetEngine()
		if u.rec.Engine != "" {
			if v, ok := nodev1.Engine_value["ENGINE_"+strings.ToUpper(u.rec.Engine)]; ok {
				eng = nodev1.Engine(v)
			}
		}
		if eng == nodev1.Engine_ENGINE_UNSPECIFIED {
			eng = nodev1.Engine_ENGINE_TELEMT
		}
		u.driver = e.Drivers[eng]
		if u.serving {
			u.name = "postern-eng-" + strings.ToLower(p.GetId()) + "-g" + strconv.FormatUint(u.rec.Generation, 10)
			u.in = engines.Instance{
				Proxy: p, InstanceID: u.name, Generation: u.rec.Generation,
				ListenPort: u.rec.ListenPort, APIPort: u.rec.APIPort, SocksPort: u.rec.SocksPort, APIToken: u.rec.APIToken,
			}
		}
		out = append(out, u)
	}
	return out
}

var notServing = Result{Status: Skip, Summary: "no engine serves the proxy"}

// ---- engine.container --------------------------------------------------------------

type restartSample struct {
	at    time.Time
	count int
}

// restartHistory keeps the restart counts of the serving containers of the
// last restart window.
type restartHistory struct {
	mu     sync.Mutex
	byName map[string][]restartSample
}

func (h *restartHistory) run(ctx context.Context, env *Env) []Result {
	var out []Result
	for _, u := range env.engineUnits() {
		r := h.check(ctx, env, u)
		r.Target = u.target
		out = append(out, r)
	}
	return out
}

func (h *restartHistory) check(ctx context.Context, env *Env, u engineUnit) Result {
	if !u.serving {
		return Result{Status: Fail, Summary: "no engine serves the proxy", Fix: FixRecreateInstance,
			Evidence: "the runtime record has no serving generation for it", Hint: "see the proxy's status for why it has none"}
	}
	if env.Docker == nil {
		return Result{Status: Skip, Summary: "no Docker client"}
	}
	d, err := env.Docker.Inspect(ctx, u.name)
	switch {
	case errors.Is(err, dockerapi.ErrNotFound):
		return Result{Status: Fail, Summary: "the serving container " + u.name + " is missing", Fix: FixRecreateInstance,
			Evidence: err.Error()}
	case err != nil:
		return Result{Status: Skip, Summary: "Docker does not answer"}
	}
	fail := func(summary string) Result {
		return Result{Status: Fail, Summary: summary, Fix: FixRecreateInstance,
			Evidence: fmt.Sprintf("%s: state %s, exit code %d, %d restarts\nlast %d log lines:\n%s",
				u.name, d.State, d.ExitCode, d.RestartCount, containerLogLines, lastLog(ctx, env.Docker, u.name))}
	}
	switch d.State {
	case "running":
	case "paused":
		r := fail("the serving container is paused")
		r.Hint = "the reconciler leaves a paused engine alone: unpause it (docker unpause " + u.name + ") or recreate it"
		return r
	case "restarting":
		return fail("the serving container restarts in a loop")
	default:
		return fail(fmt.Sprintf("the serving container is %s (exit code %d)", d.State, d.ExitCode))
	}

	now := env.now()
	h.mu.Lock()
	for name, ss := range h.byName {
		if name != u.name && (len(ss) == 0 || now.Sub(ss[len(ss)-1].at) > staleState) {
			delete(h.byName, name) // a generation gone long ago
		}
	}
	samples := h.byName[u.name]
	var base *restartSample
	kept := samples[:0]
	for i := range samples {
		s := samples[i]
		if now.Sub(s.at) > restartWindow || s.at.After(now) || s.count > d.RestartCount {
			continue
		}
		kept = append(kept, s)
	}
	if len(kept) > 0 {
		base = &kept[0]
	}
	h.byName[u.name] = append(kept, restartSample{now, d.RestartCount})
	h.mu.Unlock()

	switch {
	case base != nil && d.RestartCount-base.count >= crashLoop:
		return fail(fmt.Sprintf("the serving container restarted %d times in %s: a crash loop", d.RestartCount-base.count, now.Sub(base.at).Round(time.Second)))
	case base != nil && d.RestartCount > base.count:
		return Result{Status: Warn, Summary: fmt.Sprintf("the serving container restarted %d times in the last %s", d.RestartCount-base.count, restartWindow),
			Evidence: fmt.Sprintf("%s: %d restarts, started %s\nlast %d log lines:\n%s", u.name, d.RestartCount,
				d.StartedAt.UTC().Format(time.RFC3339), containerLogLines, lastLog(ctx, env.Docker, u.name))}
	case base == nil && d.RestartCount > 0 && !d.StartedAt.IsZero() && now.Sub(d.StartedAt) < restartWindow:
		return Result{Status: Warn, Summary: "the serving container restarted " + now.Sub(d.StartedAt).Round(time.Second).String() + " ago",
			Evidence: fmt.Sprintf("%s: %d restarts, started %s\nlast %d log lines:\n%s", u.name, d.RestartCount,
				d.StartedAt.UTC().Format(time.RFC3339), containerLogLines, lastLog(ctx, env.Docker, u.name))}
	}
	return Result{Status: OK, Summary: "the serving container " + u.name + " runs"}
}

// lastLog is the end of a container's log, without colours, for evidence (the
// runner scrubs it and redacts its addresses).
func lastLog(ctx context.Context, docker dockerapi.Client, name string) string {
	rc, err := docker.Logs(ctx, name, containerLogLines, false)
	if err != nil {
		return "(the log cannot be read)"
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
	s := stripANSI(string(b))
	if len(s) > maxContainerLog {
		s = s[len(s)-maxContainerLog:]
	}
	return s
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func stripANSI(s string) string { return ansiEscape.ReplaceAllString(s, "") }

// ---- engine.ready -----------------------------------------------------------------

func checkEngineReady(ctx context.Context, env *Env) []Result {
	var out []Result
	for _, u := range env.engineUnits() {
		r := Result{Target: u.target}
		switch {
		case !u.serving:
			r = notServing
			r.Target = u.target
		case u.driver == nil:
			r.Status, r.Summary = Skip, "the node has no driver for the engine"
		default:
			if err := u.driver.Ready(ctx, u.in); err != nil {
				r.Status, r.Summary, r.Evidence, r.Fix = Fail, "the engine is not ready", err.Error(), FixRecreateInstance
			} else {
				r.Status, r.Summary = OK, "the engine is ready"
			}
		}
		out = append(out, r)
	}
	return out
}

// ---- engine.dcs -------------------------------------------------------------------

func checkEngineDCs(ctx context.Context, env *Env) []Result {
	var out []Result
	for _, u := range env.engineUnits() {
		var r Result
		hr, ok := u.driver.(engines.HealthReporter)
		switch {
		case !u.serving:
			r = notServing
		case !u.proxy.GetUseMiddleProxy():
			r = Result{Status: Skip, Summary: "the proxy does not use the middle proxies"}
		case !ok:
			r = Result{Status: Skip, Summary: "the engine does not report its datacenters"}
		default:
			h, err := hr.Health(ctx, u.in)
			if err != nil {
				r = Result{Status: Skip, Summary: "the engine's API does not tell its datacenters (see engine.ready)"}
			} else {
				r = DCsResult(h)
			}
		}
		r.Target = u.target
		out = append(out, r)
	}
	return out
}

// DCsResult judges what an engine says of its middle proxies: off, or no
// snapshot yet, is skip (never fail). Otherwise only the coverage of the
// writers (coverage_pct) counts: every datacenter at 100 % is ok, every one
// at 0 is fail, anything between is warn. Neither the share of endpoints that
// hold a writer nor the fresh coverage changes the status, they are evidence
// only: telemt keeps all the writers a datacenter needs on one endpoint and
// leaves the others idle, and a covered datacenter with writers not seen
// lately still serves.
func DCsResult(h engines.EngineHealth) Result {
	if !h.MiddleProxy {
		why := "the middle proxies are off"
		switch h.Reason {
		case "feature_disabled":
			why = "the engine's runtime statistics are off"
		case "source_unavailable":
			why = "the middle proxies have not started yet (no snapshot)"
		}
		return Result{Status: Skip, Summary: why}
	}
	if len(h.DCs) == 0 {
		return Result{Status: Skip, Summary: "the snapshot has no datacenter"}
	}
	full, zero := true, true
	var lines []string
	for _, dc := range h.DCs {
		if dc.CoveragePct < 100 {
			full = false
		}
		if dc.CoveragePct > 0 {
			zero = false
		}
		line := fmt.Sprintf("DC %d: %d endpoints in use (%.0f %%), writers %.0f %% covered", dc.DC, dc.AvailableEndpoints, dc.AvailablePct, dc.CoveragePct)
		if dc.HasFreshCoverage {
			line += fmt.Sprintf(" (fresh %.0f %%)", dc.FreshCoveragePct)
		}
		lines = append(lines, line)
	}
	r := Result{Evidence: strings.Join(lines, "\n"), Hint: hintEgressME}
	switch {
	case full:
		r.Status, r.Summary, r.Hint = OK, fmt.Sprintf("the middle proxies of all %d datacenters are covered", len(h.DCs)), ""
	case zero:
		r.Status, r.Summary = Fail, "no middle proxy of any datacenter is available"
	default:
		r.Status, r.Summary = Warn, "some datacenters are not fully covered"
	}
	return r
}

// ---- engine.version ---------------------------------------------------------------

func checkEngineVersion(_ context.Context, env *Env) []Result {
	var since time.Time
	if env.Store != nil {
		since, _ = env.Store.DesiredModTime()
	}
	now := env.now()
	var out []Result
	for _, u := range env.engineUnits() {
		r := Result{Target: u.target}
		want := strings.ToLower(strings.TrimPrefix(u.proxy.GetEngine().String(), "ENGINE_"))
		if u.proxy.GetEngine() == nodev1.Engine_ENGINE_UNSPECIFIED {
			want = "telemt"
		}
		wantVersion := u.proxy.GetEngineVersion()
		switch {
		case !u.serving:
			r = notServing
			r.Target = u.target
		case wantVersion == "" || (u.rec.Engine == want && u.rec.Version == wantVersion):
			r.Status, r.Summary = OK, fmt.Sprintf("runs %s %s, as desired", u.rec.Engine, u.rec.Version)
		case since.IsZero() || now.Sub(since) <= versionGrace:
			r.Status, r.Summary = OK, fmt.Sprintf("runs %s %s; a roll to %s %s is under way", u.rec.Engine, u.rec.Version, want, wantVersion)
		default:
			r.Status = Warn
			r.Summary = fmt.Sprintf("runs %s %s, but %s %s is desired for %s", u.rec.Engine, u.rec.Version, want, wantVersion, now.Sub(since).Round(time.Minute))
			r.Evidence = fmt.Sprintf("serving generation %d: %s %s; desired since %s: %s %s", u.rec.Generation, u.rec.Engine, u.rec.Version,
				since.UTC().Format(time.RFC3339), want, wantVersion)
			r.Hint = "the roll did not complete: see the proxy's status (failed engine and version) and the node's events"
		}
		out = append(out, r)
	}
	return out
}

// ---- engine.log -------------------------------------------------------------------

// logPattern maps a known line of an engine's log to a cause.
type logPattern struct {
	match  string
	status nodev1.CheckStatus
	cause  string
	hint   string
	fix    string
}

// telemtPatterns are the known warning and error lines of telemt 3.5.13 (its
// sources; the first two from the spec), worst first.
var telemtPatterns = []logPattern{
	{"All ME servers for DC failed", Fail, "the middle proxies of a datacenter cannot be reached", hintEgressME, FixChangeEgress},
	{"proxy-secret is unavailable", Fail, "getProxySecret fails: the middle-proxy secret cannot be fetched", hintEgressME, FixChangeEgress},
	{"ME pool init retries exhausted", Fail, "the middle-proxy pool could not start", hintEgressME, FixChangeEgress},
	{"Failed to bind", Fail, "the engine cannot bind its port", "another process may hold it: see host.ports", FixRecreateInstance},
	{"Proxy-secret download failed", Warn, "the middle-proxy secret could not be downloaded; a cached one is used", hintEgressME, FixChangeEgress},
	{"Single-endpoint DC outage detected", Warn, "the middle proxy of a datacenter is down", hintEgressME, FixChangeEgress},
	{"ME pool is not ready yet", Warn, "the middle-proxy pool is not ready yet", hintEgressME, ""},
	{"Upstream marked unhealthy", Warn, "the route through the edge's SOCKS port fails", "the proxy's egress does not carry: see egress.member and egress.dc", FixChangeEgress},
	{"No healthy upstreams available", Warn, "the route through the edge's SOCKS port fails", "the proxy's egress does not carry: see egress.member and egress.dc", FixChangeEgress},
	{"TLS-front fetch not ready within timeout", Warn, "the certificate of the proxy's domain could not be fetched; a default one is used",
		"check that the proxy's domain answers TLS on 443 through its egress", ""},
	{"Time skew >", Warn, "the engine finds the clock off against Telegram's servers", "see host.clock", ""},
}

// patternsOf are the known lines of an engine; nil: no log check.
func patternsOf(e nodev1.Engine) []logPattern {
	if e == nodev1.Engine_ENGINE_TELEMT {
		return telemtPatterns
	}
	return nil
}

// logState is what engine.log keeps of one container: where it read to, and
// when it last saw each known line and other warning or error lines.
type logState struct {
	cursor  time.Time
	seen    map[int]time.Time
	counts  map[int]int
	unknown []time.Time
}

type engineLogs struct {
	mu     sync.Mutex
	byName map[string]*logState
}

func (l *engineLogs) run(ctx context.Context, env *Env) []Result {
	var out []Result
	live := map[string]bool{}
	for _, u := range env.engineUnits() {
		live[u.name] = true
		r := l.check(ctx, env, u)
		r.Target = u.target
		out = append(out, r)
	}
	if env.Only == "" && env.scope.proxy == "" {
		// A run of every target: forget the containers that no longer serve.
		l.mu.Lock()
		for name := range l.byName {
			if !live[name] {
				delete(l.byName, name)
			}
		}
		l.mu.Unlock()
	}
	return out
}

func (l *engineLogs) check(ctx context.Context, env *Env, u engineUnit) Result {
	if !u.serving {
		return notServing
	}
	if u.driver == nil {
		return Result{Status: Skip, Summary: "the node has no driver for the engine"}
	}
	leveler, ok := u.driver.(engines.LogLeveler)
	patterns := patternsOf(u.driver.Engine())
	if !ok || patterns == nil {
		return Result{Status: Skip, Summary: "the engine's log is not checked"}
	}
	if env.Docker == nil {
		return Result{Status: Skip, Summary: "no Docker client"}
	}
	d, err := env.Docker.Inspect(ctx, u.name)
	if err != nil {
		return Result{Status: Skip, Summary: "the serving container cannot be inspected (see engine.container)"}
	}
	for _, kv := range leveler.LogEnv() {
		if !slices.Contains(d.Env, kv) {
			return Result{Status: Skip, Summary: "this generation logs at the silent level until its next roll"}
		}
	}
	now := env.now()

	l.mu.Lock()
	for name, s := range l.byName {
		if name != u.name && now.Sub(s.cursor) > staleState {
			delete(l.byName, name) // a generation gone long ago
		}
	}
	st := l.byName[u.name]
	if st == nil {
		st = &logState{seen: map[int]time.Time{}, counts: map[int]int{}}
		st.cursor = now.Add(-firstLogRead)
		if d.StartedAt.After(st.cursor) {
			st.cursor = d.StartedAt
		}
		l.byName[u.name] = st
	}
	cursor := st.cursor
	l.mu.Unlock()

	rc, err := env.Docker.LogsSince(ctx, u.name, cursor)
	if err != nil {
		return Result{Status: Skip, Summary: "the log cannot be read"}
	}
	data, _ := io.ReadAll(io.LimitReader(rc, maxLogRead))
	_ = rc.Close()
	lines := scanLog(data, len(data) >= maxLogRead)

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ln := range lines {
		if !ln.at.Before(st.cursor) {
			st.cursor = ln.at.Add(time.Nanosecond)
		}
		if ln.level != "WARN" && ln.level != "ERROR" {
			continue
		}
		known := false
		for i, p := range patterns {
			if strings.Contains(ln.text, p.match) {
				st.seen[i], known = now, true
				st.counts[i]++
				break
			}
		}
		if !known {
			st.unknown = append(st.unknown, now)
		}
	}
	return st.result(now, patterns)
}

// result is the worst known line seen in the last logWindow, with the counts.
func (st *logState) result(now time.Time, patterns []logPattern) Result {
	for i, at := range st.seen {
		if now.Sub(at) > logWindow {
			delete(st.seen, i)
			delete(st.counts, i)
		}
	}
	st.unknown = slices.DeleteFunc(st.unknown, func(at time.Time) bool { return now.Sub(at) > logWindow })
	worst := -1
	var lines []string
	for i, p := range patterns { // worst first
		if _, ok := st.seen[i]; !ok {
			continue
		}
		if worst < 0 || p.status == Fail && patterns[worst].status != Fail {
			worst = i
		}
		lines = append(lines, fmt.Sprintf("%d× %s (%q)", st.counts[i], p.cause, p.match))
	}
	other := ""
	if n := len(st.unknown); n > 0 {
		other = fmt.Sprintf("%d other warning or error lines in the last %s (not quoted)", n, logWindow)
	}
	if worst < 0 {
		r := Result{Status: OK, Summary: "no known problem line in the engine's log"}
		if other != "" {
			r.Summary += "; " + other
		}
		return r
	}
	p := patterns[worst]
	if other != "" {
		lines = append(lines, other)
	}
	return Result{Status: p.status, Summary: "the engine's log: " + p.cause, Evidence: strings.Join(lines, "\n"), Hint: p.hint, Fix: p.fix}
}

// logLine is a line of a container's log as LogsSince gives it.
type logLine struct {
	at    time.Time
	level string
	text  string
}

// scanLog reads "<RFC 3339 time> <text>" lines; the last one is left out
// when cut (the read stopped at its bound). The level is the first word of
// the text without colours (telemt: "2026-...Z  WARN target: message").
func scanLog(data []byte, cut bool) []logLine {
	if cut {
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		}
	}
	var out []logLine
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxLogRead)
	for sc.Scan() {
		ts, rest, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		text := stripANSI(rest)
		f := strings.Fields(text)
		level := ""
		for _, w := range f[:min(len(f), 2)] {
			switch w {
			case "TRACE", "DEBUG", "INFO", "WARN", "ERROR":
				level = w
			}
		}
		out = append(out, logLine{at: at, level: level, text: text})
	}
	return out
}
