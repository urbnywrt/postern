package diag

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/node/state"
)

// Ids of the egress checks.
const (
	IDEgressMember = "egress.member"
	IDEgressDC     = "egress.dc"
	IDEgressME     = "egress.me"
)

// FixRefreshSubscription is the fix of a down member of a subscription.
const FixRefreshSubscription = "refresh_subscription"

const (
	// egressDCTimeout bounds egress.dc for one proxy, egressPerDC the
	// question to one datacenter (as the gate: 30 s, 10 s).
	egressDCTimeout = 30 * time.Second
	egressPerDC     = 10 * time.Second
	// egressMETimeout bounds egress.me for one proxy.
	egressMETimeout = 20 * time.Second
	// unitsTimeout bounds a check that asks every proxy, each under its own
	// deadline: what is left of a full run (RunTimeout) after the first
	// minute. A proxy not answered within it is "not checked in time".
	unitsTimeout = RunTimeout - time.Minute
	// instanceGrace is how long a provider's egress without an instance
	// warns before egress.member treats it as down (an instance starting).
	instanceGrace = 2 * time.Minute
	// egressParallel is how many proxies egress.dc and egress.me ask at once.
	egressParallel = 8

	hintMember   = "the edge checks every member against the datacenters and its exit IP through the echo URLs; see the provider's log"
	hintArtifact = "the panel delivers the provider's binary from its release catalog: see the panel's versions; a panel that is no published release takes psiphon-core in a release bundle (docs/releasing.md)"
	hintWayOut   = "the proxy's chain does not reach Telegram: see egress.member for its members, or move the proxy to another chain"
	memberKeySep = "/" // <egress id>/<member key> of a provider's member
	notSOCKS     = "no engine serves the proxy through a SOCKS port"
	notInTime    = "not checked in time: the check ran out of time before this target"
)

// EgressChecks are the checks of the ways out.
func EgressChecks() []Check {
	return []Check{
		{ID: IDEgressMember, Layer: LayerEgress, Light: true, Every: time.Minute, Targets: memberTargets, Run: (&memberCheck{}).run},
		{ID: IDEgressDC, Layer: LayerEgress, Timeout: unitsTimeout, Run: checkEgressDC},
		{ID: IDEgressME, Layer: LayerEgress, Timeout: unitsTimeout, Run: checkEgressME},
	}
}

// ---- egress.member -----------------------------------------------------------------

// member is a member of a chain in use, as the edge knows it.
type member struct {
	chain, key string
	egress     *nodev1.Egress
	// noInstance: a provider's egress that no instance serves, so the edge
	// has no member for it; key is then the egress id.
	noInstance bool
}

func (m member) target() string { return MemberTarget(m.chain, m.key) }

// usedChains are the chains of the enabled proxies (their own or the node's
// default, and their scope chains) and the node's default chain, sorted.
func usedChains(st *nodev1.NodeState) []string {
	used := map[string]bool{}
	def := st.GetSettings().GetDefaultChainId()
	if def != "" {
		used[def] = true
	}
	for _, p := range st.GetProxies() {
		if !p.GetEnabled() {
			continue
		}
		if c := p.GetEgressChainId(); c != "" {
			used[c] = true
		}
		for _, c := range p.GetEgressScopeChains() {
			if c != "" {
				used[c] = true
			}
		}
	}
	out := make([]string, 0, len(used))
	for c := range used {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// members are the members of the chains in use, in the order of their chains:
// an egress the edge dials itself is one member keyed by its id; a provider's
// egress has a member per member of its serving instance, keyed
// <egress id>/<member key>, or, with no instance, one placeholder.
func (e *Env) members() []member {
	egresses := map[string]*nodev1.Egress{}
	for _, eg := range e.Desired.GetEgresses() {
		egresses[eg.GetId()] = eg
	}
	chains := map[string]*nodev1.EgressChain{}
	for _, c := range e.Desired.GetChains() {
		chains[c.GetId()] = c
	}
	var out []member
	seen := map[string]bool{}
	add := func(m member) {
		if !seen[m.target()] {
			seen[m.target()] = true
			out = append(out, m)
		}
	}
	for _, cid := range usedChains(e.Desired) {
		for _, id := range chains[cid].GetMemberEgressIds() {
			eg := egresses[id]
			if eg == nil {
				continue
			}
			if !isProvider(eg.GetKind()) {
				add(member{chain: cid, key: id, egress: eg})
				continue
			}
			var rec state.EgressRecord
			if e.Runtime != nil {
				rec = e.Runtime.Egresses[id]
			}
			if rec.Generation == 0 || len(rec.Members) == 0 {
				add(member{chain: cid, key: id, egress: eg, noInstance: true})
				continue
			}
			for _, m := range rec.Members {
				add(member{chain: cid, key: id + memberKeySep + m.Key, egress: eg})
			}
		}
	}
	return out
}

// artifactMissing starts the reason of an egress whose provider binary is not
// on the node (reconcile.resolveProviderArtifact).
const artifactMissing = "artifact missing:"

// egressReason is why the instance of the egress id does not start, as the
// reconciler last reported it; "" when it does not say.
func (e *Env) egressReason(id string) string {
	if e.EgressReason == nil {
		return ""
	}
	return e.EgressReason(id)
}

func isProvider(k nodev1.EgressKind) bool {
	switch k {
	case nodev1.EgressKind_EGRESS_KIND_XRAY_URI, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
		nodev1.EgressKind_EGRESS_KIND_WARP, nodev1.EgressKind_EGRESS_KIND_PSIPHON:
		return true
	}
	return false
}

// memberTargets are the targets of egress.member.
func memberTargets(env *Env) []string {
	var out []string
	for _, m := range env.members() {
		out = append(out, m.target())
	}
	return out
}

// memberCheck is egress.member, with when each provider's egress was first
// seen without an instance.
type memberCheck struct {
	mu      sync.Mutex
	missing map[string]time.Time // egress id -> first seen without an instance
}

// sinceMissing records the egresses of all without an instance at now, forgets
// the others, and returns when each was first seen so.
func (c *memberCheck) sinceMissing(all []member, now time.Time) map[string]time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.missing == nil {
		c.missing = map[string]time.Time{}
	}
	still := map[string]bool{}
	for _, m := range all {
		if m.noInstance {
			id := m.egress.GetId()
			still[id] = true
			if _, ok := c.missing[id]; !ok {
				c.missing[id] = now
			}
		}
	}
	out := map[string]time.Time{}
	for id, at := range c.missing {
		if !still[id] {
			delete(c.missing, id)
			continue
		}
		out[id] = at
	}
	return out
}

// run is egress.member: each member as the edge's health check last saw it
// (status, latency, exit IP, the age of the check). Down is a warning while
// another member of its chain is up, which carries the traffic, and a failure
// when none is. A provider's egress without an instance warns for
// instanceGrace (its instance may be starting), then counts as down.
func (c *memberCheck) run(ctx context.Context, env *Env) []Result {
	all := env.members()
	var want []member
	for _, m := range all {
		if env.Wants(m.target()) {
			want = append(want, m)
		}
	}
	missingSince := c.sinceMissing(all, env.now())
	if len(want) == 0 {
		return nil
	}
	skipAll := func(summary string) []Result {
		out := make([]Result, 0, len(want))
		for _, m := range want {
			out = append(out, Result{Target: m.target(), Status: Skip, Summary: summary})
		}
		return out
	}
	ec := env.edge()
	if ec == nil {
		return skipAll("no edge runs, so no member health is known")
	}
	snap, err := ec.Snapshot(ctx)
	if err != nil {
		return skipAll("the edge does not answer, so no member health is known")
	}
	byChain := map[string][]*edgev1.MemberHealth{}
	health := map[string]*edgev1.MemberHealth{}
	for _, h := range snap.GetHealth() {
		byChain[h.GetChainId()] = append(byChain[h.GetChainId()], h)
		health[MemberTarget(h.GetChainId(), h.GetMemberKey())] = h
	}
	now := env.now()
	out := make([]Result, 0, len(want))
	for _, m := range want {
		r := Result{Target: m.target()}
		h := health[m.target()]
		down := false
		why := ""
		if m.noInstance {
			why = env.egressReason(m.egress.GetId())
		}
		switch {
		case why != "":
			// The node knows why the instance does not start: no grace.
			down = true
			r.Summary = "the instance of the provider cannot start: " + why
		case m.noInstance && now.Sub(missingSince[m.egress.GetId()]) < instanceGrace:
			r.Status = Warn
			r.Summary = "no instance of the provider serves the egress yet (for " + now.Sub(missingSince[m.egress.GetId()]).Truncate(time.Second).String() + "); it may be starting"
			r.Evidence = "the chain has no member for the egress until its instance runs"
		case m.noInstance:
			down = true
			r.Summary = "no instance of the provider serves the egress, so the chain has no member for it"
		case h == nil:
			r.Status, r.Summary = Skip, "the edge has not reported the member yet"
		case h.GetStatus() == "up":
			r.Status = OK
			r.Summary = fmt.Sprintf("up, %d ms, exit %s, checked %s", h.GetLatencyMs(), orUnknown(h.GetExitIp()), age(now, h.GetCheckedUnix()))
			if a, err := netip.ParseAddr(h.GetExitIp()); err == nil {
				r.keep = a
			}
		case h.GetStatus() == "down":
			down = true
			r.Summary = "down, checked " + age(now, h.GetCheckedUnix())
		default:
			r.Status, r.Summary = Skip, "not checked yet (status "+orUnknown(h.GetStatus())+")"
		}
		if down {
			r.Status, r.Hint = Fail, hintMember
			if siblingUp(byChain[m.chain], m.key) {
				r.Status = Warn
				r.Summary += "; another member of the chain is up and carries the traffic"
			} else {
				r.Summary += "; no member of the chain is up"
			}
			r.Evidence = chainEvidence(byChain[m.chain], now)
			if m.egress.GetKind() == nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION {
				r.Fix = FixRefreshSubscription
			}
			if strings.HasPrefix(why, artifactMissing) {
				r.Hint = hintArtifact
			}
		}
		out = append(out, r)
	}
	return out
}

func siblingUp(hs []*edgev1.MemberHealth, key string) bool {
	for _, h := range hs {
		if h.GetMemberKey() != key && h.GetStatus() == "up" {
			return true
		}
	}
	return false
}

// chainEvidence lists the members of a chain as the edge reports them. Exit
// IPs are left out: they would be redacted.
func chainEvidence(hs []*edgev1.MemberHealth, now time.Time) string {
	if len(hs) == 0 {
		return "the edge reports no member of the chain"
	}
	var b strings.Builder
	b.WriteString("members of the chain:\n")
	for _, h := range hs {
		fmt.Fprintf(&b, "%s: %s, checked %s\n", h.GetMemberKey(), orUnknown(h.GetStatus()), age(now, h.GetCheckedUnix()))
	}
	return b.String()
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// age is how long ago the Unix time at was, in whole seconds.
func age(now time.Time, at int64) string {
	if at <= 0 {
		return "never"
	}
	d := max(now.Sub(time.Unix(at, 0)).Truncate(time.Second), 0)
	return d.String() + " ago"
}

// ---- egress.dc and egress.me -------------------------------------------------------

// socksUnits are the enabled proxies the run wants with the SOCKS port of
// their serving engine ("" when none serves).
func (e *Env) socksUnits(only func(*nodev1.Proxy) bool) []socksUnit {
	var units []socksUnit
	for _, u := range e.engineUnits() {
		if only != nil && !only(u.proxy) {
			continue
		}
		addr := ""
		if u.serving && u.rec.SocksPort != 0 {
			addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(u.rec.SocksPort)))
		}
		units = append(units, socksUnit{u, addr})
	}
	return units
}

// eachUnit runs fn for every unit, limit at a time, each under its own
// deadline per taken from ctx, and returns the results in the order of the
// units. A unit that did not pass before ctx ended (the check's time ran out)
// is "not checked in time": a skip, never a failure.
func eachUnit[U any](ctx context.Context, units []U, limit int, per time.Duration, target func(U) string, fn func(ctx context.Context, u U) Result) []Result {
	out := make([]Result, len(units))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := range units {
		taken := false
		select {
		case sem <- struct{}{}:
			taken = true
		case <-ctx.Done():
		}
		wg.Go(func() {
			r := Result{Status: Skip}
			if taken {
				if ctx.Err() == nil {
					uctx, cancel := context.WithTimeout(ctx, per)
					r = fn(uctx, units[i])
					cancel()
				}
				<-sem
			}
			if ctx.Err() != nil && r.Status != OK {
				r = Result{Status: Skip, Summary: notInTime}
			}
			r.Target = target(units[i])
			out[i] = r
		})
	}
	wg.Wait()
	return out
}

// socksUnit is a proxy with the SOCKS port of its serving engine.
type socksUnit struct {
	engineUnit
	socks string // "" when no engine serves the proxy through one
}

func (u socksUnit) tgt() string { return u.target }

// checkEgressDC is egress.dc: a datacenter answers req_pq_multi with its resPQ
// through the SOCKS port of the proxy's serving engine (the edge and the
// proxy's chain), the datacenters of the chain's check in turn until one
// answers.
func checkEgressDC(ctx context.Context, env *Env) []Result {
	units := env.socksUnits(nil)
	return eachUnit(ctx, units, egressParallel, egressDCTimeout, socksUnit.tgt, func(ctx context.Context, u socksUnit) Result {
		addr := u.socks
		if addr == "" {
			return Result{Status: Skip, Summary: notSOCKS}
		}
		if env.PingDC == nil {
			return Result{Status: Skip, Summary: "the datacenter check is not available"}
		}
		dcs := egress.DefaultHealthCheck().GetDcAddrs()
		if env.ProxyDCs != nil {
			dcs = env.ProxyDCs(env.Desired, u.proxy)
		}
		var ev strings.Builder
		for _, dc := range dcs {
			start := time.Now()
			dctx, cancel := context.WithTimeout(ctx, egressPerDC)
			err := env.PingDC(dctx, addr, dc)
			cancel()
			if err == nil {
				return Result{Status: OK, Summary: fmt.Sprintf("%s answered resPQ through the proxy's SOCKS port in %d ms", dc, time.Since(start).Milliseconds())}
			}
			fmt.Fprintf(&ev, "%s: %v\n", dc, err)
			if ctx.Err() != nil {
				ev.WriteString("the time for this proxy ran out\n")
				break
			}
		}
		return Result{Status: Fail, Summary: "no datacenter answered through the proxy's SOCKS port", Evidence: ev.String(),
			Hint: hintWayOut, Fix: FixChangeEgress}
	})
}

// checkEgressME is egress.me, for the proxies with the middle proxies: an
// HTTPS GET of getProxySecret through the SOCKS port of the serving engine
// answers 200, which the engine needs for the middle proxies.
func checkEgressME(ctx context.Context, env *Env) []Result {
	units := env.socksUnits(func(p *nodev1.Proxy) bool { return p.GetUseMiddleProxy() })
	return eachUnit(ctx, units, egressParallel, egressMETimeout, socksUnit.tgt, func(ctx context.Context, u socksUnit) Result {
		addr := u.socks
		if addr == "" {
			return Result{Status: Skip, Summary: notSOCKS}
		}
		if env.ProxySecret == nil {
			return Result{Status: Skip, Summary: "the check of the proxy secret is not available"}
		}
		start := time.Now()
		if err := env.ProxySecret(ctx, addr); err != nil {
			return Result{Status: Fail, Summary: "getProxySecret does not come through the proxy's SOCKS port", Evidence: err.Error(),
				Hint: "the engine fetches the proxy secret for the middle proxies through the proxy's chain; " + hintWayOut, Fix: FixChangeEgress}
		}
		return Result{Status: OK, Summary: fmt.Sprintf("getProxySecret answered 200 through the proxy's SOCKS port in %d ms", time.Since(start).Milliseconds())}
	})
}
