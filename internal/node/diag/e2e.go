package diag

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/probe"
)

// Ids of the end-to-end checks.
const (
	IDE2EL1 = "e2e.l1"
	IDE2EL2 = "e2e.l2"
)

const (
	// probeTimeout bounds one probe; l1Timeout and l2Timeout one proxy of
	// the checks (L2 and, when it fails, the L1 that classifies it).
	probeTimeout = 10 * time.Second
	l1Timeout    = probeTimeout + 2*time.Second
	l2Timeout    = 2*probeTimeout + 2*time.Second
	// e2eParallel is how many proxies e2e.l1 and e2e.l2 probe at once.
	e2eParallel = 4
	// l2DC is the datacenter L2 asks for, as the panel's probes do.
	l2DC = 2
	// ProbeKindL2 is the kind of the probe result e2e.l2 hands over.
	ProbeKindL2 = "l2"
	// maxProbeError bounds the error of a probe result.
	maxProbeError = 256
)

// E2EChecks are the end-to-end checks: a client's view through the test
// listener of the proxy's listener, the loopback twin of the listener that
// takes no PROXY header and leads the proxy's domain to its serving engine.
func E2EChecks() []Check {
	return []Check{
		{ID: IDE2EL1, Layer: LayerE2E, Light: true, Every: time.Minute, Timeout: unitsTimeout, Targets: e2eTargets, Run: checkL1},
		{ID: IDE2EL2, Layer: LayerE2E, Light: true, Every: 10 * time.Minute, Timeout: unitsTimeout, Targets: e2eTargets, Run: checkL2},
	}
}

// e2eTargets are the enabled fake-TLS proxies (a WEB proxy speaks HTTP; its
// checks are web.*).
func e2eTargets(env *Env) []string {
	var out []string
	for _, p := range env.Desired.GetProxies() {
		if p.GetEnabled() && p.GetType() != nodev1.ProxyType_PROXY_TYPE_WEB {
			out = append(out, ProxyTarget(p.GetId()))
		}
	}
	return out
}

// e2eUnit is a proxy to probe: the address of its test listener, its domain
// and secret; or the reason it cannot be probed (skip).
type e2eUnit struct {
	proxy  *nodev1.Proxy
	target string
	addr   string
	secret []byte
	skip   string
}

func (u e2eUnit) tgt() string { return u.target }

func (e *Env) e2eUnits() []e2eUnit {
	var out []e2eUnit
	for _, u := range e.engineUnits() {
		if u.proxy.GetType() == nodev1.ProxyType_PROXY_TYPE_WEB {
			continue
		}
		eu := e2eUnit{proxy: u.proxy, target: u.target}
		var port uint16
		if e.Runtime != nil {
			port = e.Runtime.Ports[state.TestListenerPortKey(u.proxy.GetListenerId())]
		}
		secret, err := hex.DecodeString(u.proxy.GetSecret())
		switch {
		case !u.serving:
			eu.skip = notServing.Summary
		case port == 0:
			eu.skip = "the proxy's listener has no test listener yet"
		case err != nil || len(secret) != 16:
			eu.skip = "the proxy's secret is not 16 bytes of hex"
		default:
			eu.addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
			eu.secret = secret
		}
		out = append(out, eu)
	}
	return out
}

func (e *Env) l1(ctx context.Context, u e2eUnit) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if e.L1 != nil {
		return e.L1(ctx, u.addr, u.proxy.GetDomain(), u.secret)
	}
	return probe.FakeTLS(ctx, u.addr, u.proxy.GetDomain(), u.secret, probe.Options{Timeout: probeTimeout, Now: e.Now})
}

func (e *Env) l2(ctx context.Context, u e2eUnit) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if e.L2 != nil {
		return e.L2(ctx, u.addr, u.proxy.GetDomain(), u.secret, l2DC)
	}
	return probe.L2(ctx, u.addr, u.proxy.GetDomain(), u.secret, l2DC, probe.Options{Timeout: probeTimeout, Now: e.Now})
}

// checkL1 is e2e.l1: the fake-TLS handshake through the test listener proves
// the edge's route, the engine and its secret.
func checkL1(ctx context.Context, env *Env) []Result {
	return eachUnit(ctx, env.e2eUnits(), e2eParallel, l1Timeout, e2eUnit.tgt, func(ctx context.Context, u e2eUnit) Result {
		if u.skip != "" {
			return Result{Status: Skip, Summary: u.skip}
		}
		start := time.Now()
		if err := env.l1(ctx, u); err != nil {
			return Result{Status: Fail, Summary: "the fake-TLS handshake through the edge's test listener fails", Evidence: err.Error(),
				Hint: "the edge's route or the engine does not answer with the proxy's secret: see engine.container and engine.ready", Fix: FixRecreateInstance}
		}
		return Result{Status: OK, Summary: fmt.Sprintf("the fake-TLS handshake through the edge's test listener passes in %d ms", time.Since(start).Milliseconds())}
	})
}

// checkL2 is e2e.l2: one L2 probe through the test listener to DC 2, a
// client's view of the whole way; its result goes to the statistics as a
// probe of kind l2. A failure is classified with L1: the way out (fix
// change_egress) when L1 passes, the edge or the engine when it fails too.
// A probe cut short by the time of the check is not checked: it gives no
// result to the statistics.
func checkL2(ctx context.Context, env *Env) []Result {
	return eachUnit(ctx, env.e2eUnits(), e2eParallel, l2Timeout, e2eUnit.tgt, func(ctx context.Context, u e2eUnit) Result {
		if u.skip != "" {
			return Result{Status: Skip, Summary: u.skip}
		}
		start := time.Now()
		err := env.l2(ctx, u)
		took := time.Since(start)
		if err != nil && ctx.Err() != nil {
			return Result{Status: Skip, Summary: notInTime}
		}
		env.handProbe(u.proxy.GetId(), took, err)
		if err == nil {
			return Result{Status: OK, Summary: fmt.Sprintf("L2 through the edge's test listener: DC%d answered in %d ms", l2DC, took.Milliseconds())}
		}
		r := Result{Status: Fail, Evidence: err.Error()}
		switch l1 := env.l1(ctx, u); {
		case l1 == nil:
			r.Summary = fmt.Sprintf("L2 to DC%d fails while L1 passes: the way out does not reach Telegram", l2DC)
			r.Hint, r.Fix = "see egress.dc and egress.member; "+hintWayOut, FixChangeEgress
		case ctx.Err() != nil:
			r.Summary = fmt.Sprintf("L2 to DC%d fails; no time was left to tell why with L1", l2DC)
			r.Hint = "see " + IDE2EL1 + " and egress.dc"
		default:
			r.Summary = fmt.Sprintf("L2 to DC%d fails, and so does L1", l2DC)
			r.Hint = "the edge or the engine does not answer: see " + IDE2EL1
		}
		return r
	})
}

// handProbe gives the statistics the result of an L2 probe, its error
// scrubbed as the texts of a result are.
func (e *Env) handProbe(proxyID string, took time.Duration, err error) {
	if e.AddProbe == nil {
		return
	}
	p := &nodev1.ProbeResult{ProxyId: proxyID, Kind: ProbeKindL2, Ok: err == nil,
		LatencyMs: uint32(min(max(took.Milliseconds(), 0), 1<<31)), AtUnix: e.now().Unix()}
	if err != nil {
		p.Error = clip(e.Scrub.Clean(err.Error()), maxProbeError, true)
	}
	e.AddProbe(p)
}
