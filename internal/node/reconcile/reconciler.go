// Package reconcile converges the node to its desired state: the edge
// container that carries the traffic, one provider container per egress of
// Xray or Psiphon that a chain in use takes, one engine container per proxy,
// and the edge's routing table.
//
// One worker does all the work (Run). A pass reads the desired state and the
// runtime record from disk, writes in DNS mode doh the resolv.conf that names
// the edge's DNS forwarder (the engines and the providers mount it at
// /etc/resolv.conf while the edge reports that the forwarder runs), takes stock
// of the containers by their labels, and then works through the steps of spec
// 5.2:
//
//  1. plan: the ports of the test listeners; for every proxy the hash of the
//     instance it needs and the artifact it runs;
//  2. edge: make sure the newest edge generation runs (write its config, then
//     create it, then wait for it to answer); older generations drain; ask it
//     whether its DNS forwarder runs, and plan again when that changed; take
//     the health of the egress members from it (the events of their changes,
//     the NAT addresses of the middle proxy), and plan again when a NAT address
//     changed;
//  3. lists: the addresses of the middle proxies and the subscriptions of the
//     needed egresses, when they are due (egress.go, subscriptions.go,
//     meaddrs.go);
//  4. egresses: a needed egress whose provider instance is missing or
//     outdated gets a new generation, blue-green: new ports, files, container,
//     readiness, then the edge gets its ports in the chains and the old
//     generation drains for two minutes; an egress no longer needed drains;
//  5. engines: an enabled proxy whose instance is missing or outdated gets a
//     new generation, blue-green (spec 5.5): new ports, files, the SOCKS port
//     in the edge, container, readiness, a fake-TLS probe, the checks of its
//     way out through the edge (gate.go), then the route moves and the old
//     generation drains; any failure removes the new generation and the old
//     one goes on serving. A change of engine (telemt to mtg or back) is a
//     new instance hash like any other, so it is the same blue-green: the new
//     generation runs on the other driver beside the old one, and the route,
//     the domain and the secret stay. An mtg proxy fronts from the node itself
//     (Ruling S5-10) to the address the plan gives it: its mask target
//     override, or an address of its domain that the agent resolves through
//     the node's resolver (fronting.go), kept for frontingTTL and resolved
//     again at the next pass after that; a new address is a new generation;
//  6. the edge gets the whole table (SetConfig), and says whether its DNS
//     forwarder runs;
//  7. deleted proxies drain; draining generations are removed once their
//     connections are gone or DrainAfter is over, those of the egresses after
//     two minutes;
//  8. the runtime record is saved with the applied generation.
//
// A newer trigger that arrives during a pass makes it stop at the next step
// boundary and start over from the newest state. Every step is idempotent, and
// the runtime record is saved before a route moves, so that an agent killed at
// any point finds a consistent state when it starts again: containers it knows
// are adopted, containers it does not know are removed.
package reconcile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/node/trial"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/warp"
)

// Prober runs the L1 fake-TLS probe (probe.FakeTLS) against addr with a PROXY
// v2 header from src, and returns nil only when the server proved that it knows
// the secret (16 bytes).
type Prober func(ctx context.Context, addr, sni string, secret []byte, src netip.AddrPort) error

const (
	defaultInterval   = 30 * time.Second
	defaultDrainAfter = 30 * time.Minute
	// defaultReadyTimeout bounds the wait for a new engine generation (spec 5.5).
	defaultReadyTimeout = 90 * time.Second
	defaultReadyPoll    = time.Second
	// defaultEdgeStartTimeout bounds the wait for a new edge generation.
	defaultEdgeStartTimeout = 30 * time.Second
	defaultEdgePoll         = 500 * time.Millisecond
	defaultProbeTimeout     = 10 * time.Second
	defaultProbeAttempts    = 3
	// defaultRetryAfter is how long a generation that failed its readiness or
	// probe is not tried again with the same configuration. The memory of the
	// failure goes as soon as the proxy wants another configuration: a step
	// that a rollout reverted and retries is attempted at once.
	defaultRetryAfter = 5 * time.Minute

	// edgeDrainSeconds is what an outgoing edge generation is given to finish
	// its connections (spec 7); after edgeDrainGrace more it is stopped.
	edgeDrainSeconds = 3600
	edgeDrainGrace   = 5 * time.Minute

	dockerTimeout = 30 * time.Second
	pullTimeout   = 10 * time.Minute
	stopTimeout   = 10 * time.Second
	// edgeStopTimeout is what an edge gets between SIGTERM and SIGKILL when it
	// is stopped, by the reconciler and, through the container's StopTimeout, by
	// the daemon: on SIGTERM it waits up to 30 s for its connections.
	edgeStopTimeout = 35 * time.Second
	edgeCallTimeout = 15 * time.Second

	// edgeOpenFiles is the limit of open files of the edge container, soft and
	// hard (RLIMIT_NOFILE): the caps of the edge on connections are derived from
	// it, a relayed connection holds two descriptors and the SOCKS ports of the
	// engines take theirs from it too. Docker's default depends on the host.
	// This is the default fs.nr_open of Linux, the most open files a process
	// may have; on a host with a lower fs.nr_open the edge gets that instead
	// (see edgeOpenFileLimit).
	edgeOpenFiles = 1 << 20
	// nrOpenFile holds fs.nr_open of the host.
	nrOpenFile = "/proc/sys/fs/nr_open"
)

// Event kinds.
const (
	evEdgeStarted      = "edge_started"
	evEdgeDraining     = "edge_draining"
	evEdgeRemoved      = "edge_removed"
	evEdgeRoll         = "edge_roll"
	evEdgeRollFailed   = "edge_roll_failed"
	evEdgeRollRequest  = "edge_roll_requested"
	evEdgeOutdated     = "edge_outdated"
	evInstanceStarting = "instance_starting"
	evInstanceServing  = "instance_serving"
	evInstanceDraining = "instance_draining"
	evInstanceRemoved  = "instance_removed"
	evInstanceFailed   = "instance_failed"
	evUpgradeAborted   = "upgrade_aborted"
	evInstanceMissing  = "instance_missing"
	evInstanceRestart  = "instance_restarted"
	evOrphanRemoved    = "orphan_removed"
	evArtifactMissing  = "artifact_missing"
	evArtifactUnusable = "artifact_unusable"
	evArtifactUntried  = "artifact_untried"
	evArtifactRemoved  = "artifact_removed"
	evRenderFailed     = "render_failed"
	evReconcileFailed  = "reconcile_failed"

	sevInfo    = "info"
	sevWarning = "warning"
	sevError   = "error"
)

// errInterrupted ends a pass that a newer trigger cut short.
var errInterrupted = errors.New("reconcile: interrupted by a newer state")

// ErrRefused is, as errors.Is tells it, the error of a pass whose desired
// state was refused: it does not validate, or the edge refused the
// configuration made of it, a listener the edge cannot bind for one. The node
// works; it is the state that has to change, which is the panel's business,
// and no reason to take the agent for broken (spec 7: the healthy marker).
var ErrRefused = errors.New("reconcile: the desired state is refused")

// refusal is an error that is a refusal of the desired state (ErrRefused),
// with the text of the error it holds.
type refusal struct{ err error }

func (r refusal) Error() string        { return r.err.Error() }
func (r refusal) Unwrap() error        { return r.err }
func (r refusal) Is(target error) bool { return target == ErrRefused }

// TrialRunner is what the reconciler needs of the node's trial runner
// (trial.Runner): to try an artifact out before a new generation runs it, and
// to know which trial containers are in flight, so that the orphan sweep
// leaves them alone. The agent shares its one runner with UploadArtifact.
type TrialRunner interface {
	Run(ctx context.Context, binaryPath, binaryName string, t engines.Trial) trial.Result
	InFlight() map[string]bool
}

// Reconciler converges the node's containers and the edge table to the desired
// state. Set the fields, then call Run once; the worker reads the fields
// without locking, so do not change them while Run runs. Status may be called
// at any time from any goroutine.
type Reconciler struct {
	Docker    dockerapi.Client
	Store     *state.Store
	Artifacts *artifacts.Store
	// Trials runs the trial of an artifact that has no record yet; nil means
	// that such an artifact stays untried (and unused) on this node.
	Trials  TrialRunner
	Drivers map[nodev1.Engine]engines.Driver
	// Providers are the drivers of the egress providers by the kind of egress
	// they serve: Xray for XRAY_URI, XRAY_SUBSCRIPTION and WARP, Psiphon's client for
	// PSIPHON. An egress of a kind without one gets no instance, and that is
	// reported.
	Providers map[nodev1.EgressKind]providers.Driver
	// Alloc hands out loopback ports; nil means a default Allocator.
	Alloc *state.Allocator
	// EdgeFactory returns the control client of edge generation gen (the
	// socket data/run/edge-g<gen>.sock).
	EdgeFactory func(gen uint64) EdgeClient
	// Probe is the L1 probe of a new engine generation, L2 the L2 probe of its
	// way out (gate.go).
	Probe Prober
	L2    L2Prober
	// Resolver resolves the names of the agent's own connections: the
	// subscriptions, the lists of the middle proxies, the registration of WARP
	// devices, and the domain of an mtg proxy for its fronting address
	// (fronting.go). The agent gives the resolver that asks the edge's DNS
	// forwarder while it runs; nil means the resolver of the system.
	Resolver *net.Resolver
	// MEConfigURLs are the lists of Telegram's middle proxies that the agent
	// reads for the edge (meaddrs.go); nil means DefaultMEConfigURLs, and an
	// empty list none.
	MEConfigURLs []string
	// Log receives the reconciler's log; nil discards it. Nothing secret is
	// logged.
	Log *slog.Logger
	// Now is the clock of timestamps and drain decisions; nil means time.Now.
	Now func() time.Time

	// Version is the version of the agent, which a new edge runs as well (the
	// edge runs NodeBinaryPath). An edge that reports another one is reported
	// as outdated; empty compares nothing.
	Version string
	// RunnerImage is the image of every container the reconciler creates.
	RunnerImage string
	// NodeBinaryPath is the host path of the postern-node binary, mounted into
	// the edge.
	NodeBinaryPath string
	// Arch is the node's CPU architecture, "amd64" or "arm64".
	Arch string
	// DrainAfter is how long a draining engine generation may keep its
	// connections; 0 means 30 minutes.
	DrainAfter time.Duration
	// Events receives the node events (each step of a pass is one); nil drops
	// them. Events never carry secrets.
	Events func(*nodev1.NodeEvent)

	// NodePublicIPv4 is the node's public IPv4 address. A proxy that uses the
	// middle proxy, names no nat_ip and goes to the middle proxies through a
	// chain of direct members presents it as its NAT address while the exit
	// address of the chain is not known, and its serving instance has none
	// (Ruling S2-15, natip.go); empty means none. SetNodePublicIPv4 replaces it
	// while Run runs.
	NodePublicIPv4 string
	// Certs issues and renews the certificates of WEB proxies (web.go); nil
	// means no ACME on the node: imported certificates are served, and a
	// proxy of cert_mode acme-dns01 waits with a reason.
	Certs *acme.Manager
	// LookupIP resolves the domains of WEB proxies for their public address;
	// nil means DNS-over-HTTPS at doh.DefaultEndpoints.
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// InterfaceAddrs lists the addresses of the host, among which the public
	// address of a WEB domain is looked for; nil means net.InterfaceAddrs.
	InterfaceAddrs func() ([]net.Addr, error)
	// OnPass, if set, is called after every pass that ran to its end or
	// failed (not after one cut short by a newer trigger), with the status as
	// Status returns it and the pass's error.
	OnPass func(report *nodev1.StateReport, err error)
	// HostNameservers returns the nameservers of the host, which the edge's
	// DNS forwarder asks when DNS-over-HTTPS fails (dns.HostNameservers of
	// the agent's /etc/resolv.conf); nil means none. It is called once per pass
	// in DNS mode doh.
	HostNameservers func() []string
	// OnEdgeDNS, if set, is told whenever the current edge answers whether its
	// DNS forwarder runs (twice a pass); an edge that does not answer tells
	// nothing, and nothing is said. It is called from the worker.
	OnEdgeDNS func(up bool)

	// Tuning; zero means the default. Tests shorten them.
	interval           time.Duration
	readyTimeout       time.Duration
	egressReadyTimeout time.Duration
	readyPoll          time.Duration
	edgeStartTimeout   time.Duration
	edgePoll           time.Duration
	probeTimeout       time.Duration
	probeAttempts      int
	retryAfter         time.Duration
	gateTimeout        time.Duration
	fetchBudget        time.Duration
	// readFile reads a file of the host, as os.ReadFile does; nil means
	// os.ReadFile.
	readFile func(name string) ([]byte, error)
	// Stand-ins for the network, for the tests; nil means the real thing.
	dialDirect     dialFunc                                                                    // the agent's own connections (directDialer)
	socksDial      func(ctx context.Context, socks, target string) (net.Conn, error)           // a CONNECT through a SOCKS port of the edge
	proxySecret    func(ctx context.Context, socks string) error                               // the check of the proxy secret
	proxySecretURL string                                                                      // "" is getProxySecret
	gateTLS        *tls.Config                                                                 // of checkProxySecret; nil is the default
	warpAccount    func(ctx context.Context, path string) (*warp.Account, error)               // warp.LoadOrRegister
	warpDelete     func(ctx context.Context, a *warp.Account) error                            // warp.Delete
	cacheCopied    func(name string)                                                           // a file of a Psiphon cache was read (egresscache.go)
	frontingLookup func(ctx context.Context, host string) ([]netip.Addr, error)                // the lookup of a fronting address (fronting.go); nil is Resolver's
	issue          func(ctx context.Context, domain, email string, cred acme.Credential) error // Certs.Issue
	webProbe       func(ctx context.Context, addr, host string) error                          // webProbeHTTP

	// What Status reports, and the public address SetNodePublicIPv4 gives,
	// guarded by mu.
	mu       sync.Mutex
	status   map[string]*nodev1.ProxyStatus
	egressSt map[string]*nodev1.EgressInstanceStatus
	applied  uint64
	egress   []*nodev1.EgressMemberHealth
	passErr  string  // the error of the last pass that ended, "" when it went through
	publicIP *string // nil: NodePublicIPv4

	// The worker's memory across passes (not saved: an agent restart only
	// repeats a step).
	// listenerFailed holds the listeners the edge could not bind, by id with
	// the reason, as its last SetConfig reported them; a change is logged.
	listenerFailed map[string]string
	ownAlloc       *state.Allocator       // when Alloc is nil
	edgeClients    map[uint64]EdgeClient  // one client per edge generation
	failures       map[string]failure     // proxy id → the last failed start
	egressFailures map[string]failure     // egress id → the last failed start
	warpFailures   map[string]failure     // egress id → the last failed registration of its WARP device
	subRetry       map[subKey]time.Time   // when a subscription may be fetched again after a failure
	problems       map[string]string      // what was reported, so it is reported once
	edgeDrains     map[uint64]*edgeRetire // outgoing edge generations
	policyOff      map[string]bool        // draining containers set to restart "no"
	psiphonRetry   map[string]time.Time   // pending warp-plus devices: when each is tried next
	me             meState                // the lists of the middle proxies
	// memberStatus and activeMember are the health of the members as the edge
	// reported it last, for the events of its changes (natip.go); nil before
	// the first report.
	memberStatus map[string]string
	activeMember map[string]string
	// exitSeen is the exit address of every chain in the last two
	// observations (natip.go), and natRolls when the NAT address of a proxy
	// last made a new generation of its engine, within natRollEvery.
	exitSeen map[string]exitObservation
	natRolls map[string]time.Time
	// edgeVersionChecked is the edge generation whose version was compared
	// with Version last (see checkEdgeVersion), and edgeVersionOK whether it
	// runs the agent's.
	edgeVersionChecked uint64
	edgeVersionOK      bool
	// rollReq is UpdateEdge's request for an edge roll that waits for a pass
	// (edgeroll.go), rollRunning set while a pass holds one; guarded by mu.
	rollReq     *edgeRollRequest
	rollRunning bool
	// fronting is the fronting address of every mtg proxy domain that was
	// resolved (fronting.go), by the host that was looked up.
	fronting map[string]frontingEntry
	// lastGC is when the artifacts were last collected (artifactgc.go); zero
	// before the first time.
	lastGC      time.Time
	notRootOnce sync.Once
	badIPOnce   sync.Once
	nofileOnce  sync.Once // the edge's limit of open files is logged once

	lastDNSEvent edgeEvent // the last dns_unavailable event, for its rate limit (ruling S2-12)

	// WEB proxies (web.go), guarded by mu where the issuance goroutines
	// touch them: certsInspectOnly says Certs was made here, without ACME;
	// doh is the lookup client; webLookups the resolved domains; issuing the
	// domains whose issuance runs, issueAsked the (domain, email, credential)
	// asked for in this agent run; certDomains the ACME domain of every WEB
	// proxy (for Forget); bg and wake are Run's context and its wake-up
	// channel.
	certsInspectOnly bool
	doh              *doh.Client
	webLookups       map[string]webLookup
	issuing          map[string]bool
	issueAsked       map[string]bool
	certDomains      map[string]string
	// certUnused is when each certificate directory on disk was first seen
	// with no WEB proxy for its domain (removeUnusedCerts); touched by the
	// pass only.
	certUnused map[string]time.Time
	bg         context.Context
	wake       chan struct{}

	// Downloads of artifacts by the node itself (download.go), guarded by
	// mu: downloading the refs whose download runs, downloadFailed when the
	// download of a url last failed, downloadSlots the downloads that may run
	// at a time; downloads counts the goroutines, which Run waits for.
	downloading    map[artifacts.Ref]bool
	downloadFailed map[string]time.Time
	downloadSlots  chan struct{}
	downloads      sync.WaitGroup
	maxDownload    int64 // 0: maxDownloadSize; tests shorten it
	// Test-only loosening of the download rules, never set in production:
	// downloadAllowHTTP takes http:// urls, downloadAllowDial lets the
	// destination policy pass an address (a test server on loopback), and
	// downloadTLS is the TLS configuration of downloads (nil: the default).
	downloadAllowHTTP bool
	downloadAllowDial func(netip.AddrPort) bool
	downloadTLS       *tls.Config
	// fetchAllowDial lets the destination policy of the direct route of a
	// fetch (directDialer) pass an address: the harness's subscription
	// servers on loopback. Never set in production.
	fetchAllowDial func(netip.AddrPort) bool
}

// failure is a start of a new generation that failed its readiness or probe.
type failure struct {
	hash   string
	at     time.Time
	reason string
}

// Run is the reconcile worker. It makes a pass at once, then one for every
// trigger and every 30 s, until ctx ends. A trigger during a pass makes the
// pass stop at the next step boundary and start over. Run leaves no goroutine
// behind. Do not call it twice at the same time.
func (r *Reconciler) Run(ctx context.Context, trigger <-chan struct{}) {
	defer r.downloads.Wait()
	k := &kicks{ch: trigger}
	tick := time.NewTicker(orDefault(r.interval, defaultInterval))
	defer tick.Stop()
	wake := make(chan struct{}, 1)
	r.mu.Lock()
	r.bg, r.wake = ctx, wake
	r.mu.Unlock()
	if r.Certs != nil {
		go r.renewLoop(ctx)
	}
	for {
		err := r.reconcileOnce(ctx, k)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errInterrupted) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case _, ok := <-k.ch:
			if !ok {
				k.ch = nil
			}
		case <-wake: // a certificate issuance ended (web.go)
		case <-tick.C:
		}
	}
}

// Status is the state report of the node: the generation the last complete
// pass applied, the phase of every proxy (live, also during a pass), the
// health of the egress members as the edge last reported it, the provider
// instances of the egresses (live as well), and why the last pass that ended
// failed ("" when it went through). That text is the one of the
// reconcile_failed event, which never holds a secret; it is not bounded here.
func (r *Reconciler) Status() *nodev1.StateReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	rep := &nodev1.StateReport{AppliedGeneration: r.applied, LastError: r.passErr}
	for _, id := range slices.Sorted(maps.Keys(r.status)) {
		rep.Proxies = append(rep.Proxies, proto.Clone(r.status[id]).(*nodev1.ProxyStatus))
	}
	for _, id := range slices.Sorted(maps.Keys(r.egressSt)) {
		rep.EgressInstances = append(rep.EgressInstances, proto.Clone(r.egressSt[id]).(*nodev1.EgressInstanceStatus))
	}
	for _, h := range r.egress {
		rep.Egress = append(rep.Egress, proto.Clone(h).(*nodev1.EgressMemberHealth))
	}
	return rep
}

// Seed sets what Status reports until the first pass has run, from the
// desired state and the runtime record on disk (either may be nil): the
// applied generation, and the phase of every proxy as the record has it. A
// proxy with a serving instance serves, a paused one is paused, one without an
// instance is pending, and the instance of a proxy that is no longer desired
// drains; without a desired state, a serving instance serves. So the first
// report of a node that just started, the opening report of Watch, is not
// empty (M1). The first pass replaces all of it. Call Seed before Run.
func (r *Reconciler) Seed(st *nodev1.NodeState, rt *state.Runtime) {
	if rt == nil {
		rt = state.NewRuntime()
	}
	status := map[string]*nodev1.ProxyStatus{}
	for _, pr := range st.GetProxies() {
		id := pr.GetId()
		rec := rt.Instances[id]
		phase := nodev1.ProxyPhase_PROXY_PHASE_PENDING
		switch {
		case !pr.GetEnabled():
			phase = nodev1.ProxyPhase_PROXY_PHASE_PAUSED
		case rec.Generation > 0:
			phase = nodev1.ProxyPhase_PROXY_PHASE_SERVING
		}
		status[id] = proxyStatus(id, phase, "", rec, pr)
	}
	for id, rec := range rt.Instances {
		_, desired := status[id]
		switch {
		case desired:
		case st == nil && rec.Generation > 0:
			status[id] = proxyStatus(id, nodev1.ProxyPhase_PROXY_PHASE_SERVING, "", rec, nil)
		case st == nil && len(rec.Draining) > 0:
			status[id] = proxyStatus(id, nodev1.ProxyPhase_PROXY_PHASE_DRAINING, "", rec, nil)
		case rec.Generation > 0 || len(rec.Draining) > 0:
			status[id] = proxyStatus(id, nodev1.ProxyPhase_PROXY_PHASE_DRAINING, "the proxy was deleted", rec, nil)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
	r.applied = rt.AppliedGeneration
}

// kicks are the triggers of newer states.
type kicks struct {
	ch <-chan struct{}
}

// pending takes a trigger if one is there.
func (k *kicks) pending() bool {
	if k == nil || k.ch == nil {
		return false
	}
	select {
	case _, ok := <-k.ch:
		if !ok {
			k.ch = nil
			return false
		}
		return true
	default:
		return false
	}
}

// reconcileOnce makes one pass.
func (r *Reconciler) reconcileOnce(ctx context.Context, k *kicks) (err error) {
	r.init()
	p := &pass{
		r:                r,
		ctx:              ctx,
		kicks:            k,
		plans:            map[string]*proxyPlan{},
		starting:         map[string]startingInstance{},
		engines:          map[string]map[uint64]dockerapi.Container{},
		egressContainers: map[string]map[uint64]dockerapi.Container{},
		verdicts:         map[artifacts.Ref]artifactVerdict{},
	}
	p.noteRollRequest()
	defer func() { err = r.finish(p, err) }()
	return p.run()
}

func (r *Reconciler) init() {
	if r.failures == nil {
		r.edgeClients = map[uint64]EdgeClient{}
		r.failures = map[string]failure{}
		r.egressFailures = map[string]failure{}
		r.warpFailures = map[string]failure{}
		r.subRetry = map[subKey]time.Time{}
		r.natRolls = map[string]time.Time{}
		r.problems = map[string]string{}
		r.edgeDrains = map[uint64]*edgeRetire{}
		r.policyOff = map[string]bool{}
		r.fronting = map[string]frontingEntry{}
	}
}

// edge returns the control client of an edge generation, made once.
func (r *Reconciler) edge(gen uint64) EdgeClient {
	c, ok := r.edgeClients[gen]
	if !ok {
		c = r.EdgeFactory(gen)
		r.edgeClients[gen] = c
	}
	return c
}

// finish saves what the pass changed and publishes the outcome.
func (r *Reconciler) finish(p *pass, err error) error {
	if p.rt != nil {
		if serr := p.saveRuntime(); serr != nil && err == nil {
			err = serr
		}
	}
	p.finishRoll(err, errors.Is(err, errInterrupted))
	if errors.Is(err, errInterrupted) {
		r.log().Info("newer desired state: starting the pass over")
		return err
	}
	if err != nil && p.ctx.Err() != nil {
		return err // the agent is stopping: nothing to report
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	r.mu.Lock()
	prev := r.passErr
	r.passErr = msg
	if p.rt != nil {
		r.applied = p.rt.AppliedGeneration
	}
	r.mu.Unlock()
	if msg != "" && msg != prev {
		r.event(evReconcileFailed, sevError, "", "reconcile pass failed: "+msg, nil)
	}
	if r.OnPass != nil {
		r.OnPass(r.Status(), err)
	}
	return err
}

// pass is the state of one reconcile pass.
type pass struct {
	r     *Reconciler
	ctx   context.Context
	kicks *kicks

	st      *nodev1.NodeState
	rt      *state.Runtime
	savedRT []byte // runtime as last loaded or saved, to skip saves without changes

	proxies map[string]*nodev1.Proxy // the desired proxies by id
	plans   map[string]*proxyPlan

	edges            []edgeContainer
	engines          map[string]map[uint64]dockerapi.Container // proxy id → generation → container
	egressContainers map[string]map[uint64]dockerapi.Container // egress id → generation → container
	trialContainers  []dockerapi.Container                     // the trial containers that exist (artifactgc.go)
	// verdicts are the artifacts judged in this pass (artifactgc.go): one
	// trial per artifact and pass, however many instances need it.
	verdicts map[artifacts.Ref]artifactVerdict

	edgeGen    uint64
	edge       EdgeClient
	imageReady bool
	starting   map[string]startingInstance
	webCerts   map[string]webCert // the certificates of the WEB domains (web.go)

	dnsFallback []string // the host's nameservers for the edge's DNS forwarder

	// UpdateEdge's roll request (edgeroll.go): the one that waited as the pass
	// started, the one the pass took, and its outcome.
	rollWaiting *edgeRollRequest
	rollReq     *edgeRollRequest
	rollGen     uint64
	rollErr     error
	rollEnded   bool
}

func (p *pass) run() error {
	if err := p.r.checkConfig(); err != nil {
		return err
	}
	if err := p.load(); err != nil {
		return err
	}
	if p.st == nil {
		p.r.log().Debug("no desired state yet")
		return nil
	}
	// The resolv.conf comes first: the inventory may start an engine container
	// again, which mounts it. Once the edge runs, its forwarder decides whether
	// the engines of this pass mount it, and its health the NAT addresses of the
	// middle proxy; the egresses come before the engines, which go out through
	// them.
	steps := []func() error{
		p.prepareDNS, p.inventory, p.sweepTrials, p.plan, p.certificates, p.ensureEdge, p.checkEdgeVersion, p.settleEdgeDNS,
		p.observeEgress, p.refreshLists, p.convergeEgresses,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
		if err := p.boundary(); err != nil {
			return err
		}
	}
	for _, pr := range p.sortedProxies() {
		if err := p.converge(pr); err != nil {
			return err
		}
		if err := p.boundary(); err != nil {
			return err
		}
	}
	if err := p.pushEdgeConfig(); err != nil {
		return err
	}
	p.checkEdgeDNS()
	if err := p.boundary(); err != nil {
		return err
	}
	p.retireDeleted()
	p.drainEgresses()
	if p.drain() {
		// The edge no longer needs the SOCKS ports of what was removed.
		if err := p.pushEdgeConfig(); err != nil {
			return err
		}
	}
	if err := p.boundary(); err != nil {
		return err
	}
	if err := p.commit(); err != nil {
		return err
	}
	p.collectArtifacts()
	return nil
}

// boundary ends the pass when ctx is done or a newer state is waiting.
func (p *pass) boundary() error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if p.kicks.pending() {
		return errInterrupted
	}
	return nil
}

func (r *Reconciler) checkConfig() error {
	var missing []string
	for _, f := range []struct {
		name string
		ok   bool
	}{
		{"Docker", r.Docker != nil}, {"Store", r.Store != nil}, {"Artifacts", r.Artifacts != nil},
		{"Drivers", len(r.Drivers) > 0}, {"EdgeFactory", r.EdgeFactory != nil}, {"Probe", r.Probe != nil}, {"L2", r.L2 != nil},
		{"RunnerImage", r.RunnerImage != ""}, {"NodeBinaryPath", r.NodeBinaryPath != ""}, {"Arch", r.Arch != ""},
	} {
		if !f.ok {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("reconcile: the reconciler is missing %s", strings.Join(missing, ", "))
	}
	return nil
}

// load reads the desired state and the runtime record; a desired state that
// does not validate is not applied.
func (p *pass) load() error {
	rt, err := p.r.Store.LoadRuntime()
	if err != nil {
		return fmt.Errorf("loading the runtime record: %w", err)
	}
	p.rt = rt
	p.savedRT, _ = json.Marshal(rt)
	st, err := p.r.Store.LoadDesired()
	if err != nil {
		return fmt.Errorf("loading the desired state: %w", err)
	}
	if st == nil {
		return nil
	}
	if err := state.Validate(st, p.r.supports); err != nil {
		return refusal{fmt.Errorf("desired state of generation %d: %w", st.GetGeneration(), err)}
	}
	p.st = st
	p.proxies = map[string]*nodev1.Proxy{}
	for _, pr := range st.GetProxies() {
		p.proxies[pr.GetId()] = pr
	}
	return nil
}

// inventory lists the containers the agent manages and adopts the engines and
// the providers.
func (p *pass) inventory() error {
	ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
	defer cancel()
	list, err := p.r.Docker.List(ctx, map[string]string{labelManaged: "true"}, true)
	if err != nil {
		return fmt.Errorf("listing containers: %w", err)
	}
	for _, c := range list {
		if c.Labels[labelRole] == roleTrial {
			p.trialContainers = append(p.trialContainers, c)
			continue
		}
		gen, err := strconv.ParseUint(c.Labels[labelGeneration], 10, 64)
		if err != nil || gen == 0 {
			continue
		}
		switch c.Labels[labelRole] {
		case roleEdge:
			p.edges = append(p.edges, edgeContainer{name: c.Name, gen: gen, state: c.State})
		case roleEngine:
			id := c.Labels[labelID]
			if p.engines[id] == nil {
				p.engines[id] = map[uint64]dockerapi.Container{}
			}
			p.engines[id][gen] = c
		case roleEgress:
			id := c.Labels[labelID]
			if p.egressContainers[id] == nil {
				p.egressContainers[id] = map[uint64]dockerapi.Container{}
			}
			p.egressContainers[id][gen] = c
		}
	}
	p.adoptEngines()
	p.adoptEgresses()
	return nil
}

// commit records the applied generation and tidies up.
func (p *pass) commit() error {
	p.gcPorts()
	p.gcEgressPorts()
	p.rt.AppliedGeneration = p.st.GetGeneration()
	if err := p.saveRuntime(); err != nil {
		return err
	}
	p.sweepInstanceDirs()
	p.sweepEgressDirs()
	return nil
}

// saveRuntime writes the runtime record when it changed.
func (p *pass) saveRuntime() error {
	data, err := json.Marshal(p.rt)
	if err != nil {
		return fmt.Errorf("encoding the runtime record: %w", err)
	}
	if bytes.Equal(data, p.savedRT) {
		return nil
	}
	if err := p.r.Store.SaveRuntime(p.rt); err != nil {
		return err
	}
	p.savedRT = data
	return nil
}

func (p *pass) sortedProxies() []*nodev1.Proxy {
	out := slices.Clone(p.st.GetProxies())
	slices.SortFunc(out, func(a, b *nodev1.Proxy) int { return strings.Compare(a.GetId(), b.GetId()) })
	return out
}

// ---- status -------------------------------------------------------------------

// report sets the live status of a proxy; the instance fields come from the
// runtime record. The status says nothing of a failed attempt: see failStatus.
func (p *pass) report(id string, phase nodev1.ProxyPhase, reason string) {
	p.setStatus(proxyStatus(id, phase, reason, p.rt.Instances[id], p.proxies[id]))
}

func (p *pass) setStatus(ps *nodev1.ProxyStatus) {
	p.r.mu.Lock()
	defer p.r.mu.Unlock()
	if p.r.status == nil {
		p.r.status = map[string]*nodev1.ProxyStatus{}
	}
	p.r.status[ps.GetProxyId()] = ps
}

// proxyStatus is the status of a proxy in a phase, for a reason: the engine,
// the version and the generation of its serving instance come from its runtime
// record (the generation of the newest that drains when none serves); the
// engine is the desired proxy's, pr's, only while no instance serves (F3: after
// a failed switch the engine is the one that serves, not the one that was
// wanted).
func proxyStatus(id string, phase nodev1.ProxyPhase, reason string, rec state.InstanceRecord, pr *nodev1.Proxy) *nodev1.ProxyStatus {
	ps := &nodev1.ProxyStatus{
		ProxyId:            id,
		Phase:              phase,
		Reason:             reason,
		RunningVersion:     rec.Version,
		InstanceGeneration: rec.Generation,
	}
	switch {
	case rec.Generation > 0 && rec.Engine != "":
		ps.Engine = engineOf(rec.Engine)
	case pr != nil:
		ps.Engine = pr.GetEngine()
	default:
		ps.Engine = engineOf(rec.Engine)
	}
	if rec.Generation == 0 && len(rec.Draining) > 0 {
		ps.InstanceGeneration = rec.Draining[len(rec.Draining)-1].Generation
	}
	return ps
}

// engineOf is the Engine of a driver name as the runtime record keeps it
// ("telemt", "mtg"); ENGINE_UNSPECIFIED for one it does not know.
func engineOf(name string) nodev1.Engine {
	if e, ok := nodev1.Engine_value["ENGINE_"+strings.ToUpper(name)]; ok {
		return nodev1.Engine(e)
	}
	return nodev1.Engine_ENGINE_UNSPECIFIED
}

// keepStatus drops the status of every proxy not in keep.
func (r *Reconciler) keepStatus(keep map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.status {
		if !keep[id] {
			delete(r.status, id)
		}
	}
}

// The phases of a provider instance (EgressInstanceStatus.phase).
const (
	egressPhaseServing  = "serving"
	egressPhaseStarting = "starting"
	egressPhaseFailed   = "failed"
	egressPhaseDraining = "draining"
)

// reportEgress sets the live status of the provider instance of an egress:
// the provider, the version and the generation of the serving instance come
// from its runtime record, the provider of the desired one, pl's, while none
// serves; failedVersion is the version of the desired instance whose attempt
// was aborted, "" when none was.
func (p *pass) reportEgress(id string, pl *egressPlan, phase, reason, failedVersion string) {
	rec := p.rt.Egresses[id]
	es := &nodev1.EgressInstanceStatus{
		EgressId: id, Provider: rec.Provider, Version: rec.Version, Generation: rec.Generation,
		Phase: phase, Reason: reason, FailedVersion: failedVersion,
	}
	if es.Provider == "" && pl != nil {
		es.Provider = pl.provider
	}
	p.r.mu.Lock()
	defer p.r.mu.Unlock()
	if p.r.egressSt == nil {
		p.r.egressSt = map[string]*nodev1.EgressInstanceStatus{}
	}
	p.r.egressSt[id] = es
}

// egressFailStatus reports an egress whose desired instance could not be
// started: as serving when an older generation still serves it, as failed
// otherwise, with the version that was wanted.
func (p *pass) egressFailStatus(id string, pl *egressPlan, rec state.EgressRecord, reason string) {
	phase := egressPhaseFailed
	if rec.Generation > 0 {
		phase = egressPhaseServing
	}
	p.reportEgress(id, pl, phase, reason, pl.version)
}

// EgressReason returns why the desired instance of the egress id could not be
// started, as the last pass reported it: "" when it serves or nothing failed.
func (r *Reconciler) EgressReason(id string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if es := r.egressSt[id]; es != nil && es.GetPhase() == egressPhaseFailed {
		return es.GetReason()
	}
	return ""
}

// keepEgressStatus drops the status of every egress not in keep.
func (r *Reconciler) keepEgressStatus(keep map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.egressSt {
		if !keep[id] {
			delete(r.egressSt, id)
		}
	}
}

// setEgressHealth takes the health of the members that the current edge
// reports: for Status, and for the events of its changes.
func (r *Reconciler) setEgressHealth(hs []*edgev1.MemberHealth) {
	out := make([]*nodev1.EgressMemberHealth, 0, len(hs))
	for _, h := range hs {
		out = append(out, &nodev1.EgressMemberHealth{
			ChainId: h.GetChainId(), MemberKey: h.GetMemberKey(), Status: h.GetStatus(),
			LatencyMs: h.GetLatencyMs(), ExitIp: h.GetExitIp(), CheckedUnix: h.GetCheckedUnix(),
		})
	}
	r.healthEvents(hs)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.egress = out
}

// egressHealth is the health of the members as the current edge reported it
// last.
func (r *Reconciler) egressHealth() []*nodev1.EgressMemberHealth {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.egress
}

// ---- events and logs ------------------------------------------------------------

func (r *Reconciler) event(kind, severity, proxyID, msg string, details map[string]string) {
	level := slog.LevelInfo
	switch severity {
	case sevWarning:
		level = slog.LevelWarn
	case sevError:
		level = slog.LevelError
	}
	attrs := []any{"event", kind}
	if proxyID != "" {
		attrs = append(attrs, "proxy", proxyID)
	}
	r.log().Log(context.Background(), level, msg, attrs...)
	if r.Events != nil {
		r.Events(&nodev1.NodeEvent{Kind: kind, Severity: severity, Message: msg, ProxyId: proxyID, Details: details})
	}
}

// problem reports a lasting problem once: it returns true when key had no
// problem or a different one before.
func (r *Reconciler) problem(key, msg string) bool {
	if r.problems[key] == msg {
		return false
	}
	r.problems[key] = msg
	return true
}

// clearProblem forgets reported problems, so that a new occurrence is
// reported again.
func (r *Reconciler) clearProblem(keys ...string) {
	for _, k := range keys {
		delete(r.problems, k)
	}
}

// problemKeys are the keys of the problems a proxy can have.
func problemKeys(proxyID string) []string {
	return []string{"render:" + proxyID, "artifact:" + proxyID, "start:" + proxyID}
}

func (r *Reconciler) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

// ---- small helpers --------------------------------------------------------------

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) alloc() *state.Allocator {
	if r.Alloc != nil {
		return r.Alloc
	}
	if r.ownAlloc == nil {
		r.ownAlloc = &state.Allocator{}
	}
	return r.ownAlloc
}

func (r *Reconciler) drainAfter() time.Duration { return orDefault(r.DrainAfter, defaultDrainAfter) }

func (r *Reconciler) supports(e nodev1.Engine, t nodev1.ProxyType) bool {
	d, ok := r.Drivers[e]
	return ok && d != nil && d.Supports(t)
}

// SetNodePublicIPv4 replaces NodePublicIPv4 while Run runs, from any
// goroutine: the agent learns the address late when the first lookup could not
// resolve the echo services. The passes that begin after it take it; a proxy
// that uses it gets a new engine generation.
func (r *Reconciler) SetNodePublicIPv4(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.publicIP = &ip
}

// nodePublicIPv4 is the address of SetNodePublicIPv4, or NodePublicIPv4.
func (r *Reconciler) nodePublicIPv4() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.publicIP != nil {
		return *r.publicIP
	}
	return r.NodePublicIPv4
}

// publicIPv4 is the node's public IPv4 address (nodePublicIPv4) when it is a
// usable public IPv4 address.
func (r *Reconciler) publicIPv4() string {
	ip := r.nodePublicIPv4()
	if ip == "" {
		return ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !isPublicIPv4(a) {
		r.badIPOnce.Do(func() {
			r.log().Warn("the node's public IPv4 address is not usable as a NAT address; ignoring it")
		})
		return ""
	}
	return a.Unmap().String()
}

// loadOrRegisterWARP returns the account of the WARP device in the file at
// path, registering a device when there is none (warp.LoadOrRegister), with
// the agent's resolver.
func (r *Reconciler) loadOrRegisterWARP(ctx context.Context, path string) (*warp.Account, error) {
	if r.warpAccount != nil {
		return r.warpAccount(ctx, path)
	}
	acct, created, err := warp.LoadOrRegister(ctx, warp.NewHTTPClient(r.directDialer()), path)
	if err == nil && created {
		r.log().Info("registered a WARP device", "account", acct)
	}
	return acct, err
}

// deleteWARP deletes the WARP device of an account at Cloudflare.
func (r *Reconciler) deleteWARP(ctx context.Context, a *warp.Account) error {
	if r.warpDelete != nil {
		return r.warpDelete(ctx, a)
	}
	return warp.Delete(ctx, warp.NewHTTPClient(r.directDialer()), a)
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// sleep waits for d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// newToken is a fresh engine API token: 32 random bytes in hex.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

func genString(gen uint64) string { return strconv.FormatUint(gen, 10) }
