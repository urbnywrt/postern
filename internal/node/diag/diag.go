// Package diag is the node's check catalogue (spec 5.7): the checks of the
// host, the ingress, the engines and the egresses, run all together on
// RunDiagnostics (a full run of a scope) and, the light ones, continuously,
// each at its cadence; the agent sends the light set to the panel as a Watch
// record when a status changes.
//
// Every text of a result passes the scrubber, which takes the secrets of the
// desired state and of the runtime record out and redacts client addresses,
// before it leaves the runner.
package diag

import (
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/state"
)

// Layers of results (spec 5.7).
const (
	LayerHost    = "host"
	LayerIngress = "ingress"
	LayerEngine  = "engine"
	LayerEgress  = "egress"
	LayerWeb     = "web"
	LayerE2E     = "e2e"
)

// Statuses, as short names.
const (
	OK   = nodev1.CheckStatus_CHECK_STATUS_OK
	Warn = nodev1.CheckStatus_CHECK_STATUS_WARN
	Fail = nodev1.CheckStatus_CHECK_STATUS_FAIL
	Skip = nodev1.CheckStatus_CHECK_STATUS_SKIP
)

// Limits of a result's texts (Global Constraints, Diagnostics).
const (
	MaxSummary     = 200
	MaxEvidence    = 2 << 10
	MaxRunEvidence = 64 << 10
	maxHint        = 512
	maxFix         = 64
)

// Timeouts and bounds of the runner.
const (
	// DefaultTimeout bounds one check; SlowTimeout the clock and DNS checks.
	DefaultTimeout = 10 * time.Second
	SlowTimeout    = 15 * time.Second
	// RunTimeout bounds a full run.
	RunTimeout = 3 * time.Minute
	// Slots is how many checks run at a time, in a full run and in the light
	// loop each.
	Slots = 16
)

// ErrBusy is the error of a full run while another one runs.
var ErrBusy = errors.New("diag: a diagnostics run is already under way")

// ErrScope is the error of a scope that is neither "node" nor "proxy:<id>" of
// a proxy of the desired state.
var ErrScope = errors.New("diag: unknown scope")

// Result is one check's result for one target (spec 5.7).
type Result struct {
	ID, Layer, Target string
	Status            nodev1.CheckStatus
	Summary           string
	Evidence          string
	Hint              string
	Fix               string
	Checked           time.Time
	Duration          time.Duration
	// keep is an address the texts may show that the redactor would take
	// out otherwise: the exit IP of an egress member.
	keep netip.Addr
}

// Proto is the result as DiagnosticResult.
func (r Result) Proto() *nodev1.DiagnosticResult {
	ms := r.Duration.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	if ms > 1<<31 {
		ms = 1 << 31
	}
	var at int64
	if !r.Checked.IsZero() {
		at = r.Checked.Unix()
	}
	return &nodev1.DiagnosticResult{
		Id: r.ID, Layer: r.Layer, Target: r.Target, Status: r.Status,
		Summary: r.Summary, Evidence: r.Evidence, Hint: r.Hint, Fix: r.Fix,
		CheckedUnix: at, DurationMs: uint32(ms),
	}
}

// Check is one check of the catalogue. Run returns the results of every
// target of the check that env wants (Env.Wants); a check is run by many
// goroutines at once (a full run beside the light loop), so what it keeps
// between runs is its own to guard.
type Check struct {
	ID, Layer string
	// Light checks run continuously at Every (±10 %); the others in full
	// runs only.
	Light bool
	Every time.Duration
	// Timeout bounds one run: DefaultTimeout when 0.
	Timeout time.Duration
	// Targets, when set, lists the targets of the check, so that the light
	// loop runs it for each target on its own (Env.Only); unset, a run covers
	// every target.
	Targets func(env *Env) []string
	Run     func(ctx context.Context, env *Env) []Result
}

func (c Check) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// SocketOwner is one listening socket. Known is false when its pid could not
// be read; Owner is then empty.
type SocketOwner struct {
	Bind  string
	Port  uint16
	PID   int
	Owner string
	Known bool
}

// OwnerAgent is the owner of the agent's own sockets (its management
// listeners); the edge's sockets are owned by its containers,
// EdgeContainerPrefix<generation>.
const (
	OwnerAgent          = "postern-agent"
	EdgeContainerPrefix = "postern-edge-g"
)

// EdgeClient is what the checks ask an edge generation.
type EdgeClient interface {
	Health(ctx context.Context) (*edgev1.HealthResponse, error)
	Snapshot(ctx context.Context) (*edgev1.SnapshotResponse, error)
}

// Exchanger asks a DNS question over DNS-over-HTTPS (doh.Client).
type Exchanger interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

// AllExchanger is an Exchanger that can ask every endpoint at once
// (doh.Client): host.dns uses it when env.DoH has it, so that one silent
// endpoint does not hide the others. failed holds the error of every endpoint
// that gave no answer.
type AllExchanger interface {
	ExchangeAll(ctx context.Context, query []byte) (resp []byte, failed []error, err error)
}

// Env is what the checks work with. The runner copies it for every run and
// fills in the desired state, the runtime record, the scrubber and the scope
// of that run; checks only read it.
type Env struct {
	Store     *state.Store
	Docker    dockerapi.Client
	Edge      func(gen uint64) EdgeClient
	Drivers   map[nodev1.Engine]engines.Driver
	Artifacts *artifacts.Store
	HTTP      *http.Client
	DoH       Exchanger
	// DialUDP dials the nameservers of host.dns directly.
	DialUDP func(ctx context.Context, network, addr string) (net.Conn, error)
	// Proc is the host's /proc.
	Proc fs.FS
	Now  func() time.Time
	Log  *slog.Logger
	// PortOwners lists the listening sockets of the host (the agent's
	// lookup).
	PortOwners func(context.Context) []SocketOwner
	// PublicIPs are the node's public addresses.
	PublicIPs func(context.Context) []netip.Addr
	// Scrubber makes the scrubber of a run from the desired state and the
	// runtime record; nil: NewScrubber(st, rt, nil).
	Scrubber func(st *nodev1.NodeState, rt *state.Runtime) *Scrubber
	// DiskSpace measures the file system of DiskPath (the node's home).
	DiskSpace func(path string) (total, avail uint64, err error)
	DiskPath  string
	// ClockURLs are the endpoints host.clock asks for their Date (the DoH
	// endpoints when empty), ClockTLS its TLS configuration (nil: verified
	// against the system's roots) and ClockDial its dialer (nil: direct).
	ClockURLs []string
	ClockTLS  *tls.Config
	ClockDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// DNSServers are the nameservers host.dns asks over UDP (1.1.1.1:53 and
	// 8.8.8.8:53 when empty).
	DNSServers []string
	// StatsOverflow is the last minute whose client addresses went over the
	// statistics' bound, and how many were left out; zero when none.
	StatsOverflow func() (minute time.Time, dropped int)
	// PingDC and ProxySecret are the gate's checks of the way out through a
	// SOCKS port (reconcile.PingDC, reconcile.ProxySecretCheck); nil:
	// egress.dc and egress.me skip. ProxyDCs are the datacenters egress.dc
	// asks for a proxy (reconcile.ProxyDCs); nil: the default ones.
	PingDC      func(ctx context.Context, socksAddr, dc string) error
	ProxySecret func(ctx context.Context, socksAddr string) error
	ProxyDCs    func(st *nodev1.NodeState, p *nodev1.Proxy) []string
	// L1 and L2 probe a proxy at addr, its listener's test listener;
	// nil: probe.FakeTLS and probe.L2, without a PROXY header.
	L1 func(ctx context.Context, addr, sni string, secret []byte) error
	L2 func(ctx context.Context, addr, sni string, secret []byte, dc int16) error
	// AddProbe takes the result of the L2 probe of e2e.l2 for the
	// statistics; nil: it is dropped.
	AddProbe func(*nodev1.ProbeResult)
	// CertStatus reports on the certificate of a WEB domain on disk and its
	// issuances (acme.Manager.Status); nil: web.cert skips.
	CertStatus func(domain string) acme.Status
	// CertTrusted verifies the stored chain of a WEB domain against the
	// system's roots (acme.Manager.Trusted); nil: web.cert does not judge
	// public trust.
	CertTrusted func(domain string) error
	// LookupIP resolves a WEB domain over DNS-over-HTTPS for web.dns; nil:
	// web.dns skips.
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// EgressReason says why the instance of a provider's egress does not
	// start, as the reconciler last reported it (reconcile.Reconciler.
	// EgressReason); nil or "": egress.member does not know.
	EgressReason func(id string) string

	// Set by the runner for a run.
	Desired *nodev1.NodeState
	Runtime *state.Runtime
	Scrub   *Scrubber
	scope   scope
	// Only restricts a light run of a check with Targets to one target.
	Only string
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Wants reports whether the run covers target: in its scope, and the target
// of a light run of one target.
func (e *Env) Wants(target string) bool {
	if e.Only != "" && target != e.Only {
		return false
	}
	return e.scope.wants(target)
}

// edge is the client of the edge generation that runs, nil when none does.
func (e *Env) edge() EdgeClient {
	if e.Edge == nil || e.Runtime == nil || e.Runtime.EdgeGeneration == 0 {
		return nil
	}
	return e.Edge(e.Runtime.EdgeGeneration)
}

// Listeners are the listeners of the desired state the run wants, with their
// targets.
func (e *Env) Listeners() []*nodev1.Listener {
	var out []*nodev1.Listener
	for _, l := range e.Desired.GetListeners() {
		if e.Wants(ListenerTarget(l.GetId())) {
			out = append(out, l)
		}
	}
	return out
}

// Targets.
func ListenerTarget(id string) string { return "listener:" + id }
func ProxyTarget(id string) string    { return "proxy:" + id }
func MemberTarget(chain, member string) string {
	return "member:" + chain + "/" + member
}

// scope is what a run covers: everything, or one proxy, its listener and the
// members of its chains.
type scope struct {
	proxy    string // "" is the node
	listener string
	chains   map[string]bool
}

const ScopeNode = "node"

// parseScope reads "node" or "proxy:<id>" against the desired state.
func parseScope(s string, st *nodev1.NodeState) (scope, error) {
	if s == ScopeNode {
		return scope{}, nil
	}
	id, ok := strings.CutPrefix(s, "proxy:")
	if !ok || id == "" {
		return scope{}, ErrScope
	}
	for _, p := range st.GetProxies() {
		if p.GetId() != id {
			continue
		}
		sc := scope{proxy: id, listener: p.GetListenerId(), chains: map[string]bool{}}
		chain := p.GetEgressChainId()
		if chain == "" {
			chain = st.GetSettings().GetDefaultChainId()
		}
		if chain != "" {
			sc.chains[chain] = true
		}
		for _, c := range p.GetEgressScopeChains() {
			if c != "" {
				sc.chains[c] = true
			}
		}
		return sc, nil
	}
	return scope{}, ErrScope
}

func (s scope) wants(target string) bool {
	if s.proxy == "" || target == "" {
		return true
	}
	switch kind, rest, _ := strings.Cut(target, ":"); kind {
	case "proxy":
		return rest == s.proxy
	case "listener":
		return rest == s.listener
	case "member":
		chain, _, _ := strings.Cut(rest, "/")
		return s.chains[chain]
	}
	return false
}

// clip returns s as valid UTF-8 without control characters other than new
// lines and tabs (newlines too when oneLine), cut to n bytes at most on a
// character boundary.
func clip(s string, n int, oneLine bool) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if (r == '\n' || r == '\t') && !oneLine {
			return r
		}
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
