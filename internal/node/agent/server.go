package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/selfupdate"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/node/trial"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/version"
)

// trialRunner is what the service needs of trial.Runner.
type trialRunner interface {
	Run(ctx context.Context, binaryPath, binaryName string, t engines.Trial) trial.Result
}

const (
	// defaultMaxUpload is the largest artifact UploadArtifact takes.
	defaultMaxUpload = 200 << 20
	// maxMessageBytes bounds one message from the panel (the panel's own
	// limit for what it reads is the same).
	maxMessageBytes = 16 << 20
	// watchPage is how many buffered records Watch reads at a time.
	watchPage = 256
	// infoTimeout bounds the work of one GetInfo.
	infoTimeout = 20 * time.Second
	// edgeHealthTimeout bounds the call to the edge that GetInfo makes for its
	// version, and maxVersionText the version it passes on.
	edgeHealthTimeout = 3 * time.Second
	maxVersionText    = 128
)

// Event kinds and severities of the agent's own events (the reconciler's use
// the same severities).
const (
	evStateAccepted  = "state_accepted"
	evStateRejected  = "state_rejected"
	evArtifact       = "artifact_stored"
	evAgentStarted   = "agent_started"
	evRolledBack     = "agent_rolled_back"
	evUpdating       = "agent_updating"
	evDiagnosticsRun = "diagnostics_run"

	sevInfo    = "info"
	sevWarning = "warning"
	sevError   = "error"

	reasonStale = "stale generation"
)

// serviceConfig is what a Service works with.
type serviceConfig struct {
	store     *state.Store
	buffer    *Buffer
	journal   *journal
	status    func() *nodev1.StateReport // the reconciler's report
	trigger   func()                     // asks the reconciler for a pass
	artifacts *artifacts.Store
	drivers   map[nodev1.Engine]engines.Driver
	providers map[nodev1.EgressKind]providers.Driver
	trials    trialRunner // the node's one trial runner, shared with the reconciler
	docker    dockerapi.Client
	info      *hostInfo
	ring      *logRing
	edge      func(gen uint64) reconcile.EdgeClient // the control client of an edge generation
	certs     *acme.Manager                         // stores imported certificates (PutCertificate)
	stats     *statsCollector                       // the minute statistics; nil in tests that need none
	geo       *geoStore                             // the country databases; nil makes one in data/geoip
	diag      *diag.Runner                          // the checks (RunDiagnostics); nil answers Unimplemented
	log       *slog.Logger
	now       func() time.Time

	// The self-update: the installer (nil: UpdateSelf is refused), the node's
	// home and the agent's own binary (kept by the binary GC), whether this
	// process wrote its healthy marker, and how the agent is asked to stop
	// for a restart into the new binary.
	installer *selfupdate.Installer
	home      string
	ownBinary string
	healthy   func() bool
	restart   func()

	// The edge update: the reconciler's RollEdge (nil: UpdateEdge is
	// refused), how "<binary> version" runs (nil: the installer's Exec, else
	// the program itself), and the warnings of the host (edge-handoff-unsafe).
	rollEdge func(ctx context.Context, binary string, sum []byte) (uint64, error)
	edgeExec func(ctx context.Context, path string, args ...string) ([]byte, error)
	warnings []string
}

// Service is the agent's NodeService, the API the panel calls over mTLS.
type Service struct {
	serviceConfig
	maxUpload int64

	applyMu sync.Mutex // one ApplyState at a time
	// updateMu: one UpdateSelf at a time, and no binary GC beside it.
	updateMu sync.Mutex
	// updateLocked, if set (tests), is called when an UpdateSelf has taken
	// updateMu.
	updateLocked func()
	// edgeRollTimeout bounds an UpdateEdge (0: edgeRollTimeout).
	edgeRollTimeout time.Duration

	// settingsHook, if set, is told the settings of every state that is
	// accepted, so that the management listeners follow mgmt_sni and
	// mgmt_hidden_only (spec 5.3). It is set once, before serving begins.
	settingsHook func(*nodev1.NodeSettings)

	mu          sync.Mutex
	desiredGen  uint64           // the generation of the stored desired state
	ipPolicy    nodev1.IpPolicy  // its IP policy
	ipRetention uint32           // its ip_retention_hours
	geoRef      *nodev1.GeoIPRef // the country database it names
	edgeRolling bool             // an UpdateEdge runs
}

// restartKey is the context key of the restart flag of a call: an UpdateSelf
// that changed bin/current sets it, and the restart is asked for once the
// answer of that call went out (handler).
type restartKey struct{}

// askRestart asks for the restart after the answer of the call of ctx; a call
// that did not come through the handler (a test) asks at once.
func (s *Service) askRestart(ctx context.Context) {
	if due, ok := ctx.Value(restartKey{}).(*atomic.Bool); ok {
		due.Store(true)
		return
	}
	if s.restart != nil {
		s.restart()
	}
}

var _ nodev1connect.NodeServiceHandler = (*Service)(nil)

// newService makes the service. It reads the stored desired state for its
// generation and IP policy; one that cannot be read counts as none (the panel
// sends its state again).
func newService(cfg serviceConfig) *Service {
	if cfg.geo == nil {
		cfg.geo = newGeoStore(cfg.store.Paths.GeoIPDir(), cfg.now, nil, cfg.log)
	}
	s := &Service{serviceConfig: cfg, maxUpload: defaultMaxUpload}
	if s.geo.event == nil {
		s.geo.event = s.event
	}
	st, err := cfg.store.LoadDesired()
	if err != nil {
		cfg.log.Error("agent: the desired state cannot be read; the panel will send it again", "err", err)
	}
	s.desiredGen = st.GetGeneration()
	s.ipPolicy = st.GetSettings().GetIpPolicy()
	s.ipRetention = st.GetSettings().GetIpRetentionHours()
	s.geoRef = st.GetSettings().GetGeoip()
	return s
}

// handler is the HTTP handler of the service.
func (s *Service) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(nodev1connect.NewNodeServiceHandler(s,
		connect.WithReadMaxBytes(maxMessageBytes),
		connect.WithRecover(s.recovered),
	))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		due := new(atomic.Bool)
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), restartKey{}, due)))
		// The answer of this call, an UpdateSelf that installed a new binary,
		// has been written: now the agent stops for the restart. Other calls
		// that end meanwhile ask for nothing.
		if due.Load() && s.restart != nil {
			s.restart()
		}
	})
}

func (s *Service) recovered(_ context.Context, spec connect.Spec, _ http.Header, p any) error {
	s.log.Error("agent: a call panicked", "procedure", spec.Procedure, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

// newHTTPServer is the management server: HTTP/2 only (gRPC needs it), over
// the TLS configuration of the node's certificate. base is the context of
// every call; cancelling it ends the streams, so that Shutdown can finish.
func newHTTPServer(h http.Handler, conf *tls.Config, log *slog.Logger, base context.Context) *http.Server {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	return &http.Server{
		Handler:           h,
		TLSConfig:         conf,
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       5 * time.Minute,
		// A panel that went away without a word is found by pings.
		HTTP2: &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
		// Every scanner of the internet fails the handshake: debug, not noise.
		ErrorLog:    slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		BaseContext: func(net.Listener) context.Context { return base },
	}
}

func (s *Service) desiredGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.desiredGen
}

func (s *Service) ipFull() bool { return s.ipMode() == modeFull }

// ipMode is what the node's IP policy lets the statistics keep.
func (s *Service) ipMode() ipMode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return modeOf(s.ipPolicy)
}

// ipRetentionTime is how long client addresses stay in the buffer:
// ip_retention_hours, 168 h when it is 0.
func (s *Service) ipRetentionTime() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.ipRetention
	if h == 0 {
		h = state.DefaultIPRetentionHours
	}
	return time.Duration(h) * time.Hour
}

func (s *Service) supports(e nodev1.Engine, t nodev1.ProxyType) bool {
	d, ok := s.drivers[e]
	return ok && d != nil && d.Supports(t)
}

// event records an event of the agent's in the journal.
func (s *Service) event(kind, severity, msg string, details map[string]string) {
	s.journal.event(&nodev1.NodeEvent{Kind: kind, Severity: severity, Message: msg, Details: details})
}

// ---- GetInfo ----------------------------------------------------------------------

// capabilities are what this build of the node can do, sorted, as GetInfo
// reports them; GetInfoResponse.capabilities in node.proto says what each
// means. A node that does not report them has the slice-1 baseline: fake-TLS
// proxies on telemt. The panel stores them, and from slice 2 on refuses a
// change that a node cannot take (Ruling 43).
var capabilities = []string{
	"artifact-direct",     // NodeSettings.artifact_source direct: the node downloads ArtifactRef.url (slice 5)
	"artifact-trial",      // UploadArtifact tries the binary out; artifacts carry state (slice 5)
	"diagnostics",         // RunDiagnostics, DiagnosticsReport in Watch (slice 6)
	"dns-forwarder",       // NodeSettings.dns_mode, the edge's DNS forwarder (slice 2)
	"edge-roll",           // data/run/roll-edge (state.Paths.EdgeRollPath)
	"edge-roll-nonce",     // NodeSettings.edge_roll_nonce rolls the edge (slice 6)
	"edge-version",        // edge_version is the running edge's (Ruling 38)
	"egress-interface",    // DIRECT egresses through an interface of the node (Ruling S2-19)
	"egress-psiphon-core", // PSIPHON egresses on Psiphon's own client (not "egress-psiphon": warp-plus)
	"egress-warp",         // WARP egresses on Xray with a device of the node's
	"egress-xray",         // XRAY_URI and XRAY_SUBSCRIPTION egresses
	"engine-mtg",          // fake-TLS proxies on mtg, switched by blue-green (slice 5)
	"faketls",             // fake-TLS proxies on telemt
	"last-error",          // StateReport.last_error
	"me-routing",          // middle-proxy traffic by address, NAT from the exit address
	"restart-nonce",       // Proxy.restart_nonce rolls the engine by blue-green (slice 6)
	"rollout-status",      // serving engine, failed_engine/failed_version, egress_instances (slice 5)
	"stats-v2",            // countries, member minutes, edge refusals, IP retention, send-time filters, UploadGeoIP (slice 6)
	"update-edge",         // UpdateEdge rolls the edge to an installed binary (slice 5)
	"update-self",         // UpdateSelf, GetInfo binaries/healthy/warnings (slice 5)
	"web-diagnostics",     // web.* checks, WebSettings.reissue_nonce (slice 6)
}

// capProbeSources is the capability of an edge that exempts the panel's probes
// (EdgeConfig.probe_sources, Ruling R6-1). The edge, not the agent, does it,
// so it is reported only while the running edge is of the agent's version
// (Ruling 38): an edge started by an older agent keeps counting the probes as
// clients until it is rolled.
const capProbeSources = "probe-sources"

// capabilitiesWith returns the capabilities of the node, sorted, while the
// running edge is of version edgeVersion ("" when that is not known).
func capabilitiesWith(edgeVersion string) []string {
	caps := slices.Clone(capabilities)
	if edgeVersion != "" && edgeVersion == version.Version {
		i, _ := slices.BinarySearch(caps, capProbeSources)
		caps = slices.Insert(caps, i, capProbeSources)
	}
	return caps
}

// GetInfo describes the node: versions, platform, public addresses,
// generations, artifacts, the owners of the listening ports, and the address
// the call came from.
func (s *Service) GetInfo(ctx context.Context, req *connect.Request[nodev1.GetInfoRequest]) (*connect.Response[nodev1.GetInfoResponse], error) {
	ctx, cancel := context.WithTimeout(ctx, infoTimeout)
	defer cancel()
	st, err := s.store.LoadDesired()
	if err != nil {
		st = nil
	}
	rt, err := s.store.LoadRuntime()
	if err != nil {
		rt = nil
	}
	edgeVersion := s.edgeVersion(ctx, rt)
	resp := &nodev1.GetInfoResponse{
		AgentVersion:      version.Version,
		EdgeVersion:       edgeVersion,
		Arch:              runtime.GOARCH,
		Os:                s.info.osName(),
		PublicIps:         s.info.publicIPs(ctx),
		AppliedGeneration: s.status().GetAppliedGeneration(),
		DesiredGeneration: s.desiredGeneration(),
		Artifacts:         listArtifacts(s.artifacts),
		PortOwners:        portOwners(ctx, s.info.proc, s.info.docker, expectedOwners(st, rt)),
		Capabilities:      capabilitiesWith(edgeVersion),
		Healthy:           s.healthy != nil && s.healthy(),
		PeerAddr:          peerIP(req.Peer().Addr),
		GeoipStored:       s.geo.stored(),
		Warnings:          append(release.KeyWarnings(), s.warnings...),
	}
	if s.home != "" {
		resp.Binaries = selfupdate.Binaries(s.home)
	}
	return connect.NewResponse(resp), nil
}

// peerIP is the IP of the peer of a call as GetInfo reports it (R6-1): the
// address without its port, an IPv4-mapped one unmapped, "" when it is not a
// unicast address (or not an address at all). The peer address is the remote
// address of the connection: the TCP source on the plain management listener,
// the source of the PROXY v2 header on the hidden one (newProxyV2Listener).
func peerIP(addr string) string {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return ""
	}
	ip := ap.Addr().Unmap()
	unicast := ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	if ip.Zone() != "" || !unicast {
		return ""
	}
	return ip.String()
}

// ---- RunDiagnostics ---------------------------------------------------------------

// RunDiagnostics runs every check of a scope, "node" or "proxy:<id>", and
// streams the results as they come (diag.Runner.Run). A scope the node does
// not know is InvalidArgument, a second run while one is under way
// ResourceExhausted. The end of a run is the node event diagnostics_run with
// the counts.
func (s *Service) RunDiagnostics(ctx context.Context, req *connect.Request[nodev1.RunDiagnosticsRequest], stream *connect.ServerStream[nodev1.DiagnosticResult]) error {
	if s.diag == nil {
		return connect.NewError(connect.CodeUnimplemented, errors.New("this node does not run diagnostics"))
	}
	scope := req.Msg.GetScope()
	start := s.now()
	counts := map[nodev1.CheckStatus]int{}
	var sendErr error
	err := s.diag.Run(ctx, scope, func(r diag.Result) {
		counts[r.Status]++
		if sendErr == nil {
			sendErr = stream.Send(r.Proto())
		}
	})
	switch {
	case errors.Is(err, diag.ErrBusy):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, diag.ErrScope):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return connect.NewError(connect.CodeInternal, err)
	}
	details := map[string]string{
		"scope": clipText(scope, 128),
		"ok":    strconv.Itoa(counts[diag.OK]), "warn": strconv.Itoa(counts[diag.Warn]),
		"fail": strconv.Itoa(counts[diag.Fail]), "skip": strconv.Itoa(counts[diag.Skip]),
		"duration_ms": strconv.FormatInt(s.now().Sub(start).Milliseconds(), 10),
	}
	sev := sevInfo
	if counts[diag.Fail] > 0 {
		sev = sevWarning
	}
	s.event(evDiagnosticsRun, sev, fmt.Sprintf("diagnostics of %s: %d ok, %d warn, %d fail, %d skipped",
		details["scope"], counts[diag.OK], counts[diag.Warn], counts[diag.Fail], counts[diag.Skip]), details)
	return sendErr
}

// edgeVersion is the version of the edge that carries the traffic, the
// generation of the runtime record, as the edge says in Health. It is not the
// agent's: an edge runs the binary the agent ran when it made the edge, and
// keeps it when the agent is updated, until the edge is rolled (Ruling 38). ""
// when it is not known: there is no edge yet, it does not answer, or it is
// older than the version it reports.
func (s *Service) edgeVersion(ctx context.Context, rt *state.Runtime) string {
	if rt == nil || rt.EdgeGeneration == 0 || s.edge == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, edgeHealthTimeout)
	defer cancel()
	h, err := s.edge(rt.EdgeGeneration).Health(ctx)
	if err != nil {
		return ""
	}
	return clipText(h.GetVersion(), maxVersionText)
}

// ---- ApplyState -------------------------------------------------------------------

// ApplyState takes the panel's whole desired state. A generation that is not
// newer than the stored one is refused as stale; a state that does not
// validate is refused with the problems; otherwise it is stored and the
// reconciler is woken up.
func (s *Service) ApplyState(_ context.Context, req *connect.Request[nodev1.ApplyStateRequest]) (*connect.Response[nodev1.ApplyStateResponse], error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	cur := s.desiredGeneration()
	answer := func(accepted bool, reason string, gen uint64) (*connect.Response[nodev1.ApplyStateResponse], error) {
		return connect.NewResponse(&nodev1.ApplyStateResponse{Accepted: accepted, Reason: reason, Generation: gen}), nil
	}

	st := req.Msg.GetState()
	if st == nil {
		const reason = "the request has no state"
		s.log.Warn("agent: desired state refused", "reason", reason)
		s.event(evStateRejected, sevWarning, "desired state refused: "+reason, nil)
		return answer(false, reason, cur)
	}
	gen := st.GetGeneration()
	details := map[string]string{"generation": strconv.FormatUint(gen, 10)}
	if gen <= cur {
		// The panel sends a state when its generation is newer than the
		// node's; a stale one is a race or a restored panel, not news.
		s.log.Info("agent: stale desired state refused", "generation", gen, "have", cur)
		return answer(false, reasonStale, cur)
	}
	if err := state.Validate(st, s.supports); err != nil {
		// Validation messages never quote secrets.
		s.log.Warn("agent: desired state refused", "generation", gen, "err", err)
		s.event(evStateRejected, sevWarning, fmt.Sprintf("desired state of generation %d refused: %v", gen, err), details)
		return answer(false, err.Error(), cur)
	}
	if err := s.store.SaveDesired(st); err != nil {
		reason := "the node cannot store the state: " + err.Error()
		s.log.Error("agent: desired state not stored", "generation", gen, "err", err)
		s.event(evStateRejected, sevError, fmt.Sprintf("desired state of generation %d not stored: %v", gen, err), details)
		return answer(false, reason, cur)
	}

	policy := st.GetSettings().GetIpPolicy()
	s.mu.Lock()
	was := modeOf(s.ipPolicy)
	s.desiredGen = gen
	s.ipPolicy = policy
	s.ipRetention = st.GetSettings().GetIpRetentionHours()
	s.geoRef = st.GetSettings().GetGeoip()
	s.mu.Unlock()
	// Before the answer, nothing the new policy forbids stays: the open
	// minute loses it (a minute being published finishes first), then the
	// buffer (R6-5).
	if mode := modeOf(policy); mode < was {
		if s.stats != nil {
			s.stats.limit(mode)
		}
		if was == modeFull {
			s.scrubIPs()
		}
	}
	s.syncGeoIP()
	s.trigger()
	if s.settingsHook != nil {
		s.settingsHook(st.GetSettings())
	}
	s.log.Info("agent: desired state accepted", "generation", gen, "listeners", len(st.GetListeners()), "proxies", len(st.GetProxies()))
	s.event(evStateAccepted, sevInfo, fmt.Sprintf("desired state of generation %d accepted", gen), details)
	return answer(true, "", gen)
}

// scrubIPs removes client addresses from the buffer, as the IP policy no
// longer allows them, and empties the write-ahead log, so that they are gone
// from the disk.
func (s *Service) scrubIPs() {
	n, err := s.buffer.ScrubIPs()
	if err != nil {
		s.log.Error("agent: client addresses could not be removed from the record buffer", "err", err)
		return
	}
	if n > 0 {
		s.log.Info("agent: client addresses removed from the record buffer", "records", n)
	}
	if err := s.buffer.checkpoint(); err != nil {
		s.log.Warn("agent: the record buffer's write-ahead log could not be emptied after a scrub", "err", err)
	}
}

// ---- Watch ------------------------------------------------------------------------

// Watch opens with the current state report (connect sends the response
// headers with the first message, and the panel waits for them), replays the
// buffered records after the cursor, then streams new ones as they come. The
// opening report and the state reports that change nothing carry no sequence
// number.
func (s *Service) Watch(ctx context.Context, req *connect.Request[nodev1.WatchRequest], stream *connect.ServerStream[nodev1.WatchResponse]) error {
	w := s.journal.watch()
	defer s.journal.unwatch(w)
	opening := &nodev1.WatchResponse{TsUnix: s.now().Unix(), Payload: &nodev1.WatchResponse_State{State: s.status()}}
	if err := stream.Send(opening); err != nil {
		return err
	}

	policy := req.Msg.GetIpPolicy()
	last := req.Msg.GetCursor()
	if top, err := s.buffer.LastSeq(); err == nil && last > top {
		// The buffer was made again (lost, damaged): numbers start above the
		// old ones, but the panel's cursor must not hold back the new ones.
		s.log.Warn("agent: the panel's cursor is past the record buffer; streaming from its end", "cursor", last, "last", top)
		last = top
	}
	for {
		changed := s.buffer.Changed()
		recs, next, full, err := s.buffer.page(last, watchPage)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return connect.NewError(connect.CodeUnavailable, err)
		}
		for _, rec := range recs {
			if err := stream.Send(s.forPanel(rec, policy)); err != nil {
				return err
			}
		}
		last = next
		select {
		case rec := <-w.live:
			if err := stream.Send(s.forPanel(rec, policy)); err != nil {
				return err
			}
		default:
		}
		if full {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case rec := <-w.live:
			if err := stream.Send(s.forPanel(rec, policy)); err != nil {
				return err
			}
		}
	}
}

// forPanel filters a record by the IP policy when it goes out (R6-5): it
// keeps the client addresses only when the node's current policy and the
// stream's (the panel's, as it opened Watch; unset is the node's) are both
// full, and the country minutes only when neither is off. Records buffered
// under an earlier policy are filtered as well.
func (s *Service) forPanel(rec *nodev1.WatchResponse, stream nodev1.IpPolicy) *nodev1.WatchResponse {
	st := rec.GetStats()
	if len(st.GetIps()) == 0 && len(st.GetCountries()) == 0 {
		return rec
	}
	node := s.ipMode()
	panel := node
	if stream != nodev1.IpPolicy_IP_POLICY_UNSPECIFIED {
		panel = modeOf(stream)
	}
	keepIPs := node == modeFull && panel == modeFull
	keepCountries := node != modeOff && panel != modeOff
	if (keepIPs || len(st.GetIps()) == 0) && (keepCountries || len(st.GetCountries()) == 0) {
		return rec
	}
	out := proto.Clone(rec).(*nodev1.WatchResponse)
	if !keepIPs {
		out.GetStats().Ips = nil
	}
	if !keepCountries {
		out.GetStats().Countries = nil
	}
	return out
}

// ---- UploadArtifact -----------------------------------------------------------------

// errPutEnded says that Put stopped reading the upload; its error is the
// answer.
var errPutEnded = errors.New("agent: the artifact store stopped reading the upload")

// UploadArtifact receives an engine artifact: the first message is its
// reference (meta), the rest are chunks of the file, at most 200 MiB in all.
// The store verifies the checksum before anything is kept. Then the binary is
// tried out in the runner image (the trial of the driver or provider named by
// the reference's engine): a trial that ran is recorded and answered with
// tried=true and usable; one that did not run (Docker unreachable, the runner
// image missing) is answered with tried=false and recorded nowhere, so that
// the panel uploads again later.
func (s *Service) UploadArtifact(ctx context.Context, stream *connect.ClientStream[nodev1.UploadArtifactRequest]) (*connect.Response[nodev1.UploadArtifactResponse], error) {
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return nil, err
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the upload is empty: the first message must be meta"))
	}
	meta := stream.Msg().GetMeta()
	if meta == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the first message of an upload must be meta, not a chunk"))
	}
	ref := artifacts.Ref{
		Engine: meta.GetEngine(), Version: meta.GetVersion(), Arch: meta.GetArch(),
		SHA256: meta.GetSha256(), FileName: meta.GetFileName(), Binary: meta.GetBinary(),
	}
	if ref.Binary == "" {
		ref.Binary = s.binaryName(ref.Engine)
	}
	if err := ref.Validate(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	pr, pw := io.Pipe()
	stored := make(chan error, 1)
	go func() {
		err := s.artifacts.Put(ref, pr)
		// A Put that stops early must not leave the receiver blocked.
		_ = pr.CloseWithError(cmpErr(err, errPutEnded))
		stored <- err
	}()
	recvErr := s.receiveChunks(stream, pw)
	if recvErr != nil {
		_ = pw.CloseWithError(recvErr) // Put fails and leaves nothing behind
	} else {
		_ = pw.Close()
	}
	putErr := <-stored
	if recvErr != nil && !errors.Is(recvErr, errPutEnded) {
		return nil, recvErr
	}
	if putErr != nil {
		return nil, s.uploadError(ref, putErr)
	}

	sha := strings.ToLower(ref.SHA256)
	s.log.Info("agent: artifact stored", "engine", ref.Engine, "version", ref.Version, "arch", ref.Arch, "sha256", sha)
	details := map[string]string{"engine": ref.Engine, "version": ref.Version, "arch": ref.Arch, "sha256": sha}
	resp := &nodev1.UploadArtifactResponse{Stored: true, Sha256: sha}

	res := s.tryArtifact(ctx, ref)
	if res.Ran {
		// An outcome the node cannot keep is no outcome: the panel would
		// otherwise hold a verdict that GetInfo does not show.
		rec := artifacts.TrialRecord{OK: res.OK, Reason: res.Reason, At: s.now(), Image: RunnerImage}
		if err := s.artifacts.RecordTrial(ref, rec); err != nil {
			s.log.Error("agent: the trial record could not be written", "engine", ref.Engine, "version", ref.Version, "arch", ref.Arch, "err", err)
			res = trial.Result{Reason: "recording the trial: " + err.Error()}
		}
	}
	resp.Tried, resp.Usable, resp.Reason = res.Ran, res.OK, res.Reason
	switch {
	case !res.Ran:
		resp.Reason = "trial not run: " + res.Reason
		s.log.Warn("agent: the trial of the artifact did not run", "engine", ref.Engine, "version", ref.Version, "arch", ref.Arch, "reason", res.Reason)
		details["trial"] = stateUntried
	case res.OK:
		details["trial"] = "ok"
	default:
		s.log.Warn("agent: the artifact is unusable", "engine", ref.Engine, "version", ref.Version, "arch", ref.Arch, "reason", res.Reason)
		details["trial"] = stateUnusable
		details["reason"] = clipText(res.Reason, maxStateReason)
	}
	s.trigger() // a proxy may have waited for this artifact
	s.event(evArtifact, sevInfo, fmt.Sprintf("artifact %s %s for %s stored (trial %s)", ref.Engine, ref.Version, ref.Arch, details["trial"]), details)
	return connect.NewResponse(resp), nil
}

// tryArtifact runs the trial of a stored artifact. Without a runner, or for a
// component without a trial, nothing runs.
func (s *Service) tryArtifact(ctx context.Context, ref artifacts.Ref) trial.Result {
	tr, ok := s.trialOf(ref.Engine, ref.Version)
	switch {
	case !ok:
		return trial.Result{Reason: "no trial is known for " + ref.Engine}
	case s.trials == nil:
		return trial.Result{Reason: "the node has no trial runner"}
	}
	return s.trials.Run(ctx, s.artifacts.BinaryPath(ref), ref.Binary, tr)
}

// trialOf is the trial of a component's binary of a version: that of the
// engine driver of that name, or of the provider driver with that binary name
// (xray, psiphon-core).
func (s *Service) trialOf(component, version string) (engines.Trial, bool) {
	for e, d := range s.drivers {
		t, ok := d.(engines.Trialer)
		if ok && strings.EqualFold(strings.TrimPrefix(e.String(), "ENGINE_"), component) {
			return t.Trial(version), true
		}
	}
	for _, d := range s.providers {
		t, ok := d.(engines.Trialer)
		if ok && d.BinaryName() == component {
			return t.Trial(version), true
		}
	}
	return engines.Trial{}, false
}

// receiveChunks copies the chunks of an upload into w.
func (s *Service) receiveChunks(stream *connect.ClientStream[nodev1.UploadArtifactRequest], w io.Writer) error {
	var total int64
	for stream.Receive() {
		msg := stream.Msg()
		if msg.GetMeta() != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("meta may only be the first message of an upload"))
		}
		chunk := msg.GetChunk()
		total += int64(len(chunk))
		if total > s.maxUpload {
			return connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("the upload is over %d bytes", s.maxUpload))
		}
		if _, err := w.Write(chunk); err != nil {
			return errPutEnded
		}
	}
	return stream.Err()
}

func (s *Service) uploadError(ref artifacts.Ref, err error) error {
	switch {
	case errors.Is(err, artifacts.ErrChecksum), errors.Is(err, artifacts.ErrInvalidRef), errors.Is(err, artifacts.ErrArchive):
		s.log.Warn("agent: artifact refused", "engine", ref.Engine, "version", ref.Version, "arch", ref.Arch, "err", err)
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, artifacts.ErrTooLarge):
		return connect.NewError(connect.CodeResourceExhausted, err)
	}
	s.log.Error("agent: artifact not stored", "engine", ref.Engine, "version", ref.Version, "arch", ref.Arch, "err", err)
	return connect.NewError(connect.CodeInternal, fmt.Errorf("the node could not store the artifact: %w", err))
}

// binaryName is the binary name of an engine's driver, or of the provider
// whose binary is named like the component ("" when neither is known, which
// the reference check then refuses).
func (s *Service) binaryName(component string) string {
	for e, d := range s.drivers {
		if d != nil && strings.EqualFold(strings.TrimPrefix(e.String(), "ENGINE_"), component) {
			return d.BinaryName()
		}
	}
	for _, d := range s.providers {
		if d != nil && d.BinaryName() == component {
			return component
		}
	}
	return ""
}

func cmpErr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

// ---- UpdateSelf -------------------------------------------------------------------

// UpdateSelf receives a signed agent binary: the first message is its meta,
// the rest are chunks of the file, at most 200 MiB in all. The installer
// verifies it and switches bin/current; when that changed, the answer says
// restarting and, once it went out, the agent stops as for SIGTERM and exits
// with code 75, so that the launcher starts the new binary. Old binaries are
// collected after every call.
func (s *Service) UpdateSelf(ctx context.Context, stream *connect.ClientStream[nodev1.UpdateSelfRequest]) (*connect.Response[nodev1.UpdateSelfResponse], error) {
	if !s.updateMu.TryLock() {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("another UpdateSelf is running"))
	}
	defer s.updateMu.Unlock()
	if s.updateLocked != nil {
		s.updateLocked()
	}
	if s.installer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this agent cannot update itself"))
	}
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return nil, err
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the update is empty: the first message must be meta"))
	}
	meta := stream.Msg().GetMeta()
	if meta == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the first message of an update must be meta, not a chunk"))
	}
	defer s.collectBinaries(ctx)

	pr, pw := io.Pipe()
	type result struct {
		changed bool
		err     error
	}
	installed := make(chan result, 1)
	go func() {
		changed, err := s.installer.Install(ctx, meta, pr)
		_ = pr.CloseWithError(cmpErr(err, errPutEnded))
		installed <- result{changed, err}
	}()
	recvErr := s.receiveBinary(stream, pw)
	if recvErr != nil {
		_ = pw.CloseWithError(recvErr)
	} else {
		_ = pw.Close()
	}
	res := <-installed
	if recvErr != nil && !errors.Is(recvErr, errPutEnded) {
		return nil, recvErr
	}
	if res.err != nil {
		return nil, s.updateError(meta, res.err)
	}

	v := meta.GetVersion()
	if !res.changed {
		s.log.Info("agent: UpdateSelf: bin/current points to this version already", "version", v)
		return connect.NewResponse(&nodev1.UpdateSelfResponse{Version: v}), nil
	}
	from := version.Version
	msg := fmt.Sprintf("node agent updating from %s to %s", from, v)
	s.log.Info("agent: "+msg+"; restarting", "event", evUpdating)
	s.event(evUpdating, sevInfo, msg, map[string]string{"from": from, "to": v})
	s.askRestart(ctx)
	return connect.NewResponse(&nodev1.UpdateSelfResponse{Version: v, Restarting: true}), nil
}

// receiveBinary copies the chunks of an update into w.
func (s *Service) receiveBinary(stream *connect.ClientStream[nodev1.UpdateSelfRequest], w io.Writer) error {
	var total int64
	for stream.Receive() {
		msg := stream.Msg()
		if msg.GetMeta() != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("meta may only be the first message of an update"))
		}
		chunk := msg.GetChunk()
		total += int64(len(chunk))
		if total > s.maxUpload {
			return connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("the update is over %d bytes", s.maxUpload))
		}
		if _, err := w.Write(chunk); err != nil {
			return errPutEnded
		}
	}
	return stream.Err()
}

// updateError is the gRPC error of a refused install.
func (s *Service) updateError(meta *nodev1.NodeBinary, err error) error {
	code := connect.CodeInternal
	switch {
	case errors.Is(err, selfupdate.ErrInvalid), errors.Is(err, selfupdate.ErrChecksum):
		code = connect.CodeInvalidArgument
	case errors.Is(err, selfupdate.ErrSignature), errors.Is(err, selfupdate.ErrDowngrade):
		code = connect.CodePermissionDenied
	case errors.Is(err, selfupdate.ErrUnusable), errors.Is(err, selfupdate.ErrExists), errors.Is(err, selfupdate.ErrNoKeys):
		code = connect.CodeFailedPrecondition
	case errors.Is(err, selfupdate.ErrTooLarge):
		code = connect.CodeResourceExhausted
	}
	s.log.Warn("agent: UpdateSelf refused", "version", clipText(meta.GetVersion(), maxVersionText), "arch", clipText(meta.GetArch(), 32), "err", err)
	return connect.NewError(code, err)
}

// collectBinaries removes old agent binaries (selfupdate.GC), keeping the
// agent's own and every one a managed container mounts. When the containers
// cannot be listed nothing is removed. The caller holds updateMu.
func (s *Service) collectBinaries(ctx context.Context) {
	if s.home == "" {
		return
	}
	mounted, err := mountedBinaries(ctx, s.docker)
	if err != nil {
		s.log.Warn("agent: old agent binaries are kept: the containers cannot be listed", "err", err)
		return
	}
	own := resolved(s.ownBinary)
	keep := func(p string) bool {
		p = filepath.Clean(p)
		return p == own || mounted[p]
	}
	for _, p := range selfupdate.GC(s.home, keep) {
		s.log.Info("agent: old agent binary removed", "path", p)
	}
}

// mountedBinaries is the set of the host paths that managed containers bind,
// cleaned, and of what they resolve to.
func mountedBinaries(ctx context.Context, docker dockerapi.Client) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	list, err := docker.List(ctx, map[string]string{"postern.managed": "true"}, true)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, c := range list {
		d, err := docker.Inspect(ctx, c.ID)
		if errors.Is(err, dockerapi.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, b := range d.Binds {
			if host, _, _ := strings.Cut(b, ":"); host != "" {
				out[filepath.Clean(host)] = true
				out[resolved(host)] = true
			}
		}
	}
	return out, nil
}

// resolved is path with its symlinks resolved, or path cleaned.
func resolved(path string) string {
	if path == "" {
		return ""
	}
	if p, err := filepath.EvalSymlinks(path); err == nil {
		return p
	}
	return filepath.Clean(path)
}
