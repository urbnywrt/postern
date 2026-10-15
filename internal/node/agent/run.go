package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"aead.dev/minisign"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/edge/control"
	"github.com/urbnywrt/postern/internal/edge/dns"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/mtg"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/selfupdate"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/node/trial"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/probe"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/psiphoncore"
	"github.com/urbnywrt/postern/internal/providers/xray"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/version"
)

const (
	// DefaultHome is POSTERN_HOME when it is not set.
	DefaultHome = "/opt/postern"
	// RunnerImage is the image of every container the agent creates (Global
	// Constraints), pinned by digest.
	RunnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

	// stateEvery is the longest a Watch stream goes without a state report;
	// stateCheck is how often that is checked.
	stateEvery = 60 * time.Second
	stateCheck = 5 * time.Second
	// pruneEvery is how often the buffer drops what is older than 7 days and
	// the client addresses older than the IP retention (Buffer.Maintain).
	pruneEvery = time.Hour
	// probeTimeout bounds one fake-TLS probe of a new engine generation.
	probeTimeout = 10 * time.Second
	// shutdownTimeout is how long the management server gets to finish the
	// calls that are being answered when the agent stops.
	shutdownTimeout = 5 * time.Second
	// hostOSRelease is where compose mounts the host's /etc/os-release.
	hostOSRelease = "/host/etc/os-release"
	// hostResolvConf is the resolv.conf of the agent's container, which on the
	// host's network is a copy of the host's: its nameservers are the fallback
	// of the edge's DNS forwarder.
	hostResolvConf = "/etc/resolv.conf"
	// edgeDNSTimeout bounds the question to the edge, at the start, whether its
	// DNS forwarder runs.
	edgeDNSTimeout = 2 * time.Second
)

// nodeIDRe is the form of the node ids the panel issues.
var nodeIDRe = regexp.MustCompile(`^[0-9A-Z]{26}$`)

// Options configure Run.
type Options struct {
	// Home is POSTERN_HOME, the node's directory; empty means /opt/postern.
	Home string
	// MgmtListen is the address of the management listener; empty means
	// 0.0.0.0 and the management port in the node's bundle.
	MgmtListen string
	// Stderr receives the log; nil means os.Stderr.
	Stderr io.Writer
	// ACMEStaging takes the certificates of WEB proxies from the staging
	// directory of Let's Encrypt (POSTERN_ACME_STAGING=1): for tests.
	ACMEStaging bool

	// Seams for the tests; their zero values mean the real thing.
	docker            dockerapi.Client
	now               func() time.Time
	proc              fs.FS
	osRelease         []string
	addrs             func() ([]net.Addr, error)
	echoURLs          []string // nil: the default services; empty: none
	nodeBinary        string
	edge              func(gen uint64) reconcile.EdgeClient
	listening         func(net.Addr) // the plain management listener bound (each time it opens)
	hiddenLn          func(net.Addr) // the hidden management listener bound
	passed            func(error)    // after every reconcile pass, once the marker is decided
	mgmtFallbackAfter time.Duration  // the fallback timeout; 0 means the default
	mgmtCheckEvery    time.Duration  // how often the fallback is checked; 0 means the default
	mgmtProxyTimeout  time.Duration  // the PROXY v2 header timeout; 0 means the default

	resolvConf   string      // the host's resolv.conf; "" is /etc/resolv.conf
	dnsForwarder string      // where the edge's forwarder answers; "" is dns.ListenAddr
	dnsSwitch    *dns.Switch // the agent's resolver; nil makes one
	meConfigURLs []string    // the lists of the middle proxies; nil: Telegram's

	releaseKeys func(release.KeySet) ([]minisign.PublicKey, error)                     // nil: release.TrustedKeys
	exec        func(ctx context.Context, path string, args ...string) ([]byte, error) // nil: run the program
	after       func(time.Duration) <-chan time.Time                                   // the marker deadline's clock; nil: time.After
	procSys     string                                                                 // /proc/sys of the host; "" is /proc/sys
	diagChecks  []diag.Check                                                           // the checks; nil: diag.Catalogue(), empty: none
}

// ErrRestart is what Run returns after UpdateSelf installed a new binary: the
// agent stopped so that its launcher starts the new one (postern-node agent
// exits with code 75).
var ErrRestart = errors.New("agent: restarting into the new binary")

// markerDeadline is how long after its start the agent may go without writing
// its healthy marker (R5-3): then it exits with an error, so that the launcher
// counts the start as an unhealthy one.
const markerDeadline = 10 * time.Minute

// Run is the node agent. It reads the node's bundle from <home>/pki and
// checks that the state in <home>/data/state is this node's, opens the record
// buffer, serves NodeService on the management address over mTLS, and runs
// the reconciler and the statistics until ctx ends. It writes the launcher's
// healthy marker once the server is serving, the desired state is loaded and
// a reconcile pass ran without a failure of the agent's own (see
// healthMarker.passed).
//
// It returns nil when ctx ended, and an error when the agent cannot start or
// its server fails.
func Run(ctx context.Context, opt Options) error {
	if opt.Home == "" {
		opt.Home = DefaultHome
	}
	if !filepath.IsAbs(opt.Home) {
		return fmt.Errorf("agent: POSTERN_HOME %q is not an absolute path", opt.Home)
	}
	stderr := opt.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	now := opt.now
	if now == nil {
		now = time.Now
	}
	ring := newLogRing(agentLogLines, now)
	log := slog.New(slog.NewTextHandler(io.MultiWriter(stderr, ring), nil))
	log.Info("agent: starting", "version", version.String(), "home", opt.Home)

	paths := state.Paths{Home: opt.Home}
	pkiDir := filepath.Join(opt.Home, "pki")
	bundle, err := loadBundle(pkiDir)
	if err != nil {
		return err
	}
	if err := checkIdentity(paths, bundle.NodeID, log); err != nil {
		return err
	}
	tlsConf, err := pki.ServerTLSConfig(bundle.CAPEM, bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		return fmt.Errorf("agent: the certificates in %s: %w", pkiDir, err)
	}

	buf, err := openBuffer(filepath.Join(opt.Home, "data", "stats.db"), bundle.NodeID, now, log)
	if err != nil {
		return err
	}
	defer func() { _ = buf.Close() }()
	if n, err := buf.Prune(); err != nil {
		log.Warn("agent: the record buffer could not be pruned", "err", err)
	} else if n > 0 {
		log.Info("agent: old records pruned", "records", n)
	}
	j := newJournal(buf, log, now)
	j.event(&nodev1.NodeEvent{Kind: evAgentStarted, Severity: sevInfo,
		Message: "node agent " + version.Version + " started", Details: map[string]string{"version": version.Version}})
	launcherDir := filepath.Join(paths.RunDir(), "launcher")
	reportRollback(launcherDir, j, log)
	procSys := opt.procSys
	if procSys == "" {
		procSys = "/proc/sys"
	}
	hostWarnings, unsafeWhy := handoffWarnings(procSys)
	if unsafeWhy != "" {
		msg := unsafeWhy + ": an edge roll aborts the connections still in the accept queue of the old generation; re-run install.sh, or restart the node container (docker restart postern-agent) on a node installed with Docker (Linux 5.14 or later)"
		log.Warn("agent: "+msg, "event", evHandoffUnsafe)
		j.event(&nodev1.NodeEvent{Kind: evHandoffUnsafe, Severity: sevWarning, Message: msg})
	}

	store := &state.Store{Paths: paths}
	startRuntime, err := store.LoadRuntime()
	if err != nil {
		log.Warn("agent: the runtime record cannot be read", "err", err)
	}
	startEdge := uint64(0) // the edge that runs, whose DNS forwarder is asked about below
	if startRuntime != nil {
		startEdge = startRuntime.EdgeGeneration
	}
	startDesired, _ := store.LoadDesired() // newService reports an error
	docker := opt.docker
	if docker == nil {
		docker = dockerapi.New("")
	}
	proc := opt.proc
	if proc == nil {
		proc = os.DirFS("/proc")
	}
	resolver := newNodeResolver(opt, log)
	info := &hostInfo{
		osRelease: opt.osRelease,
		addrs:     opt.addrs,
		echoURLs:  opt.echoURLs,
		resolver:  resolver.sw.Resolver(),
		proc:      proc,
		docker:    docker,
		now:       now,
		log:       log,
	}
	if info.osRelease == nil {
		info.osRelease = []string{hostOSRelease, "/etc/os-release"}
	}
	if info.addrs == nil {
		info.addrs = net.InterfaceAddrs
	}
	if info.echoURLs == nil {
		info.echoURLs = defaultEchoURLs
	}
	arts := &artifacts.Store{Root: paths.ArtifactsDir()}
	drivers := map[nodev1.Engine]engines.Driver{nodev1.Engine_ENGINE_TELEMT: telemt.New(), nodev1.Engine_ENGINE_MTG: mtg.New()}
	xrayDriver, psiphonDriver := xray.New(), psiphoncore.New()
	providerDrivers := map[nodev1.EgressKind]providers.Driver{
		nodev1.EgressKind_EGRESS_KIND_XRAY_URI:          xrayDriver,
		nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION: xrayDriver,
		nodev1.EgressKind_EGRESS_KIND_WARP:              xrayDriver,
		nodev1.EgressKind_EGRESS_KIND_PSIPHON:           psiphonDriver,
	}

	trigger := make(chan struct{}, 1)
	kick := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	marker := &healthMarker{path: filepath.Join(launcherDir, "healthy"), log: log}
	// The node's one trial runner: UploadArtifact and the reconciler share it,
	// so that its in-flight set covers every trial of the node.
	trials := &trial.Runner{Docker: docker, RunnerImage: RunnerImage, Timeout: trial.DefaultTimeout, Log: log}
	certs := &acme.Manager{Paths: paths, Staging: opt.ACMEStaging, Events: j.event, Log: log, Now: opt.now}
	rec := &reconcile.Reconciler{
		Docker:      docker,
		Store:       store,
		Artifacts:   arts,
		Trials:      trials,
		Drivers:     drivers,
		Providers:   providerDrivers,
		EdgeFactory: opt.edge,
		Probe:       fakeTLSProbe,
		L2:          l2Probe,
		// The agent's own connections (subscriptions, the lists of the middle
		// proxies, WARP registrations) resolve through the edge's forwarder
		// while it runs.
		Resolver:       resolver.sw.Resolver(),
		MEConfigURLs:   opt.meConfigURLs,
		Log:            log,
		Now:            opt.now,
		Version:        version.Version,
		RunnerImage:    RunnerImage,
		NodeBinaryPath: opt.nodeBinary,
		Arch:           runtime.GOARCH,
		Events:         j.event,
		// The forwarder of the edge asks the host's nameservers when
		// DNS-over-HTTPS fails; OnEdgeDNS is set below.
		HostNameservers: resolver.hostNameservers,
		// The certificates of WEB proxies: ACME over DNS-01, with its own
		// DNS-over-HTTPS lookups (the edge's forwarder may be down while a
		// certificate is due).
		Certs: certs,
	}
	if rec.EdgeFactory == nil {
		rec.EdgeFactory = func(gen uint64) reconcile.EdgeClient {
			return reconcile.NewEdgeClient(control.NewClient(paths.EdgeSocketPath(gen)))
		}
	}
	if rec.NodeBinaryPath == "" {
		rec.NodeBinaryPath = nodeBinaryPath(opt.Home)
	}
	// Until the first pass has run, the reports say what the runtime record
	// says (M1).
	rec.Seed(startDesired, startRuntime)
	status := func() *nodev1.StateReport { return fitReport(rec.Status()) }
	rec.OnPass = func(rep *nodev1.StateReport, err error) {
		marker.passed(err)
		j.state(fitReport(rep))
		if opt.passed != nil {
			opt.passed(err)
		}
	}

	collector := &statsCollector{
		source: newSocketSnapshots(paths.RunDir(), snapshotTimeout), agg: newAggregator(), journal: j,
		proc: proc, diskPath: opt.Home, log: log,
	}
	geo := newGeoStore(paths.GeoIPDir(), now, nil, log)
	diagRunner := newDiagRunner(diagDeps{
		store: store, docker: docker, edge: rec.EdgeFactory, drivers: drivers, artifacts: arts,
		info: info, home: opt.Home, stats: collector, now: now, certs: certs,
		checks: opt.diagChecks, egressReason: rec.EgressReason,
	})
	restartCh := make(chan struct{})
	var restartOnce sync.Once
	svc := newService(serviceConfig{
		store: store, buffer: buf, journal: j, status: status, trigger: kick,
		artifacts: arts, drivers: drivers, providers: providerDrivers, trials: trials,
		docker: docker, info: info, ring: ring, edge: rec.EdgeFactory,
		log: log, now: now, certs: certs, stats: collector, geo: geo, diag: diagRunner,
		installer: &selfupdate.Installer{
			Home: opt.Home, Arch: runtime.GOARCH, Running: version.Version,
			Keys: opt.releaseKeys, Exec: opt.exec,
		},
		home:      opt.Home,
		ownBinary: rec.NodeBinaryPath,
		healthy:   marker.isWritten,
		restart:   func() { restartOnce.Do(func() { close(restartCh) }) },
		rollEdge: func(ctx context.Context, binary string, sum []byte) (uint64, error) {
			return rec.RollEdge(ctx, binary, sum, kick)
		},
		edgeExec: opt.exec,
		warnings: hostWarnings,
	})
	collector.mode = svc.ipMode
	collector.agg.country = geo.country
	marker.setLoaded()
	if !svc.ipFull() {
		svc.scrubIPs()
	}
	svc.syncGeoIP()

	baseCtx, endCalls := context.WithCancel(context.Background())
	defer endCalls()
	hiddenPort, err := allocHiddenPort(store, &state.Allocator{})
	if err != nil {
		return fmt.Errorf("agent: the hidden management port: %w", err)
	}
	mgmt := &mgmtListeners{
		plainAddr:  mgmtListen(opt.MgmtListen, bundle.MgmtPort),
		hiddenPort: hiddenPort,
		handler:    svc.handler(),
		tlsConf:    tlsConf,
		baseCtx:    baseCtx,
		log:        log,
		now:        now,
		event: func(kind, severity, msg string, details map[string]string) {
			j.event(&nodev1.NodeEvent{Kind: kind, Severity: severity, Message: msg, Details: details})
		},
		proxyTimeout:  orDur(opt.mgmtProxyTimeout, proxyHeaderTimeout),
		fallbackAfter: orDur(opt.mgmtFallbackAfter, mgmtFallbackAfter),
		checkEvery:    orDur(opt.mgmtCheckEvery, mgmtCheckEvery),
		onPlain:       opt.listening,
		onHidden:      opt.hiddenLn,
	}
	// A newly applied state may change mgmt_sni or mgmt_hidden_only; the service
	// tells the controller, which opens or closes the listeners.
	svc.settingsHook = mgmt.apply
	if err := mgmt.start(startDesired.GetSettings()); err != nil {
		return fmt.Errorf("agent: the management listener: %w", err)
	}
	marker.setServing()
	log.Info("agent: serving the panel", "node", bundle.NodeID)

	// The engines of proxies that use the middle proxy through a chain of
	// direct members need the node's public IPv4 address when the exit
	// address of the chain is not known yet (Ruling S2-15), before the
	// reconciler starts. It may take a lookup, which goes through the DNS
	// forwarder of the edge that runs, if it says so: the reconciler tells
	// whenever the edge answers from then on.
	if startEdge > 0 {
		if up, answered := edgeDNSUp(ctx, rec.EdgeFactory(startEdge)); answered {
			resolver.edgeDNS(up)
		}
	}
	rec.NodePublicIPv4 = info.publicIPv4(ctx)
	if rec.NodePublicIPv4 == "" {
		log.Warn("agent: the node's public IPv4 address is not known; engines that use the middle proxy get no NAT address until the exit address of their egress is known")
	}

	work, stopWork := context.WithCancel(ctx)
	defer stopWork()
	// The baseline of the edges that run now, before a pass can start one.
	collector.tick(work, now())
	var wg sync.WaitGroup
	rec.OnEdgeDNS = onEdgeDNS(work, resolver, rec, info, func(f func()) { wg.Go(f) }, kick, log)
	wg.Go(func() { rec.Run(work, trigger) })
	wg.Go(func() {
		t := time.NewTicker(statsEvery)
		defer t.Stop()
		collector.run(work, t.C)
	})
	wg.Go(func() { heartbeat(work, j, status, stateEvery, stateCheck) })
	wg.Go(func() { pruneLoop(work, buf, svc.ipRetentionTime, log) })
	wg.Go(func() { geoIPLoop(work, svc, geoIPEvery) })
	wg.Go(func() { mgmt.runFallback(work) })
	wg.Go(func() { diagRunner.Light(work, j.diagnostics) })
	wg.Go(func() {
		// Old agent binaries, once at the start (UpdateSelf collects after
		// each call).
		svc.updateMu.Lock()
		defer svc.updateMu.Unlock()
		svc.collectBinaries(work)
	})

	after := opt.after
	if after == nil {
		after = time.After
	}
	due := after(markerDeadline)
	var runErr error
	restarting := false
wait:
	for {
		select {
		case <-ctx.Done():
			break wait
		case <-restartCh:
			restarting = true
			log.Info("agent: stopping for the restart into the new binary")
			break wait
		case <-due:
			due = nil
			why := marker.notHealthy()
			if why != "" && !dockerAnswers(ctx, docker) {
				// Docker that does not answer is not the binary's fault: the
				// start is not counted against it, and the deadline starts over.
				log.Warn("agent: not healthy "+markerDeadline.String()+" after the start, but Docker does not answer; waiting another "+markerDeadline.String(), "why", why)
				due = after(markerDeadline)
				continue
			}
			if why != "" {
				log.Error("agent: not healthy "+markerDeadline.String()+" after the start; exiting so that the launcher counts an unhealthy start", "why", why)
				runErr = fmt.Errorf("agent: not healthy %s after the start: %s", markerDeadline, why)
				break wait
			}
		}
	}
	log.Info("agent: stopping")
	stopWork()
	endCalls() // the Watch and log streams end, so that Shutdown can finish
	mgmt.shutdown(shutdownTimeout)
	wg.Wait()
	log.Info("agent: stopped")
	if restarting && runErr == nil {
		return ErrRestart
	}
	return runErr
}

// dockerAnswers reports whether the Docker daemon answers a ping.
func dockerAnswers(ctx context.Context, docker dockerapi.Client) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := docker.Ping(ctx)
	return err == nil
}

// maxLastError bounds the error of the last pass in a state report.
const maxLastError = 512

// fitReport makes a state report of the reconciler fit to go out: the error of
// its last pass becomes valid text on one line, of maxLastError bytes at most
// (an error may be long, and quote anything; it never quotes a secret).
func fitReport(rep *nodev1.StateReport) *nodev1.StateReport {
	rep.LastError = clipText(rep.GetLastError(), maxLastError)
	return rep
}

// fakeTLSProbe is the reconciler's probe of a new engine generation: the L1
// fake-TLS handshake, with a PROXY v2 header from src.
func fakeTLSProbe(ctx context.Context, addr, sni string, secret []byte, src netip.AddrPort) error {
	return probe.FakeTLS(ctx, addr, sni, secret, probe.Options{ProxyHeader: &src, Timeout: probeTimeout})
}

// l2Probe is the reconciler's L2 probe of the way out of a new engine
// generation: the fake-TLS handshake and req_pq_multi to datacenter dc through
// the proxy, with a PROXY v2 header from src when it is valid.
func l2Probe(ctx context.Context, addr, sni string, secret []byte, dc int16, src netip.AddrPort) error {
	opt := probe.Options{Timeout: probeTimeout}
	if src.IsValid() {
		opt.ProxyHeader = &src
	}
	return probe.L2(ctx, addr, sni, secret, dc, opt)
}

// mgmtListen is the address of the management listener.
func mgmtListen(explicit string, port int) string {
	if explicit != "" {
		return explicit
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
}

// heartbeat makes sure a state report goes out at least every every.
func heartbeat(ctx context.Context, j *journal, status func() *nodev1.StateReport, every, check time.Duration) {
	t := time.NewTicker(check)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if j.stateDue(every - check) {
				j.state(status())
			}
		}
	}
}

func pruneLoop(ctx context.Context, buf *Buffer, ipRetention func() time.Duration, log *slog.Logger) {
	t := time.NewTicker(pruneEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m, err := buf.Maintain(ipRetention())
			if err != nil {
				log.Warn("agent: the record buffer could not be maintained", "err", err)
			}
			if m != (maintenance{}) {
				log.Info("agent: the record buffer maintained", "pruned", m.pruned, "addresses_expired", m.scrubbed,
					"over_budget_scrubbed", m.budgetScrubs, "over_budget_deleted", m.budgetDeletes)
			}
		}
	}
}

// nodeBinaryPath is the binary the edge runs: the versioned file this process
// runs from (bin/current resolved), so that an edge keeps its version when
// the agent is updated.
func nodeBinaryPath(home string) string {
	exe, err := os.Executable()
	if err == nil {
		if p, err := filepath.EvalSymlinks(exe); err == nil && within(home, p) {
			return p
		}
	}
	if p, err := filepath.EvalSymlinks(filepath.Join(home, "bin", "current")); err == nil {
		return p
	}
	return exe
}

func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ---- identity ---------------------------------------------------------------------

// bundleFiles are the files install.sh unpacks the node's bundle into.
var bundleFiles = []string{"bundle.json", "ca.pem", "node.pem", "node-key.pem"}

// loadBundle reads the node's bundle from the pki directory. The files are
// checked exactly as pki.ParseBundleTar checks a bundle archive, and the node
// id must be one the panel issues: it names paths and labels.
func loadBundle(dir string) (*pki.Bundle, error) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, name := range bundleFiles {
		// One byte over ParseBundleTar's limit lets it say "too large".
		data, err := readFileLimited(filepath.Join(dir, name), 64<<10+1)
		if err != nil {
			return nil, fmt.Errorf("agent: the node bundle in %s: %w", dir, err)
		}
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(data)), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("agent: the node bundle in %s: %w", dir, err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("agent: the node bundle in %s: %w", dir, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("agent: the node bundle in %s: %w", dir, err)
	}
	b, err := pki.ParseBundleTar(archive.Bytes())
	if err != nil {
		return nil, fmt.Errorf("agent: the node bundle in %s: %w", dir, err)
	}
	if !nodeIDRe.MatchString(b.NodeID) {
		return nil, fmt.Errorf("agent: the node bundle in %s: the node id %.40q is not one the panel issues (26 characters of 0-9 and A-Z)", dir, b.NodeID)
	}
	return b, nil
}

// checkIdentity makes sure the state directory is this node's:
// data/state/node-id holds the id of the node the state belongs to (install.sh
// writes it, and moves the state of another node aside). A missing file is
// written; a different id stops the agent, which would otherwise serve
// another node's state to this node's panel record.
func checkIdentity(paths state.Paths, nodeID string, log *slog.Logger) error {
	path := filepath.Join(paths.StateDir(), "node-id")
	data, err := readFileLimited(path, 128)
	switch {
	case err == nil:
		if have := strings.TrimSpace(string(data)); have != nodeID {
			return fmt.Errorf("agent: the state in %s belongs to node %.40q, but the bundle in pki/ is for node %s; "+
				"install the node again with its bundle (install.sh moves the old state aside)", paths.StateDir(), have, nodeID)
		}
		return nil
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(paths.StateDir(), 0o700); err != nil {
			return fmt.Errorf("agent: %w", err)
		}
		if err := state.WriteFileAtomic(path, []byte(nodeID+"\n"), 0o600); err != nil {
			return fmt.Errorf("agent: recording the node id: %w", err)
		}
		log.Info("agent: the state directory is recorded as this node's", "node", nodeID)
		return nil
	}
	return fmt.Errorf("agent: reading the node id of the state: %w", err)
}

func readFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

// ---- the launcher -----------------------------------------------------------------

// healthMarker writes the launcher's marker (deploy/node/launcher.sh): once,
// after the management server is serving, the desired state is loaded and a
// reconcile pass has run without a failure of the agent's own. A start that
// never writes it counts as unhealthy, and three in a row make the launcher go
// back to the previous binary.
type healthMarker struct {
	path string
	log  *slog.Logger

	mu      sync.Mutex
	loaded  bool
	serving bool
	written bool
	passes  int   // the passes it was told of
	lastErr error // the failure of the agent's own of the last pass
}

// isWritten reports whether this process wrote the marker (GetInfo.healthy).
func (h *healthMarker) isWritten() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.written
}

// notHealthy says why the marker is not written, "" when it is.
func (h *healthMarker) notHealthy() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.written:
		return ""
	case !h.loaded:
		return "the desired state is not loaded"
	case !h.serving:
		return "the management server is not serving"
	case h.lastErr != nil:
		return "the last reconcile pass failed: " + h.lastErr.Error()
	case h.passes == 0:
		return "no reconcile pass has finished"
	}
	return "the healthy marker cannot be written"
}

func (h *healthMarker) setLoaded() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loaded = true
}

func (h *healthMarker) setServing() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.serving = true
}

// passed is told the outcome of every reconcile pass. A pass that failed
// because its desired state was refused (reconcile.ErrRefused: the state does
// not validate, or the edge refused its configuration, a listener it cannot
// bind for one) counts as one that ran: the agent works, and the state is the
// panel's to mend (spec 7). A failure of the agent's own does not count: Docker
// that does not answer, an edge that does not answer.
func (h *healthMarker) passed(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.passes++
	h.lastErr = nil
	if err != nil && !errors.Is(err, reconcile.ErrRefused) {
		h.lastErr = err
		return
	}
	if h.written || !h.loaded || !h.serving {
		return
	}
	if err := os.MkdirAll(filepath.Dir(h.path), 0o700); err != nil {
		h.log.Warn("agent: the healthy marker cannot be written", "err", err)
		return
	}
	if err := state.WriteFileAtomic(h.path, []byte(version.String()+"\n"), 0o600); err != nil {
		h.log.Warn("agent: the healthy marker cannot be written", "err", err)
		return
	}
	h.written = true
	h.log.Info("agent: healthy")
}

// reportRollback turns the launcher's rollback record ("<unix time> <from>
// <to>") into an event and deletes it.
func reportRollback(dir string, j *journal, log *slog.Logger) {
	path := filepath.Join(dir, "rollback")
	data, err := readFileLimited(path, 1024)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Warn("agent: the launcher's rollback record cannot be read", "err", err)
		return
	}
	f := strings.Fields(string(data))
	details := map[string]string{}
	from, to := "?", "?"
	if len(f) >= 3 {
		details["time"] = clipText(f[0], 32)
		from, to = clipText(f[1], 128), clipText(f[2], 128)
	}
	details["from"], details["to"] = from, to
	msg := fmt.Sprintf("the launcher rolled the agent back from %s to %s: %s did not become healthy in 3 starts", from, to, from)
	log.Warn("agent: "+msg, "event", evRolledBack)
	j.event(&nodev1.NodeEvent{Kind: evRolledBack, Severity: sevWarning, Message: msg, Details: details})
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warn("agent: the launcher's rollback record cannot be deleted", "err", err)
	}
}
