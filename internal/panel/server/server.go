// Package server is the panel as a process: the HTTP server that wires the
// packages of the panel together. It opens the database, loads or makes the
// master key and the CA, starts the connections to the nodes, and serves
//
//	/api/<service>/<method>      the Connect API, JSON over HTTP/1.1
//	/api/nodes/{id}/bundle.tar   the download of a node bundle, for admins
//	/api/node-kit/{arch}         the download of the node kit, for admins
//	PUT /api/geoip               the upload of the country database, for admins
//	anything else                the admin UI, index.html for a path that is not a file
//
// and, for the one Host that an admin gave the public page, that page alone
// (internal/panel/publicpage): the admin is never served on that host.
//
// Every response carries the security headers. Every call to a procedure that is
// not public needs the session of an admin, and the size of a message that a
// client may send is limited (see api.go). The setup URL is printed once at
// start, when the panel has no admin yet, and is not logged.
//
// # Start
//
// [New] opens everything and starts nothing but the job runner, which fails
// the jobs that a panel before it left running. [Server.Serve] loads the
// country database and starts the refresh of it, the node manager, the
// maintenance loop and the HTTP server, prints the setup URL and, if it was
// asked to, writes the marker that the launcher waits for. When its context is
// done, which is what the SIGTERM of Docker comes down to, it stops accepting,
// lets the requests that are running finish (for a few seconds), stops the
// maintenance loop, the refresh of the country database, the jobs (for a few
// seconds more) and the node manager, and closes the database, in that order,
// so that nothing uses what has been closed.
//
// # The master key
//
// The key that seals the secrets in the database lives in a file of its own, in
// another directory than the database, so that a copy of the data directory does
// not give the secrets away. A panel with an empty database makes the key. A
// panel whose key is missing and whose database holds anything that the key
// sealed (the CA, the keys of nodes, the secrets of proxies and the parameters of
// egresses, TOTP secrets) does not start: a new key could never open those, and
// a new CA would be trusted by no node. It says where the key is expected, and
// what to do.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/deploy"
	"github.com/urbnywrt/postern/internal/panel/diagnostics"
	"github.com/urbnywrt/postern/internal/panel/egress"
	"github.com/urbnywrt/postern/internal/panel/geodb"
	"github.com/urbnywrt/postern/internal/panel/insights"
	"github.com/urbnywrt/postern/internal/panel/jobs"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/nodeupdate"
	"github.com/urbnywrt/postern/internal/panel/preflight"
	"github.com/urbnywrt/postern/internal/panel/probes"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/publicpage"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/panel/versions"
	"github.com/urbnywrt/postern/internal/panel/webui"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/version"
)

const (
	// DatabaseFile is the name of the database in the data directory.
	DatabaseFile = "postern.db"
	// KeyFile is the name of the master key in the key directory.
	KeyFile = "master.key"

	// DefaultListen is where the panel listens when it is not told.
	DefaultListen = ":8080"

	defaultMaintenanceEvery = time.Hour
	// defaultShutdownTimeout is how long the requests that are running have to
	// finish when the panel is stopped. Docker waits 10 seconds for a container
	// to stop before it kills it.
	defaultShutdownTimeout = 8 * time.Second
	// jobsCloseTimeout is how long the jobs that run, such as an install over
	// SSH, have to stop their commands and
	// record their ends when the panel stops. A job whose end is not recorded by
	// then is failed at the next start.
	jobsCloseTimeout = 5 * time.Second

	// The limits of the HTTP server. There is no write timeout: a response may
	// be a stream. (The files of the UI, which never are, have a write deadline
	// of their own, see spa.go.) ReadTimeout does not end a request that is
	// being answered, only the reading of one, the body of a slow client
	// included.
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 2 * time.Minute
	idleTimeout       = 2 * time.Minute
	maxHeaderBytes    = 64 << 10
)

// Config says where the panel keeps what it keeps, and where it listens.
type Config struct {
	// DataDir holds the database (postern.db), its backups, the downloaded
	// engine releases (artifacts/) and the country database (geoip/). Made when
	// it does not exist.
	DataDir string
	// KeysDir holds the master key (master.key), and should be another volume
	// than DataDir. Made when it does not exist.
	KeysDir string
	// Listen is the address to listen on, "host:port"; ":8080" when empty. It is
	// only used by ListenAndServe.
	Listen string
	// TrustedProxies are the peers whose X-Forwarded-For header is believed
	// when the limits on sign-in work out where a request comes from, and whose
	// X-Forwarded-Proto is when the session cookie is made Secure, see
	// auth.WithTrustedProxies. Empty means the default: the loopback only.
	TrustedProxies []netip.Prefix
	// UI is the admin UI to serve; nil means the one that is embedded in the
	// binary (webui.FS). It must have an index.html.
	UI fs.FS
	// Log is where the panel logs. nil discards it. It never gets a secret.
	Log *slog.Logger
	// Out is where messages for the operator go: the setup URL. It is not a log:
	// the URL holds a secret, and is shown once. nil discards them.
	Out io.Writer
	// HealthyFile, when not empty, is a file that the panel creates once it is
	// serving: the marker that the launcher looks for to tell a good start from
	// a bad one (deploy/panel/launcher.sh).
	HealthyFile string
	// NodeKitDir is the directory of the node kit, the binaries and the
	// installer that a node is installed from by hand, which the panel serves to
	// admins (nodes.DefaultKitDir in the Docker image; see nodes.WithKitDir).
	// Empty, or a directory without a kit, means that the panel has none.
	NodeKitDir string
	// NodeImage is the Docker image of the node that the one-command install
	// runs, with its tag or digest (POSTERN_NODE_IMAGE, resolved by
	// nodes.ResolveNodeImage); empty means none: the panel offers no
	// one-command install. See nodes.WithNodeImage.
	NodeImage string
	// GeoIPBaseURL is the directory that the country database is downloaded
	// from, <GeoIPBaseURL>/dbip-country-lite-<YYYY-MM>.mmdb.gz; empty means the
	// one of DB-IP (geodb.DefaultBaseURL). Tests and the end-to-end test point
	// it at a server of their own, or at a closed port, so that they make no
	// request to DB-IP.
	GeoIPBaseURL string
	// CloudflareRangesURLs are the lists of the Cloudflare ranges that are
	// refreshed daily; none means the published ones (preflight.CloudflareIPv4URL
	// and CloudflareIPv6URL). Tests point them at a closed port.
	CloudflareRangesURLs []string
	// PublicPageOff turns the host routing of the public page off
	// (POSTERN_PUBLIC_PAGE=off): the admin is served on every host and the
	// page on none. It is the way out for an operator who gave the page the
	// only name he reaches the panel by; the configuration of the page stays.
	PublicPageOff bool
	// ReleasesAPI is the API of GitHub that the release catalog polls for the
	// releases of the engines and providers (POSTERN_GITHUB_API); empty means
	// releases.DefaultGitHubAPI. Tests point it at a stub.
	ReleasesAPI string
	// Recovered is what selfupdate.Recover found of the last update of the
	// panel, before the store was opened; Serve records it once it serves
	// (selfupdate.Settle).
	Recovered selfupdate.Outcome
	// ImageBin is the binary of the image, which the panel's update keeps as
	// bin/previous when there is no bin/current; empty means
	// $POSTERN_PANEL_BIN or selfupdate.DefaultImageBinary.
	ImageBin string
}

// defaultReleasesAPI is what Config.ReleasesAPI means when it is empty. The
// tests of this package replace it, so that no served panel reaches GitHub.
var defaultReleasesAPI = releases.DefaultGitHubAPI

// A Server is the panel.
type Server struct {
	cfg      Config
	log      *slog.Logger
	db       *store.DB
	auth     *auth.Service
	mgr      *nodes.Manager
	settings *insights.SettingsService
	jobs     *jobs.Runner
	geo      *geodb.Manager
	probes   *probes.Scheduler
	diag     *diagnostics.Runner
	changes  *diagnostics.Changes
	cfRanges *preflight.Refresher
	releases *releases.Catalog
	rollouts *rollout.Runner
	http     *http.Server
	handler  http.Handler
	fresh    *freshConns
	// restart is signalled once the panel installed a new version: Serve
	// stops as on SIGTERM and returns selfupdate.ErrRestart.
	restart chan struct{}

	// Tests make these shorter.
	maintenanceEvery time.Duration
	shutdownTimeout  time.Duration

	mu       sync.Mutex
	served   bool
	closed   bool
	closeErr error
}

// freshConns keeps track of the connections that have been accepted and have not
// sent a request yet. A browser opens such connections ahead of time, and
// http.Server.Shutdown leaves each of them alone for five seconds before it
// takes it for idle, so a panel with a browser tab open would take that long to
// stop. Nothing that is being answered is on them, so they are closed at once.
type freshConns struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// track is the ConnState hook of the HTTP server.
func (f *freshConns) track(c net.Conn, state http.ConnState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if state == http.StateNew {
		if f.conns == nil {
			f.conns = map[net.Conn]struct{}{}
		}
		f.conns[c] = struct{}{}
		return
	}
	delete(f.conns, c)
}

// closeAll closes the connections that have sent nothing.
func (f *freshConns) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for c := range f.conns {
		_ = c.Close()
	}
	clear(f.conns)
}

// New opens the database in cfg.DataDir, loads or makes the master key in
// cfg.KeysDir and the CA of the panel, and builds the services and the HTTP
// handler. It starts nothing: see [Server.Serve]. When it fails it has closed
// what it opened.
func New(cfg Config) (*Server, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("server: no data directory")
	}
	if cfg.KeysDir == "" {
		return nil, errors.New("server: no key directory")
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ui := cfg.UI
	if ui == nil {
		ui = webui.FS()
	}
	page, err := newSPA(ui)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	db, err := store.Open(filepath.Join(cfg.DataDir, DatabaseFile))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = db.Close()
		}
	}()

	ctx := context.Background()
	key, err := loadKey(ctx, db, filepath.Join(cfg.KeysDir, KeyFile), log)
	if err != nil {
		return nil, err
	}
	ca, err := nodes.LoadOrCreateCA(ctx, db, key)
	if err != nil {
		return nil, err
	}

	var authOptions []auth.Option
	if len(cfg.TrustedProxies) > 0 {
		authOptions = append(authOptions, auth.WithTrustedProxies(cfg.TrustedProxies...))
	}
	authSvc := auth.NewService(db, key, log, authOptions...)

	// The release catalog: the built-in releases are seeded at every start;
	// the tracker runs from Serve. The proxies see it through their catalog,
	// which names its artifacts in the desired states and uploads them.
	apiBase := cfg.ReleasesAPI
	if apiBase == "" {
		apiBase = defaultReleasesAPI
	}
	relCatalog := releases.New(releases.Config{DB: db, Key: key, Dir: filepath.Join(cfg.DataDir, "releases"), APIBase: apiBase, Log: log})
	if err := relCatalog.Seed(ctx); err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	mgr := nodes.NewManager(db, key, ca, log)
	catalog := proxies.NewCatalog(relCatalog, log)
	ingestor := proxies.NewIngestor(db, log)
	builder := proxies.NewStateBuilder(db, key, catalog, log)
	builder.SetReports(ingestor)
	mgr.SetStateBuilder(builder)
	mgr.SetIngestor(ingestor)
	certs := proxies.NewCertSync(db, key, mgr, log)
	mgr.SetConnectHook(certs)

	// The ranges of Cloudflare, kept fresh by cfRefresh below: the domain
	// checks of WEB proxies, and joins (an address of Cloudflare is not a
	// node's).
	cfRanges := preflight.DefaultCloudflareRanges()
	// The binary of the node kit and of an SSH install is the running panel's
	// version: the image kit when it is, else the cache of releases (its
	// Releases are set below, before anything serves).
	nodeKit := &nodes.PanelKit{Dir: cfg.NodeKitDir, Version: version.Version, Log: log}
	nodeSvc := nodes.NewService(db, key, ca, mgr, log, nodes.WithKitDir(cfg.NodeKitDir), nodes.WithMgmtSwitcher(mgr), nodes.WithKitSource(nodeKit),
		nodes.WithNodeImage(cfg.NodeImage), nodes.WithCloudflareRanges(cfRanges))
	logNodeKit(log, nodeSvc, cfg.NodeKitDir)

	// The jobs that a panel before this one left running are failed here: no
	// process runs them any more. The one runner runs the jobs of every
	// service, so a node runs at most one job, whichever service started it.
	runner, err := jobs.New(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	// The country database: loaded and refreshed by Serve, asked for countries
	// by whatever is wired to it later. An empty GeoIPBaseURL is DB-IP's own.
	geo := geodb.NewManager(db, filepath.Join(cfg.DataDir, "geoip"), log, geodb.WithBaseURL(cfg.GeoIPBaseURL))

	// The statistics settings, and what the country database is to the nodes:
	// the reference in their states, the upload before a state that names it
	// (beside the artifacts of the catalog), the countries of the addresses
	// that they saw, and a new state when it changes.
	settingsSvc := insights.NewSettingsService(db, mgr, log)
	mgr.SetArtifactEnsurer(nodes.MultiEnsurer(catalog, insights.NewGeoIPSync(geo.Current, log)))
	geoFns := proxies.GeoIP{Country: geo.Country, Ref: func() *nodev1.GeoIPRef {
		c, ok := geo.Current()
		if !ok {
			return nil
		}
		return &nodev1.GeoIPRef{Month: c.Month, Sha256: c.SHA256}
	}}
	builder.SetGeoIP(geoFns)
	ingestor.SetGeoIP(geoFns)
	geo.OnChange(func() { settingsSvc.GeoIPChanged(context.Background()) })

	// The panel's probes of the proxies: Serve runs the schedule. They tell
	// the public page which proxies are down.
	prober := probes.NewScheduler(db, key, log)
	// Diagnostics: the runs of the checks of nodes, and the light checks
	// that the nodes report. Serve starts the runner; its runs end with the
	// background.
	diagRunner := diagnostics.NewRunner(diagnostics.Config{DB: db, Nodes: mgr, Probes: prober, GeoIP: geo.Status, Log: log})
	lights := diagnostics.NewLights(db, log, nil)
	ingestor.OnDiagnostics(lights.OnDiagnostics)
	// The runs before and after changes: the operator's edits, the fixes,
	// and what the nodes change by themselves. Serve starts it.
	diagChanges := diagnostics.NewChanges(diagnostics.ChangesConfig{Runner: diagRunner, DB: db, Log: log})
	ingestor.OnServingChange(diagChanges.OnServingChange)
	lights.OnChanges(diagChanges.OnLightChanges)
	// The problem feed: what is wrong now, from the nodes, their light
	// checks, the proxies' reports and the panel's probes.
	feed := diagnostics.NewFeed(diagnostics.FeedConfig{DB: db, ProxyReport: ingestor.ProxyReport, Down: prober.Down, GeoIP: geo.Status, Key: &key, Log: log})
	prober.OnResult(feed.OnProbe)
	// The public page reads its configuration now.
	// Its check of the host resolves over DoH, as the domains of WEB proxies are.
	public := publicpage.NewService(db, key, log, publicpage.WithProbeDown(prober.Down), publicpage.WithCountry(geo.Country),
		publicpage.WithResolver(doh.New(doh.DefaultEndpoints)))
	if cfg.PublicPageOff {
		log.Warn("POSTERN_PUBLIC_PAGE=off: the public page is served on no host, and the admin on every host, its own included")
	}

	versionSvc := versions.New(db, log)
	versionSvc.SetCatalog(relCatalog)
	// Postern's own releases: the source of the settings, the cache of signed
	// binaries under artifacts/postern, and the bundle upload.
	selfCache := &selfupdate.Cache{Dir: filepath.Join(cfg.DataDir, "artifacts", "postern")}
	if err := selfCache.Sweep(); err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	selfRel := &selfupdate.Releases{DB: db, Key: key, Limiter: relCatalog.Limiter(), APIBase: apiBase, Cache: selfCache, Log: log}
	versionSvc.SetReleases(selfRel)
	nodeKit.Releases = selfRel
	// The panel's own update: it installs into <data>/bin and asks Serve to
	// stop, after the answer, for the launcher to start the new version.
	restart := make(chan struct{}, 1)
	updater := &selfupdate.Updater{DataDir: cfg.DataDir, Releases: selfRel, DB: db, HealthyFile: cfg.HealthyFile, ImageBin: cfg.ImageBin, Log: log}
	versionSvc.SetUpdater(updater, func() {
		select {
		case restart <- struct{}{}:
		default:
		}
	}, func() bool { return kitHasSignatures(cfg.NodeKitDir) })

	proxySvc := proxies.NewService(db, key, catalog, ingestor, mgr, log)
	versionSvc.SetProxies(proxySvc)
	// The rollout runner: Serve runs it after the node manager starts and
	// stops it before the node manager stops.
	// Its hooks run the full diagnostics before and after every step (up to
	// 3 minutes each, so the hook timeout is above that).
	rollouts := rollout.NewRunner(rollout.Config{DB: db, Log: log, Hooks: rolloutHooks(db, diagRunner, diagChanges, log),
		HookTimeout: rolloutHookTimeout})
	rolloutDeps := rollout.EngineConfig{DB: db, Catalog: relCatalog, Reports: ingestor, Writer: proxySvc, Log: log}
	rollouts.Register(rollout.KeyEngineVersion, rollout.NewEngineVersions(rolloutDeps))
	rollouts.Register(rollout.KeySwitch, rollout.NewSwitch(rolloutDeps, proxySvc))
	rollouts.Register(rollout.KeyProviderVersion, rollout.NewProviderVersions(rolloutDeps, proxySvc, ingestor))
	rollouts.Register(rollout.KeyNode, nodeupdate.New(nodeupdate.Config{DB: db, Nodes: mgr, Binaries: nodeKit, Log: log}))
	versionSvc.SetRollouts(rollouts)
	proxySvc.SetCertPusher(certs)
	mgr.SetMgmtWriter(proxySvc)
	nodeSvc.SetArtifactSourceWriter(proxySvc)
	// The domains of WEB proxies are looked up over DoH, as the nodes look
	// them up: UDP/53 may be closed where the panel runs too.
	cfRefresh := &preflight.Refresher{Ranges: cfRanges, Client: releases.NewHTTPClient(), Store: db, Log: log, URLs: cfg.CloudflareRangesURLs}
	proxySvc.SetDomainChecker(preflight.New(doh.New(doh.DefaultEndpoints), cfRanges))
	egressSvc := egress.NewService(db, key, proxySvc, ingestor, log)
	diagSvc := diagnostics.NewService(db, diagRunner, log, diagnostics.WithFeed(feed), diagnostics.WithKey(&key))
	wireChanges(diagChanges, diagSvc, proxySvc, egressSvc, nodeSvc)
	handler := services{
		auth:          authSvc,
		nodes:         nodeSvc,
		proxies:       proxySvc,
		egress:        egressSvc,
		versions:      versionSvc,
		geo:           geodb.NewService(geo, log),
		settings:      settingsSvc,
		metrics:       insights.NewMetricsService(db, ingestor, geoMonth(geo), log),
		geoUpload:     geo.UploadHandler(),
		relUpload:     selfupdate.UploadHandler(selfupdate.UploadConfig{Cache: selfCache, DB: db, Stable: relCatalog, Providers: relCatalog, Log: log}),
		public:        public,
		probes:        probes.NewService(db, prober, log),
		diag:          diagSvc,
		publicRouting: !cfg.PublicPageOff,
		trusted:       cfg.TrustedProxies,
		deploy:        deploy.NewService(deploy.Config{DB: db, Key: key, Nodes: nodeSvc, Notifier: mgr, Jobs: runner, Log: log}),
		ui:            page,
	}.handler()

	fresh := &freshConns{}
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		ConnState:         fresh.track,
	}
	httpServer.RegisterOnShutdown(fresh.closeAll)

	ok = true
	return &Server{
		cfg:              cfg,
		log:              log,
		db:               db,
		auth:             authSvc,
		mgr:              mgr,
		settings:         settingsSvc,
		jobs:             runner,
		geo:              geo,
		probes:           prober,
		diag:             diagRunner,
		changes:          diagChanges,
		cfRanges:         cfRefresh,
		releases:         relCatalog,
		rollouts:         rollouts,
		handler:          handler,
		http:             httpServer,
		fresh:            fresh,
		restart:          restart,
		maintenanceEvery: defaultMaintenanceEvery,
		shutdownTimeout:  defaultShutdownTimeout,
	}, nil
}

// logNodeKit says in one line which architectures the panel has the node kit
// of. A panel that is not run from its Docker image has none, which is not a
// fault: the install steps of the UI then ask for a postern-node binary. The
// panel looks again at every request, so this line is what was there at start.
func logNodeKit(log *slog.Logger, svc *nodes.Service, dir string) {
	arches, missing := svc.KitArches()
	if len(arches) == 0 {
		log.Info("no node kit: the install steps of nodes ask for a postern-node binary instead, "+
			"which is expected of a panel that does not run from its Docker image",
			"dir", dir, "reason", fmt.Sprint(missing))
		return
	}
	attrs := []any{"dir", dir, "arches", strings.Join(arches, ",")}
	if missing != nil {
		attrs = append(attrs, "missing", missing.Error())
	}
	log.Info("node kit for the manual install of nodes", attrs...)
}

// loadKey returns the master key in the file at path. It makes the key when the
// file does not exist and the database holds nothing that a key sealed; when it
// does, it refuses, and never makes a key over the secrets.
func loadKey(ctx context.Context, db *store.DB, path string, log *slog.Logger) (seal.Key, error) {
	_, statErr := os.Stat(path)
	missing := errors.Is(statErr, fs.ErrNotExist)
	if missing {
		sealed, err := db.HasSealedData(ctx)
		if err != nil {
			return seal.Key{}, fmt.Errorf("server: cannot tell whether the database holds sealed data, so the master key is not made: %w", err)
		}
		if sealed {
			return seal.Key{}, fmt.Errorf("server: the master key %s does not exist, but the database holds data that is sealed with "+
				"it (the CA, the keys of nodes, the secrets of proxies, the parameters of egresses or TOTP secrets). "+
				"Postern will not make a new key over it: "+
				"it could never be opened, and no node would trust a new CA. Mount the volume that holds master.key "+
				"(/keys in the Docker image), or restore the key from your backup. "+
				"Only if you mean to start from nothing, remove the database, too", path)
		}
	}
	key, err := seal.LoadOrCreateKey(path)
	if err != nil {
		return seal.Key{}, fmt.Errorf("server: %w", err)
	}
	if missing {
		log.Info("made the master key: keep a copy of it, apart from the database, since without it the secrets in the database cannot be opened",
			"path", path)
	}
	return key, nil
}

// Handler returns the HTTP handler of the panel.
func (s *Server) Handler() http.Handler { return s.handler }

// ListenAndServe listens on the address of the configuration and serves, see
// [Server.Serve]. If it cannot listen it closes the server and returns the error.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := s.cfg.Listen
	if addr == "" {
		addr = DefaultListen
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("server: listen on %s: %w", addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is done or the listener fails, and then shuts the
// panel down in order: it stops accepting and gives the requests that are running
// a few seconds to finish, stops the maintenance loop, the refresh of the country
// database, the jobs and the node manager, and closes the database. A stop that
// ctx asks for gives nil.
//
// A server is served once. When Serve returns it is closed, whatever the reason.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	if s.closed || s.served {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("server: it was closed or served already")
	}
	s.served = true
	s.mu.Unlock()

	// The background work has a context of its own, so that it can be stopped
	// after the HTTP server, whose requests may still need it.
	background, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	// The country database is loaded before the node manager starts, which
	// builds the state of nodes that may name it, and before the HTTP server
	// takes a request; its refresh goes on in the background.
	s.geo.Start(background)
	// The first start of a panel with the statistics settings stores their
	// defaults and gives every node a new state with them, before the nodes
	// are connected to.
	if err := s.settings.EnsureDefaults(background); err != nil {
		s.log.Error("could not store the default statistics settings; the defaults apply until it works", "err", err)
	}
	s.mgr.Start(background)
	s.probes.Start(background)
	s.diag.Start(background)
	s.changes.Start(background)
	var maintenance sync.WaitGroup
	maintenance.Add(1)
	go func() {
		defer maintenance.Done()
		runMaintenance(background, s.db, s.maintenanceEvery, time.Now, s.log)
	}()
	maintenance.Add(1)
	go func() {
		defer maintenance.Done()
		s.releases.Run(background)
	}()
	// The rollouts run after the node manager has started, and stop (with
	// the background) before Close stops it.
	maintenance.Add(1)
	go func() {
		defer maintenance.Done()
		s.rollouts.Run(background)
	}()
	// The Cloudflare ranges of the domain check: the last good list, then a
	// refresh every day.
	maintenance.Add(1)
	go func() {
		defer maintenance.Done()
		s.cfRanges.Run(background)
	}()

	served := make(chan error, 1)
	go func() { served <- s.http.Serve(ln) }()
	s.announce(ln.Addr())
	s.markHealthy()
	selfupdate.Settle(background, s.db, s.cfg.DataDir, s.cfg.Recovered, s.log)

	var failure error
	restarting := false
	select {
	case <-ctx.Done():
	case <-s.restart:
		// An update was installed and answered: stop as on SIGTERM, and
		// let the process exit for the launcher to start the new version.
		restarting = true
		s.log.Info("the panel stops to restart into its new version")
	case err := <-served:
		// The server stopped by itself, since nobody has asked it to yet: the
		// listener failed. Serve always returns an error.
		failure = fmt.Errorf("server: serving stopped: %w", err)
	}

	s.log.Info("the panel is stopping")
	drain, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	if err := s.http.Shutdown(drain); err != nil {
		s.log.Warn("some requests did not finish in time and are cut off", "err", err)
		_ = s.http.Close()
	}
	if failure == nil {
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			failure = fmt.Errorf("server: %w", err)
		}
	}
	stopBackground()
	maintenance.Wait()
	s.geo.Wait()          // it writes to the database, which is closed next
	s.probes.Wait()       // likewise
	s.changes.Drain()     // likewise, and its runs before the runner's
	s.diag.Drain()        // likewise
	closeErr := s.Close() // the jobs, the node manager, then the database
	s.log.Info("the panel has stopped")
	if restarting {
		return errors.Join(selfupdate.ErrRestart, failure, closeErr)
	}
	return errors.Join(failure, closeErr)
}

// kitHasSignatures reports whether the node kit in dir carries a signature
// file (<arch>/postern-node.minisig) for every architecture that it has a
// binary for, and has at least one. It does not verify them: the node does,
// when it installs the binary. GetPanelVersion reports it as kit_signed,
// which says only that the image's kit came with signatures.
func kitHasSignatures(dir string) bool {
	if dir == "" {
		return false
	}
	found := false
	for _, arch := range []string{"amd64", "arm64"} {
		bin := filepath.Join(dir, arch, "postern-node")
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		if _, err := os.Stat(bin + ".minisig"); err != nil {
			return false
		}
		found = true
	}
	return found
}

// Close stops the jobs, which may take a few seconds, and the node manager,
// and closes the database. It is for a server that was not served, or that has
// to be given up; Serve closes its server itself. A second call does nothing
// and returns what the first did.
//
// A running job is cancelled and recorded as failed; one whose function does
// not return within jobsCloseTimeout is failed when the panel starts again.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), jobsCloseTimeout)
	if err := s.jobs.Close(ctx); err != nil {
		s.log.Warn("jobs did not stop in time; they are failed when the panel starts again", "err", err)
	}
	cancel()
	s.mgr.Close()
	s.closeErr = s.db.Close()
	return s.closeErr
}

// announce says that the panel is serving, in the log, and, when there is no
// admin yet, prints the setup URL for the operator: once, to Out, and never to
// the log.
func (s *Server) announce(addr net.Addr) {
	s.log.Info("the panel is serving", "version", version.String(), "listen", addr.String())
	token, ok := s.auth.SetupToken()
	if !ok || s.cfg.Out == nil {
		return
	}
	u := setupURL(addr.String(), token)
	_, _ = fmt.Fprintf(s.cfg.Out, "postern-panel: the panel has no admin yet. Open this URL within an hour to create the first one;\n"+
		"it works once, and a restart makes a new one:\n\n  %s\n\n", u)
	if hostOf(addr.String()) == "localhost" {
		_, _ = fmt.Fprintf(s.cfg.Out, "(localhost is this machine. From another one, use the address and the port of this server instead.)\n\n")
	}
}

// markHealthy writes the marker of the launcher, if there is one to write.
func (s *Server) markHealthy() {
	if s.cfg.HealthyFile == "" {
		return
	}
	if err := os.WriteFile(s.cfg.HealthyFile, []byte(version.Version+"\n"), 0o600); err != nil {
		s.log.Warn("could not write the healthy marker, so the launcher will count this start as unhealthy",
			"path", s.cfg.HealthyFile, "err", err)
	}
}

// hostOf is the host of the address that setupURL shows: "localhost" for an
// address on which the server listens on every interface.
func hostOf(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if addr, err := netip.ParseAddr(host); host == "" || (err == nil && addr.IsUnspecified()) {
		return "localhost"
	}
	return host
}

// setupURL is the address at which the first admin is made, for a server that
// listens on listen. An address that cannot be opened in a browser, because it
// stands for every interface, is replaced by localhost.
func setupURL(listen, token string) string {
	_, port, err := net.SplitHostPort(listen)
	host := hostOf(listen)
	hostPort := host
	if err == nil {
		hostPort = net.JoinHostPort(host, port)
	}
	u := url.URL{
		Scheme:   "http",
		Host:     hostPort,
		Path:     "/setup",
		RawQuery: url.Values{"token": {token}}.Encode(),
	}
	return u.String()
}

// geoMonth is the month of the country database of the panel, "" while it has
// none: what the statistics of countries name next to the attribution.
func geoMonth(g *geodb.Manager) func() string {
	return func() string {
		c, ok := g.Current()
		if !ok {
			return ""
		}
		return c.Month
	}
}
