// Package control is the control plane of the edge process.
//
// The edge runs in a container of its own, and the agent of the node
// configures it over a unix socket: Server is the service on that socket
// (edgev1.EdgeControlService), ListenUnix opens the socket, and NewClient is
// what the agent talks to it with. The edge keeps its last configuration in a
// file (LoadConfig, SaveConfig) and comes up from it without the agent, so that
// the traffic of the node does not depend on the agent being alive.
//
// One edge process has one generation: the generation of the container the
// agent made for it, which is the generation of every configuration it is sent
// for as long as it lives. A new generation is a new process.
package control

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
	"github.com/urbnywrt/postern/internal/edge"
	"github.com/urbnywrt/postern/internal/edge/dns"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/version"
)

const (
	// defaultDrain is how long a drain waits for the connections when the
	// request does not say: max_seconds is 0, which is also what a caller that
	// leaves the field out sends, and that must not mean "cut everything now".
	defaultDrain = 30 * time.Second

	// maxRequestBytes bounds a request. A configuration of thousands of routes
	// is far smaller.
	maxRequestBytes = 16 << 20

	// maxSocketPath is the longest path of a unix socket: the address has 108
	// bytes, the last of them for the terminating NUL.
	maxSocketPath = 107
)

var errDraining = errors.New("control: the edge is draining, it takes no configuration")

var _ edgev1connect.EdgeControlServiceHandler = (*Server)(nil)

// DNS is the DNS forwarder of the edge, a *dns.Forwarder.
type DNS interface {
	// Apply makes the DNS part of a configuration the one of the forwarder; an
	// error is a forwarder that does not run.
	Apply(cfg *edgev1.Dns) error
	// Running reports whether the forwarder runs.
	Running() bool
	// Close stops the forwarder for good.
	Close()
}

// Server is the control service of an edge process: it holds the three parts
// that a configuration is made of, the edge itself (listeners, routes, limits),
// the router of the egress chains and the SOCKS ports that lead into it, and
// applies a configuration to all of them, and then its DNS part to the DNS
// forwarder (SetDNS). The methods of the service and the others may be called
// from any goroutine.
type Server struct {
	edge   *edge.Edge
	router *egress.Router
	socks  *egress.SocksPorts
	path   string // the file that holds the last configuration
	log    *slog.Logger

	draining    chan struct{} // closed when a drain begins
	socksClosed chan struct{} // closed when the drain has closed the SOCKS ports
	drained     chan struct{} // closed when the drain is over

	// mu serializes the configurations that are applied, and the beginning of a
	// drain with them: no configuration is half applied when the drain begins.
	mu         sync.Mutex
	current    *edgev1.EdgeConfig // the configuration in effect; nil before the first
	drainBegun bool
	drainStop  context.CancelFunc // ends the wait of the drain
	drainTimer *time.Timer        // calls drainStop at the deadline of the drain
	drainEnds  time.Time          // the deadline; zero before the first
	dnsErr     string             // the last error of the forwarder, logged when it changes

	// dns is the forwarder, set once by SetDNS; nil: the DNS part of a
	// configuration is checked and not applied. Health reads it without mu.
	dns atomic.Pointer[dnsHolder]
}

type dnsHolder struct{ d DNS }

// NewServer returns the control service of the edge e, whose egress is the
// router r and the SOCKS ports s, which lead into r. configPath is the file the
// configuration is saved in.
//
// Nothing is configured yet. The process starts from the file by passing what
// LoadConfig reads to Apply, before the socket is opened; after that the agent
// takes over with SetConfig. The health checks of the router are not started
// here: the process runs Router.RunHealth, once, and stops it when Draining()
// is closed.
func NewServer(e *edge.Edge, r *egress.Router, s *egress.SocksPorts, configPath string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		edge:        e,
		router:      r,
		socks:       s,
		path:        configPath,
		log:         log,
		draining:    make(chan struct{}),
		socksClosed: make(chan struct{}),
		drained:     make(chan struct{}),
	}
}

// SetDNS gives the server the DNS forwarder of the edge. Call it before the
// first configuration: from then on the DNS part of every configuration that
// takes effect is applied to it, the drain stops it, and Health reports whether
// it runs.
func (s *Server) SetDNS(d DNS) { s.dns.Store(&dnsHolder{d: d}) }

// forwarder returns the forwarder of SetDNS, nil before it.
func (s *Server) forwarder() DNS {
	if h := s.dns.Load(); h != nil {
		return h.d
	}
	return nil
}

// Handler returns the HTTP handler of the service, the Connect protocol over
// HTTP/1.1 for the clients of NewClient. A panic in a handler is logged with
// its stack and answered with a plain internal error.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(edgev1connect.NewEdgeControlServiceHandler(s,
		connect.WithReadMaxBytes(maxRequestBytes),
		connect.WithRecover(s.recovered),
	))
	return mux
}

func (s *Server) recovered(_ context.Context, spec connect.Spec, _ http.Header, p any) error {
	s.log.Error("control: panic in a handler", "procedure", spec.Procedure, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Apply makes cfg the configuration in effect, in the three parts of it, and
// does not save it. It is what SetConfig does, less the file: the process uses
// it to start from the one that it finds.
//
// The router comes first: an engine that connects to a SOCKS port before the
// chain it leads into exists gets a failure. The SOCKS ports follow, and the
// edge, which takes the public ports, is the last. Each part takes a
// configuration whole or not at all; when one fails, the parts that were applied
// before it are put back as they were, so that on an error nothing has changed.
//
// The DNS part is checked with the rest and applied once the rest is in effect.
// A forwarder that cannot bind its address does not make the configuration
// fail: the proxies of the node must not depend on it. Health then reports
// that it does not run, the error is logged, and the next configuration tries
// again. The addresses of the middle proxies (me_addrs) are checked with the
// rest too, and the router takes them once the rest is in effect.
//
// The generation of the first configuration is the generation of the process.
// A configuration for another one, and any after a drain has begun, is refused.
func (s *Server) Apply(cfg *edgev1.EdgeConfig) error {
	if cfg == nil {
		return errors.New("control: no configuration")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.applyLocked(cfg)
	if err != nil {
		return err
	}
	s.commitLocked(prev, cfg)
	return nil
}

func (s *Server) checkLocked(cfg *edgev1.EdgeConfig) error {
	if s.drainBegun {
		return errDraining
	}
	if s.current != nil && cfg.GetGeneration() != s.current.GetGeneration() {
		return fmt.Errorf("control: this edge runs generation %d and takes only configurations for it, this one is for generation %d: a new generation is a new edge process",
			s.current.GetGeneration(), cfg.GetGeneration())
	}
	return nil
}

// applyLocked checks cfg and applies its parts. It returns the configuration
// that was in effect, which undoes it.
func (s *Server) applyLocked(cfg *edgev1.EdgeConfig) (prev *edgev1.EdgeConfig, err error) {
	if err := s.checkLocked(cfg); err != nil {
		return nil, err
	}
	if err := dns.CheckConfig(cfg.GetDns()); err != nil {
		return nil, err
	}
	if _, err := egress.ParseMEAddrs(cfg.GetMeAddrs()); err != nil {
		return nil, err
	}
	prev = s.current
	if err := s.router.Apply(cfg.GetChains(), cfg.GetHealth()); err != nil {
		return nil, err
	}
	if err := s.socks.Apply(cfg.GetSocks()); err != nil {
		return nil, s.failed(err, prev, stepRouter)
	}
	if err := s.edge.Apply(cfg); err != nil {
		return nil, s.failed(err, prev, stepSocks)
	}
	return prev, nil
}

// commitLocked records cfg as the configuration in effect, gives the router
// its middle-proxy addresses (checked by applyLocked), and applies its DNS
// part.
func (s *Server) commitLocked(prev, cfg *edgev1.EdgeConfig) {
	changed := prev == nil || !proto.Equal(prev, cfg)
	s.current = proto.Clone(cfg).(*edgev1.EdgeConfig)
	if me, err := egress.ParseMEAddrs(cfg.GetMeAddrs()); err == nil {
		s.router.SetMEAddrs(me)
	}
	s.applyDNSLocked(cfg.GetDns())
	// The agent sends the same configuration every pass: that is not news.
	level := slog.LevelDebug
	if changed {
		level = slog.LevelInfo
	}
	// Counts only: the configuration holds the passwords of egress members.
	s.log.Log(context.Background(), level, "control: configuration applied",
		"generation", cfg.GetGeneration(), "changed", changed,
		"listeners", len(cfg.GetListeners()), "routes", len(cfg.GetRoutes()),
		"probe_routes", len(cfg.GetProbeRoutes()),
		"socks_ports", len(cfg.GetSocks()), "chains", len(cfg.GetChains()),
		"me_addrs", len(cfg.GetMeAddrs()), "dns", cfg.GetDns().GetEnabled())
}

// applyDNSLocked applies the DNS part of the configuration in effect to the
// forwarder. Its failure is logged when it is new, and so is its end.
func (s *Server) applyDNSLocked(c *edgev1.Dns) {
	d := s.forwarder()
	if d == nil {
		return
	}
	msg := ""
	if err := d.Apply(c); err != nil {
		msg = err.Error()
	}
	switch {
	case msg == s.dnsErr:
	case msg != "":
		s.log.Error("control: the DNS forwarder does not run; the containers of the node cannot resolve names through it", "err", msg)
	default:
		s.log.Info("control: the DNS forwarder runs again")
	}
	s.dnsErr = msg
}

// The parts of a configuration, in the order that they are applied in.
type step int

const (
	stepRouter step = iota + 1
	stepSocks
	stepEdge
)

// failed puts the parts up to done back as prev has them, and returns err, to
// which it adds what is wrong if that fails too.
func (s *Server) failed(err error, prev *edgev1.EdgeConfig, done step) error {
	if uerr := s.undo(prev, done); uerr != nil {
		return fmt.Errorf("%w (and the previous configuration could not be put back: %v)", err, uerr)
	}
	return err
}

// undo applies the parts of prev up to done again, the one applied last first.
// Before the first configuration, prev is nil and the parts are emptied.
func (s *Server) undo(prev *edgev1.EdgeConfig, done step) error {
	if prev == nil {
		prev = &edgev1.EdgeConfig{}
	}
	var errs []error
	if done >= stepEdge {
		errs = append(errs, s.edge.Apply(prev))
	}
	if done >= stepSocks {
		errs = append(errs, s.socks.Apply(prev.GetSocks()))
	}
	if done >= stepRouter {
		errs = append(errs, s.router.Apply(prev.GetChains(), prev.GetHealth()))
	}
	return errors.Join(errs...)
}

// SetConfig applies the configuration of the request and saves it to the file
// of the edge. It answers applied=false with the reason when it cannot, and
// then nothing has changed: not what is in effect, and not the file. That
// includes a configuration that could be applied but not saved, because the
// edge is to come up after a restart with what it has been running.
//
// A listener that cannot be bound does not refuse the configuration: it is
// applied, and the answer lists the listener among listener_failures, with
// the reason; the edge tries it again until it binds (see edge.Edge.Apply).
//
// The agent sends a configuration on every pass of its reconciliation, whether
// it has changed or not, and the generation in it is that of the edge process:
// repeating it is as good as any other. Another generation is refused.
func (s *Server) SetConfig(_ context.Context, req *connect.Request[edgev1.SetConfigRequest]) (*connect.Response[edgev1.SetConfigResponse], error) {
	cfg := req.Msg.GetConfig()
	if err := s.set(cfg); err != nil {
		s.log.Warn("control: configuration refused", "generation", cfg.GetGeneration(), "err", err)
		return connect.NewResponse(&edgev1.SetConfigResponse{Error: err.Error()}), nil
	}
	return connect.NewResponse(&edgev1.SetConfigResponse{Applied: true, ListenerFailures: s.edge.Failures()}), nil
}

func (s *Server) set(cfg *edgev1.EdgeConfig) error {
	if cfg == nil {
		return errors.New("control: the request has no configuration")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.applyLocked(cfg)
	if err != nil {
		return err
	}
	if err := SaveConfig(s.path, cfg); err != nil {
		err = fmt.Errorf("control: the configuration is not in effect, it could not be saved: %w", err)
		if uerr := s.undo(prev, stepEdge); uerr != nil {
			err = fmt.Errorf("%w (and the previous configuration could not be put back: %v)", err, uerr)
		}
		s.restoreFile(prev)
		return err
	}
	s.commitLocked(prev, cfg)
	return nil
}

// restoreFile puts the previous configuration back in the file after a failed
// save, for the case that the failure came after the new file was in place. It
// can fail for the reason that the save did, and then there is nothing more to do.
func (s *Server) restoreFile(prev *edgev1.EdgeConfig) {
	if prev == nil {
		return
	}
	if err := SaveConfig(s.path, prev); err != nil {
		s.log.Warn("control: the previous configuration could not be written back", "err", err)
	}
}

// ---------------------------------------------------------------------------
// Snapshot and Health
// ---------------------------------------------------------------------------

// Snapshot returns the counters of the edge with the health of the members of
// the egress chains; those of the client IPs only when the request asks for
// them. The generation in it is the one of the configuration in effect, 0
// before the first.
func (s *Server) Snapshot(_ context.Context, req *connect.Request[edgev1.SnapshotRequest]) (*connect.Response[edgev1.SnapshotResponse], error) {
	snap := s.edge.Snapshot(req.Msg.GetIncludeIps())
	snap.Health = s.router.Health()
	return connect.NewResponse(snap), nil
}

// Health returns the generation of the process, the addresses the edge listens
// on, the listeners of its configuration that it could not bind, and the
// version of the binary the process runs. The edge is listening when it has an
// address, which a draining edge does not, and neither does one whose
// configuration has no listener or whose every listener failed. dns is true
// while the DNS forwarder runs.
func (s *Server) Health(_ context.Context, _ *connect.Request[edgev1.HealthRequest]) (*connect.Response[edgev1.HealthResponse], error) {
	bound := s.edge.Bound()
	d := s.forwarder()
	return connect.NewResponse(&edgev1.HealthResponse{
		Generation:       s.edge.Generation(),
		Listening:        len(bound) > 0,
		Bound:            bound,
		Dns:              d != nil && d.Running(),
		Version:          version.Version,
		ListenerFailures: s.edge.Failures(),
	}), nil
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

// Drain begins the drain of the edge (see BeginDrain) and answers as soon as
// the listeners and the SOCKS ports are closed, which is at once: the wait for
// the connections goes on in the background, however long the caller waits. The
// call is not what the drain runs under: the agent gives it 15 s, the drain
// may run for an hour, and a call that ends or is cancelled does not stop it.
//
// max_seconds is how long the drain waits for the connections at the most. 0 is
// taken as 30 s. A drain that is under way takes it only if it shortens the wait.
func (s *Server) Drain(ctx context.Context, req *connect.Request[edgev1.DrainRequest]) (*connect.Response[edgev1.DrainResponse], error) {
	wait := time.Duration(req.Msg.GetMaxSeconds()) * time.Second
	if wait == 0 {
		wait = defaultDrain
	}
	s.BeginDrain(wait)
	s.waitShut(ctx)
	return connect.NewResponse(&edgev1.DrainResponse{}), nil
}

// BeginDrain begins the drain of the edge, if it has not begun: the SOCKS ports
// and the listeners are closed, no configuration is taken any more, and the
// connections that are open are waited for, in the background, for at most wait.
// When they have all ended, or wait has passed and the rest has been closed,
// Drained() is closed, and the process is to exit.
//
// The deadline can only come nearer: a later call with a shorter wait shortens
// the wait, one with a longer wait changes nothing. A wait of zero or less ends
// the wait at once; that is the interrupt, which closes the connections.
func (s *Server) BeginDrain(wait time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.drainBegun {
		s.drainBegun = true
		ctx, stop := context.WithCancel(context.Background())
		s.drainStop = stop
		close(s.draining)
		s.log.Info("control: draining", "wait_up_to", wait.String())
		go s.runDrain(ctx)
	}
	if wait <= 0 {
		s.drainEnds = time.Now()
		s.drainStop()
		return
	}
	end := time.Now().Add(wait)
	switch {
	case s.drainEnds.IsZero():
		s.drainEnds = end
		s.drainTimer = time.AfterFunc(wait, s.drainStop)
	case s.drainTimer != nil && end.Before(s.drainEnds):
		s.drainEnds = end
		s.drainTimer.Reset(wait)
	}
}

// Draining returns a channel that is closed when a drain begins.
func (s *Server) Draining() <-chan struct{} { return s.draining }

// Drained returns a channel that is closed when the drain is over: the
// connections have ended, or the time for them has, and those that were left
// are closed. The process exits then, with status 0.
func (s *Server) Drained() <-chan struct{} { return s.drained }

// runDrain closes the SOCKS ports and the edge, and waits for the connections
// until ctx is done.
func (s *Server) runDrain(ctx context.Context) {
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("control: panic in the drain", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
		s.mu.Lock()
		if s.drainTimer != nil {
			s.drainTimer.Stop()
		}
		s.mu.Unlock()
		s.drainStop()
		close(s.drained)
	}()
	// The open connections of the SOCKS ports are not touched by this; they go on
	// to their end, or to the end of the process.
	if err := s.socks.Close(); err != nil {
		s.log.Warn("control: closing the SOCKS ports", "err", err)
	}
	// The forwarder goes with them: the generation that takes over has its own on
	// the same address (SO_REUSEPORT), and no configuration comes any more.
	if d := s.forwarder(); d != nil {
		d.Close()
	}
	close(s.socksClosed)
	if err := s.edge.Drain(ctx); err != nil {
		s.log.Info("control: the drain ended with connections still open, they are closed", "err", err)
		return
	}
	s.log.Info("control: drained, no connection is left")
}

// waitShut waits until the SOCKS ports and the listeners of the edge are
// closed, or ctx is done.
func (s *Server) waitShut(ctx context.Context) {
	select {
	case <-s.socksClosed:
	case <-s.drained:
		return
	case <-ctx.Done():
		return
	}
	// The edge closes its listeners at the beginning of its drain, right after
	// the SOCKS ports; it has no signal for it, but a list of what is bound.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for len(s.edge.Bound()) > 0 {
		select {
		case <-tick.C:
		case <-s.drained:
			return
		case <-ctx.Done():
			return
		}
	}
}

// ---------------------------------------------------------------------------
// The socket
// ---------------------------------------------------------------------------

// ListenUnix listens on the unix socket at path, for the control service. Only
// its owner may connect to it: the mode of the socket is 0600.
//
// A socket that an earlier process of the edge left behind, which is what
// a process that is killed does, is removed first. One that something still
// listens on is not: that is an error, and so is anything at path that is not
// a socket, which is never removed. The directory has to exist. Closing the
// listener removes the socket.
func ListenUnix(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("control: no socket path")
	}
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("control: the socket path %q is too long (%d bytes, a socket address takes %d)", path, len(path), maxSocketPath)
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close() // removes the socket
		return nil, fmt.Errorf("control: %w", err)
	}
	return ln, nil
}

// removeStaleSocket removes the socket at path if nothing listens on it.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("control: %s exists and is not a socket, it is not removed", path)
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("control: the socket %s is in use by another process", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, fs.ErrNotExist) {
		// Neither refused nor gone: it is not known that nothing listens there.
		return fmt.Errorf("control: cannot tell whether the socket %s is stale: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("control: %w", err)
	}
	return nil
}
