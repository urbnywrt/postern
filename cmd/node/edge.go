package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urbnywrt/postern/internal/edge"
	"github.com/urbnywrt/postern/internal/edge/control"
	"github.com/urbnywrt/postern/internal/edge/dns"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/version"
)

const (
	// sigtermDrain is the longest the drain that SIGTERM begins waits for the
	// connections that are open.
	sigtermDrain = 30 * time.Second

	// controlShutdownTimeout is how long the control server waits, when the
	// process stops, for the calls that are still being answered.
	controlShutdownTimeout = 5 * time.Second
)

// edgeOptions are the flags of the edge command.
type edgeOptions struct {
	configPath string // the file with the last configuration
	socketPath string // the unix socket of the control service
}

func edgeUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: postern-node edge --config <file> --socket <file>

Runs the edge of the node: the public listeners, the egress chains, the SOCKS
ports of the engines and the DNS forwarder of the node's containers on
127.0.0.2:53. It starts from the configuration in the --config file,
which has to exist, and then takes its configuration from the node agent over
the unix socket at --socket. Every configuration it applies is saved to --config,
so that the edge comes up from it again without the agent.

SIGTERM stops accepting connections and waits for those that are open for up to
30 s; SIGINT stops at once.

Options:
  --config <file>  JSON file with the last configuration of the edge
  --socket <file>  unix socket for the control service
`)
}

// runEdge is the edge command: it reads the flags, and runs the edge until a
// signal or the Drain call of the agent stops it. It returns the exit code: 2
// for a mistake in the flags, 1 when the edge cannot start or fails, and 0 for
// a stop that was asked for.
func runEdge(args []string, stdout, stderr io.Writer) int {
	opts, code, done := parseEdgeFlags(args, stdout, stderr)
	if done {
		return code
	}
	// Signals are taken from here on, so that none is lost while the edge starts.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigs)
	return serveEdge(opts, stderr, sigs, sigtermDrain)
}

// parseEdgeFlags reads the flags. done is true when the command has nothing
// more to do and code is its exit code: -h, or a mistake.
func parseEdgeFlags(args []string, stdout, stderr io.Writer) (opts edgeOptions, code int, done bool) {
	fs := flag.NewFlagSet("postern-node edge", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // the messages are ours
	fs.StringVar(&opts.configPath, "config", "", "")
	fs.StringVar(&opts.socketPath, "socket", "", "")
	mistake := func(msg string) (edgeOptions, int, bool) {
		_, _ = fmt.Fprintf(stderr, "postern-node edge: %s\n\n", msg)
		edgeUsage(stderr)
		return opts, 2, true
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			edgeUsage(stdout)
			return opts, 0, true
		}
		return mistake(err.Error())
	}
	switch {
	case fs.NArg() > 0:
		return mistake(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	case opts.configPath == "":
		return mistake("--config is required")
	case opts.socketPath == "":
		return mistake("--socket is required")
	}
	return opts, 0, false
}

// serveEdge runs the edge and returns the exit code. Its log goes to stderr.
//
// The configuration is read from the file and applied, the chains of the egress
// first, then the SOCKS ports, then the edge with its public listeners, before
// the control socket is opened: the edge serves what it was last given from the
// moment anybody can talk to it. Then it serves the control socket, runs the
// health checks of the egress, and waits.
//
// A signal on sigs stops it: SIGTERM begins a drain that waits for the open
// connections for at most sigtermWait, and the interrupt closes them at once,
// also in the middle of a drain. The Drain call of the agent begins a drain as
// well. The process returns when the drain is over, whichever way it began, and
// the exit code is 0.
func serveEdge(opts edgeOptions, stderr io.Writer, sigs <-chan os.Signal, sigtermWait time.Duration) int {
	log := slog.New(slog.NewTextHandler(stderr, nil))
	log.Info("edge: starting", "version", version.String(), "config", opts.configPath, "socket", opts.socketPath)

	cfg, err := control.LoadConfig(opts.configPath)
	if err != nil {
		log.Error("edge: cannot read the configuration", "err", err)
		return 1
	}

	// The forwarder serves the containers of the node, and the edge itself: the
	// mask domains of the strangers and the direct members of the chains resolve
	// names with it while it runs, and with the nameservers of the host while it
	// does not.
	fwd := dns.New(log, dns.Options{})
	e := edge.New(log, edge.Options{Resolver: fwd.Resolver()})
	router := egress.NewRouter(log)
	router.SetResolver(fwd.Resolver())
	socks := egress.NewSocksPorts(log, router)
	srv := control.NewServer(e, router, socks, opts.configPath, log)
	srv.SetDNS(fwd)

	// stop lets go of the ports of the edge and of the SOCKS ports.
	stop := func() {
		srv.BeginDrain(0)
		<-srv.Drained()
	}

	if err := srv.Apply(cfg); err != nil {
		log.Error("edge: cannot apply the configuration", "err", err)
		stop()
		return 1
	}
	ln, err := control.ListenUnix(opts.socketPath)
	if err != nil {
		log.Error("edge: cannot open the control socket", "err", err)
		stop()
		return 1
	}
	log.Info("edge: control socket open", "socket", opts.socketPath)

	// One loop of health checks for the life of the process; it ends when the
	// drain begins: the edge that takes over runs its own.
	healthCtx, stopHealth := context.WithCancel(context.Background())
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		if err := router.RunHealth(healthCtx); err != nil {
			log.Error("edge: the health checks of the egress do not run", "err", err)
		}
	}()
	defer func() {
		stopHealth()
		<-healthDone
	}()

	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	served := make(chan error, 1)
	go func() { served <- hs.Serve(ln) }()

	log.Info("edge: ready", "generation", e.Generation(), "listening", e.Bound())
	draining := srv.Draining()
	for {
		select {
		case sig := <-sigs:
			switch sig {
			case syscall.SIGTERM:
				log.Info("edge: SIGTERM, draining", "wait_up_to", sigtermWait.String())
				srv.BeginDrain(sigtermWait)
			case os.Interrupt:
				log.Info("edge: interrupted, closing everything at once")
				srv.BeginDrain(0)
			}
		case <-draining:
			stopHealth()
			draining = nil
		case <-srv.Drained():
			ctx, cancel := context.WithTimeout(context.Background(), controlShutdownTimeout)
			defer cancel()
			// Shutdown, not Close: the answer to a Drain call that is still on its
			// way out gets through.
			if err := hs.Shutdown(ctx); err != nil {
				log.Warn("edge: the control server did not stop in time", "err", err)
				_ = hs.Close()
			}
			<-served
			log.Info("edge: stopped")
			return 0
		case err := <-served:
			// Serve returns before the shutdown only when it has failed for good.
			log.Error("edge: the control server failed", "err", err)
			stop()
			_ = hs.Close()
			return 1
		}
	}
}
