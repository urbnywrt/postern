package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/urbnywrt/postern/internal/node/agent"
)

func agentUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: postern-node agent

Runs the node agent: the management API that the panel calls (gRPC over mTLS
with the certificates of the node's bundle), the reconciler that runs the edge
and the proxy engines, and the statistics of the node. The container of the
agent starts it through the launcher (bin/launcher.sh agent).

Environment:
  POSTERN_HOME         the node's directory (default /opt/postern)
  POSTERN_MGMT_LISTEN  address of the management listener
                       (default 0.0.0.0:<the management port of the bundle>)
  POSTERN_ACME_STAGING 1 takes the certificates of WEB proxies from the
                       staging directory of Let's Encrypt (for tests)

SIGTERM or SIGINT stops it. After UpdateSelf installed a new binary it exits
with code 75, and the launcher starts the new bin/current. An agent that has
not become healthy 10 minutes after its start exits with code 1, so that the
launcher counts an unhealthy start.
`)
}

// runAgent is the agent command. It returns the exit code: 2 for a mistake in
// the arguments, 1 when the agent cannot start or fails, 75 when it stopped
// to restart into a new binary (UpdateSelf), 0 when a signal stopped it.
func runAgent(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("postern-node agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // the messages are ours
	mistake := func(msg string) int {
		_, _ = fmt.Fprintf(stderr, "postern-node agent: %s\n\n", msg)
		agentUsage(stderr)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			agentUsage(stdout)
			return 0
		}
		return mistake(err.Error())
	}
	if fs.NArg() > 0 {
		return mistake(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}

	home := os.Getenv("POSTERN_HOME")
	if home == "" {
		home = agent.DefaultHome
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	err := agentRun(ctx, agent.Options{
		Home: home, MgmtListen: os.Getenv("POSTERN_MGMT_LISTEN"), Stderr: stderr,
		ACMEStaging: os.Getenv("POSTERN_ACME_STAGING") == "1",
	})
	if errors.Is(err, agent.ErrRestart) {
		_, _ = fmt.Fprintf(stderr, "postern-node agent: %v\n", err)
		return exitRestart
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "postern-node agent: %v\n", err)
		return 1
	}
	return 0
}

// exitRestart is the exit code that asks for a restart with the new binary
// (Global Constraints, self-update): Docker starts the launcher again.
const exitRestart = 75

// agentRun is the agent; a variable for the tests.
var agentRun = agent.Run
