package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/agent"
	"github.com/urbnywrt/postern/internal/node/bootstrap"
	"github.com/urbnywrt/postern/internal/version"
)

func bootstrapUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: postern-node bootstrap

The entrypoint of the node image. It checks the container (root, Docker without
user namespace remapping, POSTERN_HOME mounted from the same path on the host),
lays out POSTERN_HOME as install.sh does, joins the panel with POSTERN_JOIN when
the node has no keys yet or the token is new, puts the image's binary and
launcher.sh into bin/, reserves the node's ports and sets the sysctls through a
short-lived helper container, and then runs bin/launcher.sh agent in its place.

Environment:
  POSTERN_JOIN  <panel URL>#<token>, from the node's page in the panel
  POSTERN_HOME  the node's directory (default /opt/postern)

It exits with code 1 when the node cannot start, for example without keys and
without POSTERN_JOIN; Docker then starts the container again. When the panel
refuses the join of a node without keys (the token is unknown, expired or
used), it waits 5 minutes before it exits, so that the restarts do not hammer
the panel; docker stop ends the wait at once.
`)
}

// runBootstrap is the bootstrap command. It returns only when the node cannot
// start (1) or the arguments are wrong (2); otherwise the process becomes the
// launcher.
func runBootstrap(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("postern-node bootstrap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mistake := func(msg string) int {
		_, _ = fmt.Fprintf(stderr, "postern-node bootstrap: %s\n\n", msg)
		bootstrapUsage(stderr)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			bootstrapUsage(stdout)
			return 0
		}
		return mistake(err.Error())
	}
	if fs.NArg() > 0 {
		return mistake(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}

	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "postern-node bootstrap: cannot find the own binary: %v\n", err)
		return 1
	}
	home := os.Getenv(bootstrap.EnvHome)
	if home == "" {
		home = agent.DefaultHome
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	err = bootstrapRun(ctx, bootstrap.Options{
		Home:      home,
		Env:       os.Environ(),
		Binary:    exe,
		Signature: exe + ".minisig",
		Launcher:  filepath.Join(filepath.Dir(exe), "launcher.sh"),
		Version:   version.Version,
		Arch:      runtime.GOARCH,
		Docker:    dockerapi.New(""),
		Getuid:    os.Getuid,
		Exec:      syscall.Exec,
		Log:       slog.New(slog.NewTextHandler(stderr, nil)),
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "postern-node bootstrap: %v\n", err)
		return 1
	}
	return 0
}

// bootstrapRun is the bootstrap; a variable for the tests.
var bootstrapRun = bootstrap.Run
