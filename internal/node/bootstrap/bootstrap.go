// Package bootstrap is "postern-node bootstrap", the entrypoint of the node
// image. Inside the node container it does what deploy/node/install.sh does
// on a host, then starts the launcher:
//
//  1. checks the environment: root, POSTERN_HOME, Docker without user
//     namespace remapping, and the container's own mounts;
//  2. lays out POSTERN_HOME with the directories and modes of install.sh;
//  3. joins the panel with POSTERN_JOIN when the node has no keys yet or the
//     token is new: the key is made here, the panel signs it, and pki/ gets the
//     four files of a bundle;
//  4. seeds bin/ with the image's binary, signature and launcher.sh;
//  5. sets the sysctls of install.sh through a short-lived privileged helper;
//  6. execs bin/launcher.sh agent.
//
// Everything that touches the host comes in through Options, so that the
// tests run without root and without Docker.
package bootstrap

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/agent"
)

// ErrNoKeys is returned when the node has no keys and POSTERN_JOIN is not set.
var ErrNoKeys = errors.New("no keys yet: start the container with POSTERN_JOIN from the panel")

// Options are the inputs of Run. Zero values take the defaults that are noted.
type Options struct {
	// Home is POSTERN_HOME; it must be absolute.
	Home string
	// Env is the environment ("KEY=value"). POSTERN_JOIN is read from it, and
	// the agent gets it without POSTERN_JOIN.
	Env []string

	// Binary is the image's node binary (the resolved os.Executable()),
	// Signature its .minisig (absent in an image built from source), and
	// Launcher the image's launcher.sh.
	Binary, Signature, Launcher string
	// Version is the version of Binary (version.Version) and Arch its
	// architecture (runtime.GOARCH).
	Version, Arch string

	// Docker is the daemon.
	Docker dockerapi.Client
	// RunnerImage is the image of the sysctl helper; default agent.RunnerImage.
	RunnerImage string

	// ProcDir is where procfs is mounted (default /proc): self/mountinfo finds
	// the own container, sys/net/ipv4/... the sysctls.
	ProcDir string
	// Getuid is os.Getuid.
	Getuid func() int
	// Now is the clock (default time.Now); Sleep waits (default a timer that
	// ends early when ctx is done).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// Exec replaces the process (syscall.Exec). It returns only on failure.
	Exec func(path string, argv, env []string) error
	// RootCAs verifies the panel's HTTPS certificate; nil is the system roots.
	RootCAs *x509.CertPool
	// Log is where the steps are told; nil discards.
	Log *slog.Logger
}

// boot is one run of the bootstrap.
type boot struct {
	opt Options
	log *slog.Logger
}

// Run bootstraps the node and execs <home>/bin/launcher.sh agent. It returns
// only with an error: the reason the node cannot start.
func Run(ctx context.Context, opt Options) error {
	b, err := newBoot(opt)
	if err != nil {
		return err
	}
	if err := b.checkEnvironment(ctx); err != nil {
		return err
	}
	if err := b.makeLayout(); err != nil {
		return err
	}
	if err := b.joinStep(ctx); err != nil {
		return err
	}
	if err := b.seed(); err != nil {
		return err
	}
	b.sysctls(ctx)
	launcher := filepath.Join(b.opt.Home, "bin", "launcher.sh")
	b.log.Info("bootstrap: starting the agent through the launcher", "launcher", launcher)
	if err := b.opt.Exec(launcher, []string{"launcher.sh", "agent"}, agentEnv(b.opt.Env, b.opt.Home)); err != nil {
		return fmt.Errorf("bootstrap: exec %s: %w", launcher, err)
	}
	return nil
}

func newBoot(opt Options) (*boot, error) {
	if opt.Docker == nil || opt.Exec == nil || opt.Getuid == nil {
		return nil, errors.New("bootstrap: Docker, Exec and Getuid are required")
	}
	if opt.RunnerImage == "" {
		opt.RunnerImage = agent.RunnerImage
	}
	if opt.ProcDir == "" {
		opt.ProcDir = "/proc"
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Sleep == nil {
		opt.Sleep = sleep
	}
	log := opt.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &boot{opt: opt, log: log}, nil
}

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

// path is a path under POSTERN_HOME.
func (b *boot) path(elem ...string) string {
	return filepath.Join(append([]string{b.opt.Home}, elem...)...)
}
