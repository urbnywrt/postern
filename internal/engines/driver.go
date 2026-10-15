// Package engines defines what the node agent needs from an MTProto engine
// (telemt, mtg): which proxy types it serves, where its binary comes
// from, the config files it is started with, the container it runs in, and how
// to tell that it is ready. The implementations live in subpackages.
//
// A driver is pure: Render and Container compute their results from an Instance
// and touch nothing. Writing the files, creating the container and polling Ready
// is the reconciler's job.
package engines

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
)

// Instance is one engine instance to be rendered, run and probed: one
// generation of one proxy.
type Instance struct {
	// Proxy is the proxy to serve. It carries the secret: never log it.
	Proxy *nodev1.Proxy
	// InstanceID names the instance directory.
	InstanceID string
	// Generation is the instance generation, part of the container name.
	Generation uint64
	// ListenPort is the loopback port the engine accepts connections from the
	// edge on (PROXY protocol v2), APIPort its control API, and SocksPort the
	// loopback SOCKS5 port of the edge that is the engine's only way out.
	ListenPort, APIPort, SocksPort uint16
	// APIToken is the exact value of the Authorization header the engine's API
	// expects. Never log it.
	APIToken string
	// InstanceDir is the host directory the rendered files are written to. The
	// driver mounts it into the container: read-write for an engine that keeps
	// its caches in there (telemt, which exits at once with "Can't use
	// data_path" when it cannot create its data directory), read-only for one
	// that keeps nothing on disk (mtg). The rendered files must be readable by
	// the user the container runs as (65534); only a read-write mount needs
	// that user to be able to write there.
	InstanceDir string
	// BinaryPath is the host path of the engine binary.
	BinaryPath string
	// RunnerImage is the image of the container the binary runs in.
	RunnerImage string
	// FrontingAddr is where an engine that fronts by itself, not through
	// SocksPort, passes the connections that are not its clients' (mtg v2.2.8
	// dials its fronting target directly from the node, Ruling S5-10): the IP
	// address and port of the proxy's mask target override when it has one,
	// else an address of the proxy domain, on port 443, that the agent
	// resolved through the node's resolver. The agent passes only an address
	// that the edge's destination policy accepts (egress.DestinationAllowed),
	// and a driver that needs one refuses to render without it, or with one
	// the policy refuses: the engine never resolves or picks its fronting
	// target itself. telemt reaches its mask host through SocksPort, where the
	// edge applies the policy, and ignores it.
	FrontingAddr netip.AddrPort
}

// CheckHostPaths verifies that the two host paths the engine container binds,
// the binary and the instance directory, are what the container needs: absolute,
// existing, the binary a regular file that others can read and execute, the
// instance directory a directory.
//
// Call it before dockerapi.Client.Create. Docker creates a missing bind source
// as an empty root-owned directory (and takes a relative one for a volume name)
// and starts the container anyway: the engine would then "run" against an empty
// directory, or fail with an error that hides the real cause.
func (in Instance) CheckHostPaths() error {
	if err := checkBindSource("engine binary", in.BinaryPath); err != nil {
		return err
	}
	info, err := os.Stat(in.BinaryPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("engines: engine binary %s does not exist", in.BinaryPath)
	case err != nil:
		return fmt.Errorf("engines: engine binary: %w", err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("engines: engine binary %s is not a regular file", in.BinaryPath)
	case info.Mode().Perm()&0o001 == 0:
		return fmt.Errorf("engines: engine binary %s (mode %v) is not executable by other users, and the container does not run as its owner", in.BinaryPath, info.Mode().Perm())
	case info.Mode().Perm()&0o004 == 0:
		return fmt.Errorf("engines: engine binary %s (mode %v) is not readable by other users, and the container does not run as its owner", in.BinaryPath, info.Mode().Perm())
	}

	if err := checkBindSource("instance directory", in.InstanceDir); err != nil {
		return err
	}
	info, err = os.Stat(in.InstanceDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("engines: instance directory %s does not exist", in.InstanceDir)
	case err != nil:
		return fmt.Errorf("engines: instance directory: %w", err)
	case !info.IsDir():
		return fmt.Errorf("engines: instance directory %s is not a directory", in.InstanceDir)
	}
	return nil
}

// checkBindSource rejects host paths that cannot be used as the source of a
// bind mount, whatever is on the disk.
func checkBindSource(what, path string) error {
	switch {
	case path == "":
		return fmt.Errorf("engines: %s path is empty", what)
	case !filepath.IsAbs(path):
		return fmt.Errorf("engines: %s path %q must be absolute (Docker would take it for a volume name)", what, path)
	case strings.Contains(path, ":"):
		return fmt.Errorf("engines: %s path %q contains ':' which a bind mount spec cannot hold", what, path)
	}
	return nil
}

// Driver is the glue between the agent and one engine.
type Driver interface {
	// Engine is the engine this driver runs.
	Engine() nodev1.Engine

	// Supports reports whether the driver can serve proxies of the given type.
	Supports(t nodev1.ProxyType) bool

	// ArtifactFile is the name of the release file to download for a CPU
	// architecture ("amd64" or "arm64"), for example telemt-x86_64-linux-musl.tar.gz.
	ArtifactFile(arch string) (string, error)

	// BinaryName is the name of the executable in the release file, and the name
	// the artifact store keeps it under.
	BinaryName() string

	// Render computes the files the engine is started with: relative path to
	// content. They contain the proxy secret and must be written private.
	Render(in Instance) (map[string][]byte, error)

	// Container describes the container to run the engine in. It does not touch
	// the host: see Instance.CheckHostPaths for what to verify before creating it.
	Container(in Instance) dockerapi.ContainerSpec

	// Ready makes one check whether the engine accepts connections, and returns
	// nil when it does. It does not wait: callers poll it until their deadline.
	Ready(ctx context.Context, in Instance) error
}

// DCHealth is what an engine says of the middle proxies of one Telegram
// datacenter: how many of its endpoints hold a writer, as a share of them
// (an idle endpoint is not a broken one), and how much of the writers it
// wants it has (coverage), in percent. FreshCoveragePct counts only the
// writers seen alive lately; HasFreshCoverage is false when the engine's
// answer does not carry it (older telemt).
type DCHealth struct {
	DC                 int
	AvailableEndpoints int
	AvailablePct       float64
	CoveragePct        float64
	FreshCoveragePct   float64
	HasFreshCoverage   bool
}

// EngineHealth is an engine's own view of itself: ready to serve, and the
// state of its middle proxies. MiddleProxy false means the middle proxies are
// off or the engine has no snapshot of them yet; Reason says which.
type EngineHealth struct {
	Ready       bool
	MiddleProxy bool
	Reason      string
	DCs         []DCHealth
}

// HealthReporter is a Driver that can tell the health of an instance from its
// API (telemt). For other engines the checks that need it are skipped.
type HealthReporter interface {
	Health(ctx context.Context, in Instance) (EngineHealth, error)
}

// LogLeveler is a Driver whose containers set their log level through the
// environment: LogEnv is that environment, part of the container spec and not
// of the instance hash, so that a change of it rolls no engine.
type LogLeveler interface {
	LogEnv() []string
}
