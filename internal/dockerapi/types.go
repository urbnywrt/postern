// Package dockerapi is a minimal Docker Engine API client: only the calls the
// node agent needs to run its edge, engine and egress containers, spoken as
// plain HTTP and JSON over the daemon's unix socket, without the Docker SDK.
// Fake is an in-memory Client for unit tests of code that drives containers.
//
// Every Client method takes a context; cancelling it aborts the request. The
// client applies no timeout of its own (that would cut log and pull streams),
// so give calls a deadline. A non-2xx answer from the daemon is returned as
// *APIError, which carries Docker's own message; a 404 also satisfies
// errors.Is(err, ErrNotFound).
package dockerapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultSocket is the daemon socket New uses when it is given no path.
	DefaultSocket = "/var/run/docker.sock"

	// MaxAPIVersion is the newest Engine API version the client speaks. The
	// version actually used is min(the daemon's ApiVersion, MaxAPIVersion).
	MaxAPIVersion = "1.47"
)

// ErrNotFound is matched (errors.Is) by every error that stands for a 404 from
// the daemon: an unknown container, or an image that does not exist.
var ErrNotFound = errors.New("dockerapi: not found")

// APIError is the error for a non-2xx answer from the daemon. Message is the
// "message" field of Docker's JSON error body, or the raw body when that is
// not JSON.
type APIError struct {
	StatusCode int
	Message    string

	op string // what was attempted, for example `start container "x"`
}

func newAPIError(op string, statusCode int, message string) *APIError {
	return &APIError{StatusCode: statusCode, Message: message, op: op}
}

func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString("dockerapi: ")
	if e.op != "" {
		b.WriteString(e.op)
		b.WriteString(": ")
	}
	b.WriteString(strings.TrimSpace(fmt.Sprintf("%d %s", e.StatusCode, http.StatusText(e.StatusCode))))
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	return b.String()
}

// Is reports a 404 as ErrNotFound.
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound
}

// ContainerSpec describes a container to create. Zero-valued fields are left
// out of the request, so the image's or the daemon's defaults apply.
type ContainerSpec struct {
	// Name is the container name; empty lets the daemon pick one.
	Name string
	// Image is the image reference. It must already be present locally.
	Image string
	// User is "uid", "uid:gid" or a user name.
	User string
	// NetworkMode is HostConfig.NetworkMode, for example "host".
	NetworkMode string
	// RestartPolicy is "no", "always", "unless-stopped" or "on-failure"; empty
	// leaves the daemon default ("no").
	RestartPolicy string
	// PidMode is HostConfig.PidMode, for example "host".
	PidMode string

	// Entrypoint overrides the image's entrypoint; nil keeps it. When it is
	// set, the image's default Cmd is not used.
	Entrypoint []string
	// Cmd overrides the image's default command; nil keeps it.
	Cmd []string
	// Env is a list of "KEY=value" entries.
	Env []string
	// Binds is a list of "host-path:container-path[:options]" mounts.
	Binds []string
	// Mounts are bind mounts of the Mounts API: unlike Binds, a source that
	// does not exist fails the creation, and is not made by the daemon.
	Mounts []Mount
	// CapAdd and CapDrop are Linux capability names, or "ALL" for CapDrop.
	CapAdd  []string
	CapDrop []string
	// SecurityOpt is for example "no-new-privileges:true".
	SecurityOpt []string

	// Labels are the container labels.
	Labels map[string]string
	// Tmpfs maps a mount point to its options, for example "/tmp" to
	// "rw,noexec,nosuid,size=16m".
	Tmpfs map[string]string

	// ReadOnly mounts the root filesystem read-only.
	ReadOnly bool
	// Privileged runs the container with every capability and device and
	// without the confinement of /proc and /sys (HostConfig.Privileged). Only a
	// short-lived helper that sets host sysctls needs it.
	Privileged bool
	// MemoryBytes is the memory limit in bytes; 0 means unlimited.
	MemoryBytes int64
	// MemorySwap is the limit of memory plus swap in bytes (HostConfig.
	// MemorySwap); equal to MemoryBytes it forbids swap. 0 leaves the daemon's
	// default, twice the memory limit.
	MemorySwap int64
	// PidsLimit is the maximum number of processes; 0 leaves it unset.
	PidsLimit int64
	// Ulimits are resource limits of the processes of the container
	// (HostConfig.Ulimits); nil leaves the daemon's defaults.
	Ulimits []Ulimit
	// LogMaxSize and LogMaxFile configure rotation of the json-file log driver
	// (max-size such as "5m", and max-file). When both are zero the daemon's
	// log configuration is left alone.
	LogMaxSize string
	LogMaxFile int

	// StopTimeout is the number of seconds the daemon waits between SIGTERM and
	// SIGKILL when it stops the container without being told a timeout: on
	// shutdown, and for Client.Stop with a negative timeout. nil leaves the
	// daemon default (10 s); it is a pointer so that 0 can be told apart from
	// unset.
	StopTimeout *int
}

// Ulimit is a resource limit of the processes of a container, as setrlimit(2)
// sets it: Name is the resource without the RLIMIT_ prefix, in lower case
// ("nofile" for RLIMIT_NOFILE), Soft and Hard are the soft and the hard limit.
type Ulimit struct {
	Name string
	Soft int64
	Hard int64
}

// Container is a container as listed by the daemon.
type Container struct {
	// ID is the full container ID.
	ID string
	// Name is the container name without the leading slash.
	Name string
	// Image is the image reference the container was created from.
	Image string
	// State is "created", "running", "paused", "restarting", "removing",
	// "exited" or "dead".
	State string
	// Status is the human readable status ("Up 3 minutes"). Inspect has no such
	// field, so there it repeats State.
	Status  string
	Labels  map[string]string
	Created time.Time
}

// ContainerDetails is a container as inspected.
type ContainerDetails struct {
	Container
	// RestartPolicy is the policy name; the default is reported as "no".
	RestartPolicy string
	// Binds are the bind mounts the container was created with
	// (HostConfig.Binds), each "host-path:container-path[:options]"; nil when
	// it has none.
	Binds []string
	// Running is the daemon's State.Running flag. It is also true while the
	// container is paused or restarting; State tells those apart.
	Running bool
	// RestartCount is how many times the daemon restarted the container by its
	// restart policy since it was created.
	RestartCount int
	// Env is the environment the container was created with (Config.Env).
	Env []string
	// ExitCode is the exit code of the last run; 0 before the first run.
	ExitCode int
	// StartedAt and FinishedAt are zero while the container never started or
	// never finished.
	StartedAt, FinishedAt time.Time
	// NetworkMode is HostConfig.NetworkMode ("host", "bridge", a network
	// name, ...); "" when the daemon does not say.
	NetworkMode string
	// PortBindings are the ports published on the host (HostConfig.
	// PortBindings), sorted; nil when the container publishes none.
	PortBindings []PortBinding
	// Mounts are the mounts of the running container as the daemon reports
	// them (the top-level Mounts of the inspection): binds, volumes and tmpfs,
	// whichever API made them; nil when it has none.
	Mounts []MountPoint
}

// MountPoint is a mount of a container as inspected: Type is "bind", "volume",
// "tmpfs" ...; Source is the path on the host (for a bind), Destination the
// path in the container; RW is false for a read-only mount.
type MountPoint struct {
	Type        string
	Source      string
	Destination string
	RW          bool
}

// Info is the part of the daemon's system information (GET /info) that is used.
type Info struct {
	// SecurityOptions are the daemon's security options, such as
	// "name=seccomp,profile=builtin" and "name=userns" when the daemon remaps
	// user namespaces.
	SecurityOptions []string
}

// PortBinding is a port of a container published on the host: ContainerPort
// is "443/tcp", HostIP is "" or "0.0.0.0" for every address of the host.
type PortBinding struct {
	ContainerPort string
	HostIP        string
	HostPort      string
}

// Client is the subset of the Docker Engine API used by the node agent.
// Implementations are safe for concurrent use.
//
// Every method that addresses a container accepts its ID, a unique ID prefix or
// its name, and fails with an error matching ErrNotFound when it does not exist.
type Client interface {
	// Ping checks that the daemon answers and returns the API version this
	// client speaks: min(the daemon's ApiVersion, MaxAPIVersion), for example
	// "1.47". It also renegotiates that version.
	Ping(ctx context.Context) (apiVersion string, err error)

	// Info returns the system information of the daemon (GET /info).
	Info(ctx context.Context) (*Info, error)

	// List returns the containers that carry every label in labels. A label
	// whose value is empty matches any value of that key. all=false lists
	// running containers only. The newest container comes first.
	List(ctx context.Context, labels map[string]string, all bool) ([]Container, error)

	// Inspect returns the details of one container (ErrNotFound when it does not
	// exist).
	Inspect(ctx context.Context, idOrName string) (*ContainerDetails, error)

	// Create creates a container without starting it and returns its ID. The
	// image must already be present (see ImageExists and Pull), otherwise the
	// error matches ErrNotFound. A name that is taken is a 409 *APIError.
	Create(ctx context.Context, spec ContainerSpec) (id string, err error)

	// Start starts a created or stopped container. Starting one that is
	// already running is not an error.
	Start(ctx context.Context, id string) error

	// Stop asks the container to stop (SIGTERM) and kills it after timeout,
	// rounded up to whole seconds. A negative timeout leaves the choice to the
	// daemon (10 s unless the container's ContainerSpec.StopTimeout says
	// otherwise). Stopping a container that is not running is not an error.
	Stop(ctx context.Context, id string, timeout time.Duration) error

	// Remove deletes a container and its anonymous volumes. With force a running
	// container is killed first; without it removing a running container is a
	// 409 *APIError.
	Remove(ctx context.Context, id string, force bool) error

	// SetRestartPolicy changes the restart policy of a container, also a running
	// one (POST /containers/{id}/update). The policy is one of "no", "always",
	// "unless-stopped" and "on-failure"; empty means "no".
	SetRestartPolicy(ctx context.Context, id, policy string) error

	// Logs returns the container's stdout and stderr as one plain text stream:
	// the daemon's 8-byte frame headers are stripped (unless the container has a
	// TTY, where the stream is raw already) and the streams are not told apart.
	// tail is the number of lines to start from; a negative tail means all lines
	// and 0 none, which with follow streams only new output. With follow the
	// stream stays open until ctx is cancelled, the container exits or the
	// reader is closed. The caller must Close the reader.
	Logs(ctx context.Context, id string, tail int, follow bool) (io.ReadCloser, error)

	// LogsSince returns the output of the container (stdout and stderr, as
	// Logs does) written at or after since (all of it when since is zero),
	// each line prefixed with its RFC 3339 timestamp and a space, as the
	// daemon writes them with timestamps=1. The caller must Close the reader.
	LogsSince(ctx context.Context, id string, since time.Time) (io.ReadCloser, error)

	// ImageExists reports whether the image (name, name:tag, name@digest,
	// name:tag@digest or an image ID) is present locally.
	ImageExists(ctx context.Context, ref string) (bool, error)

	// Pull downloads an image and returns when the download has finished. A
	// failure in the middle of the download is returned as an error too.
	Pull(ctx context.Context, ref string) error
}

var (
	errEmptyID  = errors.New("dockerapi: empty container ID or name")
	errEmptyRef = errors.New("dockerapi: empty image reference")
)

func checkID(id string) error {
	if id == "" {
		return errEmptyID
	}
	return nil
}

// validateSpec is the part of Create's validation shared by the real client and
// the fake, so both reject the same specs.
func validateSpec(spec ContainerSpec) error {
	if spec.Image == "" {
		return errors.New("dockerapi: container spec has no image")
	}
	for _, u := range spec.Ulimits {
		if u.Name == "" {
			return errors.New("dockerapi: container spec has a ulimit without a name")
		}
		if u.Soft > u.Hard {
			return fmt.Errorf("dockerapi: ulimit %s: the soft limit %d is over the hard limit %d", u.Name, u.Soft, u.Hard)
		}
	}
	return checkRestartPolicy(spec.RestartPolicy)
}

// checkRestartPolicy accepts the policy names of the Engine API; empty means
// "not specified".
func checkRestartPolicy(policy string) error {
	switch policy {
	case "", "no", "always", "unless-stopped", "on-failure":
		return nil
	}
	return fmt.Errorf("dockerapi: invalid restart policy %q", policy)
}

// Mount is a bind mount of a host directory or file (HostConfig.Mounts, type
// bind). The daemon refuses a Source that does not exist.
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}
