// Package trial runs an artifact's trial (engines.Trial) on the node: the
// binary is started once in the runner image, in a container that can do
// nothing but exit (no network, read-only root, no capabilities, user 65534, 64
// MiB, 16 processes), and judged by its exit code and its output.
//
// A trial tells a binary that runs on this node from one that does not (another
// architecture, a dynamically linked build, a damaged download), and one that is
// the version it claims to be from one that is not (spec §7, finding F1).
//
// Only a trial that ran counts (Result.Ran): the container started and exited,
// or Docker refused to start it because of the binary itself (exec format error,
// missing interpreter, no such file). When Docker cannot be reached, the runner
// image cannot be pulled, or the container cannot be created or started for a
// reason that is not the binary's, nothing was judged: the caller records
// nothing and tries again later.
package trial

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
)

const (
	// DefaultTimeout is how long a trial may take to exit (Global Constraints).
	DefaultTimeout = 10 * time.Second
	// binaryDir is where the binary is mounted in the container.
	binaryDir = "/opt/engine"
	// maxOutput is how much of the container's log is kept, in bytes.
	maxOutput = 4096
	// maxReasonOutput is how much of the output a Reason quotes.
	maxReasonOutput = 200
	// removeTimeout bounds the removal of the container, which happens
	// whatever the state of the caller's context.
	removeTimeout = 15 * time.Second
	// pullAllowance is what the Docker calls of a trial may take beyond the
	// trial's Timeout: the pull of the runner image when it is missing (a few
	// MiB; two minutes covers a slow link), and the create, start, inspect and
	// log calls, which take well under a second each on a daemon that answers.
	pullAllowance = 2 * time.Minute
	// namePrefix starts every trial container's name: postern-trial-<binary>-<8 hex>.
	namePrefix = "postern-trial-"
)

// pollInterval is how often the runner looks whether the container has exited.
// A variable for the tests.
var pollInterval = 100 * time.Millisecond

// Labels are the labels of every trial container.
var Labels = map[string]string{"postern.managed": "true", "postern.role": "trial"}

// Runner runs trials. One Runner serves the whole agent (UploadArtifact and
// the reconciler share it), so that InFlight covers every trial of the node.
// The zero value is not usable; Docker and RunnerImage must be set.
type Runner struct {
	Docker      dockerapi.Client
	RunnerImage string
	// Timeout is how long a trial may take to exit; 0 means DefaultTimeout.
	Timeout time.Duration
	Log     *slog.Logger

	mu       sync.Mutex
	inFlight map[string]bool
}

// Result is the outcome of one trial.
type Result struct {
	// Ran reports that there was something to judge: the container started and
	// exited (or was killed at the timeout), or Docker refused to start the
	// binary itself. When it is false nothing is known about the binary, and
	// Reason says what went wrong instead.
	Ran bool
	// OK reports that the trial passed: Ran, the exit code is the wanted one
	// and the output matches. Reason says why not otherwise.
	OK bool
	// ExitCode is the container's exit code when it exited.
	ExitCode int
	// Output is the container's stdout and stderr together, at most 4 KiB of
	// valid UTF-8.
	Output string
	// Reason says why the trial did not pass, or did not run. Empty when OK.
	Reason string
}

// InFlight returns the names of this runner's trial containers that are
// running (created and not yet removed).
func (r *Runner) InFlight() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.inFlight)
}

func (r *Runner) track(name string, running bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if running {
		if r.inFlight == nil {
			r.inFlight = map[string]bool{}
		}
		r.inFlight[name] = true
		return
	}
	delete(r.inFlight, name)
}

// spec is the container of a trial of the binary at binaryPath, named
// binaryName in the container, with the trial's arguments (Global Constraints,
// Trial runs).
func (r *Runner) spec(name, binaryPath, binaryName string, t engines.Trial) dockerapi.ContainerSpec {
	binary := binaryDir + "/" + binaryName
	return dockerapi.ContainerSpec{
		Name:        name,
		Image:       r.RunnerImage,
		User:        "65534:65534",
		NetworkMode: "none",
		Entrypoint:  append([]string{binary}, t.Args...),
		Binds:       []string{binaryPath + ":" + binary + ":ro"},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels:      maps.Clone(Labels),
		ReadOnly:    true,
		MemoryBytes: 64 << 20,
		MemorySwap:  64 << 20, // no swap on top of the limit
		PidsLimit:   16,
		LogMaxSize:  "1m",
		LogMaxFile:  1,
	}
}

// Run tries the binary at binaryPath (a host path; the artifact store's) out.
// It pulls the runner image when it is missing, creates and starts the
// container, waits for it to exit (at most Timeout, then it is killed), reads
// its output and removes the container, whatever happened. It returns when the
// container is gone.
func (r *Runner) Run(ctx context.Context, binaryPath, binaryName string, t engines.Trial) Result {
	if err := r.check(binaryPath, binaryName); err != nil {
		return Result{Reason: err.Error()}
	}
	log := r.log().With("binary", binaryName, "path", binaryPath)
	// Every Docker call of the trial ends by this deadline: a daemon that
	// hangs cannot hold the caller (the upload) for longer than the trial's
	// timeout and the pull allowance. The removal has a deadline of its own.
	ctx, cancel := context.WithTimeout(ctx, r.timeout()+pullAllowance)
	defer cancel()

	if err := r.ensureImage(ctx); err != nil {
		return Result{Reason: err.Error()}
	}

	name := namePrefix + binaryName + "-" + randomHex(4)
	spec := r.spec(name, binaryPath, binaryName, t)
	// Tracked before Create: a sweep of orphans that runs between Create and
	// Start must see the name.
	r.track(name, true)
	defer r.track(name, false)
	id, err := r.Docker.Create(ctx, spec)
	if err != nil {
		return Result{Reason: "creating the trial container: " + err.Error()}
	}
	defer r.remove(ctx, id, log)

	if err := r.Docker.Start(ctx, id); err != nil {
		if isExecError(err) {
			// The binary itself cannot run here: that is a verdict.
			res := Result{Ran: true, Reason: "the binary cannot be started: " + execMessage(err)}
			log.Info("trial: the binary cannot be started", "reason", res.Reason)
			return res
		}
		return Result{Reason: "starting the trial container: " + err.Error()}
	}

	details, err := r.waitExit(ctx, id)
	switch {
	case errors.Is(err, errTimeout):
		res := Result{Ran: true, Reason: fmt.Sprintf("the binary did not exit within %v", r.timeout())}
		res.Output = r.output(ctx, id, log)
		log.Info("trial: killed at the timeout", "timeout", r.timeout())
		return res
	case err != nil:
		return Result{Reason: err.Error()}
	}

	res := Result{Ran: true, ExitCode: details.ExitCode}
	res.Output = r.output(ctx, id, log)
	res.OK, res.Reason = judge(t, res.ExitCode, res.Output)
	log.Info("trial: ran", "exit", res.ExitCode, "ok", res.OK, "reason", res.Reason)
	return res
}

// check refuses what cannot be a bind source or a container path element.
func (r *Runner) check(binaryPath, binaryName string) error {
	switch {
	case r.Docker == nil:
		return errors.New("trial: no Docker client")
	case r.RunnerImage == "":
		return errors.New("trial: no runner image")
	case binaryPath == "":
		return errors.New("trial: the binary path is empty")
	case !filepath.IsAbs(binaryPath):
		return fmt.Errorf("trial: the binary path %q is not absolute", binaryPath)
	case strings.Contains(binaryPath, ":"):
		return fmt.Errorf("trial: the binary path %q contains ':' which a bind mount spec cannot hold", binaryPath)
	case binaryName == "", !validName(binaryName):
		return fmt.Errorf("trial: the binary name %q is not 1 to 64 letters, digits, '.', '_', '+' and '-'", binaryName)
	}
	return nil
}

// validName is artifacts.validElement: 1 to 64 of [A-Za-z0-9._+-], starting
// with a letter or a digit.
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-' || c == '+'):
		default:
			return false
		}
	}
	return true
}

func (r *Runner) ensureImage(ctx context.Context) error {
	ok, err := r.Docker.ImageExists(ctx, r.RunnerImage)
	if err != nil {
		return fmt.Errorf("asking Docker about the runner image: %w", err)
	}
	if ok {
		return nil
	}
	r.log().Info("trial: pulling the runner image", "image", r.RunnerImage)
	if err := r.Docker.Pull(ctx, r.RunnerImage); err != nil {
		return fmt.Errorf("pulling the runner image: %w", err)
	}
	return nil
}

var errTimeout = errors.New("trial: timeout")

// waitExit polls Inspect until the container is no longer running. At the
// timeout it returns errTimeout (the deferred removal kills the container).
func (r *Runner) waitExit(ctx context.Context, id string) (*dockerapi.ContainerDetails, error) {
	deadline := time.Now().Add(r.timeout())
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		d, err := r.Docker.Inspect(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("inspecting the trial container: %w", err)
		}
		if !d.Running {
			return d, nil
		}
		if time.Now().After(deadline) {
			return nil, errTimeout
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("the trial was cancelled: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// output reads at most maxOutput bytes of the container's log and makes them
// valid UTF-8. A log that cannot be read is empty.
func (r *Runner) output(ctx context.Context, id string, log *slog.Logger) string {
	// tail -1 is dockerapi's "all lines" (0 would be none); the limit below
	// bounds what is read of them. No follow: the container has exited.
	rc, err := r.Docker.Logs(ctx, id, -1, false)
	if err != nil {
		log.Warn("trial: the output cannot be read", "err", err)
		return ""
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, maxOutput))
	if err != nil {
		log.Warn("trial: the output cannot be read", "err", err)
	}
	// Invalid bytes, and the rune the limit cut in two, are dropped: the
	// output is never longer than what was read.
	return strings.ToValidUTF8(string(b), "")
}

// judge applies the trial's rules to what the container did.
func judge(t engines.Trial, exitCode int, output string) (ok bool, reason string) {
	if exitCode != t.ExitCode {
		return false, fmt.Sprintf("exited with %d, want %d%s", exitCode, t.ExitCode, quote(output))
	}
	if t.Output != nil && !t.Output.MatchString(output) {
		return false, "the output does not match " + t.Output.String() + quote(output)
	}
	return true, ""
}

// quote is the beginning of the output for a reason, or nothing.
func quote(output string) string {
	s := strings.TrimSpace(output)
	if s == "" {
		return " (no output)"
	}
	return ": " + clip(strings.Join(strings.Fields(s), " "), maxReasonOutput)
}

// clip cuts s to at most n bytes at a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// remove takes the container away, by force, with its own deadline: the
// caller's context may be done.
func (r *Runner) remove(ctx context.Context, id string, log *slog.Logger) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), removeTimeout)
	defer cancel()
	if err := r.Docker.Remove(rctx, id, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
		log.Warn("trial: the trial container could not be removed", "id", id, "err", err)
	}
}

// execErrorRe matches what the daemon says when the binary itself cannot be
// executed (Global Constraints, Trial runs): the wrong architecture (exec
// format error), a missing dynamic loader or the file itself (`exec <path>:
// no such file or directory`, also as `exec: "<path>": stat <path>: no such
// file or directory`, or executable file not found). The "no such file"
// alternative is anchored to the exec context: a bind source that is missing
// says the same words in another sentence, and is the node's fault.
var execErrorRe = regexp.MustCompile(`(?i)exec format error|exec:? (?:"[^"]*"|\S+): (?:stat \S+: )?no such file or directory|executable file not found`)

// isExecError reports a Start error that is the daemon's verdict on the
// binary: an answer of the daemon (*dockerapi.APIError: a transport error
// never is one) whose message matches execErrorRe.
func isExecError(err error) bool {
	var apiErr *dockerapi.APIError
	return errors.As(err, &apiErr) && execErrorRe.MatchString(apiErr.Message)
}

// execMessage is Docker's message for the error, without the client's prefix.
func execMessage(err error) string {
	var apiErr *dockerapi.APIError
	if errors.As(err, &apiErr) && apiErr.Message != "" {
		return clip(apiErr.Message, maxReasonOutput)
	}
	return clip(err.Error(), maxReasonOutput)
}

func (r *Runner) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultTimeout
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
