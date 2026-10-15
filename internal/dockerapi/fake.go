package dockerapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Call is one recorded call to a Fake. Method is the name of the Client method
// ("Ping", "List", "Inspect", "Create", "Start", "Stop", "Remove",
// "SetRestartPolicy", "Logs", "LogsSince", "ImageExists" or "Pull") and the other fields are
// its arguments, as far as it has them.
type Call struct {
	Method string
	// Target is the container ID or name as the caller gave it, the image
	// reference for ImageExists and Pull, and the spec's name for Create.
	Target  string
	Spec    *ContainerSpec    // Create: a copy of the spec
	Labels  map[string]string // List
	All     bool              // List
	Policy  string            // SetRestartPolicy
	Timeout time.Duration     // Stop
	Force   bool              // Remove
	Tail    int               // Logs
	Follow  bool              // Logs
}

// Fake is an in-memory Client for tests of code that drives containers. It
// follows the behaviour of a real daemon where that matters to such code, and
// the same contract test runs against both:
//
//   - Create makes a "created" container, Start makes it "running" and Stop makes
//     it "exited" (exit code 0); Exit simulates a process that dies by itself.
//   - Starting a running container and stopping a stopped one are no-ops;
//     removing a running container needs force (otherwise a 409 *APIError);
//     a name can be used once (409); every unknown container is a 404 *APIError
//     (errors.Is(err, ErrNotFound)).
//   - Containers can be addressed by name, by ID and by a unique ID prefix; IDs
//     are 64 hex digits, reproducible from one Fake to the next.
//   - List returns the newest container first.
//
// It differs from a daemon in a few ways: no process runs, so nothing exits and
// no restart policy is ever applied, and a container prints only what
// AppendLogs put there; Create does not check that the image was pulled; a
// followed log stream ends at the end of the buffered text.
//
// Every Client call is recorded (Calls), also when it fails, and can be made to
// fail (SetError). The Fake is safe for concurrent use.
type Fake struct {
	// Now returns the time for the Created, StartedAt and FinishedAt stamps; nil
	// means time.Now. Set it before the Fake is used.
	Now func() time.Time

	mu         sync.Mutex
	seq        int
	containers []*fakeContainer // in order of creation
	images     map[string]bool
	calls      []Call
	errs       map[string]error
	info       Info
}

var _ Client = (*Fake)(nil)

type fakeContainer struct {
	id, name string
	spec     ContainerSpec
	state    string // created, running or exited
	running  bool
	exitCode int
	policy   string
	created  time.Time
	started  time.Time
	finished time.Time
	logs     []byte
	stamped  []stampedLine // the lines of logs with the time AppendLogs got them
	restarts int
	ports    []PortBinding
	mounts   []MountPoint
}

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{images: map[string]bool{}, errs: map[string]error{}}
}

// ---- test helpers -------------------------------------------------------------

// Calls returns the calls made so far, oldest first.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Call, len(f.calls))
	for i, c := range f.calls {
		if c.Spec != nil {
			spec := cloneSpec(*c.Spec)
			c.Spec = &spec
		}
		c.Labels = maps.Clone(c.Labels)
		out[i] = c
	}
	return out
}

// ResetCalls forgets the calls made so far, for example after the setup of a test.
func (f *Fake) ResetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// SetError makes every call of the named Client method fail with err until it is
// cleared with a nil err. The method "*" stands for all of them; a method's own
// error wins over it. The failed call is still recorded.
func (f *Fake) SetError(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.errs, method)
		return
	}
	if f.errs == nil {
		f.errs = map[string]error{}
	}
	f.errs[method] = err
}

// Exit simulates the main process of a running container dying on its own with
// the given exit code. It is not a Client call and is not recorded.
func (f *Fake) Exit(idOrName string, exitCode int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := f.find(fmt.Sprintf("exit container %q", idOrName), idOrName)
	if err != nil {
		return err
	}
	if !c.running {
		return fmt.Errorf("dockerapi: fake: container %q is not running", c.name)
	}
	c.stop(f.now(), exitCode)
	return nil
}

// AppendLogs adds text to the container's output. It is not a Client call and
// is not recorded.
func (f *Fake) AppendLogs(idOrName, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := f.find(fmt.Sprintf("append logs of container %q", idOrName), idOrName)
	if err != nil {
		return err
	}
	c.logs = append(c.logs, text...)
	at := f.now()
	for line := range strings.Lines(text) {
		// A nanosecond apart, as the daemon stamps each write.
		c.stamped = append(c.stamped, stampedLine{at: at, text: line})
		at = at.Add(time.Nanosecond)
	}
	return nil
}

// AddImage makes images present, as if they had been pulled before.
func (f *Fake) AddImage(refs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.images == nil {
		f.images = map[string]bool{}
	}
	for _, ref := range refs {
		f.images[ref] = true
	}
}

// SetPortBindings gives a container the ports it publishes on the host, as
// Inspect reports them (the Fake's ContainerSpec has no ports). It is not a
// Client call and is not recorded.
func (f *Fake) SetPortBindings(idOrName string, bs ...PortBinding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := f.find(fmt.Sprintf("set the ports of container %q", idOrName), idOrName)
	if err != nil {
		return err
	}
	c.ports = slices.Clone(bs)
	sortPortBindings(c.ports)
	return nil
}

// SetInfo sets what Info returns (by default an Info with no security
// options). It is not a Client call and is not recorded.
func (f *Fake) SetInfo(info Info) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.info = Info{SecurityOptions: slices.Clone(info.SecurityOptions)}
}

// SetMounts gives a container the mounts Inspect reports (the Fake does not
// derive them from its spec). It is not a Client call and is not recorded.
func (f *Fake) SetMounts(idOrName string, ms ...MountPoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := f.find(fmt.Sprintf("set the mounts of container %q", idOrName), idOrName)
	if err != nil {
		return err
	}
	c.mounts = slices.Clone(ms)
	return nil
}

// Spec returns a copy of the spec the container was created from.
func (f *Fake) Spec(idOrName string) (ContainerSpec, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := f.find("", idOrName)
	if err != nil {
		return ContainerSpec{}, false
	}
	return cloneSpec(c.spec), true
}

// ---- Client -------------------------------------------------------------------

func (f *Fake) Ping(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "Ping"}); err != nil {
		return "", err
	}
	return MaxAPIVersion, nil
}

func (f *Fake) Info(ctx context.Context) (*Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "Info"}); err != nil {
		return nil, err
	}
	return &Info{SecurityOptions: slices.Clone(f.info.SecurityOptions)}, nil
}

func (f *Fake) List(ctx context.Context, labels map[string]string, all bool) ([]Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "List", Labels: maps.Clone(labels), All: all}); err != nil {
		return nil, err
	}
	out := []Container{}
	for i := len(f.containers) - 1; i >= 0; i-- { // newest first, also among equal timestamps
		c := f.containers[i]
		if (all || c.running) && hasLabels(c.spec.Labels, labels) {
			out = append(out, c.summary())
		}
	}
	slices.SortStableFunc(out, func(a, b Container) int { return b.Created.Compare(a.Created) })
	return out, nil
}

func (f *Fake) Inspect(ctx context.Context, idOrName string) (*ContainerDetails, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "Inspect", Target: idOrName}); err != nil {
		return nil, err
	}
	c, err := f.find(fmt.Sprintf("inspect container %q", idOrName), idOrName)
	if err != nil {
		return nil, err
	}
	policy := c.policy
	if policy == "" {
		policy = "no"
	}
	return &ContainerDetails{
		Container:     c.summary(),
		RestartPolicy: policy,
		Binds:         slices.Clone(c.spec.Binds),
		Running:       c.running,
		ExitCode:      c.exitCode,
		RestartCount:  c.restarts,
		Env:           slices.Clone(c.spec.Env),
		StartedAt:     c.started,
		FinishedAt:    c.finished,
		NetworkMode:   c.spec.NetworkMode,
		PortBindings:  slices.Clone(c.ports),
		Mounts:        slices.Clone(c.mounts),
	}, nil
}

func (f *Fake) Create(ctx context.Context, spec ContainerSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	recorded := cloneSpec(spec)
	if err := f.begin(ctx, Call{Method: "Create", Target: spec.Name, Spec: &recorded}); err != nil {
		return "", err
	}
	if err := validateSpec(spec); err != nil {
		return "", err
	}
	op := fmt.Sprintf("create container %q", spec.Name)
	name := strings.TrimPrefix(spec.Name, "/")
	if name == "" {
		for n := f.seq + 1; ; n++ {
			name = fmt.Sprintf("fake_%d", n)
			if f.byName(name) == nil {
				break
			}
		}
	}
	if other := f.byName(name); other != nil {
		return "", newAPIError(op, http.StatusConflict, fmt.Sprintf(
			"Conflict. The container name %q is already in use by container %q. "+
				"You have to remove (or rename) that container to be able to reuse that name.", "/"+name, other.id))
	}
	f.seq++
	c := &fakeContainer{
		id:      fakeID(f.seq),
		name:    name,
		spec:    cloneSpec(spec),
		state:   "created",
		policy:  spec.RestartPolicy,
		created: f.now(),
	}
	f.containers = append(f.containers, c)
	return c.id, nil
}

func (f *Fake) Start(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "Start", Target: id}); err != nil {
		return err
	}
	c, err := f.find(fmt.Sprintf("start container %q", id), id)
	if err != nil {
		return err
	}
	if !c.running {
		c.running, c.state, c.exitCode, c.started = true, "running", 0, f.now()
	}
	return nil
}

func (f *Fake) Stop(ctx context.Context, id string, timeout time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "Stop", Target: id, Timeout: timeout}); err != nil {
		return err
	}
	c, err := f.find(fmt.Sprintf("stop container %q", id), id)
	if err != nil {
		return err
	}
	if c.running {
		c.stop(f.now(), 0)
	}
	return nil
}

func (f *Fake) Remove(ctx context.Context, id string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "Remove", Target: id, Force: force}); err != nil {
		return err
	}
	op := fmt.Sprintf("remove container %q", id)
	c, err := f.find(op, id)
	if err != nil {
		return err
	}
	if c.running && !force {
		return newAPIError(op, http.StatusConflict, fmt.Sprintf(
			"cannot remove container %q: container is running: stop the container before removing or force remove", "/"+c.name))
	}
	f.containers = slices.DeleteFunc(f.containers, func(x *fakeContainer) bool { return x == c })
	return nil
}

func (f *Fake) SetRestartPolicy(ctx context.Context, id, policy string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "SetRestartPolicy", Target: id, Policy: policy}); err != nil {
		return err
	}
	if err := checkRestartPolicy(policy); err != nil {
		return err
	}
	c, err := f.find(fmt.Sprintf("update container %q", id), id)
	if err != nil {
		return err
	}
	c.policy = policy
	if policy == "" {
		c.policy = "no"
	}
	return nil
}

func (f *Fake) Logs(ctx context.Context, id string, tail int, follow bool) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "Logs", Target: id, Tail: tail, Follow: follow}); err != nil {
		return nil, err
	}
	c, err := f.find(fmt.Sprintf("read logs of container %q", id), id)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(tailLines(c.logs, tail))), nil
}

func (f *Fake) ImageExists(ctx context.Context, ref string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "ImageExists", Target: ref}); err != nil {
		return false, err
	}
	if ref == "" {
		return false, errEmptyRef
	}
	return f.images[ref], nil
}

func (f *Fake) Pull(ctx context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "Pull", Target: ref}); err != nil {
		return err
	}
	if ref == "" {
		return errEmptyRef
	}
	if f.images == nil {
		f.images = map[string]bool{}
	}
	f.images[ref] = true
	return nil
}

// ---- internals ----------------------------------------------------------------

// begin records a call and returns the error the test asked for, if any, or the
// context's. The caller holds f.mu.
func (f *Fake) begin(ctx context.Context, call Call) error {
	f.calls = append(f.calls, call)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.errs[call.Method]; err != nil {
		return err
	}
	return f.errs["*"]
}

func (f *Fake) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Fake) byName(name string) *fakeContainer {
	for _, c := range f.containers {
		if c.name == name {
			return c
		}
	}
	return nil
}

// find resolves a name, an ID or a unique ID prefix. op names the attempt for
// the error. The caller holds f.mu.
func (f *Fake) find(op, ref string) (*fakeContainer, error) {
	if ref == "" {
		return nil, errEmptyID
	}
	if c := f.byName(strings.TrimPrefix(ref, "/")); c != nil {
		return c, nil
	}
	var match *fakeContainer
	matches := 0
	for _, c := range f.containers {
		if strings.HasPrefix(c.id, ref) {
			match = c
			matches++
		}
	}
	switch matches {
	case 0:
		return nil, newAPIError(op, http.StatusNotFound, "No such container: "+ref)
	case 1:
		return match, nil
	}
	return nil, newAPIError(op, http.StatusBadRequest, "Multiple IDs found with provided prefix: "+ref)
}

func (c *fakeContainer) stop(at time.Time, exitCode int) {
	c.running, c.state, c.exitCode, c.finished = false, "exited", exitCode, at
}

func (c *fakeContainer) summary() Container {
	return Container{
		ID:      c.id,
		Name:    c.name,
		Image:   c.spec.Image,
		State:   c.state,
		Status:  c.status(),
		Labels:  maps.Clone(c.spec.Labels),
		Created: c.created,
	}
}

func (c *fakeContainer) status() string {
	switch c.state {
	case "running":
		return "Up"
	case "exited":
		return fmt.Sprintf("Exited (%d)", c.exitCode)
	case "paused":
		return "Up (Paused)"
	}
	return "Created"
}

// fakeID is the n-th container ID: 64 hex digits that look like a real one and
// are the same in every Fake.
func fakeID(n int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("postern-dockerapi-fake-container-%d", n)))
	return hex.EncodeToString(sum[:])
}

// hasLabels reports whether have carries every label in want; an empty wanted
// value matches any value, like the daemon's bare "key" filter.
func hasLabels(have, want map[string]string) bool {
	for k, v := range want {
		got, ok := have[k]
		if !ok || (v != "" && got != v) {
			return false
		}
	}
	return true
}

// tailLines returns the last n lines of b (all of them for a negative n, none for
// zero). A final line without a newline counts as a line.
func tailLines(b []byte, n int) []byte {
	if n < 0 {
		return b
	}
	if n == 0 {
		return nil
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	if last := len(lines) - 1; last >= 0 && len(lines[last]) == 0 {
		lines = lines[:last]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return bytes.Join(lines, nil)
}

// cloneSpec copies the slices, maps and pointers of a spec, keeping nil ones nil.
func cloneSpec(s ContainerSpec) ContainerSpec {
	s.Entrypoint = slices.Clone(s.Entrypoint)
	s.Cmd = slices.Clone(s.Cmd)
	s.Env = slices.Clone(s.Env)
	s.Binds = slices.Clone(s.Binds)
	s.Mounts = slices.Clone(s.Mounts)
	s.CapAdd = slices.Clone(s.CapAdd)
	s.CapDrop = slices.Clone(s.CapDrop)
	s.SecurityOpt = slices.Clone(s.SecurityOpt)
	s.Labels = maps.Clone(s.Labels)
	s.Tmpfs = maps.Clone(s.Tmpfs)
	s.Ulimits = slices.Clone(s.Ulimits)
	if s.StopTimeout != nil {
		seconds := *s.StopTimeout
		s.StopTimeout = &seconds
	}
	return s
}

// stampedLine is a line of a container's output with its time.
type stampedLine struct {
	at   time.Time
	text string
}

// LogsSince returns the lines AppendLogs added at or after since, each with
// its time (RFC 3339 with nanoseconds) and a space before it, as the daemon
// writes them with timestamps=1.
func (f *Fake) LogsSince(ctx context.Context, id string, since time.Time) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx, Call{Method: "LogsSince", Target: id}); err != nil {
		return nil, err
	}
	c, err := f.find(fmt.Sprintf("read logs of container %q", id), id)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, l := range c.stamped {
		if !since.IsZero() && l.at.Before(since) {
			continue
		}
		b.WriteString(l.at.UTC().Format(time.RFC3339Nano))
		b.WriteByte(' ')
		b.WriteString(l.text)
		if !strings.HasSuffix(l.text, "\n") {
			b.WriteByte('\n')
		}
	}
	return io.NopCloser(&b), nil
}

// SetState puts a container into a daemon state that no Client call makes:
// "paused" and "restarting" (Running stays true, as the daemon reports it),
// "dead" (not running). It is not a Client call and is not recorded.
func (f *Fake) SetState(idOrName, state string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := f.find(fmt.Sprintf("set the state of container %q", idOrName), idOrName)
	if err != nil {
		return err
	}
	switch state {
	case "paused", "restarting":
		c.state, c.running = state, true
	case "dead":
		c.state, c.running = state, false
	default:
		return fmt.Errorf("dockerapi: fake: SetState does not make %q", state)
	}
	return nil
}

// Restarted counts n restarts of a container by its restart policy, as the
// daemon's RestartCount does, and starts it again at the Fake's time. It is not
// a Client call and is not recorded.
func (f *Fake) Restarted(idOrName string, n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := f.find(fmt.Sprintf("restart container %q", idOrName), idOrName)
	if err != nil {
		return err
	}
	c.restarts += n
	c.state, c.running, c.started = "running", true, f.now()
	return nil
}
