package trial

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
)

const (
	testImage  = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
	testBinary = "/opt/postern/data/artifacts/mtg/v2.2.8/amd64/mtg"
)

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

var versionTrial = engines.Trial{Args: []string{"--version"}, ExitCode: 0, Output: regexp.MustCompile(`\b2\.2\.8\b`)}

func newRunner(t *testing.T) (*Runner, *dockerapi.Fake) {
	t.Helper()
	fake := dockerapi.NewFake()
	fake.AddImage(testImage)
	return &Runner{Docker: fake, RunnerImage: testImage, Timeout: 2 * time.Second, Log: discardLog()}, fake
}

// runAsync starts Run and returns the container once it runs and a function
// that waits for the result.
func runAsync(t *testing.T, r *Runner, fake *dockerapi.Fake, tr engines.Trial) (dockerapi.Container, func() Result) {
	t.Helper()
	done := make(chan Result, 1)
	go func() { done <- r.Run(context.Background(), testBinary, "mtg", tr) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if list, _ := fake.List(context.Background(), map[string]string{"postern.role": "trial"}, false); len(list) == 1 {
			return list[0], func() Result {
				select {
				case res := <-done:
					return res
				case <-time.After(10 * time.Second):
					t.Fatal("Run did not return")
					return Result{}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no trial container was started")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func noContainersLeft(t *testing.T, fake *dockerapi.Fake) {
	t.Helper()
	if list, _ := fake.List(context.Background(), nil, true); len(list) != 0 {
		t.Errorf("containers left behind: %v", list)
	}
}

func TestRunPassesAndRemovesTheContainer(t *testing.T) {
	r, fake := newRunner(t)
	c, wait := runAsync(t, r, fake, versionTrial)
	if !strings.HasPrefix(c.Name, "postern-trial-mtg-") || len(c.Name) != len("postern-trial-mtg-")+8 {
		t.Errorf("container name %q, want postern-trial-mtg-<8 hex>", c.Name)
	}
	if got := r.InFlight(); !got[c.Name] || len(got) != 1 {
		t.Errorf("InFlight = %v, want {%s}", got, c.Name)
	}
	if err := fake.AppendLogs(c.ID, "mtg version 2.2.8 (go1.24.1)\n"); err != nil {
		t.Fatal(err)
	}
	if err := fake.Exit(c.ID, 0); err != nil {
		t.Fatal(err)
	}
	res := wait()
	want := Result{Ran: true, OK: true, ExitCode: 0, Output: "mtg version 2.2.8 (go1.24.1)\n"}
	if !reflect.DeepEqual(want, res) {
		t.Errorf("Run = %+v, want %+v", res, want)
	}
	if got := r.InFlight(); len(got) != 0 {
		t.Errorf("InFlight after the run = %v", got)
	}
	noContainersLeft(t, fake)
}

func TestRunContainerSpec(t *testing.T) {
	r, fake := newRunner(t)
	c, wait := runAsync(t, r, fake, versionTrial)
	spec, ok := fake.Spec(c.ID)
	if !ok {
		t.Fatal("no spec")
	}
	want := dockerapi.ContainerSpec{
		Name:        c.Name,
		Image:       testImage,
		User:        "65534:65534",
		NetworkMode: "none",
		Entrypoint:  []string{"/opt/engine/mtg", "--version"},
		Binds:       []string{testBinary + ":/opt/engine/mtg:ro"},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels:      map[string]string{"postern.managed": "true", "postern.role": "trial"},
		ReadOnly:    true,
		MemoryBytes: 64 << 20,
		MemorySwap:  64 << 20,
		PidsLimit:   16,
		LogMaxSize:  "1m",
		LogMaxFile:  1,
	}
	if !reflect.DeepEqual(want, spec) {
		t.Errorf("spec = %+v, want %+v", spec, want)
	}
	_ = fake.Exit(c.ID, 0)
	wait()
}

func TestRunJudgesExitCodeAndOutput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		trial  engines.Trial
		exit   int
		output string
		ok     bool
		reason string
	}{
		{"exit code mismatch", versionTrial, 1, "mtg version 2.2.8\n", false, "exited with 1, want 0"},
		{"output mismatch", versionTrial, 0, "mtg version 2.2.7\n", false, "output does not match"},
		{"any output", engines.Trial{Args: []string{"x"}, ExitCode: 1}, 1, "whatever", true, ""},
		{"no output at all", versionTrial, 0, "", false, "output does not match"},
		{"nonzero wanted", engines.Trial{Args: []string{"healthcheck"}, ExitCode: 1, Output: regexp.MustCompile(`^\[telemt\] healthcheck failed`)}, 1, "[telemt] healthcheck failed: config load failed: x\n", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, fake := newRunner(t)
			c, wait := runAsync(t, r, fake, tc.trial)
			if tc.output != "" {
				_ = fake.AppendLogs(c.ID, tc.output)
			}
			_ = fake.Exit(c.ID, tc.exit)
			res := wait()
			if !res.Ran || res.OK != tc.ok || res.ExitCode != tc.exit || res.Output != tc.output {
				t.Errorf("Run = %+v; want ran, ok %v, exit %d, output %q", res, tc.ok, tc.exit, tc.output)
			}
			if !strings.Contains(res.Reason, tc.reason) {
				t.Errorf("reason %q, want %q in it", res.Reason, tc.reason)
			}
			if tc.ok && res.Reason != "" {
				t.Errorf("a passing trial has reason %q", res.Reason)
			}
			noContainersLeft(t, fake)
		})
	}
}

func TestRunClipsTheOutput(t *testing.T) {
	r, fake := newRunner(t)
	c, wait := runAsync(t, r, fake, engines.Trial{Args: []string{"x"}, ExitCode: 0})
	// 3 bytes per rune: 4096 is not a rune boundary (4096 = 3*1365 + 1).
	long := strings.Repeat("€", 3000) + strings.Repeat("\xff", 10)
	_ = fake.AppendLogs(c.ID, long)
	_ = fake.Exit(c.ID, 0)
	res := wait()
	if !res.Ran || !res.OK {
		t.Fatalf("Run = %+v", res)
	}
	if len(res.Output) > maxOutput || !utf8.ValidString(res.Output) || !strings.HasPrefix(long, res.Output) {
		t.Errorf("output: %d bytes, valid %v, prefix %v", len(res.Output), utf8.ValidString(res.Output), strings.HasPrefix(long, res.Output))
	}
	if len(res.Output) < maxOutput-utf8.UTFMax {
		t.Errorf("output clipped to %d bytes, want close to %d", len(res.Output), maxOutput)
	}

	// Invalid bytes within the limit are dropped.
	r, fake = newRunner(t)
	c, wait = runAsync(t, r, fake, engines.Trial{Args: []string{"x"}, ExitCode: 0})
	_ = fake.AppendLogs(c.ID, "ok\xff\xfe end")
	_ = fake.Exit(c.ID, 0)
	if res := wait(); res.Output != "ok end" {
		t.Errorf("output %q, want the invalid bytes dropped", res.Output)
	}
}

func TestRunStartErrorOfTheBinaryCounts(t *testing.T) {
	for _, msg := range []string{
		`failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: exec /opt/engine/mtg: exec format error: unknown`,
		`OCI runtime create failed: unable to start container process: exec: "/opt/engine/mtg": stat /opt/engine/mtg: no such file or directory: unknown`,
		`exec /opt/engine/mtg: no such file or directory`,
		`executable file not found in $PATH`,
	} {
		r, fake := newRunner(t)
		fake.SetError("Start", &dockerapi.APIError{StatusCode: 400, Message: msg})
		res := r.Run(context.Background(), testBinary, "mtg", versionTrial)
		if !res.Ran || res.OK || !strings.Contains(res.Reason, "cannot be started") {
			t.Errorf("%s: Run = %+v; want ran, not ok, a reason that says it cannot be started", msg, res)
		}
		noContainersLeft(t, fake)
	}
}

// A Start error that is not the daemon's verdict on the binary is not a
// verdict: the daemon gone (a plain dial error) or a bind source that is
// missing (an APIError whose text happens to say "no such file").
func TestRunStartErrorOfDockerDoesNotCount(t *testing.T) {
	for _, err := range []error{
		errors.New("dial unix /var/run/docker.sock: connect: no such file or directory"),
		&dockerapi.APIError{StatusCode: 500, Message: "error while creating mount source path '/opt/postern/data/artifacts/mtg/v2.2.8/amd64/mtg': bind source path does not exist: no such file or directory"},
		&dockerapi.APIError{StatusCode: 404, Message: "No such container: abc"},
	} {
		r, fake := newRunner(t)
		fake.SetError("Start", err)
		res := r.Run(context.Background(), testBinary, "mtg", versionTrial)
		if res.Ran || res.OK || !strings.Contains(res.Reason, "starting the trial container") {
			t.Errorf("%v: Run = %+v; want not ran", err, res)
		}
		noContainersLeft(t, fake)
	}
}

// Every Docker call of a trial has a deadline: the timeout plus the pull
// allowance, so that a daemon that hangs cannot hold the caller.
func TestRunDockerCallsHaveADeadline(t *testing.T) {
	r, fake := newRunner(t)
	r.Timeout = time.Second
	seen := &deadlineClient{Client: fake}
	r.Docker = seen
	start := time.Now()
	res := r.Run(context.Background(), testBinary, "mtg", versionTrial) // nobody exits it: the timeout
	if !res.Ran || res.OK {
		t.Fatalf("Run = %+v", res)
	}
	for _, d := range seen.deadlines {
		left := d.Sub(start)
		if left < time.Second+pullAllowance-time.Second || left > time.Second+pullAllowance+time.Second {
			t.Errorf("a Docker call had %v left, want about %v", left, time.Second+pullAllowance)
		}
	}
	if len(seen.deadlines) < 4 { // ImageExists, Create, Start, Inspect...
		t.Errorf("%d calls seen", len(seen.deadlines))
	}
}

// deadlineClient records the deadline of the context of every call it sees.
type deadlineClient struct {
	dockerapi.Client
	deadlines []time.Time
}

func (c *deadlineClient) record(ctx context.Context) {
	if d, ok := ctx.Deadline(); ok {
		c.deadlines = append(c.deadlines, d)
	} else {
		c.deadlines = append(c.deadlines, time.Time{})
	}
}

func (c *deadlineClient) ImageExists(ctx context.Context, ref string) (bool, error) {
	c.record(ctx)
	return c.Client.ImageExists(ctx, ref)
}

func (c *deadlineClient) Create(ctx context.Context, spec dockerapi.ContainerSpec) (string, error) {
	c.record(ctx)
	return c.Client.Create(ctx, spec)
}

func (c *deadlineClient) Start(ctx context.Context, id string) error {
	c.record(ctx)
	return c.Client.Start(ctx, id)
}

func (c *deadlineClient) Inspect(ctx context.Context, id string) (*dockerapi.ContainerDetails, error) {
	c.record(ctx)
	return c.Client.Inspect(ctx, id)
}

func TestRunNotRan(t *testing.T) {
	for _, tc := range []struct {
		name    string
		noImage bool
		method  string
		err     string
	}{
		{"docker unreachable", false, "*", "dial unix /var/run/docker.sock: connect: no such file or directory"},
		{"image pull fails", true, "Pull", "manifest unknown"},
		{"create fails", false, "Create", "500 Internal Server Error"},
		{"start fails for another reason", false, "Start", "cgroups: cannot allocate"},
		{"inspect fails", false, "Inspect", "connection reset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, fake := newRunner(t)
			if tc.noImage {
				fake = dockerapi.NewFake()
				r.Docker = fake
			}
			fake.SetError(tc.method, errors.New(tc.err))
			res := r.Run(context.Background(), testBinary, "mtg", versionTrial)
			if res.Ran || res.OK || !strings.Contains(res.Reason, tc.err) {
				t.Errorf("Run = %+v; want not ran with a reason that holds %q", res, tc.err)
			}
			if got := r.InFlight(); len(got) != 0 {
				t.Errorf("InFlight = %v", got)
			}
			if tc.name != "docker unreachable" {
				noContainersLeft(t, fake)
			}
		})
	}
}

func TestRunPullsTheRunnerImage(t *testing.T) {
	fake := dockerapi.NewFake()
	r := &Runner{Docker: fake, RunnerImage: testImage, Timeout: 2 * time.Second, Log: discardLog()}
	c, wait := runAsync(t, r, fake, versionTrial)
	_ = fake.AppendLogs(c.ID, "2.2.8")
	_ = fake.Exit(c.ID, 0)
	if res := wait(); !res.Ran || !res.OK {
		t.Errorf("Run = %+v", res)
	}
	var pulled bool
	for _, call := range fake.Calls() {
		if call.Method == "Pull" && call.Target == testImage {
			pulled = true
		}
	}
	if !pulled {
		t.Error("the runner image was not pulled")
	}
}

func TestRunTimeoutKills(t *testing.T) {
	r, fake := newRunner(t)
	r.Timeout = 150 * time.Millisecond
	start := time.Now()
	res := r.Run(context.Background(), testBinary, "mtg", versionTrial)
	if !res.Ran || res.OK || !strings.Contains(res.Reason, "did not exit within") {
		t.Errorf("Run = %+v; want ran, not ok, a timeout reason", res)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("Run took %v", took)
	}
	var forced bool
	for _, call := range fake.Calls() {
		if call.Method == "Remove" && call.Force {
			forced = true
		}
	}
	if !forced {
		t.Error("the container was not removed by force")
	}
	noContainersLeft(t, fake)
}

func TestRunCancelled(t *testing.T) {
	r, fake := newRunner(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result, 1)
	go func() { done <- r.Run(ctx, testBinary, "mtg", versionTrial) }()
	trialContainerSoon(t, fake)
	cancel()
	res := <-done
	if res.Ran || res.OK {
		t.Errorf("Run = %+v; want not ran", res)
	}
	noContainersLeft(t, fake)
}

func trialContainerSoon(t *testing.T, fake *dockerapi.Fake) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if list, _ := fake.List(context.Background(), map[string]string{"postern.role": "trial"}, false); len(list) == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no trial container was started")
}

func TestRunRefusesBadArguments(t *testing.T) {
	r, fake := newRunner(t)
	for _, tc := range []struct{ path, binary string }{
		{"", "mtg"}, {"relative/mtg", "mtg"}, {"/a:b/mtg", "mtg"}, {testBinary, ""}, {testBinary, "a/b"}, {testBinary, "a b"},
	} {
		res := r.Run(context.Background(), tc.path, tc.binary, versionTrial)
		if res.Ran || res.Reason == "" {
			t.Errorf("Run(%q, %q) = %+v; want not ran with a reason", tc.path, tc.binary, res)
		}
	}
	if len(fake.Calls()) != 0 {
		t.Errorf("Docker was called: %v", fake.Calls())
	}
	if res := (&Runner{}).Run(context.Background(), testBinary, "mtg", versionTrial); res.Ran {
		t.Errorf("a runner without Docker ran: %+v", res)
	}
}

func TestClipReason(t *testing.T) {
	long := strings.Repeat("ё", 300)
	got := clip(long, 256)
	if len(got) > 256 || !utf8.ValidString(got) || !strings.HasPrefix(long, got) {
		t.Errorf("clip = %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	if clip("short", 256) != "short" {
		t.Error("clip changed a short string")
	}
}
