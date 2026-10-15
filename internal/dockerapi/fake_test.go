package dockerapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFakeBehavesLikeDocker(t *testing.T) {
	f := NewFake()
	testClientContract(t, f, contractEnv{
		image: runnerImage,
		cmd:   []string{"sleep", "30"},
		name:  func(tag string) string { return "postern-test-fake-" + tag },
		labels: map[string]string{
			"postern.test": "fake",
			"postern.id":   "fake-run",
		},
		seedLogs: func(t *testing.T, id string) {
			if err := f.AppendLogs(id, "out\nerr\n"); err != nil {
				t.Fatal(err)
			}
		},
	})
}

// fakeClock is a settable clock for the Fake.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestFakePing(t *testing.T) {
	got, err := NewFake().Ping(t.Context())
	if err != nil || got != MaxAPIVersion {
		t.Errorf("Ping = %q, %v; want %q", got, err, MaxAPIVersion)
	}
}

func TestFakeRecordsCalls(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	spec := ContainerSpec{Name: "edge", Image: "img", Labels: map[string]string{"k": "v"}}

	id, err := f.Create(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Start(ctx, "edge")
	_, _ = f.List(ctx, map[string]string{"k": "v"}, true)
	_, _ = f.Inspect(ctx, id)
	_ = f.SetRestartPolicy(ctx, "edge", "no")
	_ = f.Stop(ctx, "edge", 5*time.Second)
	rc, _ := f.Logs(ctx, "edge", 20, true)
	_ = rc.Close()
	_, _ = f.ImageExists(ctx, "img")
	_ = f.Pull(ctx, "img")
	_ = f.Remove(ctx, "edge", true)
	_, _ = f.Ping(ctx)
	_ = f.Start(ctx, "ghost") // failed calls are recorded too

	want := []Call{
		{Method: "Create", Target: "edge", Spec: &spec},
		{Method: "Start", Target: "edge"},
		{Method: "List", Labels: map[string]string{"k": "v"}, All: true},
		{Method: "Inspect", Target: id},
		{Method: "SetRestartPolicy", Target: "edge", Policy: "no"},
		{Method: "Stop", Target: "edge", Timeout: 5 * time.Second},
		{Method: "Logs", Target: "edge", Tail: 20, Follow: true},
		{Method: "ImageExists", Target: "img"},
		{Method: "Pull", Target: "img"},
		{Method: "Remove", Target: "edge", Force: true},
		{Method: "Ping"},
		{Method: "Start", Target: "ghost"},
	}
	if got := f.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}

	f.ResetCalls()
	if got := f.Calls(); len(got) != 0 {
		t.Errorf("Calls() after ResetCalls = %+v", got)
	}
	_ = f.Pull(ctx, "other")
	if got := f.Calls(); len(got) != 1 || got[0].Method != "Pull" {
		t.Errorf("Calls() = %+v, want only the Pull after ResetCalls", got)
	}
}

func TestFakeCallsAreCopies(t *testing.T) {
	f := NewFake()
	spec := ContainerSpec{
		Name: "edge", Image: "img", Cmd: []string{"a"}, Labels: map[string]string{"k": "v"}, StopTimeout: new(35),
	}
	if _, err := f.Create(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	// Changing the caller's spec afterwards does not rewrite history.
	spec.Cmd[0] = "changed"
	spec.Labels["k"] = "changed"
	*spec.StopTimeout = 1
	calls := f.Calls()
	if calls[0].Spec.Cmd[0] != "a" || calls[0].Spec.Labels["k"] != "v" || *calls[0].Spec.StopTimeout != 35 {
		t.Errorf("recorded spec follows the caller's slice, map and pointer: %+v", calls[0].Spec)
	}
	// Neither does changing a returned snapshot.
	calls[0].Method = "Mangled"
	calls[0].Spec.Cmd[0] = "mangled"
	*calls[0].Spec.StopTimeout = 99
	if again := f.Calls(); again[0].Method != "Create" || again[0].Spec.Cmd[0] != "a" || *again[0].Spec.StopTimeout != 35 {
		t.Errorf("Calls() hands out its internal state: %+v", again[0])
	}
}

func TestFakeSpecIsStoredByValue(t *testing.T) {
	f := NewFake()
	spec := engineSpec()
	if _, err := f.Create(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	spec.Env[0] = "changed"
	spec.Labels["postern.id"] = "changed"
	spec.Tmpfs["/tmp"] = "changed"
	spec.Ulimits[0].Soft = 1
	*spec.StopTimeout = 1

	got, ok := f.Spec(spec.Name)
	if !ok {
		t.Fatal("Spec: no such container")
	}
	if want := engineSpec(); !reflect.DeepEqual(got, want) {
		t.Errorf("Spec = %+v\nwant %+v", got, want)
	}
	got.Binds[0] = "mangled"
	got.Labels["postern.id"] = "mangled"
	got.Ulimits[0].Hard = 99
	*got.StopTimeout = 99
	if again, _ := f.Spec(spec.Name); !reflect.DeepEqual(again, engineSpec()) {
		t.Errorf("Spec hands out its internal state: %+v", again)
	}
	c, _ := f.List(t.Context(), nil, true)
	c[0].Labels["postern.id"] = "mangled"
	if d, _ := f.Inspect(t.Context(), spec.Name); d.Labels["postern.id"] != "abc123" {
		t.Errorf("List hands out the internal label map: %v", d.Labels)
	}
	if _, ok := f.Spec("ghost"); ok {
		t.Error("Spec found a container that does not exist")
	}
}

func TestFakeSetError(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	boom := errors.New("boom")

	f.SetError("Create", boom)
	if _, err := f.Create(ctx, ContainerSpec{Name: "a", Image: "img"}); !errors.Is(err, boom) {
		t.Fatalf("Create err = %v, want the injected error", err)
	}
	if got, _ := f.List(ctx, nil, true); len(got) != 0 {
		t.Errorf("a failed Create left a container behind: %+v", got)
	}
	// Other methods are unaffected, and the failed call was recorded.
	if _, err := f.Ping(ctx); err != nil {
		t.Errorf("Ping err = %v", err)
	}
	if calls := f.Calls(); len(calls) == 0 || calls[0].Method != "Create" {
		t.Errorf("the failed Create is not in Calls(): %+v", calls)
	}

	f.SetError("Create", nil)
	if _, err := f.Create(ctx, ContainerSpec{Name: "a", Image: "img"}); err != nil {
		t.Errorf("Create after clearing the error: %v", err)
	}

	f.SetError("*", boom)
	for name, err := range map[string]error{
		"Ping":  func() error { _, err := f.Ping(ctx); return err }(),
		"List":  func() error { _, err := f.List(ctx, nil, true); return err }(),
		"Start": f.Start(ctx, "a"),
		"Pull":  f.Pull(ctx, "img"),
	} {
		if !errors.Is(err, boom) {
			t.Errorf("%s with the wildcard error set: err = %v", name, err)
		}
	}
	f.SetError("*", nil)
	if err := f.Start(ctx, "a"); err != nil {
		t.Errorf("Start after clearing the wildcard error: %v", err)
	}

	// A specific error wins over the wildcard.
	other := errors.New("other")
	f.SetError("*", boom)
	f.SetError("Stop", other)
	if err := f.Stop(ctx, "a", 0); !errors.Is(err, other) {
		t.Errorf("Stop err = %v, want the method's own error", err)
	}
}

func TestFakeHonoursContext(t *testing.T) {
	f := NewFake()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.Ping(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Ping err = %v, want context.Canceled", err)
	}
	if _, err := f.Create(ctx, ContainerSpec{Name: "a", Image: "img"}); !errors.Is(err, context.Canceled) {
		t.Errorf("Create err = %v, want context.Canceled", err)
	}
	if got, _ := f.List(t.Context(), nil, true); len(got) != 0 {
		t.Errorf("a cancelled Create left a container behind: %+v", got)
	}
}

func TestFakeTimestampsFollowTheClock(t *testing.T) {
	clock := newFakeClock()
	f := NewFake()
	f.Now = clock.Now
	ctx := t.Context()
	t0 := clock.Now()

	id, err := f.Create(ctx, ContainerSpec{Name: "a", Image: "img"})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Minute)
	if err := f.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Hour)
	if err := f.Stop(ctx, id, 0); err != nil {
		t.Fatal(err)
	}
	d, err := f.Inspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	wantDetails(t, d, ContainerDetails{
		Container:     Container{ID: id, Name: "a", Image: "img", State: "exited", Status: d.Status, Created: t0},
		RestartPolicy: "no",
		StartedAt:     t0.Add(time.Minute),
		FinishedAt:    t0.Add(time.Minute + time.Hour),
	})
	list, _ := f.List(ctx, nil, true)
	if len(list) != 1 || !list[0].Created.Equal(t0) {
		t.Errorf("List = %+v, want Created %v", list, t0)
	}
}

// Inspect reports the bind mounts of the spec, as the daemon's HostConfig.Binds
// does, and a copy of them.
func TestFakeInspectBinds(t *testing.T) {
	f := NewFake()
	f.AddImage("img")
	ctx := t.Context()
	binds := []string{"/opt/postern/data/artifacts/telemt/3.5.13/amd64/telemt:/opt/engine/telemt:ro"}
	id, err := f.Create(ctx, ContainerSpec{Name: "a", Image: "img", Binds: binds})
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.Inspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.Binds, binds) {
		t.Errorf("Binds = %q, want %q", d.Binds, binds)
	}
	d.Binds[0] = "changed"
	if d2, _ := f.Inspect(ctx, id); d2.Binds[0] != binds[0] {
		t.Error("Inspect handed out the fake's own slice")
	}
	if d, _ := f.Inspect(ctx, "a"); d.Binds == nil {
		t.Error("Binds = nil after a Create with binds")
	}
}

func TestFakeStartAndStopStates(t *testing.T) {
	clock := newFakeClock()
	f := NewFake()
	f.Now = clock.Now
	ctx := t.Context()
	id, _ := f.Create(ctx, ContainerSpec{Name: "a", Image: "img", RestartPolicy: "always"})

	if err := f.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.Inspect(ctx, id); !d.Running || d.State != "running" || d.RestartPolicy != "always" {
		t.Errorf("after Start: %+v", d)
	}
	// A second Start must not move StartedAt.
	started, _ := f.Inspect(ctx, id)
	clock.Advance(time.Hour)
	_ = f.Start(ctx, id)
	if again, _ := f.Inspect(ctx, id); !again.StartedAt.Equal(started.StartedAt) {
		t.Errorf("StartedAt moved from %v to %v on a second Start", started.StartedAt, again.StartedAt)
	}
	// A second Stop must not move FinishedAt.
	_ = f.Stop(ctx, id, time.Second)
	stopped, _ := f.Inspect(ctx, id)
	clock.Advance(time.Hour)
	_ = f.Stop(ctx, id, time.Second)
	if again, _ := f.Inspect(ctx, id); !again.FinishedAt.Equal(stopped.FinishedAt) {
		t.Errorf("FinishedAt moved from %v to %v on a second Stop", stopped.FinishedAt, again.FinishedAt)
	}
}

func TestFakeExit(t *testing.T) {
	clock := newFakeClock()
	f := NewFake()
	f.Now = clock.Now
	ctx := t.Context()
	id, _ := f.Create(ctx, ContainerSpec{Name: "a", Image: "img"})

	if err := f.Exit("a", 1); err == nil {
		t.Error("Exit of a container that is not running succeeded")
	}
	if err := f.Exit("ghost", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("Exit of a missing container: err = %v, want ErrNotFound", err)
	}
	_ = f.Start(ctx, id)
	clock.Advance(time.Minute)
	f.ResetCalls()
	if err := f.Exit("a", 3); err != nil {
		t.Fatal(err)
	}
	if calls := f.Calls(); len(calls) != 0 {
		t.Errorf("Exit is not a Client call but was recorded: %+v", calls)
	}
	d, _ := f.Inspect(ctx, id)
	if d.Running || d.State != "exited" || d.ExitCode != 3 || !d.FinishedAt.Equal(clock.Now()) {
		t.Errorf("after Exit(3): %+v", d)
	}
	if got, _ := f.List(ctx, nil, false); len(got) != 0 {
		t.Errorf("a crashed container is listed as running: %+v", got)
	}
	// It can be started again, which resets the exit code.
	_ = f.Start(ctx, id)
	if d, _ := f.Inspect(ctx, id); !d.Running || d.ExitCode != 0 {
		t.Errorf("after restart: %+v", d)
	}
}

func TestFakeLogs(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	id, _ := f.Create(ctx, ContainerSpec{Name: "a", Image: "img"})
	if got := mustReadLogs(t, f, id, -1, false); got != "" {
		t.Errorf("logs of a container without output = %q", got)
	}
	if err := f.AppendLogs("a", "one\ntwo\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.AppendLogs(id, "three\nfour"); err != nil { // the last line is unfinished
		t.Fatal(err)
	}
	if err := f.AppendLogs("ghost", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("AppendLogs to a missing container: err = %v, want ErrNotFound", err)
	}
	for _, tc := range []struct {
		tail int
		want string
	}{
		{-1, "one\ntwo\nthree\nfour"},
		{100, "one\ntwo\nthree\nfour"},
		{4, "one\ntwo\nthree\nfour"},
		{2, "three\nfour"},
		{1, "four"},
		{0, ""},
	} {
		if got := mustReadLogs(t, f, id, tc.tail, false); got != tc.want {
			t.Errorf("tail %d = %q, want %q", tc.tail, got, tc.want)
		}
	}
	// Following ends at the end of what is buffered.
	if got := mustReadLogs(t, f, id, 1, true); got != "four" {
		t.Errorf("follow = %q", got)
	}
	if got := f.Calls(); !got[len(got)-1].Follow {
		t.Errorf("follow flag not recorded: %+v", got[len(got)-1])
	}
	if _, err := f.Logs(ctx, "ghost", 1, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("Logs of a missing container: err = %v", err)
	}
}

func mustReadLogs(t *testing.T, c Client, id string, tail int, follow bool) string {
	t.Helper()
	return readLogs(t, t.Context(), c, id, tail, follow)
}

func TestFakeIDsAndLookup(t *testing.T) {
	f := NewFake()
	ctx := t.Context()

	// 17 containers: by the pigeonhole principle two IDs share a first hex digit,
	// so both a unique and an ambiguous one-digit prefix get exercised.
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	ids := make([]string, 17)
	byFirstDigit := map[byte][]int{}
	for i := range ids {
		id, err := f.Create(ctx, ContainerSpec{Name: fmt.Sprintf("c%d", i), Image: "img"})
		if err != nil {
			t.Fatal(err)
		}
		if !hex64.MatchString(id) {
			t.Fatalf("ID %q is not 64 hex digits", id)
		}
		ids[i] = id
		byFirstDigit[id[0]] = append(byFirstDigit[id[0]], i)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("ID %s was handed out twice", id)
		}
		seen[id] = true
	}
	// IDs are reproducible, so tests can rely on them across runs.
	if id, _ := NewFake().Create(ctx, ContainerSpec{Name: "x", Image: "img"}); id != ids[0] {
		t.Errorf("the first container of a new Fake got ID %s, want %s", id, ids[0])
	}

	sawAmbiguous, sawUnique := false, false
	for digit, members := range byFirstDigit {
		d, err := f.Inspect(ctx, string(digit))
		if len(members) == 1 {
			sawUnique = true
			if err != nil || d.ID != ids[members[0]] {
				t.Errorf("Inspect(%q) = %v, %v; want container c%d", string(digit), d, err, members[0])
			}
			continue
		}
		sawAmbiguous = true
		wantAPIError(t, err, http.StatusBadRequest, "Multiple IDs")
		if errors.Is(err, ErrNotFound) {
			t.Errorf("an ambiguous prefix %q matches ErrNotFound", string(digit))
		}
	}
	if !sawAmbiguous || !sawUnique {
		t.Errorf("test data did not cover both an ambiguous (%v) and a unique (%v) prefix", sawAmbiguous, sawUnique)
	}

	for _, ref := range []string{"c3", "/c3", ids[3], ids[3][:12]} {
		d, err := f.Inspect(ctx, ref)
		if err != nil || d.ID != ids[3] {
			t.Errorf("Inspect(%q) = %+v, %v; want container c3", ref, d, err)
		}
	}
	if _, err := f.Inspect(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Inspect(nope): err = %v, want ErrNotFound", err)
	}
	if _, err := f.Inspect(ctx, ""); !errors.Is(err, errEmptyID) {
		t.Errorf("Inspect(empty): err = %v, want errEmptyID", err)
	}
	// Names do not match as prefixes.
	if _, err := f.Inspect(ctx, "c"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Inspect(c): err = %v, want ErrNotFound", err)
	}
}

func TestFakeNames(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	idA, err := f.Create(ctx, ContainerSpec{Image: "img"})
	if err != nil {
		t.Fatal(err)
	}
	idB, _ := f.Create(ctx, ContainerSpec{Image: "img"})
	a, _ := f.Inspect(ctx, idA)
	b, _ := f.Inspect(ctx, idB)
	if a.Name == "" || b.Name == "" || a.Name == b.Name {
		t.Errorf("auto names %q and %q: want two distinct, non-empty names", a.Name, b.Name)
	}
	if _, err := f.Create(ctx, ContainerSpec{Name: "/" + a.Name, Image: "img"}); err == nil {
		t.Error("Create accepted a name that is taken (given with a leading slash)")
	} else {
		wantAPIError(t, err, http.StatusConflict, "already in use")
	}
}

func TestFakeRejectsBadSpecs(t *testing.T) {
	f := NewFake()
	for name, spec := range map[string]ContainerSpec{
		"no image":       {Name: "x"},
		"bad restart":    {Name: "x", Image: "img", RestartPolicy: "sometimes"},
		"bad restart v2": {Name: "x", Image: "img", RestartPolicy: "on-failure:3"},
	} {
		if _, err := f.Create(t.Context(), spec); err == nil {
			t.Errorf("%s: Create succeeded", name)
		}
	}
	if list, _ := f.List(t.Context(), nil, true); len(list) != 0 {
		t.Errorf("rejected specs left containers behind: %+v", list)
	}
	id, _ := f.Create(t.Context(), ContainerSpec{Name: "ok", Image: "img"})
	if err := f.SetRestartPolicy(t.Context(), id, "sometimes"); err == nil {
		t.Error("SetRestartPolicy accepted an unknown policy")
	}
}

func TestFakeListOrderAndFilters(t *testing.T) {
	clock := newFakeClock()
	f := NewFake()
	f.Now = clock.Now
	ctx := t.Context()
	mk := func(name string, labels map[string]string, start bool) string {
		id, err := f.Create(ctx, ContainerSpec{Name: name, Image: "img", Labels: labels})
		if err != nil {
			t.Fatal(err)
		}
		if start {
			if err := f.Start(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	// All created at the same instant, as under a frozen test clock.
	mk("edge-g1", map[string]string{"postern.role": "edge", "postern.managed": "true"}, true)
	mk("eng-1", map[string]string{"postern.role": "engine", "postern.managed": "true"}, true)
	mk("eng-2", map[string]string{"postern.role": "engine", "postern.managed": "true"}, false)
	mk("other", nil, true)

	names := func(labels map[string]string, all bool) []string {
		got, err := f.List(ctx, labels, all)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, c := range got {
			out = append(out, c.Name)
		}
		return out
	}
	for _, tc := range []struct {
		name   string
		labels map[string]string
		all    bool
		want   []string
	}{
		{"everything, newest first", nil, true, []string{"other", "eng-2", "eng-1", "edge-g1"}},
		{"running only", nil, false, []string{"other", "eng-1", "edge-g1"}},
		{"by role", map[string]string{"postern.role": "engine"}, true, []string{"eng-2", "eng-1"}},
		{"by role, running", map[string]string{"postern.role": "engine"}, false, []string{"eng-1"}},
		{"two labels", map[string]string{"postern.managed": "true", "postern.role": "edge"}, true, []string{"edge-g1"}},
		{"key only", map[string]string{"postern.managed": ""}, true, []string{"eng-2", "eng-1", "edge-g1"}},
		{"value mismatch", map[string]string{"postern.role": "egress"}, true, []string{}},
		{"missing key", map[string]string{"nope": ""}, true, []string{}},
		{"key only, on the role", map[string]string{"postern.role": ""}, true, []string{"eng-2", "eng-1", "edge-g1"}},
	} {
		if got := names(tc.labels, tc.all); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	// An earlier container is listed after a later one even when the clock moves.
	clock.Advance(time.Minute)
	mk("late", nil, false)
	if got := names(nil, true); got[0] != "late" {
		t.Errorf("newest container is not first: %v", got)
	}
}

func TestFakeImages(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	if ok, err := f.ImageExists(ctx, "img:1"); err != nil || ok {
		t.Fatalf("ImageExists on a new Fake = %v, %v", ok, err)
	}
	f.AddImage("img:1", "img:2")
	for _, ref := range []string{"img:1", "img:2"} {
		if ok, _ := f.ImageExists(ctx, ref); !ok {
			t.Errorf("ImageExists(%q) = false after AddImage", ref)
		}
	}
	if err := f.Pull(ctx, "img:3"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.ImageExists(ctx, "img:3"); !ok {
		t.Error("ImageExists = false after Pull")
	}
	if err := f.Pull(ctx, ""); err == nil {
		t.Error("Pull accepted an empty reference")
	}
	if _, err := f.ImageExists(ctx, ""); err == nil {
		t.Error("ImageExists accepted an empty reference")
	}
	// Create does not insist on the image being pulled: tests that do not care
	// about images need not seed them.
	if _, err := f.Create(ctx, ContainerSpec{Name: "x", Image: "never-pulled"}); err != nil {
		t.Errorf("Create with an image that was never pulled: %v", err)
	}
}

func TestFakeConcurrentUse(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("c%d", i)
			id, err := f.Create(ctx, ContainerSpec{Name: name, Image: "img", Labels: map[string]string{"k": "v"}})
			if err != nil {
				t.Error(err)
				return
			}
			_ = f.Start(ctx, id)
			_, _ = f.List(ctx, map[string]string{"k": "v"}, false)
			_, _ = f.Inspect(ctx, name)
			_ = f.AppendLogs(id, "x\n")
			rc, err := f.Logs(ctx, id, -1, false)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, rc)
			_ = rc.Close()
			_ = f.Stop(ctx, id, 0)
			_ = f.Remove(ctx, id, false)
			_ = f.Calls()
		}()
	}
	wg.Wait()
	if got, _ := f.List(ctx, nil, true); len(got) != 0 {
		t.Errorf("%d containers left after everything was removed", len(got))
	}
	// Create, Start, List, Inspect, Logs, Stop and Remove, per goroutine; the
	// final List above is the one extra call.
	if n, want := len(f.Calls()), 20*7+1; n != want {
		t.Errorf("%d calls recorded, want %d", n, want)
	}
}

func TestFakeErrorsAreAPIErrors(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	err := f.Start(ctx, "ghost")
	wantAPIError(t, err, http.StatusNotFound, "No such container: ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Error("a missing container does not match ErrNotFound")
	}
	id, _ := f.Create(ctx, ContainerSpec{Name: "a", Image: "img"})
	_ = f.Start(ctx, id)
	err = f.Remove(ctx, "a", false)
	wantAPIError(t, err, http.StatusConflict, "running")
	if !strings.Contains(err.Error(), `remove container "a"`) {
		t.Errorf("error %q does not say what was attempted", err)
	}
}

func TestFakeInfoAndMounts(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	info, err := f.Info(ctx)
	if err != nil || len(info.SecurityOptions) != 0 {
		t.Fatalf("Info = %+v, %v; want no options", info, err)
	}
	f.SetInfo(Info{SecurityOptions: []string{"name=userns"}})
	if info, _ = f.Info(ctx); !slices.Equal(info.SecurityOptions, []string{"name=userns"}) {
		t.Errorf("Info = %+v after SetInfo", info)
	}
	id, err := f.Create(ctx, ContainerSpec{Name: "a", Image: "alpine", Privileged: true})
	if err != nil {
		t.Fatal(err)
	}
	if spec, _ := f.Spec("a"); !spec.Privileged {
		t.Error("the spec lost Privileged")
	}
	if err := f.SetMounts("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetMounts on a missing container = %v, want ErrNotFound", err)
	}
	m := MountPoint{Type: "bind", Source: "/opt/postern", Destination: "/opt/postern", RW: true}
	if err := f.SetMounts(id, m); err != nil {
		t.Fatal(err)
	}
	d, err := f.Inspect(ctx, "a")
	if err != nil || !slices.Equal(d.Mounts, []MountPoint{m}) {
		t.Fatalf("Inspect = %+v, %v; want the mounts set", d, err)
	}
}
