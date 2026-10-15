//go:build integration

package dockerapi

// These tests talk to a real Docker daemon at DefaultSocket and need network
// access to pull the runner image:
//
//	go test -tags integration ./internal/dockerapi/...
//
// Every container they create is named postern-test-<run>-<tag> and labelled
// postern.test=dockerapi, postern.id=itest-<run> with a random <run>, is
// force-removed when its test ends, and is never mistaken for anybody else's
// container: nothing is listed or removed by prefix, only by ID or by the
// run's own label.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func integrationClient(t *testing.T) Client {
	t.Helper()
	c := New("")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := c.Ping(ctx); err != nil {
		t.Fatalf("no usable Docker daemon at %s: %v", DefaultSocket, err)
	}
	return c
}

func integrationRun() string { return strings.ToLower(rand.Text())[:10] }

func integrationLabels(run string) map[string]string {
	return map[string]string{"postern.test": "dockerapi", "postern.id": "itest-" + run}
}

func TestIntegrationContract(t *testing.T) {
	c := integrationClient(t)
	run := integrationRun()
	testClientContract(t, c, contractEnv{
		image:    runnerImage,
		cmd:      []string{"sh", "-c", "echo out; echo err >&2; exec sleep 30"},
		name:     func(tag string) string { return "postern-test-" + run + "-" + tag },
		labels:   integrationLabels(run),
		seedLogs: func(*testing.T, string) {}, // the container prints its own output
	})
}

func TestIntegrationNegotiatedVersion(t *testing.T) {
	c := integrationClient(t)
	v, err := c.Ping(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if lower, err := lowerAPIVersion(v, MaxAPIVersion); err != nil || lower != v {
		t.Errorf("Ping = %q, want a version no newer than %s (%v)", v, MaxAPIVersion, err)
	}
	t.Logf("negotiated Docker API version %s", v)
}

// storedContainer is the part of GET /containers/{id}/json that shows what the
// daemon made of the create request.
type storedContainer struct {
	Config struct {
		User        string
		Entrypoint  []string
		Cmd         []string
		Env         []string
		Labels      map[string]string
		StopTimeout *int
	}
	HostConfig struct {
		Binds          []string
		NetworkMode    string
		RestartPolicy  struct{ Name string }
		ReadonlyRootfs bool
		CapAdd         []string
		CapDrop        []string
		SecurityOpt    []string
		Tmpfs          map[string]string
		Memory         int64
		PidsLimit      *int64
		Ulimits        []Ulimit
		PidMode        string
		LogConfig      struct {
			Type   string
			Config map[string]string
		}
	}
}

func inspectRaw(t *testing.T, ctx context.Context, c Client, id string) storedContainer {
	t.Helper()
	resp, err := c.(*client).call(ctx, http.MethodGet, containerPath(id, "/json"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out storedContainer
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestIntegrationSpecFieldsAreHonoured creates a container with every field of
// ContainerSpec set, as the agent will for its engines, and checks both what
// the daemon stored and how the container behaves.
func TestIntegrationSpecFieldsAreHonoured(t *testing.T) {
	c := integrationClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if err := c.Pull(ctx, runnerImage); err != nil {
		t.Fatal(err)
	}

	run := integrationRun()
	labels := integrationLabels(run)
	labels["postern.managed"] = "true"
	labels["postern.role"] = "engine"
	labels["postern.generation"] = "3"
	spec := ContainerSpec{
		Name:          "postern-test-" + run + "-spec",
		Image:         runnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		PidMode:       "host",
		Entrypoint:    []string{"/bin/sh", "-c"},
		// Six lines of output, whatever the daemon does with the settings.
		// /tmp is a tmpfs; /var/tmp is writable for everyone, so only a
		// read-only root filesystem can make the second write fail.
		Cmd: []string{"id -u; head -c 5 /host-version; echo; echo $POSTERN_TEST; " +
			"touch /tmp/x && echo tmp-ok || echo tmp-bug; " +
			"touch /var/tmp/x 2>/dev/null && echo ro-bug || echo ro-ok; " +
			"echo nofile-$(ulimit -Sn)-$(ulimit -Hn); " +
			"exec sleep 30"},
		Env:         []string{"POSTERN_TEST=hello"},
		Binds:       []string{"/proc/version:/host-version:ro"},
		CapAdd:      []string{"NET_BIND_SERVICE"},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels:      labels,
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=16m"},
		ReadOnly:    true,
		MemoryBytes: 256 << 20,
		PidsLimit:   256,
		Ulimits:     []Ulimit{{Name: "nofile", Soft: 1024, Hard: 2048}},
		LogMaxSize:  "5m",
		LogMaxFile:  2,
		StopTimeout: new(35),
	}
	id := mustCreate(t, ctx, c, spec)

	got := inspectRaw(t, ctx, c, id)
	for name, pair := range map[string][2]any{
		"User":             {got.Config.User, spec.User},
		"Entrypoint":       {got.Config.Entrypoint, spec.Entrypoint},
		"Cmd":              {got.Config.Cmd, spec.Cmd},
		"Binds":            {got.HostConfig.Binds, spec.Binds},
		"NetworkMode":      {got.HostConfig.NetworkMode, spec.NetworkMode},
		"RestartPolicy":    {got.HostConfig.RestartPolicy.Name, spec.RestartPolicy},
		"ReadonlyRootfs":   {got.HostConfig.ReadonlyRootfs, spec.ReadOnly},
		"CapAdd":           {got.HostConfig.CapAdd, spec.CapAdd},
		"CapDrop":          {got.HostConfig.CapDrop, spec.CapDrop},
		"Tmpfs":            {got.HostConfig.Tmpfs, spec.Tmpfs},
		"Memory":           {got.HostConfig.Memory, spec.MemoryBytes},
		"Ulimits":          {got.HostConfig.Ulimits, spec.Ulimits},
		"PidMode":          {got.HostConfig.PidMode, spec.PidMode},
		"LogConfig.Type":   {got.HostConfig.LogConfig.Type, "json-file"},
		"LogConfig.Config": {got.HostConfig.LogConfig.Config, map[string]string{"max-size": "5m", "max-file": "2"}},
	} {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			t.Errorf("%s stored as %#v, want %#v", name, pair[0], pair[1])
		}
	}
	if p := got.HostConfig.PidsLimit; p == nil || *p != spec.PidsLimit {
		t.Errorf("PidsLimit stored as %v, want %d", p, spec.PidsLimit)
	}
	if p := got.Config.StopTimeout; p == nil {
		t.Errorf("StopTimeout is not stored, want %d", *spec.StopTimeout)
	} else if *p != *spec.StopTimeout {
		t.Errorf("StopTimeout stored as %d, want %d", *p, *spec.StopTimeout)
	}
	// The daemon adds to these: the image's own environment, and for host
	// networking it appends label=disable to the security options.
	if !contains(got.Config.Env, "POSTERN_TEST=hello") {
		t.Errorf("Env stored as %v, want it to include POSTERN_TEST=hello", got.Config.Env)
	}
	if !contains(got.HostConfig.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("SecurityOpt stored as %v, want it to include no-new-privileges:true", got.HostConfig.SecurityOpt)
	}
	wantLabels(t, got.Config.Labels, labels)

	// And the container really runs under those settings.
	if err := c.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	var out string
	eventually(t, 20*time.Second, "the container's output", func() bool {
		out = readLogs(t, ctx, c, id, -1, false)
		return strings.Count(out, "\n") >= 6
	})
	for _, want := range []string{"65534\n", "Linux\n", "hello\n", "tmp-ok\n", "ro-ok\n", "nofile-1024-2048\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("container output %q lacks %q", out, want)
		}
	}
	if d := mustInspect(t, ctx, c, id); !d.Running {
		t.Errorf("the container is not running: %+v", d)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestIntegrationFollowLogs follows a live container's logs: output that appears
// after the call arrives through the demultiplexer, and cancelling stops it.
func TestIntegrationFollowLogs(t *testing.T) {
	c := integrationClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if err := c.Pull(ctx, runnerImage); err != nil {
		t.Fatal(err)
	}
	run := integrationRun()
	id := mustCreate(t, ctx, c, ContainerSpec{
		Name: "postern-test-" + run + "-follow", Image: runnerImage, Labels: integrationLabels(run),
		Cmd: []string{"sh", "-c", "echo before; sleep 5; echo late-out; echo late-err >&2; exec sleep 30"},
	})
	if err := c.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, "the first line", func() bool {
		return strings.Contains(readLogs(t, ctx, c, id, -1, false), "before\n")
	})

	followCtx, stop := context.WithCancel(ctx)
	defer stop()
	rc, err := c.Logs(followCtx, id, 0, true) // no history, only what comes next
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()

	lines := make(chan string, 64)
	var scanErr error
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(rc)
		for sc.Scan() {
			lines <- sc.Text()
		}
		scanErr = sc.Err()
	}()
	got := map[string]bool{}
	timeout := time.After(30 * time.Second)
	for !got["late-out"] || !got["late-err"] {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the stream ended early, got %v", got)
			}
			if line == "before" {
				t.Fatal("tail=0 replayed history")
			}
			got[line] = true
		case <-timeout:
			t.Fatalf("timed out, got %v", got)
		}
	}

	stop()
	select {
	case <-drain(lines):
	case <-time.After(10 * time.Second):
		t.Fatal("the stream did not end after the context was cancelled")
	}
	if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
		t.Errorf("reading after cancel: %v", scanErr)
	}
}

// drain returns a channel that closes once c has been closed and emptied.
func drain(c <-chan string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range c {
		}
	}()
	return done
}

// TestIntegrationCreateWithAMissingImage checks the promise of Client.Create: an
// image that is not present is ErrNotFound, and nothing is created.
func TestIntegrationCreateWithAMissingImage(t *testing.T) {
	c := integrationClient(t)
	run := integrationRun()
	name := "postern-test-" + run + "-noimage"
	id, err := c.Create(t.Context(), ContainerSpec{Name: name, Image: "postern-test-no-such-image:0", Labels: integrationLabels(run)})
	if err == nil {
		removeQuietly(c, id)
		t.Fatalf("Create with an image that is not there succeeded: %s", id)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want it to match ErrNotFound", err)
	}
	if _, err := c.Inspect(t.Context(), name); !errors.Is(err, ErrNotFound) {
		t.Errorf("a container named %s exists after the failed Create (Inspect: %v)", name, err)
	}
}

func TestIntegrationPullOfAMissingImage(t *testing.T) {
	c := integrationClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	err := c.Pull(ctx, "alpine:postern-test-no-such-tag")
	if err == nil {
		t.Fatal("Pull of a tag that does not exist succeeded")
	}
	t.Logf("the daemon says: %v", err)
}
