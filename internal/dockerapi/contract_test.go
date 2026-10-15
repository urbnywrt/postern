package dockerapi

import (
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// contractEnv parameterises testClientContract.
type contractEnv struct {
	// image is present (or pullable) and has a shell; cmd keeps a container of
	// it running for a while, printing "out" to stdout and "err" to stderr first.
	image string
	cmd   []string
	// name returns a container name that is unique to this run.
	name func(tag string) string
	// labels are carried by every container the contract creates. They must
	// include "postern.test" (any value) and "postern.id" with a value that is
	// unique to this run, so that listing by label finds nothing but our own
	// containers, even on a daemon shared with other work.
	labels map[string]string
	// seedLogs makes the container's output appear. The real daemon needs
	// nothing (the container prints it itself); the Fake has no process.
	seedLogs func(t *testing.T, id string)
}

// testClientContract holds the behaviour every Client must show. It runs
// against the Fake in the unit tests and against a real Docker daemon in the
// integration test, so that the Fake can be trusted to behave like the daemon.
func testClientContract(t *testing.T, c Client, env contractEnv) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)

	t.Run("Ping", func(t *testing.T) {
		v, err := c.Ping(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^1\.[0-9]+$`).MatchString(v) {
			t.Errorf("Ping = %q, want an API version like 1.47", v)
		}
	})

	t.Run("a container that does not exist", func(t *testing.T) {
		ghost := env.name("ghost")
		calls := map[string]func() error{
			"Inspect":          func() error { _, err := c.Inspect(ctx, ghost); return err },
			"Start":            func() error { return c.Start(ctx, ghost) },
			"Stop":             func() error { return c.Stop(ctx, ghost, time.Second) },
			"Remove":           func() error { return c.Remove(ctx, ghost, true) },
			"SetRestartPolicy": func() error { return c.SetRestartPolicy(ctx, ghost, "no") },
			"Logs":             func() error { _, err := c.Logs(ctx, ghost, 10, false); return err },
		}
		for name, call := range calls {
			if err := call(); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: err = %v, want ErrNotFound", name, err)
			}
		}
		if got := listByLabels(t, ctx, c, env.labels, true); len(got) != 0 {
			t.Errorf("List found %d containers before any was created", len(got))
		}
	})

	t.Run("an image that does not exist", func(t *testing.T) {
		ok, err := c.ImageExists(ctx, "postern-test-no-such-image:0")
		if err != nil || ok {
			t.Errorf("ImageExists = %v, %v; want false, nil", ok, err)
		}
	})

	t.Run("lifecycle", func(t *testing.T) {
		if err := c.Pull(ctx, env.image); err != nil {
			t.Fatalf("Pull: %v", err)
		}
		if ok, err := c.ImageExists(ctx, env.image); err != nil || !ok {
			t.Fatalf("ImageExists after Pull = %v, %v; want true, nil", ok, err)
		}

		name := env.name("a")
		labels := maps.Clone(env.labels)
		labels["postern.managed"] = "true"
		labels["postern.role"] = "engine"
		labels["postern.generation"] = "1"
		spec := ContainerSpec{
			Name: name, Image: env.image, Cmd: env.cmd, NetworkMode: "host",
			RestartPolicy: "unless-stopped", Labels: labels,
		}
		id := mustCreate(t, ctx, c, spec)

		// A taken name is a conflict, not a second container.
		if id2, err := c.Create(ctx, spec); err == nil {
			t.Cleanup(func() { removeQuietly(c, id2) })
			t.Fatalf("Create with a taken name succeeded: %s", id2)
		} else {
			wantAPIError(t, err, http.StatusConflict, "")
		}

		// Just created.
		d := mustInspect(t, ctx, c, name)
		if d.ID != id || d.Name != name || d.Image != env.image {
			t.Errorf("Inspect by name = %s %q %q, want %s %q %q", d.ID, d.Name, d.Image, id, name, env.image)
		}
		for _, ref := range []string{id, id[:12]} {
			if got := mustInspect(t, ctx, c, ref); got.ID != id {
				t.Errorf("Inspect(%q).ID = %s, want %s", ref, got.ID, id)
			}
		}
		wantLabels(t, d.Labels, labels)
		if d.State != "created" || d.Status == "" || d.Running || d.ExitCode != 0 || d.RestartPolicy != "unless-stopped" {
			t.Errorf("fresh container = %+v", d)
		}
		if d.Created.IsZero() || !d.StartedAt.IsZero() || !d.FinishedAt.IsZero() {
			t.Errorf("fresh container times: created %v, started %v, finished %v", d.Created, d.StartedAt, d.FinishedAt)
		}
		if got := listByLabels(t, ctx, c, env.labels, false); len(got) != 0 {
			t.Errorf("a container that never ran is listed as running: %+v", got)
		}
		all := listByLabels(t, ctx, c, env.labels, true)
		if len(all) != 1 {
			t.Fatalf("List(all) found %d containers, want 1: %+v", len(all), all)
		}
		if got := all[0]; got.ID != id || got.Name != name || got.State != "created" || got.Image == "" || got.Created.IsZero() {
			t.Errorf("List entry = %+v", got)
		}
		wantLabels(t, all[0].Labels, labels)

		// Running. Starting twice is fine.
		if err := c.Start(ctx, id); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if err := c.Start(ctx, name); err != nil {
			t.Errorf("Start of a running container: %v", err)
		}
		d = mustInspect(t, ctx, c, id)
		if d.State != "running" || !d.Running || d.StartedAt.IsZero() || !d.FinishedAt.IsZero() {
			t.Errorf("running container = %+v", d)
		}
		running := listByLabels(t, ctx, c, env.labels, false)
		if len(running) != 1 || running[0].ID != id || running[0].State != "running" {
			t.Errorf("List(running) = %+v, want our container", running)
		}

		// Label filters: every label must match; an empty value matches any.
		other := maps.Clone(env.labels)
		other["postern.role"] = "egress"
		if got := listByLabels(t, ctx, c, other, true); len(got) != 0 {
			t.Errorf("a filter with a wrong label value matched %+v", got)
		}
		anyValue := map[string]string{"postern.test": "", "postern.id": env.labels["postern.id"]}
		if got := listByLabels(t, ctx, c, anyValue, true); len(got) != 1 {
			t.Errorf("a key-only filter matched %d containers, want 1", len(got))
		}

		// The restart policy can change under a running container.
		if err := c.SetRestartPolicy(ctx, id, "no"); err != nil {
			t.Fatalf("SetRestartPolicy: %v", err)
		}
		if got := mustInspect(t, ctx, c, id).RestartPolicy; got != "no" {
			t.Errorf("RestartPolicy = %q after SetRestartPolicy(no)", got)
		}
		if err := c.SetRestartPolicy(ctx, id, "unless-stopped"); err != nil {
			t.Fatalf("SetRestartPolicy back: %v", err)
		}
		if got := mustInspect(t, ctx, c, id).RestartPolicy; got != "unless-stopped" {
			t.Errorf("RestartPolicy = %q after SetRestartPolicy(unless-stopped)", got)
		}
		if err := c.SetRestartPolicy(ctx, id, ""); err != nil {
			t.Fatalf("SetRestartPolicy(empty): %v", err)
		}
		if got := mustInspect(t, ctx, c, id).RestartPolicy; got != "no" {
			t.Errorf("RestartPolicy = %q after SetRestartPolicy(empty), want no", got)
		}

		// Logs: both streams, as plain text, tail honoured.
		env.seedLogs(t, id)
		var all1 string
		eventually(t, 20*time.Second, "both log lines to appear", func() bool {
			all1 = readLogs(t, ctx, c, id, -1, false)
			return strings.Contains(all1, "out\n") && strings.Contains(all1, "err\n")
		})
		if lines := strings.Count(all1, "\n"); lines != 2 {
			t.Errorf("logs = %q, want exactly two lines", all1)
		}
		if one := readLogs(t, ctx, c, id, 1, false); strings.Count(one, "\n") != 1 || !strings.Contains(all1, one) {
			t.Errorf("tail 1 = %q of %q, want its last line", one, all1)
		}
		if none := readLogs(t, ctx, c, id, 0, false); none != "" {
			t.Errorf("tail 0 = %q, want nothing", none)
		}

		// Stopped. Stopping twice is fine.
		if err := c.Stop(ctx, id, time.Second); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if err := c.Stop(ctx, name, time.Second); err != nil {
			t.Errorf("Stop of a stopped container: %v", err)
		}
		d = mustInspect(t, ctx, c, id)
		if d.State != "exited" || d.Running || d.FinishedAt.IsZero() || d.FinishedAt.Before(d.StartedAt) {
			t.Errorf("stopped container = %+v", d)
		}
		if got := listByLabels(t, ctx, c, env.labels, false); len(got) != 0 {
			t.Errorf("a stopped container is listed as running: %+v", got)
		}
		if got := listByLabels(t, ctx, c, env.labels, true); len(got) != 1 || got[0].State != "exited" {
			t.Errorf("List(all) after Stop = %+v, want our container as exited", got)
		}

		// A stopped container starts again, with a clean exit code.
		if err := c.Start(ctx, id); err != nil {
			t.Fatalf("Start after Stop: %v", err)
		}
		if d = mustInspect(t, ctx, c, id); !d.Running || d.ExitCode != 0 {
			t.Errorf("restarted container = %+v", d)
		}
		if err := c.Stop(ctx, id, time.Second); err != nil {
			t.Fatalf("second Stop: %v", err)
		}

		// Removed, for good.
		if err := c.Remove(ctx, id, false); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if _, err := c.Inspect(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Inspect after Remove: err = %v, want ErrNotFound", err)
		}
		if err := c.Remove(ctx, id, false); !errors.Is(err, ErrNotFound) {
			t.Errorf("second Remove: err = %v, want ErrNotFound", err)
		}
		if got := listByLabels(t, ctx, c, env.labels, true); len(got) != 0 {
			t.Errorf("List(all) after Remove = %+v, want nothing", got)
		}
		// The name is free again.
		id3 := mustCreate(t, ctx, c, spec)
		if id3 == id {
			t.Errorf("a new container got the removed container's ID %s", id)
		}
	})

	t.Run("force remove", func(t *testing.T) {
		labels := maps.Clone(env.labels)
		spec := ContainerSpec{Name: env.name("b"), Image: env.image, Cmd: env.cmd, Labels: labels}
		id := mustCreate(t, ctx, c, spec)
		if err := c.Start(ctx, id); err != nil {
			t.Fatal(err)
		}
		err := c.Remove(ctx, id, false)
		wantAPIError(t, err, http.StatusConflict, "")
		if d := mustInspect(t, ctx, c, id); !d.Running {
			t.Errorf("a refused Remove stopped the container: %+v", d)
		}
		if err := c.Remove(ctx, id, true); err != nil {
			t.Fatalf("forced Remove: %v", err)
		}
		if _, err := c.Inspect(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Inspect after forced Remove: err = %v, want ErrNotFound", err)
		}
	})
}

func mustCreate(t *testing.T, ctx context.Context, c Client, spec ContainerSpec) string {
	t.Helper()
	id, err := c.Create(ctx, spec)
	if err != nil {
		t.Fatalf("Create(%s): %v", spec.Name, err)
	}
	t.Cleanup(func() { removeQuietly(c, id) })
	return id
}

// removeQuietly force-removes a container the test created; it runs in cleanup,
// when the test's context is gone already.
func removeQuietly(c Client, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = c.Remove(ctx, id, true)
}

func mustInspect(t *testing.T, ctx context.Context, c Client, idOrName string) *ContainerDetails {
	t.Helper()
	d, err := c.Inspect(ctx, idOrName)
	if err != nil {
		t.Fatalf("Inspect(%s): %v", idOrName, err)
	}
	return d
}

func listByLabels(t *testing.T, ctx context.Context, c Client, labels map[string]string, all bool) []Container {
	t.Helper()
	got, err := c.List(ctx, labels, all)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return got
}

func readLogs(t *testing.T, ctx context.Context, c Client, id string, tail int, follow bool) string {
	t.Helper()
	rc, err := c.Logs(ctx, id, tail, follow)
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading logs: %v", err)
	}
	return string(b)
}

func wantLabels(t *testing.T, got, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("label %s = %q, want %q (labels: %v)", k, got[k], v, got)
		}
	}
}

func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
