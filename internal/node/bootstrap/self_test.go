package bootstrap

import (
	"errors"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/dockerapi"
)

func TestCheckEnvironment(t *testing.T) {
	h := newHarness(t)
	if err := h.boot().checkEnvironment(t.Context()); err != nil {
		t.Fatalf("a good container: %v", err)
	}
	if strings.Contains(h.logs.String(), "level=WARN") {
		t.Errorf("warnings for a good container:\n%s", h.logs)
	}
}

func TestCheckEnvironmentRefuses(t *testing.T) {
	for name, c := range map[string]struct {
		prep func(h *harness)
		want string
	}{
		"not root":      {func(h *harness) { h.opt.Getuid = func() int { return 1 } }, "root"},
		"relative home": {func(h *harness) { h.opt.Home = "opt/postern" }, "absolute"},
		"unclean home":  {func(h *harness) { h.opt.Home = h.home + "/" }, "absolute"},
		"no docker":     {func(h *harness) { h.docker.SetError("Ping", errors.New("no socket")) }, "Docker does not answer"},
		"userns": {func(h *harness) {
			h.docker.SetInfo(dockerapi.Info{SecurityOptions: []string{"name=seccomp,profile=builtin", "name=userns"}})
		}, "Docker remaps user namespaces; the node needs a daemon without userns-remap"},
		"home from elsewhere": {func(h *harness) {
			h.setMounts(dockerapi.MountPoint{Type: "bind", Source: "/srv/node", Destination: h.home, RW: true})
		}, "-v " + "HOME:HOME"},
		"home not mounted": {func(h *harness) {
			h.setMounts(dockerapi.MountPoint{Type: "bind", Source: dockerSocket, Destination: dockerSocket, RW: true})
		}, "is not mounted from the host"},
		"home read-only": {func(h *harness) {
			h.setMounts(dockerapi.MountPoint{Type: "bind", Source: h.home, Destination: h.home})
		}, "read-only"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			c.prep(h)
			err := h.boot().checkEnvironment(t.Context())
			want := strings.ReplaceAll(c.want, "HOME", h.home)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("checkEnvironment = %v, want %q", err, want)
			}
		})
	}
}

func TestCheckEnvironmentWarns(t *testing.T) {
	h := newHarness(t)
	h.writeMountinfo("")
	if err := h.boot().checkEnvironment(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.wantLog("cannot find the own container")

	h = newHarness(t)
	if err := h.docker.SetRestartPolicy(t.Context(), h.ownID, "no"); err != nil {
		t.Fatal(err)
	}
	h.setMounts(dockerapi.MountPoint{Type: "bind", Source: h.home, Destination: h.home, RW: true})
	if err := h.boot().checkEnvironment(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.wantLog("--restart unless-stopped")
	h.wantLog("the Docker socket is not mounted")

	h = newHarness(t)
	h.docker.SetError("Inspect", dockerapi.ErrNotFound)
	if err := h.boot().checkEnvironment(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.wantLog("cannot inspect the own container")
}
