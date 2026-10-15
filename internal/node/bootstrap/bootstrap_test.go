package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/dockerapi"
)

const testRunner = "alpine:test"

// syncBuffer is a bytes.Buffer for a logger.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// harness is a node container without root and without Docker: a temporary
// POSTERN_HOME, a fake procfs, an image directory and a Fake daemon in which
// the own container exists with the right mounts.
type harness struct {
	t         *testing.T
	home      string
	proc      string
	image     string
	docker    *dockerapi.Fake
	ownID     string
	logs      *syncBuffer
	exec      []string // path, then argv, of the exec
	execEnv   []string
	sleeps    []time.Duration
	helperRC  int    // exit code of the sysctl helpers
	helperSay string // what they print
	opt       Options
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, logs: &syncBuffer{}, docker: dockerapi.NewFake()}
	h.home = filepath.Join(t.TempDir(), "postern")
	h.proc = t.TempDir()
	h.image = t.TempDir()
	mustMkdir(t, h.home)
	h.writeImage("binary of 0.5.0")
	mustWrite(t, filepath.Join(h.image, "postern-node.minisig"), "untrusted comment: x\n")
	mustWrite(t, filepath.Join(h.image, "launcher.sh"), "#!/bin/sh\n# launcher of the image\n")
	h.setProc("", "0")

	ctx := t.Context()
	id, err := h.docker.Create(ctx, dockerapi.ContainerSpec{Name: "postern-agent", Image: "postern-node:0.5.0", RestartPolicy: "unless-stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.docker.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	h.ownID = id
	h.setMounts(dockerapi.MountPoint{Type: "bind", Source: h.home, Destination: h.home, RW: true},
		dockerapi.MountPoint{Type: "bind", Source: dockerSocket, Destination: dockerSocket, RW: true})
	h.writeMountinfo(id)
	h.docker.AddImage(testRunner)

	h.opt = Options{
		Home:        h.home,
		Env:         []string{"PATH=/usr/bin", EnvHome + "=" + h.home},
		Binary:      filepath.Join(h.image, "postern-node"),
		Signature:   filepath.Join(h.image, "postern-node.minisig"),
		Launcher:    filepath.Join(h.image, "launcher.sh"),
		Version:     "0.5.0",
		Arch:        "amd64",
		Docker:      h.docker,
		RunnerImage: testRunner,
		ProcDir:     h.proc,
		Getuid:      func() int { return 0 },
		Now:         time.Now,
		Sleep:       h.sleep,
		Exec: func(path string, argv, env []string) error {
			h.exec = append([]string{path}, argv...)
			h.execEnv = env
			return nil
		},
		Log: slog.New(slog.NewTextHandler(h.logs, nil)),
	}
	return h
}

// sleep records the wait and lets the running sysctl helpers end.
func (h *harness) sleep(ctx context.Context, d time.Duration) error {
	h.sleeps = append(h.sleeps, d)
	list, err := h.docker.List(ctx, map[string]string{"postern.role": "helper"}, false)
	if err != nil {
		return err
	}
	for _, c := range list {
		if h.helperSay != "" {
			_ = h.docker.AppendLogs(c.ID, h.helperSay)
		}
		_ = h.docker.Exit(c.ID, h.helperRC)
	}
	return nil
}

func (h *harness) writeImage(content string) {
	mustWrite(h.t, filepath.Join(h.image, "postern-node"), content)
}

func (h *harness) setMounts(ms ...dockerapi.MountPoint) {
	if err := h.docker.SetMounts(h.ownID, ms...); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) writeMountinfo(id string) {
	text := "1450 1300 0:52 / / rw,relatime master:1 - overlay overlay rw\n"
	if id != "" {
		text += "1461 1450 8:1 /var/lib/docker/containers/" + id + "/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n"
	}
	mustMkdir(h.t, filepath.Join(h.proc, "self"))
	mustWrite(h.t, filepath.Join(h.proc, "self", "mountinfo"), text)
}

// setProc sets the running sysctls; migrate "" is a kernel without it.
func (h *harness) setProc(ports, migrate string) {
	dir := filepath.Join(h.proc, "sys", "net", "ipv4")
	mustMkdir(h.t, dir)
	mustWrite(h.t, filepath.Join(dir, "ip_local_reserved_ports"), ports+"\n")
	p := filepath.Join(dir, "tcp_migrate_req")
	if migrate == "" {
		_ = os.Remove(p)
		return
	}
	mustWrite(h.t, p, migrate+"\n")
}

func (h *harness) boot() *boot {
	b, err := newBoot(h.opt)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

func (h *harness) wantLog(sub string) {
	h.t.Helper()
	if !strings.Contains(h.logs.String(), sub) {
		h.t.Errorf("the log has no %q:\n%s", sub, h.logs.String())
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func newToken(t *testing.T) string {
	t.Helper()
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestRunWithoutKeysAndWithoutJoin(t *testing.T) {
	h := newHarness(t)
	err := Run(t.Context(), h.opt)
	if !errors.Is(err, ErrNoKeys) || err.Error() != "no keys yet: start the container with POSTERN_JOIN from the panel" {
		t.Fatalf("Run = %v, want ErrNoKeys", err)
	}
	if h.exec != nil {
		t.Errorf("exec %q without keys", h.exec)
	}
	// The layout is there all the same.
	for _, d := range layout {
		st, err := os.Stat(filepath.Join(h.home, d.dir))
		if err != nil || st.Mode().Perm() != d.mode {
			t.Errorf("%s: %v, %v; want mode %v", d.dir, st.Mode(), err, d.mode)
		}
	}
}

func TestRunJoinsSeedsAndExecs(t *testing.T) {
	h := newHarness(t)
	srv := newJoinServer(t)
	h.opt.RootCAs = srv.roots
	token := newToken(t)
	h.opt.Env = append(h.opt.Env, EnvJoin+"="+srv.url+"#"+token)
	if err := Run(t.Context(), h.opt); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(h.home, "bin", "launcher.sh"), "launcher.sh", "agent"}
	if !slices.Equal(h.exec, want) {
		t.Errorf("exec = %q, want %q", h.exec, want)
	}
	if !slices.Equal(h.execEnv, []string{"PATH=/usr/bin", EnvHome + "=" + h.home}) {
		t.Errorf("the agent's environment = %q", h.execEnv)
	}
	if strings.Contains(h.logs.String(), token) {
		t.Error("the log holds the token")
	}
	if got := readString(t, filepath.Join(h.home, "data", "state", "node-id")); got != srv.nodeID+"\n" {
		t.Errorf("node-id = %q", got)
	}
	if target, _ := os.Readlink(filepath.Join(h.home, "bin", "current")); target != "postern-node-0.5.0" {
		t.Errorf("bin/current -> %q", target)
	}

	// A restart with the same token does not join again.
	srv.calls = 0
	h.exec = nil
	if err := Run(t.Context(), h.opt); err != nil {
		t.Fatal(err)
	}
	if srv.calls != 0 || h.exec == nil {
		t.Errorf("restart: %d join calls, exec %q; want none and an exec", srv.calls, h.exec)
	}
}

func TestRunStopsOnAFailedCheck(t *testing.T) {
	h := newHarness(t)
	h.opt.Getuid = func() int { return 1000 }
	if err := Run(t.Context(), h.opt); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("Run as a user = %v, want a refusal", err)
	}
	if _, err := os.Stat(filepath.Join(h.home, "bin")); err == nil {
		t.Error("the layout was made after a failed check")
	}
}
