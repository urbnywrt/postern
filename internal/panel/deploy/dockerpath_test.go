package deploy

import (
	"database/sql"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/jobs"
	"github.com/urbnywrt/postern/internal/panel/nodes"
)

const (
	testImage    = "ghcr.io/owner/postern-node:v1.2.3"
	testPanelURL = "https://panel.example.com"
)

// tokenRe is a join token: 43 characters of base64url.
var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// The SSH install takes the Docker path when the panel has a node image and
// the request a valid panel address: it removes an old agent container, makes
// a join token and starts the node with the rendered Docker command. No kit
// and no bundle go to the server, and the token never shows in the log.
func TestInstallWithTheDockerCommand(t *testing.T) {
	e := newEnv(t, envOptions{image: testImage})
	e.host.set(func(h *fakeHost) { h.agentThere = true })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), PanelUrl: "HTTPS://Panel.Example.com/"})
	t.Logf("the log of the job:\n%s", j.GetLog())
	if j.GetStatus() != jobs.StatusDone {
		t.Fatalf("job %s: %s\n%s", j.GetStatus(), j.GetError(), j.GetLog())
	}
	if got, want := e.host.Steps(), []string{"preflight", "pull", "rm agent", "docker run"}; !slices.Equal(got, want) {
		t.Errorf("steps:\n got %q\nwant %q", got, want)
	}
	if u := e.host.Unknown(); len(u) != 0 {
		t.Errorf("unknown commands: %q", u)
	}
	if u := e.host.Uploads(); len(u) != 0 {
		t.Errorf("the Docker path uploaded %d files", len(u))
	}

	var script string
	e.host.set(func(h *fakeHost) { script = h.startScripts[0] })
	m := joinRe.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no POSTERN_JOIN in the start command:\n%s", script)
	}
	panelURL, token, _ := strings.Cut(m[1], "#")
	if panelURL != testPanelURL || !tokenRe.MatchString(token) {
		t.Fatalf("POSTERN_JOIN = %q, want %s#<token>", m[1], testPanelURL)
	}
	if want := nodes.RenderDockerCommand(testImage, testPanelURL, token); !strings.Contains(script, "\n    "+want+" &\n") {
		t.Errorf("the start command does not run the rendered command:\n%s\nwant:\n%s", script, want)
	}

	for _, line := range []string{"the node starts from its Docker image", "Removing an old agent container", "postern-agent",
		"Making a join token", "Starting the node (" + testImage + ")", "POSTERN_JOIN=***", "Waiting for the node", "The node is online"} {
		if !strings.Contains(j.GetLog(), line) {
			t.Errorf("the log does not say %q", line)
		}
	}
	for _, secret := range []string{token, m[1]} {
		if strings.Contains(j.GetLog(), secret) || strings.Contains(j.GetError(), secret) || strings.Contains(e.logs.String(), secret) {
			t.Errorf("a log shows %q", secret)
		}
	}
	if mint, rm := strings.Index(j.GetLog(), "Making a join token"), strings.Index(j.GetLog(), "Removing an old agent container"); mint < 0 || rm < mint {
		t.Errorf("the token is not made before the old container is removed:\n%s", j.GetLog())
	}
	if install, mint := e.auditAdmin("node.install"), e.auditAdmin("node.join_token"); install == "" || mint != install {
		t.Errorf("node.join_token by admin %q, want the admin of the install, %q", mint, install)
	}
	audit := e.audit()
	for _, want := range []string{"node.install node:" + e.node.GetId(), "node.join_token node:" + e.node.GetId()} {
		if !slices.Contains(audit, want) {
			t.Errorf("audit %q has no %q", audit, want)
		}
	}
}

// With a node image, a panel address that the panel refuses is refused, by
// the preflight and the install alike, before the server is touched: it does
// not silently fall back to the kit path.
func TestInstallRefusesABadPanelAddress(t *testing.T) {
	for _, tt := range []struct{ name, url string }{
		{"a panel address with a path", testPanelURL + "/panel"},
		{"plain HTTP to a remote panel", "http://panel.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, envOptions{image: testImage})
			_, err := e.preflight(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: password(), PanelUrl: tt.url})
			wantCode(t, err, connect.CodeInvalidArgument)
			if !strings.Contains(err.Error(), "panel_url") {
				t.Errorf("preflight error %q does not name panel_url", err)
			}
			_, err = e.install(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), PanelUrl: tt.url})
			wantCode(t, err, connect.CodeInvalidArgument)
			if got := e.host.Steps(); len(got) != 0 {
				t.Errorf("steps %q, want none", got)
			}
		})
	}
}

// Without a node image, or without a panel address, the install is the kit
// path, as before. Without a node image the address is not looked at.
func TestInstallFallsBackToTheKit(t *testing.T) {
	for _, tt := range []struct {
		name, image, url string
	}{
		{"no node image", "", testPanelURL},
		{"no node image, a bad address", "", "http://panel.example.com"},
		{"no panel address", testImage, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, envOptions{image: tt.image})
			j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), PanelUrl: tt.url})
			if j.GetStatus() != jobs.StatusDone {
				t.Fatalf("job %s: %s\n%s", j.GetStatus(), j.GetError(), j.GetLog())
			}
			steps := e.host.Steps()
			if !slices.Contains(steps, "install.sh") || slices.Contains(steps, "docker run") || slices.Contains(steps, "rm agent") {
				t.Errorf("steps %q, want the kit path", steps)
			}
			if !strings.Contains(j.GetLog(), "the node kit is copied to the server") {
				t.Errorf("the log does not state the kit path:\n%s", j.GetLog())
			}
		})
	}
}

// The preflight states the path, and its issues are those of the path: the
// Docker path needs no kit, no bash and no Compose.
func TestPreflightOfEachPath(t *testing.T) {
	for _, tt := range []struct {
		name, image, url string
		method           string
		dir              string
		issues           []string
	}{
		{"the kit path", testImage, "", MethodKit, installDir, []string{"bash_missing/blocker", "docker_missing/blocker"}},
		{"the Docker path", testImage, testPanelURL, MethodDocker, "", []string{"docker_missing/blocker"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, envOptions{server: "alpine-3.22", image: tt.image})
			r := e.report(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: password(), PanelUrl: tt.url})
			if r.GetInstallMethod() != tt.method || r.GetInstallDir() != tt.dir {
				t.Errorf("method %q, dir %q; want %q, %q", r.GetInstallMethod(), r.GetInstallDir(), tt.method, tt.dir)
			}
			if got := issueCodes(r); !slices.Equal(got, tt.issues) {
				t.Errorf("issues = %q, want %q", got, tt.issues)
			}
		})
	}
}

// Docker is set up for the Docker path without the Compose plugin, and a
// failing docker run fails the job without the token in its error.
func TestInstallWithTheDockerCommandSetsUpDocker(t *testing.T) {
	e := newEnv(t, envOptions{server: "ubuntu-24.04-nodocker", image: testImage})
	e.host.set(func(h *fakeHost) { h.afterDocker = "ubuntu-24.04" })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), InstallDocker: true, PanelUrl: testPanelURL})
	if j.GetStatus() != jobs.StatusDone {
		t.Fatalf("job %s: %s\n%s", j.GetStatus(), j.GetError(), j.GetLog())
	}
	want := []string{"preflight", "install docker", "preflight", "pull", "rm agent", "docker run"}
	if got := e.host.Steps(); !slices.Equal(got, want) {
		t.Errorf("steps:\n got %q\nwant %q", got, want)
	}
	e.host.set(func(h *fakeHost) {
		if len(h.dockerSetups) != 1 || !strings.Contains(h.dockerSetups[0], "need_compose=0") {
			t.Errorf("the setup of Docker does not skip Compose")
		}
	})

	e2 := newEnv(t, envOptions{image: testImage})
	e2.host.set(func(h *fakeHost) { h.startCode = 125 })
	j = e2.installed(&panelv1.InstallRequest{Target: e2.confirmed("root"), Credentials: password(), PanelUrl: testPanelURL})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), "docker run failed with exit code 125") {
		t.Errorf("job %s %q, want failed by docker run", j.GetStatus(), j.GetError())
	}
	if !strings.Contains(j.GetLog(), "POSTERN_JOIN=***") {
		t.Errorf("the log does not mask the join value:\n%s", j.GetLog())
	}
}

// The image is pulled before the old agent container is removed: a pull that
// fails, with no copy of the image on the server, fails the job and leaves the
// old container running.
func TestInstallWithTheDockerCommandPullsBeforeRemoving(t *testing.T) {
	e := newEnv(t, envOptions{image: testImage})
	e.host.set(func(h *fakeHost) { h.agentThere, h.pullCode = true, 1 })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), PanelUrl: testPanelURL})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), "could not pull the node image") {
		t.Fatalf("job %s %q, want failed by the pull\n%s", j.GetStatus(), j.GetError(), j.GetLog())
	}
	if got, want := e.host.Steps(), []string{"preflight", "pull", "image inspect"}; !slices.Equal(got, want) {
		t.Errorf("steps:\n got %q\nwant %q", got, want)
	}
	e.host.set(func(h *fakeHost) {
		if !h.agentThere {
			t.Error("the old agent container was removed after a failed pull")
		}
		if !slices.Equal(h.pulled, []string{testImage}) {
			t.Errorf("pulled %q, want %q", h.pulled, testImage)
		}
	})
	if !strings.Contains(j.GetLog(), "Pulling the node image") {
		t.Errorf("the log does not say the pull:\n%s", j.GetLog())
	}
}

// When the registry cannot be reached but the image is on the server already,
// the failed pull is a warning and the install goes on with that image.
func TestInstallWithTheDockerCommandUsesALocalImage(t *testing.T) {
	e := newEnv(t, envOptions{image: testImage})
	e.host.set(func(h *fakeHost) { h.agentThere, h.pullCode, h.imageLocal = true, 1, true })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), PanelUrl: testPanelURL})
	if j.GetStatus() != jobs.StatusDone {
		t.Fatalf("job %s: %s\n%s", j.GetStatus(), j.GetError(), j.GetLog())
	}
	if got, want := e.host.Steps(), []string{"preflight", "pull", "image inspect", "rm agent", "docker run"}; !slices.Equal(got, want) {
		t.Errorf("steps:\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(j.GetLog(), "warning: the pull failed; the copy of "+testImage+" on the server is used") {
		t.Errorf("the log does not warn of the pull:\n%s", j.GetLog())
	}
}

// auditAdmin returns the admin of the last audit row of action.
func (e *env) auditAdmin(action string) string {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var admin string
	if err := db.QueryRow(`SELECT admin_id FROM audit_log WHERE action = ? ORDER BY ts DESC, rowid DESC LIMIT 1`, action).Scan(&admin); err != nil {
		e.t.Fatalf("audit row %s: %v", action, err)
	}
	return admin
}

// A token that cannot be made fails the install before the old agent
// container is touched: the node keeps running as it was.
func TestInstallWithTheDockerCommandKeepsTheAgentWithoutAToken(t *testing.T) {
	e := newEnv(t, envOptions{image: testImage})
	e.host.set(func(h *fakeHost) {
		h.agentThere = true
		h.onPreflight = func() {
			db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath))
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = db.Close() }()
			if _, err := db.Exec(`DROP TABLE node_join_tokens`); err != nil {
				t.Error(err)
			}
		}
	})
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), PanelUrl: testPanelURL})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), "could not make a join token") {
		t.Fatalf("job %s %q, want failed for the token\n%s", j.GetStatus(), j.GetError(), j.GetLog())
	}
	if got := e.host.Steps(); !slices.Equal(got, []string{"preflight"}) {
		t.Errorf("steps %q, want the preflight alone", got)
	}
	e.host.set(func(h *fakeHost) {
		if !h.agentThere {
			t.Error("the old agent container was removed without a token")
		}
	})
}
