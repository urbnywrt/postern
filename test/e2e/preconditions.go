//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/panel/proxies"
)

// What the run needs before it starts, checked by newEnv in this order: the
// cheap checks first, then what pulls or builds.

// checkComposeFile makes sure deploy/node/compose.yaml still describes the
// agent container that agentSpec makes: when one of these settings changes
// there, agentSpec has to follow.
func (e *env) checkComposeFile() {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(e.repo, "deploy", "node", "compose.yaml"))
	if err != nil {
		e.fatalf("reading the compose file of the node: %v", err)
	}
	for _, want := range []string{
		"image: " + runnerImage,
		`entrypoint: ["/opt/postern/bin/launcher.sh", "agent"]`,
		"POSTERN_HOME: /opt/postern",
		"network_mode: host",
		"pid: host",
		"read_only: true",
		"tmpfs:\n      - /tmp\n",
		"restart: unless-stopped",
		"- /var/run/docker.sock:/var/run/docker.sock\n",
		"- /opt/postern:/opt/postern\n",
		"- /etc/os-release:/host/etc/os-release:ro\n",
		`postern.managed: "true"`,
		"postern.role: agent\n",
		"postern.id: agent\n",
		"driver: json-file",
		"max-size: 10m",
		`max-file: "3"`,
	} {
		if !strings.Contains(string(data), want) {
			e.fatalf("deploy/node/compose.yaml no longer has %q: make agentSpec in test/e2e match the file again", want)
		}
	}
}

// checkNetworkNamespace makes sure the test runs where the host network of
// the containers is: on Docker Desktop that is the network of Docker's VM,
// which a process outside a container cannot reach.
func (e *env) checkNetworkNamespace() {
	e.t.Helper()
	var info struct{ OperatingSystem string }
	if err := e.raw.get(e.ctx, "/info", &info); err != nil {
		e.fatalf("docker info: %v", err)
	}
	if !strings.Contains(info.OperatingSystem, "Docker Desktop") {
		return
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		e.fatalf("the Docker daemon is %s: the host network of its containers is the network of its VM, "+
			"out of reach of this process. Run the test with scripts/e2e.sh, which runs it in a container on that network.",
			info.OperatingSystem)
	}
}

// checkNoOtherNode refuses to run next to the containers of another Postern
// node: the agent of the test would take them for its own, and adopt or
// remove them.
func (e *env) checkNoOtherNode() {
	e.t.Helper()
	list, err := e.raw.containers(e.ctx, "postern.managed=true")
	if err != nil {
		e.fatalf("listing the containers of Postern nodes: %v", err)
	}
	if len(list) == 0 {
		return
	}
	var names []string
	for _, c := range list {
		names = append(names, c.name()+" ("+c.State+")")
	}
	e.fatalf("the Docker daemon runs containers of another Postern node: %s. The agent of this test would adopt "+
		"or remove them; remove them first (a run of this test that was killed leaves such containers), or use another daemon.",
		strings.Join(names, ", "))
}

// checkGitHub skips the test when the telemt release that the panel downloads
// cannot be reached.
func (e *env) checkGitHub() {
	e.t.Helper()
	file, err := telemt.New().ArtifactFile(runtime.GOARCH)
	if err != nil {
		e.skipf("telemt has no release for %s: %v", runtime.GOARCH, err)
	}
	u := "https://github.com/telemt/telemt/releases/download/" + proxies.DefaultTelemtVersion + "/" + file
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		e.fatalf("%v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.skipf("GitHub is unreachable, so the panel cannot download telemt %s for the node; skipping (%v)",
			proxies.DefaultTelemtVersion, err)
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 500:
		e.skipf("GitHub answers %s for the telemt release, so the panel cannot download it; skipping", resp.Status)
	case resp.StatusCode != http.StatusOK:
		e.fatalf("HEAD %s: %s: the telemt release that the panel pins cannot be downloaded", u, resp.Status)
	}
}

// ensureRunnerImage pulls the runner image when the daemon does not have it.
func (e *env) ensureRunnerImage() {
	e.t.Helper()
	ok, err := e.docker.ImageExists(e.ctx, runnerImage)
	if err != nil {
		e.fatalf("looking for the runner image: %v", err)
	}
	if ok {
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Minute)
	defer cancel()
	if err := e.docker.Pull(ctx, runnerImage); err != nil {
		e.fatalf("pulling the runner image: %v", err)
	}
}

// binaries finds the binaries of the run, or builds them: postern-node of
// nodeVersion and postern-panel of updateVersion, and for TestVersions the
// node binary of updateVersion, the stand-in engine and the throwaway key
// whose public half the binaries trust (see the package comment). Where the
// first two are given, the others are taken from the environment as they are
// (versionBinaries says when they are missing); where they are not, the go
// command builds all of them with a key of its own, and without it the test
// is skipped.
func (e *env) binaries() {
	e.t.Helper()
	e.nodeBin, e.panelBin = os.Getenv("POSTERN_E2E_NODE_BIN"), os.Getenv("POSTERN_E2E_PANEL_BIN")
	e.updateBin, e.badEngineBin = os.Getenv("POSTERN_E2E_NODE_UPDATE_BIN"), os.Getenv("POSTERN_E2E_BADENGINE_BIN")
	e.releaseKey = os.Getenv("POSTERN_E2E_RELEASE_KEY")
	switch {
	case e.nodeBin != "" && e.panelBin != "":
		for _, f := range []string{e.nodeBin, e.panelBin} {
			if info, err := os.Stat(f); err != nil || !info.Mode().IsRegular() {
				e.fatalf("binary %s: not a file (%v)", f, err)
			}
		}
		return
	case e.nodeBin != "" || e.panelBin != "":
		e.fatalf("set both POSTERN_E2E_NODE_BIN and POSTERN_E2E_PANEL_BIN, or neither")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		e.skipf("POSTERN_E2E_NODE_BIN and POSTERN_E2E_PANEL_BIN are not set, and there is no go command to build them "+
			"(scripts/e2e.sh builds them): %v", err)
	}
	dir := e.t.TempDir()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		e.fatalf("making the throwaway release key: %v", err)
	}
	pubText, err := pub.MarshalText()
	if err != nil {
		e.fatalf("%v", err)
	}
	privText, err := priv.MarshalText()
	if err != nil {
		e.fatalf("%v", err)
	}
	e.releaseKey = filepath.Join(dir, "release.key")
	e.writeFile(e.releaseKey, privText, 0o600)
	e.updateBin = filepath.Join(dir, "postern-node-"+updateVersion)
	e.badEngineBin = filepath.Join(dir, "badengine")
	for _, b := range []struct {
		out      *string
		path     string
		pkg, ver string // ver "" for the stand-in engine, which is no Postern binary
	}{
		{&e.nodeBin, filepath.Join(dir, "postern-node"), "./cmd/node", nodeVersion},
		{&e.panelBin, filepath.Join(dir, "postern-panel"), "./cmd/panel", updateVersion},
		{&e.updateBin, e.updateBin, "./cmd/node", updateVersion},
		{&e.badEngineBin, e.badEngineBin, "./test/e2e/testdata/badengine", ""},
	} {
		*b.out = b.path
		args := []string{"build", "-trimpath", "-o", b.path}
		if b.ver != "" {
			// The production keys are emptied: a set with production keys
			// ignores test keys, and these binaries must trust the test key.
			args = append(args, "-ldflags", "-X github.com/urbnywrt/postern/internal/version.Version="+b.ver+
				" -X github.com/urbnywrt/postern/internal/release.extraPublicKeys="+string(pubText)+
				" -X github.com/urbnywrt/postern/internal/release.productionReleaseKeys="+
				" -X github.com/urbnywrt/postern/internal/release.productionStableKeys=")
		}
		cmd := exec.CommandContext(e.ctx, goBin, append(args, b.pkg)...)
		cmd.Dir = e.repo
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
		if out, err := cmd.CombinedOutput(); err != nil {
			e.fatalf("building %s: %v\n%s", b.pkg, err, out)
		}
	}
	e.logf("built postern-node %s and %s, postern-panel %s and the stand-in engine for linux/%s, with a throwaway release key",
		nodeVersion, updateVersion, updateVersion, runtime.GOARCH)
}

// checkSharedHost makes sure that a container on the host network reaches
// this process at 127.0.0.1 and sees the node's directory at the path that
// the test sees: the agent, the edge and the engines need both. It fails at
// once where they would not (a CI job in a container of its own, a test run
// beside Docker Desktop's VM), instead of a node that never comes online.
func (e *env) checkSharedHost() {
	e.t.Helper()
	want := rand.Text()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.fatalf("%v", err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, want) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	out := filepath.Join(e.work, "shared-host-check")
	u := "http://" + ln.Addr().String() + "/"
	code, output := e.runHelper("check", "host", []string{"wget", "-q", "-T", "10", "-O", out, u})
	got, err := os.ReadFile(out)
	if code != 0 || err != nil || string(got) != want {
		e.fatalf("a container on the host network does not reach this process at 127.0.0.1, or does not see %s "+
			"at that path (wget exit %d: %s; %v). The test must run in the network namespace and the file system that "+
			"the Docker daemon gives its containers: on Linux directly on the Docker host, on Docker Desktop with scripts/e2e.sh.",
			e.work, code, output, err)
	}
	if err := os.Remove(out); err != nil {
		e.fatalf("%v", err)
	}
}
