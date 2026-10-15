//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/pki"
)

// newNode creates a node in the panel, with its management at 127.0.0.1 and
// its links to linkHost, installs it from its bundle (installNode), starts the
// watch of the logs of its containers, and waits until the panel has it
// online.
func (e *env) newNode(a *api) *panelv1.Node {
	e.t.Helper()
	mgmtPort := e.freePort("0.0.0.0", 61000, 65535)
	created, err := a.nodes.CreateNode(e.ctx, connect.NewRequest(&panelv1.CreateNodeRequest{
		Name: "e2e-" + e.run, MgmtHost: "127.0.0.1", MgmtPort: uint32(mgmtPort), LinkHost: linkHost,
	}))
	if err != nil {
		e.fatalf("CreateNode: %v", err)
	}
	node := created.Msg.GetNode()
	if node.GetStatus() != "provisioning" || node.GetMgmtPort() != uint32(mgmtPort) || node.GetLinkHost() != linkHost {
		e.fatalf("CreateNode made a node with status %q, management port %d, link host %q; want provisioning, %d, %s",
			node.GetStatus(), node.GetMgmtPort(), node.GetLinkHost(), mgmtPort, linkHost)
	}
	e.logf("node %s created, management port %d", node.GetId(), mgmtPort)
	bundle := e.installNode(e.downloadBundle(a, created.Msg.GetBundleUrl()))
	e.watchLogs()
	if bundle.NodeID != node.GetId() || bundle.MgmtPort != mgmtPort {
		e.fatalf("the bundle is for node %s, management port %d; want %s, %d", bundle.NodeID, bundle.MgmtPort, node.GetId(), mgmtPort)
	}
	e.waitFor("node "+node.GetId(), 3*time.Minute, time.Second, func(ctx context.Context) (bool, string, error) {
		n, err := e.getNode(ctx, a, node.GetId())
		if err != nil {
			return false, "", err
		}
		switch n.GetStatus() {
		case "online":
			return true, fmt.Sprintf("online: agent %s on %s/%s", n.GetAgentVersion(), n.GetOs(), n.GetArch()), nil
		case "error":
			return false, "", fmt.Errorf("the node is in error (the panel's log says why)")
		}
		return false, n.GetStatus(), nil
	})
	return node
}

// installNode does what install.sh does with a bundle and a binary, in the
// node's directory of the test: the layout, the PKI from the bundle, the node
// id, the binary with its kept signature and bin/current, and the launcher; everything is then made
// root's, as install.sh leaves it. Then it starts the agent container.
func (e *env) installNode(bundleTar []byte) *pki.Bundle {
	e.t.Helper()
	b, err := pki.ParseBundleTar(bundleTar)
	if err != nil {
		e.fatalf("the bundle does not parse: %v", err)
	}
	files, err := untar(bundleTar)
	if err != nil {
		e.fatalf("the bundle: %v", err)
	}
	keyValues, err := keyLeaks(files["node-key.pem"])
	if err != nil {
		e.fatalf("the key of the bundle: %v", err)
	}
	e.mustNotLeak("the private key of the node", keyValues...)

	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{"", 0o755}, {"bin", 0o755}, {"pki", 0o700}, {"data", 0o700},
		{"data/state", 0o700}, {"data/edge", 0o700}, {"data/run", 0o700}, {"data/run/launcher", 0o700},
		{"data/instances", 0o700}, {"data/certs", 0o700}, {"data/artifacts", 0o755},
	} {
		dir := filepath.Join(e.home, d.path)
		if err := os.MkdirAll(dir, d.mode); err != nil {
			e.fatalf("%v", err)
		}
		if err := os.Chmod(dir, d.mode); err != nil { // whatever the umask took away
			e.fatalf("%v", err)
		}
	}
	for _, name := range []string{"bundle.json", "ca.pem", "node.pem", "node-key.pem"} {
		e.writeFile(filepath.Join(e.home, "pki", name), files[name], 0o600)
	}
	e.writeFile(filepath.Join(e.home, "data", "state", "node-id"), []byte(b.NodeID+"\n"), 0o600)
	binary, err := os.ReadFile(e.nodeBin)
	if err != nil {
		e.fatalf("%v", err)
	}
	e.writeFile(filepath.Join(e.home, "bin", nodeBinaryName), binary, 0o755)
	// install.sh keeps the release's signature beside the binary, which an
	// edge-only roll back to this version needs. The binary is signed with
	// the run's release key, when there is one (TestVersions has it).
	if e.releaseKey != "" {
		e.writeFile(filepath.Join(e.home, "bin", "."+nodeBinaryName+".minisig"), e.signNode(binary, nodeVersion, runtime.GOARCH), 0o644)
	}
	if err := os.Symlink(nodeBinaryName, filepath.Join(e.home, "bin", "current")); err != nil {
		e.fatalf("%v", err)
	}
	launcher, err := os.ReadFile(filepath.Join(e.repo, "deploy", "node", "launcher.sh"))
	if err != nil {
		e.fatalf("%v", err)
	}
	e.writeFile(filepath.Join(e.home, "bin", "launcher.sh"), launcher, 0o755)

	// install.sh runs as root. The edge runs as root without CAP_DAC_OVERRIDE
	// and creates its socket in data/run, which therefore has to be root's.
	if code, out := e.runHelper("chown", "none", []string{"chown", "-hR", "0:0", e.home}); code != 0 {
		e.fatalf("chown of the node's directory: exit %d: %s", code, out)
	}

	spec := e.agentSpec()
	ctx, cancel := context.WithTimeout(e.ctx, time.Minute)
	defer cancel()
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		e.fatalf("creating the agent container: %v", err)
	}
	e.agent = id
	if err := e.docker.Start(ctx, id); err != nil {
		e.fatalf("starting the agent container: %v", err)
	}
	e.logf("node %s installed in %s; agent container %s started", b.NodeID, e.home, spec.Name)
	return b
}

// agentSpec is the agent container of deploy/node/compose.yaml, with the
// node's directory of the test in place of /opt/postern, at the same path
// inside and outside, a name of the run, and the label of the run.
func (e *env) agentSpec() dockerapi.ContainerSpec {
	return dockerapi.ContainerSpec{
		Name:          "postern-agent-" + e.run,
		Image:         runnerImage,
		Entrypoint:    []string{e.home + "/bin/launcher.sh", "agent"},
		Env:           []string{"POSTERN_HOME=" + e.home},
		NetworkMode:   "host",
		PidMode:       "host",
		ReadOnly:      true,
		Tmpfs:         map[string]string{"/tmp": ""},
		RestartPolicy: "unless-stopped",
		Binds: []string{
			"/var/run/docker.sock:/var/run/docker.sock",
			e.home + ":" + e.home,
			"/etc/os-release:/host/etc/os-release:ro",
		},
		Labels: map[string]string{
			"postern.managed": "true",
			"postern.role":    "agent",
			"postern.id":      "agent",
			labelRun:          e.run,
		},
		LogMaxSize: "10m",
		LogMaxFile: 3,
	}
}

// exitRestart is the exit code of an agent that installed a new binary.
const exitRestart = 75

// checkAgent fails the test when the agent container is not running, or, while
// e.agentUpdates is set, restarting after an update of the agent.
func (e *env) checkAgent() {
	e.t.Helper()
	if e.agent == "" {
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	d, err := e.docker.Inspect(ctx, e.agent)
	if err != nil {
		e.fatalf("inspecting the agent container: %v", err)
	}
	switch {
	case d.State == "running":
	case e.agentUpdates && (d.State == "restarting" || d.State == "exited" && d.ExitCode == exitRestart):
		// The agent installed a new binary and exits for its launcher to start
		// it (Global Constraints, Self-update); Docker starts it again.
	default:
		e.fatalf("the agent container is %s (exit code %d)", d.State, d.ExitCode)
	}
}

// restartAgent restarts the agent container as docker restart does: SIGTERM,
// SIGKILL after 10 s, start. It returns when the container runs again.
//
// Nothing here compares times of the wall clock: the clock of a virtual
// machine (Docker Desktop's, a CI runner's) can step back by seconds while
// the test runs, also in the middle of the restart.
func (e *env) restartAgent() {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	before, err := e.docker.Inspect(ctx, e.agent)
	if err != nil {
		e.fatalf("inspecting the agent container: %v", err)
	}
	start := time.Now()
	if err := e.docker.Stop(ctx, e.agent, 10*time.Second); err != nil {
		e.fatalf("stopping the agent container: %v", err)
	}
	took := time.Since(start)
	stopped, err := e.docker.Inspect(ctx, e.agent)
	if err != nil {
		e.fatalf("inspecting the agent container: %v", err)
	}
	if err := e.docker.Start(ctx, e.agent); err != nil {
		e.fatalf("starting the agent container again: %v", err)
	}
	after, err := e.docker.Inspect(ctx, e.agent)
	if err != nil {
		e.fatalf("inspecting the agent container: %v", err)
	}
	switch {
	case after.State != "running":
		e.fatalf("the agent container is %s after the restart (exit code %d)", after.State, after.ExitCode)
	case after.StartedAt.Equal(before.StartedAt):
		e.fatalf("the agent container did not start again: it started at %v, as before", after.StartedAt)
	}
	// SIGTERM is a stop that was asked for: the agent exits with 0, and in
	// time, not by Docker's SIGKILL (137).
	if stopped.ExitCode != 0 {
		e.errorf("the agent exited with code %d on SIGTERM after %v, want 0", stopped.ExitCode, took.Round(time.Millisecond))
	}
	e.logf("the agent container restarted: SIGTERM, exit code %d after %v, started again", stopped.ExitCode, took.Round(time.Millisecond))
}

// healthyMarker identifies the launcher's healthy marker
// (deploy/node/launcher.sh) by its inode and the times of its last change, to
// the nanosecond: a new marker differs from an old one also when the clock
// stepped back in between. ok is false while there is no marker. The marker
// is root's, so a container of the run looks at it.
func (e *env) healthyMarker(ctx context.Context) (id string, ok bool) {
	e.t.Helper()
	marker := filepath.Join(e.home, "data", "run", "launcher", "healthy")
	code, out := e.runHelperCtx(ctx, "marker", "none", []string{"stat", "-c", "%i %y %z", marker})
	return out, code == 0
}

// waitHealthy waits for the healthy marker of a new agent process, one that
// is not previous: the launcher deletes the marker before it starts the
// agent, and the agent writes it once its management server serves, its
// desired state is loaded and its first reconcile pass went through. why says
// where the timeout comes from, for the message of a failure.
func (e *env) waitHealthy(previous string, timeout time.Duration, why string) {
	e.t.Helper()
	e.waitFor("the healthy marker of the new agent process ("+why+")", timeout, 500*time.Millisecond,
		func(ctx context.Context) (bool, string, error) {
			switch id, ok := e.healthyMarker(ctx); {
			case !ok:
				return false, "not written yet", nil
			case id == previous:
				return false, "the marker of the previous process", nil
			}
			return true, "written: the first reconcile pass of the new process went through", nil
		})
}

// engineContainers are the containers of the engine of the proxy, running or
// not, by their generation (the label postern.generation).
func (e *env) engineContainers(ctx context.Context, proxyID string) (map[uint64]rawContainer, error) {
	list, err := e.containersOfThisRun(ctx)
	if err != nil {
		return nil, err
	}
	out := map[uint64]rawContainer{}
	for _, c := range list {
		if c.Labels["postern.role"] != "engine" || c.Labels["postern.id"] != proxyID {
			continue
		}
		gen, err := strconv.ParseUint(c.Labels["postern.generation"], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("engine container %s: the label postern.generation: %w", c.name(), err)
		}
		out[gen] = c
	}
	return out, nil
}

// describeEngines says which generations there are and how they are, oldest
// first: "generation 1 running, generation 2 running".
func describeEngines(engines map[uint64]rawContainer) string {
	if len(engines) == 0 {
		return "none"
	}
	var parts []string
	for _, gen := range slices.Sorted(maps.Keys(engines)) {
		parts = append(parts, fmt.Sprintf("generation %d %s", gen, engines[gen].State))
	}
	return strings.Join(parts, ", ")
}

// nodeContainer is the one running container of this node's agent with the
// role and the id, and its start time.
func (e *env) nodeContainer(role, id string) (rawContainer, time.Time) {
	e.t.Helper()
	list, err := e.containersOfThisRun(e.ctx)
	if err != nil {
		e.fatalf("listing the containers of the run: %v", err)
	}
	var found []rawContainer
	for _, c := range list {
		if c.Labels["postern.role"] == role && c.Labels["postern.id"] == id && c.State == "running" {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		e.fatalf("%d running %s containers of the node with id %q, want 1", len(found), role, id)
	}
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	d, err := e.docker.Inspect(ctx, found[0].ID)
	if err != nil {
		e.fatalf("inspecting the %s container: %v", role, err)
	}
	return found[0], d.StartedAt
}
