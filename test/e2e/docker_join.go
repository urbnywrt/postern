//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
)

// The one-command install (docs/design/2026-10-08-node-docker-join.md): the
// panel renders a docker run of the node image, and the image's bootstrap
// joins the panel with the token of the command.

// joinCommand mints a join token for the node with the panel at panelURL,
// checks the docker run and the compose file that the panel renders for it
// against the command of the design, word for word, and returns the token.
func (e *env) joinCommand(a *api, nodeID, panelURL, image string) string {
	e.t.Helper()
	r, err := a.nodes.CreateJoinToken(e.ctx, connect.NewRequest(&panelv1.CreateJoinTokenRequest{NodeId: nodeID, PanelUrl: panelURL}))
	if err != nil {
		e.fatalf("CreateJoinToken: %v", err)
	}
	m := r.Msg
	token := m.GetToken()
	e.mustNotLeak("the join token", token)
	if len(token) != 43 {
		e.fatalf("the join token has %d characters, want 43", len(token))
	}
	if left := time.Until(time.Unix(m.GetExpiresUnix(), 0)); left < 23*time.Hour || left > 25*time.Hour {
		e.errorf("the join token expires in %v, want 24 h", left.Round(time.Minute))
	}
	if m.GetImage() != image {
		e.fatalf("the command runs the image %q, want %q (POSTERN_NODE_IMAGE of the panel)", m.GetImage(), image)
	}
	join := panelURL + "#" + token
	wantRun := "docker run -d --name postern-agent --restart unless-stopped \\\n" +
		"  --network host --pid host --read-only --tmpfs /tmp \\\n" +
		"  --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \\\n" +
		"  -v /var/run/docker.sock:/var/run/docker.sock \\\n" +
		"  -v /opt/postern:/opt/postern \\\n" +
		"  -v /etc/os-release:/host/etc/os-release:ro \\\n" +
		"  -e POSTERN_JOIN='" + join + "' \\\n" +
		"  " + image
	if got := strings.TrimRight(m.GetDockerCommand(), "\n"); got != wantRun {
		e.fatalf("the docker command of the panel is not that of the design:\n%s\nwant:\n%s", got, wantRun)
	}
	for _, want := range []string{
		"name: postern\n",
		"    image: " + image + "\n",
		"    container_name: postern-agent\n",
		"    restart: unless-stopped\n",
		"    network_mode: host\n",
		"    pid: host\n",
		"    read_only: true\n",
		"    tmpfs:\n      - /tmp\n",
		"      POSTERN_JOIN: \"" + join + "\"\n",
		"      - /var/run/docker.sock:/var/run/docker.sock\n",
		"      - /opt/postern:/opt/postern\n",
		"      - /etc/os-release:/host/etc/os-release:ro\n",
		"      driver: json-file\n",
		"        max-size: 10m\n",
		"        max-file: \"3\"\n",
	} {
		if !strings.Contains(m.GetComposeYaml(), want) {
			e.errorf("the compose file of the panel has no %q", want)
		}
	}
	e.logf("the panel rendered the docker command and the compose file of the design for %s", image)
	return token
}

// joinSpec is the container of the docker command, as dockerJoin checked it:
// the node's directory of the test in place of /opt/postern, at the same path
// inside and outside, with POSTERN_HOME saying so; a name of the run, and the
// label of the run. The labels postern.managed, role and id come from the
// image.
func (e *env) joinSpec(image, join string) dockerapi.ContainerSpec {
	return dockerapi.ContainerSpec{
		Name:          "postern-agent-" + e.run,
		Image:         image,
		Env:           []string{"POSTERN_JOIN=" + join, "POSTERN_HOME=" + e.home},
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
		Labels:     map[string]string{labelRun: e.run},
		LogMaxSize: "10m",
		LogMaxFile: 3,
	}
}

// startJoining creates and starts the agent container of the docker command
// with the token. A container of an earlier command goes first, as the
// operator removes it (docker rm -f) before running a new command.
func (e *env) startJoining(image, panelURL, token string) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, time.Minute)
	defer cancel()
	if e.agent != "" {
		if err := e.docker.Remove(ctx, e.agent, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			e.fatalf("removing the agent container: %v", err)
		}
		e.agent = ""
	}
	spec := e.joinSpec(image, panelURL+"#"+token)
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		e.fatalf("creating the agent container: %v", err)
	}
	e.agent = id
	if err := e.docker.Start(ctx, id); err != nil {
		e.fatalf("starting the agent container: %v", err)
	}
	d, err := e.docker.Inspect(ctx, id)
	if err != nil {
		e.fatalf("inspecting the agent container: %v", err)
	}
	for k, v := range map[string]string{"postern.managed": "true", "postern.role": "agent", "postern.id": "agent"} {
		if d.Labels[k] != v {
			e.errorf("the agent container has the label %s=%q from the image, want %q", k, d.Labels[k], v)
		}
	}
	e.logf("agent container %s started from %s with POSTERN_HOME=%s", spec.Name, image, e.home)
}

// waitJoined waits until the panel has the node online with joins audit rows
// of node.join, the last of them from the agent of nodeVersion.
func (e *env) waitJoined(a *api, nodeID string, joins int) {
	e.t.Helper()
	e.waitFor(fmt.Sprintf("node %s online after join %d", nodeID, joins), 3*time.Minute, time.Second,
		func(ctx context.Context) (bool, string, error) {
			rows, err := e.joinRows(ctx, a, nodeID)
			if err != nil {
				return false, "", err
			}
			if len(rows) > joins {
				// A join too many will not go away: the test fails here, at
				// once, and does not poll on.
				e.fatalf("%d node.join rows in the audit log for node %s, want %d: the node joined again", len(rows), nodeID, joins)
			}
			n, err := e.getNode(ctx, a, nodeID)
			if err != nil {
				return false, "", err
			}
			status := fmt.Sprintf("%d of %d joins, node %s", len(rows), joins, n.GetStatus())
			if n.GetStatus() == "error" {
				return false, "", fmt.Errorf("the node is in error (the panel's log says why)")
			}
			return len(rows) == joins && n.GetStatus() == "online", status, nil
		})
}

// joinRows are the audit rows of node.join for the node, newest first.
func (e *env) joinRows(ctx context.Context, a *api, nodeID string) ([]*panelv1.JournalAudit, error) {
	var out []*panelv1.JournalAudit
	for cursor := ""; ; {
		j, err := a.diag.ListJournal(ctx, connect.NewRequest(&panelv1.ListJournalRequest{
			Source: "audit", ActionPrefix: "node.join", Limit: 200, Cursor: cursor,
		}))
		if err != nil {
			return nil, fmt.Errorf("ListJournal: %w", err)
		}
		for _, r := range j.Msg.GetAudit() {
			// The prefix takes node.join_token as well.
			if r.GetAction() == "node.join" && r.GetTarget() == "node:"+nodeID {
				out = append(out, r)
			}
		}
		if cursor = j.Msg.GetNextCursor(); cursor == "" {
			return out, nil
		}
	}
}

// bundleStatus is the HTTP status of a download of the node's bundle.
func (e *env) bundleStatus(a *api, path string) int {
	e.t.Helper()
	req, err := http.NewRequestWithContext(e.ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		e.fatalf("%v", err)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		e.fatalf("GET %s: %v", path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// nodeIdentity is what the bootstrap wrote: the node id, the SHA-256 of the
// node certificate and the SHA-256 of the token it last joined with. The files
// are root's, so a container of the run reads them.
type nodeIdentity struct{ id, certHash, tokenHash string }

func (e *env) nodeIdentity() nodeIdentity {
	e.t.Helper()
	code, out := e.runHelper("identity", "none", []string{"sh", "-c",
		`cat "$1/data/state/node-id" "$1/data/state/join-token.sha256" && sha256sum "$1/pki/node.pem"`, "sh", e.home})
	f := strings.Fields(out)
	if code != 0 || len(f) != 4 {
		e.fatalf("reading the identity of the node: exit %d: %s", code, out)
	}
	return nodeIdentity{id: f[0], tokenHash: f[1], certHash: f[2]}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// checkInstalled checks what the bootstrap left on the host: the kernel's
// reserved ports cover the ports of the node, and bin/current is the binary
// of the image, which the agent that the panel sees runs.
func (e *env) checkInstalled(a *api, nodeID string) {
	e.t.Helper()
	// The sysctl helper sets the host's network namespace, which is that of
	// this process (scripts/e2e.sh, checkSharedHost).
	reserved, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_reserved_ports")
	if err != nil {
		e.fatalf("%v", err)
	}
	if !portsCover(string(reserved), 20000, 40999) {
		e.errorf("net.ipv4.ip_local_reserved_ports is %q after the bootstrap: it does not cover 20000-40999",
			strings.TrimSpace(string(reserved)))
	}
	current, err := os.Readlink(filepath.Join(e.home, "bin", "current"))
	if err != nil {
		e.fatalf("bin/current: %v", err)
	}
	if current != nodeBinaryName {
		e.errorf("bin/current is %s, want %s: the binary of the image", current, nodeBinaryName)
	}
	n, err := e.getNode(e.ctx, a, nodeID)
	if err != nil {
		e.fatalf("%v", err)
	}
	if n.GetAgentVersion() != nodeVersion {
		e.errorf("the agent runs %s, want %s: the version of the image", n.GetAgentVersion(), nodeVersion)
	}
	e.logf("the bootstrap reserved the ports 20000-40999 (%s) and installed %s; the agent runs %s",
		strings.TrimSpace(string(reserved)), current, n.GetAgentVersion())
}

// portsCover reports whether the list of the kernel's reserved ports (ports
// and ranges apart by commas, as /proc prints them) covers lo to hi.
func portsCover(list string, lo, hi int) bool {
	type span struct{ lo, hi int }
	var spans []span
	for _, item := range strings.Split(strings.TrimSpace(list), ",") {
		if item == "" {
			continue
		}
		a, b, isRange := strings.Cut(item, "-")
		if !isRange {
			b = a
		}
		x, err1 := strconv.Atoi(a)
		y, err2 := strconv.Atoi(b)
		if err1 != nil || err2 != nil {
			return false
		}
		spans = append(spans, span{x, y})
	}
	slices.SortFunc(spans, func(p, q span) int { return p.lo - q.lo })
	next := lo // the first port not covered yet
	for _, s := range spans {
		if s.lo > next {
			break
		}
		if s.hi >= next {
			next = s.hi + 1
		}
		if next > hi {
			return true
		}
	}
	return false
}
