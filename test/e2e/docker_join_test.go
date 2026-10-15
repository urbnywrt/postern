//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
)

// TestDockerJoin installs a node with the one Docker command of the panel
// (docs/design/2026-10-08-node-docker-join.md), from the node image of the run
// that scripts/e2e.sh builds from the installed node binary
// (POSTERN_E2E_NODE_IMAGE):
//
//  1. the panel runs with POSTERN_NODE_IMAGE set to the image; a node is
//     created (management at 127.0.0.1), and CreateJoinToken for the panel at
//     http://127.0.0.1:<port> renders the docker command and the compose file
//     of the design, word for word;
//  2. the container of the command is started (the node's directory of the
//     test in place of /opt/postern, at the same path, with POSTERN_HOME): the
//     bootstrap joins, and the node comes online. The panel keeps no key of
//     the node, so its bundle is a 409; the audit log has one node.join; the
//     kernel's reserved ports cover 20000-40999 (the sysctl helper); bin/current
//     is the binary of the image, which the agent runs;
//  3. the container restarts: the node is online again with the same keys,
//     and no new join;
//  4. a new token for the same node, and the container of its command in
//     place of the old one: the node joins again (two node.join), with the same
//     node id and a new certificate, and the panel works with it: a listener
//     made after the join is applied on the node;
//  5. no log of the run holds the tokens.
//
// No step needs Telegram or GitHub beyond what newEnv checks.
func TestDockerJoin(t *testing.T) {
	e := newEnv(t)
	image := os.Getenv("POSTERN_E2E_NODE_IMAGE")
	if image == "" {
		e.skipf("POSTERN_E2E_NODE_IMAGE is not set: scripts/e2e.sh builds the node image of the run")
	}
	if ok, err := e.docker.ImageExists(e.ctx, image); err != nil || !ok {
		e.fatalf("the node image %s is not on the Docker daemon (%v): scripts/e2e.sh builds it", image, err)
	}

	// 1. The panel, the node and the command.
	p := e.startPanel("POSTERN_NODE_IMAGE=" + image)
	a := newAPI(p.base)
	e.signIn(a, p.token)
	mgmtPort := e.freePort("0.0.0.0", 61000, 65535)
	created, err := a.nodes.CreateNode(e.ctx, connect.NewRequest(&panelv1.CreateNodeRequest{
		Name: "e2e-docker-" + e.run, MgmtHost: "127.0.0.1", MgmtPort: uint32(mgmtPort), LinkHost: linkHost,
	}))
	if err != nil {
		e.fatalf("CreateNode: %v", err)
	}
	nodeID := created.Msg.GetNode().GetId()
	e.logf("node %s created, management port %d", nodeID, mgmtPort)
	inst, err := a.nodes.GetNodeInstall(e.ctx, connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: nodeID}))
	if err != nil {
		e.fatalf("GetNodeInstall: %v", err)
	}
	if inst.Msg.GetNodeImage() != image {
		e.fatalf("GetNodeInstall gives the node image %q, want %q", inst.Msg.GetNodeImage(), image)
	}
	panelURL := p.base // http://127.0.0.1:<port>: loopback, so http is accepted
	token := e.joinCommand(a, nodeID, panelURL, image)

	// 2. The container of the command: the join, and what the bootstrap did.
	e.startJoining(image, panelURL, token)
	e.watchLogs()
	e.waitJoined(a, nodeID, 1)
	if code := e.bundleStatus(a, created.Msg.GetBundleUrl()); code != http.StatusConflict {
		e.errorf("the bundle of the joined node: %d, want 409: the panel has no key of it", code)
	}
	rows, err := e.joinRows(e.ctx, a, nodeID)
	if err != nil {
		e.fatalf("%v", err)
	}
	if v := rows[0].GetDetails()["version"]; v != nodeVersion {
		e.errorf("the node.join row says version %q, want %s", v, nodeVersion)
	}
	first := e.nodeIdentity()
	if first.id != nodeID {
		e.errorf("data/state/node-id is %s, want %s", first.id, nodeID)
	}
	if first.tokenHash != sha256Hex(token) {
		e.errorf("data/state/join-token.sha256 is not the SHA-256 of the token of the command")
	}
	e.checkInstalled(a, nodeID)

	// 3. A restart of the container: the same keys, no join.
	marker, ok := e.healthyMarker(e.ctx)
	if !ok {
		e.fatalf("the agent has not written the launcher's healthy marker")
	}
	e.restartAgent()
	e.waitHealthy(marker, 2*time.Minute, "the restart of the container")
	e.waitJoined(a, nodeID, 1)
	if again := e.nodeIdentity(); again != first {
		e.errorf("the restart changed the identity of the node: the bootstrap joined again")
	}
	e.logf("after the restart of the container the node is online with the keys of its join")

	// 4. A new token for the same node, and its command.
	marker, ok = e.healthyMarker(e.ctx)
	if !ok {
		e.fatalf("the agent has not written the launcher's healthy marker")
	}
	token2 := e.joinCommand(a, nodeID, panelURL, image)
	if token2 == token {
		e.fatalf("CreateJoinToken gave the same token twice")
	}
	e.startJoining(image, panelURL, token2)
	e.waitHealthy(marker, 3*time.Minute, "the container of the new command")
	e.waitJoined(a, nodeID, 2)
	second := e.nodeIdentity()
	switch {
	case second.id != nodeID:
		e.errorf("after the new join data/state/node-id is %s, want %s", second.id, nodeID)
	case second.tokenHash != sha256Hex(token2):
		e.errorf("after the new join data/state/join-token.sha256 is not the SHA-256 of the new token")
	case second.certHash == first.certHash:
		e.errorf("the new join kept the certificate of the first: the node did not join again")
	}
	list, err := a.nodes.ListNodes(e.ctx, connect.NewRequest(&panelv1.ListNodesRequest{}))
	if err != nil {
		e.fatalf("ListNodes: %v", err)
	}
	if n := len(list.Msg.GetNodes()); n != 1 {
		e.errorf("the panel has %d nodes after the new join, want 1", n)
	}
	lport := e.freePort("127.0.0.1", 10000, 19999)
	desired := e.change(a, nodeID, "CreateListener", func(ctx context.Context) error {
		_, err := a.listeners.CreateListener(ctx, connect.NewRequest(&panelv1.CreateListenerRequest{
			NodeId: nodeID, Kind: "tls", BindIp: "127.0.0.1", Port: uint32(lport),
		}))
		return err
	})
	e.waitFor(fmt.Sprintf("generation %d on the node", desired), 2*time.Minute, time.Second,
		func(ctx context.Context) (bool, string, error) {
			n, err := e.getNode(ctx, a, nodeID)
			if err != nil {
				return false, "", err
			}
			return n.GetStatus() == "online" && n.GetAppliedGeneration() >= desired,
				fmt.Sprintf("node %s, generation %d applied", n.GetStatus(), n.GetAppliedGeneration()), nil
		})
	e.logf("the node joined again with the new token: the same node id, a new certificate, and the panel works with it")

	// 5. No token in any log.
	if err := p.stop(15 * time.Second); err != nil {
		e.errorf("the panel did not stop cleanly with a node connected: %v", err)
	}
	e.checkLogsOf([]string{"agent"})
}
