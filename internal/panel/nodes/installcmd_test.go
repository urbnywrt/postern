package nodes

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/ids"
)

const (
	testImage = "ghcr.io/owner/postern-node:v1.2.3"
	testURL   = "https://panel.example.com"
	testToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// The docker run and the compose file of the plan, word for word.
const (
	wantDockerCommand = `docker run -d --name postern-agent --restart unless-stopped \
  --network host --pid host --read-only --tmpfs /tmp \
  --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /opt/postern:/opt/postern \
  -v /etc/os-release:/host/etc/os-release:ro \
  -e POSTERN_JOIN='https://panel.example.com#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
  ghcr.io/owner/postern-node:v1.2.3`

	wantCompose = `name: postern
services:
  postern-agent:
    image: ghcr.io/owner/postern-node:v1.2.3
    container_name: postern-agent
    restart: unless-stopped
    network_mode: host
    pid: host
    read_only: true
    tmpfs:
      - /tmp
    environment:
      POSTERN_JOIN: "https://panel.example.com#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /opt/postern:/opt/postern
      - /etc/os-release:/host/etc/os-release:ro
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
`
)

func TestRenderInstall(t *testing.T) {
	if got := RenderDockerCommand(testImage, testURL, testToken); got != wantDockerCommand {
		t.Errorf("RenderDockerCommand =\n%s\nwant\n%s", got, wantDockerCommand)
	}
	if got := RenderCompose(testImage, testURL, testToken); got != wantCompose {
		t.Errorf("RenderCompose =\n%s\nwant\n%s", got, wantCompose)
	}
}

func TestResolveNodeImage(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("ab", 32)
	for _, c := range []struct{ ref, version, want string }{
		{"", "v1.2.3", ""},
		{"", "dev", ""},
		{"ghcr.io/owner/postern-node", "v1.2.3", "ghcr.io/owner/postern-node:v1.2.3"},
		{"ghcr.io/owner/postern-node", "dev", ""},
		{"ghcr.io/owner/postern-node:v1.0.0", "dev", "ghcr.io/owner/postern-node:v1.0.0"},
		{"ghcr.io/owner/postern-node:v1.0.0", "v1.2.3", "ghcr.io/owner/postern-node:v1.0.0"},
		{"ghcr.io/owner/postern-node" + digest, "v1.2.3", "ghcr.io/owner/postern-node" + digest},
		{"ghcr.io/owner/postern-node:latest" + digest, "dev", "ghcr.io/owner/postern-node:latest" + digest},
		{"localhost:5000/postern-node", "v1.2.3", "localhost:5000/postern-node:v1.2.3"},
		{"postern-node:Edge_1", "dev", "postern-node:Edge_1"},
		{"owner/postern__node", "1.2.3-rc.1", "owner/postern__node:1.2.3-rc.1"},
		// A version that cannot be a tag gives no image, as dev does.
		{"ghcr.io/owner/postern-node", "1.2.3+build", ""},
		{"ghcr.io/owner/postern-node:v1", "1.2.3+build", "ghcr.io/owner/postern-node:v1"},
	} {
		got, err := ResolveNodeImage(c.ref, c.version)
		if err != nil || got != c.want {
			t.Errorf("ResolveNodeImage(%q, %q) = %q, %v; want %q", c.ref, c.version, got, err, c.want)
		}
	}
	for _, c := range []struct{ ref, version string }{
		{"GHCR.io/owner/postern-node", "v1"},
		{"ghcr.io/Owner/postern-node", "v1"},
		{"ghcr.io/owner/postern-node:", "v1"},
		{"ghcr.io/owner/postern-node:-x", "v1"},
		{"ghcr.io/owner/postern-node:" + strings.Repeat("a", 129), "v1"},
		{"ghcr.io/owner/postern-node@sha256:abc", "v1"},
		{"ghcr.io/owner/postern-node" + digest[:len(digest)-1] + "G", "v1"},
		{"ghcr.io/owner/postern-node:v1 ", "v1"},
		{"ghcr.io/owner/postern-node;rm", "v1"},
		{"ghcr.io/owner/postern-node$(id)", "v1"},
		{"ghcr.io//postern-node", "v1"},
		{"/postern-node", "v1"},
		{"https://ghcr.io/owner/postern-node", "v1"},
	} {
		if got, err := ResolveNodeImage(c.ref, c.version); err == nil {
			t.Errorf("ResolveNodeImage(%q, %q) = %q, want an error", c.ref, c.version, got)
		}
	}
}

// CheckPanelURL is the rule of panelurl, whose test has the cases.
func TestCheckPanelURL(t *testing.T) {
	if got, err := CheckPanelURL("HTTPS://Panel.Example.COM:8443/"); err != nil || got != "https://panel.example.com:8443" {
		t.Errorf("CheckPanelURL = %q, %v", got, err)
	}
	if _, err := CheckPanelURL("http://panel.example.com"); err == nil {
		t.Error("CheckPanelURL took plain HTTP to a remote panel")
	}
}

// What CheckPanelURL and the tokens let through is safe between the quotes of
// the rendered texts: no quote, space, backslash or other special character.
func TestRenderedValuesAreSafeToQuote(t *testing.T) {
	const unsafe = "'\" \\\t\n$`#?&;|<>(){}*!"
	for _, in := range []string{"HTTPS://Panel.Example.COM:8443/", "http://[::1]:8080", "https://192.0.2.10"} {
		got, err := CheckPanelURL(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(got, unsafe) {
			t.Errorf("CheckPanelURL(%q) = %q has an unsafe character", in, got)
		}
	}
	p := newJoinPanel(t)
	n := p.newNode("")
	for range 20 {
		token := p.mint(n.ID)
		if strings.ContainsAny(token, unsafe) || strings.Trim(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			t.Fatalf("token %q has a character outside base64url", token)
		}
	}
	// And the image: no shell or YAML syntax in a valid reference.
	for _, ref := range []string{"ghcr.io/owner/postern-node", "localhost:5000/a/b:Tag_1.x-y"} {
		got, err := ResolveNodeImage(ref, "v1.2.3")
		if err != nil || strings.ContainsAny(got, unsafe) {
			t.Errorf("ResolveNodeImage(%q) = %q, %v", ref, got, err)
		}
	}
}

func TestCreateJoinToken(t *testing.T) {
	ctx := context.Background()
	a := newAPI(t, WithNodeImage(testImage))
	id := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443}).GetNode().GetId()

	resp, err := a.nodes.CreateJoinToken(ctx, connect.NewRequest(&panelv1.CreateJoinTokenRequest{NodeId: id, PanelUrl: "HTTPS://Panel.Example.com/"}))
	if err != nil {
		t.Fatalf("CreateJoinToken: %v", err)
	}
	m := resp.Msg
	if raw, err := base64.RawURLEncoding.DecodeString(m.GetToken()); err != nil || len(raw) != 32 {
		t.Fatalf("token %q is not 32 bytes of base64url", m.GetToken())
	}
	if d := time.Until(time.Unix(m.GetExpiresUnix(), 0)) - 24*time.Hour; d > time.Minute || d < -time.Minute {
		t.Errorf("expires_unix %d is not 24 hours away", m.GetExpiresUnix())
	}
	if m.GetImage() != testImage {
		t.Errorf("image = %q, want %q", m.GetImage(), testImage)
	}
	if want := RenderDockerCommand(testImage, testURL, m.GetToken()); m.GetDockerCommand() != want {
		t.Errorf("docker_command =\n%s\nwant\n%s", m.GetDockerCommand(), want)
	}
	if want := RenderCompose(testImage, testURL, m.GetToken()); m.GetComposeYaml() != want {
		t.Errorf("compose_yaml =\n%s\nwant\n%s", m.GetComposeYaml(), want)
	}
	// The token is the node's: Join takes it.
	if stored, err := a.db.JoinTokenOf(ctx, id); err != nil || stored.ExpiresAt.Unix() != m.GetExpiresUnix() {
		t.Errorf("stored token = %+v, %v", stored, err)
	}
	if got := a.audit(); len(got) != 2 || got[1] != "node.join_token node:"+id+" "+a.adminID {
		t.Errorf("audit log = %q", got)
	}
	if strings.Contains(a.logs.String(), m.GetToken()) {
		t.Error("the token is in the log")
	}

	install, err := a.nodes.GetNodeInstall(ctx, connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: id}))
	if err != nil || install.Msg.GetNodeImage() != testImage {
		t.Errorf("GetNodeInstall node_image = %q, %v; want %q", install.Msg.GetNodeImage(), err, testImage)
	}

	for _, c := range []struct {
		name string
		req  *panelv1.CreateJoinTokenRequest
		code connect.Code
	}{
		{"a panel URL with a path", &panelv1.CreateJoinTokenRequest{NodeId: id, PanelUrl: "https://panel.example.com/x"}, connect.CodeInvalidArgument},
		{"plain http to a public host", &panelv1.CreateJoinTokenRequest{NodeId: id, PanelUrl: "http://panel.example.com"}, connect.CodeInvalidArgument},
		{"no panel URL", &panelv1.CreateJoinTokenRequest{NodeId: id}, connect.CodeInvalidArgument},
		{"an unknown node", &panelv1.CreateJoinTokenRequest{NodeId: ids.New(), PanelUrl: testURL}, connect.CodeNotFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := a.nodes.CreateJoinToken(ctx, connect.NewRequest(c.req))
			wantCode(t, err, c.code)
		})
	}
	// A refused call makes no token: the one that the node has still works.
	live, err := a.db.JoinTokenByHash(ctx, joinTokenHash(m.GetToken()))
	if err != nil || live.NodeID != id || live.Used() || !live.ExpiresAt.After(time.Now()) {
		t.Errorf("the token after the refused calls = %+v, %v; want the node's, live", live, err)
	}
	_, err = a.anon.CreateJoinToken(ctx, connect.NewRequest(&panelv1.CreateJoinTokenRequest{NodeId: id, PanelUrl: testURL}))
	wantCode(t, err, connect.CodeUnauthenticated)
	// Without the middleware too: the service checks for an admin itself.
	_, err = a.svc.CreateJoinToken(ctx, connect.NewRequest(&panelv1.CreateJoinTokenRequest{NodeId: id, PanelUrl: testURL}))
	wantCode(t, err, connect.CodeUnauthenticated)
	if got := len(a.audit()); got != 2 {
		t.Errorf("%d audit entries after the refused calls, want 2", got)
	}
}

func TestCreateJoinTokenWithoutAnImage(t *testing.T) {
	ctx := context.Background()
	a := newAPI(t)
	id := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443}).GetNode().GetId()
	_, err := a.nodes.CreateJoinToken(ctx, connect.NewRequest(&panelv1.CreateJoinTokenRequest{NodeId: id, PanelUrl: testURL}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if err == nil || !strings.Contains(err.Error(), "POSTERN_NODE_IMAGE") {
		t.Errorf("the error does not name POSTERN_NODE_IMAGE: %v", err)
	}
	if _, err := a.db.JoinTokenOf(ctx, id); err == nil {
		t.Error("a token was made without an image")
	}
	install, err := a.nodes.GetNodeInstall(ctx, connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: id}))
	if err != nil || install.Msg.GetNodeImage() != "" {
		t.Errorf("GetNodeInstall node_image = %q, %v; want none", install.Msg.GetNodeImage(), err)
	}
}
