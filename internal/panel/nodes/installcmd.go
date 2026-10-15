package nodes

import (
	"context"
	"errors"
	"regexp"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panelurl"
)

// The one-command install of a node: the panel makes a join token
// ([Service.MintJoinToken]) and renders a docker run of the node image that
// carries it, or the same as a compose file. The node joins with the token and
// a key of its own ([Service.Join]). Only the panel renders the two texts: the
// UI and the install over SSH take them as they are.

// devVersion is the version of a build that is no release: it names no image.
const devVersion = "dev"

// imageRefRe is the syntax of a Docker image reference that the panel takes:
// lower-case registry and path components, an optional tag and an optional
// sha256 digest. It is stricter than Docker in that the registry is
// lower-case too, and it keeps the reference free of anything that a shell or
// YAML would read otherwise. Group 1 is the tag, group 2 the digest.
var imageRefRe = regexp.MustCompile(`^` +
	`(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]{1,5})?/)?` + // registry
	`[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*` + // path
	`(?::([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?` + // tag
	`(@sha256:[0-9a-f]{64})?$`) // digest

// tagRe is the syntax of a tag alone.
var tagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// maxImageRefLen bounds a reference: a name of at most 255 characters, a tag
// and a digest.
const maxImageRefLen = 255 + 1 + 128 + 1 + 71

// ResolveNodeImage is the node image that the panel installs nodes from, for
// the configured reference ref (POSTERN_NODE_IMAGE, or else
// version.NodeImage) and the version of the panel: ref as it is when it has a
// tag or a digest, else ref with the tag of the version, and "" (no image, so
// no one-command install) for an empty ref, or a ref without a tag when the
// version is dev or cannot be a tag (see [NodeImageNeedsTag]). An error says
// what is wrong with the syntax of ref.
func ResolveNodeImage(ref, panelVersion string) (string, error) {
	if ref == "" {
		return "", nil
	}
	m := imageRefRe.FindStringSubmatch(ref)
	if m == nil || len(ref) > maxImageRefLen {
		return "", errors.New("it is not a Docker image reference: lower-case name components, then an optional :tag and an optional @sha256:<64 hex digits>, e.g. ghcr.io/<OWNER>/postern-node")
	}
	if m[1] != "" || m[2] != "" {
		return ref, nil
	}
	if panelVersion == devVersion || !tagRe.MatchString(panelVersion) {
		return "", nil
	}
	return ref + ":" + panelVersion, nil
}

// NodeImageNeedsTag tells whether ref is a valid reference without a tag or a
// digest that [ResolveNodeImage] turns into no image because the version of
// the panel, which is not dev, cannot be a tag (e.g. 1.2.3+build): the
// operator should be told to give the tag.
func NodeImageNeedsTag(ref, panelVersion string) bool {
	m := imageRefRe.FindStringSubmatch(ref)
	return m != nil && len(ref) <= maxImageRefLen && m[1] == "" && m[2] == "" &&
		panelVersion != devVersion && !tagRe.MatchString(panelVersion)
}

// CheckPanelURL checks the address that a node reaches the panel at and
// returns it in its normal form: see [panelurl.Check], which is the rule.
func CheckPanelURL(raw string) (string, error) { return panelurl.Check(raw) }

// RenderDockerCommand is the docker run that installs a node from image,
// joining the panel at panelURL with token. panelURL comes from
// [CheckPanelURL] and token from [Service.MintJoinToken], so that neither has
// a quote, a space or a backslash. The text has no final newline.
func RenderDockerCommand(image, panelURL, token string) string {
	return "docker run -d --name postern-agent --restart unless-stopped \\\n" +
		"  --network host --pid host --read-only --tmpfs /tmp \\\n" +
		"  --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \\\n" +
		"  -v /var/run/docker.sock:/var/run/docker.sock \\\n" +
		"  -v /opt/postern:/opt/postern \\\n" +
		"  -v /etc/os-release:/host/etc/os-release:ro \\\n" +
		"  -e POSTERN_JOIN='" + panelURL + "#" + token + "' \\\n" +
		"  " + image
}

// RenderCompose is the compose file that does what [RenderDockerCommand]
// does, ending in a newline.
func RenderCompose(image, panelURL, token string) string {
	return "name: postern\n" +
		"services:\n" +
		"  postern-agent:\n" +
		"    image: " + image + "\n" +
		"    container_name: postern-agent\n" +
		"    restart: unless-stopped\n" +
		"    network_mode: host\n" +
		"    pid: host\n" +
		"    read_only: true\n" +
		"    tmpfs:\n" +
		"      - /tmp\n" +
		"    environment:\n" +
		"      POSTERN_JOIN: \"" + panelURL + "#" + token + "\"\n" +
		"    volumes:\n" +
		"      - /var/run/docker.sock:/var/run/docker.sock\n" +
		"      - /opt/postern:/opt/postern\n" +
		"      - /etc/os-release:/host/etc/os-release:ro\n" +
		"    logging:\n" +
		"      driver: json-file\n" +
		"      options:\n" +
		"        max-size: 10m\n" +
		"        max-file: \"3\"\n"
}

// WithNodeImage gives the panel the node image that it installs nodes from,
// as [ResolveNodeImage] resolved it; empty for none, which leaves the panel
// without the one-command install.
func WithNodeImage(image string) Option {
	return func(s *Service) { s.nodeImage = image }
}

// NodeImage is the node image that the panel installs nodes from (see
// [WithNodeImage]); empty when it has none.
func (s *Service) NodeImage() string { return s.nodeImage }

// errNoNodeImage is the answer of CreateJoinToken when the panel has no node
// image.
var errNoNodeImage = connect.NewError(connect.CodeFailedPrecondition,
	errors.New("the panel has no node image to install nodes from: set POSTERN_NODE_IMAGE to the image, with a tag in a dev build (e.g. ghcr.io/<OWNER>/postern-node:v1.2.3)"))

// CreateJoinToken makes a join token for a node and renders the command that
// installs the node with it, and the same as a compose file. The token is in
// the response only.
func (s *Service) CreateJoinToken(ctx context.Context, req *connect.Request[panelv1.CreateJoinTokenRequest]) (*connect.Response[panelv1.CreateJoinTokenResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.nodeImage == "" {
		return nil, errNoNodeImage
	}
	panelURL, err := CheckPanelURL(req.Msg.GetPanelUrl())
	if err != nil {
		return nil, invalid("panel_url: %v", err)
	}
	token, expires, err := s.MintJoinToken(ctx, req.Msg.GetNodeId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.CreateJoinTokenResponse{
		Token:         token,
		ExpiresUnix:   expires.Unix(),
		DockerCommand: RenderDockerCommand(s.nodeImage, panelURL, token),
		ComposeYaml:   RenderCompose(s.nodeImage, panelURL, token),
		Image:         s.nodeImage,
	}), nil
}
