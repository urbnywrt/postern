// Package xray is the providers.Driver for Xray-core
// (https://github.com/XTLS/Xray-core), pinned at v26.3.27. It serves the egress
// kinds XRAY_URI (one share link), XRAY_SUBSCRIPTION (the servers of a
// subscription) and WARP (Xray's WireGuard outbound with an account of package
// providers/warp, Ruling S2-4).
//
// One Xray process serves every member of an egress: per member a SOCKS5 inbound
// on 127.0.0.1, routed to the member's own outbound. The official release binary
// runs in the stock runner image on the host network, unprivileged.
//
// A member Xray would refuse is refused by Render first, with a
// *providers.MemberError that names the member and the field: Xray refuses a
// config as a whole, so one bad member of a subscription would take the others
// down with it. The checks are those of Xray v26.3.27, from its source (see
// config.go); the integration test runs what Render makes, and what it refuses,
// through the real binary (xray run -test).
package xray

import (
	"context"
	"fmt"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/providers"
)

// Driver runs Xray. It holds no state: one value serves every instance.
type Driver struct{}

// New returns the Xray driver.
func New() *Driver { return &Driver{} }

var _ providers.Driver = Driver{}

// Kinds are XRAY_URI, XRAY_SUBSCRIPTION and WARP.
func (Driver) Kinds() []nodev1.EgressKind {
	return []nodev1.EgressKind{
		nodev1.EgressKind_EGRESS_KIND_XRAY_URI,
		nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
		nodev1.EgressKind_EGRESS_KIND_WARP,
	}
}

// ArtifactFile is the release file for a CPU architecture: a zip with the xray
// binary in it (and geo data files this driver does not use). Its checksum is
// the SHA2-256 line of the release's .dgst file.
func (Driver) ArtifactFile(arch string) (string, error) {
	switch arch {
	case "amd64":
		return "Xray-linux-64.zip", nil
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	}
	return "", fmt.Errorf("xray: no release for architecture %q (want amd64 or arm64)", arch)
}

// BinaryName is "xray".
func (Driver) BinaryName() string { return "xray" }

var _ engines.Trialer = Driver{}

// Trial is `xray version`: exit code 0 and an output that starts with
// "Xray <n> (" (core.VersionStatement: `Xray <version> (<codename>) ...`),
// where n is the version without its leading v. A version that is not a plain
// version string matches nothing.
func (Driver) Trial(version string) engines.Trial {
	return engines.Trial{Args: []string{"version"}, ExitCode: 0, Output: providers.VersionOutput(`^Xray `, version, ` \(`)}
}

// Render returns the config of the instance: one file, config.json. It holds the
// members' credentials (ids, passwords, the WARP private key), so it must be
// written private, readable by the container's user. A member that Xray would
// refuse makes Render fail with a *providers.MemberError for it (see
// providers.MemberErrors); an instance that does not fit its kind, or whose
// members have bad keys or ports, is a plain error. No error holds a credential.
//
// A server address must pass providers.CheckServerAddress: IP literals of the
// loopback, unspecified, link-local and multicast addresses and of cloud
// metadata services are refused, and so are the names of the loopback. Other
// host names are allowed: Xray resolves them when it connects, through the
// resolver of the container (Instance.ResolvConf).
func (Driver) Render(in providers.Instance) (map[string][]byte, error) {
	cfg, err := renderConfig(in)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{configFile: cfg}, nil
}

// Container describes the container the instance runs in (see
// providers.ContainerSpec), with the instance directory read-only and 512 MiB of
// memory, started as
//
//	/opt/engine/xray run -c /etc/egress/config.json
func (Driver) Container(in providers.Instance) dockerapi.ContainerSpec {
	return providers.ContainerSpec(in, providers.ContainerOptions{
		Binary:      "xray",
		Args:        []string{"run", "-c", providers.InstanceMount + "/" + configFile},
		MemoryBytes: 512 << 20,
	})
}

// Ready checks that every member's SOCKS5 port answers the greeting (see
// providers.CheckSOCKS). It makes one check and does not wait.
func (Driver) Ready(ctx context.Context, in providers.Instance) error {
	if err := providers.CheckSOCKS(ctx, in.Members); err != nil {
		return fmt.Errorf("xray: %w", err)
	}
	return nil
}
