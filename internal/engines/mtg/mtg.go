// Package mtg is the engines.Driver for mtg v2 (https://github.com/9seconds/mtg),
// the Go MTProto proxy, a second engine for fake-TLS proxies beside telemt.
//
// The official static release binary runs in a stock Alpine container on the
// host network, the way the telemt driver runs telemt. It listens on 127.0.0.1
// only, behind the node's own edge router, which hands it every connection
// with a PROXY protocol v2 header. The container is unprivileged: user 65534,
// read-only root file system, no capabilities, a small tmpfs. mtg keeps
// nothing on disk, so the instance directory, which holds only the config, is
// mounted read-only.
//
// mtg is given the full "ee" secret of the proxy's link, so a proxy that moves
// between telemt and mtg keeps its link. It has no middle proxy and no promo
// tag: a proxy that uses either is refused, and stays on telemt (spec 5.5).
//
// Where mtg v2.2.8 connects with the config of this driver:
//
//   - To Telegram, through its [network] proxies: the edge's SOCKS port of the
//     proxy, one SOCKS network for the single entry (makeNetwork in
//     internal/cli/run_proxy.go).
//   - To its fronting target, where it passes every connection that is not a
//     client of the proxy (a wrong secret, a browser, a prober): directly from
//     the node, not through its proxies. Proxy.doDomainFronting dials with
//     Network.NativeDialer, "a configured instance of native dialer that skips
//     proxy connections" (mtglib/proxy.go, mtglib/init.go), and the SOCKS
//     network does not override it (network/v2/proxy_network.go). So the
//     target is never mtg's to choose (Ruling S5-10): the agent passes it as
//     Instance.FrontingAddr, the address of the mask target override or an
//     address of the proxy domain that it resolved; Render holds it to the
//     edge's destination policy (only a public address), refuses to render
//     without it, and always names it in the config ([domain-fronting] ip and
//     port), so that mtg resolves no name and picks no address itself.
//   - Nowhere else: no block list download, no lookup of its public address, no
//     configuration updates from Telegram, no doppelganger crawl.
package mtg

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
)

// DefaultVersion is the mtg release the node runs unless the panel names
// another one: the upstream tag, with its v.
const DefaultVersion = "v2.2.8"

// Driver runs mtg. It holds no state: one value serves every instance.
type Driver struct{}

// New returns the mtg driver.
func New() *Driver { return &Driver{} }

var (
	_ engines.Driver  = Driver{}
	_ engines.Trialer = Driver{}
)

// Engine is ENGINE_MTG.
func (Driver) Engine() nodev1.Engine { return nodev1.Engine_ENGINE_MTG }

// Supports reports fake-TLS proxies only: mtg serves nothing else.
func (Driver) Supports(t nodev1.ProxyType) bool {
	return t == nodev1.ProxyType_PROXY_TYPE_FAKETLS
}

// AssetName is the name of the release file of an mtg version for a CPU
// architecture ("amd64" or "arm64"): mtg-<version without v>-linux-<arch>.tar.gz,
// a .tar.gz with the static binary at mtg-<version>-linux-<arch>/mtg. version is
// the upstream tag, for example "v2.2.8".
func AssetName(version, arch string) (string, error) {
	n := strings.TrimPrefix(version, "v")
	if !validVersion(n) {
		return "", fmt.Errorf("mtg: %.64q is not a release version", version)
	}
	switch arch {
	case "amd64", "arm64":
		return "mtg-" + n + "-linux-" + arch + ".tar.gz", nil
	}
	return "", fmt.Errorf("mtg: no release for architecture %q (want amd64 or arm64)", arch)
}

// validVersion accepts a version without its v: 1 to 64 characters of
// [0-9A-Za-z.+-] that start with a digit, so that it is safe in a file name
// and a URL and matches the artifact store's rules for a path element.
func validVersion(n string) bool {
	if n == "" || len(n) > 64 || n[0] < '0' || n[0] > '9' {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '.' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

// ArtifactFile is the release file of DefaultVersion for a CPU architecture.
func (Driver) ArtifactFile(arch string) (string, error) { return AssetName(DefaultVersion, arch) }

// BinaryName is "mtg".
func (Driver) BinaryName() string { return "mtg" }

// Render returns the config of the instance: one file, config.toml. It contains
// the proxy secret, so it must be written private. A proxy that mtg cannot
// serve (see the package documentation and renderFakeTLS) is an error, and the
// error never holds a secret.
func (Driver) Render(in engines.Instance) (map[string][]byte, error) {
	cfg, err := renderFakeTLS(in)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{configFile: cfg}, nil
}

// Container describes the container the instance runs in:
//
//	postern-eng-<proxy id, lower case>-g<generation>
//
// from the runner image, as user 65534 on the host network, with a read-only
// root file system, no capabilities, no new privileges, a 16 MiB /tmp, 256 MiB of
// memory and 256 processes. The binary and the instance directory are mounted
// read-only, and mtg is started with "run /etc/mtg/config.toml". Check the two
// host paths with Instance.CheckHostPaths before creating it.
func (Driver) Container(in engines.Instance) dockerapi.ContainerSpec {
	id := cmp.Or(in.Proxy.GetId(), in.InstanceID)
	gen := strconv.FormatUint(in.Generation, 10)
	return dockerapi.ContainerSpec{
		Name:          "postern-eng-" + strings.ToLower(id) + "-g" + gen,
		Image:         in.RunnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		Entrypoint:    []string{binaryMount, "run", configMount},
		Binds: []string{
			in.BinaryPath + ":" + binaryMount + ":ro",
			in.InstanceDir + ":" + instanceMount + ":ro",
		},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels: map[string]string{
			"postern.managed":    "true",
			"postern.role":       "engine",
			"postern.id":         id,
			"postern.generation": gen,
		},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=16m"},
		ReadOnly:    true,
		MemoryBytes: 256 << 20,
		PidsLimit:   256,
		LogMaxSize:  "5m",
		LogMaxFile:  2,
	}
}

// ---- trial --------------------------------------------------------------------

// Trial runs the binary with --version, which prints the version that the
// release build set, without its v, and the build information, and exits with
// 0 before any config is read. For v2.2.8 (getVersion in buildinfo.go):
//
//	2.2.8 (go1.26.1: 2026-04-07T16:10:41Z on 83a31e0…, modules checksum …)
//
// Output wants the version as a whole word of the output, with or without a v
// in front, in case a release prints its tag: 2.2.8 is not found in 2.2.80, in
// 2.2.8-rc.1 or in vv2.2.8. A version that AssetName would not take (empty,
// not valid UTF-8, with characters that a version does not have) matches
// nothing.
func (Driver) Trial(version string) engines.Trial {
	n := strings.TrimPrefix(version, "v")
	output := regexp.MustCompile(`[^\x00-\x{10FFFF}]`) // matches nothing
	if validVersion(n) {
		const edge = `[^0-9A-Za-z.+-]`
		output = regexp.MustCompile(`(?:^|` + edge + `)v?` + regexp.QuoteMeta(n) + `(?:` + edge + `|$)`)
	}
	return engines.Trial{Args: []string{"--version"}, ExitCode: 0, Output: output}
}

// ---- readiness ----------------------------------------------------------------

// maxReadyBody bounds what Ready reads of the statistics: the page of a running
// mtg is a few kilobytes.
const maxReadyBody = 1 << 20

// The time Ready gives each of its two steps, so that an engine that accepts
// the connection and then says nothing cannot hold a polling loop for longer
// than its own deadline allows. Variables for the tests.
var (
	readyDialTimeout    = 2 * time.Second
	readyRequestTimeout = 5 * time.Second
)

// statsClient talks to the statistics endpoint on loopback: no proxy from the
// environment, no redirects (mtg never sends one), no connection reuse.
var statsClient = &http.Client{
	Transport: &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Ready checks that mtg accepts connections: a TCP connection to the proxy
// port, 127.0.0.1:<ListenPort>, within 2 s, closed at once; then GET
// http://127.0.0.1:<APIPort>/, the Prometheus statistics, which has to answer
// 200 with at most 1 MiB within 5 s. mtg opens the statistics endpoint before
// the proxy port, so the endpoint alone does not tell. It makes a single
// attempt and does not wait: callers poll.
//
// mtg passes the empty connection to its fronting target like any connection
// that does not start with a client's handshake, so each check that gets
// through the first step makes one connection from the node to that target.
func (Driver) Ready(ctx context.Context, in engines.Instance) error {
	if in.ListenPort == 0 {
		return errors.New("mtg: no listen port")
	}
	if in.APIPort == 0 {
		return errors.New("mtg: no statistics port")
	}

	dialCtx, cancel := context.WithTimeout(ctx, readyDialTimeout)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", loopback(in.ListenPort))
	cancel()
	if err != nil {
		return fmt.Errorf("mtg: the proxy port does not accept connections: %w", err)
	}
	_ = conn.Close()

	ctx, cancel = context.WithTimeout(ctx, readyRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+loopback(in.APIPort)+"/", nil)
	if err != nil {
		return fmt.Errorf("mtg: %w", err)
	}
	resp, err := statsClient.Do(req)
	if err != nil {
		return fmt.Errorf("mtg: statistics: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mtg: the statistics endpoint answered HTTP %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxReadyBody+1))
	if err != nil {
		return fmt.Errorf("mtg: statistics: reading the answer: %w", err)
	}
	if n > maxReadyBody {
		return fmt.Errorf("mtg: the statistics endpoint answered with more than %d bytes: is something else on its port?", maxReadyBody)
	}
	return nil
}

// loopback is 127.0.0.1:<port>.
func loopback(port uint16) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}
