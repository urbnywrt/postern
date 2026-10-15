// Package psiphoncore is the providers.Driver for Psiphon's own client, the
// ConsoleClient of psiphon-tunnel-core
// (https://github.com/Psiphon-Labs/psiphon-tunnel-core, GPL-3.0). It serves the
// egress kind PSIPHON: one Psiphon tunnel out of one country, behind one SOCKS5
// port on 127.0.0.1. There is no WARP layer: on a node abroad nothing needs to
// hide the connection to Psiphon, and warp-plus's WARP hop was the part that
// failed (psiphon-research.md).
//
// Postern builds the client itself (Ruling S2-26): a release of Postern builds
// the ConsoleClient from a pinned upstream commit, statically, for linux/amd64
// and linux/arm64 (scripts/psiphon-core.sh), and ships it as a signed artifact
// of the release, psiphon-core-linux-<arch>, whose SHA-256 the panel pins.
// (Psiphon's own prebuilt binary is a UPX-packed glibc program, which the
// runner image cannot run, and there is none for arm64.)
//
// The client runs as a separate program in the stock runner image on the host
// network, unprivileged: Postern does not link it, and stays under its own
// licence. It reads its settings from psiphon.json, which Render writes into the
// instance directory (0600, owned by the container user: FilesOwnedByRunner).
// Its data (the server list, the datastore, the notices) is in the cache
// directory of the generation, which the agent seeds with a copy of the cache
// of the generation before (providers.Instance.CacheDir).
package psiphoncore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/providers"
)

const (
	// Binary is the name the client is stored and run under.
	Binary = "psiphon-core"
	// ConfigFile is the one file Render writes.
	ConfigFile = "psiphon.json"
	// instanceDataDir is the data root inside the container when the instance
	// has no Instance.CacheDir: in the instance directory, which is then
	// read-write.
	instanceDataDir = providers.InstanceMount + "/data"
	// hostDataDir is instanceDataDir on the host, relative to InstanceDir.
	hostDataDir = "data"

	// DefaultPartnerID is the PropagationChannelId and the SponsorId of a
	// client without a Psiphon partner agreement: what warp-plus and Oblivion
	// use (warp-plus v1.2.6 psiphon/p.go). An operator with ids of their own
	// sets them on the egress.
	DefaultPartnerID = "FFFFFFFFFFFFFFFF"

	// The public remote server list, and the key its signature is checked
	// with. Both are copied exactly from warp-plus v1.2.6, psiphon/p.go
	// (https://github.com/bepass-org/warp-plus/blob/v1.2.6/psiphon/p.go), which
	// copied them from Psiphon's own sample configuration.
	remoteServerListURL                = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	remoteServerListSignaturePublicKey = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
	// remoteServerListDownloadFilename is the legacy name of the download.
	// The client of today keeps the download under its data root and reads
	// this name only to move an old download there.
	remoteServerListDownloadFilename = "remote_server_list"

	// establishTimeout is EstablishTunnelTimeoutSeconds: 0, no limit. The
	// client keeps trying until it has a tunnel, and the agent decides how
	// long a new generation may take to be ready (its ready timeout), so that
	// a slow first start, with the server list still to fetch, is not cut by
	// an exit of the client.
	establishTimeout = 0

	// DataDir is the directory of the client under its data root
	// (psiphon.PsiphonDataDirectoryName), NoticeFiles the rotating notices in
	// it (psiphon.NoticesFilename, psiphon.OldNoticesFilename), which the
	// client writes with -useNoticeFiles. A copy of a cache leaves the notices
	// of the generation before out (StaleFiles).
	DataDir = "ca.psiphon.PsiphonTunnel.tunnel-core"
)

// NoticeFiles are the notices file and the one rotated before it, relative to
// the data root.
var NoticeFiles = []string{DataDir + "/notices", DataDir + "/notices.1"}

// countries are the exit countries a PSIPHON egress takes: those of warp-plus
// v1.2.6 (psiphon/p.go: Countries), which the egresses of a panel already hold.
var countries = []string{
	"AT", "AU", "BE", "BG", "CA", "CH", "CZ", "DE", "DK", "EE", "ES", "FI",
	"FR", "GB", "HR", "HU", "IE", "IN", "IT", "JP", "LV", "NL", "NO", "PL",
	"PT", "RO", "RS", "SE", "SG", "SK", "US",
}

// Countries returns the exit countries, as two upper-case letters.
func Countries() []string { return slices.Clone(countries) }

// partnerID is what a PropagationChannelId or a SponsorId looks like: 16
// upper-case hex digits.
var partnerID = regexp.MustCompile(`^[0-9A-F]{16}$`)

// ValidPartnerID reports whether s is a partner id: 16 hex digits in upper
// case.
func ValidPartnerID(s string) bool { return partnerID.MatchString(s) }

// Driver runs psiphon-tunnel-core. It holds no state: one value serves every
// instance.
type Driver struct{}

// New returns the driver.
func New() *Driver { return &Driver{} }

var _ providers.Driver = Driver{}

// Kinds is PSIPHON.
func (Driver) Kinds() []nodev1.EgressKind {
	return []nodev1.EgressKind{nodev1.EgressKind_EGRESS_KIND_PSIPHON}
}

// ArtifactFile is the binary itself, as a release of Postern ships it:
// psiphon-core-linux-<arch>, for amd64 and arm64.
func (Driver) ArtifactFile(arch string) (string, error) {
	switch arch {
	case "amd64", "arm64":
		return "psiphon-core-linux-" + arch, nil
	}
	return "", fmt.Errorf("psiphon: no client for architecture %q (want amd64 or arm64)", arch)
}

// BinaryName is "psiphon-core", the name of the component in the catalog: the node finds the artifact of a provider by it.
func (Driver) BinaryName() string { return Binary }

// FilesOwnedByRunner says that the rendered files are the container user's,
// 0600 (see providers.RunnerOwnedFiles).
func (Driver) FilesOwnedByRunner() bool { return true }

var _ engines.Trialer = Driver{}

// revision is the source revision at the end of a version: the versions of
// the client are <build date>-<revision>, such as 20261005-c4a09096ab, for the
// binaries are not tagged.
var revision = regexp.MustCompile(`^[0-9]{8}-([0-9a-f]{7,40})$`)

// Trial is `psiphon-core -version`: exit code 0 and the line
// "Revision: <revision>" with the revision of the version. A version that is
// not <date>-<revision> matches nothing.
func (Driver) Trial(version string) engines.Trial {
	m := revision.FindStringSubmatch(version)
	if m == nil {
		return engines.Trial{Args: []string{"-version"}, Output: regexp.MustCompile(`[^\x00-\x{10FFFF}]`)}
	}
	return engines.Trial{Args: []string{"-version"}, Output: regexp.MustCompile(`(?m)^\s*Revision:\s*` + m[1] + `\s*$`)}
}

// config is the configuration of the client: the fields of psiphon.Config it
// is given, in this order.
type config struct {
	LocalSocksProxyPort                int    `json:"LocalSocksProxyPort"`
	ListenInterface                    string `json:"ListenInterface"`
	DisableLocalHTTPProxy              bool   `json:"DisableLocalHTTPProxy"`
	EgressRegion                       string `json:"EgressRegion"`
	PropagationChannelID               string `json:"PropagationChannelId"`
	SponsorID                          string `json:"SponsorId"`
	RemoteServerListURL                string `json:"RemoteServerListUrl"`
	RemoteServerListSignaturePublicKey string `json:"RemoteServerListSignaturePublicKey"`
	RemoteServerListDownloadFilename   string `json:"RemoteServerListDownloadFilename"`
	DataRootDirectory                  string `json:"DataRootDirectory"`
	NetworkID                          string `json:"NetworkID"`
	EstablishTunnelTimeoutSeconds      int    `json:"EstablishTunnelTimeoutSeconds"`
}

// Render checks the instance (a PSIPHON egress with one member, which has
// neither a server nor a WARP account, a country of Countries, and partner
// ids that are both empty or both valid) and returns psiphon.json: the SOCKS5
// port of the member on the loopback ("lo") only, no HTTP proxy, the country,
// the partner ids (DefaultPartnerID when none are set), the public remote
// server list, the data root and no limit to establish a tunnel (0: the agent's ready
// timeout decides).
func (Driver) Render(in providers.Instance) (map[string][]byte, error) {
	if err := check(in); err != nil {
		return nil, err
	}
	prop, sponsor := in.PropagationChannelID, in.SponsorID
	if prop == "" {
		prop, sponsor = DefaultPartnerID, DefaultPartnerID
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(config{
		LocalSocksProxyPort:                int(in.Members[0].Port),
		ListenInterface:                    "lo",
		DisableLocalHTTPProxy:              true,
		EgressRegion:                       strings.ToUpper(in.Country),
		PropagationChannelID:               prop,
		SponsorID:                          sponsor,
		RemoteServerListURL:                remoteServerListURL,
		RemoteServerListSignaturePublicKey: remoteServerListSignaturePublicKey,
		RemoteServerListDownloadFilename:   remoteServerListDownloadFilename,
		DataRootDirectory:                  dataRoot(in),
		NetworkID:                          "postern",
		EstablishTunnelTimeoutSeconds:      establishTimeout,
	}); err != nil {
		return nil, fmt.Errorf("psiphon: %w", err)
	}
	return map[string][]byte{ConfigFile: b.Bytes()}, nil
}

func check(in providers.Instance) error {
	if err := providers.CheckEgressID(in.EgressID); err != nil {
		return fmt.Errorf("psiphon: %w", err)
	}
	if in.Kind != nodev1.EgressKind_EGRESS_KIND_PSIPHON {
		return fmt.Errorf("psiphon: cannot serve an egress of kind %s", in.Kind)
	}
	if err := providers.CheckMembers(in.Members); err != nil {
		return fmt.Errorf("psiphon: %w", err)
	}
	if len(in.Members) != 1 {
		return fmt.Errorf("psiphon: a PSIPHON egress has one member, not %d", len(in.Members))
	}
	if m := in.Members[0]; m.Server != nil || m.WARP != nil {
		return fmt.Errorf("psiphon: member %s of a PSIPHON egress has a server or a WARP account", m.Key)
	}
	if !slices.Contains(countries, strings.ToUpper(in.Country)) {
		return errors.New("psiphon: the country is not one Psiphon can exit in")
	}
	switch {
	case in.PropagationChannelID == "" && in.SponsorID == "":
	case !ValidPartnerID(in.PropagationChannelID) || !ValidPartnerID(in.SponsorID):
		return errors.New("psiphon: the propagation channel id and the sponsor id are both 16 upper-case hex digits, or both unset")
	}
	return nil
}

// dataRoot is the data root of the client inside the container.
func dataRoot(in providers.Instance) string {
	if in.CacheDir == "" {
		return instanceDataDir
	}
	return providers.CacheMount
}

// hostDataRoot is the data root of the client on the host.
func hostDataRoot(in providers.Instance) string {
	if in.CacheDir == "" {
		return filepath.Join(in.InstanceDir, hostDataDir)
	}
	return in.CacheDir
}

// Container describes the container the instance runs in (see
// providers.ContainerSpec), with 512 MiB of memory:
//
//	/opt/engine/psiphon-core -config /etc/egress/psiphon.json -useNoticeFiles
//
// -useNoticeFiles has the client write its notices, rotated at 1 MiB, to
// NoticeFiles under its data root as well, where Ready reads them. The instance
// directory is read only, but without a CacheDir, when the data root is in it.
func (Driver) Container(in providers.Instance) dockerapi.ContainerSpec {
	return providers.ContainerSpec(in, providers.ContainerOptions{
		Binary:      Binary,
		Args:        []string{"-config", providers.InstanceMount + "/" + ConfigFile, "-useNoticeFiles"},
		InstanceRW:  in.CacheDir == "",
		MemoryBytes: 512 << 20,
	})
}

// maxNoticeTail is how much of the end of a notices file Ready reads.
const maxNoticeTail = 256 << 10

// ProbeAddr is where the SOCKS connect of Ready goes when the notices do not
// show a tunnel: a front of Telegram's DC 2 (an address, so that nothing is
// resolved), which is what the egress is for. connectTimeout bounds it. Both
// are variables for the tests.
var (
	ProbeAddr      = "149.154.167.51:443"
	connectTimeout = 5 * time.Second
)

// Ready checks that the member's SOCKS5 port answers the greeting (see
// providers.CheckSOCKS) and that the client has a tunnel: its last Tunnels
// notice counts one or more, or, when the notices do not show that (none
// yet, a rotation, a count of 0), a SOCKS5 CONNECT through the port to
// ProbeAddr succeeds, which the client answers only once a tunnel carried it.
// The client opens its port before it has a tunnel, and answers the greeting
// then too. It makes one check and does not wait.
func (Driver) Ready(ctx context.Context, in providers.Instance) error {
	if err := providers.CheckSOCKS(ctx, in.Members); err != nil {
		return fmt.Errorf("psiphon: %w", err)
	}
	why := "no Tunnels notice yet"
	if count, seen := tunnelNotice(hostDataRoot(in)); seen && count >= 1 {
		return nil
	} else if seen {
		why = "the client reports no tunnel"
	}
	if err := socksConnect(ctx, in.Members[0].Port, ProbeAddr); err != nil {
		return fmt.Errorf("psiphon: no tunnel yet: %s, and a connect through it fails: %w", why, err)
	}
	return nil
}

// tunnelNotice returns the count of the last Tunnels notice of the client
// under its data root dir, and whether there is one: in the notices, or, when
// they have none (just rotated), in the file before them.
func tunnelNotice(dir string) (count int, seen bool) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, false
	}
	defer func() { _ = root.Close() }()
	for _, name := range NoticeFiles {
		if count, seen := TunnelCount(readTail(root, name)); seen {
			return count, true
		}
	}
	return 0, false
}

// socksConnect asks the SOCKS5 server on the loopback port for a CONNECT to
// addr (an IPv4 address and a port) without authentication, and returns nil
// when it answers success. It closes the connection at once.
func socksConnect(ctx context.Context, port uint16, addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Is4() {
		return fmt.Errorf("the probe address %q is not an IPv4 address and port", addr)
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	ip := ap.Addr().As4()
	return SOCKSConnect(conn, []byte{1, ip[0], ip[1], ip[2], ip[3]}, ap.Port())
}

// SOCKSConnect makes the SOCKS5 handshake on conn without authentication and
// a CONNECT to the address addr (its type byte and its bytes: 1 and an IPv4
// address, or 3, a length and a name) and port, and returns nil when the
// server answers success. The greeting is answered before the request is
// sent, as clients do: the client of Psiphon drops a request that comes with
// the greeting.
func SOCKSConnect(conn net.Conn, addr []byte, port uint16) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fmt.Errorf("no answer to the greeting: %w", err)
	}
	if choice[0] != 5 || choice[1] != 0 {
		return errors.New("the SOCKS5 server takes no method without authentication")
	}
	req := append(append([]byte{5, 1, 0}, addr...), byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("no answer to the CONNECT: %w", err)
	}
	switch {
	case reply[0] != 5:
		return errors.New("the answer to the CONNECT is not SOCKS5")
	case reply[1] != 0:
		return fmt.Errorf("the CONNECT failed (SOCKS5 reply %d)", reply[1])
	}
	// The bound address, which says nothing here.
	var n int
	switch reply[3] {
	case 1:
		n = 4 + 2
	case 4:
		n = 16 + 2
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		n = int(l[0]) + 2
	default:
		return fmt.Errorf("the answer to the CONNECT has an address of type %d", reply[3])
	}
	_, err := io.ReadFull(conn, make([]byte, n))
	return err
}

// readTail returns at most the last maxNoticeTail bytes of the regular file
// name under root, nil when there is none. The container writes the file:
// nothing leaves root.
func readTail(root *os.Root, name string) []byte {
	f, err := root.Open(name)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	if off := info.Size() - maxNoticeTail; off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return nil
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxNoticeTail))
	if err != nil {
		return nil
	}
	return data
}

// TunnelCount reads notices, one JSON object a line, and returns the count of
// the last Tunnels notice, {"noticeType":"Tunnels","data":{"count":N}}, and
// whether there is one. Lines that are not such a notice are skipped, a cut
// first line too.
func TunnelCount(notices []byte) (count int, seen bool) {
	for line := range bytes.SplitSeq(notices, []byte("\n")) {
		if !bytes.Contains(line, []byte(`"Tunnels"`)) {
			continue
		}
		var n struct {
			NoticeType string `json:"noticeType"`
			Data       struct {
				Count *int `json:"count"`
			} `json:"data"`
		}
		if json.Unmarshal(line, &n) != nil || n.NoticeType != "Tunnels" || n.Data.Count == nil {
			continue
		}
		count, seen = *n.Data.Count, true
	}
	return count, seen
}
