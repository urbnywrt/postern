// Package providers defines what the node agent needs from an egress provider:
// a program that runs in a container on the host network and gives every member
// of an egress a SOCKS5 port on 127.0.0.1, through which the edge reaches the
// outside. Xray serves share links, subscriptions and WARP (package
// providers/xray); Psiphon's own client serves Psiphon (package
// providers/psiphoncore); package providers/warp registers the WARP accounts.
//
// Like an engine driver (package engines), a provider driver is pure: Render and
// Container compute their results from an Instance and touch nothing. Writing
// the files, creating the container and polling Ready is the agent's job.
//
// Members hold credentials (a Server's id or password, a WARP account's keys):
// nothing here logs them, and no error repeats them. Log a member by its Key.
//
// A provider driver whose binary can be tried out before it is used implements
// engines.Trialer, like an engine driver: the node runs the trial of an
// uploaded artifact in the runner image (package node/trial). VersionOutput
// builds the output pattern of a trial that must show the version.
package providers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/providers/warp"
)

// The loopback port range of egress members (Global Constraints).
const (
	MinPort = 35000
	MaxPort = 39999
)

// Where a provider container sees things.
const (
	// BinaryDir holds the provider binary: BinaryDir/<binary name>.
	BinaryDir = "/opt/engine"
	// InstanceMount is the instance directory.
	InstanceMount = "/etc/egress"
	// CacheMount is where Instance.CacheDir is mounted, read-write.
	CacheMount = "/var/cache/egress"
	// resolvConfMount is where Instance.ResolvConf is mounted.
	resolvConfMount = "/etc/resolv.conf"
)

// Member is one member of an egress: one SOCKS5 port on 127.0.0.1, one way out.
type Member struct {
	// Key names the member: 1 to 64 letters, digits, '-' and '_', starting with
	// a letter or a digit, unique in the instance. An Xray member of a share link
	// or a subscription is keyed by egressuri.Server.Key, so that it keeps its
	// port when its subscription is refreshed. It is what logs and errors name.
	Key string
	// Port is the member's SOCKS5 port on 127.0.0.1, from MinPort to MaxPort.
	Port uint16
	// Server is the remote server of an Xray member of an XRAY_URI or
	// XRAY_SUBSCRIPTION egress, nil otherwise. It holds credentials: never log
	// it, log Key.
	Server *egressuri.Server
	// WARP is the account of the member of a WARP egress, nil otherwise. It
	// holds the private key and the token.
	WARP *warp.Account
}

// Instance is one provider instance to be rendered, run and probed: one
// generation of one egress.
type Instance struct {
	// EgressID is the egress the instance serves; Generation the instance
	// generation. Both are part of the container name.
	EgressID   string
	Generation uint64
	// Kind is the kind of the egress.
	Kind nodev1.EgressKind
	// Members are the members, in order. Xray: one per server (XRAY_URI one,
	// XRAY_SUBSCRIPTION any number) or one with WARP set (WARP). Psiphon:
	// exactly one, with neither Server nor WARP.
	Members []Member
	// Country is the two-letter exit country of a PSIPHON egress.
	Country string
	// PropagationChannelID and SponsorID are the Psiphon partner ids of a
	// PSIPHON egress, both "" for the defaults of a client without a partner
	// agreement.
	PropagationChannelID, SponsorID string
	// InstanceDir is the host directory the rendered files are written to,
	// mounted at /etc/egress: read-only, but for Psiphon without a CacheDir,
	// which keeps its data there. The files hold credentials: they must be
	// written private, and be readable (the directory writable, for such a
	// Psiphon) by the user the container runs as, 65534.
	InstanceDir string
	// CacheDir is the host path of the cache directory of the generation,
	// mounted read-write at CacheMount, or "". Psiphon keeps its data there
	// (its server list, its datastore, its notices); the agent makes it a
	// copy of the cache of the generation before, so that a new generation
	// does not register and bootstrap again, and no two generations open the
	// same files (Ruling S2-18). It must be writable by 65534.
	CacheDir string
	// BinaryPath is the host path of the provider binary, RunnerImage the image
	// of its container.
	BinaryPath, RunnerImage string
	// ResolvConf is the host path of a resolv.conf to mount read-only at
	// /etc/resolv.conf, or "" to keep the resolver of the host. The agent decides
	// which (Rulings S2-1, S2-8).
	ResolvConf string
}

// Driver is the glue between the agent and one provider.
type Driver interface {
	// Kinds are the egress kinds the driver serves.
	Kinds() []nodev1.EgressKind

	// ArtifactFile is the name of the release file to download for a CPU
	// architecture ("amd64" or "arm64").
	ArtifactFile(arch string) (string, error)

	// BinaryName is the name of the executable in the release file, and the name
	// the artifact store keeps it under.
	BinaryName() string

	// Render computes the files the provider is started with: relative path to
	// content. They hold credentials and must be written private. A member that
	// cannot be rendered makes Render fail with a *MemberError for it (all of
	// them are reported, see MemberErrors), so that the agent can leave the
	// member out and render again; anything else wrong with the instance is a
	// plain error. No error holds a credential.
	Render(in Instance) (map[string][]byte, error)

	// Container describes the container to run the provider in. It does not
	// touch the host: see Instance.CheckHostPaths for what to check before
	// creating it, and call it only for an instance that Render took.
	Container(in Instance) dockerapi.ContainerSpec

	// Ready makes one check that every member port accepts a TCP connection and
	// answers the SOCKS5 greeting (method "no authentication"), and returns nil
	// when all do. It does not wait: callers poll it until their deadline. A
	// member that answers the greeting is not known to work: Xray acknowledges a
	// CONNECT before its outbound has connected (F1), so whether a member gets
	// through is the health checker's to find out.
	Ready(ctx context.Context, in Instance) error
}

// RunnerOwnedFiles is implemented by a driver whose rendered files must be the
// container user's (65534), mode 0600, rather than root's and readable by the
// group of that user (0640). FilesOwnedByRunner reports whether they are.
type RunnerOwnedFiles interface {
	FilesOwnedByRunner() bool
}

// ---- trials -------------------------------------------------------------------

// VersionOutput is the output pattern of a trial that must show the version:
// before, then the version without its leading v (quoted), then after, where
// before and after are regular expressions. The version must be 1 to 64
// characters of [0-9A-Za-z.+-] starting with a digit (what an upstream tag
// without its v looks like: 26.3.27, 1.2.6, 2.1.7-rc.1): any other version
// gives a pattern that matches nothing, so that a trial never passes by
// accident.
func VersionOutput(before, version, after string) *regexp.Regexp {
	n := strings.TrimPrefix(version, "v")
	if !plainVersion(n) {
		return regexp.MustCompile(`[^\x00-\x{10FFFF}]`) // matches nothing
	}
	return regexp.MustCompile(`(?m)` + before + regexp.QuoteMeta(n) + after)
}

func plainVersion(n string) bool {
	if n == "" || len(n) > 64 || n[0] < '0' || n[0] > '9' {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '+', c == '-':
		default:
			return false
		}
	}
	return true
}

// ---- member errors ------------------------------------------------------------

// MemberError is the error of Render for a member it cannot render: which member
// (its key) and which field. Field is the name of the share-link parameter where
// there is one (fp, pbk, sid, flow, ...), else the name of the field of the
// egressuri.Server or of the WARP account. Reason says what is wrong without
// repeating the value: a share link holds credentials, and a subscription is
// written by a third party.
type MemberError struct {
	Key, Field, Reason string
}

func (e *MemberError) Error() string {
	return "member " + e.Key + ": " + e.Field + ": " + e.Reason
}

// memberErrors is the error of several bad members.
type memberErrors []*MemberError

func (m memberErrors) Error() string {
	parts := make([]string, len(m))
	for i, e := range m {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}

func (m memberErrors) Unwrap() []error {
	errs := make([]error, len(m))
	for i, e := range m {
		errs[i] = e
	}
	return errs
}

// JoinMemberErrors makes one error of the member errors of a Render, nil when
// there are none.
func JoinMemberErrors(errs []*MemberError) error {
	if len(errs) == 0 {
		return nil
	}
	return memberErrors(errs)
}

// MemberErrors returns the member errors in err, in order: those of Render, or
// any other error tree. It is nil when there are none.
func MemberErrors(err error) []*MemberError {
	var out []*MemberError
	var walk func(error)
	walk = func(err error) {
		switch e := err.(type) {
		case nil:
		case *MemberError:
			out = append(out, e)
		case interface{ Unwrap() []error }:
			for _, x := range e.Unwrap() {
				walk(x)
			}
		case interface{ Unwrap() error }:
			walk(e.Unwrap())
		}
	}
	walk(err)
	return out
}

// ---- checks -------------------------------------------------------------------

// metadataAddrs are the instance metadata services of cloud hosts. The IPv4 one
// (AWS, GCP, Azure, Oracle, DigitalOcean, Hetzner, ...) is link-local anyway;
// fd00:ec2::254 is AWS's over IPv6, 100.100.100.200 Alibaba Cloud's, and
// 168.63.129.16 Azure's WireServer. Their names (metadata.google.internal, say)
// are names like any other: allowed, see CheckServerAddress.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("168.63.129.16"),
}

// loopbackNames are names that mean the loopback by convention: RFC 6761
// localhost, and what the /etc/hosts of common distributions adds to it
// (Debian's ip6-*, Red Hat's localhost4 and localhost6).
var loopbackNames = []string{
	"localhost", "localhost.localdomain",
	"localhost4", "localhost4.localdomain4", "localhost6", "localhost6.localdomain6",
	"ip6-localhost", "ip6-loopback",
}

// CheckServerAddress refuses an address that a provider must not connect to for
// a member: an IP literal that is a loopback, unspecified, link-local or
// multicast address or the metadata service of a cloud host (169.254.169.254,
// fd00:ec2::254, 100.100.100.200, 168.63.129.16), also as an IPv4-mapped IPv6
// address; the names that mean the loopback by convention (localhost,
// *.localhost, localhost.localdomain, localhost4, localhost4.localdomain4,
// localhost6, localhost6.localdomain6, ip6-localhost, ip6-loopback); "env:...",
// which Xray replaces by an environment variable of its process; and anything
// that is neither an IP literal nor a plain name. The provider runs on the host
// network, and a subscription, which a third party writes, must not point it at
// the services of the node.
//
// The address is read the way Xray's net.ParseAddress reads it: one pair of
// brackets around it taken off first, then the spaces around it, but only when
// its first or last character is not a letter or a digit. What is left and is
// not an IP literal is a name to Xray, and it dials "<name>:<port>": a name
// that holds a bracket, a colon, a space or a control character is refused, for
// Go's dialer would take "[127.0.0.1]" in it for the address 127.0.0.1.
//
// Every other host name is allowed: the provider resolves it when it connects,
// and a name can resolve to anything (the names of metadata services too), so
// this is a guard against the plain cases, not a sandbox. The error never
// repeats the address.
func CheckServerAddress(host string) error {
	if hasEnvPrefix(host) {
		return errors.New("an environment variable, not an address")
	}
	h := host
	if len(h) > 0 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if len(h) > 0 && (!isAlphaNum(h[0]) || !isAlphaNum(h[len(h)-1])) {
		h = strings.TrimSpace(h)
	}
	if h == "" {
		return errors.New("no address")
	}
	if hasEnvPrefix(h) {
		return errors.New("an environment variable, not an address")
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		addr = addr.Unmap()
		switch {
		case addr.IsLoopback():
			return errors.New("a loopback address")
		case addr.IsUnspecified():
			return errors.New("an unspecified address")
		case slices.Contains(metadataAddrs, addr.WithZone("")):
			return errors.New("the address of a cloud metadata service")
		case addr.IsLinkLocalUnicast():
			return errors.New("a link-local address")
		case addr.IsMulticast():
			return errors.New("a multicast address")
		}
		return nil
	}
	if strings.ContainsFunc(h, func(r rune) bool {
		return r == '[' || r == ']' || r == ':' || unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return errors.New("neither an IP address nor a host name")
	}
	name := strings.TrimSuffix(strings.ToLower(h), ".")
	if slices.Contains(loopbackNames, name) || strings.HasSuffix(name, ".localhost") {
		return errors.New("a name of the loopback")
	}
	return nil
}

// hasEnvPrefix reports whether s starts with "env:" in any case: Xray's Address
// takes such a value for the name of an environment variable.
func hasEnvPrefix(s string) bool {
	return len(s) >= 4 && strings.EqualFold(s[:4], "env:")
}

// isAlphaNum is the isAlphaNum of Xray's common/net.
func isAlphaNum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// validName accepts 1 to 64 letters, digits, '-' and '_', starting with a letter
// or a digit: what can be part of a container name and of an Xray tag.
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '-' || c == '_'):
		default:
			return false
		}
	}
	return true
}

// CheckEgressID checks the id of an egress, which is part of the container name:
// 1 to 64 letters, digits, '-' and '_', starting with a letter or a digit.
func CheckEgressID(id string) error {
	if !validName(id) {
		return fmt.Errorf("egress id %.64q is not 1 to 64 letters, digits, '-' and '_'", id)
	}
	return nil
}

// CheckMembers checks what every driver needs of the members of an instance: at
// least one; keys that are valid (see Member.Key) and distinct; ports from
// MinPort to MaxPort and distinct. The errors are plain errors, not member
// errors: the members of an instance are the agent's to get right.
func CheckMembers(members []Member) error {
	if len(members) == 0 {
		return errors.New("no members")
	}
	keys := make(map[string]bool, len(members))
	ports := make(map[uint16]bool, len(members))
	for i, m := range members {
		if !validName(m.Key) {
			return fmt.Errorf("member #%d: the key is not 1 to 64 letters, digits, '-' and '_'", i)
		}
		if keys[m.Key] {
			return fmt.Errorf("member %s: the key is used by another member", m.Key)
		}
		keys[m.Key] = true
		if m.Port < MinPort || m.Port > MaxPort {
			return fmt.Errorf("member %s: port %d is outside %d-%d", m.Key, m.Port, MinPort, MaxPort)
		}
		if ports[m.Port] {
			return fmt.Errorf("member %s: port %d is used by another member", m.Key, m.Port)
		}
		ports[m.Port] = true
	}
	return nil
}

// ---- containers ---------------------------------------------------------------

// ContainerName is postern-egr-<egress id, lower case>-g<generation>.
func ContainerName(egressID string, gen uint64) string {
	return "postern-egr-" + strings.ToLower(egressID) + "-g" + strconv.FormatUint(gen, 10)
}

// ContainerOptions are what the container of one provider has of its own.
type ContainerOptions struct {
	// Binary is the name of the binary, mounted at BinaryDir/Binary; Args are
	// its arguments.
	Binary string
	Args   []string
	// InstanceRW mounts the instance directory read-write instead of read-only.
	InstanceRW bool
	// MemoryBytes is the memory limit.
	MemoryBytes int64
}

// ContainerSpec is the container of a provider instance, the same for every
// provider but for o: named ContainerName, from the runner image, as user 65534
// on the host network, with a read-only root file system, no capabilities, no
// new privileges, a 16 MiB /tmp, 256 processes, and rotated logs. It mounts the
// binary read-only, the instance directory at /etc/egress, Instance.CacheDir
// read-write at CacheMount when it is set, and Instance.ResolvConf read-only at
// /etc/resolv.conf when it is set (Docker honours that mount on the host
// network).
func ContainerSpec(in Instance, o ContainerOptions) dockerapi.ContainerSpec {
	binary := BinaryDir + "/" + o.Binary
	instanceBind := in.InstanceDir + ":" + InstanceMount
	if !o.InstanceRW {
		instanceBind += ":ro"
	}
	binds := []string{in.BinaryPath + ":" + binary + ":ro", instanceBind}
	if in.CacheDir != "" {
		binds = append(binds, in.CacheDir+":"+CacheMount)
	}
	if in.ResolvConf != "" {
		binds = append(binds, in.ResolvConf+":"+resolvConfMount+":ro")
	}
	gen := strconv.FormatUint(in.Generation, 10)
	return dockerapi.ContainerSpec{
		Name:          ContainerName(in.EgressID, in.Generation),
		Image:         in.RunnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		Entrypoint:    append([]string{binary}, o.Args...),
		Binds:         binds,
		CapDrop:       []string{"ALL"},
		SecurityOpt:   []string{"no-new-privileges:true"},
		Labels: map[string]string{
			"postern.managed":    "true",
			"postern.role":       "egress",
			"postern.id":         in.EgressID,
			"postern.generation": gen,
		},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=16m"},
		ReadOnly:    true,
		MemoryBytes: o.MemoryBytes,
		PidsLimit:   256,
		LogMaxSize:  "5m",
		LogMaxFile:  2,
	}
}

// CheckHostPaths verifies the host paths the container binds: the binary (an
// existing regular file that others can read and execute: the container does
// not run as its owner), the instance directory (an existing directory), when it
// is set CacheDir (an existing directory), and when it is set ResolvConf (an
// existing regular file that others can read). All of them must be absolute and
// free of ':'.
//
// Call it before dockerapi.Client.Create: Docker creates a missing bind source
// as an empty root-owned directory and starts the container anyway.
func (in Instance) CheckHostPaths() error {
	if err := checkFile("provider binary", in.BinaryPath, 0o005); err != nil {
		return err
	}
	if err := checkDir("instance directory", in.InstanceDir); err != nil {
		return err
	}
	if in.CacheDir != "" {
		if err := checkDir("cache directory", in.CacheDir); err != nil {
			return err
		}
	}
	if in.ResolvConf != "" {
		if err := checkFile("resolv.conf", in.ResolvConf, 0o004); err != nil {
			return err
		}
	}
	return nil
}

// checkDir checks that path is an existing directory that can be a bind source.
func checkDir(what, path string) error {
	if err := checkBindSource(what, path); err != nil {
		return err
	}
	switch info, err := os.Stat(path); {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("providers: %s %s does not exist", what, path)
	case err != nil:
		return fmt.Errorf("providers: %s: %w", what, err)
	case !info.IsDir():
		return fmt.Errorf("providers: %s %s is not a directory", what, path)
	}
	return nil
}

// checkFile checks that path is a regular file whose mode has the bits of
// others.
func checkFile(what, path string, others fs.FileMode) error {
	if err := checkBindSource(what, path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("providers: %s %s does not exist", what, path)
	case err != nil:
		return fmt.Errorf("providers: %s: %w", what, err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("providers: %s %s is not a regular file", what, path)
	case info.Mode().Perm()&others != others:
		return fmt.Errorf("providers: %s %s (mode %v) is not open enough to other users, and the container does not run as its owner", what, path, info.Mode().Perm())
	}
	return nil
}

// checkBindSource rejects host paths that cannot be the source of a bind mount.
func checkBindSource(what, path string) error {
	switch {
	case path == "":
		return fmt.Errorf("providers: %s path is empty", what)
	case !filepath.IsAbs(path):
		return fmt.Errorf("providers: %s path %q must be absolute (Docker would take it for a volume name)", what, path)
	case strings.Contains(path, ":"):
		return fmt.Errorf("providers: %s path %q contains ':' which a bind mount spec cannot hold", what, path)
	}
	return nil
}

// ---- readiness ----------------------------------------------------------------

// greetTimeout bounds the check of one member, so that a port that accepts and
// says nothing cannot hold a polling loop. A variable for the tests.
var greetTimeout = 2 * time.Second

// CheckSOCKS is Driver.Ready for every provider: it connects to the SOCKS5 port
// of each member on 127.0.0.1, offers the method "no authentication" and wants
// it accepted, member by member. The error names the first member that fails,
// by key and port.
func CheckSOCKS(ctx context.Context, members []Member) error {
	if len(members) == 0 {
		return errors.New("no members")
	}
	for _, m := range members {
		if err := greet(ctx, m.Port); err != nil {
			return fmt.Errorf("member %s (port %d): %w", m.Key, m.Port, err)
		}
	}
	return nil
}

func greet(ctx context.Context, port uint16) error {
	ctx, cancel := context.WithTimeout(ctx, greetTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return fmt.Errorf("not accepting connections: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fmt.Errorf("sending the SOCKS5 greeting: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("no answer to the SOCKS5 greeting: %w", err)
	}
	switch {
	case reply[0] != 5:
		return errors.New("the answer to the greeting is not SOCKS5")
	case reply[1] == 0xff:
		return errors.New("the SOCKS5 server accepts no method without authentication")
	case reply[1] != 0:
		return fmt.Errorf("the SOCKS5 server chose method %d, not 0 (no authentication)", reply[1])
	}
	return nil
}
