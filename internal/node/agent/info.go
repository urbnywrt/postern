package agent

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/node/state"
)

const (
	// maxOSName bounds the operating system's name in GetInfo.
	maxOSName = 256

	// echoTimeout bounds one request to an echo service, echoBudget all of
	// them together.
	echoTimeout = 3 * time.Second
	echoBudget  = 10 * time.Second
	// echoCacheOK is how long an address an echo service told is used,
	// echoCacheFail how long the services are left alone after none told one.
	echoCacheOK   = 10 * time.Minute
	echoCacheFail = time.Minute

	// portScanBudget bounds the search of /proc for the owners of sockets.
	portScanBudget = 3 * time.Second
	dockerTimeout  = 5 * time.Second
	unknownOwner   = "unknown"
)

// defaultEchoURLs are services that answer with the address a request came
// from; the same ones the edge asks for an egress's exit address.
var defaultEchoURLs = []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"}

// cgnat is the shared address space of carrier-grade NAT (RFC 6598): not an
// address the internet can reach.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// hostInfo answers the questions GetInfo asks about the host.
type hostInfo struct {
	// osRelease are the os-release files to try, in order: the host's, which
	// compose mounts at /host/etc/os-release, then the container's own.
	osRelease []string
	// addrs lists the addresses of the host's interfaces (the agent runs in
	// the host's network namespace).
	addrs func() ([]net.Addr, error)
	// echoURLs are asked, in order, for the public address when no interface
	// has one.
	echoURLs []string
	client   *http.Client
	// resolver resolves the names of the echo services: the agent's, which
	// asks the edge's DNS forwarder while it runs. nil is the system's.
	resolver *net.Resolver
	// proc is the host's /proc (the agent runs with pid: host).
	proc   fs.FS
	docker dockerapi.Client
	now    func() time.Time
	log    *slog.Logger

	mu       sync.Mutex // one echo lookup at a time
	echoAddr netip.Addr // invalid: none was told
	echoAt   time.Time
	echoDone bool
}

// osName is PRETTY_NAME of the first os-release file there is, or "".
func (h *hostInfo) osName() string {
	for _, path := range h.osRelease {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, 64<<10))
		_ = f.Close()
		if err != nil {
			continue
		}
		return parseOSRelease(data)
	}
	return ""
}

// parseOSRelease returns PRETTY_NAME, unquoted the way os-release(5) quotes
// it, or "Linux", the default the format names.
func parseOSRelease(data []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") || strings.TrimSpace(key) != "PRETTY_NAME" {
			continue
		}
		return clipText(unquoteShell(strings.TrimSpace(value)), maxOSName)
	}
	return "Linux"
}

// unquoteShell undoes the quoting os-release values use: double quotes with
// backslash escapes, single quotes, or none.
func unquoteShell(v string) string {
	switch {
	case len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'':
		return v[1 : len(v)-1]
	case len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"':
		v = v[1 : len(v)-1]
		var b strings.Builder
		for i := 0; i < len(v); i++ {
			if v[i] == '\\' && i+1 < len(v) && strings.IndexByte("\"\\$`", v[i+1]) >= 0 {
				i++
			}
			b.WriteByte(v[i])
		}
		return b.String()
	}
	return v
}

// publicIPs are the public addresses of the host's interfaces; when there is
// none, the address an echo service sees the node at (its NAT's), if one
// answers. Sorted, IPv4 first.
func (h *hostInfo) publicIPs(ctx context.Context) []string {
	var found []netip.Addr
	if h.addrs != nil {
		if list, err := h.addrs(); err == nil {
			found = publicAddrs(list)
		}
	}
	if len(found) == 0 {
		if a, ok := h.echo(ctx); ok {
			found = []netip.Addr{a}
		}
	}
	out := make([]string, len(found))
	for i, a := range found {
		out[i] = a.String()
	}
	return out
}

// refreshPublicIPv4 is publicIPv4 without what the echo services told before,
// or did not.
func (h *hostInfo) refreshPublicIPv4(ctx context.Context) string {
	h.mu.Lock()
	h.echoDone = false
	h.mu.Unlock()
	return h.publicIPv4(ctx)
}

// publicIPv4 is the first public IPv4 address, or "".
func (h *hostInfo) publicIPv4(ctx context.Context) string {
	for _, s := range h.publicIPs(ctx) {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return s
		}
	}
	return ""
}

// publicAddrs picks the public addresses out of interface addresses.
func publicAddrs(list []net.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range list {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if isPublic(addr) && !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// isPublic reports whether the internet can reach a: a global unicast
// address that is not private (RFC 1918, ULA) and not carrier-grade NAT (an
// IPv4 prefix, which never contains an IPv6 address).
func isPublic(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// echo is the public address the echo services tell, cached.
func (h *hostInfo) echo(ctx context.Context) (netip.Addr, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if h.echoDone {
		ttl := echoCacheFail
		if h.echoAddr.IsValid() {
			ttl = echoCacheOK
		}
		if now.Sub(h.echoAt) < ttl {
			return h.echoAddr, h.echoAddr.IsValid()
		}
	}
	h.echoAddr = h.lookupEcho(ctx)
	h.echoAt, h.echoDone = now, true
	return h.echoAddr, h.echoAddr.IsValid()
}

// lookupEcho asks the echo services in order, over IPv4, and returns the
// first public address one of them tells. Failures are normal (no internet,
// services blocked) and only logged at debug.
func (h *hostInfo) lookupEcho(ctx context.Context) netip.Addr {
	if len(h.echoURLs) == 0 {
		return netip.Addr{}
	}
	ctx, cancel := context.WithTimeout(ctx, echoBudget)
	defer cancel()
	client := h.client
	if client == nil {
		client = echoClient(h.resolver)
	}
	for _, u := range h.echoURLs {
		a, err := askEcho(ctx, client, u)
		if err == nil {
			return a
		}
		h.log.Debug("agent: an echo service did not tell the public address", "url", u, "err", err)
		if ctx.Err() != nil {
			break
		}
	}
	return netip.Addr{}
}

func askEcho(ctx context.Context, client *http.Client, u string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, echoTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, errors.New("the answer is not an address")
	}
	if a = a.Unmap(); !isPublic(a) {
		return netip.Addr{}, fmt.Errorf("%s is not a public address", a)
	}
	return a, nil
}

// echoClient asks over IPv4 only: the address is the node's NAT address for
// the engines' middle proxy, which is IPv4. The names of the services are
// resolved with resolver, nil for the system's.
func echoClient(resolver *net.Resolver) *http.Client {
	dialer := &net.Dialer{Timeout: echoTimeout, Resolver: resolver}
	return &http.Client{
		Timeout: echoTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp4", addr)
			},
			TLSHandshakeTimeout:   echoTimeout,
			ResponseHeaderTimeout: echoTimeout,
			DisableKeepAlives:     true,
		},
	}
}

// ---- artifacts ------------------------------------------------------------------

// Artifact states, as GetInfo reports them: "" when the trial passed.
const (
	stateUntried  = "untried"
	stateUnusable = "unusable"
	// maxStateReason bounds ArtifactRef.state_reason.
	maxStateReason = 256
)

// listArtifacts lists the verified artifacts in the store (artifacts.Store.List)
// with the state their trial record gives them: "" when the trial passed,
// "untried" when there is no record, "unusable" when it failed, with the
// reason.
func listArtifacts(store *artifacts.Store) []*nodev1.ArtifactRef {
	var out []*nodev1.ArtifactRef
	for _, ref := range store.List() {
		a := &nodev1.ArtifactRef{Engine: ref.Engine, Version: ref.Version, Arch: ref.Arch, Sha256: ref.SHA256, Binary: ref.Binary}
		switch rec, ok := store.Trial(ref); {
		case !ok:
			a.State = stateUntried
		case !rec.OK:
			a.State = stateUnusable
			a.StateReason = clipText(rec.Reason, maxStateReason)
		}
		out = append(out, a)
	}
	return out
}

// ---- port owners ------------------------------------------------------------------

// sockAddr is the local address of a listening socket.
type sockAddr = netip.AddrPort

// listenSocket is a listening TCP socket from /proc/net/tcp{,6}.
type listenSocket struct {
	addr  sockAddr
	inode uint64
}

// tcpListen is the state of a listening socket in /proc/net/tcp.
const tcpListen = "0A"

// parseProcNet reads the listening sockets from /proc/net/tcp (v6: tcp6).
func parseProcNet(data []byte, v6 bool) []listenSocket {
	var out []listenSocket
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != tcpListen {
			continue
		}
		addr, ok := parseHexAddrPort(f[1], v6)
		if !ok {
			continue
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, listenSocket{addr: addr, inode: inode})
	}
	return out
}

// parseHexAddrPort reads an address as /proc/net/tcp{,6} print it: the
// address as 32-bit words in hex, each word in the host's byte order, a colon
// and the port in hex.
func parseHexAddrPort(s string, v6 bool) (sockAddr, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return sockAddr{}, false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return sockAddr{}, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (v6 && len(raw) != 16) || (!v6 && len(raw) != 4) {
		return sockAddr{}, false
	}
	var ip [16]byte
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(ip[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	var addr netip.Addr
	if v6 {
		addr = netip.AddrFrom16(ip).Unmap()
	} else {
		addr = netip.AddrFrom4([4]byte(ip[:4]))
	}
	return netip.AddrPortFrom(addr, uint16(p)), true
}

// containerInfo is what Docker says about a container.
type containerInfo struct {
	name    string
	managed bool
}

// portOwners lists the listening TCP sockets of the host and who holds them:
//
//   - a container of the agent's (postern.managed=true): its name;
//   - another container: "<process> (container <name>)";
//   - a process on the host: "<process> (pid <pid>)";
//   - a socket whose process the agent may not see (procfs hides other
//     processes' file descriptors without ptrace rights): the container of
//     the agent's that expected names for it, if that one runs; otherwise
//     "unknown".
//
// Nothing here fails: what cannot be read is unknown.
func portOwners(ctx context.Context, proc fs.FS, docker dockerapi.Client, expected map[sockAddr]string) []*nodev1.PortOwner {
	socks, running := scanSockets(ctx, proc, docker, 0)
	type key struct {
		addr  sockAddr
		owner string
	}
	seen := map[key]bool{}
	var out []*nodev1.PortOwner
	for _, s := range socks {
		owner := s.owner
		if !s.known {
			owner = unknownOwner
			if name, ok := expected[s.addr]; ok && running[name] {
				owner = name
			}
		}
		k := key{s.addr, owner}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, &nodev1.PortOwner{Bind: s.addr.Addr().String(), Port: uint32(s.addr.Port()), Owner: owner})
	}
	slices.SortFunc(out, func(a, b *nodev1.PortOwner) int {
		return cmp.Or(cmp.Compare(a.GetPort(), b.GetPort()), strings.Compare(a.GetBind(), b.GetBind()), strings.Compare(a.GetOwner(), b.GetOwner()))
	})
	return out
}

// ownedSocket is a listening socket and its owner, as describeProcess names
// it; known is false when its process could not be found.
type ownedSocket struct {
	addr  sockAddr
	pid   int
	owner string
	known bool
}

// scanSockets lists the listening TCP sockets of the host with their owners,
// and the names of the agent's own containers that run. A socket of the
// process self (the agent: its management listeners) is owned by
// diag.OwnerAgent; 0 names no process.
func scanSockets(ctx context.Context, proc fs.FS, docker dockerapi.Client, self int) ([]ownedSocket, map[string]bool) {
	var socks []listenSocket
	for _, f := range []struct {
		name string
		v6   bool
	}{{"net/tcp", false}, {"net/tcp6", true}} {
		data, err := fs.ReadFile(proc, f.name)
		if err != nil {
			continue
		}
		socks = append(socks, parseProcNet(data, f.v6)...)
	}
	if len(socks) == 0 {
		return nil, nil
	}
	want := map[uint64]bool{}
	for _, s := range socks {
		want[s.inode] = true
	}
	scanCtx, cancel := context.WithTimeout(ctx, portScanBudget)
	pids := socketPIDs(scanCtx, proc, want)
	cancel()
	byID, running := listContainers(ctx, docker)
	out := make([]ownedSocket, 0, len(socks))
	for _, s := range socks {
		o := ownedSocket{addr: s.addr}
		if pid, ok := pids[s.inode]; ok {
			o.pid, o.known = pid, true
			if self > 0 && pid == self {
				o.owner = diag.OwnerAgent
			} else {
				o.owner = describeProcess(proc, pid, byID)
			}
		}
		out = append(out, o)
	}
	return out, running
}

// socketOwners lists every listening socket of the host for the diagnostics
// (host.ports): one entry per socket, so that two SO_REUSEPORT sockets of one
// port are told apart, and an owner that cannot be read is unknown, never
// guessed from the address.
func socketOwners(ctx context.Context, proc fs.FS, docker dockerapi.Client, self int) []diag.SocketOwner {
	socks, _ := scanSockets(ctx, proc, docker, self)
	out := make([]diag.SocketOwner, 0, len(socks))
	for _, s := range socks {
		out = append(out, diag.SocketOwner{Bind: s.addr.Addr().String(), Port: s.addr.Port(), PID: s.pid, Owner: s.owner, Known: s.known})
	}
	return out
}

// socketPIDs finds the process of each socket inode in want through
// /proc/<pid>/fd. Processes whose descriptors cannot be listed are skipped.
func socketPIDs(ctx context.Context, proc fs.FS, want map[uint64]bool) map[uint64]int {
	found := map[uint64]int{}
	entries, err := fs.ReadDir(proc, ".")
	if err != nil {
		return found
	}
	for _, e := range entries {
		if ctx.Err() != nil || len(found) == len(want) {
			break
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fds, err := fs.ReadDir(proc, e.Name()+"/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := fs.ReadLink(proc, e.Name()+"/fd/"+fd.Name())
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok || !want[inode] {
				continue
			}
			if _, dup := found[inode]; !dup {
				found[inode] = pid
			}
		}
	}
	return found
}

// socketInode reads "socket:[<inode>]".
func socketInode(target string) (uint64, bool) {
	num, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return 0, false
	}
	num, ok = strings.CutSuffix(num, "]")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(num, 10, 64)
	return n, err == nil
}

// dockerIDRe finds a container id in /proc/<pid>/cgroup, for the systemd and
// the cgroupfs drivers, also seen from another cgroup namespace.
var dockerIDRe = regexp.MustCompile(`(?:docker-|/docker/)([0-9a-f]{64})`)

func describeProcess(proc fs.FS, pid int, byID map[string]containerInfo) string {
	comm := "?"
	if data, err := readSmall(proc, strconv.Itoa(pid)+"/comm", 256); err == nil {
		if c := clipText(strings.TrimSpace(string(data)), 64); c != "" {
			comm = c
		}
	}
	if data, err := readSmall(proc, strconv.Itoa(pid)+"/cgroup", 16<<10); err == nil {
		if m := dockerIDRe.FindSubmatch(data); m != nil {
			if c, ok := byID[string(m[1])]; ok {
				if c.managed {
					return c.name
				}
				return fmt.Sprintf("%s (container %s)", comm, c.name)
			}
		}
	}
	return fmt.Sprintf("%s (pid %d)", comm, pid)
}

// listContainers returns the containers by id, and the names of the agent's
// own containers that run. Without Docker both are empty.
func listContainers(ctx context.Context, docker dockerapi.Client) (map[string]containerInfo, map[string]bool) {
	byID := map[string]containerInfo{}
	running := map[string]bool{}
	if docker == nil {
		return byID, running
	}
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	list, err := docker.List(ctx, nil, true)
	if err != nil {
		return byID, running
	}
	for _, c := range list {
		managed := c.Labels["postern.managed"] == "true"
		byID[c.ID] = containerInfo{name: clipText(c.Name, 128), managed: managed}
		if managed && c.State == "running" {
			running[c.Name] = true
		}
	}
	return byID, running
}

func readSmall(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

// expectedOwners names the agent's container that should hold each address
// the desired state and the runtime record give it: the edge holds the
// listeners, the test listeners and the engines' SOCKS ports; an engine holds
// its listen and API ports.
func expectedOwners(st *nodev1.NodeState, rt *state.Runtime) map[sockAddr]string {
	out := map[sockAddr]string{}
	if rt == nil {
		return out
	}
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	edge := ""
	if rt.EdgeGeneration > 0 {
		edge = fmt.Sprintf("postern-edge-g%d", rt.EdgeGeneration)
		for _, l := range st.GetListeners() {
			if a, err := netip.ParseAddr(l.GetBindIp()); err == nil && l.GetPort() > 0 && l.GetPort() <= 65535 {
				out[netip.AddrPortFrom(a.Unmap(), uint16(l.GetPort()))] = edge
			}
		}
	}
	for key, port := range rt.Ports {
		at := netip.AddrPortFrom(loopback, port)
		parts := strings.Split(key, ":")
		switch {
		case len(parts) == 3 && parts[0] == "svc" && parts[1] == "test" && edge != "":
			out[at] = edge
		case len(parts) == 4 && parts[0] == "eng" && parts[3] == state.PortSocks && edge != "":
			out[at] = edge
		case len(parts) == 4 && parts[0] == "eng" && (parts[3] == state.PortListen || parts[3] == state.PortAPI):
			gen, err := strconv.ParseUint(strings.TrimPrefix(parts[2], "g"), 10, 64)
			if err == nil && gen > 0 {
				out[at] = fmt.Sprintf("postern-eng-%s-g%d", strings.ToLower(parts[1]), gen)
			}
		case len(parts) == 4 && parts[0] == "egr":
			// The SOCKS port of a member of a provider instance.
			gen, err := strconv.ParseUint(strings.TrimPrefix(parts[2], "g"), 10, 64)
			if err == nil && gen > 0 {
				out[at] = fmt.Sprintf("postern-egr-%s-g%d", strings.ToLower(parts[1]), gen)
			}
		}
	}
	return out
}
