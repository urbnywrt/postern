package deploy

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// preflightScript is the script that finds out the facts of a server; see the
// comment at its top.
//
//go:embed preflight.sh
var preflightScript string

// sharedFunctions is what the preflight and the setup of Docker share: the
// PATH, and functions. The panel puts it before each, after root=.
//
//go:embed shared.sh
var sharedFunctions string

const (
	// preflightMarker starts the line of the output that holds the facts.
	preflightMarker = "postern-preflight "

	// maxPreflightOutput bounds what the preflight may print, all of it: the
	// line of the facts and whatever a login shell adds.
	maxPreflightOutput = 2 << 20

	// maxFactKeys and maxFactKey bound the keys of the facts, and maxFact the
	// size of one value once it is decoded: the script cuts each at 256 KiB at
	// most.
	maxFactKeys = 64
	maxFactKey  = 32
	maxFact     = 256 << 10

	// maxText is the most of a text from the server that the panel keeps or
	// shows: a name, a version, a line of an error.
	maxText = 200

	// maxListeners and maxProcesses bound what is kept of the listening
	// sockets of a server.
	maxListeners = 512
	maxProcesses = 16
)

// packageTools are the package tools that the preflight looks for.
var packageTools = []string{"apt-get", "dnf", "yum", "apk", "zypper", "pacman"}

// The architectures of the node kits, by what uname -m says.
var machineArch = map[string]string{
	"x86_64":  "amd64",
	"amd64":   "amd64",
	"aarch64": "arm64",
	"arm64":   "arm64",
}

// preflightCommand is the script with its parameters: the management port of
// the node, which it looks for among the listening ports, and root, the
// directory of /etc and /proc, which is "" but for the tests.
func preflightCommand(mgmtPort uint32, root string) string {
	return "mgmt_port=" + strconv.FormatUint(uint64(mgmtPort), 10) + "\nroot=" + shellQuote(root) + "\n" + sharedFunctions + preflightScript
}

// shellQuote quotes s for sh, in single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Facts are what the preflight found out about a server. What it could not
// find out is zero: an empty string, a nil slice or pointer, false.
type Facts struct {
	// RemoteTime is the clock of the server when the preflight started.
	RemoteTime time.Time
	UID        int    // the user that the commands run as; -1 when unknown
	Machine    string // what uname -m says
	Arch       string // amd64 or arm64, the architecture of the node kit; "" for any other machine
	OS         OSInfo

	BashMajor int // the major version of bash; 0 when there is no bash

	// PackageTools are the package tools of the server, of apt-get, dnf, yum,
	// apk, zypper and pacman.
	PackageTools []string

	Docker     DockerInfo
	Containers []Container // every container, when Docker answers

	DiskPath string // /opt, or / when there is no /opt
	Disk     *Disk

	// ListenTool says where Listeners come from: "ss", "netstat", or "proc",
	// the tables of the kernel, which do not name processes.
	ListenTool string
	Listeners  []Listener
	// ContainerOf is the container of each process that listens on 443 or on
	// the management port and that runs in a container of Docker.
	ContainerOf map[int]string

	PublicIPs []netip.Addr // the public addresses of the interfaces
}

// OSInfo is what /etc/os-release says.
type OSInfo struct {
	PrettyName string
	ID         string
	VersionID  string
}

// DockerInfo is what the server says about Docker.
type DockerInfo struct {
	Installed bool
	// Version is the version of the daemon; "" when it did not answer, and
	// then Problem says why, in a line.
	Version string
	Problem string
	// Stopped says that the daemon does not run, as systemd or pidof says;
	// Problem is dockerStopped then.
	Stopped bool
	// UsernsRemap says that the daemon remaps user namespaces, which Postern
	// does not support.
	UsernsRemap bool
	// ComposeVersion is the version of the Compose v2 plugin; "" when there
	// is none.
	ComposeVersion string
	// Origin is the packages that the engine comes from: docker-ce,
	// docker.io or alpine; "" for others, such as a static binary.
	Origin string
}

// A Container is one of the containers of Docker.
type Container struct {
	ID      string // 64 hex digits
	Name    string
	Status  string
	Postern bool // it has the label postern.managed=true
}

// Disk is the free and the whole space of the file system of DiskPath.
type Disk struct {
	FreeBytes  uint64
	TotalBytes uint64
}

// A Listener is a listening TCP socket.
type Listener struct {
	Addr      netip.Addr // the unspecified address for every address; invalid when it could not be read
	Port      uint16
	Processes []Process // nil when the tool does not say
}

// A Process is a process that holds a listening socket.
type Process struct {
	Name string
	PID  int
}

// errNoFacts is the error of an output that does not hold the line of the facts.
var errNoFacts = errors.New("the preflight printed no facts")

// parsePreflight reads the facts from what the preflight printed: the last
// line that starts with the marker. Everything in it is checked; a value that
// does not make sense is left out, as if the server had not said it.
func parsePreflight(out []byte) (*Facts, error) {
	raw, err := decodeFacts(out)
	if err != nil {
		return nil, err
	}
	if string(raw["format"]) != "1" {
		return nil, fmt.Errorf("the preflight speaks format %q, not 1", plain(string(raw["format"]), 16))
	}
	f := &Facts{UID: -1}
	if sec, err := strconv.ParseInt(string(raw["time"]), 10, 64); err == nil && sec > 1e9 && sec < 1e10 {
		f.RemoteTime = time.Unix(sec, 0)
	}
	if uid, err := strconv.Atoi(string(raw["uid"])); err == nil && uid >= 0 {
		f.UID = uid
	}
	f.Machine = plain(string(raw["machine"]), 64)
	f.Arch = machineArch[f.Machine]
	f.OS = parseOSRelease(raw["os_release"])
	if ran(raw, "bash") {
		if major, err := strconv.Atoi(strings.TrimSpace(string(raw["bash"]))); err == nil && major > 0 && major < 100 {
			f.BashMajor = major
		}
	}
	for t := range strings.FieldsSeq(string(raw["package_tools"])) {
		if slices.Contains(packageTools, t) && !slices.Contains(f.PackageTools, t) {
			f.PackageTools = append(f.PackageTools, t)
		}
	}
	f.Docker = parseDocker(raw)
	if ran(raw, "containers") {
		f.Containers = parseContainers(raw["containers"])
	}
	if p := string(raw["disk_path"]); p == "/opt" || p == "/" {
		f.DiskPath = p
		if ran(raw, "df") {
			f.Disk = parseDF(raw["df"])
		}
	}
	switch tool := string(raw["listen_tool"]); tool {
	case "ss", "netstat", "proc":
		f.ListenTool = tool
		f.Listeners = parseListeners(tool, raw["listen"])
	}
	f.ContainerOf = parseCgroups(raw["pids"])
	if _, ok := raw["addrs"]; ok {
		f.PublicIPs = parseAddrs(raw["addrs"])
	}
	return f, nil
}

// decodeFacts finds the line of the facts in the output and decodes it into its
// values, by key.
func decodeFacts(out []byte) (map[string][]byte, error) {
	if len(out) > maxPreflightOutput {
		return nil, fmt.Errorf("the preflight printed more than %d bytes", maxPreflightOutput)
	}
	var line []byte
	for l := range bytes.SplitSeq(out, []byte("\n")) {
		if rest, ok := bytes.CutPrefix(bytes.TrimRight(l, "\r"), []byte(preflightMarker)); ok {
			line = rest
		}
	}
	if line == nil {
		return nil, errNoFacts
	}
	var values map[string]string
	if err := json.Unmarshal(line, &values); err != nil {
		return nil, fmt.Errorf("the facts of the preflight are not a JSON object of strings: %w", err)
	}
	if len(values) > maxFactKeys {
		return nil, fmt.Errorf("the preflight printed %d facts, more than %d", len(values), maxFactKeys)
	}
	raw := make(map[string][]byte, len(values))
	for k, v := range values {
		if !factKey(k) {
			return nil, fmt.Errorf("the preflight printed a fact with the key %q", plain(k, maxFactKey))
		}
		if base64.StdEncoding.DecodedLen(len(v)) > maxFact+3 {
			return nil, fmt.Errorf("the fact %s is larger than %d bytes", k, maxFact)
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("the fact %s is not base64: %w", k, err)
		}
		if len(b) > maxFact {
			return nil, fmt.Errorf("the fact %s is larger than %d bytes", k, maxFact)
		}
		raw[k] = b
	}
	return raw, nil
}

// factKey reports whether k may be the key of a fact: lower-case letters,
// digits and underscores.
func factKey(k string) bool {
	if k == "" || len(k) > maxFactKey {
		return false
	}
	for _, r := range k {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// ran reports whether the command of key ran and exited with 0.
func ran(raw map[string][]byte, key string) bool {
	_, ok := raw[key]
	return ok && string(raw[key+"_rc"]) == "0"
}

// plain returns s as one line of plain text: valid UTF-8 without control
// characters (a tab becomes a space), without spaces around it, and at most
// max bytes, cut between characters with "…" where it was cut.
func plain(s string, max int) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, s))
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// firstLine returns the first line of b that is not empty, as plain text.
func firstLine(b []byte) string {
	for l := range strings.SplitSeq(string(b), "\n") {
		if s := plain(l, maxText); s != "" {
			return s
		}
	}
	return ""
}

// parseOSRelease reads PRETTY_NAME, ID and VERSION_ID from an os-release file.
func parseOSRelease(data []byte) OSInfo {
	var info OSInfo
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		value = plain(unquote(strings.TrimSpace(value)), 128)
		switch strings.TrimSpace(key) {
		case "PRETTY_NAME":
			info.PrettyName = value
		case "ID":
			info.ID = value
		case "VERSION_ID":
			info.VersionID = value
		}
	}
	return info
}

// unquote undoes the quoting of os-release: double quotes with backslash
// escapes, single quotes, or none.
func unquote(v string) string {
	switch {
	case len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'':
		return v[1 : len(v)-1]
	case len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"':
		var b strings.Builder
		inner := v[1 : len(v)-1]
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\\' && i+1 < len(inner) {
				i++
			}
			b.WriteByte(inner[i])
		}
		return b.String()
	}
	return v
}

var (
	versionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)
	composeRe = regexp.MustCompile(`\bv?([0-9]+)\.([0-9]+)\.([0-9]+[0-9A-Za-z.+_-]{0,48})`)
)

// dockerStopped is the problem of a Docker whose daemon does not run, which the
// preflight does not ask.
const dockerStopped = "the Docker daemon does not run"

// parseDocker reads what docker said about itself.
func parseDocker(raw map[string][]byte) DockerInfo {
	var d DockerInfo
	if _, ok := raw["docker"]; !ok {
		return d
	}
	d.Installed = true
	if string(raw["docker_active"]) == "no" {
		d.Stopped, d.Problem = true, dockerStopped
	} else if v := strings.TrimSpace(string(raw["docker_version"])); ran(raw, "docker_version") && versionRe.MatchString(v) {
		d.Version = v
	} else {
		d.Problem = firstLine(raw["docker_version"])
		if d.Problem == "" {
			d.Problem = "docker version failed"
		}
	}
	if ran(raw, "docker_security") {
		d.UsernsRemap = bytes.Contains(raw["docker_security"], []byte("name=userns"))
	}
	switch o := string(raw["docker_origin"]); o {
	case "docker-ce", "docker.io", "alpine":
		d.Origin = o
	}
	if ran(raw, "compose_version") {
		if m := composeRe.FindStringSubmatch(string(raw["compose_version"])); m != nil {
			if major, err := strconv.Atoi(m[1]); err == nil && major >= 2 {
				d.ComposeVersion = m[1] + "." + m[2] + "." + m[3]
			}
		}
	}
	return d
}

var (
	containerIDRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	containerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
)

// parseContainers reads the lines of docker ps: id|names|postern.managed|status.
func parseContainers(data []byte) []Container {
	var out []Container
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.SplitN(strings.TrimRight(line, "\r"), "|", 4)
		if len(fields) != 4 || !containerIDRe.MatchString(fields[0]) {
			continue
		}
		// A container that others link to has more than one name; the first is its own.
		name, _, _ := strings.Cut(fields[1], ",")
		if !containerNameRe.MatchString(name) {
			continue
		}
		out = append(out, Container{ID: fields[0], Name: name, Postern: fields[2] == "true", Status: plain(fields[3], 64)})
		if len(out) == 4096 {
			break
		}
	}
	return out
}

// parseDF reads the free and the whole space from df -Pk: the line after the
// header, whose capacity is the first field that ends in %, after the size,
// the used and the available space in KiB.
func parseDF(data []byte) *Disk {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return nil
	}
	fields := strings.Fields(strings.Join(lines[1:], " "))
	for i := 3; i < len(fields); i++ {
		if !strings.HasSuffix(fields[i], "%") {
			continue
		}
		total, err1 := strconv.ParseUint(fields[i-3], 10, 64)
		free, err2 := strconv.ParseUint(fields[i-1], 10, 64)
		if err1 != nil || err2 != nil || free > total || total > 1<<50 {
			return nil
		}
		return &Disk{FreeBytes: free << 10, TotalBytes: total << 10}
	}
	return nil
}

// parseListeners reads the listening sockets from the output of tool.
func parseListeners(tool string, data []byte) []Listener {
	var out []Listener
	for line := range strings.SplitSeq(string(data), "\n") {
		var (
			l  Listener
			ok bool
		)
		switch tool {
		case "ss":
			l, ok = parseSSLine(line)
		case "netstat":
			l, ok = parseNetstatLine(line)
		case "proc":
			l, ok = parseProcNetLine(line)
		}
		if ok {
			out = append(out, l)
			if len(out) == maxListeners {
				break
			}
		}
	}
	return out
}

// ssUserRe finds the processes in the last column of ss -p:
// users:(("nginx",pid=1234,fd=6),("nginx",pid=1235,fd=6)).
var ssUserRe = regexp.MustCompile(`\("([^"]{0,64})",pid=([0-9]{1,9}),`)

// parseSSLine reads a line of ss -ltnp: state, the queues, the local and the
// peer address, and the processes.
func parseSSLine(line string) (Listener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "LISTEN" {
		return Listener{}, false
	}
	l, ok := splitAddrPort(fields[3])
	if !ok {
		return Listener{}, false
	}
	for _, m := range ssUserRe.FindAllStringSubmatch(strings.Join(fields[5:], " "), maxProcesses) {
		pid, err := strconv.Atoi(m[2])
		if err == nil && pid > 0 {
			l.Processes = append(l.Processes, Process{Name: plain(m[1], 64), PID: pid})
		}
	}
	return l, true
}

// parseNetstatLine reads a line of netstat -ltnp, of busybox or of net-tools:
// the protocol, the queues, the local and the foreign address, the state, and
// pid/program.
func parseNetstatLine(line string) (Listener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 || (fields[0] != "tcp" && fields[0] != "tcp6") || fields[5] != "LISTEN" {
		return Listener{}, false
	}
	l, ok := splitAddrPort(fields[3])
	if !ok {
		return Listener{}, false
	}
	if len(fields) > 6 {
		pidText, name, found := strings.Cut(strings.Join(fields[6:], " "), "/")
		if pid, err := strconv.Atoi(pidText); found && err == nil && pid > 0 {
			l.Processes = []Process{{Name: plain(name, 64), PID: pid}}
		}
	}
	return l, true
}

// splitAddrPort reads a local address as ss and netstat print it: 0.0.0.0:443,
// *:443, [::]:443, :::443, 127.0.0.53%lo:53, [fe80::1%eth0]:22. An address that
// cannot be read is invalid, and the port is kept.
func splitAddrPort(s string) (Listener, bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return Listener{}, false
	}
	port, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil || port == 0 {
		return Listener{}, false
	}
	host := strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]")
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	var addr netip.Addr
	switch host {
	case "0.0.0.0":
		addr = netip.IPv4Unspecified()
	case "::", "", "*":
		// ss prints * for a socket of IPv6 that takes IPv4 as well.
		addr = netip.IPv6Unspecified()
	default:
		if a, err := netip.ParseAddr(host); err == nil {
			addr = a.Unmap()
		}
	}
	return Listener{Addr: addr, Port: uint16(port)}, true
}

// parseProcNetLine reads a line of /proc/net/tcp or tcp6: the listening
// sockets have the state 0A, and the local address is in hex, each 32-bit word
// in the byte order of the host (little-endian on amd64 and arm64).
func parseProcNetLine(line string) (Listener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[3] != "0A" {
		return Listener{}, false
	}
	hexAddr, hexPort, ok := strings.Cut(fields[1], ":")
	if !ok {
		return Listener{}, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil || port == 0 {
		return Listener{}, false
	}
	var addr netip.Addr
	switch len(hexAddr) {
	case 8, 32:
		raw := make([]byte, len(hexAddr)/2)
		for w := 0; w < len(raw)/4; w++ {
			word, err := strconv.ParseUint(hexAddr[8*w:8*w+8], 16, 32)
			if err != nil {
				return Listener{}, false
			}
			raw[4*w], raw[4*w+1], raw[4*w+2], raw[4*w+3] = byte(word), byte(word>>8), byte(word>>16), byte(word>>24)
		}
		a, _ := netip.AddrFromSlice(raw)
		addr = a.Unmap()
	default:
		return Listener{}, false
	}
	return Listener{Addr: addr, Port: uint16(port)}, true
}

// dockerIDRe finds the container of Docker in /proc/<pid>/cgroup, for the
// systemd and the cgroupfs drivers.
var dockerIDRe = regexp.MustCompile(`(?:docker-|/docker/)([0-9a-f]{64})`)

// parseCgroups reads the control groups that the preflight printed, each after
// a line "pid <pid>", and returns the container of each process that runs in
// one.
func parseCgroups(data []byte) map[int]string {
	out := map[int]string{}
	pid := 0
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "pid "); ok {
			pid = 0
			if n, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil && n > 0 {
				pid = n
			}
			continue
		}
		if m := dockerIDRe.FindStringSubmatch(line); m != nil && pid > 0 {
			if _, seen := out[pid]; !seen {
				out[pid] = m[1]
			}
		}
	}
	return out
}

// addrRe finds the addresses that ip -o addr and ifconfig print.
var addrRe = regexp.MustCompile(`\binet6?\s+(?:addr:\s*)?([0-9A-Fa-f][0-9A-Fa-f.:]*)`)

// cgnat is the shared address space of carrier-grade NAT (RFC 6598).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// parseAddrs returns the public addresses among those of the interfaces,
// sorted, IPv4 first.
func parseAddrs(data []byte) []netip.Addr {
	var out []netip.Addr
	for _, m := range addrRe.FindAllStringSubmatch(string(data), 256) {
		a, err := netip.ParseAddr(m[1])
		if err != nil {
			continue
		}
		a = a.Unmap()
		if isPublic(a) && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}
