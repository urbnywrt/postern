package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/state"
)

func TestParseOSRelease(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"double quotes", "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n", "Ubuntu 24.04.1 LTS"},
		{"single quotes", "PRETTY_NAME='Debian GNU/Linux 12 (bookworm)'\n", "Debian GNU/Linux 12 (bookworm)"},
		{"bare", "PRETTY_NAME=Alpine\n", "Alpine"},
		{"escapes", `PRETTY_NAME="Say \"hi\" \\ \$HOME"` + "\n", `Say "hi" \ $HOME`},
		{"comments and blanks", "# PRETTY_NAME=\"no\"\n\n  PRETTY_NAME=\"Fedora Linux 41\"  \n", "Fedora Linux 41"},
		{"no pretty name", "NAME=\"Arch Linux\"\n", "Linux"},
		{"control characters", "PRETTY_NAME=\"bad\x01name\"\n", "badname"},
		{"long", "PRETTY_NAME=\"" + strings.Repeat("x", 600) + "\"\n", strings.Repeat("x", maxOSName)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseOSRelease([]byte(tc.in)); got != tc.want {
				t.Errorf("parseOSRelease = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOSNameReadsTheHostFileFirst(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "host-os-release")
	own := filepath.Join(dir, "os-release")
	if err := os.WriteFile(own, []byte("PRETTY_NAME=\"Alpine Linux v3.22\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := &hostInfo{osRelease: []string{host, own}}
	if got := h.osName(); got != "Alpine Linux v3.22" {
		t.Errorf("without the host file: %q", got)
	}
	if err := os.WriteFile(host, []byte("PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := h.osName(); got != "Ubuntu 24.04.1 LTS" {
		t.Errorf("with the host file: %q", got)
	}
	if got := (&hostInfo{osRelease: []string{filepath.Join(dir, "none")}}).osName(); got != "" {
		t.Errorf("with no file: %q", got)
	}
}

func ipNet(cidr string) net.Addr {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}

func TestPublicIPsOfTheInterfaces(t *testing.T) {
	mapped := &net.IPNet{IP: net.ParseIP("198.51.100.7").To16(), Mask: net.CIDRMask(120, 128)}
	addrs := []net.Addr{
		ipNet("127.0.0.1/8"), ipNet("10.1.2.3/8"), ipNet("192.168.1.5/24"), ipNet("172.17.0.1/16"),
		ipNet("100.64.1.1/10"), ipNet("169.254.1.1/16"), ipNet("203.0.113.10/24"), mapped,
		ipNet("fe80::1/64"), ipNet("fd00::1/8"), ipNet("2001:db8::10/64"), ipNet("::1/128"),
		ipNet("203.0.113.10/32"), // the same address twice
	}
	var echoed atomic.Int32
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		echoed.Add(1)
		_, _ = fmt.Fprintln(w, "198.51.100.99")
	}))
	defer echo.Close()
	h := &hostInfo{
		addrs:    func() ([]net.Addr, error) { return addrs, nil },
		echoURLs: []string{echo.URL},
		now:      time.Now,
		log:      discardLog(),
	}
	got := h.publicIPs(context.Background())
	if want := []string{"198.51.100.7", "203.0.113.10", "2001:db8::10"}; !slices.Equal(got, want) {
		t.Errorf("publicIPs = %v, want %v", got, want)
	}
	if got := h.publicIPv4(context.Background()); got != "198.51.100.7" {
		t.Errorf("publicIPv4 = %q", got)
	}
	if n := echoed.Load(); n != 0 {
		t.Errorf("the echo service was asked %d times although an interface has a public address", n)
	}
}

func TestPublicIPsFallBackToTheEchoServices(t *testing.T) {
	var asked atomic.Int32
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		http.Error(w, "no", http.StatusBadGateway)
	}))
	defer failing.Close()
	private := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = fmt.Fprint(w, "10.0.0.1")
	}))
	defer private.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = fmt.Fprint(w, "  198.51.100.23\n")
	}))
	defer good.Close()

	clock := newTestClock()
	h := &hostInfo{
		addrs:    func() ([]net.Addr, error) { return []net.Addr{ipNet("10.1.2.3/8"), ipNet("127.0.0.1/8")}, nil },
		echoURLs: []string{failing.URL, private.URL, good.URL},
		now:      clock.Now,
		log:      discardLog(),
	}
	if got := h.publicIPs(context.Background()); !slices.Equal(got, []string{"198.51.100.23"}) {
		t.Fatalf("publicIPs = %v", got)
	}
	if n := asked.Load(); n != 3 {
		t.Errorf("asked %d services, want 3", n)
	}
	// The answer is kept for a while.
	if got := h.publicIPv4(context.Background()); got != "198.51.100.23" {
		t.Errorf("publicIPv4 = %q", got)
	}
	if n := asked.Load(); n != 3 {
		t.Errorf("asked again within the cache time: %d", n)
	}
	clock.Advance(echoCacheOK + time.Second)
	h.publicIPs(context.Background())
	if n := asked.Load(); n != 6 {
		t.Errorf("not asked again after the cache time: %d", n)
	}
}

func TestPublicIPsWithoutAnswer(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	h := &hostInfo{
		addrs:    func() ([]net.Addr, error) { return nil, fmt.Errorf("no interfaces") },
		echoURLs: []string{down.URL, "http://127.0.0.1:1/ip"},
		now:      time.Now,
		log:      discardLog(),
	}
	if got := h.publicIPs(context.Background()); len(got) != 0 {
		t.Errorf("publicIPs = %v, want none", got)
	}
	if got := h.publicIPv4(context.Background()); got != "" {
		t.Errorf("publicIPv4 = %q, want empty", got)
	}
}

func putArtifact(t *testing.T, store *artifacts.Store, engine, version, arch string, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	err := store.Put(artifacts.Ref{Engine: engine, Version: version, Arch: arch, SHA256: strings.ToUpper(sha), FileName: "telemt", Binary: "telemt"}, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return sha
}

func TestListArtifacts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifacts")
	store := &artifacts.Store{Root: root}
	sha1 := putArtifact(t, store, "telemt", "3.5.13", "amd64", []byte("binary one"))
	sha2 := putArtifact(t, store, "telemt", "3.5.12", "arm64", []byte("binary two"))
	// Leftovers that are not artifacts.
	for _, dir := range []string{".stage-123", "telemt/3.5.13/.amd64.old-abc", "telemt/9.9.9/amd64", "telemt/3.5.11/amd64"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "telemt/9.9.9/amd64/telemt"), []byte("no marker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "telemt/3.5.11/amd64/telemt"), []byte("bad marker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "telemt/3.5.11/amd64/.sha256"), []byte("not a checksum\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A checksum marker that is right, beside files the store would never
	// have written: a name it refuses, and a directory name it refuses.
	for _, dir := range []string{"telemt/3.5.10/amd64", "tel emt/3.5.13/amd64"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, ".sha256"), []byte(sha1+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "telemt/3.5.10/amd64/tel emt"), []byte("binary one"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tel emt/3.5.13/amd64/telemt"), []byte("binary one"), 0o755); err != nil {
		t.Fatal(err)
	}

	// One artifact is untried, one failed its trial with a long reason, one
	// passed.
	sha3 := putArtifact(t, store, "telemt", "3.5.14", "amd64", []byte("binary three"))
	longReason := strings.Repeat("ё", 200) // 400 bytes
	if err := store.RecordTrial(artifacts.Ref{Engine: "telemt", Version: "3.5.13", Arch: "amd64", SHA256: sha1, Binary: "telemt"},
		artifacts.TrialRecord{OK: false, Reason: longReason, At: time.Now(), Image: RunnerImage}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordTrial(artifacts.Ref{Engine: "telemt", Version: "3.5.14", Arch: "amd64", SHA256: sha3, Binary: "telemt"},
		artifacts.TrialRecord{OK: true, At: time.Now(), Image: RunnerImage}); err != nil {
		t.Fatal(err)
	}

	got := listArtifacts(store)
	want := []*nodev1.ArtifactRef{
		{Engine: "telemt", Version: "3.5.12", Arch: "arm64", Sha256: sha2, Binary: "telemt", State: "untried"},
		{Engine: "telemt", Version: "3.5.13", Arch: "amd64", Sha256: sha1, Binary: "telemt", State: "unusable", StateReason: strings.Repeat("ё", 128)},
		{Engine: "telemt", Version: "3.5.14", Arch: "amd64", Sha256: sha3, Binary: "telemt"},
	}
	if len(got) != len(want) {
		t.Fatalf("artifacts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i].String() {
			t.Errorf("artifact %d = %v, want %v", i, got[i], want[i])
		}
	}
	if got := listArtifacts(&artifacts.Store{Root: filepath.Join(t.TempDir(), "none")}); len(got) != 0 {
		t.Errorf("an empty store lists %v", got)
	}
}

// procNetLine formats a line of /proc/net/tcp{,6}.
func procNetLine(n int, local string, state string, inode int) string {
	return fmt.Sprintf("%4d: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n", n, local, state, inode)
}

const procNetHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func symlink(target string) *fstest.MapFile {
	return &fstest.MapFile{Mode: fs.ModeSymlink | 0o777, Data: []byte(target)}
}

// deniedFS refuses to list the directories in deny, as procfs does for the fd
// directories of processes the agent may not look into.
type deniedFS struct {
	fstest.MapFS
	deny map[string]bool
}

func (d deniedFS) Open(name string) (fs.File, error) {
	if d.deny[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.MapFS.Open(name)
}

func (d deniedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if d.deny[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.MapFS.ReadDir(name)
}

func (d deniedFS) ReadLink(name string) (string, error) { return d.MapFS.ReadLink(name) }

func (d deniedFS) Lstat(name string) (fs.FileInfo, error) { return d.MapFS.Lstat(name) }

func containerID(t *testing.T, docker dockerapi.Client, name string) string {
	t.Helper()
	c, err := docker.Inspect(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func addTestContainer(t *testing.T, docker *dockerapi.Fake, name string, labels map[string]string, running bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := docker.Create(ctx, dockerapi.ContainerSpec{Name: name, Image: "alpine:3.22", NetworkMode: "host", Labels: labels}); err != nil {
		t.Fatal(err)
	}
	if running {
		if err := docker.Start(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
}

func managedLabels(role, id string, gen int) map[string]string {
	return map[string]string{"postern.managed": "true", "postern.role": role, "postern.id": id, "postern.generation": fmt.Sprint(gen)}
}

// portsWorld is a host with an edge, a host nginx, a foreign container and a
// process the agent may not look into.
func portsWorld(t *testing.T) (deniedFS, *dockerapi.Fake) {
	t.Helper()
	docker := dockerapi.NewFake()
	addTestContainer(t, docker, "postern-edge-g2", managedLabels("edge", "edge", 2), true)
	addTestContainer(t, docker, "postern-eng-p1-g1", managedLabels("engine", "p1", 1), true)
	addTestContainer(t, docker, "postern-eng-p2-g4", managedLabels("engine", "p2", 4), false)
	addTestContainer(t, docker, "remnanode", map[string]string{"app": "other"}, true)
	edgeID := containerID(t, docker, "postern-edge-g2")
	otherID := containerID(t, docker, "remnanode")

	tcp := procNetHeader +
		procNetLine(0, "00000000:01BB", "0A", 1001) + // 0.0.0.0:443, the edge
		procNetLine(1, "0100007F:1F90", "0A", 1002) + // 127.0.0.1:8080, nginx
		procNetLine(2, "00000000:0805", "0A", 1003) + // 0.0.0.0:2053, a foreign container
		procNetLine(3, "0100007F:4E20", "0A", 1004) + // 127.0.0.1:20000, a process we cannot see: engine p1
		procNetLine(4, "0100007F:4E21", "0A", 1005) + // 127.0.0.1:20001, nobody we know
		procNetLine(5, "0100007F:4E22", "0A", 1009) + // 127.0.0.1:20002, engine p2, not running
		procNetLine(6, "0A7100CB:15B3", "01", 1006) // 203.0.113.10:5555, a connection, not a listener
	tcp6 := procNetHeader +
		procNetLine(0, "00000000000000000000000000000000:01BB", "0A", 1007) + // [::]:443, the edge
		procNetLine(1, "00000000000000000000000001000000:2328", "0A", 1008) // [::1]:9000, nginx

	proc := deniedFS{MapFS: fstest.MapFS{
		"net/tcp":       {Data: []byte(tcp)},
		"net/tcp6":      {Data: []byte(tcp6)},
		"200/comm":      {Data: []byte("postern-node-v1\n")},
		"200/cgroup":    {Data: []byte("0::/system.slice/docker-" + edgeID + ".scope\n")},
		"200/fd/3":      symlink("socket:[1001]"),
		"200/fd/4":      symlink("socket:[1007]"),
		"200/fd/5":      symlink("/dev/null"),
		"300/comm":      {Data: []byte("nginx\n")},
		"300/cgroup":    {Data: []byte("0::/system.slice/nginx.service\n")},
		"300/fd/6":      symlink("socket:[1002]"),
		"300/fd/7":      symlink("socket:[1008]"),
		"400/comm":      {Data: []byte("xray\n")},
		"400/cgroup":    {Data: []byte("0::/../docker-" + otherID + ".scope\n")},
		"400/fd/3":      symlink("socket:[1003]"),
		"500/comm":      {Data: []byte("telemt\n")},
		"500/fd/3":      symlink("socket:[1004]"),
		"self/fd/0":     symlink("/dev/null"),
		"sys/kernel/x":  {Data: []byte("1")},
		"acpi/whatever": {Data: []byte("1")},
	}, deny: map[string]bool{"500/fd": true}}
	return proc, docker
}

func ownersMap(owners []*nodev1.PortOwner) map[string]string {
	m := map[string]string{}
	for _, o := range owners {
		m[net.JoinHostPort(o.GetBind(), fmt.Sprint(o.GetPort()))] = o.GetOwner()
	}
	return m
}

func TestPortOwners(t *testing.T) {
	proc, docker := portsWorld(t)
	expected := map[sockAddr]string{
		mustSockAddr("127.0.0.1:20000"): "postern-eng-p1-g1",
		mustSockAddr("127.0.0.1:20002"): "postern-eng-p2-g4",
		mustSockAddr("0.0.0.0:443"):     "postern-edge-g2",
	}
	got := portOwners(context.Background(), proc, docker, expected)
	want := map[string]string{
		"0.0.0.0:443":     "postern-edge-g2",
		"[::]:443":        "postern-edge-g2",
		"127.0.0.1:8080":  "nginx (pid 300)",
		"[::1]:9000":      "nginx (pid 300)",
		"0.0.0.0:2053":    "xray (container remnanode)",
		"127.0.0.1:20000": "postern-eng-p1-g1",
		"127.0.0.1:20001": "unknown",
		"127.0.0.1:20002": "unknown",
	}
	if m := ownersMap(got); !mapsEqual(m, want) {
		t.Errorf("owners = %v\nwant %v", m, want)
	}
	// Sorted by port, then address.
	for i := 1; i < len(got); i++ {
		if got[i-1].GetPort() > got[i].GetPort() {
			t.Errorf("not sorted by port: %v", got)
		}
	}
}

// Without Docker the processes are still named; what only Docker could
// confirm stays unknown.
func TestPortOwnersWithoutDocker(t *testing.T) {
	proc, _ := portsWorld(t)
	expected := map[sockAddr]string{mustSockAddr("127.0.0.1:20000"): "postern-eng-p1-g1"}
	broken := dockerapi.NewFake()
	broken.SetError("*", fmt.Errorf("docker is down"))
	for _, docker := range []dockerapi.Client{nil, broken} {
		m := ownersMap(portOwners(context.Background(), proc, docker, expected))
		if m["0.0.0.0:443"] != "postern-node-v1 (pid 200)" || m["127.0.0.1:20000"] != "unknown" || m["127.0.0.1:8080"] != "nginx (pid 300)" {
			t.Errorf("owners without docker (%T) = %v", docker, m)
		}
	}
}

func TestPortOwnersWithoutProcNet(t *testing.T) {
	if got := portOwners(context.Background(), fstest.MapFS{}, nil, nil); len(got) != 0 {
		t.Errorf("owners = %v, want none", got)
	}
}

func TestParseProcNet(t *testing.T) {
	data := procNetHeader +
		procNetLine(0, "0100007F:0050", "0A", 11) +
		"garbage line\n" +
		procNetLine(1, "zz:0050", "0A", 12) +
		procNetLine(2, "00000000:0016", "06", 13)
	got := parseProcNet([]byte(data), false)
	if len(got) != 1 || got[0].addr.String() != "127.0.0.1:80" || got[0].inode != 11 {
		t.Errorf("parseProcNet = %+v", got)
	}
	v6 := procNetHeader + procNetLine(0, "B80D0120000000000000000010000000:01BB", "0A", 21)
	got = parseProcNet([]byte(v6), true)
	if len(got) != 1 || got[0].addr.String() != "[2001:db8::10]:443" {
		t.Errorf("parseProcNet v6 = %+v", got)
	}
}

func mustSockAddr(s string) sockAddr { return netip.MustParseAddrPort(s) }

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// The node's own containers own the loopback ports of the runtime record: an
// engine its listen and API ports, the edge the SOCKS ports of the engines and
// the test listeners, a provider instance the SOCKS ports of its members.
func TestExpectedOwnersOfTheRecordedPorts(t *testing.T) {
	rt := state.NewRuntime()
	rt.EdgeGeneration = 3
	rt.Ports = map[string]uint16{
		state.EnginePortKey("P1", 1, state.PortListen): 20001,
		state.EnginePortKey("P1", 1, state.PortSocks):  30001,
		state.TestListenerPortKey("L1"):                40001,
		state.EgressPortKey("NL", 2, "0123456789ab"):   35001,
		state.EgressPortKey("NL", 2, "warp"):           35002,
	}
	got := expectedOwners(nil, rt)
	want := map[string]string{
		"127.0.0.1:20001": "postern-eng-p1-g1",
		"127.0.0.1:30001": "postern-edge-g3",
		"127.0.0.1:40001": "postern-edge-g3",
		"127.0.0.1:35001": "postern-egr-nl-g2",
		"127.0.0.1:35002": "postern-egr-nl-g2",
	}
	if len(got) != len(want) {
		t.Errorf("owners = %v, want %v", got, want)
	}
	for addr, owner := range want {
		if got[mustSockAddr(addr)] != owner {
			t.Errorf("owner of %s = %q, want %q", addr, got[mustSockAddr(addr)], owner)
		}
	}
}
