package psiphoncore

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/warp"
)

// update rewrites the golden files in testdata:
//
//	go test ./internal/providers/psiphoncore -run TestRenderGolden -update
var update = flag.Bool("update", false, "rewrite the golden files in testdata")

const runnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

func psiphon(country string, members ...providers.Member) providers.Instance {
	if members == nil {
		members = []providers.Member{{Key: "psiphon", Port: 35005}}
	}
	return providers.Instance{
		EgressID:    "01J9ZZ0000000000000000PSIP",
		Generation:  2,
		Kind:        nodev1.EgressKind_EGRESS_KIND_PSIPHON,
		Members:     members,
		Country:     country,
		InstanceDir: "/opt/postern/data/egress/01J9ZZ0000000000000000PSIP/g2",
		CacheDir:    "/opt/postern/data/egress/01J9ZZ0000000000000000PSIP/cache-g2",
		BinaryPath:  "/opt/postern/data/artifacts/psiphon-core/20261005-c4a09096ab/amd64/psiphon-core",
		RunnerImage: runnerImage,
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s =\n%s\nwant\n%s", name, got, want)
	}
}

func TestRenderGolden(t *testing.T) {
	files, err := Driver{}.Render(psiphon("de"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("Render wrote %d files", len(files))
	}
	golden(t, "psiphon.json", files[ConfigFile])

	in := psiphon("NL")
	in.PropagationChannelID, in.SponsorID = "0123456789ABCDEF", "FEDCBA9876543210"
	in.CacheDir = ""
	files, err = Driver{}.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "psiphon-partner-nocache.json", files[ConfigFile])
}

// The settings the brief asks for, whatever the golden file says.
func TestRenderSettings(t *testing.T) {
	files, err := Driver{}.Render(psiphon("DE"))
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(files[ConfigFile], &c); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"LocalSocksProxyPort": 35005.0, "ListenInterface": "lo", "DisableLocalHTTPProxy": true,
		"EgressRegion": "DE", "PropagationChannelId": DefaultPartnerID, "SponsorId": DefaultPartnerID,
		"RemoteServerListDownloadFilename": "remote_server_list", "DataRootDirectory": "/var/cache/egress",
		"EstablishTunnelTimeoutSeconds": 0.0, // no limit: the agent's ready timeout decides
	} {
		if c[k] != want {
			t.Errorf("%s = %v, want %v", k, c[k], want)
		}
	}
	if _, ok := c["LocalHttpProxyPort"]; ok {
		t.Error("an HTTP proxy port is set")
	}
	// The rendered file changes with what the instance runs with, so that a
	// hash of it does too.
	a, _ := Driver{}.Render(psiphon("DE"))
	b, _ := Driver{}.Render(psiphon("NL"))
	c2, _ := Driver{}.Render(psiphon("DE", providers.Member{Key: "psiphon", Port: 35006}))
	p := psiphon("DE")
	p.PropagationChannelID, p.SponsorID = "0123456789ABCDEF", "0123456789ABCDEF"
	d, _ := Driver{}.Render(p)
	for _, other := range [][]byte{b[ConfigFile], c2[ConfigFile], d[ConfigFile]} {
		if bytes.Equal(a[ConfigFile], other) {
			t.Error("the rendered file does not follow the country, the port or the partner ids")
		}
	}
}

func TestCountries(t *testing.T) {
	want := "AT AU BE BG CA CH CZ DE DK EE ES FI FR GB HR HU IE IN IT JP LV NL NO PL PT RO RS SE SG SK US"
	if got := strings.Join(Countries(), " "); got != want {
		t.Errorf("Countries = %s\nwant       %s", got, want)
	}
	for _, c := range []string{"", "XX", "RU", "DEU", "D", " DE"} {
		if _, err := (Driver{}).Render(psiphon(c)); err == nil {
			t.Errorf("country %q accepted", c)
		}
	}
}

func TestRenderRefusesBadInstances(t *testing.T) {
	srv := &egressuri.Server{Protocol: "trojan", Address: "example.com", Port: 443, Password: "pass-pass-pass", Network: "tcp", Security: "tls"}
	tests := map[string]providers.Instance{
		"two members":       psiphon("DE", providers.Member{Key: "a", Port: 35005}, providers.Member{Key: "b", Port: 35006}),
		"a server":          psiphon("DE", providers.Member{Key: "a", Port: 35005, Server: srv}),
		"a warp account":    psiphon("DE", providers.Member{Key: "a", Port: 35005, WARP: &warp.Account{}}),
		"port out of range": psiphon("DE", providers.Member{Key: "a", Port: 8086}),
	}
	kind := psiphon("DE")
	kind.Kind = nodev1.EgressKind_EGRESS_KIND_WARP
	tests["kind warp"] = kind
	badID := psiphon("DE")
	badID.EgressID = "a/b"
	tests["bad egress id"] = badID
	for name, ids := range map[string][2]string{
		"one id only":  {"0123456789ABCDEF", ""},
		"lower case":   {"0123456789abcdef", "0123456789ABCDEF"},
		"short":        {"0123456789ABCDE", "0123456789ABCDEF"},
		"injection":    {`0123456789ABCDE"`, "0123456789ABCDEF"},
		"sponsor only": {"", "0123456789ABCDEF"},
	} {
		in := psiphon("DE")
		in.PropagationChannelID, in.SponsorID = ids[0], ids[1]
		tests[name] = in
	}
	for name, in := range tests {
		if _, err := (Driver{}).Render(in); err == nil {
			t.Errorf("%s: Render accepted it", name)
		}
	}
}

func TestContainer(t *testing.T) {
	in := psiphon("DE")
	got := Driver{}.Container(in)
	if fmt.Sprint(got.Entrypoint) != "[/opt/engine/psiphon-core -config /etc/egress/psiphon.json -useNoticeFiles]" {
		t.Errorf("Entrypoint %q", got.Entrypoint)
	}
	wantBinds := []string{
		in.BinaryPath + ":/opt/engine/psiphon-core:ro",
		in.InstanceDir + ":/etc/egress:ro",
		in.CacheDir + ":/var/cache/egress",
	}
	if !reflect.DeepEqual(got.Binds, wantBinds) {
		t.Errorf("Binds %q, want %q", got.Binds, wantBinds)
	}
	if got.User != "65534:65534" || !got.ReadOnly || got.NetworkMode != "host" || got.MemoryBytes != 512<<20 {
		t.Errorf("container %#v", got)
	}
	in.CacheDir, in.ResolvConf = "", "/opt/postern/data/run/resolv.conf"
	b := Driver{}.Container(in).Binds
	if b[1] != in.InstanceDir+":/etc/egress" || b[len(b)-1] != "/opt/postern/data/run/resolv.conf:/etc/resolv.conf:ro" {
		t.Errorf("Binds %q", b)
	}
}

func TestArtifactAndKinds(t *testing.T) {
	d := New()
	for _, arch := range []string{"amd64", "arm64"} {
		if got, err := d.ArtifactFile(arch); err != nil || got != "psiphon-core-linux-"+arch {
			t.Errorf("ArtifactFile(%s) = %q, %v", arch, got, err)
		}
	}
	if _, err := d.ArtifactFile("386"); err == nil {
		t.Error("ArtifactFile(386) = nil error")
	}
	if d.BinaryName() != "psiphon-core" || !d.FilesOwnedByRunner() {
		t.Errorf("BinaryName = %q", d.BinaryName())
	}
	if !reflect.DeepEqual(d.Kinds(), []nodev1.EgressKind{nodev1.EgressKind_EGRESS_KIND_PSIPHON}) {
		t.Errorf("Kinds = %v", d.Kinds())
	}
	var _ providers.RunnerOwnedFiles = d
}

func TestTrial(t *testing.T) {
	tr := New().Trial("20261005-c4a09096ab")
	if !reflect.DeepEqual(tr.Args, []string{"-version"}) || tr.ExitCode != 0 {
		t.Fatalf("Trial = %+v", tr)
	}
	real := "Psiphon Console Client\n  Build Date: 2026-10-05T17:43:13+00:00\n  Built With: go1.26.8\n" +
		"  Repository: https://github.com/Psiphon-Labs/psiphon-tunnel-core.git\n  Revision: c4a09096ab\n"
	for output, want := range map[string]bool{
		real: true,
		strings.Replace(real, "c4a09096ab", "c4a09096ac", 1):  false,
		strings.Replace(real, "c4a09096ab", "c4a09096abc", 1): false,
		strings.Replace(real, "Revision: ", "Revision: x", 1): false,
		"": false,
	} {
		if got := tr.Output.MatchString(output); got != want {
			t.Errorf("Output.MatchString(%q) = %v, want %v", output, got, want)
		}
	}
	for _, bad := range []string{"", "v2.0.41", "c4a09096ab", "20261005-", "20261005-XYZ0000", "20261005-c4a09096ab "} {
		if New().Trial(bad).Output.MatchString(real) {
			t.Errorf("Trial(%q) matches", bad)
		}
	}
}

// Sample notices of the client (one JSON object a line, as -useNoticeFiles
// writes them).
const (
	noticeStart   = `{"data":{"port":35005},"noticeType":"ListeningSocksProxyPort","timestamp":"2026-10-07T10:00:00.000Z"}`
	noticeNone    = `{"data":{"count":0},"noticeType":"Tunnels","timestamp":"2026-10-07T10:00:01.000Z"}`
	noticeOne     = `{"data":{"count":1},"noticeType":"Tunnels","timestamp":"2026-10-07T10:00:09.000Z"}`
	noticeTwo     = `{"data":{"count":2},"noticeType":"Tunnels","timestamp":"2026-10-07T10:00:10.000Z"}`
	noticeActive  = `{"data":{"protocol":"OSSH","region":"DE"},"noticeType":"ActiveTunnel","timestamp":"2026-10-07T10:00:09.000Z"}`
	noticeFakeOne = `{"data":{"message":"\"Tunnels\" count 1"},"noticeType":"Info","timestamp":"2026-10-07T10:00:11.000Z"}`
)

func lines(ls ...string) []byte { return []byte(strings.Join(ls, "\n") + "\n") }

func TestTunnelCount(t *testing.T) {
	for name, tc := range map[string]struct {
		notices []byte
		count   int
		seen    bool
	}{
		"empty":            {nil, 0, false},
		"starting":         {lines(noticeStart), 0, false},
		"none yet":         {lines(noticeStart, noticeNone), 0, true},
		"one":              {lines(noticeStart, noticeNone, noticeActive, noticeOne), 1, true},
		"two":              {lines(noticeOne, noticeTwo), 2, true},
		"lost again":       {lines(noticeOne, noticeNone), 0, true},
		"other notices":    {lines(noticeOne, noticeFakeOne), 1, true},
		"fake only":        {lines(noticeFakeOne), 0, false},
		"cut first line":   {[]byte(noticeOne[20:] + "\n" + noticeNone + "\n"), 0, true},
		"no final newline": {[]byte(noticeNone + "\n" + noticeOne), 1, true},
	} {
		count, seen := TunnelCount(tc.notices)
		if count != tc.count || seen != tc.seen {
			t.Errorf("%s: TunnelCount = %d, %v, want %d, %v", name, count, seen, tc.count, tc.seen)
		}
	}
}

// socks5 answers the SOCKS5 greeting with "no authentication" on a free port
// of the loopback until the test ends, and closes the connection then.
func socks5(t *testing.T) uint16 { return socks5Connect(t, -1, nil) }

// socks5Connect is socks5 that answers a CONNECT too, with the reply code
// connect (-1: it closes after the greeting), and sends the address of each
// CONNECT to asked when it is not nil.
func socks5Connect(t *testing.T, connect int, asked chan<- string) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var greet [3]byte
				if _, err := io.ReadFull(c, greet[:]); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				if connect < 0 {
					return
				}
				var req [10]byte
				if _, err := io.ReadFull(c, req[:]); err != nil || req[1] != 1 || req[3] != 1 {
					return
				}
				if asked != nil {
					asked <- fmt.Sprintf("%d.%d.%d.%d:%d", req[4], req[5], req[6], req[7], int(req[8])<<8|int(req[9]))
				}
				_, _ = c.Write([]byte{5, byte(connect), 0, 1, 0, 0, 0, 0, 0, 0})
			}()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// Without a Tunnels notice that counts one, Ready tries a CONNECT through the
// port to ProbeAddr: a success is a tunnel, a failure is none.
func TestReadyFallsBackToAConnect(t *testing.T) {
	asked := make(chan string, 4)
	in := psiphon("DE")
	in.CacheDir = t.TempDir() // no notices at all
	in.Members[0].Port = socks5Connect(t, 0, asked)
	if err := (Driver{}).Ready(t.Context(), in); err != nil {
		t.Errorf("Ready with a CONNECT that succeeds = %v", err)
	}
	select {
	case got := <-asked:
		if got != ProbeAddr {
			t.Errorf("CONNECT to %s, want %s", got, ProbeAddr)
		}
	case <-time.After(5 * time.Second):
		t.Error("no CONNECT came")
	}
	// The server refuses the CONNECT (5: connection refused, no tunnel).
	in.Members[0].Port = socks5Connect(t, 5, nil)
	if err := (Driver{}).Ready(t.Context(), in); err == nil || !strings.Contains(err.Error(), "no Tunnels notice") {
		t.Errorf("Ready with a CONNECT that fails = %v", err)
	}
	if err := socksConnect(t.Context(), in.Members[0].Port, "example.com:443"); err == nil {
		t.Error("socksConnect took a name for the probe address")
	}
}

func TestReady(t *testing.T) {
	in := psiphon("DE")
	in.CacheDir = t.TempDir()
	in.Members[0].Port = socks5(t)
	write := func(name string, data []byte) {
		t.Helper()
		p := filepath.Join(in.CacheDir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ready := func() error { return Driver{}.Ready(t.Context(), in) }

	// The port answers before there is a tunnel.
	if err := ready(); err == nil || !strings.Contains(err.Error(), "no tunnel") {
		t.Errorf("Ready without notices = %v", err)
	}
	write(NoticeFiles[0], lines(noticeStart, noticeNone))
	if err := ready(); err == nil {
		t.Error("Ready with no tunnel = nil")
	}
	write(NoticeFiles[0], lines(noticeStart, noticeNone, noticeOne))
	if err := ready(); err != nil {
		t.Errorf("Ready with a tunnel = %v", err)
	}
	// Just rotated: the last Tunnels notice is in the older file.
	write(NoticeFiles[1], lines(noticeStart, noticeOne))
	write(NoticeFiles[0], lines(noticeActive))
	if err := ready(); err != nil {
		t.Errorf("Ready after a rotation = %v", err)
	}
	// The newer file decides.
	write(NoticeFiles[0], lines(noticeNone))
	if err := ready(); err == nil {
		t.Error("Ready with the tunnel lost = nil")
	}
	// A notices file that is a symlink out of the data root is not read.
	if err := os.Remove(filepath.Join(in.CacheDir, NoticeFiles[0])); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(in.CacheDir, NoticeFiles[1])); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "notices")
	if err := os.WriteFile(outside, lines(noticeOne), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(in.CacheDir, NoticeFiles[0])); err == nil {
		if err := ready(); err == nil {
			t.Error("Ready read a notices file out of the data root")
		}
	}

	// Without a cache directory the data root is in the instance directory.
	in2 := psiphon("DE")
	in2.CacheDir, in2.InstanceDir = "", t.TempDir()
	in2.Members[0].Port = in.Members[0].Port
	p := filepath.Join(in2.InstanceDir, "data", NoticeFiles[0])
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, lines(noticeOne), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (Driver{}).Ready(t.Context(), in2); err != nil {
		t.Errorf("Ready without a cache directory = %v", err)
	}

	// A port that does not answer is not ready, whatever the notices say.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	in2.Members[0].Port = uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	if err := (Driver{}).Ready(t.Context(), in2); err == nil || !strings.Contains(err.Error(), "psiphon") {
		t.Errorf("Ready = %v, want an error naming the member", err)
	}
}
