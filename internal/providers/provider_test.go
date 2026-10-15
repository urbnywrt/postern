package providers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
)

const runnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

// ---- server addresses -----------------------------------------------------------

func TestCheckServerAddress(t *testing.T) {
	refused := []string{
		"127.0.0.1", "127.1.2.3", "::1", "[::1]", " 127.0.0.1", "127.0.0.1\t",
		"[ 127.0.0.1 ]", "[\t::1 ]", // Xray strips the brackets, then the spaces
		"0.0.0.0", "::", "[::]",
		"169.254.169.254", "169.254.0.1", "fe80::1", "fe80::abcd:1",
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff05::1:3", "ff01::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:0.0.0.0",
		"fd00:ec2::254", "100.100.100.200", "::ffff:100.100.100.200", "168.63.129.16",
		// After Xray's own trimming these are names to it, which it dials as
		// "<name>:<port>", and Go's dialer takes the brackets off again.
		" [127.0.0.1]", "[::1] ", "[[::1]]", " [169.254.169.254]", "[ [::1] ]", "\t[::ffff:127.0.0.1]",
		"x:y", "127.0.0.1 x", "a b.example.com", "fe80::1%eth0", "host\x00.example.com",
		"localhost", "LOCALHOST", "localhost.", "api.localhost", "a.b.LocalHost", " localhost",
		"localhost.localdomain", "localhost4", "localhost4.localdomain4", "localhost6",
		"LOCALHOST6.LOCALDOMAIN6", "ip6-localhost", "ip6-loopback",
		"env:HOSTNAME", "ENV:HOSTNAME", "env:", " env:HOSTNAME",
		"", "[]", " ",
	}
	for _, host := range refused {
		err := CheckServerAddress(host)
		if err == nil {
			t.Errorf("CheckServerAddress(%q) = nil, want a refusal", host)
			continue
		}
		if h := strings.Trim(host, " \t[]"); h != "" && strings.Contains(err.Error(), h) {
			t.Errorf("CheckServerAddress(%q) = %q: the error repeats the address", host, err)
		}
	}
	allowed := []string{
		"example.com", "vless.example.com", "localhost.example.com", "mylocalhost", "notlocalhost.test",
		"localhost7", "environment.example.com", "env.example.com",
		"192.0.2.1", "198.51.100.200", "203.0.113.9", "2001:db8::1", "[2001:db8::1]",
		"10.0.0.1", "172.16.5.4", "192.168.1.1", "100.64.0.1", "fd12:3456::1", // private networks are not the node
		"149.154.167.51", "fd00:ec2::253", "100.100.100.201", "168.63.129.17",
		"metadata.google.internal", "xn--bcher-kva.example", "under_score.example.com", "trailing.dot.example.com.",
	}
	for _, host := range allowed {
		if err := CheckServerAddress(host); err != nil {
			t.Errorf("CheckServerAddress(%q) = %v, want nil", host, err)
		}
	}
}

// ---- member errors --------------------------------------------------------------

func TestMemberErrors(t *testing.T) {
	if JoinMemberErrors(nil) != nil {
		t.Error("JoinMemberErrors(nil) is not nil")
	}
	a := &MemberError{Key: "aaaaaaaaaaaa", Field: "fp", Reason: "unknown fingerprint"}
	b := &MemberError{Key: "bbbbbbbbbbbb", Field: "flow", Reason: "not supported"}
	joined := JoinMemberErrors([]*MemberError{a, b})
	if got, want := joined.Error(), "member aaaaaaaaaaaa: fp: unknown fingerprint; member bbbbbbbbbbbb: flow: not supported"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	wrapped := fmt.Errorf("xray: %w", joined)
	got := MemberErrors(wrapped)
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Errorf("MemberErrors = %v, want both, in order", got)
	}
	var me *MemberError
	if !errors.As(wrapped, &me) || me != a {
		t.Errorf("errors.As finds %v, want the first", me)
	}
	if MemberErrors(errors.New("plain")) != nil || MemberErrors(nil) != nil {
		t.Error("MemberErrors finds member errors where there are none")
	}
	if got := MemberErrors(errors.Join(errors.New("x"), fmt.Errorf("y: %w", a))); len(got) != 1 || got[0] != a {
		t.Errorf("MemberErrors in a mixed join = %v", got)
	}
}

// ---- members and ids ------------------------------------------------------------

func TestCheckMembers(t *testing.T) {
	good := []Member{{Key: "0123456789ab", Port: 35000}, {Key: "warp", Port: 39999}, {Key: "a_b-C", Port: 35001}} // gitleaks:allow (member keys, not secrets)
	if err := CheckMembers(good); err != nil {
		t.Fatalf("CheckMembers(good) = %v", err)
	}
	bad := map[string][]Member{
		"no members":        nil,
		"empty key":         {{Key: "", Port: 35000}},
		"key with a space":  {{Key: "a b", Port: 35000}},
		"key with a dot":    {{Key: "a.b", Port: 35000}},
		"key with a slash":  {{Key: "a/b", Port: 35000}},
		"key too long":      {{Key: strings.Repeat("k", 65), Port: 35000}},
		"duplicate key":     {{Key: "same", Port: 35000}, {Key: "same", Port: 35001}},
		"port zero":         {{Key: "a", Port: 0}},
		"port below range":  {{Key: "a", Port: 34999}},
		"port above range":  {{Key: "a", Port: 40000}},
		"duplicate port":    {{Key: "a", Port: 35000}, {Key: "b", Port: 35000}},
		"key starts with -": {{Key: "-a", Port: 35000}},
	}
	for name, members := range bad {
		if err := CheckMembers(members); err == nil {
			t.Errorf("%s: CheckMembers = nil", name)
		} else if len(MemberErrors(err)) != 0 {
			t.Errorf("%s: %v is a member error; the members of an instance are the agent's to get right", name, err)
		}
	}
}

func TestCheckEgressID(t *testing.T) {
	for _, id := range []string{"01J9ZZ0000000000000000EGRS", "egress-1", "a"} {
		if err := CheckEgressID(id); err != nil {
			t.Errorf("CheckEgressID(%q) = %v", id, err)
		}
	}
	for _, id := range []string{"", "-x", "a b", "a/b", "a.b", "a:b", strings.Repeat("x", 65), "é"} {
		if err := CheckEgressID(id); err == nil {
			t.Errorf("CheckEgressID(%q) = nil", id)
		}
	}
}

// ---- containers -----------------------------------------------------------------

func TestContainerSpec(t *testing.T) {
	in := Instance{
		EgressID:    "01J9ZZ0000000000000000EGRS",
		Generation:  4,
		Kind:        nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
		Members:     []Member{{Key: "k", Port: 35123}},
		InstanceDir: "/opt/postern/data/instances/egr-01J9ZZ0000000000000000EGRS-g4",
		BinaryPath:  "/opt/postern/data/artifacts/xray/v26.3.27/amd64/xray",
		RunnerImage: runnerImage,
	}
	got := ContainerSpec(in, ContainerOptions{Binary: "xray", Args: []string{"run", "-c", "/etc/egress/config.json"}, MemoryBytes: 512 << 20})
	want := dockerapi.ContainerSpec{
		Name:          "postern-egr-01j9zz0000000000000000egrs-g4",
		Image:         runnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		Entrypoint:    []string{"/opt/engine/xray", "run", "-c", "/etc/egress/config.json"},
		Binds: []string{
			"/opt/postern/data/artifacts/xray/v26.3.27/amd64/xray:/opt/engine/xray:ro",
			"/opt/postern/data/instances/egr-01J9ZZ0000000000000000EGRS-g4:/etc/egress:ro",
		},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels: map[string]string{
			"postern.managed":    "true",
			"postern.role":       "egress",
			"postern.id":         "01J9ZZ0000000000000000EGRS",
			"postern.generation": "4",
		},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=16m"},
		ReadOnly:    true,
		MemoryBytes: 512 << 20,
		PidsLimit:   256,
		LogMaxSize:  "5m",
		LogMaxFile:  2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ContainerSpec =\n%#v\nwant\n%#v", got, want)
	}

	// The instance directory read-write, and a resolv.conf.
	in.ResolvConf = "/opt/postern/data/run/resolv.conf"
	got = ContainerSpec(in, ContainerOptions{Binary: "warp-plus", Args: []string{"-b", "127.0.0.1:35123"}, InstanceRW: true, MemoryBytes: 256 << 20})
	wantBinds := []string{
		"/opt/postern/data/artifacts/xray/v26.3.27/amd64/xray:/opt/engine/warp-plus:ro",
		"/opt/postern/data/instances/egr-01J9ZZ0000000000000000EGRS-g4:/etc/egress",
		"/opt/postern/data/run/resolv.conf:/etc/resolv.conf:ro",
	}
	if !reflect.DeepEqual(got.Binds, wantBinds) {
		t.Errorf("Binds = %q, want %q", got.Binds, wantBinds)
	}
	if got.Entrypoint[0] != "/opt/engine/warp-plus" || got.MemoryBytes != 256<<20 {
		t.Errorf("Entrypoint %q, memory %d", got.Entrypoint, got.MemoryBytes)
	}

	// A cache directory that outlives the generations, read-write at
	// CacheMount.
	in.ResolvConf = ""
	in.CacheDir = "/opt/postern/data/instances/egr-01j9zz0000000000000000egrs/cache"
	got = ContainerSpec(in, ContainerOptions{Binary: "warp-plus"})
	wantBinds = []string{
		"/opt/postern/data/artifacts/xray/v26.3.27/amd64/xray:/opt/engine/warp-plus:ro",
		"/opt/postern/data/instances/egr-01J9ZZ0000000000000000EGRS-g4:/etc/egress:ro",
		"/opt/postern/data/instances/egr-01j9zz0000000000000000egrs/cache:" + CacheMount,
	}
	if !reflect.DeepEqual(got.Binds, wantBinds) {
		t.Errorf("Binds = %q, want %q", got.Binds, wantBinds)
	}
}

func TestContainerName(t *testing.T) {
	if got := ContainerName("ABC-def_1", 12); got != "postern-egr-abc-def_1-g12" {
		t.Errorf("ContainerName = %q", got)
	}
}

func TestCheckHostPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "xray")
	mustWrite(t, bin, 0o755)
	inst := filepath.Join(dir, "inst")
	if err := os.Mkdir(inst, 0o700); err != nil {
		t.Fatal(err)
	}
	resolv := filepath.Join(dir, "resolv.conf")
	mustWrite(t, resolv, 0o644)

	in := Instance{BinaryPath: bin, InstanceDir: inst}
	if err := in.CheckHostPaths(); err != nil {
		t.Fatalf("CheckHostPaths = %v", err)
	}
	in.ResolvConf = resolv
	if err := in.CheckHostPaths(); err != nil {
		t.Fatalf("CheckHostPaths with a resolv.conf = %v", err)
	}
	cache := filepath.Join(dir, "cache")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	in.CacheDir = cache
	if err := in.CheckHostPaths(); err != nil {
		t.Fatalf("CheckHostPaths with a cache directory = %v", err)
	}

	notExec := filepath.Join(dir, "notexec")
	mustWrite(t, notExec, 0o750)
	notReadable := filepath.Join(dir, "notreadable")
	mustWrite(t, notReadable, 0o711)
	privateResolv := filepath.Join(dir, "private-resolv.conf")
	mustWrite(t, privateResolv, 0o600)
	file := filepath.Join(dir, "afile")
	mustWrite(t, file, 0o644)

	bad := map[string]Instance{
		"binary missing":         {BinaryPath: filepath.Join(dir, "missing"), InstanceDir: inst},
		"binary relative":        {BinaryPath: "xray", InstanceDir: inst},
		"binary empty":           {BinaryPath: "", InstanceDir: inst},
		"binary a directory":     {BinaryPath: inst, InstanceDir: inst},
		"binary not executable":  {BinaryPath: notExec, InstanceDir: inst},
		"binary not readable":    {BinaryPath: notReadable, InstanceDir: inst},
		"binary with a colon":    {BinaryPath: dir + "/a:b", InstanceDir: inst},
		"instance dir missing":   {BinaryPath: bin, InstanceDir: filepath.Join(dir, "nope")},
		"instance dir a file":    {BinaryPath: bin, InstanceDir: file},
		"instance dir relative":  {BinaryPath: bin, InstanceDir: "inst"},
		"resolv.conf missing":    {BinaryPath: bin, InstanceDir: inst, ResolvConf: filepath.Join(dir, "nope.conf")},
		"resolv.conf a dir":      {BinaryPath: bin, InstanceDir: inst, ResolvConf: inst},
		"resolv.conf relative":   {BinaryPath: bin, InstanceDir: inst, ResolvConf: "resolv.conf"},
		"resolv.conf unreadable": {BinaryPath: bin, InstanceDir: inst, ResolvConf: privateResolv},
		"cache dir missing":      {BinaryPath: bin, InstanceDir: inst, CacheDir: filepath.Join(dir, "nope")},
		"cache dir a file":       {BinaryPath: bin, InstanceDir: inst, CacheDir: file},
		"cache dir relative":     {BinaryPath: bin, InstanceDir: inst, CacheDir: "cache"},
		"cache dir with a colon": {BinaryPath: bin, InstanceDir: inst, CacheDir: dir + "/a:b"},
	}
	for name, in := range bad {
		if err := in.CheckHostPaths(); err == nil {
			t.Errorf("%s: CheckHostPaths = nil", name)
		}
	}
}

func mustWrite(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// ---- readiness ------------------------------------------------------------------

// fakeSOCKS listens on 127.0.0.1 and answers every greeting with reply (nil: says
// nothing and holds the connection). It returns the port.
func fakeSOCKS(t *testing.T, reply []byte) uint16 {
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
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(c, greeting); err != nil {
					return
				}
				if greeting[0] != 5 || greeting[1] != 1 || greeting[2] != 0 {
					return // not the greeting Ready should send
				}
				if reply == nil {
					_, _ = io.Copy(io.Discard, c)
					return
				}
				_, _ = c.Write(reply)
			}()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// closedPort is a loopback port that nothing listens on: port 1, which no
// test can take (a port below 1024 needs root), so connecting is refused. A
// freed random port could be taken by a fake server of the same test.
func closedPort(*testing.T) uint16 { return 1 }

func TestCheckSOCKS(t *testing.T) {
	old := greetTimeout
	greetTimeout = 300 * time.Millisecond
	t.Cleanup(func() { greetTimeout = old })

	ok1, ok2 := fakeSOCKS(t, []byte{5, 0}), fakeSOCKS(t, []byte{5, 0})
	if err := CheckSOCKS(t.Context(), []Member{{Key: "a", Port: ok1}, {Key: "b", Port: ok2}}); err != nil {
		t.Fatalf("CheckSOCKS = %v", err)
	}

	tests := []struct {
		name string
		port uint16
		want string
	}{
		{"nothing listens", closedPort(t), "not accepting connections"},
		{"wants a password", fakeSOCKS(t, []byte{5, 0xff}), "no method without authentication"},
		{"chooses another method", fakeSOCKS(t, []byte{5, 2}), "method 2"},
		{"not socks5", fakeSOCKS(t, []byte{4, 0}), "not SOCKS5"},
		{"says nothing", fakeSOCKS(t, nil), "no answer"},
		{"closes at once", fakeSOCKS(t, []byte{}), "no answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			err := CheckSOCKS(t.Context(), []Member{{Key: "good", Port: ok1}, {Key: "badmember", Port: tt.port}})
			if err == nil {
				t.Fatal("CheckSOCKS = nil")
			}
			for _, want := range []string{"badmember", fmt.Sprint(tt.port), tt.want} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not say %q", err, want)
				}
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("CheckSOCKS took %v", d)
			}
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := CheckSOCKS(ctx, []Member{{Key: "a", Port: ok1}}); err == nil {
		t.Error("CheckSOCKS with a cancelled context = nil")
	}
	if err := CheckSOCKS(t.Context(), nil); err == nil {
		t.Error("CheckSOCKS without members = nil")
	}
}
