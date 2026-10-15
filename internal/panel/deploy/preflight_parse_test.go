package deploy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// factsLine is the line of facts that the preflight prints for values, which
// it encodes as the script does.
func factsLine(values map[string]string) string {
	enc := make(map[string]string, len(values))
	for k, v := range values {
		enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	b, err := json.Marshal(enc)
	if err != nil {
		panic(err)
	}
	return preflightMarker + string(b)
}

// minimal are the facts of a server that said little.
func minimal(extra map[string]string) map[string]string {
	v := map[string]string{"format": "1", "time": "1791200000", "uid": "0", "machine": "x86_64"}
	for k, x := range extra {
		v[k] = x
	}
	return v
}

func mustParse(t *testing.T, out string) *Facts {
	t.Helper()
	f, err := parsePreflight([]byte(out))
	if err != nil {
		t.Fatalf("parsePreflight: %v", err)
	}
	return f
}

// What a login shell prints around the line does not matter, nor line ends of
// Windows; the last line of facts counts.
func TestPreflightOutputAroundTheFacts(t *testing.T) {
	out := "Welcome to the server\r\n" + factsLine(minimal(map[string]string{"machine": "riscv64"})) + "\r\n" +
		"sudo: unable to resolve host box\n" + factsLine(minimal(nil)) + "\r\n" + "bye\n"
	f := mustParse(t, out)
	if f.Machine != "x86_64" || f.Arch != "amd64" {
		t.Errorf("Machine %q, Arch %q: want the last line of facts, x86_64 and amd64", f.Machine, f.Arch)
	}
}

// Output that is not what the script prints is refused, whole.
func TestPreflightOutputThatIsRefused(t *testing.T) {
	big := strings.Repeat("A", maxFact+3)
	many := minimal(nil)
	for i := range maxFactKeys {
		many[fmt.Sprintf("k%d", i)] = "x"
	}
	tests := []struct {
		name string
		out  string
	}{
		{"no facts", "postern-preflight\nsomething else\n"},
		{"nothing", ""},
		{"not JSON", preflightMarker + "{not json}"},
		{"not an object of strings", preflightMarker + `{"format":1}`},
		{"not base64", preflightMarker + `{"format":"MQ==","time":"!!!"}`},
		{"a key that is not one", preflightMarker + `{"format":"MQ==","Docker":"MQ=="}`},
		{"a key that is too long", preflightMarker + `{"format":"MQ==","` + strings.Repeat("a", maxFactKey+1) + `":"MQ=="}`},
		{"too many keys", factsLine(many)},
		{"a value that is too large", preflightMarker + `{"format":"MQ==","df":"` + big + `"}`},
		{"too much output", factsLine(minimal(nil)) + "\n" + strings.Repeat("x", maxPreflightOutput)},
		{"another format", factsLine(minimal(map[string]string{"format": "2"}))},
		{"no format", factsLine(map[string]string{"time": "1791200000"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if f, err := parsePreflight([]byte(tt.out)); err == nil {
				t.Errorf("parsePreflight = %+v, want an error", f)
			}
		})
	}
	if _, err := parsePreflight([]byte("hello\n")); !errors.Is(err, errNoFacts) {
		t.Errorf("parsePreflight of output without facts: err = %v, want errNoFacts", err)
	}
}

// A value that does not make sense is left out, as if the server had not said
// it.
func TestPreflightValuesThatMakeNoSense(t *testing.T) {
	f := mustParse(t, factsLine(minimal(map[string]string{
		"time":               "soon",
		"uid":                "-3",
		"machine":            "riscv64\x1b[31m",
		"bash":               "five",
		"bash_rc":            "0",
		"docker":             "/usr/bin/docker",
		"docker_version":     "27.0; rm -rf /",
		"docker_version_rc":  "0",
		"compose_version":    "Docker Compose version v1.29.2",
		"compose_version_rc": "0",
		"disk_path":          "/srv",
		"df":                 "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 50 50 50% /",
		"df_rc":              "0",
		"listen_tool":        "lsof",
		"listen":             "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*",
	})))
	switch {
	case !f.RemoteTime.IsZero():
		t.Errorf("RemoteTime = %v, want none", f.RemoteTime)
	case f.UID != -1:
		t.Errorf("UID = %d, want -1", f.UID)
	case f.Arch != "":
		t.Errorf("Arch = %q, want none for riscv64", f.Arch)
	case strings.ContainsAny(f.Machine, "\x1b\n"):
		t.Errorf("Machine = %q holds control characters", f.Machine)
	case f.BashMajor != 0:
		t.Errorf("BashMajor = %d, want 0", f.BashMajor)
	case f.Docker.Version != "" || f.Docker.Problem == "":
		t.Errorf("Docker = %+v, want no version and the problem", f.Docker)
	case f.Docker.ComposeVersion != "":
		t.Errorf("ComposeVersion = %q, want none for Compose v1", f.Docker.ComposeVersion)
	case f.DiskPath != "" || f.Disk != nil:
		t.Errorf("DiskPath %q, Disk %+v: want none for a path that the script does not look at", f.DiskPath, f.Disk)
	case f.ListenTool != "" || f.Listeners != nil:
		t.Errorf("ListenTool %q, Listeners %+v: want none from an unknown tool", f.ListenTool, f.Listeners)
	}
	stopped := mustParse(t, factsLine(minimal(map[string]string{"docker": "/usr/bin/docker", "docker_active": "no",
		"docker_version": "27.0.0", "docker_version_rc": "0"})))
	if stopped.Docker.Version != "" || stopped.Docker.Problem != dockerStopped {
		t.Errorf("a daemon that does not run gave %+v, want no version and the problem", stopped.Docker)
	}
	for _, sec := range []string{"5", "99999999999", "1791200000.5"} {
		g := mustParse(t, factsLine(minimal(map[string]string{"time": sec})))
		if !g.RemoteTime.IsZero() {
			t.Errorf("time %q gave %v, want none", sec, g.RemoteTime)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	got := parseOSRelease([]byte("# comment\nNAME=Weird\nPRETTY_NAME=\"Weird \\\"Linux\\\" \x1b[1m1.0\xff\"\n" +
		"ID='weird'\nVERSION_ID=1.0\nnot a line\n"))
	want := OSInfo{PrettyName: "Weird \"Linux\" [1m1.0\uFFFD", ID: "weird", VersionID: "1.0"}
	if got != want {
		t.Errorf("parseOSRelease = %+v, want %+v", got, want)
	}
	long := parseOSRelease([]byte("PRETTY_NAME=" + strings.Repeat("é", 200)))
	if len(long.PrettyName) > 128+len("…") {
		t.Errorf("a long name is %d bytes, want at most 128 and the ellipsis", len(long.PrettyName))
	}
}

func TestParseListenerLines(t *testing.T) {
	tests := []struct {
		tool, line string
		want       *Listener
	}{
		{"ss", "LISTEN 0 4096 [fe80::1%eth0]:22 [::]:*", &Listener{Addr: addr("fe80::1"), Port: 22}},
		{"ss", "LISTEN 0 4096 [::ffff:127.0.0.1]:8080 *:*", &Listener{Addr: addr("127.0.0.1"), Port: 8080}},
		{"ss", "LISTEN 0 4096 garbage:22 *:*", &Listener{Port: 22}},
		{"ss", "LISTEN 0 4096 0.0.0.0:0 *:*", nil},
		{"ss", "LISTEN 0 4096 0.0.0.0:70000 *:*", nil},
		{"ss", "LISTEN 0 4096 0.0.0.0 *:*", nil},
		{"ss", "ESTAB 0 0 203.0.113.1:22 198.51.100.1:5000", nil},
		{"ss", "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"a\",pid=0,fd=1),(\"b\",pid=12,fd=2))",
			&Listener{Addr: addr("0.0.0.0"), Port: 443, Processes: []Process{{"b", 12}}}},
		{"netstat", "tcp 0 0 0.0.0.0:443 0.0.0.0:* LISTEN -", &Listener{Addr: addr("0.0.0.0"), Port: 443}},
		{"netstat", "tcp6 0 0 ::1:631 :::* LISTEN 812/cupsd", &Listener{Addr: addr("::1"), Port: 631, Processes: []Process{{"cupsd", 812}}}},
		{"netstat", "tcp 0 0 0.0.0.0:443 0.0.0.0:* LISTEN 1234/nginx: master p", &Listener{Addr: addr("0.0.0.0"), Port: 443, Processes: []Process{{"nginx: master p", 1234}}}},
		{"netstat", "udp 0 0 0.0.0.0:53 0.0.0.0:* 1/x", nil},
		{"netstat", "tcp 0 0 0.0.0.0:22 203.0.113.9:4000 ESTABLISHED 1/x", nil},
		{"proc", "0: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 1", &Listener{Addr: addr("127.0.0.1"), Port: 8080}},
		{"proc", "0: 0100007F:1F90 00000000:0000 06 0 0 0 0 0 1", nil},
		{"proc", "0: 0100007:1F90 00000000:0000 0A 0 0 0 0 0 1", nil},
		{"proc", "0: 0100007G:1F90 00000000:0000 0A 0 0 0 0 0 1", nil},
	}
	for _, tt := range tests {
		got := parseListeners(tt.tool, []byte(tt.line))
		var want []Listener
		if tt.want != nil {
			want = []Listener{*tt.want}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s %q:\n got %+v\nwant %+v", tt.tool, tt.line, got, want)
		}
	}
	var many strings.Builder
	for i := range maxListeners + 10 {
		fmt.Fprintf(&many, "LISTEN 0 1 0.0.0.0:%d 0.0.0.0:*\n", 1000+i)
	}
	if got := parseListeners("ss", []byte(many.String())); len(got) != maxListeners {
		t.Errorf("%d listeners kept, want at most %d", len(got), maxListeners)
	}
}

func TestParseContainers(t *testing.T) {
	id := strings.Repeat("ab", 32)
	data := id + "|good|true|Up\n" +
		"short|bad||Up\n" +
		id + "|has space||Up\n" +
		id + "|shop-nginx,other/alias||Up\n" +
		id + "|three|fields\n"
	got := parseContainers([]byte(data))
	want := []Container{{ID: id, Name: "good", Status: "Up", Postern: true}, {ID: id, Name: "shop-nginx", Status: "Up"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseContainers:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseDF(t *testing.T) {
	tests := []struct {
		out  string
		want *Disk
	}{
		{"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 400 600 40% /opt", &Disk{FreeBytes: 600 << 10, TotalBytes: 1000 << 10}},
		// A long name of a file system goes on a line of its own in some df.
		{"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/very-long-name\n 1000 400 600 40% /", &Disk{FreeBytes: 600 << 10, TotalBytes: 1000 << 10}},
		{"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 400 6000 40% /", nil},
		{"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 x y z 40% /", nil},
		{"df: /opt: No such file or directory", nil},
		{"", nil},
	}
	for _, tt := range tests {
		if got := parseDF([]byte(tt.out)); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseDF(%q) = %+v, want %+v", tt.out, got, tt.want)
		}
	}
}

func TestParseCgroupsAndAddrs(t *testing.T) {
	id := strings.Repeat("0f", 32)
	got := parseCgroups([]byte("pid 10\n0::/system.slice/docker-" + id + ".scope\n" +
		"pid abc\n0::/system.slice/docker-" + id + ".scope\n" +
		"pid 11\n0::/user.slice\n" +
		"pid 12\n0::/docker/" + id[:60] + "\n"))
	if want := map[int]string{10: id}; !reflect.DeepEqual(got, want) {
		t.Errorf("parseCgroups = %v, want %v", got, want)
	}

	addrs := parseAddrs([]byte("inet 127.0.0.1/8\ninet 10.1.2.3/8\ninet 100.64.1.1/10\ninet 192.168.1.1/24\n" +
		"inet6 fe80::1/64\ninet6 fd00::1/64\ninet6 2001:db8::5/64\ninet 198.51.100.7/24\n" +
		"inet addr:198.51.100.7  Bcast:198.51.100.255\ninet6 addr: 2001:db8::5/64 Scope:Global\ninet 999.1.1.1/8\n"))
	if want := []netip.Addr{addr("198.51.100.7"), addr("2001:db8::5")}; !reflect.DeepEqual(addrs, want) {
		t.Errorf("parseAddrs = %v, want %v", addrs, want)
	}
}

func TestPlain(t *testing.T) {
	if got := plain("  a\tb\x00c\x1b[0m\xffd  ", 100); got != "a bc[0m\uFFFDd" {
		t.Errorf("plain = %q", got)
	}
	if got := plain(strings.Repeat("ж", 10), 5); got != "жж…" {
		t.Errorf("plain cut = %q, want two whole letters and the ellipsis", got)
	}
	if got := firstLine([]byte("\n\x1b\n  second  \nthird")); got != "second" {
		t.Errorf("firstLine = %q", got)
	}
}
