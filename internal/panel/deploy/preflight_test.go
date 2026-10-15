package deploy

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The preflight script runs here against fake servers: a directory of
// testdata/preflight/<host> holds what the commands of a server print (cmd/),
// and its /etc, /opt, /proc and /run (root/). Stand-ins for the commands print
// the canned outputs and note every call, and the PATH holds them and the few
// tools that the script needs from the machine of the test, so that a command
// that the server does not have is missing for the script too.

// stubCase is one call of a command that the stand-in knows: its arguments,
// as "$*" has them, the file of its output in cmd/, and what the command says
// when the server has no such file (it fails then).
type stubCase struct {
	args, file, missing string
}

// stubCommands are the commands that the script runs and the stand-ins have.
// A server has the command when it has a file for one of its calls, or a file
// named as the command (cmd/pidof: pidof is there, and finds nothing).
var stubCommands = map[string][]stubCase{
	"uname": {{"-m", "uname", ""}},
	"id":    {{"-u", "id", ""}},
	"date":  {{"-u +%s", "date", ""}},
	"bash":  {{`-c echo "${BASH_VERSINFO[0]}"`, "bash", ""}},
	"docker": {
		{"version --format {{.Server.Version}}", "docker-version", ""},
		{"info --format {{.SecurityOptions}}", "docker-info", ""},
		{"compose version", "docker-compose", "docker: unknown command: docker compose"},
		{`ps -a --no-trunc --format {{.ID}}|{{.Names}}|{{.Label "postern.managed"}}|{{.Status}}`, "docker-ps", ""},
	},
	"df":      {{"-Pk /opt", "df", ""}, {"-Pk /", "df", ""}},
	"ss":      {{"-ltnpH", "ss-H", "ss: invalid option -- H"}, {"-ltnp", "ss", "ss: no output"}},
	"netstat": {{"-ltnp", "netstat", ""}},
	"ip":      {{"-o addr show", "ip-addr", ""}},
	"dpkg-query": {
		{"-W -f=${Status} docker-ce", "dpkg-docker-ce", "dpkg-query: no packages found matching docker-ce"},
		{"-W -f=${Status} docker.io", "dpkg-docker.io", "dpkg-query: no packages found matching docker.io"},
	},
	"apk":       {{"info -e docker", "apk-docker", ""}},
	"systemctl": {{"is-active --quiet docker", "systemctl-is-active", ""}},
	"pidof":     {{"dockerd", "pidof-dockerd", ""}},
	// The package tools are only looked for: a server has one with a file
	// cmd/<tool>, and the script must not run it.
	"apt-get": nil,
	"dnf":     nil,
	"yum":     nil,
	"zypper":  nil,
	"pacman":  nil,
}

// A fake is a fake server, made for one run of the script.
type fake struct {
	bin, root string
	calls     string // the log of the calls of the stand-ins
	env       []string
}

// Calls returns the calls of the stand-ins so far, as "name args".
func (f fake) Calls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.calls)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// machineTools are the tools of the machine of the test that the script and
// the stand-ins use.
var machineTools = []string{"head", "base64", "tr", "cat", "awk", "sort", "cut", "true", "grep"}

// fakeServer makes the stand-ins of host in a directory of their own, and
// returns them with the root of the server and the environment of the script.
func fakeServer(t *testing.T, host string) fake {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", "preflight", host))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("no fake server %s: %v", host, err)
	}
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "calls")
	for _, tool := range machineTools {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("the machine of the test has no %s", tool)
		}
		if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for name, cases := range stubCommands {
		has := false
		var b strings.Builder
		fmt.Fprintf(&b, "#!/bin/sh\necho \"%s $*\" >> %s\ncase \"$*\" in\n", name, shellQuote(calls))
		if _, err := os.Stat(filepath.Join(dir, "cmd", name)); err == nil {
			has = true
		}
		for _, c := range cases {
			file := filepath.Join(dir, "cmd", c.file)
			if _, err := os.Stat(file); err == nil {
				has = true
			}
			fmt.Fprintf(&b, "%s) f=%s m=%s ;;\n", shellQuote(c.args), shellQuote(file), shellQuote(c.missing))
		}
		fmt.Fprintf(&b, "*) echo \"%s (stand-in): unexpected arguments: $*\" >&2; exit 99 ;;\nesac\n", name)
		b.WriteString(`if [ -f "$f" ]; then
	cat "$f"
	if [ -f "$f.rc" ]; then exit "$(cat "$f.rc")"; fi
	exit 0
fi
echo "$m" >&2
exit 1
`)
		if has {
			writeExecutable(t, filepath.Join(bin, name), b.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "cmd", "timeout")); err == nil {
		// A timeout that runs the command without the time.
		writeExecutable(t, filepath.Join(bin, "timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n")
	}
	return fake{bin: bin, root: filepath.Join(dir, "root"), calls: calls, env: []string{"PATH=" + bin, "LANG=C"}}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

// shells are the shells that the script is tried with, where the machine of
// the test has them: the sh of the machine (dash on Debian and Ubuntu, the ash
// of busybox on Alpine), bash, and busybox.
func shells(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	if sh, err := exec.LookPath("sh"); err == nil {
		out["sh"] = []string{sh, "-c"}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		out["bash"] = []string{bash, "-c"}
	}
	if busybox, err := exec.LookPath("busybox"); err == nil {
		out["busybox"] = []string{busybox, "sh", "-c"}
	}
	if len(out) == 0 {
		t.Skip("the machine of the test has no shell")
	}
	return out
}

// fakeableShells are the shells of shells that run a command from PATH, where
// the tests put their fakes. A busybox built with FEATURE_SH_STANDALONE (the one
// of the Ubuntu runners of GitHub) runs its own applets (date, id, df, ip...)
// in preference to PATH, so the script would see the machine of the test
// instead of the fake server: such a shell is left out, and the log says so.
func fakeableShells(t *testing.T) map[string][]string {
	t.Helper()
	dir := t.TempDir()
	const marker = "postern-fake-date"
	if err := os.WriteFile(filepath.Join(dir, "date"), []byte("#!/bin/sh\necho "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for name, shell := range shells(t) {
		cmd := exec.Command(shell[0], append(shell[1:], "date")...)
		cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		if got, err := cmd.Output(); err == nil && strings.TrimSpace(string(got)) == marker {
			out[name] = shell
		} else {
			t.Logf("left out %s: it does not run the fakes in PATH (its own applets first?)", name)
		}
	}
	if len(out) == 0 {
		t.Skip("no shell of the machine of the test runs commands from PATH")
	}
	return out
}

// runPreflight runs the script with shell against the fake server host and
// returns what it printed, its error output included, as sshx does, and the
// calls of the stand-ins.
func runPreflight(t *testing.T, shell []string, host string, mgmtPort uint32) ([]byte, []string) {
	t.Helper()
	f := fakeServer(t, host)
	args := append(append([]string(nil), shell[1:]...), preflightCommand(mgmtPort, f.root))
	cmd := exec.Command(shell[0], args...)
	cmd.Env = f.env
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the preflight failed: %v\n%s", err, out)
	}
	return out, f.Calls(t)
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func repeatHex(pair string) string { return strings.Repeat(pair, 32) }

// preflightHosts are the fake servers, the management port of the node that
// is installed there, and the facts that the panel must read.
var preflightHosts = []struct {
	host     string
	mgmtPort uint32
	want     Facts
}{
	{
		host: "ubuntu-24.04", mgmtPort: 61001,
		want: Facts{
			RemoteTime: time.Unix(1791200000, 0), UID: 0, Machine: "x86_64", Arch: "amd64",
			OS:           OSInfo{PrettyName: "Ubuntu 24.04.1 LTS", ID: "ubuntu", VersionID: "24.04"},
			BashMajor:    5,
			PackageTools: []string{"apt-get"},
			Docker:       DockerInfo{Installed: true, Version: "27.5.1", ComposeVersion: "2.27.1+ds1-0ubuntu1", Origin: "docker.io"},
			DiskPath:     "/opt", Disk: &Disk{FreeBytes: 37237888 << 10, TotalBytes: 40470732 << 10},
			ListenTool: "ss",
			Listeners: []Listener{
				{Addr: addr("127.0.0.53"), Port: 53, Processes: []Process{{"systemd-resolve", 612}}},
				{Addr: addr("127.0.0.54"), Port: 53, Processes: []Process{{"systemd-resolve", 612}}},
				{Addr: addr("0.0.0.0"), Port: 22, Processes: []Process{{"sshd", 1021}, {"systemd", 1}}},
				{Addr: addr("::"), Port: 22, Processes: []Process{{"sshd", 1021}, {"systemd", 1}}},
			},
			ContainerOf: map[int]string{},
			PublicIPs:   []netip.Addr{addr("203.0.113.10"), addr("2001:db8:10::a")},
		},
	},
	{
		host: "debian-12", mgmtPort: 61443,
		want: Facts{
			RemoteTime: time.Unix(1791200000, 0), UID: 0, Machine: "x86_64", Arch: "amd64",
			OS:           OSInfo{PrettyName: "Debian GNU/Linux 12 (bookworm)", ID: "debian", VersionID: "12"},
			BashMajor:    5,
			PackageTools: []string{"apt-get"},
			Docker:       DockerInfo{Installed: true, Version: "28.4.0", ComposeVersion: "2.39.4", Origin: "docker-ce"},
			Containers: []Container{
				{ID: repeatHex("e1"), Name: "postern-edge-g3", Status: "Up 2 days", Postern: true},
				{ID: repeatHex("c3"), Name: "postern-eng-01hzy4k3m2n1p0q9r8s7t6v5w4-g3", Status: "Up 2 days", Postern: true},
				{ID: repeatHex("a9"), Name: "postern-agent", Status: "Up 2 days (healthy)", Postern: true},
			},
			DiskPath: "/opt", Disk: &Disk{FreeBytes: 14290580 << 10, TotalBytes: 20466256 << 10},
			ListenTool: "ss",
			Listeners: []Listener{
				{Addr: addr("0.0.0.0"), Port: 22, Processes: []Process{{"sshd", 702}}},
				{Addr: addr("0.0.0.0"), Port: 443, Processes: []Process{{"postern-node", 3311}}},
				{Addr: addr("127.0.0.1"), Port: 20001, Processes: []Process{{"telemt", 3402}}},
				{Addr: addr("::"), Port: 61443, Processes: []Process{{"current", 2950}}},
				{Addr: addr("::"), Port: 22, Processes: []Process{{"sshd", 702}}},
			},
			ContainerOf: map[int]string{3311: repeatHex("e1"), 2950: repeatHex("a9")},
			PublicIPs:   []netip.Addr{addr("198.51.100.20")},
		},
	},
	{
		host: "debian-12-stopped", mgmtPort: 61443,
		want: Facts{
			RemoteTime: time.Unix(1791200000, 0), UID: 0, Machine: "x86_64", Arch: "amd64",
			OS:           OSInfo{PrettyName: "Debian GNU/Linux 12 (bookworm)", ID: "debian", VersionID: "12"},
			BashMajor:    5,
			PackageTools: []string{"apt-get"},
			Docker:       DockerInfo{Installed: true, Stopped: true, Problem: dockerStopped, ComposeVersion: "2.39.4", Origin: "docker-ce"},
			DiskPath:     "/opt", Disk: &Disk{FreeBytes: 14290580 << 10, TotalBytes: 20466256 << 10},
			ListenTool: "ss",
			Listeners: []Listener{
				{Addr: addr("0.0.0.0"), Port: 22, Processes: []Process{{"sshd", 702}}},
				{Addr: addr("::"), Port: 22, Processes: []Process{{"sshd", 702}}},
			},
			ContainerOf: map[int]string{},
			PublicIPs:   []netip.Addr{addr("198.51.100.20")},
		},
	},
	{
		host: "alpine-3.22", mgmtPort: 61001,
		want: Facts{
			RemoteTime: time.Unix(1791200000, 0), UID: 0, Machine: "aarch64", Arch: "arm64",
			OS:           OSInfo{PrettyName: "Alpine Linux v3.22", ID: "alpine", VersionID: "3.22.1"},
			PackageTools: []string{"apk"},
			DiskPath:     "/", Disk: &Disk{FreeBytes: 7132884 << 10, TotalBytes: 8191416 << 10},
			ListenTool: "netstat",
			Listeners: []Listener{
				{Addr: addr("0.0.0.0"), Port: 22, Processes: []Process{{"sshd", 2211}}},
				{Addr: addr("::"), Port: 22, Processes: []Process{{"sshd", 2211}}},
			},
			ContainerOf: map[int]string{},
			PublicIPs:   []netip.Addr{addr("203.0.113.30"), addr("2001:db8:30::1")},
		},
	},
	{
		host: "alpine-3.22-ss", mgmtPort: 61001,
		want: Facts{
			RemoteTime: time.Unix(1791200000, 0), UID: 0, Machine: "x86_64", Arch: "amd64",
			OS:           OSInfo{PrettyName: "Alpine Linux v3.22", ID: "alpine", VersionID: "3.22.1"},
			BashMajor:    5,
			PackageTools: []string{"apk"},
			Docker:       DockerInfo{Installed: true, ComposeVersion: "2.36.2", Origin: "alpine", Stopped: true, Problem: dockerStopped},
			DiskPath:     "/opt", Disk: &Disk{FreeBytes: 629415 << 10, TotalBytes: 8191416 << 10},
			ListenTool: "ss",
			Listeners: []Listener{
				{Addr: addr("0.0.0.0"), Port: 22, Processes: []Process{{"sshd", 1990}}},
				{Addr: addr("0.0.0.0"), Port: 443, Processes: []Process{{"nginx", 2101}, {"nginx", 2100}}},
				{Addr: addr("::"), Port: 22, Processes: []Process{{"sshd", 1990}}},
			},
			ContainerOf: map[int]string{},
		},
	},
	{
		host: "containers", mgmtPort: 61001,
		want: Facts{
			RemoteTime: time.Unix(1791200000, 0), UID: 0, Machine: "x86_64", Arch: "amd64",
			OS:           OSInfo{PrettyName: "Ubuntu 22.04.5 LTS", ID: "ubuntu", VersionID: "22.04"},
			BashMajor:    5,
			PackageTools: []string{"apt-get"},
			Docker:       DockerInfo{Installed: true, Version: "24.0.7", ComposeVersion: "2.21.0", Origin: "docker-ce"},
			Containers: []Container{
				{ID: repeatHex("4e"), Name: "shop-nginx", Status: "Up 3 weeks"},
				{ID: repeatHex("5d"), Name: "shop-app-a1b2c3", Status: "Up 3 weeks"},
				{ID: repeatHex("6d"), Name: "shop-app-d4e5f6", Status: "Exited (0) 2 days ago"},
				{ID: repeatHex("7f"), Name: "shop-worker-a1b2c3", Status: "Up 3 weeks"},
				{ID: repeatHex("8b"), Name: "shop-api", Status: "Up 3 weeks"},
			},
			DiskPath: "/opt", Disk: &Disk{FreeBytes: 71856704 << 10, TotalBytes: 81106868 << 10},
			ListenTool: "ss",
			Listeners: []Listener{
				{Addr: addr("0.0.0.0"), Port: 443, Processes: []Process{{"nginx", 4120}, {"nginx", 4093}}},
				{Addr: addr("0.0.0.0"), Port: 8443, Processes: []Process{{"docker-proxy", 3900}}},
				{Addr: addr("127.0.0.1"), Port: 8088, Processes: []Process{{"nginx", 4120}, {"nginx", 4093}}},
				{Addr: addr("0.0.0.0"), Port: 22, Processes: []Process{{"sshd", 800}}},
				{Addr: addr("::"), Port: 8443, Processes: []Process{{"docker-proxy", 3907}}},
			},
			ContainerOf: map[int]string{4093: repeatHex("4e"), 4120: repeatHex("4e")},
			PublicIPs:   []netip.Addr{addr("203.0.113.50")},
		},
	},
	{
		host: "userns", mgmtPort: 61635,
		want: Facts{
			RemoteTime: time.Unix(1791200000, 0), UID: 0, Machine: "x86_64", Arch: "amd64",
			OS:           OSInfo{PrettyName: "Debian GNU/Linux 12 (bookworm)", ID: "debian", VersionID: "12"},
			BashMajor:    5,
			PackageTools: []string{"apt-get"},
			Docker:       DockerInfo{Installed: true, Version: "28.4.0", UsernsRemap: true, ComposeVersion: "2.39.4", Origin: "docker-ce"},
			DiskPath:     "/opt", Disk: &Disk{FreeBytes: 14290580 << 10, TotalBytes: 20466256 << 10},
			ListenTool: "proc",
			Listeners: []Listener{
				{Addr: addr("0.0.0.0"), Port: 22},
				{Addr: addr("127.0.0.53"), Port: 53},
				{Addr: addr("::"), Port: 22},
				{Addr: addr("::"), Port: 61635},
				{Addr: addr("2001:db8::1"), Port: 443},
			},
			ContainerOf: map[int]string{},
			PublicIPs:   []netip.Addr{addr("198.51.100.40")},
		},
	},
}

// The script, run by every shell there is, gives the panel the facts of each
// fake server. It changes nothing: where the daemon of Docker does not run, the
// script does not ask it, which would start it through the socket of systemd.
func TestPreflightScript(t *testing.T) {
	asksDaemon := regexp.MustCompile(`^docker (version|info|ps|inspect)\b`)
	for name, shell := range fakeableShells(t) {
		for _, h := range preflightHosts {
			t.Run(name+"/"+h.host, func(t *testing.T) {
				out, calls := runPreflight(t, shell, h.host, h.mgmtPort)
				got, err := parsePreflight(out)
				if err != nil {
					t.Fatalf("parsePreflight: %v\noutput:\n%s", err, out)
				}
				checkFacts(t, got, &h.want)
				if h.want.Docker.Stopped {
					for _, c := range calls {
						if asksDaemon.MatchString(c) {
							t.Errorf("the daemon does not run, and the script asked it: %q", c)
						}
					}
				}
			})
		}
	}
}

// checkFacts compares the facts field by field, so that a failure names the
// field.
func checkFacts(t *testing.T, got, want *Facts) {
	t.Helper()
	gv, wv := reflect.ValueOf(*got), reflect.ValueOf(*want)
	for i := range gv.NumField() {
		g, w := gv.Field(i).Interface(), wv.Field(i).Interface()
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s:\n got %+v\nwant %+v", gv.Type().Field(i).Name, describe(g), describe(w))
		}
	}
}

// describe makes a pointer show what it points to.
func describe(v any) any {
	if d, ok := v.(*Disk); ok && d != nil {
		return *d
	}
	return v
}

// The scripts look for the tools of the system in /usr/local/sbin and
// /usr/local/bin too, after the directories of PATH, and add neither twice.
func TestSharedPath(t *testing.T) {
	for name, shell := range shells(t) {
		t.Run(name, func(t *testing.T) {
			path := "/opt/tools:/srv/usr/local/bin:" + filepath.Dir(shell[0])
			cmd := exec.Command(shell[0], append(append([]string(nil), shell[1:]...), "root=/srv\n"+sharedFunctions+`printf '%s' "$PATH"`)...)
			cmd.Env = []string{"PATH=" + path, "LANG=C"}
			out, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			if want := path + ":/srv/usr/local/sbin"; string(out) != want {
				t.Errorf("PATH = %q, want %q", out, want)
			}
		})
	}
}

// The script fits the command line that sshx sends, with room to spare.
func TestPreflightCommandIsSmall(t *testing.T) {
	if n := len(preflightCommand(65535, "")); n > 32<<10 {
		t.Errorf("the preflight is %d bytes, which leaves little room under the limit of sshx", n)
	}
	if !strings.HasPrefix(preflightCommand(61001, ""), "mgmt_port=61001\nroot=''\n") {
		t.Errorf("the parameters are not set first: %q", preflightCommand(61001, "")[:40])
	}
}
