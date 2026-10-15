package bootstrap

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/dockerapi"
)

func TestPortListUnion(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{[]string{"", nodePorts}, "20000-40999"},
		{[]string{"\n", nodePorts}, "20000-40999"},
		{[]string{"8080,20000-30000", nodePorts}, "8080,20000-40999"},
		{[]string{"40999-41000", nodePorts}, "20000-41000"},
		{[]string{"19999", nodePorts}, "19999-40999"},
		{[]string{"41001", nodePorts}, "20000-40999,41001"},
		{[]string{"9090, 8080\n", nodePorts}, "8080,9090,20000-40999"},
		{[]string{"0,65535", nodePorts}, "0,20000-40999,65535"},
		{[]string{"20000-40999"}, "20000-40999"},
		{[]string{"5,5,6"}, "5-6"},
		{nil, ""},
	} {
		got, err := portListUnion(c.in...)
		if err != nil || got != c.want {
			t.Errorf("portListUnion(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"a", "70000", "5-3", "1,,2", "1-2-3", "123456", "-5", "5-"} {
		if got, err := portListUnion(bad, nodePorts); err == nil {
			t.Errorf("portListUnion(%q) = %q, want an error", bad, got)
		}
	}
}

func TestSysctlFileText(t *testing.T) {
	want := `# Written by the Postern node (bootstrap or install.sh), and again by each run of it.
# The loopback ports of the node, 20000-40999, are reserved: the kernel never
# picks one of them as the local port of an outgoing connection, so the engines and
# the edge always find their ports free. The ports that were reserved already when
# the installer ran are in the list too.
net.ipv4.ip_local_reserved_ports = 8080,20000-40999
# The connections in the accept queue of an edge generation that drains move to
# the generation that takes over, instead of being aborted (Linux 5.14 or later).
net.ipv4.tcp_migrate_req = 1`
	if got := sysctlFileText("8080,20000-40999", true); got != want {
		t.Errorf("sysctlFileText =\n%s\nwant\n%s", got, want)
	}
	if got := sysctlFileText("20000-40999", false); strings.Contains(got, migrateReqKey) {
		t.Errorf("a kernel without tcp_migrate_req gets it:\n%s", got)
	}
}

// TestSysctlFileMatchesInstallSh runs install.sh's own functions on the same
// input: the setting lines and the merged list are the same, and only the
// header line differs (ruling N-1).
func TestSysctlFileMatchesInstallSh(t *testing.T) {
	bash, err := exec.LookPath("bash")
	script, _ := filepath.Abs(filepath.Join("..", "..", "..", "deploy", "node", "install.sh"))
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("no bash")
	}
	for _, current := range []string{"", "8080", "8080,20000-30000", "40999-41000 , 19999", "1-65535"} {
		for _, migrate := range []bool{true, false} {
			flag := ""
			if migrate {
				flag = "1"
			}
			cmd := exec.Command(bash, "-c", `source "$1"; MIGRATE_REQ_SUPPORTED=$3; merged=$(port_list_union "$2" "$RESERVED_PORTS") || exit 9; reserved_ports_file "$merged"`,
				"test", script, current, flag)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("install.sh with %q: %v", current, err)
			}
			merged, err := portListUnion(current, nodePorts)
			if err != nil {
				t.Fatal(err)
			}
			theirs := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
			ours := strings.Split(sysctlFileText(merged, migrate), "\n")
			if len(theirs) != len(ours) || !slices.Equal(theirs[1:], ours[1:]) {
				t.Errorf("current %q, migrate %v:\ninstall.sh:\n%s\nbootstrap:\n%s", current, migrate, out, strings.Join(ours, "\n"))
			}
			if !strings.Contains(theirs[0], "install.sh") || !strings.Contains(ours[0], "the Postern node (bootstrap or install.sh)") {
				t.Errorf("header lines: %q / %q", theirs[0], ours[0])
			}
		}
	}
}

func helperSpecs(h *harness) []dockerapi.ContainerSpec {
	var out []dockerapi.ContainerSpec
	for _, c := range h.docker.Calls() {
		if c.Method == "Create" && strings.HasPrefix(c.Target, helperPrefix) {
			out = append(out, *c.Spec)
		}
	}
	return out
}

func TestSysctlsRunTheHelper(t *testing.T) {
	h := newHarness(t)
	h.setProc("8080", "0")
	h.helperSay = "wrote /etc/sysctl.d/90-postern.conf\n"
	b := h.boot()
	if err := b.makeLayout(); err != nil {
		t.Fatal(err)
	}
	b.sysctls(t.Context())
	specs := helperSpecs(h)
	if len(specs) != 1 {
		t.Fatalf("helpers = %d, want 1", len(specs))
	}
	s := specs[0]
	text := sysctlFileText("8080,20000-40999", true)
	wantLabels := map[string]string{"postern.managed": "true", "postern.role": "helper"}
	switch {
	case !s.Privileged, s.NetworkMode != "host", s.Image != testRunner, s.User != "0:0":
		t.Errorf("spec = %+v", s)
	case !slices.Equal(s.Binds, []string{"/etc/sysctl.d:/host/etc/sysctl.d"}):
		t.Errorf("binds = %q", s.Binds)
	case !maps.Equal(s.Labels, wantLabels):
		t.Errorf("labels = %v", s.Labels)
	case !slices.Equal(s.Env, []string{"PORTS=8080,20000-40999", "MIGRATE=1", "CONF=" + text}):
		t.Errorf("env = %q", s.Env)
	case !slices.Equal(s.Entrypoint, []string{"/bin/sh", "-c", helperScript}):
		t.Errorf("entrypoint = %q", s.Entrypoint)
	case len(s.Name) != len(helperPrefix)+8:
		t.Errorf("name = %q", s.Name)
	}
	if list, _ := h.docker.List(t.Context(), map[string]string{"postern.role": "helper"}, true); len(list) != 0 {
		t.Errorf("the helper was not removed: %v", list)
	}
	h.wantLog("wrote /etc/sysctl.d/90-postern.conf")
	if got := readString(t, filepath.Join(h.home, "data", "run", sysctlMarker)); got != textHash(text)+"\n" {
		t.Errorf("marker = %q", got)
	}

	// The kernel has the values now, and the file is known: no helper.
	h.setProc("8080,20000-40999", "1")
	h.docker.ResetCalls()
	b.sysctls(t.Context())
	if n := len(helperSpecs(h)); n != 0 {
		t.Errorf("helpers = %d with everything set", n)
	}
	// A reboot drops the values: the helper runs again.
	h.setProc("8080", "0")
	b.sysctls(t.Context())
	if n := len(helperSpecs(h)); n != 1 {
		t.Errorf("helpers = %d after a reboot", n)
	}
}

func TestSysctlsFailuresAreWarnings(t *testing.T) {
	h := newHarness(t)
	h.helperRC = helperFileFailed | helperSysctlFailed
	b := h.boot()
	if err := b.makeLayout(); err != nil {
		t.Fatal(err)
	}
	b.sysctls(t.Context())
	h.wantLog("cannot write /etc/sysctl.d/90-postern.conf")
	h.wantLog("sysctl -w failed in the helper")
	if _, err := os.Stat(filepath.Join(h.home, "data", "run", sysctlMarker)); !os.IsNotExist(err) {
		t.Error("the marker was written though the file was not")
	}

	h.docker.SetError("Create", os.ErrPermission)
	b.sysctls(t.Context())
	h.wantLog("the sysctls of the node are not set")

	// The image is pulled when it is missing.
	h2 := newHarness(t)
	h2.opt.RunnerImage = "alpine:missing"
	h2.boot().sysctls(t.Context())
	var pulled bool
	for _, c := range h2.docker.Calls() {
		pulled = pulled || (c.Method == "Pull" && c.Target == "alpine:missing")
	}
	if !pulled {
		t.Error("the runner image was not pulled")
	}
}

func TestSysctlsRemoveAnOldHelper(t *testing.T) {
	h := newHarness(t)
	if _, err := h.docker.Create(t.Context(), dockerapi.ContainerSpec{Name: helperPrefix + "deadbeef", Image: testRunner,
		Labels: map[string]string{"postern.managed": "true", "postern.role": "helper"}}); err != nil {
		t.Fatal(err)
	}
	h.boot().sysctls(t.Context())
	if _, err := h.docker.Inspect(t.Context(), helperPrefix+"deadbeef"); err == nil {
		t.Error("the helper of an earlier run is still there")
	}
}

func TestSysctlsKernelWithoutMigrateReq(t *testing.T) {
	h := newHarness(t)
	h.setProc("20000-40999", "")
	b := h.boot()
	if err := b.makeLayout(); err != nil {
		t.Fatal(err)
	}
	b.sysctls(t.Context())
	h.wantLog("this kernel has no net.ipv4.tcp_migrate_req")
	specs := helperSpecs(h)
	if len(specs) != 1 || !slices.Contains(specs[0].Env, "MIGRATE=") {
		t.Fatalf("helpers = %+v", specs)
	}
}

// TestHelperScript runs the helper's script with sh, the directory and
// sysctl stood in for.
func TestHelperScript(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	tools := t.TempDir()
	calls := filepath.Join(t.TempDir(), "calls")
	mustWrite(t, filepath.Join(tools, "sysctl"), "#!/bin/sh\necho \"$@\" >> "+calls+"\nexit ${SYSCTL_RC:-0}\n")
	if err := os.Chmod(filepath.Join(tools, "sysctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(helperScript, helperMount, dir)
	text := sysctlFileText("20000-40999", true)
	run := func(rc string) (int, string) {
		cmd := exec.Command(sh, "-c", script)
		cmd.Env = []string{"PATH=" + tools + ":/usr/bin:/bin", "PORTS=20000-40999", "MIGRATE=1", "CONF=" + text, "SYSCTL_RC=" + rc}
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, string(out)
	}
	code, out := run("0")
	if code != 0 || !strings.Contains(out, "wrote") {
		t.Fatalf("first run: %d, %q", code, out)
	}
	file := filepath.Join(dir, sysctlFile)
	if got := readString(t, file); got != text+"\n" {
		t.Errorf("the file = %q", got)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o644 {
		t.Errorf("the file mode %v", st.Mode().Perm())
	}
	want := "-w net.ipv4.ip_local_reserved_ports=20000-40999\n-w net.ipv4.tcp_migrate_req=1\n"
	if got := readString(t, calls); got != want {
		t.Errorf("sysctl calls = %q, want %q", got, want)
	}
	// The same text again: the file is left alone.
	if code, out := run("0"); code != 0 || strings.Contains(out, "wrote") {
		t.Errorf("second run: %d, %q", code, out)
	}
	if code, _ := run("1"); code != helperSysctlFailed {
		t.Errorf("a failing sysctl: exit %d, want %d", code, helperSysctlFailed)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Errorf("left behind: %q", left)
	}
}
