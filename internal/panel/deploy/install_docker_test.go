package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The script that sets up Docker runs here against a fake server: stand-ins
// for docker and for the tools that start a service or install packages keep
// their state in files and write every call to a log. The PATH holds them and
// a few tools of the machine of the test, so that what the server lacks is
// missing for the script too. Nothing on the machine of the test is touched.

// dockerHost is how the fake server starts.
type dockerHost struct {
	installed bool     // docker is installed
	running   bool     // its daemon answers
	startable bool     // starting the daemon works
	compose   bool     // the Compose v2 plugin is there
	origin    string   // the packages of the engine: "docker-ce", "docker.io", "alpine", "rpm", or "" for none
	osID      string   // ID of os-release
	systemd   bool     // systemd is the init
	tools     []string // the service and package tools that the server has, besides docker
	curlFails bool     // the download of get.docker.com fails
	osInLib   bool     // os-release is in /usr/lib only, not in /etc
	// answersAfter is how many calls of docker info a daemon that was started
	// fails before it answers, as one that OpenRC starts in the background:
	// 0 answers at once.
	answersAfter int
	// dockerPath is an install on the Docker path, which needs no Compose.
	dockerPath bool
}

// dockerStubTools are the tools of the machine of the test that the script and
// the stand-ins need.
var dockerStubTools = []string{"sh", "cat", "grep", "head", "mktemp", "rm", "sed", "tr", "cp", "chmod", "touch"}

// installEngine is the shell that a stand-in runs to install the engine.
const installEngine = `cp "$S/docker-template" "$B/docker" && chmod 0755 "$B/docker" && touch "$S/compose"`

// startDaemon is the shell that a stand-in runs to start the daemon: it
// answers at once, or once docker info has been called as often as
// answers-after says.
const startDaemon = `if [ -f "$S/answers-after" ]; then cp "$S/answers-after" "$S/countdown"; else touch "$S/running"; fi`

// dockerStubs are the stand-ins, by name. $S is the state directory, $B the
// directory of the stand-ins, $L the log of calls.
var dockerStubs = map[string]string{
	"docker-template": `case "$1" in
info) if [ -f "$S/countdown" ]; then
    n=$(cat "$S/countdown")
    if [ "$n" -le 0 ]; then rm -f "$S/countdown"; touch "$S/running"; else echo $((n - 1)) > "$S/countdown"; fi
  fi
  [ -f "$S/running" ] && { echo "Server Version: 27.0.0"; exit 0; }
  echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1 ;;
version) [ -f "$S/running" ] && { echo 27.0.0; exit 0; }
  echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1 ;;
compose) [ -f "$S/compose" ] && { echo "Docker Compose version v2.29.7"; exit 0; }
  echo "docker: 'compose' is not a docker command." >&2; exit 1 ;;
esac
exit 0`,
	"systemctl": `case "$*" in
"start docker"|"enable --now docker"|"restart docker")
  [ -f "$S/startable" ] && { ` + startDaemon + `; exit 0; }
  echo "Job for docker.service failed because the control process exited with error code." >&2; exit 1 ;;
esac
exit 0`,
	"service": `case "$*" in
"docker start")
  [ -f "$S/startable" ] && { ` + startDaemon + `; exit 0; }
  echo " * Starting Docker: docker failed" >&2; exit 1 ;;
esac
exit 0`,
	"rc-service": `case "$*" in
"docker start")
  [ -f "$S/startable" ] && { ` + startDaemon + `; exit 0; }
  echo " * ERROR: docker failed to start" >&2; exit 1 ;;
esac
exit 0`,
	"rc-update": `exit 0`,
	"dpkg-query": `for p; do :; done
[ -f "$S/dpkg-$p" ] && { echo "install ok installed"; exit 0; }
echo "dpkg-query: no packages found matching $p" >&2; exit 1`,
	"rpm": `for p; do :; done
[ -f "$S/rpm-$p" ] && { echo "$p-27.0.0-1.el9.x86_64"; exit 0; }
echo "package $p is not installed"; exit 1`,
	"apt-get": `install=
for a; do [ "$a" = install ] && install=1; done
[ -n "$install" ] || exit 0
for p; do
  case "$p" in
  docker.io) ` + installEngine + ` && touch "$S/dpkg-docker.io" "$S/startable" ;;
  docker-compose-v2|docker-compose-plugin) touch "$S/compose" ;;
  esac
done
exit 0`,
	"dnf": `for p; do
  case "$p" in
  docker-compose-plugin) touch "$S/compose" ;;
  esac
done
exit 0`,
	"apk": `case "$1" in
info) [ -f "$S/apk-docker" ] && { echo docker; exit 0; }; exit 1 ;;
add) for p; do
    case "$p" in
    docker) ` + installEngine + ` && touch "$S/apk-docker" "$S/startable" ;;
    docker-cli-compose) touch "$S/compose" ;;
    esac
  done; exit 0 ;;
esac
exit 0`,
	"curl": `[ -f "$S/curl-fails" ] && { echo "curl: (6) Could not resolve host: get.docker.com" >&2; exit 6; }
out=
while [ $# -gt 0 ]; do
  [ "$1" = -o ] && { out=$2; shift; }
  shift
done
{
  echo "S='$S' B='$B' L='$L'"
  echo 'echo "get-docker.sh $*" >> "$L"'
  echo '` + installEngine + `'
  echo 'touch "$S/dpkg-docker-ce" "$S/running"'
} > "$out"
exit 0`,
	"wget": `exit 1`,
	// sleep does not sleep: the call is what counts.
	"sleep": `exit 0`,
	// timeout runs the command without the time.
	"timeout": `shift
"$@"`,
}

// runDockerSetup runs the script under shell against a fake server set up as
// h, and returns its exit status, its output and the calls that it made.
func runDockerSetup(t *testing.T, shell []string, h dockerHost) (int, string, []string) {
	t.Helper()
	dir := t.TempDir()
	bin, state, root := filepath.Join(dir, "bin"), filepath.Join(dir, "state"), filepath.Join(dir, "root")
	calls := filepath.Join(dir, "calls")
	for _, d := range []string{bin, state, filepath.Join(root, "etc")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range dockerStubTools {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("the machine of the test has no %s", tool)
		}
		if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	stub := func(name, body string) string {
		return fmt.Sprintf("#!/bin/sh\nS=%s B=%s L=%s\necho \"%s $*\" >> \"$L\"\n%s\n",
			shellQuote(state), shellQuote(bin), shellQuote(calls), name, body)
	}
	writeExecutable(t, filepath.Join(state, "docker-template"), stub("docker", dockerStubs["docker-template"]))
	if h.installed {
		writeExecutable(t, filepath.Join(bin, "docker"), stub("docker", dockerStubs["docker-template"]))
	}
	for _, tool := range append([]string{"curl", "wget", "sleep"}, h.tools...) {
		writeExecutable(t, filepath.Join(bin, tool), stub(tool, dockerStubs[tool]))
	}
	touch := func(name string, on bool) {
		if on {
			if err := os.WriteFile(filepath.Join(state, name), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	touch("running", h.running)
	touch("startable", h.startable)
	touch("compose", h.compose)
	touch("curl-fails", h.curlFails)
	switch h.origin {
	case "docker-ce", "docker.io":
		touch("dpkg-"+h.origin, true)
	case "alpine":
		touch("apk-docker", true)
	case "rpm":
		touch("rpm-docker-ce", true)
	}
	if h.answersAfter > 0 {
		if err := os.WriteFile(filepath.Join(state, "answers-after"), []byte(strconv.Itoa(h.answersAfter)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if h.osID != "" {
		etc := filepath.Join(root, "etc")
		if h.osInLib {
			etc = filepath.Join(root, "usr", "lib")
		}
		if err := os.MkdirAll(etc, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(etc, "os-release"), []byte("NAME=Test\nID=\""+h.osID+"\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if h.systemd {
		if err := os.MkdirAll(filepath.Join(root, "run", "systemd", "system"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	args := append(append([]string(nil), shell[1:]...), dockerSetupCommand(root, !h.dockerPath))
	cmd := exec.Command(shell[0], args...)
	cmd.Env = []string{"PATH=" + bin, "LANG=C"}
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("the script did not run: %v", err)
		}
		code = exit.ExitCode()
	}
	data, _ := os.ReadFile(calls)
	return code, string(out), strings.Split(strings.TrimSpace(string(data)), "\n")
}

// engineInstall finds a call that installs or replaces a Docker engine.
var engineInstall = regexp.MustCompile(`^(curl|wget|get-docker\.sh)\b|^(apt-get|dnf|yum) .*\binstall\b.*\b(docker\.io|docker-ce|docker-ce-cli|containerd\.io|moby-engine)\b|^apk add\b.*\bdocker( |$)`)

func TestDockerSetup(t *testing.T) {
	apt := []string{"systemctl", "dpkg-query", "apt-get"}
	openrc := []string{"rc-service", "rc-update", "apk"}
	const aptGet = "apt-get -o DPkg::Lock::Timeout=120 "
	tests := []struct {
		name    string
		host    dockerHost
		code    int
		want    []string // calls that must have been made
		not     []string // calls that must not have been made
		says    string   // what the output must say
		engines bool     // an engine may be installed: Docker was not there
		sleeps  int      // the seconds that the script waited for the daemon
	}{
		{name: "Docker that runs with Compose", code: 0,
			host: dockerHost{installed: true, running: true, compose: true, origin: "docker.io", osID: "ubuntu", systemd: true, tools: apt}},
		{name: "a daemon that hangs is asked within a time", code: 0,
			host: dockerHost{installed: true, running: true, compose: true, origin: "docker.io", osID: "ubuntu", systemd: true,
				tools: append([]string{"timeout"}, apt...)},
			want: []string{"timeout 15 docker info"}},
		{name: "Docker that is stopped is started", code: 0,
			host: dockerHost{installed: true, startable: true, compose: true, origin: "docker-ce", osID: "debian", systemd: true, tools: apt},
			want: []string{"systemctl start docker"}},
		{name: "Docker that is stopped is started by OpenRC", code: 0,
			host: dockerHost{installed: true, startable: true, compose: true, origin: "alpine", osID: "alpine", tools: openrc},
			want: []string{"rc-service docker start"}},
		{name: "Docker that OpenRC starts is waited for until it answers", code: 0,
			host: dockerHost{installed: true, startable: true, compose: true, origin: "alpine", osID: "alpine", tools: openrc, answersAfter: 3},
			want: []string{"rc-service docker start"}, sleeps: 3},
		{name: "Docker that is started and never answers fails after some 20 seconds", code: 1,
			host: dockerHost{installed: true, startable: true, compose: true, origin: "docker-ce", osID: "debian", systemd: true, tools: apt,
				answersAfter: 1000},
			want: []string{"systemctl start docker"}, says: "Docker does not answer, also after it was started", sleeps: 20},
		{name: "Docker that does not start fails with what it says", code: 1,
			host: dockerHost{installed: true, compose: true, origin: "docker.io", osID: "ubuntu", systemd: true, tools: apt},
			want: []string{"systemctl start docker"}, says: "Cannot connect to the Docker daemon"},
		{name: "docker-ce without Compose gets docker-compose-plugin", code: 0,
			host: dockerHost{installed: true, running: true, origin: "docker-ce", osID: "debian", systemd: true, tools: apt},
			want: []string{aptGet + "update", aptGet + "install -y docker-compose-plugin"}},
		{name: "docker.io of Ubuntu without Compose gets docker-compose-v2", code: 0,
			host: dockerHost{installed: true, running: true, origin: "docker.io", osID: "ubuntu", systemd: true, tools: apt},
			want: []string{aptGet + "install -y docker-compose-v2"}},
		{name: "docker.io of Ubuntu whose os-release is in /usr/lib gets docker-compose-v2", code: 0,
			host: dockerHost{installed: true, running: true, origin: "docker.io", osID: "ubuntu", osInLib: true, systemd: true, tools: apt},
			want: []string{aptGet + "install -y docker-compose-v2"}},
		{name: "docker.io of Debian without Compose is left to the admin", code: 1,
			host: dockerHost{installed: true, running: true, origin: "docker.io", osID: "debian", systemd: true, tools: apt},
			says: "install Docker Compose v2 by hand"},
		{name: "Docker of Alpine without Compose gets docker-cli-compose", code: 0,
			host: dockerHost{installed: true, running: true, origin: "alpine", osID: "alpine", tools: openrc},
			want: []string{"apk add --no-cache docker-cli-compose"}},
		{name: "docker-ce of an RPM system without Compose gets docker-compose-plugin", code: 0,
			host: dockerHost{installed: true, running: true, origin: "rpm", osID: "rocky", systemd: true, tools: []string{"systemctl", "rpm", "dnf"}},
			want: []string{"dnf install -y docker-compose-plugin"}},
		{name: "Docker of no known packages without Compose is left to the admin", code: 1,
			host: dockerHost{installed: true, running: true, osID: "ubuntu", systemd: true, tools: apt},
			says: "install Docker Compose v2 by hand"},
		{name: "no Docker: the script of get.docker.com", code: 0, engines: true,
			host: dockerHost{osID: "ubuntu", systemd: true, tools: apt},
			want: []string{"curl -fsSL --proto =https --tlsv1.2 --max-time 300 -o"}},
		{name: "no Docker and no get.docker.com: the packages of Ubuntu", code: 0, engines: true,
			host: dockerHost{osID: "ubuntu", systemd: true, curlFails: true, tools: apt},
			want: []string{aptGet + "install -y docker.io docker-compose-v2", "systemctl enable --now docker"}},
		{name: "no Docker and no get.docker.com: the packages of Alpine", code: 0, engines: true,
			host: dockerHost{osID: "alpine", curlFails: true, tools: openrc},
			want: []string{"apk add --no-cache docker docker-cli-compose", "rc-update add docker default", "rc-service docker start"}},
		{name: "no Docker: the packages of Alpine, whose daemon is waited for", code: 0, engines: true,
			host: dockerHost{osID: "alpine", curlFails: true, tools: openrc, answersAfter: 2},
			want: []string{"apk add --no-cache docker docker-cli-compose", "rc-service docker start"}, sleeps: 2},
		{name: "no Docker and no way to install it", code: 1, engines: true,
			host: dockerHost{osID: "plan9", curlFails: true}, says: "Docker could not be installed"},
		// The Docker path needs no Compose: none is added, and none is missed.
		{name: "docker.io of Debian without Compose will do for the Docker path", code: 0,
			host: dockerHost{installed: true, running: true, origin: "docker.io", osID: "debian", systemd: true, tools: apt, dockerPath: true},
			says: "Docker is ready", not: []string{"apt-get"}},
		{name: "docker-ce without Compose gets no plugin on the Docker path", code: 0,
			host: dockerHost{installed: true, running: true, origin: "docker-ce", osID: "debian", systemd: true, tools: apt, dockerPath: true},
			not:  []string{"apt-get"}},
		{name: "no Docker and no get.docker.com: docker.io alone for the Docker path", code: 0, engines: true,
			host: dockerHost{osID: "debian", systemd: true, curlFails: true, tools: apt, dockerPath: true},
			want: []string{aptGet + "install -y docker.io", "systemctl enable --now docker"},
			not:  []string{aptGet + "install -y docker.io docker-compose-v2"}},
		{name: "no Docker and no get.docker.com: docker alone of Alpine for the Docker path", code: 0, engines: true,
			host: dockerHost{osID: "alpine", curlFails: true, tools: openrc, dockerPath: true},
			want: []string{"apk add --no-cache docker", "rc-service docker start"},
			not:  []string{"apk add --no-cache docker docker-cli-compose"}},
	}
	for name, shell := range fakeableShells(t) {
		for _, tt := range tests {
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				code, out, calls := runDockerSetup(t, shell, tt.host)
				if code != tt.code {
					t.Errorf("exit status %d, want %d\noutput:\n%s\ncalls: %q", code, tt.code, out, calls)
				}
				for _, w := range tt.want {
					found := false
					for _, c := range calls {
						if strings.HasPrefix(c, w) {
							found = true
						}
					}
					if !found {
						t.Errorf("no call %q; calls: %q", w, calls)
					}
				}
				for _, n := range tt.not {
					for _, c := range calls {
						if strings.HasPrefix(c, n) {
							t.Errorf("a call %q, which must not be made; calls: %q", c, calls)
						}
					}
				}
				if tt.says != "" && !strings.Contains(out, tt.says) {
					t.Errorf("the output does not say %q:\n%s", tt.says, out)
				}
				sleeps := 0
				for _, c := range calls {
					if c == "sleep 1" {
						sleeps++
					}
				}
				if sleeps != tt.sleeps {
					t.Errorf("the script waited %d s for the daemon, want %d; calls: %q", sleeps, tt.sleeps, calls)
				}
				if !tt.engines {
					for _, c := range calls {
						if engineInstall.MatchString(c) {
							t.Errorf("Docker was installed, and the script installed an engine over it: %q", c)
						}
					}
				}
			})
		}
	}
}
