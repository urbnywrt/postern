package deploy

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/sshx/sshxtest"
	"github.com/urbnywrt/postern/internal/pki"
)

// fakeHost is a server for the tests of the service, behind the SSH server of
// sshxtest. It answers the commands that an install sends: the preflight, which
// runs the real script against a fake server of testdata/preflight, the
// directory of the install, the uploads, install.sh, the removal of the bundle
// and the install of Docker. It records what ran and the files that the
// uploads left, and refuses anything else.
type fakeHost struct {
	t *testing.T

	mu          sync.Mutex
	server      string // the fake server of the preflight
	afterDocker string // the fake server once Docker is installed
	steps       []string
	files       map[string]remoteFile // what the uploads put, by path
	uploads     []upload              // every upload, in order
	tmp         map[string][]byte     // the temporary files of uploads
	installCmds []string
	unknown     []string

	// What install.sh does: its exit code and output, and onInstall, which
	// runs when it starts (block makes it wait for ctx, as a long command).
	// Unless block, the wrapper of install.sh removes the bundle when it ends,
	// as the real one does.
	installCode   int
	installOutput string
	onInstall     func()
	block         bool
	echoBundleKey bool // install.sh prints the private key of the node
	dockerCode    int
	preflightJunk string // printed instead of the preflight, when set
	failRemoval   bool   // the bundle cannot be removed
	foreignDir    bool   // the directory of the install belongs to another user

	// The Docker path: whether a container of the agent is there, which the
	// install removes; what docker run exits with, and the scripts that
	// started the node. docker run prints the value of POSTERN_JOIN, as a
	// server that echoes it would.
	agentThere   bool
	startCode    int
	startScripts []string
	pullCode     int      // what docker pull of the image exits with
	imageLocal   bool     // the image is on the server already
	pulled       []string // the images that docker pull was asked for
	dockerSetups []string // the scripts that set up Docker
	onPreflight  func()   // runs as the preflight starts
}

type remoteFile struct {
	data []byte
	mode string
}

type upload struct {
	path, mode string
	data       []byte
}

func newFakeHost(t *testing.T, server string) *fakeHost {
	return &fakeHost{t: t, server: server, files: map[string]remoteFile{}, tmp: map[string][]byte{},
		installOutput: "==> checking the bundle\n==> starting the agent\nPostern node installed.\n"}
}

// The commands of an install, as the service sends them.
var (
	uploadFirstRe  = regexp.MustCompile(`^umask 077; cat > (\S+)$`)
	uploadSecondRe = regexp.MustCompile(`^\[ \$\(wc -c < (\S+)\) -eq ([0-9]+) \] && \[ ! -d (\S+) \] && chmod ([0-7]{4}) \S+ && mv -f \S+ \S+ \|\| \{ rm -f \S+; exit 1; \}$`)
	installDirRe   = regexp.MustCompile(`\ncd (\S+) \|\| exit 1\n`)
	joinRe         = regexp.MustCompile(`-e POSTERN_JOIN='([^']*)'`)
	removeBundleRe = regexp.MustCompile(`^rm -f -- (\S+/postern-node-bundle\.tar); \[ ! -e \S+ \]$`)
	pullRe         = regexp.MustCompile(`\n    docker pull '([^']+)' &\n`)
	imageThereRe   = regexp.MustCompile(`^docker image inspect '[^']+' > /dev/null$`)
)

func (h *fakeHost) step(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.steps = append(h.steps, s)
}

// Steps returns the names of the commands that ran, in order.
func (h *fakeHost) Steps() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.steps...)
}

func (h *fakeHost) handle(ctx context.Context, e *sshxtest.Exec) int {
	s := e.Script
	switch {
	case s == sshxtest.SudoCheck:
		return 0
	case strings.HasPrefix(s, "mgmt_port="):
		h.step("preflight")
		return h.preflight(ctx, e)
	case strings.HasPrefix(s, "# postern: mkdir\n"):
		h.step("mkdir")
		return h.mkdir(e)
	case uploadFirstRe.MatchString(s):
		data, err := io.ReadAll(e.Stdin)
		if err != nil {
			return 1
		}
		h.mu.Lock()
		h.tmp[uploadFirstRe.FindStringSubmatch(s)[1]] = data
		h.mu.Unlock()
		return 0
	case uploadSecondRe.MatchString(s):
		m := uploadSecondRe.FindStringSubmatch(s)
		h.mu.Lock()
		defer h.mu.Unlock()
		data, ok := h.tmp[m[1]]
		if size, _ := strconv.Atoi(m[2]); !ok || len(data) != size {
			return 1
		}
		delete(h.tmp, m[1])
		h.files[m[3]] = remoteFile{data: data, mode: m[4]}
		h.uploads = append(h.uploads, upload{path: m[3], mode: m[4], data: data})
		h.steps = append(h.steps, "upload "+m[3])
		return 0
	case strings.HasPrefix(s, "# postern: install\n") && installDirRe.MatchString(s) &&
		strings.Contains(s, "bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node &"):
		h.step("install.sh")
		dir := installDirRe.FindStringSubmatch(s)[1]
		bundle := dir + "/postern-node-bundle.tar"
		h.mu.Lock()
		h.installCmds = append(h.installCmds, s)
		on, block, code, out, echoKey, keep := h.onInstall, h.block, h.installCode, h.installOutput, h.echoBundleKey, h.failRemoval
		uploaded := h.files[bundle].data
		h.mu.Unlock()
		_, _ = io.WriteString(e.Stdout, out)
		if echoKey {
			if b, err := pki.ParseBundleTar(uploaded); err == nil {
				_, _ = e.Stdout.Write(b.KeyPEM)
			}
		}
		if on != nil {
			on()
		}
		if block {
			<-ctx.Done()
			return sshxtest.NoExitStatus
		}
		if !keep {
			h.mu.Lock()
			delete(h.files, bundle)
			h.mu.Unlock()
		}
		return code
	case removeBundleRe.MatchString(s):
		h.mu.Lock()
		defer h.mu.Unlock()
		h.steps = append(h.steps, "rm bundle")
		if h.failRemoval {
			return 1
		}
		delete(h.files, removeBundleRe.FindStringSubmatch(s)[1])
		return 0
	case strings.HasPrefix(s, "# postern: docker\n") && strings.Contains(s, "# Sets up Docker for an install over SSH"):
		h.step("install docker")
		h.mu.Lock()
		defer h.mu.Unlock()
		h.dockerSetups = append(h.dockerSetups, s)
		_, _ = io.WriteString(e.Stdout, "==> Installing Docker with the script of https://get.docker.com\n")
		if h.dockerCode == 0 && h.afterDocker != "" {
			h.server = h.afterDocker
		}
		return h.dockerCode
	case strings.HasPrefix(s, "# postern: pull\n") && pullRe.MatchString(s):
		h.step("pull")
		h.mu.Lock()
		defer h.mu.Unlock()
		h.pulled = append(h.pulled, pullRe.FindStringSubmatch(s)[1])
		if h.pullCode != 0 {
			_, _ = io.WriteString(e.Stderr, "Error response from daemon: Get \"https://ghcr.io/v2/\": dial tcp: i/o timeout\n")
		}
		return h.pullCode
	case imageThereRe.MatchString(s):
		h.step("image inspect")
		h.mu.Lock()
		defer h.mu.Unlock()
		if !h.imageLocal {
			return 1
		}
		return 0
	case strings.HasPrefix(s, "# postern: remove-agent\n"):
		h.step("rm agent")
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.agentThere {
			h.agentThere = false
			_, _ = io.WriteString(e.Stdout, "postern-agent\n")
		}
		return 0
	case strings.HasPrefix(s, "# postern: start\n") && strings.Contains(s, "docker run -d --name postern-agent "):
		h.step("docker run")
		h.mu.Lock()
		defer h.mu.Unlock()
		h.startScripts = append(h.startScripts, s)
		if m := joinRe.FindStringSubmatch(s); m != nil {
			_, _ = fmt.Fprintf(e.Stdout, "POSTERN_JOIN=%s\n", m[1])
		}
		if h.startCode == 0 {
			h.agentThere = true
		}
		return h.startCode
	}
	h.mu.Lock()
	h.unknown = append(h.unknown, s)
	h.mu.Unlock()
	_, _ = fmt.Fprintf(e.Stderr, "fake host: unknown command\n")
	return 127
}

// preflight runs the real script against the fake server of the host.
func (h *fakeHost) preflight(ctx context.Context, e *sshxtest.Exec) int {
	h.mu.Lock()
	server, junk, on := h.server, h.preflightJunk, h.onPreflight
	h.mu.Unlock()
	if on != nil {
		on()
	}
	if junk != "" {
		_, _ = io.WriteString(e.Stdout, junk)
		return 0
	}
	f := fakeServer(h.t, server)
	// The clock of the server is the clock of the test, not the one of the
	// fake server.
	writeExecutable(h.t, f.bin+"/date", fmt.Sprintf("#!/bin/sh\necho %d\n", time.Now().Unix()))
	script, ok := strings.CutPrefix(e.Script, "mgmt_port=")
	port, rest, _ := strings.Cut(script, "\n")
	if !ok || !strings.HasPrefix(rest, "root=''\n") {
		_, _ = fmt.Fprintf(e.Stderr, "fake host: the preflight has no empty root\n")
		return 2
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", "mgmt_port="+port+"\nroot="+shellQuote(f.root)+"\n"+strings.TrimPrefix(rest, "root=''\n"))
	cmd.Env = f.env
	cmd.Dir = h.t.TempDir()
	cmd.Stdout, cmd.Stderr = e.Stdout, e.Stderr
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		return 1
	}
	return 0
}

// mkdirRe is the command that makes the directory of the install, for root.
var mkdirRe = regexp.MustCompile(`\nd=(\S+)\nu=0\n`)

func (h *fakeHost) mkdir(e *sshxtest.Exec) int {
	m := mkdirRe.FindStringSubmatch(e.Script)
	if m == nil {
		return 2
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.foreignDir {
		_, _ = fmt.Fprintf(e.Stderr, "%s belongs to uid 1000, not to 0: remove it, and install again\n", m[1])
		return 1
	}
	h.files[m[1]+"/"] = remoteFile{mode: "dir"}
	// As the real command, which TestMkdirCommand runs: a bundle that an
	// earlier install left goes.
	delete(h.files, m[1]+"/"+bundleFileName)
	return 0
}

// file returns what an upload put at path.
func (h *fakeHost) file(path string) (remoteFile, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f, ok := h.files[path]
	return f, ok
}

// Uploads returns every upload, in order.
func (h *fakeHost) Uploads() []upload {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]upload(nil), h.uploads...)
}

func (h *fakeHost) Unknown() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.unknown...)
}

func (h *fakeHost) set(fn func(h *fakeHost)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn(h)
}

// writeKit writes a node kit into a directory, as the panel image has it,
// with the binaries of arches, and returns the directory.
func writeKit(t *testing.T, arches ...string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data string, mode os.FileMode) {
		path := dir + "/" + name
		if err := os.MkdirAll(path[:strings.LastIndexByte(path, '/')], 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("install.sh", "#!/usr/bin/env bash\n# the installer of a test kit\n", 0o755)
	write("launcher.sh", "#!/bin/sh\n# the launcher of a test kit\n", 0o755)
	write("compose.yaml", "# the compose file of a test kit\n", 0o644)
	for _, arch := range arches {
		write(arch+"/postern-node", kitBinary(arch), 0o755)
	}
	return dir
}

// kitBinary is the binary of arch in a test kit: some 100 KB that name it.
func kitBinary(arch string) string {
	return "\x7fELF " + arch + strings.Repeat(" the node binary of "+arch, 5000)
}
