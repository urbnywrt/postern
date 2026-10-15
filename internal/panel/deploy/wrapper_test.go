package deploy

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The commands of an install that run for long, and the one that makes the
// directory of the install, run here under every shell there is, in temporary
// directories of the test. Nothing outside them is touched.

// childScript is a command that waits until it is signalled, and notes the
// signal; the one of exitScript ends at once.
const (
	childScript = `trap 'echo TERM > got; exit 3' TERM
trap 'echo HUP > got; exit 4' HUP
echo started > started
while :; do sleep 1; done
`
	exitScript = "echo started > started\nexit 7\n"
)

// startWrapped starts the wrapper of child under shell in dir, with a cleanup
// that removes the file "bundle" and notes that it ran.
func startWrapped(t *testing.T, shell []string, dir, child string) *exec.Cmd {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "child.sh"), []byte(child), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := wrapped("test", "cd "+shellQuote(dir)+" || exit 1\n", "sh ./child.sh", `rm -f -- bundle; echo cleaned > cleaned`)
	cmd := exec.Command(shell[0], append(append([]string(nil), shell[1:]...), script)...)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	waitForFile(t, filepath.Join(dir, "started"))
	return cmd
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// exitCode waits for cmd and returns its exit status.
func exitCode(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(waitTimeout):
		t.Fatal("the wrapper did not end")
		return -1
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", filepath.Base(path), err)
	}
	return strings.TrimSpace(string(data))
}

// The wrapper passes TERM and HUP on to its command, which a shell of sshd that
// is told to stop would not do, waits for it, exits as it did, and runs its
// cleanup at the end, after a signal as well.
func TestWrapper(t *testing.T) {
	for name, shell := range shells(t) {
		t.Run(name, func(t *testing.T) {
			for _, tt := range []struct {
				sig  syscall.Signal
				name string
				code int
			}{{syscall.SIGTERM, "TERM", 3}, {syscall.SIGHUP, "HUP", 4}} {
				dir := t.TempDir()
				cmd := startWrapped(t, shell, dir, childScript)
				if err := cmd.Process.Signal(tt.sig); err != nil {
					t.Fatal(err)
				}
				if code := exitCode(t, cmd); code != tt.code {
					t.Errorf("%s: the wrapper exited with %d, want %d, the status of its command", tt.name, code, tt.code)
				}
				if got := read(t, filepath.Join(dir, "got")); got != tt.name {
					t.Errorf("%s: the command got %q", tt.name, got)
				}
				if _, err := os.Stat(filepath.Join(dir, "bundle")); !errors.Is(err, os.ErrNotExist) || read(t, filepath.Join(dir, "cleaned")) != "cleaned" {
					t.Errorf("%s: the cleanup did not run (bundle: %v)", tt.name, err)
				}
			}

			dir := t.TempDir()
			cmd := startWrapped(t, shell, dir, exitScript)
			if code := exitCode(t, cmd); code != 7 {
				t.Errorf("the wrapper exited with %d, want 7, the status of its command", code)
			}
			if _, err := os.Stat(filepath.Join(dir, "bundle")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the cleanup did not run after the command ended: %v", err)
			}
		})
	}
}

// A signal that comes as the wrapper starts its command must not be lost: the
// child that dash or the ash of busybox has just forked starts with the traps
// of the wrapper, and forgets a signal that reaches it before it has put them
// back. Many runs get a TERM at a random time of their start, from 0 to 24 ms,
// and some just before the fork, where the wrapper is held in a sleep and
// sends the TERM on right after it has forked. Every run must end, and leave
// no child behind.
func TestWrapperLosesNoSignal(t *testing.T) {
	const (
		randomRuns = 48
		armedRuns  = 12
		workers    = 8
	)
	for name, shell := range shells(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			var hung atomic.Bool
			runs := make(chan bool)
			var wg sync.WaitGroup
			for range workers {
				wg.Go(func() {
					for armed := range runs {
						if !hung.Load() && !signalRun(t, shell, base, armed) {
							hung.Store(true) // the runs that are left are skipped
						}
					}
				})
			}
			for i := range randomRuns + armedRuns {
				runs <- i >= randomRuns
			}
			close(runs)
			wg.Wait()
		})
	}
}

// signalRun runs a wrapper under shell, in a directory of its own in base,
// whose child sleeps until a signal ends it, and sends the wrapper TERM: just
// before the fork when armed, else after a random 0 to 24 ms. It returns false
// when the wrapper did not end.
func signalRun(t *testing.T, shell []string, base string, armed bool) bool {
	dir, err := os.MkdirTemp(base, "run")
	if err != nil {
		t.Error(err)
		return true
	}
	child := `sh -c 'echo $$ > pid; exec sleep 30'`
	if armed {
		child = "echo > armed; sleep 0.2; " + child
	}
	cmd := exec.Command(shell[0], append(append([]string(nil), shell[1:]...), wrapped("test", "cd "+shellQuote(dir)+" || exit 1\n", child, ""))...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Error(err)
		return true
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if armed {
		for deadline := time.Now().Add(waitTimeout); ; time.Sleep(time.Millisecond) {
			if _, err := os.Stat(filepath.Join(dir, "armed")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Error("the wrapper did not come to its fork")
				break
			}
		}
	} else {
		time.Sleep(time.Duration(rand.IntN(25)) * time.Millisecond)
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	what := fmt.Sprintf("a TERM %s", map[bool]string{true: "just before the fork", false: "early on"}[armed])
	select {
	case err := <-done:
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		// 143: the child ended on the TERM, and the wrapper with its status.
		// -1: the TERM came before the traps of the wrapper, and ended it
		// before it started anything.
		if code != 143 && code != -1 {
			t.Errorf("after %s the wrapper ended with %v, want exit status 143, or the TERM", what, err)
		}
	case <-time.After(waitTimeout):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		t.Errorf("after %s the wrapper did not end within %s: the signal was lost", what, waitTimeout)
		return false
	}
	if data, err := os.ReadFile(filepath.Join(dir, "pid")); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && running(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Errorf("after %s the child %d runs on, and the wrapper has ended", what, pid)
		}
	}
	return true
}

// running reports whether the process pid runs: it is there, and not a zombie.
func running(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// "pid (comm) state ...": comm may hold anything, the state follows its
	// last parenthesis.
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || s[i+2] != 'Z'
}

// The wrapper of the setup of Docker hands the script to its sh whole, through
// its quoting. Its sh is replaced by printf here: nothing of the setup runs.
func TestDockerCommandCarriesTheScript(t *testing.T) {
	const child = `sh -c "$s" &`
	cmdText := dockerCommand(true)
	if strings.Count(cmdText, child) != 1 {
		t.Fatalf("the wrapper does not run the script as %q", child)
	}
	for name, shell := range shells(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "script")
			text := strings.Replace(cmdText, child, `printf '%s' "$s" > `+shellQuote(out)+` &`, 1)
			if b, err := exec.Command(shell[0], append(append([]string(nil), shell[1:]...), text)...).CombinedOutput(); err != nil {
				t.Fatalf("the wrapper failed: %v\n%s", err, b)
			}
			if got := read(t, out); got != strings.TrimSpace(dockerSetupCommand("", true)) {
				t.Errorf("the script arrived changed (%d bytes, want %d)", len(got), len(strings.TrimSpace(dockerSetupCommand("", true))))
			}
		})
	}
}

// The wrapper of install.sh removes the bundle when install.sh ends, also when
// it is stopped, and passes the signal on to it.
func TestInstallCommandRemovesTheBundle(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("the machine of the test has no bash, which install.sh needs")
	}
	for name, shell := range shells(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for file, content := range map[string]string{
				"install.sh":              "echo \"$@\" > args\n" + childScript,
				"postern-node-bundle.tar": "the key of the node",
			} {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(shell[0], append(append([]string(nil), shell[1:]...), installCommand(dir))...)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			waitForFile(t, filepath.Join(dir, "started"))
			if got := read(t, filepath.Join(dir, "args")); got != "--bundle postern-node-bundle.tar --binary ./postern-node" {
				t.Errorf("install.sh got %q", got)
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			if code := exitCode(t, cmd); code != 3 {
				t.Errorf("exit status %d, want 3, that of install.sh", code)
			}
			if got := read(t, filepath.Join(dir, "got")); got != "TERM" {
				t.Errorf("install.sh got %q, want TERM", got)
			}
			if _, err := os.Stat(filepath.Join(dir, "postern-node-bundle.tar")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the bundle is still there after install.sh was stopped: %v", err)
			}
		})
	}
}

// The directory of the install is made for root only, and one that is a link,
// a file, or a directory of another user is refused. The temporary files that
// an upload of the bundle may have left are removed, and so is a bundle that
// an earlier install could not remove.
func TestMkdirCommand(t *testing.T) {
	uid := os.Getuid()
	for name, shell := range shells(t) {
		t.Run(name, func(t *testing.T) {
			run := func(dir string, uid int) (int, string) {
				out, err := exec.Command(shell[0], append(append([]string(nil), shell[1:]...), mkdirCommand(dir, uid))...).CombinedOutput()
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					return exit.ExitCode(), string(out)
				}
				if err != nil {
					t.Fatal(err)
				}
				return 0, string(out)
			}
			mode := func(path string) os.FileMode {
				fi, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				return fi.Mode()
			}

			fresh := filepath.Join(t.TempDir(), "postern-install")
			if code, out := run(fresh, uid); code != 0 || mode(fresh) != os.ModeDir|0o700 {
				t.Errorf("a new directory: exit %d, mode %v, want 0 and drwx------\n%s", code, mode(fresh), out)
			}

			old := filepath.Join(t.TempDir(), "postern-install")
			if err := os.Mkdir(old, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, f := range []string{".postern-node-bundle.tar.tmp-0123456789abcdef", "postern-node-bundle.tar", "postern-node"} {
				if err := os.WriteFile(filepath.Join(old, f), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if code, out := run(old, uid); code != 0 || mode(old) != os.ModeDir|0o700 {
				t.Errorf("a directory that is there: exit %d, mode %v, want 0 and drwx------\n%s", code, mode(old), out)
			}
			if _, err := os.Stat(filepath.Join(old, ".postern-node-bundle.tar.tmp-0123456789abcdef")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a temporary file of the bundle is left: %v", err)
			}
			if _, err := os.Stat(filepath.Join(old, "postern-node-bundle.tar")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the bundle that an earlier install left is still there: %v", err)
			}
			if _, err := os.Stat(filepath.Join(old, "postern-node")); err != nil {
				t.Errorf("another file of the directory was removed: %v", err)
			}

			if code, out := run(old, uid+1); code == 0 || !strings.Contains(out, "belongs to uid") {
				t.Errorf("a directory of another user: exit %d, want a refusal\n%s", code, out)
			}

			target := t.TempDir()
			link := filepath.Join(t.TempDir(), "postern-install")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if code, out := run(link, uid); code == 0 || !strings.Contains(out, "is not a directory") {
				t.Errorf("a link: exit %d, want a refusal\n%s", code, out)
			}
			if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
				t.Errorf("the command wrote through the link: %v %v", entries, err)
			}

			file := filepath.Join(t.TempDir(), "postern-install")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if code, out := run(file, uid); code == 0 || !strings.Contains(out, "is not a directory") {
				t.Errorf("a file: exit %d, want a refusal\n%s", code, out)
			}
		})
	}
}
