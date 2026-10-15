package sshxtest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// SudoMode is how the sudo that [Shell] and [ForeignShell] put first on the
// PATH behaves.
type SudoMode int

const (
	// SudoPasswordless runs the command, as sudo does for a user with
	// NOPASSWD.
	SudoPasswordless SudoMode = iota

	// SudoNeedsPassword refuses as sudo -n does when it would have to ask for
	// a password: "sudo: a password is required".
	SudoNeedsPassword

	// SudoRsNeedsPassword refuses as sudo-rs, the sudo of Ubuntu 25.10 and
	// later, does: "sudo: interactive authentication is required".
	SudoRsNeedsPassword

	// SudoNotInSudoers refuses a user that the sudoers file does not name, in
	// words that sshx does not look for.
	SudoNotInSudoers

	// SudoLocalized refuses in another language, which sshx cannot read.
	SudoLocalized

	// SudoPasswordlessForTrueOnly runs "sudo -n true" and asks for a password
	// for anything else, as sudo does for a user with NOPASSWD for /usr/bin/true
	// only.
	SudoPasswordlessForTrueOnly
)

// The stand-ins for sudo share a start: they know only "sudo -n true" and
// "sudo -n -- command...", the forms that sshx uses, and want LC_ALL=C, which
// sshx sets so that sudo speaks English.
const sudoHeader = `#!/bin/sh
if [ "${LC_ALL-}" != C ]; then
	echo "sudo (sshxtest): LC_ALL is not C" >&2
	exit 65
fi
if [ "${1-}" != -n ]; then
	echo "sudo (sshxtest): unexpected arguments: $*" >&2
	exit 64
fi
shift
if [ "${1-}" = -- ]; then
	shift
fi
if [ "$#" -eq 0 ]; then
	echo "sudo (sshxtest): no command" >&2
	exit 64
fi
`

var sudoScripts = map[SudoMode]string{
	SudoPasswordless:    sudoHeader + "exec \"$@\"\n",
	SudoNeedsPassword:   sudoHeader + "echo 'sudo: a password is required' >&2\nexit 1\n",
	SudoRsNeedsPassword: sudoHeader + "echo 'sudo: interactive authentication is required' >&2\nexit 1\n",
	SudoNotInSudoers:    sudoHeader + "echo \"$USER is not in the sudoers file.\" >&2\nexit 1\n",
	SudoLocalized:       sudoHeader + "echo 'sudo: требуется пароль' >&2\nexit 1\n",
	SudoPasswordlessForTrueOnly: sudoHeader + `if [ "$*" = true ]; then
	exit 0
fi
echo 'sudo: a password is required' >&2
exit 1
`,
}

// A ShellOption changes the machine on which [Shell] and [ForeignShell] run
// commands.
type ShellOption func(*shellEnv)

// WithoutBase64 leaves base64 out of the PATH: it holds sh and the stand-in for
// sudo, and nothing else.
func WithoutBase64() ShellOption {
	return func(env *shellEnv) { env.bare = true }
}

// WithBash makes bash the login shell, and the sh on the PATH as well, which
// bash runs in its POSIX mode. The test is skipped where there is no bash.
func WithBash() ShellOption {
	return func(env *shellEnv) { env.bash = true }
}

// WithTrace makes the login shell trace what it runs on the error output (sh
// -x), as one does with "set -x" in a .bashrc that sshd reads.
func WithTrace() ShellOption {
	return func(env *shellEnv) { env.trace = true }
}

// Shell returns a Handler that runs every command with sh -c on the test
// machine, the way sshd runs it with the login shell of the user, so that a
// test sees what a real shell makes of the command line. Commands run in a
// directory of their own, with HOME, USER and LOGNAME set as sshd sets them,
// LANG=C, and a PATH that starts with a directory that holds a stand-in for
// sudo (see [SudoMode]).
//
// As sshd, the handler passes the signals of the client on to the process that
// it started, and leaves the process running when the client closes the
// session; the test ends what is left. Each command runs in a process group of
// its own, which goes when the test ends.
//
// The test is skipped where there is no sh.
func Shell(t testing.TB, sudo SudoMode, opts ...ShellOption) Handler {
	t.Helper()
	env := newShellEnv(t, sudo, opts)
	return func(ctx context.Context, e *Exec) int {
		if env.trace {
			return env.run(ctx, e, env.sh, "-x", "-c", e.Command)
		}
		return env.run(ctx, e, env.sh, "-c", e.Command)
	}
}

// ForeignShell returns a Handler like [Shell] for a user whose login shell is
// not sh, such as fish or csh. It takes from a command line only what every
// shell reads alike: words separated by single spaces, each either a string in
// single quotes without backslashes, line ends or '!' in it, or a run of
// letters, digits and _ . / + = : -. It runs the first word with the others as
// its arguments, the first word after "exec" if the line starts with it, as
// every shell has exec. Any other command line it refuses, with exit code 127,
// as a shell that does not speak sh would fail on it.
func ForeignShell(t testing.TB, sudo SudoMode, opts ...ShellOption) Handler {
	t.Helper()
	env := newShellEnv(t, sudo, opts)
	return func(ctx context.Context, e *Exec) int {
		words, ok := foreignWords(e.Command)
		if ok && words[0] == "exec" {
			words = words[1:]
		}
		if !ok || len(words) == 0 {
			_, _ = fmt.Fprintf(e.Stderr, "foreign shell (sshxtest): cannot read %q\n", e.Command)
			return 127
		}
		return env.run(ctx, e, words[0], words[1:]...)
	}
}

// plainChars are the characters of a word without quotes that every shell
// takes as they are.
const plainChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./+=:-"

// foreignWords splits a command line as [ForeignShell] reads it.
func foreignWords(line string) ([]string, bool) {
	var words []string
	for {
		var w string
		if strings.HasPrefix(line, "'") {
			end := strings.IndexByte(line[1:], '\'')
			if end < 0 {
				return nil, false
			}
			w, line = line[1:1+end], line[2+end:]
			if strings.ContainsAny(w, "\\\n!") {
				return nil, false
			}
		} else {
			end := strings.IndexByte(line, ' ')
			if end < 0 {
				end = len(line)
			}
			w, line = line[:end], line[end:]
			if w == "" || strings.TrimLeft(w, plainChars) != "" {
				return nil, false
			}
		}
		words = append(words, w)
		if line == "" {
			return words, true
		}
		if line[0] != ' ' || len(line) == 1 {
			return nil, false
		}
		line = line[1:]
	}
}

// shellEnv is where the commands of [Shell] and [ForeignShell] run.
type shellEnv struct {
	sh, home, path string
	bare           bool // the PATH holds sh and sudo only
	bash           bool // bash is the login shell and sh
	trace          bool // the login shell traces what it runs

	mu     sync.Mutex
	groups []int // the process groups of the commands, to end when the test ends
}

func newShellEnv(t testing.TB, sudo SudoMode, opts []ShellOption) *shellEnv {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sshxtest: no sh on this machine")
	}
	script, ok := sudoScripts[sudo]
	if !ok {
		t.Fatalf("sshxtest: unknown sudo mode %d", sudo)
	}
	env := &shellEnv{sh: sh}
	for _, o := range opts {
		o(env)
	}
	if env.bash {
		bash, err := exec.LookPath("bash")
		if err != nil {
			t.Skip("sshxtest: no bash on this machine")
		}
		env.sh = bash
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	env.home = filepath.Join(dir, "home")
	for _, d := range []string{bin, env.home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("sshxtest: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(script), 0o700); err != nil {
		t.Fatalf("sshxtest: %v", err)
	}
	if env.bare || env.bash {
		// The sh of the commands: the login shell itself, which is bash in its
		// POSIX mode when it is run as sh.
		if err := os.Symlink(env.sh, filepath.Join(bin, "sh")); err != nil {
			t.Fatalf("sshxtest: %v", err)
		}
	}
	env.path = strings.Join([]string{bin, "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}, ":")
	if env.bare {
		env.path = bin
	}
	t.Cleanup(env.killAll)
	return env
}

// signals are the signals that a client can send, by their names in SSH.
var signals = map[string]syscall.Signal{
	"HUP": syscall.SIGHUP, "INT": syscall.SIGINT, "QUIT": syscall.SIGQUIT, "KILL": syscall.SIGKILL, "TERM": syscall.SIGTERM,
}

// run runs name with args for e and returns its exit status, or NoExitStatus
// once the client has gone: the process may run on then, as it does under
// sshd, which only closes its input and output.
func (env *shellEnv) run(ctx context.Context, e *Exec, name string, args ...string) int {
	cmd := exec.Command(name, args...)
	cmd.Dir = env.home
	cmd.Env = []string{"PATH=" + env.path, "HOME=" + env.home, "USER=" + e.User, "LOGNAME=" + e.User, "LANG=C"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = e.Stdin, e.Stdout, e.Stderr
	// The input is the SSH channel, which ends only when the client closes its
	// side; a command that does not read it must not keep Run waiting.
	cmd.WaitDelay = 2 * time.Second
	newProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(e.Stderr, "sshxtest: %v\n", err)
		return 127
	}
	env.mu.Lock()
	env.groups = append(env.groups, cmd.Process.Pid)
	env.mu.Unlock()

	exited := make(chan int, 1)
	go func() {
		_ = cmd.Wait()
		// A command that a signal ended has the status that a shell gives it,
		// 128 and the number of the signal, which is also what an SSH client
		// makes of the exit signal of sshd.
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			exited <- 128 + int(ws.Signal())
			return
		}
		exited <- cmd.ProcessState.ExitCode()
	}()
	pass := func(name string) {
		if sig, ok := signals[name]; ok {
			_ = cmd.Process.Signal(sig)
		}
	}
	for {
		select {
		case code := <-exited:
			return code
		case name := <-e.Signals:
			pass(name)
		case <-ctx.Done():
			// A signal that came with the end of ctx is passed on all the same.
			for {
				select {
				case name := <-e.Signals:
					pass(name)
				default:
					return NoExitStatus
				}
			}
		}
	}
}

// killAll ends the process groups of every command, and what they left
// behind.
func (env *shellEnv) killAll() {
	env.mu.Lock()
	defer env.mu.Unlock()
	for _, pid := range env.groups {
		killProcessGroup(pid)
	}
}
