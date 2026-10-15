package deploy

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/sshx"
	"github.com/urbnywrt/postern/internal/panel/sshx/sshxtest"
)

// The script reaches a server whole through the transport of sshx, as root
// and through sudo, and runs there: here a server with sh and the tools of a
// base system only, whose /etc and /proc are those of the machine of the test.
// It finds the SSH server of the test among the listening sockets.
func TestPreflightThroughTheTransport(t *testing.T) {
	// The script looks in /usr/local/sbin and /usr/local/bin too, which the
	// server here shares with the machine of the test.
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin"} {
		for _, tool := range []string{"docker", "ss", "netstat"} {
			if _, err := os.Stat(filepath.Join(dir, tool)); err == nil {
				t.Skipf("the machine of the test has %s in %s, where the script looks for it", tool, dir)
			}
		}
	}
	bin := t.TempDir()
	for _, tool := range []string{"sh", "base64", "head", "tr", "cat", "awk", "sort", "cut", "uname", "id", "date", "true"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("the machine of the test has no %s", tool)
		}
		if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	// A sudo that runs the command, as passwordless sudo does.
	writeExecutable(t, filepath.Join(bin, "sudo"), "#!/bin/sh\n[ \"$1\" = -n ] && shift\n[ \"$1\" = -- ] && shift\nexec \"$@\"\n")
	home := t.TempDir()
	srv := sshxtest.Start(t, sshxtest.Config{Password: sshPassword, Handler: func(ctx context.Context, e *sshxtest.Exec) int {
		// The login shell gets the command line, as sshd hands it over.
		cmd := exec.CommandContext(ctx, filepath.Join(bin, "sh"), "-c", e.Command)
		cmd.Env = []string{"PATH=" + bin, "HOME=" + home, "LANG=C"}
		cmd.Dir = home
		cmd.Stdin, cmd.Stdout, cmd.Stderr = e.Stdin, e.Stdout, e.Stderr
		var exit *exec.ExitError
		switch err := cmd.Run(); {
		case err == nil:
			return 0
		case errors.As(err, &exit):
			return exit.ExitCode()
		}
		return 1
	}})
	machine, err := exec.Command("uname", "-m").Output()
	if err != nil {
		t.Fatal(err)
	}

	for _, user := range []string{"root", "deploy"} {
		t.Run(user, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
			defer cancel()
			client, _, err := sshx.Dial(ctx, sshx.Target{Host: srv.Host, Port: srv.Port, User: user, HostKey: srv.Fingerprint()},
				sshx.Auth{Password: sshPassword})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer func() { _ = client.Close() }()
			out := &cappedBuffer{max: maxPreflightOutput}
			before := time.Now()
			code, err := client.Run(ctx, preflightCommand(uint32(srv.Port), ""), nil, out)
			if err != nil || code != 0 {
				t.Fatalf("Run = %d, %v\n%s", code, err, out.b)
			}
			f, err := parsePreflight(out.b)
			if err != nil {
				t.Fatalf("parsePreflight: %v\n%s", err, out.b)
			}
			if f.Machine != strings.TrimSpace(string(machine)) || f.UID != os.Getuid() {
				t.Errorf("machine %q uid %d, want %q and %d", f.Machine, f.UID, bytes.TrimSpace(machine), os.Getuid())
			}
			if d := f.RemoteTime.Sub(before); d < -2*time.Second || d > time.Minute {
				t.Errorf("the clock of the server is %v, the test began at %v", f.RemoteTime, before)
			}
			if f.Docker.Installed || f.ListenTool != "proc" {
				t.Errorf("Docker %+v, listen tool %q: want no Docker and the tables of the kernel", f.Docker, f.ListenTool)
			}
			want := netip.AddrPortFrom(netip.MustParseAddr(srv.Host), uint16(srv.Port))
			if !slices.ContainsFunc(f.Listeners, func(l Listener) bool { return netip.AddrPortFrom(l.Addr, l.Port) == want }) {
				t.Errorf("the listeners %+v do not have the SSH server %v", f.Listeners, want)
			}
		})
	}
}
