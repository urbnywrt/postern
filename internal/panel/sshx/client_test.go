package sshx

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/urbnywrt/postern/internal/panel/sshx/sshxtest"
)

// waitTimeout bounds every wait of these tests, so that a regression is a
// failure and not a hang.
const waitTimeout = 10 * time.Second

// newPassword returns a made-up password, a new one for every test, so that no
// password is written in the source.
func newPassword() string { return rand.Text() }

// confirmed is the target of a server whose host key the admin has confirmed.
func confirmed(s *sshxtest.Server, user string) Target {
	return Target{Host: s.Host, Port: s.Port, User: user, HostKey: s.Fingerprint(), HostKeyType: s.HostKey().Type()}
}

// dial connects to s and fails the test if it cannot. The client is closed
// when the test ends.
func dial(t *testing.T, tgt Target, auth Auth) *Client {
	t.Helper()
	c, res, err := Dial(context.Background(), tgt, auth)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if res == nil || res.Fingerprint != tgt.HostKey || res.FirstContact {
		t.Fatalf("Dial: host key result = %+v, want the confirmed key and no first contact", res)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// shellServer is a server that runs commands with a real sh and accepts a
// password.
func shellServer(t *testing.T, sudo sshxtest.SudoMode, opts ...sshxtest.ShellOption) (*sshxtest.Server, Auth) {
	t.Helper()
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: sshxtest.Shell(t, sudo, opts...)})
	return s, Auth{Password: pw}
}

// shells are the sh of the commands that the tests of the command form run
// with: dash, and bash in its POSIX mode.
var shells = []struct {
	name string
	opts []sshxtest.ShellOption
}{
	{"dash", nil},
	{"bash", []sshxtest.ShellOption{sshxtest.WithBash()}},
}

// run runs cmd and returns its exit code and its output.
func run(t *testing.T, c *Client, cmd string, stdin io.Reader) (int, string) {
	t.Helper()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	code, err := c.Run(ctx, cmd, stdin, &out)
	if err != nil {
		t.Fatalf("Run(%q): %v (output %q)", cmd, err, out.String())
	}
	return code, out.String()
}

// --- host keys ---

// The first contact with a server only learns its host key: the connection is
// closed before authentication, so the credentials never reach a server that
// the admin has not confirmed.
func TestFirstContactReturnsTheKeyAndSendsNoCredentials(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw})
	tgt := Target{Host: s.Host, Port: s.Port, User: "root"}

	c, res, err := Dial(context.Background(), tgt, Auth{Password: pw})
	if !errors.Is(err, ErrHostKeyUnconfirmed) {
		t.Fatalf("Dial with no host key: err = %v, want ErrHostKeyUnconfirmed", err)
	}
	if c != nil {
		t.Error("Dial returned a client for an unconfirmed host")
	}
	want := HostKeyResult{Fingerprint: s.Fingerprint(), KeyType: ssh.KeyAlgoED25519, FirstContact: true}
	if res == nil || *res != want {
		t.Fatalf("host key result = %+v, want %+v", res, want)
	}
	if !strings.HasPrefix(res.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint %q is not in the form of ssh-keygen -l", res.Fingerprint)
	}
	if got := s.AuthAttempts(); len(got) != 0 {
		t.Errorf("the server saw authentication attempts %+v, want none", got)
	}
	if got := s.Commands(); len(got) != 0 {
		t.Errorf("the server ran %q", got)
	}
}

// The first contact needs no credentials at all.
func TestFirstContactWithoutCredentials(t *testing.T) {
	s := sshxtest.Start(t, sshxtest.Config{Password: newPassword()})
	_, res, err := Dial(context.Background(), Target{Host: s.Host, Port: s.Port, User: "root"}, Auth{})
	if !errors.Is(err, ErrHostKeyUnconfirmed) || res == nil || res.Fingerprint != s.Fingerprint() {
		t.Fatalf("Dial = %+v, %v; want the fingerprint and ErrHostKeyUnconfirmed", res, err)
	}
}

func TestConfirmedHostKey(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c, res, err := Dial(context.Background(), confirmed(s, "root"), auth)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	want := HostKeyResult{Fingerprint: s.Fingerprint(), KeyType: ssh.KeyAlgoED25519}
	if *res != want {
		t.Errorf("host key result = %+v, want %+v", *res, want)
	}
	if code, out := run(t, c, "echo hello", nil); code != 0 || out != "hello\n" {
		t.Errorf("Run = %d, %q; want 0, hello", code, out)
	}
}

// A key that is not the confirmed one is refused, with both fingerprints, and
// the credentials are not sent.
func TestChangedHostKeyIsRefused(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw})
	old := ssh.FingerprintSHA256(sshxtest.NewEd25519Key(t).PublicKey())
	tgt := Target{Host: s.Host, Port: s.Port, User: "root", HostKey: old, HostKeyType: ssh.KeyAlgoED25519}

	c, res, err := Dial(context.Background(), tgt, Auth{Password: pw})
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("Dial: err = %v, want ErrHostKeyChanged", err)
	}
	if c != nil {
		t.Error("Dial returned a client for a changed host key")
	}
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) || changed.Want != old || changed.Got != s.Fingerprint() {
		t.Fatalf("err = %#v, want a HostKeyChangedError from %s to %s", err, old, s.Fingerprint())
	}
	if msg := err.Error(); !strings.Contains(msg, old) || !strings.Contains(msg, s.Fingerprint()) {
		t.Errorf("the error %q does not show both fingerprints", msg)
	}
	if res == nil || res.Fingerprint != s.Fingerprint() || res.FirstContact {
		t.Errorf("host key result = %+v, want the new fingerprint", res)
	}
	if got := s.AuthAttempts(); len(got) != 0 {
		t.Errorf("the server saw authentication attempts %+v, want none", got)
	}
}

// A server can have keys of several types. Once a key is confirmed, only its
// type is negotiated, so the server presents that key and not another one
// that the client happens to prefer.
func TestConfirmedKeyTypeIsTheOneNegotiated(t *testing.T) {
	edKey, ecKey := sshxtest.NewEd25519Key(t), sshxtest.NewECDSAKey(t)
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, HostKeys: []ssh.Signer{ecKey, edKey}})
	edFP, ecFP := ssh.FingerprintSHA256(edKey.PublicKey()), ssh.FingerprintSHA256(ecKey.PublicKey())

	// The first contact prefers Ed25519, as OpenSSH does.
	_, res, err := Dial(context.Background(), Target{Host: s.Host, Port: s.Port, User: "root"}, Auth{})
	if !errors.Is(err, ErrHostKeyUnconfirmed) || res == nil || res.Fingerprint != edFP || res.KeyType != ssh.KeyAlgoED25519 {
		t.Fatalf("first contact = %+v, %v; want the Ed25519 key %s", res, err, edFP)
	}

	// An admin who confirmed the ECDSA key gets the ECDSA key.
	tgt := Target{Host: s.Host, Port: s.Port, User: "root", HostKey: ecFP, HostKeyType: ssh.KeyAlgoECDSA256}
	c, res, err := Dial(context.Background(), tgt, Auth{Password: pw})
	if err != nil {
		t.Fatalf("Dial with the confirmed ECDSA key: %v", err)
	}
	_ = c.Close()
	if res.Fingerprint != ecFP || res.KeyType != ssh.KeyAlgoECDSA256 {
		t.Errorf("host key result = %+v, want the ECDSA key", res)
	}

	// Without the type, the server presents the key that the client prefers,
	// which is not the confirmed one.
	tgt.HostKeyType = ""
	if _, _, err := Dial(context.Background(), tgt, Auth{Password: pw}); !errors.Is(err, ErrHostKeyChanged) {
		t.Errorf("Dial without the key type: err = %v, want ErrHostKeyChanged", err)
	}
}

// A server that no longer has a key of the confirmed type has changed its host
// key as well.
func TestConfirmedKeyTypeNoLongerOffered(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw}) // Ed25519 only
	gone := ssh.FingerprintSHA256(sshxtest.NewECDSAKey(t).PublicKey())
	tgt := Target{Host: s.Host, Port: s.Port, User: "root", HostKey: gone, HostKeyType: ssh.KeyAlgoECDSA256}

	_, _, err := Dial(context.Background(), tgt, Auth{Password: pw})
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("Dial: err = %v, want ErrHostKeyChanged", err)
	}
	if !strings.Contains(err.Error(), gone) || !strings.Contains(err.Error(), ssh.KeyAlgoECDSA256) {
		t.Errorf("the error %q does not name the confirmed key and its type", err)
	}
	if got := s.AuthAttempts(); len(got) != 0 {
		t.Errorf("the server saw authentication attempts %+v, want none", got)
	}
}

func TestRSAHostKey(t *testing.T) {
	pw := newPassword()
	key := sshxtest.NewRSAKey(t)
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, HostKeys: []ssh.Signer{key}})

	_, res, err := Dial(context.Background(), Target{Host: s.Host, Port: s.Port, User: "root"}, Auth{})
	if !errors.Is(err, ErrHostKeyUnconfirmed) || res == nil || res.KeyType != ssh.KeyAlgoRSA || res.Fingerprint != s.Fingerprint() {
		t.Fatalf("first contact = %+v, %v; want the RSA key", res, err)
	}
	c, res, err := Dial(context.Background(), confirmed(s, "root"), Auth{Password: pw})
	if err != nil {
		t.Fatalf("Dial with the confirmed RSA key: %v", err)
	}
	_ = c.Close()
	if res.KeyType != ssh.KeyAlgoRSA {
		t.Errorf("key type = %q, want %q", res.KeyType, ssh.KeyAlgoRSA)
	}
}

// Targets that cannot be right are refused before anything goes on the
// network.
func TestDialRefusesBadTargets(t *testing.T) {
	s := sshxtest.Start(t, sshxtest.Config{Password: newPassword()})
	good := confirmed(s, "root")
	auth := Auth{Password: newPassword()}
	for _, c := range []struct {
		name string
		edit func(*Target)
	}{
		{"no host", func(t *Target) { t.Host = "" }},
		{"negative port", func(t *Target) { t.Port = -1 }},
		{"port too high", func(t *Target) { t.Port = 65536 }},
		{"no user", func(t *Target) { t.User = "" }},
		{"a key type without a key", func(t *Target) { t.HostKey = "" }},
		{"a fingerprint that is not SHA-256", func(t *Target) { t.HostKey = "MD5:00:11" }},
		{"a key type that is not supported", func(t *Target) { t.HostKeyType = "ssh-dss" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			tgt := good
			c.edit(&tgt)
			if cl, _, err := Dial(context.Background(), tgt, auth); err == nil {
				_ = cl.Close()
				t.Fatal("Dial succeeded")
			}
		})
	}
	if n := s.Connections(); n != 0 {
		t.Errorf("the server saw %d connections, want none", n)
	}
}

func TestDialToAClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	_, res, err := Dial(context.Background(), Target{Host: "127.0.0.1", Port: port, User: "root"}, Auth{})
	if err == nil || errors.Is(err, ErrHostKeyUnconfirmed) || res != nil {
		t.Errorf("Dial to a closed port = %+v, %v; want a connection error", res, err)
	}
}

// --- authentication ---

func TestPasswordAuth(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	if code, _ := run(t, c, "true", nil); code != 0 {
		t.Errorf("exit code %d", code)
	}
	attempts := s.AuthAttempts()
	if len(attempts) == 0 || !attempts[len(attempts)-1].OK || attempts[len(attempts)-1].Method != "password" {
		t.Errorf("auth attempts = %+v, want a successful password", attempts)
	}
}

func TestWrongPassword(t *testing.T) {
	s := sshxtest.Start(t, sshxtest.Config{Password: newPassword()})
	wrong := newPassword()
	c, res, err := Dial(context.Background(), confirmed(s, "root"), Auth{Password: wrong})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("Dial with a wrong password: err = %v, want ErrAuth", err)
	}
	if c != nil {
		t.Error("Dial returned a client")
	}
	if res == nil || res.Fingerprint != s.Fingerprint() {
		t.Errorf("host key result = %+v, want the confirmed key", res)
	}
	if strings.Contains(err.Error(), wrong) {
		t.Error("the error shows the password")
	}
}

// Servers with PAM often take the password through keyboard-interactive
// authentication only.
func TestKeyboardInteractivePassword(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, KeyboardInteractive: true})
	c := dial(t, confirmed(s, "root"), Auth{Password: pw})
	if code, _ := run(t, c, "true", nil); code != 0 {
		t.Errorf("exit code %d", code)
	}
	if _, _, err := Dial(context.Background(), confirmed(s, "root"), Auth{Password: newPassword()}); !errors.Is(err, ErrAuth) {
		t.Errorf("a wrong password through keyboard-interactive: err = %v, want ErrAuth", err)
	}
}

// A server that wants a second factor, such as a one-time code, does not get
// the password for it: the password answers one question, and only before
// anything has partly succeeded.
func TestNoPasswordForASecondFactor(t *testing.T) {
	key, pub := sshxtest.NewClientKey(t, "")
	for _, c := range []struct {
		name string
		cfg  sshxtest.Config
		auth Auth
	}{
		{"code after the password, in one conversation",
			sshxtest.Config{KeyboardInteractive: true, SecondFactor: true}, Auth{}},
		{"code after the password, in a step of its own",
			sshxtest.Config{SecondFactor: true}, Auth{}},
		{"code after the key",
			sshxtest.Config{AuthorizedKeys: []ssh.PublicKey{pub}, SecondFactor: true}, Auth{PrivateKeyPEM: key}},
	} {
		t.Run(c.name, func(t *testing.T) {
			pw := newPassword()
			c.cfg.Password, c.auth.Password = pw, pw
			s := sshxtest.Start(t, c.cfg)
			cl, _, err := Dial(context.Background(), confirmed(s, "root"), c.auth)
			if err == nil {
				_ = cl.Close()
				t.Fatal("Dial succeeded without the second factor")
			}
			if !errors.Is(err, ErrAuth) {
				t.Errorf("Dial: err = %v, want ErrAuth", err)
			}
			if got := s.Answers(); len(got) != 0 {
				t.Errorf("the client answered the question for the code (%d answers)", len(got))
			}
		})
	}
}

func TestPrivateKeyAuth(t *testing.T) {
	plain, plainPub := sshxtest.NewClientKey(t, "")
	passphrase := newPassword()
	locked, lockedPub := sshxtest.NewClientKey(t, passphrase)
	other, _ := sshxtest.NewClientKey(t, "")
	s := sshxtest.Start(t, sshxtest.Config{AuthorizedKeys: []ssh.PublicKey{plainPub, lockedPub}})
	tgt := confirmed(s, "root")

	for _, c := range []struct {
		name    string
		auth    Auth
		wantErr error // nil: success; errAny: some error
	}{
		{"a key", Auth{PrivateKeyPEM: plain}, nil},
		{"a key with its passphrase", Auth{PrivateKeyPEM: locked, Passphrase: passphrase}, nil},
		{"a key that does not need the passphrase given", Auth{PrivateKeyPEM: plain, Passphrase: passphrase}, nil},
		{"a key that the server does not know", Auth{PrivateKeyPEM: other}, ErrAuth},
		{"a key without its passphrase", Auth{PrivateKeyPEM: locked}, ErrKeyPassphrase},
		{"a key with a wrong passphrase", Auth{PrivateKeyPEM: locked, Passphrase: newPassword()}, ErrKeyPassphrase},
		{"something that is not a key", Auth{PrivateKeyPEM: []byte("not a key")}, errAny},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl, _, err := Dial(context.Background(), tgt, c.auth)
			switch {
			case c.wantErr == nil:
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
				_ = cl.Close()
			case err == nil:
				_ = cl.Close()
				t.Fatalf("Dial succeeded, want %v", c.wantErr)
			case c.wantErr != errAny && !errors.Is(err, c.wantErr):
				t.Fatalf("Dial: err = %v, want %v", err, c.wantErr)
			}
			if err != nil && c.auth.Passphrase != "" && strings.Contains(err.Error(), c.auth.Passphrase) {
				t.Error("the error shows the passphrase")
			}
		})
	}
}

// errAny stands for "some error" in a table of wanted errors.
var errAny = errors.New("any error")

// A key that cannot be read, or no credentials at all, are found before the
// connection is made.
func TestCredentialErrorsComeFirst(t *testing.T) {
	locked, lockedPub := sshxtest.NewClientKey(t, newPassword())
	s := sshxtest.Start(t, sshxtest.Config{AuthorizedKeys: []ssh.PublicKey{lockedPub}})
	for _, auth := range []Auth{{}, {PrivateKeyPEM: locked}, {PrivateKeyPEM: []byte("not a key")}} {
		if c, _, err := Dial(context.Background(), confirmed(s, "root"), auth); err == nil {
			_ = c.Close()
			t.Errorf("Dial with %d bytes of key succeeded", len(auth.PrivateKeyPEM))
		}
	}
	if n := s.Connections(); n != 0 {
		t.Errorf("the server saw %d connections, want none", n)
	}
}

// --- commands ---

func TestRunExitCodesAndOutput(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	for _, tc := range []struct {
		cmd      string
		wantCode int
		wantOut  string
	}{
		{"true", 0, ""},
		{"echo out", 0, "out\n"},
		{"echo failing >&2; exit 3", 3, "failing\n"},
		{"exit 255", 255, ""},
	} {
		code, out := run(t, c, tc.cmd, nil)
		if code != tc.wantCode || out != tc.wantOut {
			t.Errorf("Run(%q) = %d, %q; want %d, %q", tc.cmd, code, out, tc.wantCode, tc.wantOut)
		}
	}
	// A shell reports a signal as 128 and its number. (The login shell may
	// say "Terminated" as well, as it does here.)
	if code, _ := run(t, c, "kill -TERM $$", nil); code != 128+15 {
		t.Errorf("Run(kill -TERM $$) = %d, want %d", code, 128+15)
	}
	// Both streams go to the one writer. They travel apart, so their order is
	// not kept.
	_, out := run(t, c, "echo out; echo err >&2", nil)
	if out != "out\nerr\n" && out != "err\nout\n" {
		t.Errorf("output of both streams = %q, want both lines", out)
	}
}

// RunOutputs keeps the output and the error output of a command apart, as root
// and through sudo, so that what a command prints is not mixed with the
// warnings of sudo or of the command.
func TestRunOutputsKeepsTheStreamsApart(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	for _, user := range []string{"root", "deploy"} {
		c := dial(t, confirmed(s, user), auth)
		var stdout, stderr bytes.Buffer
		code, err := c.RunOutputs(context.Background(), "echo out; echo err >&2; echo more; exit 2", nil, &stdout, &stderr)
		if err != nil || code != 2 {
			t.Fatalf("%s: RunOutputs = %d, %v", user, code, err)
		}
		if stdout.String() != "out\nmore\n" || stderr.String() != "err\n" {
			t.Errorf("%s: stdout %q, stderr %q; want them apart", user, stdout.String(), stderr.String())
		}
		// Either writer may be nil.
		stdout.Reset()
		if code, err := c.RunOutputs(context.Background(), "echo out; echo err >&2", nil, &stdout, nil); err != nil || code != 0 || stdout.String() != "out\n" {
			t.Errorf("%s: RunOutputs without stderr = %d, %v, %q", user, code, err, stdout.String())
		}
	}

	// A refusal of sudo is still found on the error output.
	refusing, auth := shellServer(t, sshxtest.SudoNeedsPassword)
	c := dial(t, confirmed(refusing, "deploy"), auth)
	var stdout, stderr bytes.Buffer
	if _, err := c.RunOutputs(context.Background(), "echo out", nil, &stdout, &stderr); !errors.Is(err, ErrSudoPassword) {
		t.Errorf("RunOutputs with sudo that wants a password: %v, want ErrSudoPassword", err)
	}
}

func TestRunStdin(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	in := strings.Repeat("a line of input\n", 10000)
	if code, out := run(t, c, "cat", strings.NewReader(in)); code != 0 || out != in {
		t.Errorf("Run(cat) = %d, %d bytes; want 0 and the %d bytes of input", code, len(out), len(in))
	}
	// Without input the command reads the end of it at once.
	if code, out := run(t, c, "wc -c", nil); code != 0 || strings.TrimSpace(out) != "0" {
		t.Errorf("Run(wc -c) without input = %d, %q; want 0, 0", code, out)
	}
}

func TestRunWithoutOutputWriter(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	code, err := c.Run(context.Background(), "echo ignored; exit 4", nil, nil)
	if err != nil || code != 4 {
		t.Errorf("Run with a nil writer = %d, %v; want 4, nil", code, err)
	}
}

func TestRunWithoutExitStatus(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: func(context.Context, *sshxtest.Exec) int {
		return sshxtest.NoExitStatus
	}})
	c := dial(t, confirmed(s, "root"), Auth{Password: pw})
	if code, err := c.Run(context.Background(), "anything", nil, io.Discard); err == nil {
		t.Errorf("Run = %d, nil; want an error for a command without an exit status", code)
	}
}

// trickyCommand is a command with everything that shells read differently:
// quotes of both kinds, a variable in single quotes, a backslash, a line end,
// a glob and a '!'. wantTricky is what it prints.
const (
	trickyCommand = `printf '%s|' "it's" 'a "quoted" word' '$HOME' "back\\slash" 'two
lines' '*' 'bang!'; echo`
	wantTricky = `it's|a "quoted" word|$HOME|back\slash|two` + "\n" + `lines|*|bang!|` + "\n"
)

// sent is the command line that sshx sends for a script, built here from the
// form that sshxtest documents.
func sent(script string) string {
	return "exec sh -c '" + sshxtest.TransportScript + "' sh '" + base64.StdEncoding.EncodeToString([]byte(script)) + "'"
}

// The forms that sshxtest decodes are those of sshx.
func TestTestServerKnowsTheForms(t *testing.T) {
	if sshxtest.TransportScript != transportScript || sshxtest.SudoPrefix != sudoPrefix || sshxtest.SudoCheck != sudoCheck {
		t.Errorf("sshxtest has %q, %q, %q; sshx has %q, %q, %q", sshxtest.TransportScript, sshxtest.SudoPrefix,
			sshxtest.SudoCheck, transportScript, sudoPrefix, sudoCheck)
	}
}

// Every command goes to the login shell in one form, whatever the user: sh in
// its place, with the command in base64 as an argument. root runs the command
// as it is. Any other user runs it through "LC_ALL=C exec sudo -n", after one
// check that sudo works without a password, and the command means the same.
func TestCommandForm(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	root := dial(t, confirmed(s, "root"), auth)
	deploy := dial(t, confirmed(s, "deploy"), auth)

	if code, got := run(t, root, trickyCommand, nil); code != 0 || got != wantTricky {
		t.Fatalf("as root: %d, %q; want 0, %q", code, got, wantTricky)
	}
	if code, got := run(t, deploy, trickyCommand, nil); code != 0 || got != wantTricky {
		t.Errorf("through sudo: %d, %q; want 0, %q", code, got, wantTricky)
	}
	wantSent := []string{
		sent(trickyCommand),
		sent("LC_ALL=C sudo -n true"),
		sent("LC_ALL=C exec sudo -n -- sh -c -- '" + strings.ReplaceAll(trickyCommand, `'`, `'\''`) + "'"),
	}
	if got := s.Commands(); !slices.Equal(got, wantSent) {
		t.Errorf("command lines = %q, want %q", got, wantSent)
	}
	if got, want := s.Scripts(), []string{trickyCommand, sshxtest.SudoCheck, "sudo: " + trickyCommand}; !slices.Equal(got, want) {
		t.Errorf("scripts = %q, want %q", got, want)
	}
}

// A login shell that is not sh, such as fish or csh, reads the command lines
// of sshx as sh would: they hold nothing but what every shell reads alike.
func TestForeignLoginShell(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: sshxtest.ForeignShell(t, sshxtest.SudoPasswordless)})
	for _, user := range []string{"root", "deploy"} {
		t.Run(user, func(t *testing.T) {
			c := dial(t, confirmed(s, user), Auth{Password: pw})
			if code, got := run(t, c, trickyCommand, nil); code != 0 || got != wantTricky {
				t.Errorf("tricky command: %d, %q; want 0, %q", code, got, wantTricky)
			}
			if code, _ := run(t, c, "exit 7", nil); code != 7 {
				t.Errorf("exit code %d, want 7", code)
			}
			path := filepath.Join(t.TempDir(), "file")
			data := randomBytes(10 << 10)
			if err := c.Upload(context.Background(), path, 0o640, bytes.NewReader(data)); err != nil {
				t.Fatalf("Upload: %v", err)
			}
			checkFile(t, path, data, 0o640)
		})
	}
}

// A command that is stopped gets SIGTERM in the process that runs it: the
// shell of a command of root, sudo for any other user, which passes it on.
// What the command would have done next does not happen.
func TestStoppedCommandDoesNotGoOn(t *testing.T) {
	for _, sh := range shells {
		for _, user := range []string{"root", "deploy"} {
			t.Run(sh.name+"/"+user, func(t *testing.T) {
				testStoppedCommandDoesNotGoOn(t, user, sh.opts)
			})
		}
	}
}

func testStoppedCommandDoesNotGoOn(t *testing.T, user string, opts []sshxtest.ShellOption) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless, opts...)
	c := dial(t, confirmed(s, user), auth)
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for range 2000 {
			if _, err := os.Stat(first); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	if _, err := c.Run(ctx, "touch "+first+"; sleep 1; touch "+second, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: err = %v, want Canceled", err)
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("the first step did not run, so the test shows nothing: %v", err)
	}
	time.Sleep(2 * time.Second) // the second step would have run by now
	if _, err := os.Stat(second); err == nil {
		t.Error("the second step ran after the command was stopped")
	}
	if !slices.Contains(s.Requests(), "signal TERM") {
		t.Errorf("requests = %q, want a TERM signal", s.Requests())
	}
}

// A server without base64 cannot decode commands: they fail with ErrNoBase64
// and do not run, instead of doing nothing and reporting success.
func TestServerWithoutBase64(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw,
		Handler: sshxtest.Shell(t, sshxtest.SudoPasswordless, sshxtest.WithoutBase64())})
	for _, user := range []string{"root", "deploy"} {
		c := dial(t, confirmed(s, user), Auth{Password: pw})
		code, err := c.Run(context.Background(), "exit 0", nil, nil)
		if !errors.Is(err, ErrNoBase64) || code != -1 {
			t.Errorf("%s: Run = %d, %v; want -1, ErrNoBase64", user, code, err)
		}
	}
}

// A login shell that traces what it runs puts the command line on the error
// output. A command that ends with 127 by itself is not taken for a server
// without base64 for that: the sentence that says so is only whole when the
// transport says it.
func TestTracingLoginShell(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless, sshxtest.WithTrace())
	for _, user := range []string{"root", "deploy"} {
		c := dial(t, confirmed(s, user), auth)
		if code, err := c.Run(context.Background(), "exit 127", nil, io.Discard); err != nil || code != 127 {
			t.Errorf("%s: Run = %d, %v; want 127, nil", user, code, err)
		}
	}
}

// A command that starts with - or + is a command, not options of sh.
func TestCommandThatStartsLikeAnOption(t *testing.T) {
	for _, sh := range shells {
		t.Run(sh.name, func(t *testing.T) {
			s, auth := shellServer(t, sshxtest.SudoPasswordless, sh.opts...)
			for _, user := range []string{"root", "deploy"} {
				c := dial(t, confirmed(s, user), auth)
				for _, cmd := range []string{"-x 2>/dev/null || echo ok", "+x 2>/dev/null || echo ok"} {
					if code, out := run(t, c, cmd, nil); code != 0 || out != "ok\n" {
						t.Errorf("%s: Run(%q) = %d, %q; want 0, ok", user, cmd, code, out)
					}
				}
			}
		})
	}
}

// A command has no arguments, for root as for anyone else: $0 is sh, $# is 0.
// It keeps the line ends at its end, which a here-document needs.
func TestCommandsHaveNoArguments(t *testing.T) {
	for _, sh := range shells {
		t.Run(sh.name, func(t *testing.T) {
			s, auth := shellServer(t, sshxtest.SudoPasswordless, sh.opts...)
			for _, user := range []string{"root", "deploy"} {
				c := dial(t, confirmed(s, user), auth)
				if code, out := run(t, c, `printf '%s|%s|%s\n' "$#" "$0" "$*"`, nil); code != 0 || out != "0|sh|\n" {
					t.Errorf("%s: %d, %q; want 0, %q", user, code, out, "0|sh|\n")
				}
				if code, out := run(t, c, "cat <<END\nhere\nEND\n", nil); code != 0 || out != "here\n" {
					t.Errorf("%s: here-document: %d, %q; want 0, %q", user, code, out, "here\n")
				}
			}
		})
	}
}

// A command line longer than Linux takes in one argument, which is how sshd
// hands it to the login shell, is refused before a session is opened.
func TestCommandLineLimit(t *testing.T) {
	if MaxCommandLine != 131071 {
		t.Errorf("MaxCommandLine = %d, want 131071", MaxCommandLine)
	}
	// lineLen is the length of the command line for a script of n bytes.
	lineLen := func(n int) int {
		return len("exec sh -c '") + len(sshxtest.TransportScript) + len("' sh '") + base64.StdEncoding.EncodedLen(n) + len("'")
	}
	// longestScript is the length of the longest script whose line fits.
	longestScript := func() int {
		n := 0
		for lineLen(n+1) <= 131071 {
			n++
		}
		return n
	}()
	// The numbers that the documentation of MaxCommandLine gives.
	if lineLen(0) != wantLineForm || longestScript != wantLongestScript || len(sudoPrefix) != wantSudoPrefix {
		t.Errorf("a line is %d bytes and the script, which is up to %d bytes, and the sudo prefix is %d bytes; "+
			"the documentation says %d, %d and %d", lineLen(0), longestScript, len(sudoPrefix),
			wantLineForm, wantLongestScript, wantSudoPrefix)
	}
	comment := func(n int) string { return "#" + strings.Repeat("x", n-1) } // a comment: nothing to run

	s, auth := recordingServer(t)
	for _, user := range []string{"root", "deploy"} {
		t.Run(user, func(t *testing.T) {
			c := dial(t, confirmed(s, user), auth)
			// The longest command: the script is the command itself for root,
			// and for anyone else the sudo prefix and the command in quotes.
			around := 0
			if user != "root" {
				around = len(sshxtest.SudoPrefix) + len("''")
			}
			longest := longestScript - around

			if code, err := c.Run(context.Background(), comment(longest), nil, nil); err != nil || code != 0 {
				t.Fatalf("Run with the longest command: %d, %v", code, err)
			}
			got := s.Commands()
			if len(got) == 0 {
				t.Fatal("nothing was sent")
			}
			if n := len(got[len(got)-1]); n != lineLen(longest+around) || n > MaxCommandLine {
				t.Fatalf("sent a line of %d bytes, want %d", n, lineLen(longest+around))
			}
			sessions := s.Sessions()
			_, err := c.Run(context.Background(), comment(longest+1), nil, nil)
			if !errors.Is(err, ErrCommandTooLong) || !strings.Contains(err.Error(), "131071") {
				t.Errorf("Run with a command one byte longer: err = %v, want ErrCommandTooLong naming the limit", err)
			}
			if s.Sessions() != sessions {
				t.Errorf("%d sessions were opened for a line that is too long", s.Sessions()-sessions)
			}
		})
	}
}

// The numbers that the documentation of MaxCommandLine gives (see there).
const (
	wantLineForm      = 166
	wantLongestScript = 98178
	wantSudoPrefix    = 34
)

// An upload that fails because the server has no base64, or because sudo
// refuses, says what the server said once: the error of Run has it already.
func TestUploadErrorSaysItOnce(t *testing.T) {
	t.Run("no base64", func(t *testing.T) {
		pw := newPassword()
		s := sshxtest.Start(t, sshxtest.Config{Password: pw,
			Handler: sshxtest.Shell(t, sshxtest.SudoPasswordless, sshxtest.WithoutBase64())})
		c := dial(t, confirmed(s, "root"), Auth{Password: pw})
		err := c.Upload(context.Background(), "/tmp/postern-test/file", 0o600, strings.NewReader("x"))
		if !errors.Is(err, ErrNoBase64) {
			t.Fatalf("Upload: err = %v, want ErrNoBase64", err)
		}
		if n := strings.Count(err.Error(), "the server said"); n != 1 {
			t.Errorf("the error says what the server said %d times: %q", n, err)
		}
	})
	t.Run("sudo", func(t *testing.T) {
		pw := newPassword()
		s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: func(_ context.Context, e *sshxtest.Exec) int {
			if e.Script == sshxtest.SudoCheck {
				return 0
			}
			_, _ = io.WriteString(e.Stderr, "sudo: a password is required\n")
			return 1
		}})
		c := dial(t, confirmed(s, "deploy"), Auth{Password: pw})
		err := c.Upload(context.Background(), "/tmp/postern-test/file", 0o600, strings.NewReader("x"))
		if !errors.Is(err, ErrSudoPassword) {
			t.Fatalf("Upload: err = %v, want ErrSudoPassword", err)
		}
		if n := strings.Count(err.Error(), "a password is required"); n != 1 {
			t.Errorf("the error says what sudo said %d times: %q", n, err)
		}
	})
}

// What the server said goes into the error of an upload as plain text.
func TestUploadErrorIsPlainText(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: func(_ context.Context, e *sshxtest.Exec) int {
		_, _ = io.WriteString(e.Stderr, "\x1b[31mcannot\x07 create\r\nsecond line\n")
		return 1
	}})
	c := dial(t, confirmed(s, "root"), Auth{Password: pw})
	err := c.Upload(context.Background(), "/tmp/postern-test/file", 0o600, strings.NewReader("x"))
	if err == nil {
		t.Fatal("Upload succeeded")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\x1b\x07\r\n") || strings.Contains(msg, "[31m") ||
		!strings.Contains(msg, "cannot create") || !strings.Contains(msg, "second line") {
		t.Errorf("error = %q, want what the server said, as plain text", msg)
	}
}

// Commands of root do not go through sudo, and root is not checked.
func TestRootIsNotCheckedForSudo(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoNeedsPassword)
	root := dial(t, confirmed(s, "root"), auth)
	if code, _ := run(t, root, "true", nil); code != 0 {
		t.Errorf("root: exit code %d", code)
	}
	if got := s.Scripts(); !slices.Equal(got, []string{"true"}) {
		t.Errorf("scripts = %q, want only the command", got)
	}
}

// Sudo is checked once per client, before its first command, also when the
// first commands start together.
func TestSudoIsCheckedOnce(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	deploy := dial(t, confirmed(s, "deploy"), auth)
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Go(func() {
			if code, err := deploy.Run(context.Background(), fmt.Sprintf("exit %d", i), nil, io.Discard); err != nil || code != i {
				t.Errorf("Run %d = %d, %v", i, code, err)
			}
		})
	}
	wg.Wait()
	scripts := s.Scripts()
	if len(scripts) != 7 || scripts[0] != sshxtest.SudoCheck || slices.Contains(scripts[1:], sshxtest.SudoCheck) {
		t.Errorf("scripts = %q, want one check of sudo first, then the six commands", scripts)
	}
}

// However sudo refuses (in English, as sudo-rs does, in words that sshx does
// not know, or in another language), the user cannot run commands, and the
// error says what sudo said. The check finds it before the first command; a
// sudo that allows only some commands without a password is found when it
// refuses one of them.
func TestSudoRefusals(t *testing.T) {
	for _, c := range []struct {
		name    string
		mode    sshxtest.SudoMode
		said    string
		checked bool // found by the check, before any command
	}{
		{"sudo", sshxtest.SudoNeedsPassword, "sudo: a password is required", true},
		{"sudo-rs", sshxtest.SudoRsNeedsPassword, "sudo: interactive authentication is required", true},
		{"not in sudoers", sshxtest.SudoNotInSudoers, "deploy is not in the sudoers file.", true},
		{"another language", sshxtest.SudoLocalized, "sudo: требуется пароль", true},
		{"no password for true only", sshxtest.SudoPasswordlessForTrueOnly, "sudo: a password is required", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, auth := shellServer(t, c.mode)
			deploy := dial(t, confirmed(s, "deploy"), auth)
			for attempt := range 2 {
				code, err := deploy.Run(context.Background(), "id -u", nil, io.Discard)
				if !errors.Is(err, ErrSudoPassword) || code != -1 {
					t.Fatalf("Run #%d = %d, %v; want -1, ErrSudoPassword", attempt, code, err)
				}
				if msg := err.Error(); !strings.Contains(msg, "deploy") || !strings.Contains(msg, c.said) {
					t.Errorf("the error %q does not name the user and say %q", msg, c.said)
				}
			}
			// A refusal of the check is kept: sudo is not asked again.
			want := []string{sshxtest.SudoCheck}
			if !c.checked {
				want = append(want, "sudo: id -u", "sudo: id -u")
			}
			if got := s.Scripts(); !slices.Equal(got, want) {
				t.Errorf("scripts = %q, want %q", got, want)
			}
		})
	}
}

// A sudo that passed the check may still refuse a command, as it does for a
// user with NOPASSWD for some commands only. Both English complaints, that of
// sudo and that of sudo-rs, are recognized; LC_ALL=C makes sudo use them.
func TestSudoRefusesACommandLater(t *testing.T) {
	for _, said := range []string{"sudo: a password is required", "sudo: interactive authentication is required"} {
		t.Run(said, func(t *testing.T) {
			pw := newPassword()
			s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: func(_ context.Context, e *sshxtest.Exec) int {
				if e.Script == sshxtest.SudoCheck {
					return 0
				}
				_, _ = io.WriteString(e.Stderr, said+"\n")
				return 1
			}})
			deploy := dial(t, confirmed(s, "deploy"), Auth{Password: pw})
			code, err := deploy.Run(context.Background(), "id -u", nil, io.Discard)
			if !errors.Is(err, ErrSudoPassword) || code != -1 || !strings.Contains(err.Error(), said) {
				t.Errorf("Run = %d, %v; want -1 and ErrSudoPassword saying %q", code, err, said)
			}
		})
	}
}

// A check of sudo that could not finish is tried again by the next command; it
// is not taken for a refusal.
func TestSudoCheckIsTriedAgain(t *testing.T) {
	pw := newPassword()
	var checks atomic.Int32
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: func(ctx context.Context, e *sshxtest.Exec) int {
		if e.Script == sshxtest.SudoCheck && checks.Add(1) == 1 {
			<-ctx.Done() // the first check hangs
			return sshxtest.NoExitStatus
		}
		return 0
	}})
	deploy := dial(t, confirmed(s, "deploy"), Auth{Password: pw})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := deploy.Run(ctx, "true", nil, nil); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrSudoPassword) {
		t.Fatalf("first Run: err = %v, want DeadlineExceeded", err)
	}
	if code, _ := run(t, deploy, "true", nil); code != 0 {
		t.Errorf("second Run: exit code %d", code)
	}
	if got, want := s.Scripts(), []string{sshxtest.SudoCheck, sshxtest.SudoCheck, "sudo: true"}; !slices.Equal(got, want) {
		t.Errorf("scripts = %q, want %q", got, want)
	}
}

// What sudo said reaches the error as one short line of plain text: its first
// line on the error output, without control characters, and not what the
// shell of the user printed on the output.
func TestSudoMessageIsCleanedUp(t *testing.T) {
	pw := newPassword()
	long := strings.Repeat("x", 1000)
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: func(_ context.Context, e *sshxtest.Exec) int {
		_, _ = io.WriteString(e.Stdout, "Welcome to the server\n")
		_, _ = io.WriteString(e.Stderr, "\n\x1b[31msudo: no\x07 way\r "+long+"\nsecond line\n")
		return 1
	}})
	deploy := dial(t, confirmed(s, "deploy"), Auth{Password: pw})
	_, err := deploy.Run(context.Background(), "true", nil, nil)
	if !errors.Is(err, ErrSudoPassword) {
		t.Fatalf("Run: err = %v, want ErrSudoPassword", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "sudo: no way") || strings.ContainsAny(msg, "\x1b\x07\r\n") || strings.Contains(msg, "[31m") ||
		strings.Contains(msg, "Welcome") || strings.Contains(msg, "second line") {
		t.Errorf("error = %q, want the first line of sudo, cleaned up", msg)
	}
	if len(msg) > 400 {
		t.Errorf("error of %d bytes, want it short", len(msg))
	}
}

// A command that fails with exit code 1 is not taken for sudo asking for a
// password, and neither is one that only prints the words.
func TestSudoPasswordIsNotGuessed(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	deploy := dial(t, confirmed(s, "deploy"), auth)
	for _, cmd := range []string{"exit 1", "echo 'sudo: a password is required' >&2; exit 2"} {
		code, err := deploy.Run(context.Background(), cmd, nil, io.Discard)
		if err != nil || code == 0 {
			t.Errorf("Run(%q) = %d, %v; want its own exit code and no error", cmd, code, err)
		}
	}
}

// blockingServer runs commands that write a line and then wait until the
// client goes, and tells when one has started.
func blockingServer(t *testing.T) (*sshxtest.Server, Auth, <-chan struct{}) {
	t.Helper()
	pw := newPassword()
	started := make(chan struct{}, 16)
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: func(ctx context.Context, e *sshxtest.Exec) int {
		_, _ = io.WriteString(e.Stdout, "working\n")
		started <- struct{}{}
		<-ctx.Done()
		return sshxtest.NoExitStatus
	}})
	return s, Auth{Password: pw}, started
}

func TestRunTimeout(t *testing.T) {
	s, auth, _ := blockingServer(t)
	c := dial(t, confirmed(s, "root"), auth)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	begin := time.Now()
	var out bytes.Buffer
	_, err := c.Run(ctx, "sleep forever", nil, &out)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run: err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(begin); d > 5*time.Second {
		t.Errorf("Run returned after %v", d)
	}
	waitFor(t, "the signal", func() bool { return slices.Contains(s.Requests(), "signal TERM") })
	// The client still works.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	if _, err := c.Run(ctx2, "again", nil, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("second Run: err = %v, want DeadlineExceeded", err)
	}
}

func TestRunCancel(t *testing.T) {
	s, auth, started := blockingServer(t)
	c := dial(t, confirmed(s, "root"), auth)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	if _, err := c.Run(ctx, "sleep forever", nil, io.Discard); !errors.Is(err, context.Canceled) {
		t.Errorf("Run: err = %v, want Canceled", err)
	}
}

// A command whose context has no deadline gets the default timeout.
func TestRunDefaultTimeout(t *testing.T) {
	defer setVar(&defaultCommandTimeout, 200*time.Millisecond)()
	s, auth, _ := blockingServer(t)
	c := dial(t, confirmed(s, "root"), auth)
	if _, err := c.Run(context.Background(), "sleep forever", nil, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run: err = %v, want DeadlineExceeded", err)
	}
}

// A command that has finished is not reported as stopped because its context
// ended at the same moment.
func TestFinishedCommandIsNotReportedAsStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 1000 {
		done := make(chan runResult, 1)
		done <- runResult{code: 3}
		if res, ok := awaitResult(ctx, done); !ok || res.code != 3 {
			t.Fatalf("awaitResult = %+v, %v; want the result that is there", res, ok)
		}
	}
}

// Once Run has returned, the output of the command does not reach the writer
// any more.
func TestNoOutputAfterRunReturns(t *testing.T) {
	pw := newPassword()
	s := sshxtest.Start(t, sshxtest.Config{Password: pw, Handler: func(ctx context.Context, e *sshxtest.Exec) int {
		for ctx.Err() == nil {
			if _, err := io.WriteString(e.Stdout, "more output\n"); err != nil {
				break
			}
		}
		return sshxtest.NoExitStatus
	}})
	c := dial(t, confirmed(s, "root"), Auth{Password: pw})
	w := &guardedWriter{t: t}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.Run(ctx, "yes", nil, w); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run: err = %v, want DeadlineExceeded", err)
	}
	w.close()
	time.Sleep(100 * time.Millisecond) // a late write would fail the test now
}

// guardedWriter fails the test when it is written to after close.
type guardedWriter struct {
	t      *testing.T
	mu     sync.Mutex
	closed bool
}

func (w *guardedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		w.t.Errorf("Write of %d bytes after Run returned", len(p))
	}
	return len(p), nil
}

func (w *guardedWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

// Commands of one client can run at the same time, each with its own input
// and output.
func TestConcurrentRuns(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "deploy"), auth)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			in := strings.Repeat(fmt.Sprintf("line %d\n", i), 1000)
			var out bytes.Buffer
			code, err := c.Run(context.Background(), fmt.Sprintf("cat; exit %d", i), strings.NewReader(in), &out)
			if err != nil || code != i || out.String() != in {
				t.Errorf("run %d = %d, %v, %d bytes; want %d and the %d bytes of input", i, code, err, out.Len(), i, len(in))
			}
		})
	}
	wg.Wait()
}

func TestRunAfterClose(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c, _, err := Dial(context.Background(), confirmed(s, "root"), auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.Run(context.Background(), "true", nil, nil); err == nil {
		t.Error("Run after Close succeeded")
	}
}

// The client asks for nothing but commands: no terminal, no agent, no
// forwarding, no SFTP.
func TestOnlyCommandsAreRequested(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "deploy"), auth)
	run(t, c, "true", nil)
	if err := c.Upload(context.Background(), filepath.Join(t.TempDir(), "file"), 0o600, strings.NewReader("x")); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("requests other than commands: %q", got)
	}
}

// stallingProxy forwards TCP between a client and a server until it is told to
// stall. Then it forwards nothing more, in either direction, and holds the
// connections open, as a network that has died does.
type stallingProxy struct {
	port    int
	stalled chan struct{}
	once    sync.Once
}

func newStallingProxy(t *testing.T, target string) *stallingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &stallingProxy{port: ln.Addr().(*net.TCPAddr).Port, stalled: make(chan struct{})}
	closed := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			select {
			case <-p.stalled:
				<-closed // stop reading: what was sent is lost
				return
			default:
			}
			if n > 0 {
				if _, err := dst.Write(buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			mu.Lock()
			conns = append(conns, c, s)
			mu.Unlock()
			wg.Add(2)
			go pipe(s, c)
			go pipe(c, s)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		close(closed)
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return p
}

func (p *stallingProxy) stall() { p.once.Do(func() { close(p.stalled) }) }

// When the network dies under a command, Run still returns in time: once the
// server has not answered for a while after the deadline, the connection is
// closed, and the other commands of the client fail at once instead of waiting
// for a server that is gone.
func TestRunWhenTheNetworkDies(t *testing.T) {
	defer setVar(&abandonAfter, 200*time.Millisecond)()
	s, auth, started := blockingServer(t)
	p := newStallingProxy(t, s.Addr())
	tgt := confirmed(s, "root")
	tgt.Port = p.port
	c := dial(t, tgt, auth)

	go func() {
		<-started
		p.stall()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	begin := time.Now()
	if _, err := c.Run(ctx, "sleep forever", nil, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run: err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("Run returned after %v", d)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel2()
	begin = time.Now()
	if _, err := c.Run(ctx2, "true", nil, nil); err == nil {
		t.Error("Run on the dead connection succeeded")
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("Run on the dead connection returned after %v", d)
	}
}

// A command cannot even start when the network is gone; Run returns in time
// all the same.
func TestRunBeforeTheNetworkDies(t *testing.T) {
	defer setVar(&abandonAfter, 200*time.Millisecond)()
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	p := newStallingProxy(t, s.Addr())
	tgt := confirmed(s, "root")
	tgt.Port = p.port
	c := dial(t, tgt, auth)
	p.stall()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	begin := time.Now()
	if _, err := c.Run(ctx, "true", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run: err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("Run returned after %v", d)
	}
}

// --- timeouts of the connection ---

// stalledListener accepts connections and never says a word.
func stalledListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func TestDialTimeoutFromContext(t *testing.T) {
	port := stalledListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, _, err := Dial(ctx, Target{Host: "127.0.0.1", Port: port, User: "root"}, Auth{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial: err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(begin); d > 5*time.Second {
		t.Errorf("Dial returned after %v", d)
	}
}

// Dial bounds the connection and the handshake by itself.
func TestDialTimeout(t *testing.T) {
	if DialTimeout != 15*time.Second {
		t.Errorf("DialTimeout = %v, want 15s", DialTimeout)
	}
	defer setVar(&dialTimeout, 200*time.Millisecond)()
	port := stalledListener(t)
	begin := time.Now()
	_, _, err := Dial(context.Background(), Target{Host: "127.0.0.1", Port: port, User: "root"}, Auth{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial: err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(begin); d > 5*time.Second {
		t.Errorf("Dial returned after %v", d)
	}
}

func TestDialCancel(t *testing.T) {
	port := stalledListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	if _, _, err := Dial(ctx, Target{Host: "127.0.0.1", Port: port, User: "root"}, Auth{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Dial: err = %v, want Canceled", err)
	}
}

// --- uploads ---

// randomBytes returns n bytes that no other test has.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// dirEntries lists the names in dir.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestUpload(t *testing.T) {
	for _, user := range []string{"root", "deploy"} {
		t.Run(user, func(t *testing.T) {
			s, auth := shellServer(t, sshxtest.SudoPasswordless)
			c := dial(t, confirmed(s, user), auth)
			dir := t.TempDir()
			path := filepath.Join(dir, "postern-node")

			data := randomBytes(300 << 10)
			if err := c.Upload(context.Background(), path, 0o751, bytes.NewReader(data)); err != nil {
				t.Fatalf("Upload: %v", err)
			}
			checkFile(t, path, data, 0o751)
			if got := dirEntries(t, dir); !slices.Equal(got, []string{"postern-node"}) {
				t.Errorf("the directory holds %q, want only the file", got)
			}

			// A second upload replaces the file, mode and all.
			data = randomBytes(1000)
			if err := c.Upload(context.Background(), path, 0o600, bytes.NewReader(data)); err != nil {
				t.Fatalf("second Upload: %v", err)
			}
			checkFile(t, path, data, 0o600)

			// An empty file is a file too.
			if err := c.Upload(context.Background(), path, 0o644, bytes.NewReader(nil)); err != nil {
				t.Fatalf("empty Upload: %v", err)
			}
			checkFile(t, path, nil, 0o644)
			if got := dirEntries(t, dir); !slices.Equal(got, []string{"postern-node"}) {
				t.Errorf("the directory holds %q, want only the file", got)
			}
		})
	}
}

func checkFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the uploaded file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("the uploaded file has %d bytes, want the %d that were sent", len(got), len(data))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != mode {
		t.Errorf("mode = %v, want %v", fi.Mode().Perm(), mode)
	}
}

// The file is written next to its place under a name of its own, with nobody
// else allowed to read it, and only then moved there.
func TestUploadCommands(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	path := filepath.Join(t.TempDir(), "bundle.tar")
	if err := c.Upload(context.Background(), path, 0o640, strings.NewReader("bundle")); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	cmds := s.Scripts()
	if len(cmds) != 2 {
		t.Fatalf("commands = %q, want two", cmds)
	}
	write, commit := cmds[0], cmds[1]
	prefix := "umask 077; cat > " + filepath.Dir(path) + "/.bundle.tar.tmp-"
	if !strings.HasPrefix(write, prefix) {
		t.Fatalf("first command %q, want it to start with %q", write, prefix)
	}
	tmp := strings.TrimPrefix(write, "umask 077; cat > ")
	for _, part := range []string{"wc -c < " + tmp, "-eq 6 ]", "[ ! -d " + path + " ]", "chmod 0640 " + tmp,
		"mv -f " + tmp + " " + path, "rm -f " + tmp} {
		if !strings.Contains(commit, part) {
			t.Errorf("second command %q does not contain %q", commit, part)
		}
	}
	// Two uploads to the same place do not share the name of the temporary file.
	if err := c.Upload(context.Background(), path, 0o640, strings.NewReader("bundle")); err != nil {
		t.Fatal(err)
	}
	if again := s.Scripts()[2]; again == write {
		t.Errorf("the temporary name %q was used twice", tmp)
	}
}

// recordingServer is a server that accepts a password and records commands
// without running any of them, for tests that send what must never run.
func recordingServer(t *testing.T) (*sshxtest.Server, Auth) {
	t.Helper()
	pw := newPassword()
	return sshxtest.Start(t, sshxtest.Config{Password: pw}), Auth{Password: pw}
}

// The paths hold shell syntax, harmless as it is: the server runs nothing, and
// the commands in them would do nothing if one ran.
func TestUploadRefusesBadPaths(t *testing.T) {
	s, auth := recordingServer(t)
	c := dial(t, confirmed(s, "root"), auth)
	for _, path := range []string{
		"",
		"relative/file",
		"/",
		"/tmp/postern-test/",
		"/tmp/../tmp/file",
		"/tmp/./file",
		"//tmp/file",
		"/tmp/a file",
		"/tmp/file;true",
		"/tmp/$(true)",
		"/tmp/`true`",
		"/tmp/file'quote",
		"/tmp/file\"quote",
		"/tmp/file\ntrue",
		"/tmp/file&",
		"/tmp/file|true",
		"/tmp/file>marker",
		"/tmp/~file",
		"/tmp/*",
		"/tmp/file\\x",
		"/tmp/" + strings.Repeat("x", 250),
	} {
		if err := c.Upload(context.Background(), path, 0o600, strings.NewReader("x")); err == nil {
			t.Errorf("Upload(%q) succeeded", path)
		}
	}
	if got := s.Commands(); len(got) != 0 {
		t.Errorf("commands were sent: %q", got)
	}
}

func TestUploadRefusesBadModes(t *testing.T) {
	s, auth := recordingServer(t)
	c := dial(t, confirmed(s, "root"), auth)
	path := filepath.Join(t.TempDir(), "file")
	for _, mode := range []os.FileMode{os.ModeSetuid | 0o755, os.ModeSticky | 0o755, os.ModeDir | 0o755} {
		if err := c.Upload(context.Background(), path, mode, strings.NewReader("x")); err == nil {
			t.Errorf("Upload with mode %v succeeded", mode)
		}
	}
	if err := c.Upload(context.Background(), path, 0o600, nil); err == nil {
		t.Error("Upload of a nil reader succeeded")
	}
	if got := s.Commands(); len(got) != 0 {
		t.Errorf("commands were sent: %q", got)
	}
}

func TestUploadToAMissingDirectory(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	path := filepath.Join(t.TempDir(), "missing", "file")
	err := c.Upload(context.Background(), path, 0o600, strings.NewReader("x"))
	if err == nil {
		t.Fatal("Upload into a directory that does not exist succeeded")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("the error %q does not show what the server said", err)
	}
}

// A directory in the place of the file is not replaced, and the file does not
// end up inside it.
func TestUploadOntoADirectory(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	dir := t.TempDir()
	path := filepath.Join(dir, "postern-install")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.Upload(context.Background(), path, 0o600, strings.NewReader("x")); err == nil {
		t.Fatal("Upload onto a directory succeeded")
	}
	if got := dirEntries(t, path); len(got) != 0 {
		t.Errorf("the directory holds %q now", got)
	}
	if got := dirEntries(t, dir); !slices.Equal(got, []string{"postern-install"}) {
		t.Errorf("next to the directory: %q", got)
	}
}

// failingReader gives some bytes and then fails, as a file on a broken disk
// would.
type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// When the data does not arrive whole, nothing is installed: the file that
// was there stays as it was, and the temporary file is removed.
func TestUploadThatDoesNotArriveWhole(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	dir := t.TempDir()
	path := filepath.Join(dir, "postern-node")
	old := []byte("the binary that works")
	if err := os.WriteFile(path, old, 0o755); err != nil {
		t.Fatal(err)
	}
	broken := errors.New("disk read error")
	err := c.Upload(context.Background(), path, 0o755, &failingReader{data: randomBytes(100 << 10), err: broken})
	if !errors.Is(err, broken) {
		t.Fatalf("Upload: err = %v, want the error of the reader", err)
	}
	checkFile(t, path, old, 0o755)
	waitFor(t, "the temporary file to go", func() bool {
		return slices.Equal(dirEntries(t, dir), []string{"postern-node"})
	})
}

func TestUploadTimeout(t *testing.T) {
	s, auth := shellServer(t, sshxtest.SudoPasswordless)
	c := dial(t, confirmed(s, "root"), auth)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// The reader never ends, so the upload cannot finish.
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	err := c.Upload(ctx, filepath.Join(dir, "file"), 0o600, pr)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Upload: err = %v, want DeadlineExceeded", err)
	}
	if got := dirEntries(t, dir); slices.Contains(got, "file") {
		t.Errorf("the file was installed: %q", got)
	}
}

// --- helpers ---

// setVar sets *p to v and returns a function that puts the old value back.
func setVar[T any](p *T, v T) func() {
	old := *p
	*p = v
	return func() { *p = old }
}

// waitFor polls cond until it holds and fails the test if it does not within
// waitTimeout.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
