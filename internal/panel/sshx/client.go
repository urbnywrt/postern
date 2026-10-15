// Package sshx is the SSH client of the panel, which installs nodes over SSH
// (spec §9). It runs commands and uploads files,
// as root or through passwordless sudo, and nothing else: it asks for no
// terminal, forwards no agent and no ports, and does not use SFTP.
//
// # Host keys
//
// The panel trusts a server only once an admin has confirmed its host key.
// [Dial] with a [Target] that has no host key performs the key exchange, which
// shows the key of the server, and closes the connection before the
// authentication: it returns [ErrHostKeyUnconfirmed] with the fingerprint to
// show to the admin, and the credentials do not leave the panel. With the
// confirmed fingerprint, a server that presents another key is refused with a
// [HostKeyChangedError], which shows both fingerprints. Once the type of the
// confirmed key is known, it is the only type that the client accepts, so a
// server with keys of several types keeps presenting the confirmed one.
//
// # Commands and uploads
//
// [Client.Run] runs a command with sh, whatever the login shell of the user,
// with its output and its error output in one writer; [Client.RunOutputs] keeps
// them apart. The login shell gets
//
//	exec sh -c 's=$(printf %s "$1" | base64 -d) || { echo "..." "..." >&2; exit 127; }; exec sh -c -- "$s"' sh '<the script in base64>'
//
// which holds nothing that any shell, sh, bash, zsh, fish or csh, reads in its
// own way. The login shell, then the sh that decodes the script, replace
// themselves with the sh that runs it, so the process of the session, which
// sshd signals, is the one that runs the script, without arguments. A server
// without base64 runs nothing and fails with [ErrNoBase64]; a command line is
// at most [MaxCommandLine] bytes.
//
// The script is the command itself for root. Any other user runs the command
// as "LC_ALL=C exec sudo -n -- sh -c -- '<command>'", in which sudo, too, takes
// the place of the shell, and fails at once instead of asking for a password;
// before the first command of a client, "LC_ALL=C sudo -n true" checks that
// sudo works without a password, and when it does not, commands fail with
// [ErrSudoPassword] and what sudo said, in whatever words and language. Every
// command has a timeout: the deadline of its context, or
// [DefaultCommandTimeout].
//
// [Client.Upload] writes a file through the input of a command: the data goes
// to a temporary file next to the target that nobody else can read (umask
// 077), and only when all of it has arrived does the file get its mode and
// replace the target. Remote paths are fixed by the code, never taken from an
// operator; a path with anything in it that a shell would interpret is
// refused rather than quoted.
//
// Nothing in this package logs, and no error holds a password, a private key
// or a passphrase.
package sshx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

const (
	// DialTimeout bounds the connection, the SSH handshake and the
	// authentication of [Dial].
	DialTimeout = 15 * time.Second

	// DefaultCommandTimeout bounds a command whose context has no deadline.
	// Long commands, such as an install, set a deadline of their own.
	DefaultCommandTimeout = 120 * time.Second

	// DefaultPort is the port of a [Target] whose port is 0.
	DefaultPort = 22
)

// The timings, which tests shorten.
var (
	dialTimeout           = DialTimeout
	defaultCommandTimeout = DefaultCommandTimeout

	// cleanupTimeout bounds the removal of the temporary file of an upload
	// that failed.
	cleanupTimeout = 10 * time.Second

	// abandonAfter is how long Run waits for the session of a command whose
	// context has ended to end as well. A server that has not answered by then
	// has lost the connection, and Run closes it.
	abandonAfter = 5 * time.Second
)

var (
	// ErrHostKeyUnconfirmed is returned by [Dial] for a [Target] without a
	// host key, with the fingerprint of the key that the server presented.
	ErrHostKeyUnconfirmed = errors.New("sshx: the host key of the server has not been confirmed")

	// ErrHostKeyChanged is what a [HostKeyChangedError] is.
	ErrHostKeyChanged = errors.New("sshx: the host key of the server has changed")

	// ErrAuth is returned by [Dial] when the server refuses the credentials,
	// and when it wants more than a password or a key, such as a one-time
	// code, which the panel does not have.
	ErrAuth = errors.New("sshx: the server refused the credentials")

	// ErrKeyPassphrase is returned by [Dial] for a private key that is
	// encrypted when no passphrase, or a wrong one, is given.
	ErrKeyPassphrase = errors.New("sshx: the private key is protected by a passphrase")

	// ErrSudoPassword is returned by [Client.Run] for a user other than root
	// whom sudo does not let run commands without a password, whatever the
	// reason: the user needs passwordless sudo (NOPASSWD), or the panel has to
	// connect as root. The error holds the first line of what sudo said.
	ErrSudoPassword = errors.New("sshx: sudo does not run commands without a password")

	// ErrNoBase64 is returned by [Client.Run] when the server cannot decode
	// the command, which travels in base64: base64 is missing there, or does
	// not work. The command has not run.
	ErrNoBase64 = errors.New("sshx: the server cannot decode commands: base64 is missing or does not work")

	// ErrCommandTooLong is returned by [Client.Run] for a command whose
	// command line would be longer than [MaxCommandLine]. Nothing is sent.
	ErrCommandTooLong = errors.New("sshx: the command line is too long")
)

// MaxCommandLine is the longest command line that a server takes. sshd hands
// it to the login shell as one argument, and Linux takes at most 131072 bytes
// in one argument, the zero byte that ends it included.
//
// The command line is 166 bytes and the script in base64, 4 bytes for every 3
// of it, rounded up: a script of up to 98178 bytes fits. The script is the
// command for root; for any other user it is the command quoted for sh, which
// adds 2 bytes and 3 for every single quote in the command, after a sudo
// prefix of 34 bytes.
const MaxCommandLine = 131071

// A Target is a server and the user to log in as.
type Target struct {
	Host string
	Port int // 0 means DefaultPort
	User string

	// HostKey is the fingerprint of the host key that an admin confirmed, as
	// ssh-keygen -l prints it ("SHA256:..."), or "" for the first contact.
	HostKey string

	// HostKeyType is the type of that key ([HostKeyResult.KeyType]), or "" if
	// it is not known. When it is known, it is the only type of key that the
	// server may present.
	HostKeyType string
}

// Auth is what the client logs in with: a password, a private key in PEM form
// (OpenSSH, PKCS#1, PKCS#8 or SEC 1), with its passphrase if it is encrypted, or
// both, in which case the key is tried first.
type Auth struct {
	Password      string
	PrivateKeyPEM []byte
	Passphrase    string
}

// HostKeyResult is the host key that a server presented.
type HostKeyResult struct {
	Fingerprint  string // "SHA256:...", as ssh-keygen -l prints it
	KeyType      string // for example "ssh-ed25519"
	FirstContact bool   // the target had no confirmed key
}

// A HostKeyChangedError is returned by [Dial] when a server does not present
// the confirmed host key. It is [ErrHostKeyChanged].
type HostKeyChangedError struct {
	Want, WantType string // the confirmed key and its type
	Got, GotType   string // the key that the server presented; "" when it offers no key of the confirmed type
}

func (e *HostKeyChangedError) Error() string {
	if e.Got == "" {
		return fmt.Sprintf("sshx: the host key of the server has changed: it no longer offers a key of type %s, the confirmed key was %s",
			e.WantType, e.Want)
	}
	return fmt.Sprintf("sshx: the host key of the server has changed: the confirmed key is %s, the server presented %s (%s)",
		e.Want, e.Got, e.GotType)
}

// Is reports whether target is [ErrHostKeyChanged].
func (e *HostKeyChangedError) Is(target error) bool { return target == ErrHostKeyChanged }

// firstContactAlgorithms are the host key algorithms of a first contact, in
// the order of preference of OpenSSH, which offers Ed25519 first. Certificates
// are left out, because the fingerprint of a certificate changes whenever it is
// renewed, and so are SHA-1 RSA signatures and DSA, which are weak.
var firstContactAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// hostKeyAlgorithms returns the host key algorithms to offer for a confirmed
// key of this type: the algorithms that sign with it, or all of
// firstContactAlgorithms when the type is not known.
func hostKeyAlgorithms(keyType string) ([]string, error) {
	switch keyType {
	case "":
		return slices.Clone(firstContactAlgorithms), nil
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return []string{keyType}, nil
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}, nil
	}
	return nil, fmt.Errorf("sshx: host keys of type %q are not supported", keyType)
}

func (t Target) check() error {
	switch {
	case t.Host == "":
		return errors.New("sshx: the target has no host")
	case t.Port < 0 || t.Port > 65535:
		return fmt.Errorf("sshx: port %d is out of range", t.Port)
	case t.User == "":
		return errors.New("sshx: the target has no user")
	case t.HostKey == "" && t.HostKeyType != "":
		return errors.New("sshx: the target has the type of a host key but no host key")
	case t.HostKey != "" && !strings.HasPrefix(t.HostKey, "SHA256:"):
		return errors.New("sshx: the host key of the target is not a SHA-256 fingerprint (SHA256:...)")
	}
	return nil
}

// A Client is a connection to a server, authenticated. It is safe for
// concurrent use: every command runs in a session of its own.
type Client struct {
	client *ssh.Client
	user   string
	sudo   bool // the user is not root, so commands go through sudo

	// The check of sudo, which runs once, before the first command of a user
	// other than root. sudoTurn holds a token while it runs; sudoErr, guarded
	// by it, is the refusal of sudo once there has been one.
	sudoOK   atomic.Bool
	sudoTurn chan struct{}
	sudoErr  error
}

// Dial connects to the server of t, checks its host key and logs in with a.
//
// For a target without a host key it returns no client, the key that the
// server presented, and [ErrHostKeyUnconfirmed]; the connection is closed
// before the authentication starts, and a is not used. For a key other than
// the confirmed one it returns no client, the key, and a [HostKeyChangedError].
// When the server refuses the credentials the error is [ErrAuth], and the
// HostKeyResult is the confirmed key.
//
// Dial takes at most [DialTimeout], or until ctx ends if that is sooner.
func Dial(ctx context.Context, t Target, a Auth) (*Client, *HostKeyResult, error) {
	if err := t.check(); err != nil {
		return nil, nil, err
	}
	algorithms, err := hostKeyAlgorithms(t.HostKeyType)
	if err != nil {
		return nil, nil, err
	}
	var methods []ssh.AuthMethod
	steps := &authSteps{}
	if t.HostKey != "" {
		// Credentials are only read for a server whose key is confirmed, and a
		// key that cannot be used fails here, before the connection.
		if methods, err = authMethods(a, steps); err != nil {
			return nil, nil, err
		}
	}
	port := t.Port
	if port == 0 {
		port = DefaultPort
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(port))

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, dialError(ctx, "connect to "+addr, err)
	}
	// The SSH handshake does not take a context. The deadline of the
	// connection bounds it, and the connection is closed if ctx ends first.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })

	check := &hostKeyCheck{want: t.HostKey}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              t.User,
		Auth:              methods,
		AuthCallback:      steps.observe,
		HostKeyCallback:   check.callback,
		HostKeyAlgorithms: algorithms,
	})
	if stopped := stop(); err == nil && !stopped {
		// ctx ended just now, and the connection is being closed.
		_ = sshConn.Close()
		err = ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		res := check.result()
		var negotiation *ssh.AlgorithmNegotiationError
		switch {
		case res != nil && res.FirstContact:
			return nil, res, ErrHostKeyUnconfirmed
		case res != nil && res.Fingerprint != t.HostKey:
			return nil, res, &HostKeyChangedError{Want: t.HostKey, WantType: t.HostKeyType, Got: res.Fingerprint, GotType: res.KeyType}
		case res == nil && t.HostKeyType != "" && errors.As(err, &negotiation) && negotiation.What == "host key":
			return nil, nil, &HostKeyChangedError{Want: t.HostKey, WantType: t.HostKeyType}
		case res != nil && isAuthFailure(err):
			return nil, res, fmt.Errorf("%w: user %s at %s: %w", ErrAuth, t.User, addr, err)
		}
		return nil, res, dialError(ctx, "SSH handshake with "+addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	c := &Client{client: ssh.NewClient(sshConn, chans, reqs), user: t.User, sudo: t.User != "root",
		sudoTurn: make(chan struct{}, 1)}
	return c, check.result(), nil
}

// dialError describes a failed connection or handshake. When it failed because
// ctx ended, it is the error of ctx.
func dialError(ctx context.Context, what string, err error) error {
	ctxErr := ctx.Err()
	if ctxErr == nil {
		// The deadline of the connection is that of ctx, and may pass a moment
		// before ctx says so.
		deadline, ok := ctx.Deadline()
		if errors.Is(err, os.ErrDeadlineExceeded) || (ok && !time.Now().Before(deadline)) {
			ctxErr = context.DeadlineExceeded
		}
	}
	if ctxErr != nil {
		return fmt.Errorf("sshx: %s: %w", what, ctxErr)
	}
	return fmt.Errorf("sshx: %s: %w", what, err)
}

// isAuthFailure reports whether a handshake failed because the server refused
// every way of logging in that the client offered.
func isAuthFailure(err error) bool {
	if errors.Is(err, ErrAuth) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "authentication attempts")
}

// hostKeyCheck is the host key callback of one handshake, and remembers the key
// that the server presented.
type hostKeyCheck struct {
	want string

	mu  sync.Mutex
	got *HostKeyResult
}

func (h *hostKeyCheck) callback(_ string, _ net.Addr, key ssh.PublicKey) error {
	res := &HostKeyResult{Fingerprint: ssh.FingerprintSHA256(key), KeyType: key.Type(), FirstContact: h.want == ""}
	h.mu.Lock()
	h.got = res
	h.mu.Unlock()
	switch {
	case h.want == "":
		// Ends the handshake before the authentication.
		return ErrHostKeyUnconfirmed
	case res.Fingerprint != h.want:
		return ErrHostKeyChanged
	}
	return nil
}

func (h *hostKeyCheck) result() *HostKeyResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.got == nil {
		return nil
	}
	res := *h.got
	return &res
}

// authMethods returns the ways to log in with a: the key first, then the
// password, which servers with PAM take through keyboard-interactive.
func authMethods(a Auth, steps *authSteps) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(a.PrivateKeyPEM) > 0 {
		signer, err := parsePrivateKey(a.PrivateKeyPEM, a.Passphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if a.Password != "" {
		methods = append(methods, ssh.Password(a.Password), ssh.KeyboardInteractive(passwordAnswers(a.Password, steps)))
	}
	if len(methods) == 0 {
		return nil, errors.New("sshx: no password and no private key to log in with")
	}
	return methods, nil
}

// authSteps follows the authentication of one handshake: whether a method has
// partly succeeded, so that the server wants another factor.
type authSteps struct {
	partial atomic.Bool
}

// observe is the auth callback of the client config, which x/crypto calls
// after every attempt. It only takes note, and lets the client go on as it
// would.
func (s *authSteps) observe(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	if len(ctx.PartialSuccessMethods) > 0 {
		s.partial.Store(true)
	}
	return nil, nil
}

// parsePrivateKey reads a private key. A passphrase that the key does not need
// is ignored.
func parsePrivateKey(pemBytes []byte, passphrase string) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return signer, nil
	case !errors.As(err, &missing):
		return nil, fmt.Errorf("sshx: read the private key: %w", err)
	case passphrase == "":
		return nil, fmt.Errorf("%w, and none was given", ErrKeyPassphrase)
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	switch {
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, fmt.Errorf("%w, and the one given does not open it", ErrKeyPassphrase)
	case err != nil:
		return nil, fmt.Errorf("sshx: read the private key: %w", err)
	}
	return signer, nil
}

// passwordAnswers answers keyboard-interactive authentication with the
// password: one question whose answer is not echoed, once, and only while no
// method has partly succeeded. A question after the password, or after a
// partial success, asks for a second factor, such as a one-time code, which the
// password is not: the server is refused, and the password does not go into
// what may be logged as a wrong code.
func passwordAnswers(password string, steps *authSteps) ssh.KeyboardInteractiveChallenge {
	answered := false
	return func(_, _ string, questions []string, echos []bool) ([]string, error) {
		switch {
		case len(questions) == 0:
			return nil, nil // a round without questions, which some servers send
		case answered || steps.partial.Load():
			return nil, fmt.Errorf("%w: the server asks for a second factor", ErrAuth)
		case len(questions) == 1 && len(echos) == 1 && !echos[0]:
			answered = true
			return []string{password}, nil
		}
		return nil, fmt.Errorf("%w: the server asks for more than a password", ErrAuth)
	}
}

// Close closes the connection. Commands that still run fail.
func (c *Client) Close() error {
	return c.client.Close()
}

// Run runs cmd and writes what it prints, on its output and its error output,
// to out, which may be nil. It sends stdin, which may be nil, to the input of
// the command, and the end of the input after it.
//
// A command that ran returns its exit code (128 and the number of the signal
// for a command that a signal ended) and a nil error, whatever the code is.
// When err is not nil, exitCode is -1.
//
// For a user other than root the first command of the client checks first
// that sudo works without a password, and fails with [ErrSudoPassword] if it
// does not; the refusal is kept, and the following commands fail the same way
// without asking sudo again. A command that sudo refuses on its own, as sudo
// does for a user with NOPASSWD for some commands only, fails with
// [ErrSudoPassword] as well.
//
// The command runs until ctx ends, or [DefaultCommandTimeout] if ctx has no
// deadline; then it is sent SIGTERM and its session is closed, and Run returns
// the error of ctx. SIGTERM reaches the shell that runs the command, which
// ends without running anything more, or sudo, which passes it on to that
// shell. A process that the shell has started and that is still running is not
// signalled, and without a terminal nothing more can be done to stop it: it
// lives on until it ends by itself. A server that does not answer for a few
// seconds more has lost the connection: Run closes the client then, so that it
// returns in time also when the network has died, and so do the other commands
// of the client.
//
// A command whose command line would be longer than [MaxCommandLine] fails
// with [ErrCommandTooLong] before anything is sent, and on a server that has no
// base64 commands fail with [ErrNoBase64] without running.
//
// Run does not write to out after it has returned. Writes to out are not
// concurrent, but the output and the error output reach it in no fixed order.
func (c *Client) Run(ctx context.Context, cmd string, stdin io.Reader, out io.Writer) (exitCode int, err error) {
	return c.RunOutputs(ctx, cmd, stdin, out, out)
}

// RunOutputs is [Client.Run] with the output and the error output of the
// command apart: what it prints on its output goes to stdout, and what it
// prints on its error output to stderr, either of which may be nil, so that
// what a command prints is not mixed with the warnings of sudo or of the
// command itself. The two may be the same writer, as for Run. Writes to them
// are not concurrent, and none comes after RunOutputs has returned.
func (c *Client) RunOutputs(ctx context.Context, cmd string, stdin io.Reader, stdout, stderr io.Writer) (exitCode int, err error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCommandTimeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return -1, fmt.Errorf("sshx: run a command: %w", err)
	}
	script := cmd
	if c.sudo {
		script = sudoPrefix + shellQuote(cmd)
	}
	line := commandLine(script)
	if len(line) > MaxCommandLine {
		return -1, fmt.Errorf("%w: it would be %d bytes, and a server takes at most %d", ErrCommandTooLong, len(line), MaxCommandLine)
	}
	if !c.sudo {
		code, _, err := c.exec(ctx, line, stdin, stdout, stderr)
		return code, err
	}
	if err := c.checkSudo(ctx); err != nil {
		return -1, err
	}
	code, errHead, err := c.exec(ctx, line, stdin, stdout, stderr)
	if err != nil {
		return -1, err
	}
	// The check passed, but sudo may allow some commands only. With LC_ALL=C
	// its complaint is in English, that of sudo or that of sudo-rs.
	if code == 1 && (bytes.Contains(errHead, []byte("a password is required")) ||
		bytes.Contains(errHead, []byte("interactive authentication is required"))) {
		return -1, c.sudoRefused(errHead)
	}
	return code, nil
}

// checkSudo finds out, once per client, whether sudo runs commands for the
// user without a password: "LC_ALL=C sudo -n true" exits with 0 then. A
// refusal is kept. A check that could not finish, because ctx ended or the
// connection failed, is not taken for an answer, and the next command checks
// again.
func (c *Client) checkSudo(ctx context.Context) error {
	if c.sudoOK.Load() {
		return nil
	}
	select {
	case c.sudoTurn <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("sshx: check sudo: %w", ctx.Err())
	}
	defer func() { <-c.sudoTurn }()
	switch {
	case c.sudoOK.Load():
		return nil
	case c.sudoErr != nil:
		return c.sudoErr
	}
	code, errHead, err := c.exec(ctx, commandLine(sudoCheck), nil, nil, nil)
	if err != nil {
		return fmt.Errorf("sshx: check sudo: %w", err)
	}
	if code != 0 {
		c.sudoErr = c.sudoRefused(errHead)
		return c.sudoErr
	}
	c.sudoOK.Store(true)
	return nil
}

// sudoRefused is the error for a refusal of sudo, with the first line of what
// it said on its error output.
func (c *Client) sudoRefused(errHead []byte) error {
	said := firstLine(errHead)
	if said == "" {
		said = "nothing"
	}
	return fmt.Errorf("%w: user %s needs passwordless sudo (NOPASSWD), or the panel has to connect as root; sudo said: %s",
		ErrSudoPassword, c.user, said)
}

// saidMax is the most of a line from the server that an error holds.
const saidMax = 200

// firstLine returns the first line of b that is not empty once it is plain
// text: without terminal escape sequences, control characters and spaces
// around it, and at most saidMax bytes of it.
func firstLine(b []byte) string {
	for line := range strings.SplitSeq(string(b), "\n") {
		if s := plainText(line); s != "" {
			return shorten(s, saidMax)
		}
	}
	return ""
}

// excerpt returns what a server said as one line of plain text: the lines of b
// that are not empty once they are plain text, joined by "; ", and at most
// twice saidMax bytes of them.
func excerpt(b []byte) string {
	var lines []string
	for line := range strings.SplitSeq(string(b), "\n") {
		if s := plainText(line); s != "" {
			lines = append(lines, s)
		}
	}
	return shorten(strings.Join(lines, "; "), 2*saidMax)
}

// shorten returns at most the first max bytes of s, cut between characters,
// with "…" when something was cut.
func shorten(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// plainText returns s without terminal escape sequences and control
// characters, as valid UTF-8, and without spaces around it.
func plainText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != 0x1b {
			b.WriteByte(s[i])
			continue
		}
		// ESC [ ... ends with a byte from @ to ~; any other escape is ESC and
		// one byte.
		i++
		if i < len(s) && s[i] == '[' {
			for i++; i < len(s) && (s[i] < '@' || s[i] > '~'); i++ {
			}
		}
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(b.String(), string(utf8.RuneError))))
}

// exec runs a command line (commandLine) in a session of its own, for as long
// as ctx lets it, as [Client.Run] says. Its output goes to stdout and its error
// output to stderr, which may be the same writer or nil; it also returns the
// first errHeadSize bytes of the error output.
func (c *Client) exec(ctx context.Context, line string, stdin io.Reader, stdout, stderr io.Writer) (int, []byte, error) {
	o := &outputs{stdout: stdout, stderr: stderr}
	defer o.close()

	// Opening a session, starting the command and waiting for it all wait for
	// the server, and none of them takes a context: they run on their own.
	r := &running{}
	done := make(chan runResult, 1)
	go func() {
		code, err := c.session(line, stdin, o, r)
		done <- runResult{code, err}
	}()
	if res, ok := awaitResult(ctx, done); ok {
		head := o.head()
		if res.err == nil && res.code == 127 && bytes.Contains(head, []byte(noBase64Said)) {
			return -1, head, fmt.Errorf("%w (the server said: %s)", ErrNoBase64, firstLine(head))
		}
		return res.code, head, res.err
	}
	// Stopping writes to the connection, which can block when the network has
	// died: it runs on its own as well.
	go r.stop()
	select {
	case <-done:
	case <-time.After(abandonAfter):
		_ = c.client.Close()
	}
	return -1, nil, fmt.Errorf("sshx: the command did not finish: %w", ctx.Err())
}

type runResult struct {
	code int
	err  error
}

// The forms of commands. Package sshxtest has copies, which its tests compare.
const (
	// transportScript is what the login shell passes to sh. It decodes the
	// script, which follows as the first argument in base64, into a variable,
	// and replaces itself with a sh that runs the script: the script has the
	// input of the command and no arguments, and SIGTERM, which sshd sends to
	// the process of the session, reaches the shell that runs it. -- makes a
	// script that starts with - or + a script and not options. ($( ) drops the
	// line ends at the end of the script, which only end its last command.)
	//
	// When the script cannot be decoded, because base64 is missing or fails,
	// it says noBase64Said and exits with 127 without running anything. echo
	// puts the sentence together from two words, so that it is not whole in
	// the command line: a login shell that traces what it runs (set -x in a
	// .bashrc) prints the line on the error output, and a command that ends
	// with 127 by itself must not be taken for a missing base64 for that.
	transportScript = `s=$(printf %s "$1" | base64 -d) || { echo "` + noBase64Head + `" "` + noBase64Tail +
		`" >&2; exit 127; }; exec sh -c -- "$s"`

	// noBase64Said is what the transport says when it cannot decode a script,
	// the two words that echo joins with a space.
	noBase64Said = noBase64Head + " " + noBase64Tail
	noBase64Head = "sshx: the command cannot be"
	noBase64Tail = "decoded: base64 is missing or failed"

	// sudoPrefix starts the script of a command of a user other than root;
	// the command follows, quoted for sh. exec puts sudo in the place of the
	// shell, so that SIGTERM reaches sudo, which passes it on to the command.
	// LC_ALL=C makes sudo speak English, and sudo passes it on as well.
	sudoPrefix = "LC_ALL=C exec sudo -n -- sh -c -- "

	// sudoCheck is the script that checks sudo.
	sudoCheck = "LC_ALL=C sudo -n true"
)

// commandLine is what the login shell gets for a script: sh, in the place of
// the login shell, with the script in base64. The line holds a string in
// single quotes without backslashes, line ends or '!' in it, and plain words:
// nothing that any shell reads in its own way.
func commandLine(script string) string {
	return "exec sh -c '" + transportScript + "' sh '" + base64.StdEncoding.EncodeToString([]byte(script)) + "'"
}

// awaitResult waits for the result of a command or the end of ctx. A result
// that is there when ctx ends is taken: a command that has finished is not
// reported as stopped.
func awaitResult(ctx context.Context, done <-chan runResult) (runResult, bool) {
	select {
	case res := <-done:
		return res, true
	case <-ctx.Done():
	}
	select {
	case res := <-done:
		return res, true
	default:
		return runResult{}, false
	}
}

// running is the session of one command, which Run stops when its context
// ends, also while the session is being opened.
type running struct {
	mu      sync.Mutex
	session *ssh.Session
	stopped bool
}

// set records the session of the command. It reports false when the command
// has been stopped already, and the session must not start it.
func (r *running) set(s *ssh.Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session = s
	return !r.stopped
}

// stop sends SIGTERM to the command and closes its session.
func (r *running) stop() {
	r.mu.Lock()
	r.stopped = true
	s := r.session
	r.mu.Unlock()
	if s != nil {
		_ = s.Signal(ssh.SIGTERM)
		_ = s.Close()
	}
}

// session runs a command line in a session of its own and waits until it ends.
func (c *Client) session(line string, stdin io.Reader, o *outputs, r *running) (int, error) {
	s, err := c.client.NewSession()
	if err != nil {
		return -1, fmt.Errorf("sshx: open a session: %w", err)
	}
	defer func() { _ = s.Close() }()
	if !r.set(s) {
		return -1, errors.New("sshx: the command was stopped before it started")
	}

	s.Stdout, s.Stderr = stream{o, false}, stream{o, true}
	if stdin != nil {
		s.Stdin = stdin
	}
	if err := s.Start(line); err != nil {
		return -1, fmt.Errorf("sshx: start a command: %w", err)
	}

	err = s.Wait()
	exitCode := 0
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		exitCode = exit.ExitStatus()
	case errors.As(err, &missing):
		return -1, errors.New("sshx: the command ended without an exit status")
	default:
		return -1, fmt.Errorf("sshx: the input or the output of the command failed: %w", err)
	}
	if werr := o.err(); werr != nil {
		return -1, fmt.Errorf("sshx: write the output of the command: %w", werr)
	}
	return exitCode, nil
}

// shellQuote quotes s for a POSIX shell: in single quotes, in which nothing is
// special but the single quote itself. A single quote ends the quoted string,
// follows as an escaped quote, and starts a new quoted string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// errHeadSize is how much of the error output of a command is kept, to find a
// complaint of sudo, which comes first.
const errHeadSize = 512

// outputs are the output and the error output of one command. Their writes
// reach the writers of the caller one at a time, and none once the command is
// over for the caller. The first errHeadSize bytes of the error output are
// kept.
// An error of a writer is kept and reported; the output is drained in the
// meantime, so that the command is not stalled.
type outputs struct {
	mu             sync.Mutex
	stdout, stderr io.Writer
	errHead        []byte
	closed         bool
	failed         error
}

// stream is one of the outputs of a command.
type stream struct {
	o     *outputs
	isErr bool
}

func (s stream) Write(p []byte) (int, error) {
	o := s.o
	o.mu.Lock()
	defer o.mu.Unlock()
	w := o.stdout
	if s.isErr {
		w = o.stderr
		if room := errHeadSize - len(o.errHead); room > 0 {
			o.errHead = append(o.errHead, p[:min(room, len(p))]...)
		}
	}
	if o.closed || w == nil || o.failed != nil {
		return len(p), nil
	}
	if _, err := w.Write(p); err != nil {
		o.failed = err
	}
	return len(p), nil
}

func (o *outputs) close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
}

func (o *outputs) err() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.failed
}

func (o *outputs) head() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.errHead)
}

const (
	// maxNameLen is the longest file name that the file systems of a node
	// take.
	maxNameLen = 255

	// tempNameExtra is what the name of a temporary file adds to the name of
	// its file: a dot in front, and ".tmp-" and 16 hex digits after it.
	tempNameExtra = len(".") + len(".tmp-") + 16
)

// Upload writes what r holds to the file at path on the server, with mode,
// which can only hold permission bits. path has to be absolute and clean, and
// may hold nothing but letters, digits and / . _ + -; its directory has to
// exist.
//
// The data goes to a temporary file in the same directory first, which only
// the user can read (umask 077), and when all of it has arrived the temporary
// file gets mode and replaces the file at path in one rename. When anything
// fails the file at path is left as it was, and the temporary file is removed
// if the server can still be reached. The timeout is that of [Client.Run].
func (c *Client) Upload(ctx context.Context, path string, mode os.FileMode, r io.Reader) error {
	if err := checkRemotePath(path); err != nil {
		return err
	}
	if mode&^os.ModePerm != 0 {
		return fmt.Errorf("sshx: upload %s: mode %v has more than permission bits", path, mode)
	}
	if r == nil {
		return fmt.Errorf("sshx: upload %s: nothing to upload", path)
	}
	tmp := tempPath(path)

	// The command ends when the input ends, and that can be a broken
	// connection or a reader that failed as well as the end of the data: what
	// arrived is only installed once its size has been checked.
	in := &countingReader{r: r}
	var out headBuffer
	code, err := c.Run(ctx, "umask 077; cat > "+tmp, in, &out)
	n, eof, readErr := in.state()
	switch {
	case err != nil:
	case readErr != nil:
		err = readErr
	case code != 0:
		err = fmt.Errorf("writing the file failed with exit code %d", code)
	case !eof:
		err = errors.New("the server stopped reading before the end of the data")
	}
	if err == nil {
		// mv would move the file into a directory that is in its place.
		code, err = c.Run(ctx, fmt.Sprintf("[ $(wc -c < %[1]s) -eq %[2]d ] && [ ! -d %[4]s ] && chmod %04[3]o %[1]s && mv -f %[1]s %[4]s || { rm -f %[1]s; exit 1; }",
			tmp, n, uint32(mode.Perm()), path), nil, &out)
		if err == nil && code != 0 {
			err = fmt.Errorf("installing the file failed with exit code %d", code)
		}
	}
	if err != nil {
		c.removeQuietly(ctx, tmp)
		// The errors for a missing base64 and for sudo say what the server
		// said already.
		quoted := errors.Is(err, ErrNoBase64) || errors.Is(err, ErrSudoPassword)
		if said := excerpt(out.b); said != "" && !quoted {
			return fmt.Errorf("sshx: upload %s: %w (the server said: %s)", path, err, said)
		}
		return fmt.Errorf("sshx: upload %s: %w", path, err)
	}
	return nil
}

// removeQuietly removes a temporary file that an upload left behind, also when
// ctx has ended. When the connection is gone the file stays, under a name that
// starts with a dot.
func (c *Client) removeQuietly(ctx context.Context, tmp string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	_, _ = c.Run(ctx, "rm -f "+tmp, nil, nil)
}

// checkRemotePath refuses a path for an upload that is not absolute and clean,
// or that holds a character that a shell would interpret.
func checkRemotePath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("sshx: remote path %q is not absolute", p)
	}
	if p == "/" || path.Clean(p) != p {
		return fmt.Errorf("sshx: remote path %q is not a clean path to a file", p)
	}
	for _, r := range p {
		if !pathChar(r) {
			return fmt.Errorf("sshx: remote path %q holds a character other than letters, digits and / . _ + -", p)
		}
	}
	if len(path.Base(p))+tempNameExtra > maxNameLen {
		return fmt.Errorf("sshx: remote path %q: the name of the file is too long", p)
	}
	return nil
}

// pathChar reports whether r may be part of a remote path: an ASCII letter or
// digit, or one of / . _ + -, none of which a shell interprets in a word that
// starts with a slash.
func pathChar(r rune) bool {
	switch {
	case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9':
		return true
	}
	return strings.ContainsRune("/._+-", r)
}

// tempPath returns the path of a new temporary file next to p:
// <dir>/.<name>.tmp-<16 random hex digits>.
func tempPath(p string) string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail
	return path.Join(path.Dir(p), "."+path.Base(p)+".tmp-"+hex.EncodeToString(b[:]))
}

// countingReader counts what has been read from r and remembers how reading
// ended. The SSH client reads it from a goroutine of its own, which can outlive
// Run, so it is locked.
type countingReader struct {
	r io.Reader

	mu  sync.Mutex
	n   int64
	eof bool  // r returned io.EOF
	err error // the first error of r other than io.EOF
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n += int64(n)
	switch {
	case errors.Is(err, io.EOF):
		c.eof = true
	case err != nil && c.err == nil:
		c.err = err
	}
	return n, err
}

func (c *countingReader) state() (n int64, eof bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n, c.eof, c.err
}

// headBuffer keeps the first 2 KiB written to it: what a failing command said,
// for the error.
type headBuffer struct {
	b []byte
}

const headBufferSize = 2 << 10

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := headBufferSize - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}
