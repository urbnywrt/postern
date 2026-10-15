// Package sshxtest runs an SSH server inside the test process, for the tests of
// package sshx and of the code that drives servers through it.
//
// The server listens on loopback only. It accepts the password and the public
// keys that it is given, for any user, and hands every command (an SSH "exec"
// request) to a [Handler]: a fake of the test's own that answers from canned
// outputs, [Shell], which runs the command with sh on the test machine, or
// [ForeignShell], which stands for a login shell that is not sh. Without a
// handler it runs nothing and only records. It records what clients did, so
// that tests can check what was sent: the authentication attempts, the
// commands, and every other request.
//
// Nothing here is for production: the server does not limit itself in any way.
package sshxtest

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// NoExitStatus is what a [Handler] returns to end a session without an exit
// status, which RFC 4254 allows and which a client has to cope with.
const NoExitStatus = -1

// A Handler runs one command and returns its exit status, or [NoExitStatus].
// ctx ends when the client sends a signal or closes the session; a handler
// that runs for long has to watch it. A handler that runs a process passes the
// signals on to it, as sshd does (Exec.Signals).
type Handler func(ctx context.Context, e *Exec) int

// An Exec is one command that a client asked the server to run.
type Exec struct {
	User    string // the user that the client authenticated as
	Command string // the command line, as the client sent it

	// Script and Sudo are what the command line means in the form of package
	// sshx (see [Script]): the command, and whether it runs through sudo.
	Script string
	Sudo   bool

	Stdin  io.Reader // what the client sends, until it closes its side
	Stdout io.Writer
	Stderr io.Writer

	// Signals are the signals that the client sends, by name ("TERM", "KILL",
	// ...). ctx ends at the first one as well.
	Signals <-chan string
}

// Config is what a test server accepts and how it runs commands.
type Config struct {
	// HostKeys are the host keys of the server. None means one new Ed25519
	// key.
	HostKeys []ssh.Signer

	// Password is the password that the server accepts for every user; ""
	// accepts no password.
	Password string

	// KeyboardInteractive makes the server ask for the password with
	// keyboard-interactive authentication instead of the password method, as
	// an sshd with PAM and "PasswordAuthentication no" does.
	KeyboardInteractive bool

	// AuthorizedKeys are the public keys that the server accepts for every
	// user.
	AuthorizedKeys []ssh.PublicKey

	// SecondFactor makes the server want a one-time code as well, which it
	// asks for with keyboard-interactive authentication: one question,
	// "Verification code: ", not echoed. After a password or a key it asks in
	// a step of its own, as sshd does with AuthenticationMethods
	// "password,keyboard-interactive"; with KeyboardInteractive it asks in the
	// same conversation, after the password, as PAM does. No code is right, and
	// the answers are recorded (Answers).
	SecondFactor bool

	// Handler runs the commands. nil runs nothing: every command succeeds
	// without output, and is only recorded.
	Handler Handler
}

// An AuthAttempt is one attempt of a client to authenticate.
type AuthAttempt struct {
	User   string
	Method string // "none", "password", "publickey", "keyboard-interactive"
	OK     bool
}

// Server is a running test server. Its methods are safe for concurrent use.
type Server struct {
	// Host and Port are where the server listens: 127.0.0.1 and a free port.
	Host string
	Port int

	hostKeys []ssh.Signer
	handler  Handler
	config   *ssh.ServerConfig
	ln       net.Listener
	wg       sync.WaitGroup

	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]struct{}
	accepted int
	sessions int
	auths    []AuthAttempt
	answers  []string
	commands []string
	requests []string
}

// Start starts a server with cfg and stops it when the test ends.
func Start(t testing.TB, cfg Config) *Server {
	t.Helper()
	s := &Server{
		Host:     "127.0.0.1",
		hostKeys: cfg.HostKeys,
		handler:  cfg.Handler,
		conns:    map[net.Conn]struct{}{},
	}
	if len(s.hostKeys) == 0 {
		s.hostKeys = []ssh.Signer{NewEd25519Key(t)}
	}
	if s.handler == nil {
		s.handler = func(context.Context, *Exec) int { return 0 }
	}

	sc := &ssh.ServerConfig{AuthLogCallback: s.logAuth}
	// askCode asks for the one-time code, records the answers, and refuses
	// them all.
	askCode := func(client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		answers, err := client("", "", []string{"Verification code: "}, []bool{false})
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.answers = append(s.answers, answers...)
		s.mu.Unlock()
		return nil, errors.New("sshxtest: wrong code")
	}
	// passed is what a first method that succeeded returns.
	passed := func() (*ssh.Permissions, error) {
		if cfg.SecondFactor {
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
					return askCode(client)
				},
			}}
		}
		return &ssh.Permissions{}, nil
	}
	if cfg.Password != "" {
		want := []byte(cfg.Password)
		right := func(got []byte) bool { return subtle.ConstantTimeCompare(got, want) == 1 }
		if cfg.KeyboardInteractive {
			sc.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				answers, err := client("", "", []string{"Password: "}, []bool{false})
				if err != nil {
					return nil, err
				}
				if len(answers) != 1 || !right([]byte(answers[0])) {
					return nil, errors.New("sshxtest: wrong password")
				}
				if cfg.SecondFactor {
					return askCode(client)
				}
				return &ssh.Permissions{}, nil
			}
		} else {
			sc.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if !right(password) {
					return nil, errors.New("sshxtest: wrong password")
				}
				return passed()
			}
		}
	}
	if len(cfg.AuthorizedKeys) > 0 {
		keys := cfg.AuthorizedKeys
		sc.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			for _, k := range keys {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return passed()
				}
			}
			return nil, errors.New("sshxtest: unknown key")
		}
	}
	for _, k := range s.hostKeys {
		sc.AddHostKey(k)
	}
	s.config = sc

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sshxtest: listen: %v", err)
	}
	s.ln = ln
	s.Port = ln.Addr().(*net.TCPAddr).Port
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// Addr is the address of the server, "127.0.0.1:<port>".
func (s *Server) Addr() string {
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// HostKey is the public part of the first host key of the server.
func (s *Server) HostKey() ssh.PublicKey {
	return s.hostKeys[0].PublicKey()
}

// Fingerprint is the SHA-256 fingerprint of the first host key of the server,
// as ssh-keygen -l prints it.
func (s *Server) Fingerprint() string {
	return ssh.FingerprintSHA256(s.HostKey())
}

// Connections is the number of TCP connections that the server has accepted.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// Sessions is the number of sessions that clients have opened.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions
}

// AuthAttempts returns every authentication attempt so far, in order.
func (s *Server) AuthAttempts() []AuthAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuthAttempt(nil), s.auths...)
}

// Answers returns every answer that clients gave to the question for a
// one-time code (Config.SecondFactor), in order.
func (s *Server) Answers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.answers...)
}

// Commands returns every command line that a client asked to run, in order.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

// Scripts returns what the command lines mean in the form of package sshx
// ([Script]), in order. A script that runs through sudo starts with "sudo: ".
func (s *Server) Scripts() []string {
	var out []string
	for _, line := range s.Commands() {
		script, sudo := Script(line)
		if sudo {
			script = "sudo: " + script
		}
		out = append(out, script)
	}
	return out
}

// Requests returns every request that was not a command, in order: the types
// of other session requests ("pty-req", "env", "shell", "subsystem", ...),
// signals as "signal <name>", global requests as "global <type>" and channels
// of a type other than session as "channel <type>". The server refuses all of
// them except signals.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// Close stops the server, closes every connection and waits until every
// handler has returned. It is called when the test ends, and may be called
// before.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	_ = s.ln.Close()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) logAuth(conn ssh.ConnMetadata, method string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auths = append(s.auths, AuthAttempt{User: conn.User(), Method: method, OK: err == nil})
}

func (s *Server) record(list *[]string, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*list = append(*list, v)
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.accepted++
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) handleConn(nc net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, s.config)
	if err != nil {
		return // the client refused the host key, or did not authenticate
	}
	defer func() { _ = conn.Close() }()
	go func() {
		for req := range reqs {
			s.record(&s.requests, "global "+req.Type)
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()
	var sessions sync.WaitGroup
	defer sessions.Wait()
	for nch := range chans {
		if nch.ChannelType() != "session" {
			s.record(&s.requests, "channel "+nch.ChannelType())
			_ = nch.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.sessions++
		s.mu.Unlock()
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			s.session(conn.User(), ch, creqs)
		}()
	}
}

// session serves one session channel: one command at most, then the exit
// status and the end of the channel.
func (s *Server) session(user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	signals := make(chan string, 8)
	started := false
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				// The client closed the session.
				cancel()
				if started {
					<-done
				}
				return
			}
			switch req.Type {
			case "exec":
				var msg struct{ Command string }
				if started || ssh.Unmarshal(req.Payload, &msg) != nil {
					_ = req.Reply(false, nil)
					continue
				}
				s.record(&s.commands, msg.Command)
				_ = req.Reply(true, nil)
				started = true
				script, sudo := Script(msg.Command)
				e := &Exec{User: user, Command: msg.Command, Script: script, Sudo: sudo,
					Stdin: ch, Stdout: ch, Stderr: ch.Stderr(), Signals: signals}
				go func() { done <- s.handler(ctx, e) }()
			case "signal":
				var msg struct{ Signal string }
				_ = ssh.Unmarshal(req.Payload, &msg)
				s.record(&s.requests, "signal "+msg.Signal)
				select {
				case signals <- msg.Signal: // passed on before ctx ends
				default:
				}
				cancel()
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				s.record(&s.requests, req.Type)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		case code := <-done:
			_ = ch.CloseWrite()
			if code != NoExitStatus {
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			}
			go ssh.DiscardRequests(reqs)
			return
		}
	}
}
