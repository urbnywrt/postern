package pki

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testTimeout bounds every network operation in these tests, so that a
// regression shows up as a failure and not as a hang.
const testTimeout = 10 * time.Second

// serverEvent is what a test server saw of one connection.
type serverEvent struct {
	err   error               // handshake error; nil when the handshake completed
	state tls.ConnectionState // valid when err is nil
}

// echoServer is a TLS server on a loopback port. It answers one request line
// per connection with "hello <common name of the client certificate>", a
// stand-in for NodeService.GetInfo.
type echoServer struct {
	addr   string
	events chan serverEvent
}

// startEchoServer listens on 127.0.0.1 with cfg until the test ends.
func startEchoServer(t *testing.T, cfg *tls.Config) *echoServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &echoServer{addr: ln.Addr().String(), events: make(chan serverEvent, 64)}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // the listener is closed
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.serve(conn.(*tls.Conn))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return s
}

func (s *echoServer) serve(conn *tls.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(testTimeout))

	if err := conn.Handshake(); err != nil {
		s.events <- serverEvent{err: err}
		return
	}
	state := conn.ConnectionState()
	s.events <- serverEvent{state: state}

	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		return
	}
	// A server that wrongly lets an anonymous client in must make the test
	// fail, not crash it.
	who := "nobody"
	if len(state.PeerCertificates) > 0 {
		who = state.PeerCertificates[0].Subject.CommonName
	}
	_, _ = fmt.Fprintf(conn, "hello %s\n", who)
}

// next returns the outcome of the next handshake the server has finished.
func (s *echoServer) next(t *testing.T) serverEvent {
	t.Helper()
	select {
	case ev := <-s.events:
		return ev
	case <-time.After(testTimeout):
		t.Fatal("the server reported no handshake outcome")
		return serverEvent{}
	}
}

// clientOutcome is what a test client saw of one connection.
type clientOutcome struct {
	handshakeErr error               // the client refused the handshake
	ioErr        error               // the handshake passed, the request did not
	reply        string              // the server's answer
	state        tls.ConnectionState // valid when handshakeErr is nil
}

// err returns the first failure, nil when the request was answered.
func (o clientOutcome) err() error {
	if o.handshakeErr != nil {
		return o.handshakeErr
	}
	return o.ioErr
}

// exchange connects to addr, handshakes with cfg, sends a request and reads the
// answer.
//
// The request matters. In TLS 1.3 a client finishes its handshake before the
// server has looked at the client certificate, so a server that rejects the
// certificate is only noticed on the first read.
func exchange(t *testing.T, addr string, cfg *tls.Config) clientOutcome {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, testTimeout)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(testTimeout))

	conn := tls.Client(raw, cfg)
	var out clientOutcome
	if err := conn.Handshake(); err != nil {
		out.handshakeErr = err
		return out
	}
	out.state = conn.ConnectionState()
	if _, err := fmt.Fprint(conn, "GetInfo\n"); err != nil {
		out.ioErr = err
		return out
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		out.ioErr = err
		return out
	}
	out.reply = strings.TrimSpace(reply)
	return out
}

// serverTLS is ServerTLSConfig for a server that presents c and accepts panels
// signed by p's CA.
func serverTLS(t *testing.T, p *testPKI, c cred) *tls.Config {
	t.Helper()
	cfg, err := ServerTLSConfig(p.ca.CertPEM, c.certPEM, c.keyPEM)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	return cfg
}

// clientTLS is ClientTLSConfig for a client that presents c and trusts p's CA.
func clientTLS(t *testing.T, p *testPKI, c cred, serverName, pin string) *tls.Config {
	t.Helper()
	cfg, err := ClientTLSConfig(p.ca.CertPEM, c.certPEM, c.keyPEM, serverName, pin)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	return cfg
}

func wantUnknownAuthority(t *testing.T, err error) {
	t.Helper()
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Errorf("error = %v, want a certificate signed by an unknown authority", err)
	}
}

func wantReason(reason x509.InvalidReason) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var invalid x509.CertificateInvalidError
		if !errors.As(err, &invalid) || invalid.Reason != reason {
			t.Errorf("error = %v, want an invalid certificate with reason %d", err, reason)
		}
	}
}

func wantError(want error) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("error = %v, want %v", err, want)
		}
	}
}

func TestIssueAndHandshake(t *testing.T) {
	p := newTestPKI(t)
	fp := mustFingerprint(t, p.node.certPEM)
	nodeDER := mustCert(t, p.node.certPEM).Raw

	tests := []struct {
		name       string
		serverName string
		pin        string
	}{
		// The management SNI is a plausible domain that appears in no certificate.
		{"pinned, SNI of an unrelated domain", "cdn.example.com", fp},
		{"pinned, SNI the certificate names", "node.example", fp},
		{"pinned, no SNI", "", fp},
		{"not pinned", "cdn.example.com", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startEchoServer(t, serverTLS(t, p, p.node))
			clientCfg := clientTLS(t, p, p.panel, tt.serverName, tt.pin)

			// The configuration is reusable: a connection manager dials again and again.
			for i := range 2 {
				out := exchange(t, srv.addr, clientCfg)
				if err := out.err(); err != nil {
					t.Fatalf("connection %d: %v", i, err)
				}
				if want := "hello postern-panel"; out.reply != want {
					t.Errorf("connection %d: reply = %q, want %q", i, out.reply, want)
				}
				if out.state.Version != tls.VersionTLS13 {
					t.Errorf("connection %d: negotiated TLS version %#x, want TLS 1.3", i, out.state.Version)
				}
				if !bytes.Equal(out.state.PeerCertificates[0].Raw, nodeDER) {
					t.Errorf("connection %d: the client did not talk to the node's certificate", i)
				}

				ev := srv.next(t)
				if ev.err != nil {
					t.Fatalf("connection %d: server handshake: %v", i, ev.err)
				}
				if ev.state.ServerName != tt.serverName {
					t.Errorf("connection %d: the server saw SNI %q, want %q", i, ev.state.ServerName, tt.serverName)
				}
				if len(ev.state.VerifiedChains) == 0 {
					t.Errorf("connection %d: the server did not verify the client certificate", i)
				}
			}
		})
	}
}

func TestRejectForeignCA(t *testing.T) {
	p := newTestPKI(t)
	// Two CAs that neither the panel nor the nodes trust. One passes for ours
	// by carrying the same subject; the other is openly a stranger.
	lookalike, _ := mustCA(t, testCAName)
	stranger, _ := mustCA(t, "Some Other CA")
	foreigners := []struct {
		name string
		ca   *CA
	}{
		{"same subject", lookalike},
		{"other subject", stranger},
	}

	t.Run("server certificate", func(t *testing.T) {
		for _, foreign := range foreigners {
			node := mustServer(t, foreign.ca, "node-1")
			// Pinning the foreign certificate's own fingerprint must not
			// stand in for chain verification.
			for _, pin := range []string{"", mustFingerprint(t, node.certPEM)} {
				t.Run(fmt.Sprintf("%s, pinned=%t", foreign.name, pin != ""), func(t *testing.T) {
					srv := startEchoServer(t, serverTLS(t, p, node))
					out := exchange(t, srv.addr, clientTLS(t, p, p.panel, "node.example", pin))
					if out.handshakeErr == nil {
						t.Fatal("the client accepted a server certificate from a foreign CA")
					}
					wantUnknownAuthority(t, out.handshakeErr)
					if out.reply != "" {
						t.Errorf("got a reply %q from an untrusted server", out.reply)
					}
				})
			}
		}
	})

	t.Run("client certificate", func(t *testing.T) {
		tests := []struct {
			name  string
			ca    *CA
			check func(*testing.T, error) // what the server reports; nil to only require a rejection
		}{
			{"same subject", lookalike, wantUnknownAuthority},
			// A client does not even offer a certificate whose issuer the
			// server did not ask for, so the server has nothing to verify.
			{"other subject", stranger, nil},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				panel := mustClient(t, tt.ca, "postern-panel")
				srv := startEchoServer(t, serverTLS(t, p, p.node))
				out := exchange(t, srv.addr, clientTLS(t, p, panel, "node.example", mustFingerprint(t, p.node.certPEM)))

				ev := srv.next(t)
				if ev.err == nil {
					t.Fatal("the server accepted a client certificate from a foreign CA")
				}
				if tt.check != nil {
					tt.check(t, ev.err)
				}
				if out.err() == nil || out.reply != "" {
					t.Errorf("the client was served (reply %q, error %v)", out.reply, out.err())
				}
			})
		}
	})
}

func TestRejectServerCertAsClient(t *testing.T) {
	p := newTestPKI(t)
	// Node 2 is a legitimate node of the same CA. Its certificate must not
	// work as a panel credential, or one captured node could manage them all.
	node2 := mustServer(t, p.ca, "node-2")

	srv := startEchoServer(t, serverTLS(t, p, p.node))
	out := exchange(t, srv.addr, clientTLS(t, p, node2, "node.example", ""))

	ev := srv.next(t)
	if ev.err == nil {
		t.Fatal("the server accepted a node's server certificate as a client certificate")
	}
	wantReason(x509.IncompatibleUsage)(t, ev.err)
	if out.err() == nil || out.reply != "" {
		t.Errorf("the client was served (reply %q, error %v)", out.reply, out.err())
	}

	// Control: the very same certificate is a perfectly good server certificate.
	good := startEchoServer(t, serverTLS(t, p, node2))
	if err := exchange(t, good.addr, clientTLS(t, p, p.panel, "node.example", "")).err(); err != nil {
		t.Errorf("node 2 does not work as a server: %v", err)
	}
}

func TestRejectClientCertAsServer(t *testing.T) {
	p := newTestPKI(t)
	// A node that presents the panel's client certificate (say, because
	// someone copied the wrong files) must not be taken for a server.
	srv := startEchoServer(t, serverTLS(t, p, p.panel))
	out := exchange(t, srv.addr, clientTLS(t, p, p.panel, "node.example", ""))

	if out.handshakeErr == nil {
		t.Fatal("the client accepted a client certificate as a server certificate")
	}
	wantReason(x509.IncompatibleUsage)(t, out.handshakeErr)
	if out.reply != "" {
		t.Errorf("got a reply %q from an unsuitable server", out.reply)
	}
}

func TestRejectPinMismatch(t *testing.T) {
	p := newTestPKI(t)
	// Node 2 is a legitimate node of the same CA. Its certificate passes chain
	// verification, so only the pin tells it apart from node 1.
	node2 := mustServer(t, p.ca, "node-2")
	fp1 := mustFingerprint(t, p.node.certPEM)
	fp2 := mustFingerprint(t, node2.certPEM)

	tests := []struct {
		name      string
		server    cred   // what the server presents
		presented string // the fingerprint of that certificate
		pin       string
		wantOK    bool
	}{
		{"pinned to the certificate presented", p.node, fp1, fp1, true},
		{"pinned in upper case", p.node, fp1, strings.ToUpper(fp1), true},
		{"not pinned", node2, fp2, "", true},
		{"pinned to another node of the same CA", node2, fp2, fp1, false},
		{"pinned to node 2, node 1 answers", p.node, fp1, fp2, false},
		{"pin is all zeros", p.node, fp1, strings.Repeat("0", 64), false},
		{"pin is not a fingerprint", p.node, fp1, "deadbeef", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startEchoServer(t, serverTLS(t, p, tt.server))
			out := exchange(t, srv.addr, clientTLS(t, p, p.panel, "cdn.example.com", tt.pin))

			if tt.wantOK {
				if err := out.err(); err != nil {
					t.Fatalf("exchange: %v", err)
				}
				if out.reply != "hello postern-panel" {
					t.Errorf("reply = %q", out.reply)
				}
				return
			}
			if out.handshakeErr == nil {
				t.Fatal("the client accepted a certificate that is not the pinned one")
			}
			if !errors.Is(out.handshakeErr, ErrPinMismatch) {
				t.Errorf("error = %v, want ErrPinMismatch", out.handshakeErr)
			}
			// The operator needs to see which certificate the node showed.
			if !strings.Contains(out.handshakeErr.Error(), tt.presented) {
				t.Errorf("error %q does not name the presented fingerprint %s", out.handshakeErr, tt.presented)
			}
			if out.reply != "" {
				t.Errorf("got a reply %q from a server that is not the pinned one", out.reply)
			}
		})
	}
}

// TestRejectUnsuitableCertificates covers certificates that chain to the right
// CA and still must not authenticate anyone, in both directions.
func TestRejectUnsuitableCertificates(t *testing.T) {
	p := newTestPKI(t)
	now := time.Now()

	// craftWith builds a certificate that is fine for both roles, after mutate
	// has broken it in exactly one way.
	craftWith := func(mutate func(*x509.Certificate)) cred {
		tmpl := x509.Certificate{
			Subject:     pkix.Name{CommonName: "crafted"},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		mutate(&tmpl)
		return craft(t, p.ca, tmpl)
	}

	t.Run("control, a sound certificate for both roles", func(t *testing.T) {
		both := craftWith(func(*x509.Certificate) {})

		srv := startEchoServer(t, serverTLS(t, p, both))
		if err := exchange(t, srv.addr, clientTLS(t, p, p.panel, "node.example", "")).err(); err != nil {
			t.Errorf("as a server certificate: %v", err)
		}
		srv = startEchoServer(t, serverTLS(t, p, p.node))
		if err := exchange(t, srv.addr, clientTLS(t, p, both, "node.example", "")).err(); err != nil {
			t.Errorf("as a client certificate: %v", err)
		}
	})

	tests := []struct {
		name         string
		cred         cred
		serverReject func(*testing.T, error) // the client's verdict when a server presents it
		clientReject func(*testing.T, error) // the server's verdict when a client presents it
	}{
		{
			// The standard library takes a certificate without extended key
			// usages for good in every role. Ours must not.
			name:         "no extended key usage",
			cred:         craftWith(func(c *x509.Certificate) { c.ExtKeyUsage = nil }),
			serverReject: wantError(errNoServerAuth),
			clientReject: wantError(errNoClientAuth),
		},
		{
			name:         "any extended key usage",
			cred:         craftWith(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }),
			serverReject: wantError(errNoServerAuth),
			clientReject: wantError(errNoClientAuth),
		},
		{
			// It chains to itself, and in a pool that holds it that is enough
			// for the standard library.
			name:         "the CA certificate itself",
			cred:         cred{p.ca.CertPEM, p.caKeyPEM},
			serverReject: wantError(errNoServerAuth),
			clientReject: wantError(errNoClientAuth),
		},
		{
			name: "expired",
			cred: craftWith(func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
			}),
			serverReject: wantReason(x509.Expired),
			clientReject: wantReason(x509.Expired),
		},
		{
			name: "not yet valid",
			cred: craftWith(func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = now.Add(24*time.Hour), now.Add(48*time.Hour)
			}),
			serverReject: wantReason(x509.Expired),
			clientReject: wantReason(x509.Expired),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/as server certificate", func(t *testing.T) {
			srv := startEchoServer(t, serverTLS(t, p, tt.cred))
			out := exchange(t, srv.addr, clientTLS(t, p, p.panel, "node.example", ""))
			if out.handshakeErr == nil {
				t.Fatal("the client accepted the certificate from a server")
			}
			tt.serverReject(t, out.handshakeErr)
			if out.reply != "" {
				t.Errorf("got a reply %q from an unsuitable server", out.reply)
			}
		})
		t.Run(tt.name+"/as client certificate", func(t *testing.T) {
			srv := startEchoServer(t, serverTLS(t, p, p.node))
			out := exchange(t, srv.addr, clientTLS(t, p, tt.cred, "node.example", ""))
			ev := srv.next(t)
			if ev.err == nil {
				t.Fatal("the server accepted the certificate from a client")
			}
			tt.clientReject(t, ev.err)
			if out.err() == nil || out.reply != "" {
				t.Errorf("the client was served (reply %q, error %v)", out.reply, out.err())
			}
		})
	}
}

// TestHTTP2OverMutualTLS runs the configurations under net/http, the stack the
// panel and the agent talk through: HTTP/2 is negotiated, the handler sees the
// panel's identity and the SNI, and failures stay recognisable after the HTTP
// client has wrapped them, which is how the panel's connection manager will
// meet them.
func TestHTTP2OverMutualTLS(t *testing.T) {
	p := newTestPKI(t)
	fp := mustFingerprint(t, p.node.certPEM)

	startServer := func(t *testing.T, c cred) *httptest.Server {
		t.Helper()
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "%s %s %s", r.Proto, r.TLS.PeerCertificates[0].Subject.CommonName, r.TLS.ServerName)
		}))
		srv.EnableHTTP2 = true
		srv.TLS = serverTLS(t, p, c)
		srv.Config.ErrorLog = log.New(io.Discard, "", 0) // rejected handshakes are expected here
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	newClient := func(t *testing.T, cfg *tls.Config) *http.Client {
		t.Helper()
		tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: testTimeout}
	}

	t.Run("pinned node", func(t *testing.T) {
		srv := startServer(t, p.node)
		client := newClient(t, clientTLS(t, p, p.panel, "cdn.example.com", fp))
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if want := "HTTP/2.0 postern-panel cdn.example.com"; string(body) != want {
			t.Errorf("body = %q, want %q", body, want)
		}
	})

	t.Run("pin mismatch", func(t *testing.T) {
		srv := startServer(t, mustServer(t, p.ca, "node-2"))
		client := newClient(t, clientTLS(t, p, p.panel, "cdn.example.com", fp))
		_, err := client.Get(srv.URL)
		if !errors.Is(err, ErrPinMismatch) {
			t.Errorf("error = %v, want one that wraps ErrPinMismatch", err)
		}
	})

	t.Run("foreign CA", func(t *testing.T) {
		foreign, _ := mustCA(t, testCAName)
		srv := startServer(t, mustServer(t, foreign, "node-1"))
		client := newClient(t, clientTLS(t, p, p.panel, "cdn.example.com", ""))
		_, err := client.Get(srv.URL)
		if err == nil {
			t.Fatal("the client accepted a server certificate from a foreign CA")
		}
		wantUnknownAuthority(t, err)
	})

	t.Run("node certificate as client", func(t *testing.T) {
		srv := startServer(t, p.node)
		client := newClient(t, clientTLS(t, p, mustServer(t, p.ca, "node-2"), "cdn.example.com", fp))
		if resp, err := client.Get(srv.URL); err == nil {
			_ = resp.Body.Close()
			t.Error("the server accepted a node certificate as a client certificate")
		}
	})
}

func TestServerRequiresClientCertificate(t *testing.T) {
	p := newTestPKI(t)
	// A client that verifies the server perfectly well but has no certificate.
	anonymous := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    poolOf(p.ca.Cert),
		ServerName: "node.example",
	}

	srv := startEchoServer(t, serverTLS(t, p, p.node))
	out := exchange(t, srv.addr, anonymous)
	ev := srv.next(t)
	if ev.err == nil {
		t.Fatal("the server completed a handshake with a client that has no certificate")
	}
	if out.err() == nil || out.reply != "" {
		t.Errorf("the anonymous client was served (reply %q, error %v)", out.reply, out.err())
	}
}

func TestTLS13Only(t *testing.T) {
	p := newTestPKI(t)
	roots := poolOf(p.ca.Cert)
	panelCert, err := tls.X509KeyPair(p.panel.certPEM, p.panel.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	nodeCert, err := tls.X509KeyPair(p.node.certPEM, p.node.keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	if got := serverTLS(t, p, p.node); got.MinVersion != tls.VersionTLS13 || got.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("server config: MinVersion %#x, ClientAuth %v, want TLS 1.3 and RequireAndVerifyClientCert", got.MinVersion, got.ClientAuth)
	}
	if got := clientTLS(t, p, p.panel, "", ""); got.MinVersion != tls.VersionTLS13 {
		t.Errorf("client config: MinVersion %#x, want TLS 1.3", got.MinVersion)
	}

	t.Run("the server refuses a TLS 1.2 client", func(t *testing.T) {
		old := &tls.Config{
			MaxVersion:   tls.VersionTLS12,
			RootCAs:      roots,
			ServerName:   "node.example",
			Certificates: []tls.Certificate{panelCert},
		}
		srv := startEchoServer(t, serverTLS(t, p, p.node))
		out := exchange(t, srv.addr, old)
		if out.err() == nil {
			t.Error("the server talked TLS 1.2")
		}
		if ev := srv.next(t); ev.err == nil {
			t.Error("the server completed a TLS 1.2 handshake")
		}
	})

	t.Run("the client refuses a TLS 1.2 server", func(t *testing.T) {
		old := &tls.Config{
			MaxVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{nodeCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    roots,
		}
		srv := startEchoServer(t, old)
		out := exchange(t, srv.addr, clientTLS(t, p, p.panel, "node.example", ""))
		if out.handshakeErr == nil {
			t.Error("the client talked TLS 1.2")
		}
	})
}

func TestTLSConfigErrors(t *testing.T) {
	p := newTestPKI(t)
	other := newTestPKI(t)

	tests := []struct {
		name    string
		caPEM   []byte
		certPEM []byte
		keyPEM  []byte
	}{
		{"no CA", nil, p.node.certPEM, p.node.keyPEM},
		{"CA is not PEM", []byte("not a CA"), p.node.certPEM, p.node.keyPEM},
		{"CA PEM holds no certificate", p.node.keyPEM, p.node.certPEM, p.node.keyPEM},
		{"no certificate", p.ca.CertPEM, nil, p.node.keyPEM},
		{"no key", p.ca.CertPEM, p.node.certPEM, nil},
		{"key of another certificate", p.ca.CertPEM, p.node.certPEM, other.node.keyPEM},
		{"garbage key", p.ca.CertPEM, p.node.certPEM, []byte("not a key")},
	}
	for _, tt := range tests {
		t.Run("server/"+tt.name, func(t *testing.T) {
			if cfg, err := ServerTLSConfig(tt.caPEM, tt.certPEM, tt.keyPEM); err == nil {
				t.Errorf("ServerTLSConfig succeeded (%v), want an error", cfg != nil)
			}
		})
		t.Run("client/"+tt.name, func(t *testing.T) {
			if cfg, err := ClientTLSConfig(tt.caPEM, tt.certPEM, tt.keyPEM, "node.example", ""); err == nil {
				t.Errorf("ClientTLSConfig succeeded (%v), want an error", cfg != nil)
			}
		})
	}
}
