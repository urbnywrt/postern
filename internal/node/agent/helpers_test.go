package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/pki"
)

// Node ids in the panel's format: 26 characters of 0-9 and A-Z.
const (
	testNodeID  = "01JA2B3C4D5E6F7G8H9JKMNPQR"
	otherNodeID = "01JB2B3C4D5E6F7G8H9JKMNPQR"
)

// testClock is a clock that moves only when told to.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 10, 4, 12, 0, 30, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// syncBuffer is a bytes.Buffer that a logger and a test can share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testPKI is a CA, the node's server certificate and the panel's client
// certificate, as the panel issues them.
type testPKI struct {
	ca                    *pki.CA
	nodeCert, nodeKey     []byte
	clientCert, clientKey []byte
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	ca, _, err := pki.NewCA("Internal CA")
	if err != nil {
		t.Fatal(err)
	}
	p := &testPKI{ca: ca}
	lower := strings.ToLower(testNodeID)
	if p.nodeCert, p.nodeKey, err = ca.IssueServer(lower, []string{lower + ".internal"}, nil); err != nil {
		t.Fatal(err)
	}
	if p.clientCert, p.clientKey, err = ca.IssueClient("client"); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *testPKI) serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	conf, err := pki.ServerTLSConfig(p.ca.CertPEM, p.nodeCert, p.nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

// client returns a NodeService client the way the panel makes one: gRPC over
// HTTP/2 and TLS 1.3, presenting certPEM/keyPEM, checking the node's
// certificate against the CA and its fingerprint.
func (p *testPKI) client(t *testing.T, addr string, certPEM, keyPEM []byte) nodev1connect.NodeServiceClient {
	t.Helper()
	fp, err := pki.Fingerprint(p.nodeCert)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := pki.ClientTLSConfig(p.ca.CertPEM, certPEM, keyPEM, strings.ToLower(testNodeID)+".internal", fp)
	if err != nil {
		t.Fatal(err)
	}
	return clientWithTLS(t, addr, conf)
}

func clientWithTLS(t *testing.T, addr string, conf *tls.Config) nodev1connect.NodeServiceClient {
	t.Helper()
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	tr := &http.Transport{TLSClientConfig: conf, Protocols: &protocols, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	return nodev1connect.NewNodeServiceClient(&http.Client{Transport: tr}, "https://"+addr, connect.WithGRPC())
}

// serveTLS serves handler like the agent does, on a free loopback port, until
// the test ends.
func serveTLS(t *testing.T, handler http.Handler, conf *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveTLSOn(t, ln, handler, conf)
}

// serveTLSOn serves handler like the agent does on ln until the test ends.
func serveTLSOn(t *testing.T, ln net.Listener, handler http.Handler, conf *tls.Config) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv := newHTTPServer(handler, conf, discardLog(), ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.ServeTLS(ln, "", "")
	}()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-done
	})
	return ln.Addr().String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// checkGoroutines fails the test when goroutines that it started are still
// running two seconds after it ended.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			n := runtime.NumGoroutine()
			if n <= before {
				return
			}
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<20)
				buf = buf[:runtime.Stack(buf, true)]
				t.Errorf("%d goroutines before the test, %d after it:\n%s", before, n, buf)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}
