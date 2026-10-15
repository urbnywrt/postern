package doh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ---------------------------------------------------------------------------
// A DNS-over-HTTPS server for the tests
// ---------------------------------------------------------------------------

// dohServer is an RFC 8484 endpoint on an httptest TLS server: it takes POSTed
// DNS queries and answers them with what answer makes of the question. It notes
// every request it gets.
type dohServer struct {
	*httptest.Server
	answer func(q dnsmessage.Message) dnsmessage.Message

	hits atomic.Int32
	mu   sync.Mutex
	reqs []*recorded
}

// recorded is what a request carried.
type recorded struct {
	method, contentType, accept string
	id                          uint16
	question                    dnsmessage.Question
}

func startDoH(t *testing.T, answer func(q dnsmessage.Message) dnsmessage.Message) *dohServer {
	t.Helper()
	s := &dohServer{answer: answer}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *dohServer) serve(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var q dnsmessage.Message
	rec := &recorded{method: r.Method, contentType: r.Header.Get("Content-Type"), accept: r.Header.Get("Accept")}
	if err := q.Unpack(body); err == nil && len(q.Questions) == 1 {
		rec.id, rec.question = q.ID, q.Questions[0]
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, rec)
	s.mu.Unlock()
	if r.Method != http.MethodPost || len(q.Questions) != 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp := s.answer(q)
	wire, err := resp.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(wire)
}

func (s *dohServer) url() string { return s.URL + "/dns-query" }

func (s *dohServer) requests() []*recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

// rawServer is an endpoint that answers every request with h, for answers that
// are not DNS messages.
func rawServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return s
}

// trusting returns a client of the endpoints that trusts the certificates of the
// test servers, with timeout for every request.
func trusting(t *testing.T, timeout time.Duration, endpoints []string, servers ...*httptest.Server) *Client {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	c := newClient(endpoints, timeout, pool)
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// ---------------------------------------------------------------------------
// DNS messages
// ---------------------------------------------------------------------------

// name is a name for the messages of the tests; they are all valid.
func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

// query returns a query in wire format.
func query(t *testing.T, id uint16, qname string, qtype dnsmessage.Type) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name(qname), Type: qtype, Class: dnsmessage.ClassINET}},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func reply(q dnsmessage.Message, rcode dnsmessage.RCode, answers ...dnsmessage.Resource) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true, RCode: rcode,
		},
		Questions: q.Questions,
		Answers:   answers,
	}
}

func rrA(owner, ip string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(owner), Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
	}
}

func rrAAAA(owner, ip string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(owner), Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(ip).As16()},
	}
}

func rrCNAME(owner, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(owner), Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.CNAMEResource{CNAME: name(target)},
	}
}

func rrTXT(owner string, parts ...string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(owner), Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.TXTResource{TXT: parts},
	}
}

// fixed answers every A question for www.example.com. with 192.0.2.10.
func fixed() func(q dnsmessage.Message) dnsmessage.Message {
	return func(q dnsmessage.Message) dnsmessage.Message {
		return reply(q, dnsmessage.RCodeSuccess, rrA(q.Questions[0].Name.String(), "192.0.2.10"))
	}
}

func unpack(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("the answer does not parse: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// Exchange
// ---------------------------------------------------------------------------

// RFC 8484: a POST of the query in wire format, as application/dns-message,
// with the ID set to 0; the answer comes back with the ID of the query.
func TestExchangeSpeaksRFC8484AndRestoresTheID(t *testing.T) {
	srv := startDoH(t, fixed())
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)

	resp, err := c.Exchange(context.Background(), query(t, 0xbeef, "www.example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := binary.BigEndian.Uint16(resp); got != 0xbeef {
		t.Errorf("the answer has the ID %#x, want the query's %#x", got, 0xbeef)
	}
	m := unpack(t, resp)
	if !m.Response || m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("answer = %+v", m)
	}
	if a, ok := m.Answers[0].Body.(*dnsmessage.AResource); !ok || netip.AddrFrom4(a.A) != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("answer record = %v", m.Answers[0].Body)
	}

	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("the endpoint got %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.method != http.MethodPost || r.contentType != "application/dns-message" || r.accept != "application/dns-message" {
		t.Errorf("request = %s, Content-Type %q, Accept %q", r.method, r.contentType, r.accept)
	}
	if r.id != 0 {
		t.Errorf("the query went out with the ID %#x, want 0 (RFC 8484 4.1)", r.id)
	}
	if r.question.Name.String() != "www.example.com." || r.question.Type != dnsmessage.TypeA {
		t.Errorf("question = %v", r.question)
	}
}

// The query that is passed in is not changed: its ID is zeroed in a copy.
func TestExchangeLeavesTheQueryAlone(t *testing.T) {
	srv := startDoH(t, fixed())
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)
	q := query(t, 0x1234, "www.example.com.", dnsmessage.TypeA)
	before := bytes.Clone(q)
	if _, err := c.Exchange(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(q, before) {
		t.Error("Exchange changed the query it was given")
	}
}

func TestExchangeFailsOverToTheSecondEndpoint(t *testing.T) {
	cases := []struct {
		name  string
		first http.HandlerFunc
	}{
		{"an HTTP error", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}},
		{"not a DNS message", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>captive portal</html>"))
		}},
		{"garbage of the right type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write([]byte{1, 2, 3})
		}},
		{"SERVFAIL", nil},
		{"REFUSED", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var first *httptest.Server
			switch tc.name {
			case "SERVFAIL", "REFUSED":
				rcode := dnsmessage.RCodeServerFailure
				if tc.name == "REFUSED" {
					rcode = dnsmessage.RCodeRefused
				}
				first = startDoH(t, func(q dnsmessage.Message) dnsmessage.Message { return reply(q, rcode) }).Server
			default:
				first = rawServer(t, tc.first)
			}
			second := startDoH(t, fixed())
			c := trusting(t, time.Second, []string{first.URL + "/dns-query", second.url()}, first, second.Server)

			resp, err := c.Exchange(context.Background(), query(t, 7, "www.example.com.", dnsmessage.TypeA))
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if m := unpack(t, resp); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
				t.Errorf("answer = %+v, want the one of the second endpoint", m)
			}
			if second.hits.Load() != 1 {
				t.Errorf("the second endpoint got %d requests, want 1", second.hits.Load())
			}
		})
	}
}

// An endpoint that failed on its own, by its timeout or an error, is left
// behind at once, also when the caller gives up on the query afterwards: the
// forwarder of the edge stops waiting for DNS-over-HTTPS when the nameservers of
// the host answer first, and a black-holed endpoint must not stay first.
func TestExchangeMovesOnPastAnAttemptThatFailedOnItsOwn(t *testing.T) {
	var hits [2]atomic.Int32
	reached := make(chan struct{}, 2) // the second endpoint has a request
	hang0 := rawServer(t, countHits(&hits[0], hanging))
	hang1 := rawServer(t, countHits(&hits[1], func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
		hanging(w, r)
	}))
	good := startDoH(t, fixed())
	// A second for each request: the good endpoint answers well within it, also
	// with the race detector on a busy machine.
	c := trusting(t, time.Second, []string{hang0.URL + "/q", hang1.URL + "/q", good.url()}, hang0, hang1, good.Server)

	// The first endpoint fails on its own, by its timeout; the caller gives up
	// once the second has the request, in the middle of the second attempt.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-reached:
			cancel()
		case <-ctx.Done():
		}
	}()
	if _, err := c.Exchange(ctx, query(t, 1, "www.example.com.", dnsmessage.TypeA)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Exchange = %v, want the caller's cancellation", err)
	}
	if h0, h1 := hits[0].Load(), hits[1].Load(); h0 != 1 || h1 != 1 {
		t.Fatalf("requests %d and %d, want 1 and 1", h0, h1)
	}

	// The next query begins with the second endpoint, not with the first again.
	if _, err := c.Exchange(context.Background(), query(t, 2, "www.example.com.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if h0, h1, h2 := hits[0].Load(), hits[1].Load(), good.hits.Load(); h0 != 1 || h1 != 2 || h2 != 1 {
		t.Errorf("requests %d, %d, %d; want 1, 2, 1: the second query begins past the endpoint that failed", h0, h1, h2)
	}
	// And it stays with the one that answers.
	if _, err := c.Exchange(context.Background(), query(t, 3, "www.example.com.", dnsmessage.TypeA)); err != nil || good.hits.Load() != 2 {
		t.Errorf("third query: %v, %d requests to the good endpoint, want 2", err, good.hits.Load())
	}
}

// A query tries two endpoints at the most. The next query starts with an
// endpoint that was not tried, and stays with the one that answers.
func TestExchangeTriesTwoEndpointsAndMovesOn(t *testing.T) {
	var aHits, bHits atomic.Int32
	failing := func(t *testing.T, n *atomic.Int32) *httptest.Server {
		return rawServer(t, countHits(n, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusBadGateway)
		}))
	}
	a, b := failing(t, &aHits), failing(t, &bHits)
	good := startDoH(t, fixed())
	c := trusting(t, time.Second, []string{a.URL + "/q", b.URL + "/q", good.url()}, a, b, good.Server)

	_, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA))
	if err == nil {
		t.Fatal("Exchange succeeded, want the failure of both endpoints it may try")
	}
	if aHits.Load() != 1 || bHits.Load() != 1 || good.hits.Load() != 0 {
		t.Fatalf("requests: %d, %d, %d; want 1, 1, 0", aHits.Load(), bHits.Load(), good.hits.Load())
	}
	var de *Error
	if !errors.As(err, &de) || len(de.Attempts) != 2 {
		t.Errorf("error %v (%T), want an *Error with two attempts", err, err)
	}

	// The next query starts with the third endpoint, and so does the one after.
	for i := range 2 {
		if _, err := c.Exchange(context.Background(), query(t, 2, "www.example.com.", dnsmessage.TypeA)); err != nil {
			t.Fatalf("query %d: %v", i+2, err)
		}
	}
	if aHits.Load() != 1 || bHits.Load() != 1 || good.hits.Load() != 2 {
		t.Errorf("requests: %d, %d, %d; want 1, 1, 2", aHits.Load(), bHits.Load(), good.hits.Load())
	}
}

// countHits counts the requests that h gets.
func countHits(n *atomic.Int32, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	}
}

// An answer is a DNS message, which is 65535 bytes at the most: a longer body is
// refused, whether it says its length or not.
func TestExchangeRefusesAnOversizeBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length bool
	}{{"with a content length", true}, {"chunked", false}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := rawServer(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				big := make([]byte, 65536)
				copy(big, body)
				big[2] |= 0x80 // QR
				w.Header().Set("Content-Type", "application/dns-message")
				if tc.length {
					w.Header().Set("Content-Length", "65536")
					_, _ = w.Write(big)
					return
				}
				for off := 0; off < len(big); off += 4096 {
					_, _ = w.Write(big[off : off+4096])
					w.(http.Flusher).Flush()
				}
			})
			c := trusting(t, time.Second, []string{srv.URL + "/dns-query"}, srv)
			_, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA))
			if err == nil || !strings.Contains(err.Error(), "65535") {
				t.Errorf("Exchange = %v, want an error about the 65535-byte limit", err)
			}
		})
	}
}

// hanging is an endpoint that never answers. It reads the query first: the
// server only notices that the client has gone once the body is read, and the
// request would otherwise outlive the test and hold up the server's Close.
func hanging(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	select {
	case <-r.Context().Done():
	case <-time.After(10 * time.Second):
	}
}

// Every request has its own timeout; an endpoint that does not answer costs no
// more than that, and the second one is tried.
func TestExchangeTimesOut(t *testing.T) {
	hang := rawServer(t, hanging)
	good := startDoH(t, fixed())

	c := trusting(t, 200*time.Millisecond, []string{hang.URL + "/q", good.url()}, hang, good.Server)
	start := time.Now()
	if _, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 2*time.Second {
		t.Errorf("the answer took %v, want about the timeout of one request (200ms)", d)
	}

	c = trusting(t, 200*time.Millisecond, []string{hang.URL + "/a", hang.URL + "/b"}, hang)
	start = time.Now()
	_, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA))
	if err == nil {
		t.Fatal("Exchange succeeded with endpoints that never answer")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Exchange took %v, want about two timeouts (400ms)", d)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v, want one that is context.DeadlineExceeded", err)
	}
}

// The caller's context ends a query at once, and no further endpoint is tried.
func TestExchangeStopsWithTheContext(t *testing.T) {
	var hits atomic.Int32
	hang := rawServer(t, countHits(&hits, hanging))
	c := trusting(t, 5*time.Second, []string{hang.URL + "/a", hang.URL + "/b"}, hang)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Exchange(ctx, query(t, 1, "www.example.com.", dnsmessage.TypeA))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Exchange took %v after its context was done", d)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("%d requests, want 1: no endpoint is tried once the context is done", n)
	}
}

// The answer must be an answer to the question that was asked.
func TestExchangeRefusesAnAnswerToAnotherQuestion(t *testing.T) {
	cases := map[string]func(q dnsmessage.Message) dnsmessage.Message{
		"another name": func(q dnsmessage.Message) dnsmessage.Message {
			q.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName("other.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}
			return reply(q, dnsmessage.RCodeSuccess)
		},
		"another type": func(q dnsmessage.Message) dnsmessage.Message {
			q.Questions[0].Type = dnsmessage.TypeAAAA
			return reply(q, dnsmessage.RCodeSuccess)
		},
		"no question": func(q dnsmessage.Message) dnsmessage.Message {
			q.Questions = nil
			return reply(q, dnsmessage.RCodeSuccess)
		},
		"not a response": func(q dnsmessage.Message) dnsmessage.Message {
			m := reply(q, dnsmessage.RCodeSuccess)
			m.Response = false
			return m
		},
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			srv := startDoH(t, answer)
			c := trusting(t, time.Second, []string{srv.url()}, srv.Server)
			if _, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA)); err == nil {
				t.Error("Exchange took the answer")
			}
		})
	}
}

// The case of the name in the answer does not matter (DNS 0x20).
func TestExchangeTakesTheQuestionInAnotherCase(t *testing.T) {
	srv := startDoH(t, func(q dnsmessage.Message) dnsmessage.Message {
		q.Questions[0].Name = dnsmessage.MustNewName("WWW.Example.COM.")
		return reply(q, dnsmessage.RCodeSuccess)
	})
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)
	if _, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA)); err != nil {
		t.Errorf("Exchange: %v", err)
	}
}

func TestExchangeRefusesQueriesItCannotMatch(t *testing.T) {
	srv := startDoH(t, fixed())
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)
	two := dnsmessage.Message{Questions: []dnsmessage.Question{
		{Name: name("a.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		{Name: name("b.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
	}}
	twoWire, err := two.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string][]byte{
		"empty":         nil,
		"short":         {1, 2, 3},
		"two questions": twoWire,
		"no question":   make([]byte, 12),
	} {
		if _, err := c.Exchange(context.Background(), q); err == nil {
			t.Errorf("%s: Exchange took the query", name)
		}
	}
	if srv.hits.Load() != 0 {
		t.Errorf("the endpoint got %d requests for queries that were refused", srv.hits.Load())
	}
}

func TestExchangeWithoutEndpoints(t *testing.T) {
	if _, err := New(nil).Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA)); !errors.Is(err, ErrNoEndpoints) {
		t.Errorf("error %v, want ErrNoEndpoints", err)
	}
}

// The endpoints are named by IP address: a host name in an endpoint would need
// a lookup to be reached, and none is made.
func TestExchangeRefusesAnEndpointNamedByAHostName(t *testing.T) {
	srv := startDoH(t, fixed())
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	url := "https://localhost:" + strconv.Itoa(port) + "/dns-query"
	c := trusting(t, time.Second, []string{url}, srv.Server)
	_, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA))
	if err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Errorf("Exchange = %v, want an error that the endpoint is not an IP address", err)
	}
	if srv.hits.Load() != 0 {
		t.Error("the endpoint was reached through a host name")
	}
}

// The certificate of an endpoint must be valid for its IP address.
func TestExchangeVerifiesTheCertificateOfTheIPAddress(t *testing.T) {
	ca, leaf := certFor(t, netip.MustParseAddr("192.0.2.1")) // not the address of the server
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	c := newClient([]string{srv.URL + "/dns-query"}, time.Second, pool)
	t.Cleanup(c.CloseIdleConnections)

	_, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA))
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Errorf("Exchange = %v, want a certificate that is not valid for 127.0.0.1", err)
	}
}

// certFor makes a CA and a server certificate that is valid for ip alone.
func certFor(t *testing.T, ip netip.Addr) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ip.String()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip.AsSlice()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return ca, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// An error names an endpoint by its host, never by its URL, whose path or
// query could carry what is not to be logged.
func TestErrorsNameTheHostAndNotTheURL(t *testing.T) {
	down := rawServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	hang := rawServer(t, hanging)
	host := func(srv *httptest.Server) string { return srv.Listener.Addr().String() }
	c := trusting(t, 200*time.Millisecond, []string{down.URL + "/private-path-1?key=private-2", hang.URL + "/private-path-3"}, down, hang)
	_, err := c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA))
	if err == nil {
		t.Fatal("Exchange succeeded")
	}
	text := err.Error()
	for _, leak := range []string{"private-path", "private-2", "https://", "/dns-query"} {
		if strings.Contains(text, leak) {
			t.Errorf("the error %q gives away %q of the URL", text, leak)
		}
	}
	if !strings.Contains(text, host(down)) || !strings.Contains(text, host(hang)) {
		t.Errorf("the error %q does not name the hosts %s and %s", text, host(down), host(hang))
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the timeout of the second endpoint is lost: %v", err)
	}

	// A string that is not a URL is named by its index.
	c = trusting(t, time.Second, []string{"::not a url/private-path-4"})
	_, err = c.Exchange(context.Background(), query(t, 1, "www.example.com.", dnsmessage.TypeA))
	if err == nil || strings.Contains(err.Error(), "private-path") || !strings.Contains(err.Error(), "endpoint 0") {
		t.Errorf("Exchange = %v, want an error that names endpoint 0 and nothing of it", err)
	}
}

// TLS 1.2 at least; the certificates are verified against the roots of the
// system when no others are given; no proxy; 3 s per request.
func TestTransportSettings(t *testing.T) {
	c := New(DefaultEndpoints)
	cfg := c.tr.TLSClientConfig
	if cfg == nil || cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("TLS configuration %+v, want at least TLS 1.2", cfg)
	}
	if cfg.InsecureSkipVerify || cfg.RootCAs != nil {
		t.Error("the certificates of the endpoints are not verified against the roots of the system")
	}
	if c.tr.Proxy != nil {
		t.Error("the transport has a proxy function: the proxies of the environment would be used")
	}
	if c.hc.Timeout != Timeout || c.tr.ResponseHeaderTimeout != Timeout || c.tr.TLSHandshakeTimeout != Timeout {
		t.Errorf("timeouts %v, %v, %v; want %v", c.hc.Timeout, c.tr.ResponseHeaderTimeout, c.tr.TLSHandshakeTimeout, Timeout)
	}
	if Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want 3s", Timeout)
	}
	// Four endpoints, each https with an IP address for its host and the path
	// of RFC 8484. (The online test asks each of them.)
	if len(DefaultEndpoints) != 4 {
		t.Errorf("%d default endpoints, want 4", len(DefaultEndpoints))
	}
	for _, ep := range DefaultEndpoints {
		u, err := url.Parse(ep)
		if err != nil || u.Scheme != "https" || u.Path != "/dns-query" || u.Port() != "" {
			t.Errorf("default endpoint %q is not https://<address>/dns-query", ep)
			continue
		}
		if a, err := netip.ParseAddr(u.Hostname()); err != nil || !a.Is4() || !a.IsGlobalUnicast() {
			t.Errorf("default endpoint %q: the host is not a public IPv4 address", ep)
		}
	}
}

// ---------------------------------------------------------------------------
// LookupIP and LookupTXT
// ---------------------------------------------------------------------------

// zone answers like a resolver over a small zone with a CNAME.
func zone() func(q dnsmessage.Message) dnsmessage.Message {
	return func(q dnsmessage.Message) dnsmessage.Message {
		qq := q.Questions[0]
		switch strings.ToLower(qq.Name.String()) {
		case "www.example.com.":
			chain := []dnsmessage.Resource{rrCNAME("www.example.com.", "edge.example.com.")}
			switch qq.Type {
			case dnsmessage.TypeA:
				chain = append(chain, rrA("edge.example.com.", "192.0.2.2"), rrA("edge.example.com.", "192.0.2.1"),
					rrA("unrelated.example.com.", "198.51.100.1"))
			case dnsmessage.TypeAAAA:
				chain = append(chain, rrAAAA("edge.example.com.", "2001:db8::1"))
			}
			return reply(q, dnsmessage.RCodeSuccess, chain...)
		case "v4.example.com.":
			if qq.Type == dnsmessage.TypeA {
				return reply(q, dnsmessage.RCodeSuccess, rrA("v4.example.com.", "192.0.2.3"))
			}
			return reply(q, dnsmessage.RCodeSuccess)
		case "txt.example.com.":
			if qq.Type == dnsmessage.TypeTXT {
				return reply(q, dnsmessage.RCodeSuccess,
					rrTXT("txt.example.com.", "v=spf1 ", "-all"), rrTXT("txt.example.com.", "token-1"))
			}
			return reply(q, dnsmessage.RCodeSuccess)
		case "empty.example.com.":
			return reply(q, dnsmessage.RCodeSuccess)
		}
		return reply(q, dnsmessage.RCodeNameError)
	}
}

func TestLookupIP(t *testing.T) {
	srv := startDoH(t, zone())
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)

	got, err := c.LookupIP(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	// The records of the CNAME chain, IPv4 first, in the order of the answer;
	// the record of a name outside the chain is not one of them.
	want := []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	if !slices.Equal(got, want) {
		t.Errorf("LookupIP = %v, want %v", got, want)
	}

	got, err = c.LookupIP(context.Background(), "v4.example.com.")
	if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.3")}) {
		t.Errorf("LookupIP(v4 only) = %v, %v", got, err)
	}

	types := map[dnsmessage.Type]int{}
	for _, r := range srv.requests() {
		types[r.question.Type]++
	}
	if types[dnsmessage.TypeA] != 2 || types[dnsmessage.TypeAAAA] != 2 {
		t.Errorf("questions by type = %v, want 2 A and 2 AAAA", types)
	}
}

func TestLookupIPOfAnAddressAsksNothing(t *testing.T) {
	srv := startDoH(t, zone())
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)
	got, err := c.LookupIP(context.Background(), "192.0.2.77")
	if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.77")}) {
		t.Errorf("LookupIP = %v, %v", got, err)
	}
	if srv.hits.Load() != 0 {
		t.Error("an address was looked up")
	}
}

func TestLookupNotFound(t *testing.T) {
	srv := startDoH(t, zone())
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)
	for _, n := range []string{"missing.example.com", "empty.example.com"} {
		_, err := c.LookupIP(context.Background(), n)
		var de *net.DNSError
		if !errors.As(err, &de) || !de.IsNotFound || de.Name != n {
			t.Errorf("LookupIP(%s) = %v, want a *net.DNSError that is IsNotFound", n, err)
		}
	}
	_, err := c.LookupTXT(context.Background(), "missing.example.com")
	var de *net.DNSError
	if !errors.As(err, &de) || !de.IsNotFound {
		t.Errorf("LookupTXT(missing) = %v, want a *net.DNSError that is IsNotFound", err)
	}
}

func TestLookupFailure(t *testing.T) {
	srv := rawServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	c := trusting(t, time.Second, []string{srv.URL + "/dns-query"}, srv)
	if _, err := c.LookupIP(context.Background(), "www.example.com"); err == nil {
		t.Error("LookupIP succeeded with an endpoint that is down")
	}
	if _, err := c.LookupTXT(context.Background(), "txt.example.com"); err == nil {
		t.Error("LookupTXT succeeded with an endpoint that is down")
	}
}

func TestLookupTXT(t *testing.T) {
	srv := startDoH(t, zone())
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)
	got, err := c.LookupTXT(context.Background(), "txt.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	// The strings of one record are one value, as net.LookupTXT has them.
	if want := []string{"v=spf1 -all", "token-1"}; !slices.Equal(got, want) {
		t.Errorf("LookupTXT = %q, want %q", got, want)
	}
	// A name without TXT records has none, and that is not an error.
	got, err = c.LookupTXT(context.Background(), "v4.example.com")
	if err != nil || len(got) != 0 {
		t.Errorf("LookupTXT(no records) = %q, %v", got, err)
	}
}

func TestLookupRefusesBadNames(t *testing.T) {
	srv := startDoH(t, zone())
	c := trusting(t, time.Second, []string{srv.url()}, srv.Server)
	for _, n := range []string{"", ".", "a..example.com", strings.Repeat("a", 64) + ".example.com", strings.Repeat("abcdefghi.", 26) + "com"} {
		if _, err := c.LookupIP(context.Background(), n); err == nil {
			t.Errorf("LookupIP(%q) succeeded", n)
		}
		if _, err := c.LookupTXT(context.Background(), n); err == nil {
			t.Errorf("LookupTXT(%q) succeeded", n)
		}
	}
	if srv.hits.Load() != 0 {
		t.Errorf("%d queries for names that are not valid", srv.hits.Load())
	}
}

// ExchangeAll asks every endpoint, each within its own timeout, takes the good
// answer and names every endpoint that failed; the place of Exchange stays.
func TestExchangeAllAsksEveryEndpoint(t *testing.T) {
	hang := rawServer(t, hanging)
	bad := rawServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
	good := startDoH(t, fixed())
	eps := []string{hang.URL + "/a", bad.URL + "/dns-query", good.url(), hang.URL + "/b"}
	c := trusting(t, 200*time.Millisecond, eps, hang, bad, good.Server)

	start := time.Now()
	resp, failed, err := c.ExchangeAll(context.Background(), query(t, 9, "www.example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("ExchangeAll: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("ExchangeAll took %v, want about one timeout (200ms)", d)
	}
	if m := unpack(t, resp); m.ID != 9 || len(m.Answers) != 1 {
		t.Errorf("answer = %+v, want the good endpoint's with ID 9", m)
	}
	if len(failed) != 3 {
		t.Fatalf("failed = %v, want the three endpoints that did not answer", failed)
	}
	if !strings.Contains(failed[1].Error(), "503") {
		t.Errorf("failed[1] = %v, want the HTTP error of the second endpoint", failed[1])
	}
	if c.next.Load() != 0 {
		t.Errorf("the place of Exchange moved to %d", c.next.Load())
	}

	c = trusting(t, 200*time.Millisecond, []string{hang.URL + "/a", bad.URL + "/b"}, hang, bad)
	_, failed, err = c.ExchangeAll(context.Background(), query(t, 9, "www.example.com.", dnsmessage.TypeA))
	var de *Error
	if !errors.As(err, &de) || len(de.Attempts) != 2 || len(failed) != 2 {
		t.Errorf("err = %v, failed = %v; want an *Error of both endpoints", err, failed)
	}
}
