package dns

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/doh"
)

// No test here calls t.Parallel: TestCloseEndsEveryGoroutine counts the
// goroutines of the whole process.

var quiet = slog.New(slog.DiscardHandler)

// ioWait bounds every read of a test from a socket, so that a forwarder that
// does not answer fails the test instead of hanging it.
const ioWait = 5 * time.Second

// ---------------------------------------------------------------------------
// A clock
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---------------------------------------------------------------------------
// DNS messages
// ---------------------------------------------------------------------------

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func question(qname string, qtype dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: name(qname), Type: qtype, Class: dnsmessage.ClassINET}
}

// optRR is an OPT record that announces size.
func optRR(size int) dnsmessage.Resource {
	var r dnsmessage.Resource
	r.Body = &dnsmessage.OPTResource{}
	_ = r.Header.SetEDNS0(size, dnsmessage.RCodeSuccess, false)
	return r
}

// mkQuery is a query of qname and qtype; edns > 0 adds an OPT record that
// announces that size.
func mkQuery(t *testing.T, id uint16, qname string, qtype dnsmessage.Type, edns int) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{question(qname, qtype)},
	}
	if edns > 0 {
		m.Additionals = []dnsmessage.Resource{optRR(edns)}
	}
	return pack(t, m)
}

func pack(t *testing.T, m dnsmessage.Message) []byte {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unpack(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("the answer does not parse: %v (% x)", err, b)
	}
	return m
}

func rrA(owner, ip string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(owner), Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
	}
}

func rrSOA(owner string, ttl uint32) dnsmessage.Resource { return rrSOAMin(owner, ttl, 900) }

// rrSOAMin is an SOA record with the TTL ttl and the minimum minTTL.
func rrSOAMin(owner string, ttl, minTTL uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(owner), Class: dnsmessage.ClassINET, TTL: ttl},
		Body: &dnsmessage.SOAResource{
			NS: name("ns.example.com."), MBox: name("hostmaster.example.com."),
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, MinTTL: minTTL,
		},
	}
}

// reply answers q with rcode and the records.
func reply(q dnsmessage.Message, rcode dnsmessage.RCode, answers, authorities []dnsmessage.Resource) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true, RCode: rcode,
		},
		Questions:   q.Questions,
		Answers:     answers,
		Authorities: authorities,
	}
}

// bigCount is the number of A records of big.example.com: far more than 512
// bytes.
const bigCount = 40

// hugeCount is the number of A records of huge.example.com: more than the
// 8 KiB an answer may take in the cache.
const hugeCount = 600

// zone answers like a resolver of a small zone.
func zone(q dnsmessage.Message) dnsmessage.Message {
	qq := q.Questions[0]
	soa := []dnsmessage.Resource{rrSOA("example.com.", 900)}
	switch strings.ToLower(qq.Name.String()) {
	case "www.example.com.":
		if qq.Type == dnsmessage.TypeA {
			return reply(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA("www.example.com.", "192.0.2.10", 60)}, nil)
		}
		return reply(q, dnsmessage.RCodeSuccess, nil, soa)
	case "long.example.com.":
		return reply(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA("long.example.com.", "192.0.2.11", 3600)}, nil)
	case "big.example.com.":
		var rrs []dnsmessage.Resource
		for i := range bigCount {
			rrs = append(rrs, rrA("big.example.com.", fmt.Sprintf("198.51.100.%d", i+1), 60))
		}
		return reply(q, dnsmessage.RCodeSuccess, rrs, nil)
	case "nodata.example.com.":
		return reply(q, dnsmessage.RCodeSuccess, nil, soa)
	case "huge.example.com.":
		var rrs []dnsmessage.Resource
		for i := range hugeCount {
			rrs = append(rrs, rrA("huge.example.com.", fmt.Sprintf("198.51.100.%d", i%250+1), 60))
		}
		return reply(q, dnsmessage.RCodeSuccess, rrs, nil)
	case "glue.example.com.":
		// One answer and much glue: the glue is what does not fit.
		m := reply(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA("glue.example.com.", "192.0.2.30", 60)}, nil)
		for i := range bigCount {
			m.Additionals = append(m.Additionals, rrA(fmt.Sprintf("ns%d.example.com.", i), fmt.Sprintf("198.51.100.%d", i+1), 60))
		}
		return m
	case "cname.example.com.": // a CNAME whose target has no record of the type: NODATA
		cname := dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: name("cname.example.com."), Class: dnsmessage.ClassINET, TTL: 3600},
			Body:   &dnsmessage.CNAMEResource{CNAME: name("gone.example.com.")},
		}
		return reply(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{cname}, soa)
	case "glueset.example.com.":
		// One answer, a small RRset of glue, and a large one that does not fit.
		m := reply(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA("glueset.example.com.", "192.0.2.31", 60)}, nil)
		m.Additionals = append(m.Additionals, rrA("a.example.com.", "198.51.100.1", 60))
		for i := range bigCount {
			m.Additionals = append(m.Additionals, rrA("ns.example.com.", fmt.Sprintf("198.51.100.%d", i+10), 60))
		}
		return m
	case "shortneg.example.com.": // the SOA lives 10 s
		return reply(q, dnsmessage.RCodeNameError, nil, []dnsmessage.Resource{rrSOAMin("example.com.", 10, 900)})
	case "minneg.example.com.": // the SOA minimum is 5 s
		return reply(q, dnsmessage.RCodeNameError, nil, []dnsmessage.Resource{rrSOAMin("example.com.", 900, 5)})
	case "nosoa.example.com.": // no SOA at all
		return reply(q, dnsmessage.RCodeNameError, nil, nil)
	}
	if n := strings.ToLower(qq.Name.String()); strings.HasPrefix(n, "q") && strings.HasSuffix(n, ".example.com.") {
		return reply(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA(n, "192.0.2.20", 60)}, nil)
	}
	return reply(q, dnsmessage.RCodeNameError, nil, soa)
}

func firstA(t *testing.T, m dnsmessage.Message) (netip.Addr, uint32) {
	t.Helper()
	for _, rr := range m.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			return netip.AddrFrom4(a.A), rr.Header.TTL
		}
	}
	t.Fatalf("the answer has no A record: %+v", m)
	return netip.Addr{}, 0
}

// ---------------------------------------------------------------------------
// A DNS-over-HTTPS upstream
// ---------------------------------------------------------------------------

// fakeUpstream stands in for the DNS-over-HTTPS client. It answers from a
// function, notes every question, and can be made to wait.
type fakeUpstream struct {
	mu      sync.Mutex
	answer  func(q dnsmessage.Message) (dnsmessage.Message, error)
	calls   []dnsmessage.Message
	gate    chan struct{} // Exchange waits until it is closed, when not nil
	entered chan struct{} // gets a value at every Exchange, when not nil
}

func newUpstream(answer func(q dnsmessage.Message) (dnsmessage.Message, error)) *fakeUpstream {
	return &fakeUpstream{answer: answer}
}

func fromZone() *fakeUpstream {
	return newUpstream(func(q dnsmessage.Message) (dnsmessage.Message, error) { return zone(q), nil })
}

func failingUpstream(err error) *fakeUpstream {
	return newUpstream(func(dnsmessage.Message) (dnsmessage.Message, error) { return dnsmessage.Message{}, err })
}

func (u *fakeUpstream) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil {
		return nil, err
	}
	u.mu.Lock()
	u.calls = append(u.calls, q)
	gate, entered, answer := u.gate, u.entered, u.answer
	u.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	m, err := answer(q)
	if err != nil {
		return nil, err
	}
	return m.Pack()
}

func (u *fakeUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func (u *fakeUpstream) questions() []dnsmessage.Message {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.calls)
}

// hold makes Exchange wait until release; entered gets a value for each call.
func (u *fakeUpstream) hold(capacity int) (entered <-chan struct{}, release func()) {
	u.mu.Lock()
	defer u.mu.Unlock()
	gate, ch := make(chan struct{}), make(chan struct{}, capacity)
	u.gate, u.entered = gate, ch
	var once sync.Once
	return ch, func() { once.Do(func() { close(gate) }) }
}

// ---------------------------------------------------------------------------
// The forwarder under test
// ---------------------------------------------------------------------------

// testDoHURL stands for a DNS-over-HTTPS endpoint; the fake upstream answers in
// its place.
const testDoHURL = "https://192.0.2.1/dns-query"

type rig struct {
	t     *testing.T
	f     *Forwarder
	clock *fakeClock
	up    *fakeUpstream
	urls  [][]string // the URLs every upstream was made for
	mu    sync.Mutex
}

// startForwarder runs a forwarder on a port of 127.0.0.1 with up for its
// DNS-over-HTTPS side and the given fallback, with the limits changed by edit.
func startForwarder(t *testing.T, up *fakeUpstream, fallback []string, edit func(*limits)) *rig {
	t.Helper()
	r := &rig{t: t, clock: newClock(), up: up}
	opts := Options{
		Addr: "127.0.0.1:0",
		Now:  r.clock.Now,
		NewUpstream: func(urls []string) Upstream {
			r.mu.Lock()
			r.urls = append(r.urls, slices.Clone(urls))
			r.mu.Unlock()
			return up
		},
	}
	if edit != nil {
		edit(&opts.limits)
	}
	r.f = New(quiet, opts)
	t.Cleanup(r.f.Close)
	if err := r.f.Apply(&edgev1.Dns{Enabled: true, DohUrls: []string{testDoHURL}, Fallback: fallback}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !r.f.Running() {
		t.Fatal("the forwarder does not run after Apply")
	}
	return r
}

func (r *rig) addr() netip.AddrPort { return r.f.Addr() }

// udp sends a query over UDP and returns the answer.
func (r *rig) udp(q []byte) dnsmessage.Message {
	r.t.Helper()
	b, err := udpExchange(r.addr(), q, ioWait)
	if err != nil {
		r.t.Fatalf("no answer over UDP: %v", err)
	}
	return unpack(r.t, b)
}

func (r *rig) udpRaw(q []byte) []byte {
	r.t.Helper()
	b, err := udpExchange(r.addr(), q, ioWait)
	if err != nil {
		r.t.Fatalf("no answer over UDP: %v", err)
	}
	return b
}

// udpExchange sends q from a socket of its own and waits for one datagram.
func udpExchange(addr netip.AddrPort, q []byte, wait time.Duration) ([]byte, error) {
	c, err := net.Dial("udp", addr.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(wait))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// tcp sends the queries over one TCP connection, all at once, and returns the
// answers.
func (r *rig) tcp(qs ...[]byte) []dnsmessage.Message {
	r.t.Helper()
	c, err := net.Dial("tcp", r.addr().String())
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(ioWait))
	var out bytes.Buffer
	for _, q := range qs {
		_ = binary.Write(&out, binary.BigEndian, uint16(len(q)))
		out.Write(q)
	}
	if _, err := c.Write(out.Bytes()); err != nil {
		r.t.Fatal(err)
	}
	var answers []dnsmessage.Message
	for range qs {
		b, err := readTCPMessage(c)
		if err != nil {
			r.t.Fatalf("reading an answer over TCP: %v", err)
		}
		answers = append(answers, unpack(r.t, b))
	}
	return answers
}

func readTCPMessage(c net.Conn) ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	return b, nil
}

// waitFor polls cond until it holds, for ioWait at most.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(ioWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// joined is the number of clients that waited for a question in flight.
func (f *Forwarder) joined() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.srv == nil {
		return 0
	}
	return f.srv.joins.Load()
}

// noAnswer checks that a query over UDP gets no answer at all.
func (r *rig) noAnswer(q []byte) {
	r.t.Helper()
	if b, err := udpExchange(r.addr(), q, 300*time.Millisecond); err == nil {
		r.t.Errorf("got an answer (% x), want none", b)
	}
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

func TestUDPRoundTrip(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	m := r.udp(mkQuery(t, 0x4242, "WwW.ExAmple.com.", dnsmessage.TypeA, 0))

	if m.ID != 0x4242 || !m.Response || m.RCode != dnsmessage.RCodeSuccess || !m.RecursionDesired || !m.RecursionAvailable {
		t.Errorf("header = %+v", m.Header)
	}
	if m.Truncated || m.Authoritative {
		t.Errorf("header = %+v, want neither TC nor AA", m.Header)
	}
	// The question comes back as it was asked, in its case.
	if len(m.Questions) != 1 || m.Questions[0].Name.String() != "WwW.ExAmple.com." || m.Questions[0].Type != dnsmessage.TypeA {
		t.Errorf("questions = %v", m.Questions)
	}
	if a, ttl := firstA(t, m); a != netip.MustParseAddr("192.0.2.10") || ttl != 60 {
		t.Errorf("answer = %s ttl %d, want 192.0.2.10 ttl 60", a, ttl)
	}
	// Without EDNS in the query, none in the answer.
	for _, rr := range m.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			t.Error("the answer has an OPT record, the query had none")
		}
	}

	// The upstream was asked the question once, in lower case, with recursion.
	qs := r.up.questions()
	if len(qs) != 1 {
		t.Fatalf("the upstream got %d queries, want 1", len(qs))
	}
	if qs[0].Questions[0].Name.String() != "www.example.com." || !qs[0].RecursionDesired {
		t.Errorf("upstream query = %+v", qs[0])
	}
	if got := r.urls; len(got) != 1 || !slices.Equal(got[0], []string{testDoHURL}) {
		t.Errorf("upstreams made for %q, want one for %q", got, testDoHURL)
	}
}

// A query with EDNS gets an answer with EDNS, which announces the size the
// forwarder takes over UDP.
func TestEDNSAnswer(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	m := r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 1232))
	var opts int
	for _, rr := range m.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			opts++
			if int(rr.Header.Class) != maxUDPSize {
				t.Errorf("the OPT record announces %d bytes, want %d", rr.Header.Class, maxUDPSize)
			}
		}
	}
	if opts != 1 {
		t.Errorf("the answer has %d OPT records, want 1", opts)
	}
}

func TestTCPRoundTrip(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	// Two queries in one connection, one after the other (RFC 7766).
	ms := r.tcp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0), mkQuery(t, 2, "missing.example.com.", dnsmessage.TypeA, 0))
	if ms[0].ID != 1 || ms[0].RCode != dnsmessage.RCodeSuccess {
		t.Errorf("first answer = %+v", ms[0].Header)
	}
	if a, _ := firstA(t, ms[0]); a != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("first answer = %s", a)
	}
	if ms[1].ID != 2 || ms[1].RCode != dnsmessage.RCodeNameError {
		t.Errorf("second answer = %+v, want NXDOMAIN", ms[1].Header)
	}
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

func TestCacheHit(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))
	r.clock.Advance(10 * time.Second)
	// Another case of the same name is the same question.
	m := r.udp(mkQuery(t, 2, "WWW.EXAMPLE.COM.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 1 {
		t.Fatalf("the upstream got %d queries, want 1: the second answer is the cache's", n)
	}
	if m.ID != 2 || m.Questions[0].Name.String() != "WWW.EXAMPLE.COM." {
		t.Errorf("cached answer = %+v", m)
	}
	if _, ttl := firstA(t, m); ttl != 50 {
		t.Errorf("the cached answer has a TTL of %d, want 60 less the 10 s it was kept", ttl)
	}
	// Over TCP the cache answers as well.
	if ms := r.tcp(mkQuery(t, 3, "www.example.com.", dnsmessage.TypeA, 0)); r.up.count() != 1 || ms[0].RCode != dnsmessage.RCodeSuccess {
		t.Errorf("TCP: %d upstream queries, answer %+v", r.up.count(), ms[0].Header)
	}
	// Another type is another question.
	r.udp(mkQuery(t, 4, "www.example.com.", dnsmessage.TypeAAAA, 0))
	if n := r.up.count(); n != 2 {
		t.Errorf("the upstream got %d queries, want 2", n)
	}
	// Once the TTL is over, the upstream is asked again.
	r.clock.Advance(51 * time.Second)
	r.udp(mkQuery(t, 5, "www.example.com.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 3 {
		t.Errorf("the upstream got %d queries, want 3: the answer had expired", n)
	}
}

// A TTL is cut to 300 s: the answer says so, and the cache keeps it no longer.
func TestCacheCapsTheTTL(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	m := r.udp(mkQuery(t, 1, "long.example.com.", dnsmessage.TypeA, 0))
	if _, ttl := firstA(t, m); ttl != 300 {
		t.Errorf("TTL %d, want the 3600 of the upstream cut to 300", ttl)
	}
	r.clock.Advance(299 * time.Second)
	m = r.udp(mkQuery(t, 2, "long.example.com.", dnsmessage.TypeA, 0))
	if _, ttl := firstA(t, m); ttl != 1 || r.up.count() != 1 {
		t.Errorf("after 299 s: TTL %d with %d upstream queries, want 1 and 1", ttl, r.up.count())
	}
	r.clock.Advance(time.Second)
	r.udp(mkQuery(t, 3, "long.example.com.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 2 {
		t.Errorf("after 300 s the upstream got %d queries, want 2", n)
	}
}

// A name that does not exist, and a name without records of the type, are
// kept for 30 s, whatever the SOA says.
func TestCacheKeepsNegativeAnswers30Seconds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode dnsmessage.RCode
	}{{"missing.example.com.", dnsmessage.RCodeNameError}, {"nodata.example.com.", dnsmessage.RCodeSuccess}} {
		t.Run(tc.name, func(t *testing.T) {
			r := startForwarder(t, fromZone(), nil, nil)
			m := r.udp(mkQuery(t, 1, tc.name, dnsmessage.TypeA, 0))
			if m.RCode != tc.rcode || len(m.Answers) != 0 || len(m.Authorities) != 1 {
				t.Fatalf("answer = %+v", m)
			}
			if ttl := m.Authorities[0].Header.TTL; ttl > 30 {
				t.Errorf("the SOA has a TTL of %d, more than the 30 s the answer is kept", ttl)
			}
			r.clock.Advance(29 * time.Second)
			m = r.udp(mkQuery(t, 2, tc.name, dnsmessage.TypeA, 0))
			if r.up.count() != 1 || m.RCode != tc.rcode {
				t.Errorf("after 29 s: %d upstream queries and %v, want the cached answer", r.up.count(), m.RCode)
			}
			if ttl := m.Authorities[0].Header.TTL; ttl != 1 {
				t.Errorf("after 29 s the SOA has a TTL of %d, want 1", ttl)
			}
			r.clock.Advance(time.Second)
			r.udp(mkQuery(t, 3, tc.name, dnsmessage.TypeA, 0))
			if n := r.up.count(); n != 2 {
				t.Errorf("after 30 s the upstream got %d queries, want 2", n)
			}
		})
	}
}

func TestCacheIsBounded(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, func(l *limits) { l.cacheEntries = 3 })
	for i := range 4 {
		r.udp(mkQuery(t, uint16(i), fmt.Sprintf("q%d.example.com.", i), dnsmessage.TypeA, 0))
	}
	// q0 was the least recently used: it is gone; q3 is there.
	r.udp(mkQuery(t, 9, "q3.example.com.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 4 {
		t.Errorf("the upstream got %d queries, want 4: q3 is cached", n)
	}
	r.udp(mkQuery(t, 9, "q0.example.com.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 5 {
		t.Errorf("the upstream got %d queries, want 5: q0 was evicted", n)
	}
	if got := defaultLimits().cacheEntries; got != 4096 {
		t.Errorf("the cache holds %d entries by default, want 4096", got)
	}
}

// The failure of every upstream is kept for a second per question (RFC 9520):
// the clients that ask again at once get SERVFAIL without a new upstream query.
func TestFailuresAreKeptOneSecond(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	up := newUpstream(func(q dnsmessage.Message) (dnsmessage.Message, error) {
		if fail.Load() {
			return dnsmessage.Message{}, errors.New("down")
		}
		return zone(q), nil
	})
	r := startForwarder(t, up, nil, nil)
	if m := r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0)); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v, want SERVFAIL", m.RCode)
	}
	fail.Store(false)
	if m := r.udp(mkQuery(t, 2, "www.example.com.", dnsmessage.TypeA, 0)); m.RCode != dnsmessage.RCodeServerFailure || up.count() != 1 {
		t.Errorf("within the second: %v with %d upstream queries, want SERVFAIL with 1", m.RCode, up.count())
	}
	// Another question is asked.
	if m := r.udp(mkQuery(t, 3, "www.example.com.", dnsmessage.TypeAAAA, 0)); m.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("another question: %v, want an answer", m.RCode)
	}
	r.clock.Advance(time.Second)
	if m := r.udp(mkQuery(t, 4, "www.example.com.", dnsmessage.TypeA, 0)); m.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("after the second: %v, want an answer", m.RCode)
	}
}

// The cache holds 16 MiB at the most, by default: with less room, the least
// recently used answers go although the count of entries is far from full.
func TestCacheIsBoundedInBytes(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, func(l *limits) { l.cacheBytes = 1000 })
	for i := range 6 {
		r.udp(mkQuery(t, uint16(i), fmt.Sprintf("q%d.example.com.", i), dnsmessage.TypeA, 0))
	}
	entries, bytes := r.f.cache.usage()
	if bytes > 1000 || entries == 0 || entries >= 6 {
		t.Errorf("the cache holds %d entries in %d bytes, want fewer than 6 in 1000 bytes at the most", entries, bytes)
	}
	r.udp(mkQuery(t, 9, "q5.example.com.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 6 {
		t.Errorf("the upstream got %d queries, want 6: q5 is cached", n)
	}
	r.udp(mkQuery(t, 9, "q0.example.com.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 7 {
		t.Errorf("the upstream got %d queries, want 7: q0 was evicted", n)
	}
	if got := defaultLimits().cacheBytes; got != 16<<20 {
		t.Errorf("the cache holds %d bytes by default, want 16 MiB", got)
	}
}

// An answer of more than 8 KiB in wire form is served whole and not kept.
func TestLongAnswersAreServedAndNotKept(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	for i := range 2 {
		m := r.tcp(mkQuery(t, uint16(i), "huge.example.com.", dnsmessage.TypeA, 0))[0]
		if len(m.Answers) != hugeCount || m.Truncated {
			t.Fatalf("answer %d: %d records (TC %v), want all %d", i, len(m.Answers), m.Truncated, hugeCount)
		}
	}
	if n := r.up.count(); n != 2 {
		t.Errorf("the upstream got %d queries, want 2: the answer is not kept", n)
	}
	if entries, _ := r.f.cache.usage(); entries != 0 {
		t.Errorf("the cache holds %d entries", entries)
	}
	// One that fits is kept, as before.
	r.udp(mkQuery(t, 3, "big.example.com.", dnsmessage.TypeA, 4096))
	r.udp(mkQuery(t, 4, "big.example.com.", dnsmessage.TypeA, 4096))
	if n := r.up.count(); n != 3 {
		t.Errorf("the upstream got %d queries, want 3", n)
	}
}

// A negative answer is kept for the TTL of its SOA or the SOA minimum,
// whichever is less, 30 s at the most (RFC 2308 5); without an SOA, not at all.
func TestNegativeAnswersFollowTheirSOA(t *testing.T) {
	for _, tc := range []struct {
		name string
		keep time.Duration // 0: not kept
	}{
		{"shortneg.example.com.", 10 * time.Second},
		{"minneg.example.com.", 5 * time.Second},
		{"nosoa.example.com.", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := startForwarder(t, fromZone(), nil, nil)
			m := r.udp(mkQuery(t, 1, tc.name, dnsmessage.TypeA, 0))
			if m.RCode != dnsmessage.RCodeNameError {
				t.Fatalf("rcode %v, want NXDOMAIN", m.RCode)
			}
			if tc.keep == 0 {
				r.udp(mkQuery(t, 2, tc.name, dnsmessage.TypeA, 0))
				if n := r.up.count(); n != 2 {
					t.Errorf("the upstream got %d queries, want 2: an answer without SOA is not kept", n)
				}
				return
			}
			if ttl := m.Authorities[0].Header.TTL; time.Duration(ttl)*time.Second > tc.keep {
				t.Errorf("the SOA has a TTL of %d, more than the %v the answer is kept", ttl, tc.keep)
			}
			r.clock.Advance(tc.keep - time.Second)
			m = r.udp(mkQuery(t, 2, tc.name, dnsmessage.TypeA, 0))
			if n := r.up.count(); n != 1 || m.Authorities[0].Header.TTL != 1 {
				t.Errorf("1 s before the end: %d upstream queries, SOA TTL %d; want 1 and 1", n, m.Authorities[0].Header.TTL)
			}
			r.clock.Advance(time.Second)
			r.udp(mkQuery(t, 3, tc.name, dnsmessage.TypeA, 0))
			if n := r.up.count(); n != 2 {
				t.Errorf("at the end: %d upstream queries, want 2", n)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

func TestUDPAnswersAreTruncatedToTheClientsSize(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)

	// No EDNS: 512 bytes at the most, TC set, records dropped.
	raw := r.udpRaw(mkQuery(t, 1, "big.example.com.", dnsmessage.TypeA, 0))
	m := unpack(t, raw)
	if len(raw) > 512 || !m.Truncated || len(m.Answers) >= bigCount {
		t.Errorf("without EDNS: %d bytes, TC %v, %d records; want at most 512 bytes, TC, fewer than %d", len(raw), m.Truncated, len(m.Answers), bigCount)
	}
	if m.ID != 1 || m.RCode != dnsmessage.RCodeSuccess || len(m.Questions) != 1 {
		t.Errorf("truncated answer = %+v", m.Header)
	}

	// EDNS with a small size: that size.
	raw = r.udpRaw(mkQuery(t, 2, "big.example.com.", dnsmessage.TypeA, 600))
	m = unpack(t, raw)
	if len(raw) > 600 || !m.Truncated || len(m.Answers) >= bigCount {
		t.Errorf("EDNS 600: %d bytes, TC %v, %d records", len(raw), m.Truncated, len(m.Answers))
	}
	// A size below 512 means 512.
	raw = r.udpRaw(mkQuery(t, 3, "big.example.com.", dnsmessage.TypeA, 100))
	if len(raw) > 512 || len(raw) < 400 {
		t.Errorf("EDNS 100: %d bytes, want close to 512", len(raw))
	}

	// EDNS with room for all of it: no truncation.
	raw = r.udpRaw(mkQuery(t, 4, "big.example.com.", dnsmessage.TypeA, 4096))
	m = unpack(t, raw)
	if m.Truncated || len(m.Answers) != bigCount {
		t.Errorf("EDNS 4096: TC %v, %d records; want all %d", m.Truncated, len(m.Answers), bigCount)
	}

	// TCP is never truncated.
	ms := r.tcp(mkQuery(t, 5, "big.example.com.", dnsmessage.TypeA, 0))
	if ms[0].Truncated || len(ms[0].Answers) != bigCount {
		t.Errorf("TCP: TC %v, %d records", ms[0].Truncated, len(ms[0].Answers))
	}
	if n := r.up.count(); n != 1 {
		t.Errorf("the upstream got %d queries, want 1", n)
	}
}

// Additional records that do not fit are dropped without TC (RFC 2181 9): the
// answer is complete without them, and the client must not ask again.
func TestTCOnlyWhenAnswersOrAuthoritiesGo(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	raw := r.udpRaw(mkQuery(t, 1, "glue.example.com.", dnsmessage.TypeA, 0))
	m := unpack(t, raw)
	if len(raw) > 512 || m.Truncated || len(m.Answers) != 1 || len(m.Additionals) >= bigCount {
		t.Errorf("%d bytes, TC %v, %d answers, %d additional records; want at most 512 bytes without TC, the answer, fewer additional records",
			len(raw), m.Truncated, len(m.Answers), len(m.Additionals))
	}
	if ms := r.tcp(mkQuery(t, 2, "glue.example.com.", dnsmessage.TypeA, 0)); len(ms[0].Additionals) != bigCount {
		t.Errorf("TCP: %d additional records, want all %d", len(ms[0].Additionals), bigCount)
	}
}

// ---------------------------------------------------------------------------
// What is not a query
// ---------------------------------------------------------------------------

func TestMalformedQueriesGetFORMERR(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	two := pack(t, dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{question("a.example.com.", dnsmessage.TypeA), question("b.example.com.", dnsmessage.TypeA)},
	})
	none := pack(t, dnsmessage.Message{Header: dnsmessage.Header{ID: 7}})
	twoOPT := pack(t, dnsmessage.Message{
		Header:      dnsmessage.Header{ID: 7},
		Questions:   []dnsmessage.Question{question("www.example.com.", dnsmessage.TypeA)},
		Additionals: []dnsmessage.Resource{optRR(1232), optRR(1232)},
	})
	cut := mkQuery(t, 7, "www.example.com.", dnsmessage.TypeA, 0)
	cut = cut[:len(cut)-3] // the question ends in the middle
	for name, q := range map[string][]byte{
		"two questions":  two,
		"no question":    none,
		"two OPT":        twoOPT,
		"a cut question": cut,
	} {
		t.Run(name, func(t *testing.T) {
			m := r.udp(q)
			if m.RCode != dnsmessage.RCodeFormatError || m.ID != 7 || !m.Response {
				t.Errorf("answer = %+v, want FORMERR", m.Header)
			}
			ms := r.tcp(q)
			if ms[0].RCode != dnsmessage.RCodeFormatError {
				t.Errorf("over TCP: %v, want FORMERR", ms[0].RCode)
			}
		})
	}
	if n := r.up.count(); n != 0 {
		t.Errorf("the upstream got %d queries", n)
	}
}

func TestOtherOpcodesGetNOTIMP(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	q := mkQuery(t, 9, "www.example.com.", dnsmessage.TypeA, 0)
	q[2] |= 2 << 3 // opcode STATUS
	if m := r.udp(q); m.RCode != dnsmessage.RCodeNotImplemented || m.ID != 9 {
		t.Errorf("answer = %+v, want NOTIMP", m.Header)
	}
}

// A message that is not even a header, and an answer sent to the forwarder,
// get nothing back: no loops between two servers, no reflection.
func TestNoAnswerToRuntsAndResponses(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	r.noAnswer([]byte{1, 2, 3})
	resp := mkQuery(t, 9, "www.example.com.", dnsmessage.TypeA, 0)
	resp[2] |= 0x80 // QR
	r.noAnswer(resp)
	if n := r.up.count(); n != 0 {
		t.Errorf("the upstream got %d queries", n)
	}
	// The forwarder still works.
	r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))
}

// ---------------------------------------------------------------------------
// Failures and the fallback
// ---------------------------------------------------------------------------

// When the DNS-over-HTTPS endpoints fail and there is no fallback, the answer
// is SERVFAIL: the forwarder never resolves anything itself.
func TestUpstreamFailureIsSERVFAIL(t *testing.T) {
	r := startForwarder(t, failingUpstream(&doh.Error{Attempts: []error{errors.New("down")}}), nil, nil)
	for _, edns := range []int{0, 1232} {
		m := r.udp(mkQuery(t, 3, "www.example.com.", dnsmessage.TypeA, edns))
		if m.RCode != dnsmessage.RCodeServerFailure || m.ID != 3 || len(m.Questions) != 1 || len(m.Answers) != 0 {
			t.Errorf("EDNS %d: answer = %+v, want SERVFAIL with the question", edns, m)
		}
	}
	if ms := r.tcp(mkQuery(t, 4, "www.example.com.", dnsmessage.TypeA, 0)); ms[0].RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("TCP: %v, want SERVFAIL", ms[0].RCode)
	}
}

// An answer the forwarder takes says NOERROR or NXDOMAIN; anything else from the
// upstream is a failure of it.
func TestUpstreamErrorAnswersAreFailures(t *testing.T) {
	for _, rc := range []dnsmessage.RCode{dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused, dnsmessage.RCodeFormatError, dnsmessage.RCodeNotImplemented} {
		up := newUpstream(func(q dnsmessage.Message) (dnsmessage.Message, error) { return reply(q, rc, nil, nil), nil })
		r := startForwarder(t, up, nil, nil)
		if m := r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0)); m.RCode != dnsmessage.RCodeServerFailure {
			t.Errorf("upstream %v: answer %v, want SERVFAIL", rc, m.RCode)
		}
	}
	// An answer to another question is no answer.
	up := newUpstream(func(q dnsmessage.Message) (dnsmessage.Message, error) {
		q.Questions = []dnsmessage.Question{question("other.example.com.", dnsmessage.TypeA)}
		return zone(q), nil
	})
	r := startForwarder(t, up, nil, nil)
	if m := r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0)); m.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("an answer to another question: %v, want SERVFAIL", m.RCode)
	}
}

// stub is a nameserver of the host: UDP, TCP or both on one port of 127.0.0.1.
type stub struct {
	addr     netip.AddrPort
	udpHits  atomic.Int32
	tcpHits  atomic.Int32
	answer   func(q dnsmessage.Message, tcp bool) [][]byte // the datagrams (UDP) or the message (TCP) to send
	closeFns []func()
}

func startStub(t *testing.T, withUDP, withTCP bool, answer func(q dnsmessage.Message, tcp bool) [][]byte) *stub {
	t.Helper()
	s := &stub{answer: answer}
	for range 20 {
		// One port for both: a UDP port first, then TCP on it if that is free.
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			_ = pc.Close()
			continue
		}
		s.addr = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
		if withUDP {
			go s.serveUDP(pc)
			s.closeFns = append(s.closeFns, func() { _ = pc.Close() })
		} else {
			_ = pc.Close()
		}
		if withTCP {
			go s.serveTCP(ln)
			s.closeFns = append(s.closeFns, func() { _ = ln.Close() })
		} else {
			_ = ln.Close()
		}
		t.Cleanup(func() {
			for _, f := range s.closeFns {
				f()
			}
		})
		return s
	}
	t.Fatal("no port free for UDP and TCP at once")
	return nil
}

func (s *stub) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		s.udpHits.Add(1)
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil {
			continue
		}
		for _, d := range s.answer(q, false) {
			_, _ = pc.WriteTo(d, from)
		}
	}
}

func (s *stub) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(ioWait))
			b, err := readTCPMessage(c)
			if err != nil {
				return
			}
			s.tcpHits.Add(1)
			var q dnsmessage.Message
			if q.Unpack(b) != nil {
				return
			}
			for _, d := range s.answer(q, true) {
				var out bytes.Buffer
				_ = binary.Write(&out, binary.BigEndian, uint16(len(d)))
				out.Write(d)
				_, _ = c.Write(out.Bytes())
			}
		}()
	}
}

// fromZoneStub answers from the zone, with the A record of www.example.com
// changed to tell the stub's answers apart.
func fromZoneStub(q dnsmessage.Message, _ bool) [][]byte {
	m := zone(q)
	if strings.EqualFold(q.Questions[0].Name.String(), "www.example.com.") && q.Questions[0].Type == dnsmessage.TypeA {
		m.Answers = []dnsmessage.Resource{rrA("www.example.com.", "203.0.113.53", 60)}
	}
	b, _ := m.Pack()
	return [][]byte{b}
}

func TestFallbackToTheHostsNameserver(t *testing.T) {
	s := startStub(t, true, true, fromZoneStub)
	r := startForwarder(t, failingUpstream(errors.New("doh is blocked")), []string{s.addr.String()}, nil)
	m := r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))
	if a, _ := firstA(t, m); a != netip.MustParseAddr("203.0.113.53") {
		t.Errorf("answer %s, want the one of the host's nameserver", a)
	}
	if s.udpHits.Load() != 1 || s.tcpHits.Load() != 0 {
		t.Errorf("the nameserver got %d UDP and %d TCP queries, want 1 and 0", s.udpHits.Load(), s.tcpHits.Load())
	}
	if r.up.count() != 1 {
		t.Errorf("DNS-over-HTTPS was asked %d times, want 1: it comes first", r.up.count())
	}
}

// The nameservers of the host are asked only when DNS-over-HTTPS fails.
func TestNoFallbackWhileDoHAnswers(t *testing.T) {
	s := startStub(t, true, true, fromZoneStub)
	r := startForwarder(t, fromZone(), []string{s.addr.String()}, nil)
	if a, _ := firstA(t, r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))); a != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("answer %s, want the one of DNS-over-HTTPS", a)
	}
	if s.udpHits.Load()+s.tcpHits.Load() != 0 {
		t.Error("the host's nameserver was asked although DNS-over-HTTPS answered")
	}
}

// A truncated answer over UDP is asked for again over TCP.
func TestFallbackTruncatedGoesToTCP(t *testing.T) {
	s := startStub(t, true, true, func(q dnsmessage.Message, tcp bool) [][]byte {
		m := zone(q)
		if !tcp {
			m.Truncated, m.Answers = true, nil
		}
		b, _ := m.Pack()
		return [][]byte{b}
	})
	r := startForwarder(t, failingUpstream(errors.New("down")), []string{s.addr.String()}, nil)
	m := r.tcp(mkQuery(t, 1, "big.example.com.", dnsmessage.TypeA, 0))[0]
	if len(m.Answers) != bigCount {
		t.Errorf("%d records, want the %d of the TCP answer", len(m.Answers), bigCount)
	}
	if s.udpHits.Load() != 1 || s.tcpHits.Load() != 1 {
		t.Errorf("UDP %d, TCP %d; want 1 and 1", s.udpHits.Load(), s.tcpHits.Load())
	}
}

// When UDP does not get through, TCP is tried.
func TestFallbackTCPWhenUDPFails(t *testing.T) {
	s := startStub(t, false, true, fromZoneStub) // no UDP: the port refuses
	r := startForwarder(t, failingUpstream(errors.New("down")), []string{s.addr.String()}, func(l *limits) {
		l.exchangeTimeout = 300 * time.Millisecond
	})
	if a, _ := firstA(t, r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))); a != netip.MustParseAddr("203.0.113.53") {
		t.Errorf("answer %s, want the one of the host's nameserver over TCP", a)
	}
	if s.tcpHits.Load() != 1 {
		t.Errorf("TCP %d, want 1", s.tcpHits.Load())
	}
}

// A datagram with another ID, or for another question, is not the answer: it
// is ignored, and the real answer that follows is taken.
func TestFallbackIgnoresAnswersThatAreNotOurs(t *testing.T) {
	s := startStub(t, true, false, func(q dnsmessage.Message, _ bool) [][]byte {
		wrongID := zone(q)
		wrongID.ID++
		wrongQ := zone(q)
		wrongQ.Questions = []dnsmessage.Question{question("other.example.com.", dnsmessage.TypeA)}
		right := zone(q)
		right.Answers = []dnsmessage.Resource{rrA("www.example.com.", "203.0.113.54", 60)}
		var out [][]byte
		for _, m := range []dnsmessage.Message{wrongID, wrongQ, right} {
			b, _ := m.Pack()
			out = append(out, b)
		}
		return out
	})
	r := startForwarder(t, failingUpstream(errors.New("down")), []string{s.addr.String()}, nil)
	if a, _ := firstA(t, r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))); a != netip.MustParseAddr("203.0.113.54") {
		t.Errorf("answer %s, want the one with the right ID and question", a)
	}
}

// The nameservers are asked in order; when none answers, the answer is
// SERVFAIL, after the time each may take.
func TestFallbackFailsOverAndGivesUp(t *testing.T) {
	silent := startStub(t, true, false, func(dnsmessage.Message, bool) [][]byte { return nil })
	good := startStub(t, true, true, fromZoneStub)
	r := startForwarder(t, failingUpstream(errors.New("down")), []string{silent.addr.String(), good.addr.String()}, func(l *limits) {
		l.exchangeTimeout = 200 * time.Millisecond
	})
	if a, _ := firstA(t, r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))); a != netip.MustParseAddr("203.0.113.53") {
		t.Errorf("answer %s, want the one of the second nameserver", a)
	}

	r2 := startForwarder(t, failingUpstream(errors.New("down")), []string{silent.addr.String()}, func(l *limits) {
		l.exchangeTimeout = 200 * time.Millisecond
	})
	start := time.Now()
	if m := r2.udp(mkQuery(t, 2, "www.example.com.", dnsmessage.TypeA, 0)); m.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("answer %v, want SERVFAIL", m.RCode)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("SERVFAIL took %v", d)
	}
}

// DNS-over-HTTPS that does not answer within the hedge delay does not hold the
// client up: the host's nameserver is asked as well, and its answer is taken.
func TestHedgeAsksTheFallbackAfterTheDelay(t *testing.T) {
	up := fromZone()
	_, release := up.hold(4) // DNS-over-HTTPS never answers
	defer release()
	s := startStub(t, true, true, fromZoneStub)
	r := startForwarder(t, up, []string{s.addr.String()}, func(l *limits) { l.hedgeDelay = 100 * time.Millisecond })
	start := time.Now()
	m := r.udp(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))
	if a, _ := firstA(t, m); a != netip.MustParseAddr("203.0.113.53") {
		t.Errorf("answer %s, want the one of the host's nameserver", a)
	}
	if d := time.Since(start); d < 80*time.Millisecond || d > 2*time.Second {
		t.Errorf("the answer took %v, want about the hedge delay", d)
	}
	if n := up.count(); n != 1 {
		t.Errorf("DNS-over-HTTPS was asked %d times, want 1: it is asked first", n)
	}
	if got := defaultLimits().hedgeDelay; got != 1500*time.Millisecond {
		t.Errorf("the hedge delay is %v by default, want 1.5 s", got)
	}
}

// Once both sides are asked, the first good answer wins, whichever it is.
func TestHedgeTakesTheFirstGoodAnswer(t *testing.T) {
	up := fromZone()
	_, release := up.hold(4)
	defer release()
	silent := startStub(t, true, false, func(dnsmessage.Message, bool) [][]byte { return nil })
	r := startForwarder(t, up, []string{silent.addr.String()}, func(l *limits) {
		l.hedgeDelay = 50 * time.Millisecond
		l.exchangeTimeout = ioWait // the nameserver would keep the client waiting
	})
	q := mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0)
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := udpExchange(r.addr(), q, ioWait)
		done <- result{b, err}
	}()
	waitFor(t, "the host's nameserver to be asked", func() bool { return silent.udpHits.Load() >= 1 })
	start := time.Now()
	release() // DNS-over-HTTPS answers now
	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	if a, _ := firstA(t, unpack(t, res.b)); a != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("answer %s, want the one of DNS-over-HTTPS", a)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the answer came %v after DNS-over-HTTPS had it", d)
	}
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

func TestDefaultLimits(t *testing.T) {
	l := defaultLimits()
	if l.tcpConns != 16 || l.tcpIdle != 10*time.Second || l.inFlight != 256 || l.cacheEntries != 4096 {
		t.Errorf("limits = %+v, want 16 TCP connections, 10 s idle, 256 queries in flight, 4096 entries", l)
	}
	if maxTTL != 300 || negativeTTL != 30 || failTTL != 1 {
		t.Errorf("TTLs %d, %d and %d, want 300, 30 and 1", maxTTL, negativeTTL, failTTL)
	}
	if maxCachedAnswer != 8<<10 || l.cacheBytes != 16<<20 || l.hedgeDelay != 1500*time.Millisecond {
		t.Errorf("the cache keeps answers of %d bytes, %d in all, and hedges after %v; want 8 KiB, 16 MiB, 1.5 s",
			maxCachedAnswer, l.cacheBytes, l.hedgeDelay)
	}
	if ListenAddr != "127.0.0.2:53" {
		t.Errorf("ListenAddr = %q", ListenAddr)
	}
}

// Identical questions in flight make one upstream query; every client gets its
// answer with its own ID.
func TestIdenticalQuestionsShareOneUpstreamQuery(t *testing.T) {
	up := fromZone()
	entered, release := up.hold(16)
	r := startForwarder(t, up, nil, nil)
	type result struct {
		id  uint16
		err error
	}
	results := make(chan result, 5)
	for i := range 5 {
		q := mkQuery(t, uint16(100+i), "www.example.com.", dnsmessage.TypeA, 0)
		go func() {
			b, err := udpExchange(r.addr(), q, ioWait)
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{id: binary.BigEndian.Uint16(b)}
		}()
	}
	<-entered
	waitFor(t, "the other four clients to wait for the question in flight", func() bool { return r.f.joined() == 4 })
	if n := up.count(); n != 1 {
		t.Errorf("the upstream got %d queries for one question in flight, want 1", n)
	}
	release()
	var ids []uint16
	for range 5 {
		res := <-results
		if res.err != nil {
			t.Fatal(res.err)
		}
		ids = append(ids, res.id)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []uint16{100, 101, 102, 103, 104}) {
		t.Errorf("answers with the IDs %v", ids)
	}
}

// Over the cap of questions in flight, a new question gets SERVFAIL at once.
func TestInFlightQueriesAreCapped(t *testing.T) {
	up := fromZone()
	entered, release := up.hold(16)
	defer release()
	r := startForwarder(t, up, nil, func(l *limits) { l.inFlight = 3 })

	conn, err := net.Dial("udp", r.addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for i := range 3 {
		if _, err := conn.Write(mkQuery(t, uint16(i), fmt.Sprintf("q%d.example.com.", i), dnsmessage.TypeA, 0)); err != nil {
			t.Fatal(err)
		}
		<-entered
	}
	start := time.Now()
	m := r.udp(mkQuery(t, 99, "q99.example.com.", dnsmessage.TypeA, 0))
	if m.RCode != dnsmessage.RCodeServerFailure || time.Since(start) > time.Second {
		t.Errorf("over the cap: %v after %v, want SERVFAIL at once", m.RCode, time.Since(start))
	}
	// A question in flight takes a new client without a new upstream query.
	release()
	_ = conn.SetDeadline(time.Now().Add(ioWait))
	buf := make([]byte, 65535)
	for range 3 {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("the questions in flight got no answer: %v", err)
		}
		if m := unpack(t, buf[:n]); m.RCode != dnsmessage.RCodeSuccess {
			t.Errorf("answer %v", m.RCode)
		}
	}
}

// At most 16 TCP connections at a time: the next one is closed at once.
func TestTCPConnectionsAreCapped(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	var held []net.Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := range 16 {
		c, err := net.Dial("tcp", r.addr().String())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		// Each is served: it answers.
		if i == 15 {
			_ = c.SetDeadline(time.Now().Add(ioWait))
			q := mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0)
			_ = binary.Write(c, binary.BigEndian, uint16(len(q)))
			_, _ = c.Write(q)
			if _, err := readTCPMessage(c); err != nil {
				t.Fatalf("the 16th connection got no answer: %v", err)
			}
		}
	}
	extra, err := net.Dial("tcp", r.addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = extra.Close() }()
	_ = extra.SetReadDeadline(time.Now().Add(ioWait))
	if _, err := extra.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Errorf("the 17th connection: %v, want it closed", err)
	}
	// One goes, and there is room again.
	_ = held[0].Close()
	held = held[1:]
	deadline := time.Now().Add(ioWait)
	for {
		ms, err := tryTCP(r.addr(), mkQuery(t, 2, "www.example.com.", dnsmessage.TypeA, 0))
		if err == nil {
			if ms.RCode != dnsmessage.RCodeSuccess {
				t.Errorf("answer %v", ms.RCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no room for a connection after one closed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func isReset(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "broken pipe"))
}

func tryTCP(addr netip.AddrPort, q []byte) (dnsmessage.Message, error) {
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint16(len(q)))
	out.Write(q)
	if _, err := c.Write(out.Bytes()); err != nil {
		return dnsmessage.Message{}, err
	}
	b, err := readTCPMessage(c)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var m dnsmessage.Message
	return m, m.Unpack(b)
}

// A TCP connection that says nothing for the idle time is closed.
func TestIdleTCPConnectionsAreClosed(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, func(l *limits) { l.tcpIdle = 150 * time.Millisecond })
	c, err := net.Dial("tcp", r.addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(ioWait))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Errorf("read %v, want the connection closed", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("closed after %v, want about the idle time", d)
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestCheckConfig(t *testing.T) {
	good := []*edgev1.Dns{
		nil,
		{},
		{Enabled: false, DohUrls: []string{"not checked when disabled"}},
		{Enabled: true},
		{Enabled: true, DohUrls: doh.DefaultEndpoints},
		{Enabled: true, DohUrls: []string{"https://[2001:db8::1]/dns-query", "https://192.0.2.1:8443/q"}},
		{Enabled: true, Fallback: []string{"192.0.2.53", "127.0.0.53", "2001:db8::53", "2001:db8::54%eth0", "127.0.0.1:5353", "[2001:db8::53]:5353"}},
	}
	for i, c := range good {
		if err := CheckConfig(c); err != nil {
			t.Errorf("good config %d: %v", i, err)
		}
	}
	bad := map[string]*edgev1.Dns{
		"http":              {Enabled: true, DohUrls: []string{"http://192.0.2.1/dns-query"}},
		"a host name":       {Enabled: true, DohUrls: []string{"https://dns.example.com/dns-query"}},
		"credentials":       {Enabled: true, DohUrls: []string{"https://user:pw@192.0.2.1/dns-query"}},
		"not a URL":         {Enabled: true, DohUrls: []string{"::"}},
		"an empty URL":      {Enabled: true, DohUrls: []string{""}},
		"a name":            {Enabled: true, Fallback: []string{"ns.example.com"}},
		"no port":           {Enabled: true, Fallback: []string{"192.0.2.1:"}},
		"the forwarder":     {Enabled: true, Fallback: []string{"127.0.0.2"}},
		"the forwarder:53":  {Enabled: true, Fallback: []string{"127.0.0.2:53"}},
		"an empty fallback": {Enabled: true, Fallback: []string{""}},
		"port zero":         {Enabled: true, Fallback: []string{"192.0.2.1:0"}},
	}
	for name, c := range bad {
		if err := CheckConfig(c); err == nil {
			t.Errorf("%s: CheckConfig accepted %v", name, c)
		}
	}
}

func TestApplyStartsAndStopsTheForwarder(t *testing.T) {
	up := fromZone()
	var made atomic.Int32
	f := New(quiet, Options{Addr: "127.0.0.1:0", Now: newClock().Now, NewUpstream: func([]string) Upstream {
		made.Add(1)
		return up
	}})
	defer f.Close()

	if err := f.Apply(nil); err != nil || f.Running() {
		t.Fatalf("Apply(nil) = %v, running %v; want nothing running", err, f.Running())
	}
	if err := f.Apply(&edgev1.Dns{Enabled: true}); err != nil || !f.Running() {
		t.Fatalf("Apply(enabled) = %v, running %v", err, f.Running())
	}
	addr := f.Addr()
	if b, err := udpExchange(addr, mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0), ioWait); err != nil || unpack(t, b).RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("query: %v", err)
	}

	// The same configuration again changes nothing; a new fallback keeps the
	// sockets and makes a new upstream only when the endpoints change.
	if err := f.Apply(&edgev1.Dns{Enabled: true}); err != nil || f.Addr() != addr || made.Load() != 1 {
		t.Errorf("same config: %v, addr %v (was %v), %d upstreams", err, f.Addr(), addr, made.Load())
	}
	if err := f.Apply(&edgev1.Dns{Enabled: true, Fallback: []string{"192.0.2.53"}}); err != nil || f.Addr() != addr {
		t.Errorf("new fallback: %v, addr %v (was %v)", err, f.Addr(), addr)
	}
	if err := f.Apply(&edgev1.Dns{Enabled: true, DohUrls: []string{testDoHURL}, Fallback: []string{"192.0.2.53"}}); err != nil || made.Load() != 2 {
		t.Errorf("new endpoints: %v, %d upstreams, want 2", err, made.Load())
	}

	// A bad configuration is refused, and the forwarder goes on as it was.
	if err := f.Apply(&edgev1.Dns{Enabled: true, DohUrls: []string{"http://192.0.2.1/"}}); err == nil || !f.Running() {
		t.Errorf("bad config: %v, running %v", err, f.Running())
	}

	if err := f.Apply(&edgev1.Dns{}); err != nil || f.Running() {
		t.Fatalf("Apply(disabled) = %v, running %v", err, f.Running())
	}
	if _, err := udpExchange(addr, mkQuery(t, 2, "www.example.com.", dnsmessage.TypeA, 0), 300*time.Millisecond); err == nil {
		t.Error("an answer after the forwarder was disabled")
	}

	f.Close()
	if err := f.Apply(&edgev1.Dns{Enabled: true}); err == nil || f.Running() {
		t.Errorf("Apply after Close = %v, running %v", err, f.Running())
	}
}

// When the address is taken, Apply says so and the forwarder does not run; the
// next Apply tries again.
func TestApplyWhenTheAddressIsTaken(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	f := New(quiet, Options{Addr: addr, NewUpstream: func([]string) Upstream { return fromZone() }})
	defer f.Close()
	if err := f.Apply(&edgev1.Dns{Enabled: true}); err == nil || f.Running() {
		t.Fatalf("Apply on a taken address = %v, running %v", err, f.Running())
	}
	_ = ln.Close()
	if err := f.Apply(&edgev1.Dns{Enabled: true}); err != nil || !f.Running() {
		t.Errorf("Apply once the address is free = %v, running %v", err, f.Running())
	}
}

// The default upstream is the DNS-over-HTTPS client of the default endpoints
// when the configuration names none.
func TestDefaultEndpoints(t *testing.T) {
	var got []string
	f := New(quiet, Options{Addr: "127.0.0.1:0", NewUpstream: func(urls []string) Upstream {
		got = slices.Clone(urls)
		return fromZone()
	}})
	defer f.Close()
	if err := f.Apply(&edgev1.Dns{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, doh.DefaultEndpoints) {
		t.Errorf("upstream made for %q, want the defaults %q", got, doh.DefaultEndpoints)
	}
	if _, ok := defaultUpstream([]string{testDoHURL}).(*doh.Client); !ok {
		t.Error("the default upstream is not the DNS-over-HTTPS client")
	}
}

// The edge generation that takes over binds the address of the one that drains
// while it is still bound (SO_REUSEPORT): both answer, and when the old one has
// gone the new one answers alone, over UDP and TCP.
func TestTwoForwardersShareOneAddress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_REUSEPORT is set on Linux only")
	}
	old := startForwarder(t, fromZone(), nil, nil)
	addr := old.addr()
	next := New(quiet, Options{Addr: addr.String(), Now: newClock().Now, NewUpstream: func([]string) Upstream { return fromZone() }})
	t.Cleanup(next.Close)
	if err := next.Apply(&edgev1.Dns{Enabled: true, DohUrls: []string{testDoHURL}}); err != nil {
		t.Fatalf("the second forwarder cannot bind %s while the first holds it: %v", addr, err)
	}
	if next.Addr() != addr {
		t.Fatalf("the second forwarder is bound to %s, want %s", next.Addr(), addr)
	}
	ask := func(what string) {
		t.Helper()
		for i := range 20 {
			b, err := udpExchange(addr, mkQuery(t, uint16(i), "www.example.com.", dnsmessage.TypeA, 0), ioWait)
			if err != nil {
				t.Fatalf("%s: UDP query %d: %v", what, i, err)
			}
			if m := unpack(t, b); m.RCode != dnsmessage.RCodeSuccess {
				t.Fatalf("%s: UDP query %d: %v", what, i, m.RCode)
			}
		}
		if m, err := tryTCP(addr, mkQuery(t, 99, "www.example.com.", dnsmessage.TypeA, 0)); err != nil || m.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("%s: TCP query: %v, %v", what, err, m.RCode)
		}
	}
	ask("both bound")
	old.f.Close()
	ask("after the first one closed")
}

// ---------------------------------------------------------------------------
// The resolver of the edge
// ---------------------------------------------------------------------------

// While the forwarder runs, its resolver asks it; when it stops, the resolver
// goes back to the nameservers of the system.
func TestResolverFollowsTheForwarder(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	if got := r.f.sw.Target(); got != r.addr().String() {
		t.Fatalf("the resolver goes to %q, want the forwarder %s", got, r.addr())
	}
	ctx, cancel := context.WithTimeout(context.Background(), ioWait)
	defer cancel()
	addrs, err := r.f.Resolver().LookupNetIP(ctx, "ip4", "www.example.com")
	if err != nil || !slices.Equal(addrs, []netip.Addr{netip.MustParseAddr("192.0.2.10")}) {
		t.Errorf("LookupNetIP = %v, %v; want the answer of the forwarder", addrs, err)
	}
	if err := r.f.Apply(&edgev1.Dns{}); err != nil {
		t.Fatal(err)
	}
	if got := r.f.sw.Target(); got != "" {
		t.Errorf("after the forwarder stopped the resolver goes to %q, want the system's nameservers", got)
	}
}

func TestSwitch(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	sw := NewSwitch()
	if sw.Target() != "" {
		t.Errorf("a new switch goes to %q", sw.Target())
	}
	if !sw.Use(r.addr().String()) || sw.Use(r.addr().String()) {
		t.Error("Use does not report the change, or reports one where there is none")
	}
	ctx, cancel := context.WithTimeout(context.Background(), ioWait)
	defer cancel()
	addrs, err := sw.Resolver().LookupNetIP(ctx, "ip4", "www.example.com")
	if err != nil || !slices.Equal(addrs, []netip.Addr{netip.MustParseAddr("192.0.2.10")}) {
		t.Errorf("LookupNetIP = %v, %v", addrs, err)
	}
	if !sw.Use("") || sw.Target() != "" {
		t.Errorf("Use(\"\") does not go back to the system's nameservers")
	}
}

// ---------------------------------------------------------------------------
// The nameservers of the host
// ---------------------------------------------------------------------------

func TestNameservers(t *testing.T) {
	conf := `# written by hand
nameserver 192.0.2.53
nameserver 127.0.0.2
search example.com
nameserver	2001:db8::53   # a comment
nameserver 192.0.2.53
nameserver not-an-address
nameserver 192.0.2.54:53
options ndots:2 timeout:1
; nameserver 198.51.100.1
nameserver 2001:db8::54%eth0
nameserver 127.0.0.53
`
	got := Nameservers([]byte(conf))
	want := []string{"192.0.2.53", "2001:db8::53", "2001:db8::54%eth0"}
	if !slices.Equal(got, want) {
		t.Errorf("Nameservers = %q, want %q (the first three usable ones, not the forwarder)", got, want)
	}
	if got := Nameservers([]byte("nameserver 127.0.0.53\n")); !slices.Equal(got, []string{"127.0.0.53"}) {
		t.Errorf("the stub of systemd-resolved: %q", got)
	}
	if got := Nameservers(nil); len(got) != 0 {
		t.Errorf("an empty file: %q", got)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := HostNameservers(path); !slices.Equal(got, want) {
		t.Errorf("HostNameservers = %q", got)
	}
	if got := HostNameservers(filepath.Join(dir, "missing")); got != nil {
		t.Errorf("HostNameservers of a missing file = %q, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// Goroutines
// ---------------------------------------------------------------------------

// Close ends every goroutine of the forwarder, also those that wait for an
// upstream that does not answer.
func TestCloseEndsEveryGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	up := fromZone()
	entered, release := up.hold(4)
	defer release()
	r := startForwarder(t, up, nil, nil)
	conn, err := net.Dial("udp", r.addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write(mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0))
	<-entered
	tc, err := net.Dial("tcp", r.addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()

	done := make(chan struct{})
	go func() {
		r.f.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(ioWait):
		t.Fatal("Close did not return")
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+1 { // +1: the goroutine of Close may still be on its way out
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%d goroutines before, %d after Close:\n%s", before, runtime.NumGoroutine(), buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Round 2 of the review
// ---------------------------------------------------------------------------

// panicky is an upstream with a bug: it panics.
type panicky struct{}

func (panicky) Exchange(context.Context, []byte) ([]byte, error) { panic("a bug in the upstream") }

// A panic while an upstream is asked is that upstream's failure, logged with
// its stack: the forwarder, and the edge it runs in, go on.
func TestAPanickingUpstreamIsAFailure(t *testing.T) {
	logs := &syncBuf{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	s := startStub(t, true, true, fromZoneStub)
	f := New(log, Options{Addr: "127.0.0.1:0", NewUpstream: func([]string) Upstream { return panicky{} }})
	t.Cleanup(f.Close)
	if err := f.Apply(&edgev1.Dns{Enabled: true, DohUrls: []string{testDoHURL}, Fallback: []string{s.addr.String()}}); err != nil {
		t.Fatal(err)
	}
	b, err := udpExchange(f.Addr(), mkQuery(t, 1, "www.example.com.", dnsmessage.TypeA, 0), ioWait)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if a, _ := firstA(t, unpack(t, b)); a != netip.MustParseAddr("203.0.113.53") {
		t.Errorf("answer %s, want the one of the host's nameserver", a)
	}
	if text := logs.String(); !strings.Contains(text, "panic") || !strings.Contains(text, "a bug in the upstream") || !strings.Contains(text, "goroutine") {
		t.Errorf("the panic is not logged with its stack:\n%s", text)
	}
	// A bug that strikes every question is logged as the other warnings are:
	// once in a while, not for every question.
	for i := range 4 {
		if _, err := udpExchange(f.Addr(), mkQuery(t, uint16(10+i), fmt.Sprintf("p%d.example.com.", i), dnsmessage.TypeA, 0), ioWait); err != nil {
			t.Fatalf("question %d: no answer: %v", i, err)
		}
	}
	if n := strings.Count(logs.String(), "panic while asking an upstream"); n != 1 {
		t.Errorf("the panic is logged %d times for 5 questions, want once", n)
	}

	// Without a fallback the answer is SERVFAIL, and the forwarder still works.
	g := New(quiet, Options{Addr: "127.0.0.1:0", NewUpstream: func([]string) Upstream { return panicky{} }})
	t.Cleanup(g.Close)
	if err := g.Apply(&edgev1.Dns{Enabled: true, DohUrls: []string{testDoHURL}}); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		b, err := udpExchange(g.Addr(), mkQuery(t, uint16(i), fmt.Sprintf("q%d.example.com.", i), dnsmessage.TypeA, 0), ioWait)
		if err != nil {
			t.Fatalf("query %d: no answer: %v", i, err)
		}
		if m := unpack(t, b); m.RCode != dnsmessage.RCodeServerFailure {
			t.Errorf("query %d: %v, want SERVFAIL", i, m.RCode)
		}
	}
}

// A side of a lookup frees what it holds, its DNS-over-HTTPS slot, before it
// sends its outcome, also when it panics: the lookup that takes the outcome,
// and the question after it, find the slot free.
func TestASideFreesWhatItHoldsBeforeItsOutcome(t *testing.T) {
	s := &server{f: New(quiet, Options{Addr: "127.0.0.1:0"})}
	defer s.wg.Wait()
	for _, c := range []struct {
		name string
		ask  func(context.Context) (*entry, error)
	}{
		{"a failure", func(context.Context) (*entry, error) { return nil, errors.New("no answer") }},
		{"a panic", func(context.Context) (*entry, error) { panic("a bug in the upstream") }},
	} {
		results := make(chan outcome, 1)
		freed := make(chan int, 1)
		s.askSide(context.Background(), "test", c.ask, func() { freed <- len(results) }, results)
		if n := <-freed; n != 0 {
			t.Errorf("%s: the outcome was sent before the side freed what it holds", c.name)
		}
		if o := <-results; o.err == nil {
			t.Errorf("%s: the outcome has no error", c.name)
		}
	}
}

// syncBuf collects log output from many goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *syncBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *syncBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// gatedListener is a TCP listener that, until it opens, takes connections and
// never says a word: a DNS-over-HTTPS endpoint that a network black-holes, as
// the client sees it. Once open, Accept returns the connections that come.
type gatedListener struct {
	net.Listener
	open     chan struct{}
	accepted atomic.Int32
	mu       sync.Mutex
	held     []net.Conn
}

func newGatedListener(t *testing.T) *gatedListener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &gatedListener{Listener: ln, open: make(chan struct{})}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.accepted.Add(1)
		select {
		case <-l.open:
			return c, nil
		default:
			l.mu.Lock()
			l.held = append(l.held, c)
			l.mu.Unlock()
		}
	}
}

func (l *gatedListener) Close() error {
	err := l.Listener.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.held {
		_ = c.Close()
	}
	l.held = nil
	return err
}

func (l *gatedListener) url() string { return "https://" + l.Addr().String() + "/dns-query" }

// blackHole is a gated listener that never opens, accepting in the background.
func blackHole(t *testing.T) *gatedListener {
	t.Helper()
	l := newGatedListener(t)
	go func() {
		for {
			if _, err := l.Accept(); err != nil {
				return
			}
		}
	}()
	return l
}

// The DNS-over-HTTPS attempt that the nameservers of the host beat is not cut
// short: it runs on to its own timeouts, so that the real client moves on past
// the black-holed endpoint, and the next question begins at the next endpoint.
// When an endpoint answers, DNS-over-HTTPS is used again.
func TestTheLosingDoHAttemptMovesTheClientOn(t *testing.T) {
	// Endpoints 0 and 1 are black holes; endpoint 2 is one too until it opens,
	// and then answers as a DNS-over-HTTPS endpoint would.
	dead0, dead1 := blackHole(t), blackHole(t)
	var dohHits atomic.Int32
	answering := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dohHits.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
		var q dnsmessage.Message
		if q.Unpack(body) != nil || len(q.Questions) != 1 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		m := reply(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA(q.Questions[0].Name.String(), "192.0.2.10", 60)}, nil)
		wire, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	gate := newGatedListener(t)
	answering.Listener = gate
	answering.StartTLS()
	t.Cleanup(answering.Close)
	pool := x509.NewCertPool()
	pool.AddCert(answering.Certificate())
	endpoint2 := gate.url()

	stub := startStub(t, true, true, func(q dnsmessage.Message, _ bool) [][]byte {
		m := reply(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA(q.Questions[0].Name.String(), "203.0.113.53", 60)}, nil)
		b, _ := m.Pack()
		return [][]byte{b}
	})
	opts := Options{Addr: "127.0.0.1:0", NewUpstream: func(urls []string) Upstream { return doh.NewWithRoots(urls, pool) }}
	// The hedge gives DNS-over-HTTPS 2 s, of which a local endpoint needs a
	// fraction, also with the race detector on a busy machine; the client
	// waits 3 s for an endpoint that says nothing. Nothing else depends on
	// time: each step waits for what the endpoints see.
	opts.limits.hedgeDelay = 2 * time.Second
	f := New(quiet, opts)
	t.Cleanup(f.Close)
	if err := f.Apply(&edgev1.Dns{Enabled: true, DohUrls: []string{dead0.url(), dead1.url(), endpoint2}, Fallback: []string{stub.addr.String()}}); err != nil {
		t.Fatal(err)
	}
	ask := func(qname string) netip.Addr {
		t.Helper()
		b, err := udpExchange(f.Addr(), mkQuery(t, 1, qname, dnsmessage.TypeA, 0), ioWait)
		if err != nil {
			t.Fatalf("%s: no answer: %v", qname, err)
		}
		a, _ := firstA(t, unpack(t, b))
		return a
	}

	// No endpoint answers: the host's nameserver does.
	if a := ask("one.example.com."); a != netip.MustParseAddr("203.0.113.53") {
		t.Fatalf("first question: %s, want the host's nameserver's answer", a)
	}
	// The client gave up on endpoint 0 by its own timeout (3 s) and went on to
	// endpoint 1, although the question had its answer before.
	waitLong(t, "the attempt at endpoint 1", func() bool { return dead1.accepted.Load() >= 1 })

	// Endpoint 2 answers from now on. The next question begins at endpoint 1,
	// not at the black hole 0 again, and its attempt goes on to endpoint 2.
	close(gate.open)
	ask("two.example.com.")
	waitLong(t, "the second question at endpoint 1", func() bool { return dead1.accepted.Load() >= 2 })
	if n := dead0.accepted.Load(); n != 1 {
		t.Errorf("endpoint 0 was tried %d times, want once: the next question begins past it", n)
	}
	waitLong(t, "an answer of endpoint 2", func() bool { return dohHits.Load() >= 1 })

	// The client stays with endpoint 2: the questions get the answers of
	// DNS-over-HTTPS again, and the host's nameserver is not asked.
	before := stub.udpHits.Load()
	if a := ask("three.example.com."); a != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("third question: %s, want the answer of DNS-over-HTTPS", a)
	}
	if n := stub.udpHits.Load() - before; n != 0 {
		t.Errorf("third question: %d questions to the host's nameserver, want none", n)
	}
}

// waitLong polls cond for 15 s at the most: the real client waits 3 s per
// endpoint.
func waitLong(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The DNS-over-HTTPS attempts that run on after their question has its answer
// are bounded: with every slot taken, the nameservers of the host are asked at
// once, without DNS-over-HTTPS.
func TestTheDoHAttemptsThatRunOnAreBounded(t *testing.T) {
	up := fromZone()
	entered, release := up.hold(8)
	defer release()
	s := startStub(t, true, true, fromZoneStub)
	r := startForwarder(t, up, []string{s.addr.String()}, func(l *limits) {
		l.inFlight = 2
		l.hedgeDelay = 50 * time.Millisecond
	})
	for i := range 2 {
		if a, _ := firstA(t, r.udp(mkQuery(t, uint16(i), "www.example.com.", dnsmessage.TypeA, 0))); a != netip.MustParseAddr("203.0.113.53") {
			t.Fatalf("question %d: %s", i, a)
		}
		<-entered
		r.clock.Advance(time.Hour) // the cached answer is gone for the next question
	}
	if n := up.count(); n != 2 {
		t.Fatalf("DNS-over-HTTPS was asked %d times, want 2", n)
	}
	// Both slots are taken by attempts that run on: the third question goes to
	// the nameservers at once.
	if a, _ := firstA(t, r.udp(mkQuery(t, 3, "www.example.com.", dnsmessage.TypeA, 0))); a != netip.MustParseAddr("203.0.113.53") {
		t.Errorf("third question: %s", a)
	}
	if n := up.count(); n != 2 {
		t.Errorf("DNS-over-HTTPS was asked %d times with no slot free, want 2", n)
	}
	// When they end, DNS-over-HTTPS is asked again.
	release()
	waitFor(t, "the attempts that ran on to end", func() bool { return r.f.dohInUse() == 0 })
	r.clock.Advance(time.Hour)
	r.udp(mkQuery(t, 4, "www.example.com.", dnsmessage.TypeA, 0))
	if n := up.count(); n != 3 {
		t.Errorf("DNS-over-HTTPS was asked %d times after the slots came free, want 3", n)
	}
}

// dohInUse is the number of DNS-over-HTTPS attempts that run.
func (f *Forwarder) dohInUse() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.srv == nil {
		return 0
	}
	return len(f.srv.dohSlots)
}

// A NOERROR answer that is a CNAME chain without data at its end is a negative
// answer (NODATA, RFC 2308 2.2): kept for 30 s at the most by its SOA, not for
// the 300 s of a positive answer.
func TestACNAMEWithoutDataIsNegative(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	m := r.udp(mkQuery(t, 1, "cname.example.com.", dnsmessage.TypeA, 0))
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("answer = %+v", m)
	}
	if ttl := m.Answers[0].Header.TTL; ttl > 30 {
		t.Errorf("the CNAME has a TTL of %d, more than the 30 s a negative answer is kept", ttl)
	}
	r.clock.Advance(29 * time.Second)
	r.udp(mkQuery(t, 2, "cname.example.com.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 1 {
		t.Fatalf("after 29 s: %d upstream queries, want 1", n)
	}
	r.clock.Advance(time.Second)
	r.udp(mkQuery(t, 3, "cname.example.com.", dnsmessage.TypeA, 0))
	if n := r.up.count(); n != 2 {
		t.Errorf("after 30 s: %d upstream queries, want 2: the answer is negative", n)
	}
	// A question for the CNAME itself has its data.
	r.udp(mkQuery(t, 4, "cname.example.com.", dnsmessage.TypeCNAME, 0))
	r.clock.Advance(31 * time.Second)
	r.udp(mkQuery(t, 5, "cname.example.com.", dnsmessage.TypeCNAME, 0))
	if n := r.up.count(); n != 3 {
		t.Errorf("CNAME questions: %d upstream queries in all, want 3: the CNAME is data, kept beyond 30 s", n)
	}
}

func rrCNAME(owner, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(owner), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.CNAMEResource{CNAME: name(target)},
	}
}

// typed is rr with the type in its header, as a parsed answer has it.
func typed(rr dnsmessage.Resource, t dnsmessage.Type) dnsmessage.Resource {
	rr.Header.Type = t
	return rr
}

// The data of a question is a record of its type for its name or for the end of
// its CNAME chain, in any order and in any case; a loop or a chain of more than
// 16 CNAME records has none.
func TestHasData(t *testing.T) {
	a := func(owner string) dnsmessage.Resource { return typed(rrA(owner, "192.0.2.1", 60), dnsmessage.TypeA) }
	var long []dnsmessage.Resource
	for i := range 17 {
		long = append(long, rrCNAME(fmt.Sprintf("c%d.example.com.", i), fmt.Sprintf("c%d.example.com.", i+1)))
	}
	cases := []struct {
		name    string
		q       dnsmessage.Question
		answers []dnsmessage.Resource
		want    bool
	}{
		{"a record", question("www.example.com.", dnsmessage.TypeA), []dnsmessage.Resource{a("www.example.com.")}, true},
		{"another name", question("www.example.com.", dnsmessage.TypeA), []dnsmessage.Resource{a("mail.example.com.")}, false},
		{"another case", question("WWW.Example.com.", dnsmessage.TypeA), []dnsmessage.Resource{a("www.EXAMPLE.com.")}, true},
		{"nothing", question("www.example.com.", dnsmessage.TypeA), nil, false},
		{"a chain out of order", question("www.example.com.", dnsmessage.TypeA), []dnsmessage.Resource{
			a("c.example.com."), rrCNAME("b.example.com.", "c.example.com."), rrCNAME("www.example.com.", "b.example.com."),
		}, true},
		{"a chain without data", question("www.example.com.", dnsmessage.TypeA), []dnsmessage.Resource{
			rrCNAME("www.example.com.", "b.example.com."), a("elsewhere.example.com."),
		}, false},
		{"another type at the end", question("www.example.com.", dnsmessage.TypeAAAA), []dnsmessage.Resource{
			rrCNAME("www.example.com.", "b.example.com."), a("b.example.com."),
		}, false},
		{"the CNAME asked for", question("www.example.com.", dnsmessage.TypeCNAME), []dnsmessage.Resource{
			rrCNAME("www.example.com.", "b.example.com."),
		}, true},
		{"any", question("www.example.com.", dnsmessage.TypeALL), []dnsmessage.Resource{a("www.example.com.")}, true},
		{"a loop", question("a.example.com.", dnsmessage.TypeA), []dnsmessage.Resource{
			rrCNAME("a.example.com.", "b.example.com."), rrCNAME("b.example.com.", "a.example.com."),
		}, false},
		{"16 CNAME records", question("c1.example.com.", dnsmessage.TypeA), append(slices.Clone(long[1:]), a("c17.example.com.")), true},
		{"17 CNAME records", question("c0.example.com.", dnsmessage.TypeA), append(slices.Clone(long), a("c17.example.com.")), false},
	}
	for _, c := range cases {
		if got := hasData(c.answers, c.q); got != c.want {
			t.Errorf("%s: hasData = %v, want %v", c.name, got, c.want)
		}
	}

	// As many CNAME records as an answer holds, in reverse order: no time at all.
	var many []dnsmessage.Resource
	for i := 4000; i > 0; i-- {
		many = append(many, rrCNAME(fmt.Sprintf("c%d.example.com.", i-1), fmt.Sprintf("c%d.example.com.", i)))
	}
	start := time.Now()
	hasData(many, question("c0.example.com.", dnsmessage.TypeA))
	if d := time.Since(start); d > time.Second {
		t.Errorf("hasData took %v for %d CNAME records", d, len(many))
	}
}

// Additional records are dropped by whole RRsets: no answer leaves part of an
// RRset without TC.
func TestAdditionalRRsetsAreNotSplit(t *testing.T) {
	r := startForwarder(t, fromZone(), nil, nil)
	raw := r.udpRaw(mkQuery(t, 1, "glueset.example.com.", dnsmessage.TypeA, 0))
	m := unpack(t, raw)
	if len(raw) > 512 || m.Truncated || len(m.Answers) != 1 {
		t.Fatalf("%d bytes, TC %v, %d answers", len(raw), m.Truncated, len(m.Answers))
	}
	ns := 0
	for _, rr := range m.Additionals {
		if rr.Header.Name.String() == "ns.example.com." {
			ns++
		}
	}
	if ns != 0 && ns != bigCount {
		t.Errorf("%d of the %d records of the RRset of ns.example.com, want all or none", ns, bigCount)
	}
	if len(m.Additionals) != 1 || m.Additionals[0].Header.Name.String() != "a.example.com." {
		t.Errorf("additional records %v, want the RRset of a.example.com alone", m.Additionals)
	}
}

// The cache counts what an answer takes: the capacity of its bytes, which is
// their length, and an overhead for the rest.
func TestTheCacheCountsWhatAnAnswerTakes(t *testing.T) {
	q := question("www.example.com.", dnsmessage.TypeA)
	// The answer as the forwarder has it: packed by an upstream, and parsed.
	up := zone(dnsmessage.Message{Header: dnsmessage.Header{ID: 1, RecursionDesired: true}, Questions: []dnsmessage.Question{q}})
	b, err := up.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	e, err := newEntry(&m, q, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if cap(e.wire) != len(e.wire) {
		t.Errorf("the answer keeps %d bytes of capacity for %d of length", cap(e.wire), len(e.wire))
	}
	c := newCache(10, 1<<20)
	k := keyOf(q)
	c.put(k, e)
	if n, used := c.usage(); n != 1 || used != cap(e.wire)+len(k.name)+itemOverhead {
		t.Errorf("the cache holds %d entries in %d bytes, want 1 in %d", n, used, cap(e.wire)+len(k.name)+itemOverhead)
	}
	if itemOverhead < 256 {
		t.Errorf("an entry is counted %d bytes besides its answer and key, want 256 at least", itemOverhead)
	}
}
