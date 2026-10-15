// Package doh is a DNS-over-HTTPS client (RFC 8484).
//
// A query is a DNS message in wire format, POSTed as application/dns-message
// with its ID set to 0, and the answer is a DNS message as well. The endpoints
// are named by IP address, as DefaultEndpoints are, so that no name has to be
// looked up to reach them: the client never makes a lookup of
// its own, and refuses an endpoint whose host is a name. Their certificates
// are verified for that address against the roots of the system, with TLS 1.2
// at least, and the proxies of the environment are not used.
//
// The node needs this where UDP port 53 is blocked: the DNS forwarder of the
// edge asks these endpoints for the containers of the node, and the agent asks
// them for the names it needs itself.
package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DefaultEndpoints are the endpoints of the node: Cloudflare and Google, two
// addresses each, by IP address.
var DefaultEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://1.0.0.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://8.8.4.4/dns-query",
}

// Timeout bounds one request to an endpoint: the connection, the TLS handshake,
// the question and the answer. A query goes to two endpoints at the most, so a
// caller of Exchange or of the lookups waits 2 x Timeout = 6 s at the most. The
// DNS forwarder of the edge does not keep its clients waiting that long: it asks
// the host's nameservers as well when an endpoint has not answered in 1.5 s.
const Timeout = 3 * time.Second

const (
	// maxAttempts is the most endpoints a query is sent to.
	maxAttempts = 2
	// maxMessage is the longest DNS message: its length is a 16-bit number.
	maxMessage = 65535
	// mediaType is the type of a DNS message in wire format (RFC 8484 6).
	mediaType = "application/dns-message"
)

// ErrNoEndpoints is the error of a query of a client without endpoints.
var ErrNoEndpoints = errors.New("doh: no endpoints")

// Error is the failure of a query: no endpoint that was tried gave an answer.
// Attempts holds the error of each, in the order they were tried. An endpoint is
// named by its host in them, never by its URL.
type Error struct {
	Attempts []error
}

func (e *Error) Error() string {
	parts := make([]string, len(e.Attempts))
	for i, err := range e.Attempts {
		parts[i] = err.Error()
	}
	return "doh: no endpoint answered: " + strings.Join(parts, "; ")
}

func (e *Error) Unwrap() []error { return e.Attempts }

// Client asks DNS-over-HTTPS endpoints. It is safe for concurrent use.
//
// A query goes to one endpoint, and to the next one when that fails: its
// connection, its TLS, its HTTP status, an answer that is not a DNS message for
// the question, or one that says SERVFAIL or REFUSED. Two endpoints are tried at
// the most. The client remembers where it is: a query begins with the endpoint
// that answered the one before, and after a query that got no answer, with the
// first endpoint that was not tried. Endpoints that do not work are thus left
// behind after one query, and every endpoint gets its turn: an endpoint that
// fails on its own is left behind at once, also when the caller of that query
// then gives up on it. Every request has a timeout of Timeout (3 s), so a query
// takes 6 s at the most.
type Client struct {
	endpoints []string
	hosts     []string // what an error calls each endpoint: its host, never its URL
	tr        *http.Transport
	hc        *http.Client
	timeout   time.Duration
	next      atomic.Uint32 // the index of the endpoint a query begins with
}

// New returns a client of the endpoints, in the order given: https URLs whose
// host is an IP address. Every request has a timeout of Timeout.
func New(endpoints []string) *Client {
	return newClient(endpoints, Timeout, nil)
}

// NewWithRoots is New for endpoints whose certificates are signed by roots
// rather than by the roots of the system: endpoints of a private CA, and the
// test endpoints of other packages.
func NewWithRoots(endpoints []string, roots *x509.CertPool) *Client {
	return newClient(endpoints, Timeout, roots)
}

// newClient is New with the timeout of a request and the roots that the
// certificates are verified against; nil means those of the system.
func newClient(endpoints []string, timeout time.Duration, roots *x509.CertPool) *Client {
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy: nil, // never the proxies of the environment
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if _, err := netip.ParseAddrPort(addr); err != nil {
				return nil, fmt.Errorf("the host of the endpoint %s is not an IP address, and no name is looked up to reach it", addr)
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 16 << 10,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        60 * time.Second,
	}
	hosts := make([]string, len(endpoints))
	for i, ep := range endpoints {
		hosts[i] = fmt.Sprintf("endpoint %d", i)
		if u, err := url.Parse(ep); err == nil && u.Host != "" {
			hosts[i] = u.Host
		}
	}
	return &Client{
		endpoints: slices.Clone(endpoints),
		hosts:     hosts,
		tr:        tr,
		hc: &http.Client{
			Transport:     tr,
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		timeout: timeout,
	}
}

// CloseIdleConnections closes the connections to the endpoints that are not in
// use. A client that is no longer needed should be told, so that nothing of it
// stays open.
func (c *Client) CloseIdleConnections() { c.tr.CloseIdleConnections() }

// Exchange sends query, a DNS message in wire format with exactly one question,
// and returns the answer in wire format, with the ID of the query: the query
// goes out with the ID 0 (RFC 8484 4.1), and the answer comes back with it.
// query itself is not changed.
//
// The answer is a response to the question of the query, which is checked: the
// name (in any case), the type and the class. Its RCODE is anything but
// SERVFAIL and REFUSED, which make the query go to the next endpoint. When no
// endpoint gives an answer the error is an *Error with the failure of each, and
// when ctx ends the query, it unwraps to the error of ctx.
func (c *Client) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	q, err := questionOf(query)
	if err != nil {
		return nil, err
	}
	n := len(c.endpoints)
	if n == 0 {
		return nil, ErrNoEndpoints
	}
	wire := bytes.Clone(query)
	id := binary.BigEndian.Uint16(wire)
	binary.BigEndian.PutUint16(wire, 0)

	start := int(c.next.Load()) % n
	var attempts []error
	for i := range min(maxAttempts, n) {
		idx := (start + i) % n
		resp, err := c.post(ctx, idx, wire, q)
		if err == nil {
			c.next.Store(uint32(idx))
			binary.BigEndian.PutUint16(resp, id)
			return resp, nil
		}
		attempts = append(attempts, err)
		if ctx.Err() != nil {
			break // cut short by the caller: that says nothing of the endpoint
		}
		// The endpoint failed on its own, by its timeout or an error: the
		// queries after this one begin past it, at once and whatever becomes
		// of this one, unless another query has moved on meanwhile.
		c.next.CompareAndSwap(uint32(idx), uint32((idx+1)%n))
	}
	return nil, &Error{Attempts: attempts}
}

// ExchangeAll sends query to every endpoint at once, each with its own timeout
// of Timeout, and waits for them all: it takes as long as the slowest endpoint,
// Timeout at the most. The answer is the first good one to arrive, with the ID
// of the query; failed holds the error of every endpoint that gave no answer,
// in the order of the endpoints. When none answered, err is an *Error with
// them all. It is a probe of every endpoint, for diagnostics: the client's
// place (where Exchange begins) is left alone.
func (c *Client) ExchangeAll(ctx context.Context, query []byte) (resp []byte, failed []error, err error) {
	q, err := questionOf(query)
	if err != nil {
		return nil, nil, err
	}
	n := len(c.endpoints)
	if n == 0 {
		return nil, nil, ErrNoEndpoints
	}
	wire := bytes.Clone(query)
	id := binary.BigEndian.Uint16(wire)
	binary.BigEndian.PutUint16(wire, 0)

	errs := make([]error, n)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			body, err := c.post(ctx, i, wire, q)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[i] = err
			} else if resp == nil {
				resp = body
			}
		})
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			failed = append(failed, e)
		}
	}
	if resp == nil {
		return nil, failed, &Error{Attempts: failed}
	}
	binary.BigEndian.PutUint16(resp, id)
	return resp, failed, nil
}

// post sends one query to the endpoint i and returns the answer, checked. Its
// errors name the endpoint by its host.
func (c *Client) post(ctx context.Context, i int, wire []byte, q dnsmessage.Question) ([]byte, error) {
	host := c.hosts[i]
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoints[i], bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("%s: the endpoint is not a URL", host)
	}
	req.Header.Set("Content-Type", mediaType)
	req.Header.Set("Accept", mediaType)
	resp, err := c.hc.Do(req)
	if err != nil {
		// The *url.Error of the client quotes the URL: only what it wraps is kept.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("%s: %w", host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", host, resp.Status)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != mediaType {
		return nil, fmt.Errorf("%s answered with %q, not a DNS message", host, resp.Header.Get("Content-Type"))
	}
	if resp.ContentLength > maxMessage {
		return nil, fmt.Errorf("%s answered with %d bytes, more than the 65535 of a DNS message", host, resp.ContentLength)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessage+1))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("%s: reading the answer: %w", host, err)
	}
	if len(body) > maxMessage {
		return nil, fmt.Errorf("%s answered with more than the 65535 bytes of a DNS message", host)
	}
	rcode, err := checkAnswer(body, q)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", host, err)
	}
	if rcode == dnsmessage.RCodeServerFailure || rcode == dnsmessage.RCodeRefused {
		return nil, fmt.Errorf("%s answered %s", host, rcodeName(rcode))
	}
	return body, nil
}

// questionOf returns the question of a query, which must have exactly one.
func questionOf(query []byte) (dnsmessage.Question, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		return dnsmessage.Question{}, fmt.Errorf("doh: the query is not a DNS message: %w", err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return dnsmessage.Question{}, fmt.Errorf("doh: the query is not a DNS message: %w", err)
	}
	if len(qs) != 1 {
		return dnsmessage.Question{}, fmt.Errorf("doh: the query has %d questions, not one", len(qs))
	}
	return qs[0], nil
}

// checkAnswer checks that msg is a response to the question q, and returns its
// RCODE.
func checkAnswer(msg []byte, q dnsmessage.Question) (dnsmessage.RCode, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return 0, fmt.Errorf("the answer is not a DNS message: %w", err)
	}
	if !h.Response {
		return 0, errors.New("the answer is not a DNS response")
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return 0, fmt.Errorf("the answer is not a DNS message: %w", err)
	}
	if len(qs) != 1 || !SameQuestion(qs[0], q) {
		return 0, errors.New("the answer is for another question")
	}
	return h.RCode, nil
}

// SameQuestion reports whether a and b ask the same: the same name, in any
// ASCII case, the same type and the same class.
func SameQuestion(a, b dnsmessage.Question) bool {
	return a.Type == b.Type && a.Class == b.Class && EqualNames(a.Name, b.Name)
}

// EqualNames reports whether two names are the same, in any ASCII case.
func EqualNames(a, b dnsmessage.Name) bool {
	if a.Length != b.Length {
		return false
	}
	for i := range int(a.Length) {
		if lower(a.Data[i]) != lower(b.Data[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// rcodeName is the name of an RCODE as DNS documents spell it.
func rcodeName(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	}
	return rc.String()
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

// LookupIP returns the IPv4 and the IPv6 addresses of name: the A and the AAAA
// records, asked for at the same time, of name and of the names its CNAME
// records lead to, IPv4 first, each in the order of the answer. An IP address
// is returned as it is, without a query.
//
// A name that does not exist, or that has no address, is a *net.DNSError that
// is IsNotFound. When one of the two questions gets no answer and the other has
// no addresses, the error is the one of the question that failed.
func (c *Client) LookupIP(ctx context.Context, name string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(name); err == nil {
		return []netip.Addr{a}, nil
	}
	n, err := fqdn(name)
	if err != nil {
		return nil, err
	}
	type result struct {
		recs []dnsmessage.Resource
		err  error
	}
	var v4, v6 result
	var wg sync.WaitGroup
	wg.Go(func() { v4.recs, v4.err = c.lookup(ctx, name, n, dnsmessage.TypeA) })
	wg.Go(func() { v6.recs, v6.err = c.lookup(ctx, name, n, dnsmessage.TypeAAAA) })
	wg.Wait()

	var addrs []netip.Addr
	for _, r := range append(v4.recs, v6.recs...) {
		switch b := r.Body.(type) {
		case *dnsmessage.AResource:
			addrs = append(addrs, netip.AddrFrom4(b.A))
		case *dnsmessage.AAAAResource:
			addrs = append(addrs, netip.AddrFrom16(b.AAAA))
		}
	}
	if len(addrs) > 0 {
		return addrs, nil
	}
	for _, err := range []error{v4.err, v6.err} {
		if err != nil && !isNotFound(err) {
			return nil, err
		}
	}
	return nil, notFound(name)
}

// LookupTXT returns the TXT records of name, and of the names its CNAME records
// lead to, in the order of the answer. The strings of one record are one value,
// as net.LookupTXT has them. A name that does not exist is a *net.DNSError that
// is IsNotFound; one that has no TXT records has none, and no error.
func (c *Client) LookupTXT(ctx context.Context, name string) ([]string, error) {
	n, err := fqdn(name)
	if err != nil {
		return nil, err
	}
	recs, err := c.lookup(ctx, name, n, dnsmessage.TypeTXT)
	if err != nil && !isNoData(err) {
		return nil, err
	}
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		if b, ok := r.Body.(*dnsmessage.TXTResource); ok {
			out = append(out, strings.Join(b.TXT, ""))
		}
	}
	return out, nil
}

// errNoData is the text of the IsNotFound error of a name that exists but has
// no record of the type asked for.
const errNoData = "no such record"

// lookup asks for the records of type t of n, and returns those of n and of the
// names its CNAME records lead to. A name that does not exist is an IsNotFound
// *net.DNSError, and so is one without records of the type (Err errNoData).
func (c *Client) lookup(ctx context.Context, name string, n dnsmessage.Name, t dnsmessage.Type) ([]dnsmessage.Resource, error) {
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: t, Class: dnsmessage.ClassINET}},
	}
	query, err := msg.Pack()
	if err != nil {
		return nil, &net.DNSError{Err: "the name cannot be asked for: " + err.Error(), Name: name}
	}
	resp, err := c.Exchange(ctx, query)
	if err != nil {
		return nil, err
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return nil, fmt.Errorf("doh: the answer is not a DNS message: %w", err)
	}
	switch m.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, notFound(name)
	default:
		return nil, &net.DNSError{Err: "the server answered " + rcodeName(m.RCode), Name: name}
	}
	recs := chain(m.Answers, n, t)
	if len(recs) == 0 {
		return nil, &net.DNSError{Err: errNoData, Name: name, IsNotFound: true}
	}
	return recs, nil
}

// chain returns the records of type t in answers whose owner is n or a name
// that the CNAME records lead to from n.
func chain(answers []dnsmessage.Resource, n dnsmessage.Name, t dnsmessage.Type) []dnsmessage.Resource {
	names := []dnsmessage.Name{n}
	known := func(x dnsmessage.Name) bool {
		return slices.ContainsFunc(names, func(y dnsmessage.Name) bool { return EqualNames(x, y) })
	}
	// The CNAME records may come in any order: follow them until no new name
	// turns up. A chain is never longer than the answer.
	for grew := true; grew; {
		grew = false
		for _, r := range answers {
			if cn, ok := r.Body.(*dnsmessage.CNAMEResource); ok && known(r.Header.Name) && !known(cn.CNAME) {
				names = append(names, cn.CNAME)
				grew = true
			}
		}
	}
	var out []dnsmessage.Resource
	for _, r := range answers {
		if r.Header.Type == t && r.Header.Class == dnsmessage.ClassINET && known(r.Header.Name) {
			out = append(out, r)
		}
	}
	return out
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// isNotFound reports whether err is the error of a name that does not exist,
// or that has no record of the type asked for.
func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// isNoData reports whether err is the error of a name that exists and has no
// record of the type asked for.
func isNoData(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound && de.Err == errNoData
}

// fqdn turns name into a fully qualified name to ask for: not empty, labels of
// 1 to 63 bytes, 253 bytes at the most without the dot at its end.
func fqdn(name string) (dnsmessage.Name, error) {
	bad := func(why string) (dnsmessage.Name, error) {
		return dnsmessage.Name{}, &net.DNSError{Err: why, Name: name}
	}
	s := strings.TrimSuffix(name, ".")
	switch {
	case s == "":
		return bad("an empty name")
	case len(s) > 253:
		return bad("the name is longer than 253 bytes")
	}
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 {
			return bad("a label of the name is empty or longer than 63 bytes")
		}
	}
	return dnsmessage.NewName(s + ".")
}
