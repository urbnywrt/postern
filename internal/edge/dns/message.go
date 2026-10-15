package dns

import (
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urbnywrt/postern/internal/doh"
)

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// incoming is a query a client sent, as far as it could be read.
type incoming struct {
	h     dnsmessage.Header
	q     dnsmessage.Question
	edns  bool             // the query has an OPT record
	size  int              // the UDP size it announces with it
	rcode dnsmessage.RCode // not 0: the query is answered with this RCODE alone
}

// parseQuery reads a query. ok is false when there is nothing to answer: a
// message that is not even a header, or a response. A query that is not
// well-formed, or does not have exactly one question, gets rcode FORMERR, and
// one of another opcode than QUERY NOTIMP.
func parseQuery(msg []byte) (in incoming, ok bool) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response {
		return incoming{}, false
	}
	in.h = h
	if h.OpCode != 0 {
		in.rcode = dnsmessage.RCodeNotImplemented
		return in, true
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		in.rcode = dnsmessage.RCodeFormatError
		return in, true
	}
	in.q = qs[0]
	if err := p.SkipAllAnswers(); err != nil {
		in.rcode = dnsmessage.RCodeFormatError
		return in, true
	}
	if err := p.SkipAllAuthorities(); err != nil {
		in.rcode = dnsmessage.RCodeFormatError
		return in, true
	}
	for {
		rh, err := p.AdditionalHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			in.rcode = dnsmessage.RCodeFormatError
			return in, true
		}
		if rh.Type == dnsmessage.TypeOPT {
			if in.edns { // RFC 6891 6.1.1: one OPT at the most
				in.rcode = dnsmessage.RCodeFormatError
				return in, true
			}
			in.edns, in.size = true, int(rh.Class)
		}
		if err := p.SkipAdditional(); err != nil {
			in.rcode = dnsmessage.RCodeFormatError
			return in, true
		}
	}
	if in.q.Type == dnsmessage.TypeOPT {
		in.rcode = dnsmessage.RCodeFormatError
	}
	return in, true
}

// udpSize is the largest answer the client takes over UDP: what it announces
// with EDNS(0), between 512 bytes and maxUDPSize, or 512 without it.
func (in incoming) udpSize() int {
	if !in.edns {
		return minUDPSize
	}
	return min(max(in.size, minUDPSize), maxUDPSize)
}

// header is the header of an answer to the query.
func (in incoming) header(rcode dnsmessage.RCode) dnsmessage.Header {
	return dnsmessage.Header{
		ID: in.h.ID, Response: true, OpCode: in.h.OpCode,
		RecursionDesired: in.h.RecursionDesired, RecursionAvailable: true, RCode: rcode,
	}
}

// reply is an answer with an RCODE and nothing else: the question, when the
// query had one that could be read, and an OPT record when the query had one.
func (in incoming) reply(rcode dnsmessage.RCode) []byte {
	m := dnsmessage.Message{Header: in.header(rcode)}
	if rcode != dnsmessage.RCodeFormatError && rcode != dnsmessage.RCodeNotImplemented {
		m.Questions = []dnsmessage.Question{in.q}
		if in.edns {
			m.Additionals = []dnsmessage.Resource{ourOPT()}
		}
	}
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

// answer is the answer of the cache entry e to the query, at now: the question
// as the client asked it, the records with the TTLs that are left. limit, when
// it is not 0, is the most bytes the answer may take; records are dropped from
// the end until it fits (see packWithin). An entry of a failure is SERVFAIL.
func (in incoming) answer(e *entry, now time.Time, limit int) []byte {
	if e.fail {
		return in.reply(dnsmessage.RCodeServerFailure)
	}
	var kept dnsmessage.Message
	if err := kept.Unpack(e.wire); err != nil {
		return in.reply(dnsmessage.RCodeServerFailure)
	}
	elapsed := e.elapsed(now)
	m := dnsmessage.Message{
		Header:      in.header(kept.RCode),
		Questions:   []dnsmessage.Question{in.q},
		Answers:     withTTL(kept.Answers, elapsed),
		Authorities: withTTL(kept.Authorities, elapsed),
		Additionals: withTTL(kept.Additionals, elapsed),
	}
	var opt *dnsmessage.Resource
	if in.edns {
		o := ourOPT()
		opt = &o
	}
	if limit == 0 || limit > 65535 {
		limit = 65535 // the length of a message over TCP is 16 bits
	}
	b, err := packWithin(m, opt, limit)
	if err != nil {
		return in.reply(dnsmessage.RCodeServerFailure)
	}
	return b
}

// packWithin packs m with opt at the end of its additional records. When that
// takes more than limit bytes, it keeps as many records as fit, in the order of
// the sections, and sets TC when an answer or an authority record had to go.
// Additional records that do not fit are dropped without TC (RFC 2181 9), by
// whole RRsets: an RRset is never left in part without TC.
func packWithin(m dnsmessage.Message, opt *dnsmessage.Resource, limit int) ([]byte, error) {
	an, ns := len(m.Answers), len(m.Authorities)
	total := an + ns + len(m.Additionals)
	pack := func(answers, authorities, additionals []dnsmessage.Resource, tc bool) ([]byte, error) {
		mm := m
		mm.Answers, mm.Authorities, mm.Additionals = answers, authorities, additionals
		if opt != nil {
			mm.Additionals = append(additionals[:len(additionals):len(additionals)], *opt)
		}
		mm.Truncated = tc
		return mm.Pack()
	}
	// prefix keeps the first keep records, in the order of the sections.
	prefix := func(keep int) ([]byte, error) {
		a := min(keep, an)
		n := min(keep-a, ns)
		d := keep - a - n
		return pack(m.Answers[:a:a], m.Authorities[:n:n], m.Additionals[:d:d], keep < an+ns)
	}
	b, err := prefix(total)
	if err != nil || len(b) <= limit {
		return b, err
	}
	// The length grows with the records kept: find the most that fit.
	lo, hi := 0, total-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		b, err := prefix(mid)
		if err != nil {
			return nil, err
		}
		if len(b) <= limit {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if lo < an+ns {
		return prefix(lo) // TC: the client asks again over TCP, and takes no part of it
	}
	// Only additional records go, and no RRset in part.
	d := lo - an - ns
	gone := map[rrsetKey]bool{}
	for _, rr := range m.Additionals[d:] {
		gone[rrsetOf(rr)] = true
	}
	var kept []dnsmessage.Resource
	for _, rr := range m.Additionals[:d] {
		if !gone[rrsetOf(rr)] {
			kept = append(kept, rr)
		}
	}
	return pack(m.Answers, m.Authorities, kept, false)
}

// rrsetKey is the RRset of a record: its name in lower case, its type and its
// class.
type rrsetKey struct {
	name  string
	typ   dnsmessage.Type
	class dnsmessage.Class
}

func rrsetOf(rr dnsmessage.Resource) rrsetKey {
	return rrsetKey{name: lowerString(rr.Header.Name), typ: rr.Header.Type, class: rr.Header.Class}
}

// ourOPT is the OPT record of an answer: the size the forwarder takes over UDP,
// no DNSSEC.
func ourOPT() dnsmessage.Resource {
	var r dnsmessage.Resource
	r.Body = &dnsmessage.OPTResource{}
	_ = r.Header.SetEDNS0(maxUDPSize, dnsmessage.RCodeSuccess, false)
	return r
}

// withTTL returns copies of rrs with elapsed seconds taken off their TTLs.
func withTTL(rrs []dnsmessage.Resource, elapsed uint32) []dnsmessage.Resource {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dnsmessage.Resource, len(rrs))
	for i, rr := range rrs {
		if rr.Header.TTL > elapsed {
			rr.Header.TTL -= elapsed
		} else {
			rr.Header.TTL = 0
		}
		out[i] = rr
	}
	return out
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

// cacheKey is a question: the name in lower case, the type and the class.
type cacheKey struct {
	name  string
	typ   dnsmessage.Type
	class dnsmessage.Class
}

func keyOf(q dnsmessage.Question) cacheKey {
	n := lowerName(q.Name)
	return cacheKey{name: string(n.Data[:n.Length]), typ: q.Type, class: q.Class}
}

// lowerName returns n in ASCII lower case.
func lowerName(n dnsmessage.Name) dnsmessage.Name {
	for i := range int(n.Length) {
		if c := n.Data[i]; 'A' <= c && c <= 'Z' {
			n.Data[i] = c + 'a' - 'A'
		}
	}
	return n
}

// entry is an answer as the cache keeps it: in wire form, which takes little
// room, with its TTLs cut to what the answer may be kept for, or the failure
// of every upstream (RFC 9520: a resolution failure is kept for a moment, so
// that the clients that ask again do not make the upstreams be asked again at
// once).
type entry struct {
	// wire is the answer packed: ID 0, the question in lower case, the records
	// without OPT; nil for a failure.
	wire   []byte
	fail   bool      // the upstreams failed: SERVFAIL
	stored time.Time // when the answer came
	ttl    uint32    // seconds the entry is good for
}

// failure is the entry of a question that no upstream answered, at now.
func failure(now time.Time) *entry {
	return &entry{fail: true, stored: now, ttl: failTTL}
}

// newEntry makes an entry of an upstream answer m to q (in lower case), at now.
// A positive answer is kept for the least TTL of its records, maxTTL at the
// most. A negative one, a name that does not exist or that has no record of the
// type (NODATA, also behind a CNAME chain, RFC 2308 2.2), is kept as RFC 2308 5
// says, for the TTL of the SOA record of its authority section or the SOA
// minimum, whichever is less, and negativeTTL at the most; without an SOA it is
// not kept. The TTLs of the records are cut to that bound, and OPT records are
// left out. The answer is kept in a slice of its exact length: the cache counts
// what it takes.
func newEntry(m *dnsmessage.Message, q dnsmessage.Question, now time.Time) (*entry, error) {
	answers := withoutOPT(m.Answers)
	negative := m.RCode == dnsmessage.RCodeNameError || !hasData(answers, q)
	limit := uint32(maxTTL)
	if negative {
		limit = 0 // no SOA: not kept
		for _, rr := range m.Authorities {
			if soa, ok := rr.Body.(*dnsmessage.SOAResource); ok {
				limit = min(negativeTTL, rr.Header.TTL, soa.MinTTL)
				break
			}
		}
	}
	ttl := limit
	capTTL := func(rrs []dnsmessage.Resource) []dnsmessage.Resource {
		for i := range rrs {
			rrs[i].Header.TTL = min(rrs[i].Header.TTL, limit)
			ttl = min(ttl, rrs[i].Header.TTL)
		}
		return rrs
	}
	kept := dnsmessage.Message{
		Header:      dnsmessage.Header{Response: true, RecursionAvailable: true, RCode: m.RCode},
		Questions:   []dnsmessage.Question{q},
		Answers:     capTTL(answers),
		Authorities: capTTL(withoutOPT(m.Authorities)),
		Additionals: capTTL(withoutOPT(m.Additionals)),
	}
	if negative {
		ttl = limit // the SOA decides, not the least TTL of the records
	}
	packed, err := kept.Pack()
	if err != nil {
		return nil, fmt.Errorf("the answer cannot be packed again: %w", err)
	}
	wire := make([]byte, len(packed)) // not the spare capacity of packing
	copy(wire, packed)
	return &entry{wire: wire, stored: now, ttl: ttl}, nil
}

// maxCNAMEChain is the most CNAME records that hasData follows from the name of
// a question: a longer chain, or a loop, has no data for the cache.
const maxCNAMEChain = 16

// hasData reports whether answers hold a record of the type of q, for its name
// or for a name that its CNAME records lead to, in any order, maxCNAMEChain of
// them at the most. A question of the type CNAME has its data in the CNAME
// record, and one of the type ANY in any record. It takes time linear in the
// records, whatever an upstream sends.
func hasData(answers []dnsmessage.Resource, q dnsmessage.Question) bool {
	if q.Type == dnsmessage.TypeALL {
		return len(answers) > 0
	}
	owners := map[string]bool{}   // the names with a record of the type
	cnames := map[string]string{} // a CNAME record by its name
	for _, rr := range answers {
		if rr.Header.Type == q.Type {
			owners[lowerString(rr.Header.Name)] = true
		}
		if cn, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
			cnames[lowerString(rr.Header.Name)] = lowerString(cn.CNAME)
		}
	}
	name := lowerString(q.Name)
	for range maxCNAMEChain + 1 {
		if owners[name] {
			return true
		}
		next, ok := cnames[name]
		if !ok {
			return false
		}
		name = next
	}
	return false
}

// lowerString is n in ASCII lower case, as a string.
func lowerString(n dnsmessage.Name) string {
	n = lowerName(n)
	return string(n.Data[:n.Length])
}

// withoutOPT returns copies of the records of rrs that are not OPT records.
func withoutOPT(rrs []dnsmessage.Resource) []dnsmessage.Resource {
	var out []dnsmessage.Resource
	for _, rr := range rrs {
		if rr.Header.Type != dnsmessage.TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}

// elapsed is the whole seconds since the entry was stored.
func (e *entry) elapsed(now time.Time) uint32 {
	d := now.Sub(e.stored)
	if d <= 0 {
		return 0
	}
	return uint32(min(d/time.Second, 1<<31))
}

func (e *entry) expired(now time.Time) bool {
	return now.Sub(e.stored) >= time.Duration(e.ttl)*time.Second
}

// itemOverhead is what an entry of the cache takes beside its answer and the
// name of its question: the list element, the map slot, the structs, the
// strings and their headers, rounded up.
const itemOverhead = 256

// cache holds answers by question, the most recently used first: maxEntries
// of them and maxBytes in all at the most, counted with their keys and
// itemOverhead; the least recently used go first. An answer whose wire form is
// longer than maxCachedAnswer is not kept at all. It is safe for concurrent
// use.
type cache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int
	bytes      int
	ll         *list.List // of *cacheItem
	items      map[cacheKey]*list.Element
}

type cacheItem struct {
	key  cacheKey
	e    *entry
	size int
}

func newCache(maxEntries, maxBytes int) *cache {
	return &cache{maxEntries: maxEntries, maxBytes: maxBytes, ll: list.New(), items: map[cacheKey]*list.Element{}}
}

// get returns the entry of k that is good at now, nil when there is none.
func (c *cache) get(k cacheKey, now time.Time) *entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return nil
	}
	it := el.Value.(*cacheItem)
	if it.e.expired(now) {
		c.removeLocked(el)
		return nil
	}
	c.ll.MoveToFront(el)
	return it.e
}

// put keeps e for k, unless it is good for no time at all or its answer is
// longer than maxCachedAnswer; then the least recently used entries go until
// the cache is within its bounds.
func (c *cache) put(k cacheKey, e *entry) {
	if e.ttl == 0 || len(e.wire) > maxCachedAnswer {
		return
	}
	size := cap(e.wire) + len(k.name) + itemOverhead
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		c.removeLocked(el)
	}
	c.items[k] = c.ll.PushFront(&cacheItem{key: k, e: e, size: size})
	c.bytes += size
	for c.ll.Len() > c.maxEntries || c.bytes > c.maxBytes {
		c.removeLocked(c.ll.Back())
	}
}

func (c *cache) removeLocked(el *list.Element) {
	it := el.Value.(*cacheItem)
	c.ll.Remove(el)
	delete(c.items, it.key)
	c.bytes -= it.size
}

// usage returns the entries and the bytes the cache holds.
func (c *cache) usage() (entries, bytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len(), c.bytes
}

func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	clear(c.items)
	c.bytes = 0
}

// ---------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------

// lookupError is the failure of every upstream that was asked a question.
type lookupError struct {
	errs []error
}

func (e *lookupError) Error() string {
	if len(e.errs) == 0 {
		return "no upstream to ask"
	}
	parts := make([]string, len(e.errs))
	for i, err := range e.errs {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; ")
}

func (e *lookupError) Unwrap() []error { return e.errs }

// lookup asks the upstreams for the answer to q. The question goes out in
// lower case, with recursion desired, to the DNS-over-HTTPS endpoints first.
// When they fail, or have not answered within the hedge delay (1.5 s), the
// nameservers of the host are asked as well, one after the other, over UDP and
// then TCP, and the first answer that is NOERROR or NXDOMAIN for the question
// wins. The hedge keeps a slow or blocked endpoint from costing the clients the
// 2 x 3 s that the DNS-over-HTTPS client may take, longer than they wait.
//
// The asking runs in goroutines of the server (askSide), and a panic in one of
// them is the failure of that side, logged with its stack as rarely as the
// other warnings: it never takes the edge down.
//
// When the nameservers win, the DNS-over-HTTPS attempt is not cut short: its
// client moves on past an endpoint only when the endpoint fails on its own, and
// a black-holed endpoint would otherwise stay first for every question. It runs
// on, on the server's context, which Close ends, to its own timeouts. Such
// attempts are bounded, as many as there may be questions in flight: without a
// free slot, the nameservers are asked at once. The nameservers are cut short
// when DNS-over-HTTPS wins.
func (s *server) lookup(q dnsmessage.Question) (*entry, error) {
	f := s.f
	ups := f.ups.Load()
	q.Name = lowerName(q.Name)

	results := make(chan outcome, 2) // never blocks a side that ends after the answer
	pending := 0
	spawn := func(ctx context.Context, done func(), side string, ask func(ctx context.Context) (*entry, error)) {
		pending++
		s.askSide(ctx, side, ask, done, results)
	}

	fbCtx, fbCancel := context.WithTimeout(s.ctx, f.lim.resolveTimeout)
	defer fbCancel()
	fallbackAsked := false
	askFallback := func() {
		if fallbackAsked || len(ups.fallback) == 0 {
			return
		}
		fallbackAsked = true
		spawn(fbCtx, func() {}, "nameservers", func(ctx context.Context) (*entry, error) { return f.askFallback(ctx, ups.fallback, q) })
	}
	var errs []error
	switch {
	case ups.doh == nil:
		askFallback()
	case s.takeDoHSlot():
		dohCtx, dohCancel := context.WithTimeout(s.ctx, f.lim.resolveTimeout)
		spawn(dohCtx, func() { dohCancel(); s.releaseDoHSlot() }, "DNS-over-HTTPS",
			func(ctx context.Context) (*entry, error) { return f.askDoH(ctx, ups.doh, q) })
	default:
		errs = append(errs, errors.New("DNS-over-HTTPS: too many attempts in flight"))
		askFallback()
	}

	hedge := time.NewTimer(f.lim.hedgeDelay)
	defer hedge.Stop()
	for pending > 0 {
		select {
		case o := <-results:
			pending--
			if o.err == nil {
				return o.e, nil
			}
			errs = append(errs, o.err)
			askFallback() // DNS-over-HTTPS failed: no reason to wait for the hedge
		case <-hedge.C:
			askFallback()
		}
	}
	return nil, &lookupError{errs: errs}
}

// outcome is what one side of a lookup found.
type outcome struct {
	e   *entry
	err error
}

// askSide runs ask, one side of a lookup, in a goroutine of the server and
// sends its outcome to results. done frees what the side holds, such as its
// slot, before the outcome goes: the lookup that takes it, and the question
// after it, find the slot free. A panic in ask is the failure of the side,
// logged with its stack, as rarely as the other warnings.
func (s *server) askSide(ctx context.Context, side string, ask func(ctx context.Context) (*entry, error), done func(), results chan<- outcome) {
	s.wg.Go(func() {
		o := outcome{err: fmt.Errorf("%s: internal error", side)}
		// Deferred calls run last first: the recover, done, then the send.
		defer func() { results <- o }()
		defer done()
		defer func() {
			if p := recover(); p != nil && s.f.warns.allow() {
				s.f.log.Error("dns: panic while asking an upstream", "upstream", side, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			}
		}()
		o.e, o.err = ask(ctx)
	})
}

// takeDoHSlot takes a slot for a DNS-over-HTTPS attempt, if one is free.
func (s *server) takeDoHSlot() bool {
	select {
	case s.dohSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *server) releaseDoHSlot() { <-s.dohSlots }

// askDoH asks the DNS-over-HTTPS endpoints.
func (f *Forwarder) askDoH(ctx context.Context, u Upstream, q dnsmessage.Question) (*entry, error) {
	resp, err := exchangeDoH(ctx, u, q)
	if err == nil {
		var e *entry
		if e, err = f.take(resp, q); err == nil {
			return e, nil
		}
	}
	return nil, fmt.Errorf("DNS-over-HTTPS: %w", err)
}

// askFallback asks the nameservers of the host in order, each over UDP and
// then TCP, until one answers.
func (f *Forwarder) askFallback(ctx context.Context, servers []netip.AddrPort, q dnsmessage.Question) (*entry, error) {
	var errs []error
	for _, ns := range servers {
		if ctx.Err() != nil {
			break
		}
		resp, err := f.askNameserver(ctx, ns, q)
		if err == nil {
			var e *entry
			if e, err = f.take(resp, q); err == nil {
				return e, nil
			}
		}
		errs = append(errs, fmt.Errorf("nameserver %s: %w", ns, err))
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("nameservers: %w", ctx.Err())
	}
	return nil, &lookupError{errs: errs}
}

// take makes a cache entry of an upstream answer to q, if it is one to take.
func (f *Forwarder) take(resp []byte, q dnsmessage.Question) (*entry, error) {
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return nil, fmt.Errorf("the answer is not a DNS message: %w", err)
	}
	switch {
	case !m.Response:
		return nil, errors.New("the answer is not a response")
	case len(m.Questions) != 1 || !doh.SameQuestion(m.Questions[0], q):
		return nil, errors.New("the answer is for another question")
	case m.Truncated:
		return nil, errors.New("the answer is truncated")
	case m.RCode != dnsmessage.RCodeSuccess && m.RCode != dnsmessage.RCodeNameError:
		return nil, fmt.Errorf("the answer is %s", rcodeText(m.RCode))
	}
	return newEntry(&m, q, f.now())
}

func rcodeText(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE %d", rc)
}

// packQuery is the query of q with the ID id, recursion desired.
func packQuery(q dnsmessage.Question, id uint16) ([]byte, error) {
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{q},
	}
	return m.Pack()
}

func exchangeDoH(ctx context.Context, u Upstream, q dnsmessage.Question) ([]byte, error) {
	query, err := packQuery(q, 0) // RFC 8484 4.1: the ID is 0
	if err != nil {
		return nil, err
	}
	return u.Exchange(ctx, query)
}

// askNameserver asks a nameserver of the host over UDP, and over TCP when that
// fails or the answer is truncated. Each query has a random ID of its own.
func (f *Forwarder) askNameserver(ctx context.Context, ns netip.AddrPort, q dnsmessage.Question) ([]byte, error) {
	resp, udpErr := exchangeUDP(ctx, ns, q, f.lim.exchangeTimeout)
	if udpErr == nil && !truncated(resp) {
		return resp, nil
	}
	resp, err := exchangeTCP(ctx, ns, q, f.lim.exchangeTimeout)
	if err != nil && udpErr != nil {
		return nil, fmt.Errorf("udp: %v; tcp: %w", udpErr, err)
	}
	return resp, err
}

// truncated reports whether a message has TC set.
func truncated(msg []byte) bool { return len(msg) >= headerLen && msg[2]&0x02 != 0 }

func randomID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return binary.BigEndian.Uint16(b[:])
}

// exchangeUDP sends q to ns over UDP and waits, for timeout at most, for the
// datagram that answers it: the ID and the question of the query. Datagrams
// that are not are ignored (an answer to an earlier query, or a forgery).
func exchangeUDP(ctx context.Context, ns netip.AddrPort, q dnsmessage.Question, timeout time.Duration) ([]byte, error) {
	id := randomID()
	query, err := packQuery(q, id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", ns.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if resp := buf[:n]; isAnswerTo(resp, id, q) {
			return bytes.Clone(resp), nil
		}
	}
}

// exchangeTCP sends q to ns over TCP and reads the answer, in timeout at most.
func exchangeTCP(ctx context.Context, ns netip.AddrPort, q dnsmessage.Question, timeout time.Duration) ([]byte, error) {
	id := randomID()
	query, err := packQuery(q, id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", ns.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := writeMessage(c, query); err != nil {
		return nil, err
	}
	resp, err := readMessage(c)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if !isAnswerTo(resp, id, q) {
		return nil, errors.New("the answer over TCP is not the answer to the query")
	}
	return resp, nil
}

// isAnswerTo reports whether msg is a response with the ID id to the question q.
func isAnswerTo(msg []byte, id uint16, q dnsmessage.Question) bool {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.ID != id {
		return false
	}
	qs, err := p.AllQuestions()
	return err == nil && len(qs) == 1 && doh.SameQuestion(qs[0], q)
}

// readMessage reads a DNS message over TCP: two bytes of length, then the
// message.
func readMessage(r io.Reader) ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// writeMessage writes a DNS message over TCP, its length first, in one write.
func writeMessage(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return errors.New("the message is longer than 65535 bytes")
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	_, err := w.Write(out)
	return err
}
