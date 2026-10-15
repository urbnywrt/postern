package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// zoneDoH is a DNS-over-HTTPS endpoint for the tests, on an httptest TLS
// server (its certificate is for 127.0.0.1). It answers TXT questions from
// its records, which a test changes as it goes: a name it has no entry for
// does not exist (NXDOMAIN), a name with an empty entry exists without TXT
// records.
type zoneDoH struct {
	*httptest.Server
	hits atomic.Int32

	mu      sync.Mutex
	txt     map[string][]string // lowercase name without the dot → values
	status  int                 // when not 0, the HTTP status of every answer
	onQuery func()              // when set, called before every answer
}

func newZoneDoH(t *testing.T) *zoneDoH {
	t.Helper()
	z := &zoneDoH{txt: map[string][]string{}}
	z.Server = httptest.NewTLSServer(http.HandlerFunc(z.serve))
	t.Cleanup(z.Close)
	return z
}

func (z *zoneDoH) url() string { return z.URL + "/dns-query" }

func (z *zoneDoH) set(name string, values ...string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.txt[name] = append([]string{}, values...)
}

func (z *zoneDoH) fail(status int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.status = status
}

func (z *zoneDoH) serve(w http.ResponseWriter, r *http.Request) {
	z.hits.Add(1)
	z.mu.Lock()
	hook, status := z.onQuery, z.status
	z.mu.Unlock()
	if hook != nil {
		hook()
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var q dnsmessage.Message
	if err := q.Unpack(body); err != nil || len(q.Questions) != 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if status != 0 {
		http.Error(w, "down", status)
		return
	}
	question := q.Questions[0]
	name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: q.Questions,
	}
	z.mu.Lock()
	values, ok := z.txt[name]
	z.mu.Unlock()
	switch {
	case !ok:
		resp.RCode = dnsmessage.RCodeNameError
	case question.Type == dnsmessage.TypeTXT:
		for _, v := range values {
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.TXTResource{TXT: []string{v}},
			})
		}
	}
	wire, err := resp.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(wire)
}

// trust returns a pool of the certificates of the test servers.
func trust(servers ...*httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	return pool
}

func TestThePropagationIsCheckedAtCloudflareAndAtGoogle(t *testing.T) {
	want := [][]string{
		{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"},
		{"https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"},
	}
	got := defaultPropagationEndpoints()
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("defaultPropagationEndpoints() = %q, want %q", got, want)
	}
	got[0][0] = "https://192.0.2.1/dns-query" // a caller that changes its copy changes nothing
	if again := defaultPropagationEndpoints(); again[0][0] != want[0][0] {
		t.Errorf("the default endpoints can be changed from outside: %q", again)
	}
	// A manager without endpoints, or with an empty list, checks at both
	// providers, one client each: the check is never left out.
	for _, endpoints := range [][][]string{nil, {}} {
		m := &Manager{PropagationEndpoints: endpoints, LookupIP: noLookup}
		m.init()
		var names []string
		for _, r := range m.checker.resolvers {
			names = append(names, r.name)
		}
		if want := []string{"1.1.1.1/1.0.0.1", "8.8.8.8/8.8.4.4"}; !slices.Equal(names, want) {
			t.Errorf("PropagationEndpoints %#v: resolvers %q, want one per provider, named by its hosts: %q", endpoints, names, want)
		}
	}
	if PropagationTimeout != 120*time.Second {
		t.Errorf("PropagationTimeout = %v, want 120 s", PropagationTimeout)
	}
}

// deadURL is the URL of an endpoint where nothing listens any more, as an
// address that a node cannot reach.
func deadURL(t *testing.T) string {
	t.Helper()
	z := newZoneDoH(t)
	z.Close()
	return z.url()
}

func TestCheckerFailsOverInsideAProvider(t *testing.T) {
	// The first address of Cloudflare cannot be reached; its second answers:
	// the value is visible at Cloudflare.
	const name = "_acme-challenge.web.example.com"
	cf2, google := newZoneDoH(t), newZoneDoH(t)
	cf2.set(name, "v")
	google.set(name, "v")
	c := newChecker([][]string{{deadURL(t), cf2.url()}, {google.url()}}, trust(cf2.Server, google.Server))
	if err := c.visible(t.Context(), name, "v"); err != nil {
		t.Errorf("visible: %v, want the second address of the provider to answer", err)
	}
	if got := cf2.hits.Load(); got != 1 {
		t.Errorf("the second address of Cloudflare was asked %d times, want once", got)
	}
}

func TestCheckerWantsTheValueAtEveryResolver(t *testing.T) {
	const name = "_acme-challenge.web.example.com"
	tests := []struct {
		label       string
		cf, google  []string // nil: the name does not exist there
		visible     bool
		mentions    []string // in the error
		notMentions []string
	}{
		{label: "at both", cf: []string{"other", "v"}, google: []string{"v"}, visible: true},
		{label: "at Cloudflare only", cf: []string{"v"}, google: []string{"stale"}, mentions: []string{"google", "do not hold the value"}, notMentions: []string{"cloudflare"}},
		{label: "at Google only", cf: nil, google: []string{"v"}, mentions: []string{"cloudflare", "no record at " + name}, notMentions: []string{"google"}},
		{label: "the name exists without TXT records", cf: []string{}, google: []string{}, mentions: []string{"cloudflare", "google", "no TXT record at " + name}},
		{label: "nowhere", mentions: []string{"cloudflare: ", "google: "}},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			cf, google := newZoneDoH(t), newZoneDoH(t)
			if tt.cf != nil {
				cf.set(name, tt.cf...)
			}
			if tt.google != nil {
				google.set(name, tt.google...)
			}
			c := newChecker([][]string{{cf.url()}, {google.url()}}, trust(cf.Server, google.Server))
			// Name the resolvers for the messages, as the hosts of the real ones are.
			c.resolvers[0].name, c.resolvers[1].name = "cloudflare", "google"
			err := c.visible(t.Context(), name, "v")
			if got := err == nil; got != tt.visible {
				t.Fatalf("visible = %v (err %v), want %v", got, err, tt.visible)
			}
			for _, s := range tt.mentions {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("the error %q does not say %q", err, s)
				}
			}
			for _, s := range tt.notMentions {
				if err != nil && strings.Contains(err.Error(), s) {
					t.Errorf("the error %q names %q, which sees the value", err, s)
				}
			}
		})
	}
}

func TestCheckerAsksEachEndpointThroughAClientOfItsOwn(t *testing.T) {
	// Never across providers: both addresses of the first provider fail, the
	// second provider has the value. A client of all of them would fail over
	// to the second provider and see it; each provider has its own, so the
	// value is not visible at the first.
	const name = "_acme-challenge.web.example.com"
	down, up := newZoneDoH(t), newZoneDoH(t)
	down.fail(http.StatusInternalServerError)
	up.set(name, "v")
	c := newChecker([][]string{{down.url(), deadURL(t)}, {up.url()}}, trust(down.Server, up.Server))
	err := c.visible(t.Context(), name, "v")
	if err == nil {
		t.Fatal("the value is visible although the first provider fails")
	}
	if !strings.Contains(err.Error(), endpointName(down.URL)) || !strings.Contains(err.Error(), "500") {
		t.Errorf("the error %q does not name the endpoint that failed and how", err)
	}
	if got := up.hits.Load(); got != 1 {
		t.Errorf("the second provider was asked %d times, want once: by its own client only", got)
	}
	if got := down.hits.Load(); got != 1 {
		t.Errorf("the first endpoint was asked %d times, want once", got)
	}
}

func TestCheckerAsksTheResolversAtTheSameTime(t *testing.T) {
	// Each endpoint answers only once both have been asked: asked one after
	// the other, the first would wait for the second until its timeout.
	const name = "_acme-challenge.web.example.com"
	a, b := newZoneDoH(t), newZoneDoH(t)
	var arrived sync.WaitGroup
	arrived.Add(2)
	both := make(chan struct{})
	go func() { arrived.Wait(); close(both) }()
	barrier := func() {
		arrived.Done()
		select {
		case <-both:
		case <-time.After(5 * time.Second):
		}
	}
	a.onQuery, b.onQuery = barrier, barrier
	a.set(name, "v")
	b.set(name, "v")
	c := newChecker([][]string{{a.url()}, {b.url()}}, trust(a.Server, b.Server))
	start := time.Now()
	if err := c.visible(t.Context(), name, "v"); err != nil {
		t.Fatalf("visible: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the check took %v: the resolvers were not asked at the same time", d)
	}
}

func TestPrecheckAsksFirstALongWhileAfterTheRecordIsWritten(t *testing.T) {
	if FirstPollAfter != 10*time.Second || PropagationTimeout != 120*time.Second {
		t.Errorf("FirstPollAfter = %v, PropagationTimeout = %v; want 10 s and 120 s", FirstPollAfter, PropagationTimeout)
	}
	// A resolver asked before the record is everywhere would keep its "no
	// such name" for the negative TTL of the zone: the first question comes
	// FirstPollAfter after the record was written, not before.
	const name = "_acme-challenge.web.example.com"
	cf := newZoneDoH(t)
	cf.set(name, "v")
	var mu sync.Mutex
	var first time.Time
	cf.onQuery = func() {
		mu.Lock()
		defer mu.Unlock()
		if first.IsZero() {
			first = time.Now()
		}
	}
	c := newChecker([][]string{{cf.url()}}, trust(cf.Server))
	written := time.Now()
	check := c.precheck(t.Context(), time.Minute, 300*time.Millisecond, func(string) time.Time { return written })
	if stop, err := check("web.example.com", "", "v", nil); !stop || err != nil {
		t.Fatalf("check = %v, %v", stop, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if d := first.Sub(written); d < 300*time.Millisecond {
		t.Errorf("the first question came %v after the record was written, want 300ms at least", d)
	}

	// The whole wait counts from the writing of the record.
	gone := newZoneDoH(t)
	c = newChecker([][]string{{gone.url()}}, trust(gone.Server))
	check = c.precheck(t.Context(), time.Second, 0, func(string) time.Time { return time.Now().Add(-2 * time.Second) })
	if stop, err := check("web.example.com", "", "v", nil); !stop || err == nil || !strings.Contains(err.Error(), "within 1s") {
		t.Errorf("a record written longer ago than the timeout: check = %v, %v; want the timeout at once", stop, err)
	}
}

func TestPrecheckAsksTheChallengeNameAndStops(t *testing.T) {
	cf := newZoneDoH(t)
	c := newChecker([][]string{{cf.url()}}, trust(cf.Server))

	// lego hands over the name it found itself: the check asks where the DNS
	// provider wrote the record, _acme-challenge.<domain>.
	cf.set("_acme-challenge.web.example.com", "v")
	check := c.precheck(t.Context(), time.Minute, 0, unknownWrite)
	if stop, err := check("web.example.com", "elsewhere.test.", "v", nil); !stop || err != nil {
		t.Errorf("visible: check = %v, %v; want true, nil", stop, err)
	}

	// Not visible yet: go on, with what is missing.
	check = c.precheck(t.Context(), time.Minute, 0, unknownWrite)
	stop, err := check("other.example.com", "", "v", nil)
	if stop || err == nil || !strings.Contains(err.Error(), "_acme-challenge.other.example.com") {
		t.Errorf("not visible: check = %v, %v; want false and why", stop, err)
	}

	// Past the timeout from the first call: stop, with an error that says so.
	check = c.precheck(t.Context(), 50*time.Millisecond, 0, unknownWrite)
	if stop, _ := check("other.example.com", "", "v", nil); stop {
		t.Fatal("stopped at the first call")
	}
	time.Sleep(80 * time.Millisecond)
	stop, err = check("other.example.com", "", "v", nil)
	if !stop || err == nil || !strings.Contains(err.Error(), "was not visible at every resolver within 50ms") {
		t.Errorf("after the timeout: check = %v, %v; want true and the timeout", stop, err)
	}

	// The end of the issuance stops the wait.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	check = c.precheck(ctx, time.Minute, 0, unknownWrite)
	if stop, err := check("web.example.com", "", "v", nil); !stop || !errors.Is(err, context.Canceled) {
		t.Errorf("after the context: check = %v, %v; want true, context.Canceled", stop, err)
	}
}

// unknownWrite is a check that does not know when the record was written: it
// counts from its first call.
func unknownWrite(string) time.Time { return time.Time{} }
