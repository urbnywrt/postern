package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

func TestLegoNeverAsksTheResolverOfTheSystem(t *testing.T) {
	m := &Manager{LookupIP: noLookup}
	m.init()

	// lego's own DNS client has no nameserver left: a query fails at once,
	// before a packet is sent.
	start := time.Now()
	_, err := dns01.FindZoneByFqdn("web.example.com.")
	var de *dns01.DNSError
	if !errors.As(err, &de) || !strings.Contains(err.Error(), "empty list of nameservers") {
		t.Errorf("FindZoneByFqdn = %v, want the error of a client without nameservers", err)
	}

	// The CNAME of the challenge name is therefore not followed: lego asks
	// where the DNS provider writes, and with the value the manager computes.
	info := dns01.GetChallengeInfo("web.example.com", "token.thumbprint")
	if info.EffectiveFQDN != "_acme-challenge.web.example.com." || info.FQDN != info.EffectiveFQDN {
		t.Errorf("GetChallengeInfo = %+v", info)
	}
	if info.Value != txtValue("token.thumbprint") {
		t.Errorf("txtValue = %q, lego's %q", txtValue("token.thumbprint"), info.Value)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("lego's lookups took %v: they went to a nameserver", d)
	}
}

func noLookup(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("no lookup in this test")
}

func TestTheDirectory(t *testing.T) {
	tests := []struct {
		m    *Manager
		want string
	}{
		{&Manager{}, "https://acme-v02.api.letsencrypt.org/directory"},
		{&Manager{Staging: true}, "https://acme-staging-v02.api.letsencrypt.org/directory"},
		{&Manager{Staging: true, Directory: "https://127.0.0.1:14000/dir"}, "https://127.0.0.1:14000/dir"},
	}
	for _, tt := range tests {
		if got := tt.m.directory(); got != tt.want {
			t.Errorf("directory() = %q, want %q", got, tt.want)
		}
	}
}

func TestHTTPClientsIgnoreProxiesAndResolveOverLookupIP(t *testing.T) {
	// A proxy that the environment names and that does not work: a client
	// that used it would fail.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var asked []string
	m := &Manager{
		RootCAs: trust(srv),
		LookupIP: func(_ context.Context, host string) ([]netip.Addr, error) {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, host)
			if host == "example.com" { // the name of the certificate of httptest
				// An address where nothing listens first: the next one is tried.
				return []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}, nil
			}
			return nil, errors.New("no such host")
		},
	}
	m.init()
	defer m.transport.CloseIdleConnections()

	if m.transport.Proxy != nil {
		t.Error("the transport takes proxies from somewhere")
	}
	if got := m.transport.TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x", got)
	}
	ctx := t.Context()
	for name, c := range map[string]*http.Client{"cloudflare": m.httpClient(), "acme": m.acmeClient(ctx)} {
		if c.Timeout != 30*time.Second {
			t.Errorf("%s: Timeout = %v, want 30 s", name, c.Timeout)
		}
		resp, err := c.Get("https://example.com:" + port + "/")
		if err != nil {
			t.Fatalf("%s: GET by name: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "ok" {
			t.Errorf("%s: body %q", name, body)
		}
	}
	mu.Lock()
	if len(asked) == 0 || !slices.Contains(asked, "example.com") {
		t.Errorf("LookupIP was asked %q, want example.com", asked)
	}
	before := len(asked)
	mu.Unlock()

	// An address is not looked up.
	resp, err := m.httpClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET by address: %v", err)
	}
	_ = resp.Body.Close()
	// A name that does not resolve says so.
	_, err = m.httpClient().Get("https://missing.example.com:" + port + "/")
	if err == nil || !strings.Contains(err.Error(), "looking up missing.example.com") {
		t.Errorf("GET of a name that does not resolve = %v", err)
	}
	mu.Lock()
	if got := asked[before:]; !slices.Equal(got, []string{"missing.example.com"}) {
		t.Errorf("then LookupIP was asked %q", got)
	}
	mu.Unlock()
}

func TestACMERequestsEndWithTheIssuance(t *testing.T) {
	arrived, ended := make(chan struct{}), make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/quick" {
			_, _ = io.WriteString(w, "quick")
			return
		}
		close(arrived)
		<-r.Context().Done() // a CA that takes its time
		close(ended)
	}))
	defer srv.Close()
	m := &Manager{RootCAs: trust(srv), LookupIP: noLookup}
	m.init()
	defer m.transport.CloseIdleConnections()

	ctx, cancel := context.WithCancel(t.Context())
	client := m.acmeClient(ctx)
	// A request that ends before the issuance does: its body is read after
	// RoundTrip returned.
	resp, err := client.Get(srv.URL + "/quick")
	if err != nil {
		t.Fatal(err)
	}
	if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "quick" {
		t.Errorf("body %q, %v", body, err)
	}
	_ = resp.Body.Close()

	errc := make(chan error, 1)
	go func() {
		// As lego makes them: without a context.
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/slow", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		errc <- err
	}()
	select { // the issuance ends while the CA has the request
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not reach the server")
	}
	cancel()
	select {
	case err := <-errc:
		var ue *url.Error
		if err == nil || !errors.As(err, &ue) || !errors.Is(err, context.Canceled) {
			t.Errorf("the request = %v, want it cut short with the issuance", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not end with the issuance")
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Error("the server did not see the request end")
	}
}

// fakeACME is as much of an ACME server as an issuance reaches before the CA
// refuses its order for a rate limit: the directory, nonces, the account, and
// a newOrder that answers 429 rateLimited with Retry-After.
type fakeACME struct {
	*httptest.Server
	orders atomic.Int32
	nonce  atomic.Int64
}

func newFakeACME(t *testing.T, retryAfter string) *fakeACME {
	t.Helper()
	f := &fakeACME{}
	mux := http.NewServeMux()
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	base := f.URL
	nonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", f.nonce.Add(1)))
	}
	mux.HandleFunc("/dir", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"revokeCert":%q,"keyChange":%q}`,
			base+"/nonce", base+"/account", base+"/order", base+"/revoke", base+"/key")
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) { nonce(w) })
	mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		w.Header().Set("Location", base+"/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"status":"valid"}`)
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, _ *http.Request) {
		f.orders.Add(1)
		nonce(w)
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("Retry-After", retryAfter)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rateLimited",`+
			`"detail":"too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s","status":429}`)
	})
	return f
}

func TestTheRateLimitOfTheCAIsHonoured(t *testing.T) {
	// Through lego: its rate-limit error is read as it is, not as a text.
	ca := newFakeACME(t, "3600")
	r := newRig(t)
	r.m.obtain = nil
	r.m.Directory = ca.URL + "/dir"
	r.m.RootCAs = trust(ca.Server)
	rec := &recordingDNS{}
	r.m.DNS = func(Credential) (DNSProvider, error) { return rec, nil }

	err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	if err == nil || !strings.Contains(err.Error(), "rateLimited") {
		t.Fatalf("Issue = %v, want the rate limit", err)
	}
	if n := ca.orders.Load(); n != 1 {
		t.Errorf("%d orders, want 1: no retry into a rate limit", n)
	}
	if st := r.m.Status("web.example.com"); !st.RetryAt.Equal(r.clock.now().Add(time.Hour)) {
		t.Errorf("RetryAt = %v, want the Retry-After of the CA, an hour on", st.RetryAt)
	}
	r.clock.add(30 * time.Minute)
	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); !errors.Is(err, ErrBackoff) {
		t.Errorf("Issue half an hour on = %v, want ErrBackoff", err)
	}
	r.clock.add(31 * time.Minute)
	_ = r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	if n := ca.orders.Load(); n != 2 {
		t.Errorf("%d orders after the Retry-After, want 2", n)
	}
}

func TestACMERequestsLeaveNoRegistrationsBehind(t *testing.T) {
	// lego never closes the body of its HEAD requests for nonces, nor of
	// some others: none of them may leave a registration on the context of
	// the issuance, which lives for minutes.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		_, _ = io.WriteString(w, "body")
	}))
	defer srv.Close()
	m := &Manager{RootCAs: trust(srv), LookupIP: noLookup}
	m.init()
	defer m.transport.CloseIdleConnections()
	ctx := t.Context()
	tr := &ctxTransport{base: m.transport, ctx: ctx}

	client := &http.Client{Transport: tr, Timeout: HTTPTimeout}
	for range 100 {
		resp, err := client.Head(srv.URL) // as lego does: the body is never closed
		if err != nil {
			t.Fatal(err)
		}
		_ = resp
	}
	if n := tr.live.Load(); n != 0 {
		t.Errorf("%d registrations left by HEAD requests", n)
	}
	for range 10 { // read to the end, not closed
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Fatal(err)
		}
	}
	if n := tr.live.Load(); n != 0 {
		t.Errorf("%d registrations left by bodies read to their end", n)
	}
	// Neither read nor closed: released when the request's own context ends.
	short := &http.Client{Transport: tr, Timeout: 100 * time.Millisecond}
	for range 10 {
		if _, err := short.Get(srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for tr.live.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := tr.live.Load(); n != 0 {
		t.Errorf("%d registrations left by bodies that were never read", n)
	}
	if ctx.Err() != nil {
		t.Fatal("the context of the issuance ended")
	}
}

// recordingDNS is a DNSProvider that notes its calls, and the context of each
// as it was during the call.
type recordingDNS struct {
	mu        sync.Mutex
	calls     []string
	ctxs      []context.Context
	ended     []error         // ctx.Err() during the call
	deadlines []time.Duration // how long the call had, or 0 without a deadline
	err       error
}

func (r *recordingDNS) note(ctx context.Context, call string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
	r.ctxs = append(r.ctxs, ctx)
	r.ended = append(r.ended, ctx.Err())
	var left time.Duration
	if dl, ok := ctx.Deadline(); ok {
		left = time.Until(dl)
	}
	r.deadlines = append(r.deadlines, left)
	return r.err
}

func (r *recordingDNS) RemoveStale(ctx context.Context, domain string) error {
	return r.note(ctx, "stale "+domain)
}

func (r *recordingDNS) Present(ctx context.Context, domain, value string) error {
	return r.note(ctx, "present "+domain+" "+value)
}

func (r *recordingDNS) CleanUp(ctx context.Context, domain, value string) error {
	return r.note(ctx, "cleanup "+domain+" "+value)
}

func TestLegoDNSWritesTheDigestAndAlwaysCleansUp(t *testing.T) {
	rec := &recordingDNS{}
	ctx, cancel := context.WithCancel(t.Context())
	d := &legoDNS{ctx: ctx, provider: rec, log: (&Manager{}).log(), timeout: 3 * time.Minute, interval: 5 * time.Second}
	if !d.writtenAt("web.example.com").IsZero() {
		t.Error("a record is noted as written before Present")
	}
	before := time.Now()
	if err := d.Present("web.example.com", "token", "token.thumbprint"); err != nil {
		t.Fatal(err)
	}
	// The check counts its first wait and its timeout from the writing.
	if w := d.writtenAt("web.example.com"); w.Before(before) || w.After(time.Now()) {
		t.Errorf("writtenAt = %v, want the time Present wrote the record", w)
	}
	cancel() // the issuance is cut short: the record goes all the same
	rec.err = errors.New("the API is down")
	if err := d.CleanUp("web.example.com", "token", "token.thumbprint"); err == nil {
		t.Error("the error of the provider was lost")
	}
	v := txtValue("token.thumbprint")
	if want := []string{"present web.example.com " + v, "cleanup web.example.com " + v}; !slices.Equal(rec.calls, want) {
		t.Errorf("calls = %q, want %q", rec.calls, want)
	}
	if rec.ctxs[0] != ctx {
		t.Error("Present does not run in the context of the issuance")
	}
	if err := rec.ended[1]; err != nil {
		t.Errorf("CleanUp ran with a context that had ended: %v", err)
	}
	if left := rec.deadlines[1]; left <= 0 || left > HTTPTimeout {
		t.Errorf("CleanUp had %v, want a deadline of HTTPTimeout at the most", left)
	}
	if timeout, interval := d.Timeout(); timeout != 3*time.Minute || interval != 5*time.Second {
		t.Errorf("Timeout = %v, %v", timeout, interval)
	}
}
