package reconcile

import (
	"cmp"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/socks5"
)

// subToken is the token in the URL of the subscriptions of the tests: a
// credential, which must show up nowhere.
const subToken = "sub-token-7d1f0c2b9e" // gitleaks:allow (a fake token)

// subServer serves a subscription, at a path that ends in path ("/" and the
// token of the tests when it is empty).
type subServer struct {
	mu     sync.Mutex
	path   string
	body   string
	status int
	hits   int
	agent  string
}

func (s *subServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits++
	s.agent = r.Header.Get("User-Agent")
	if !strings.HasSuffix(r.URL.Path, cmp.Or(s.path, "/"+subToken)) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	_, _ = io.WriteString(w, s.body)
}

func (s *subServer) set(body string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.status = body, status
}

func (s *subServer) hitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// newSubServer serves body; host is where it listens, as host:port.
func newSubServer(t *testing.T, body string) (*subServer, string) {
	t.Helper()
	s := &subServer{body: body}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, srv.Listener.Addr().String()
}

func subEgress(id, url, sel string) *nodev1.Egress {
	return &nodev1.Egress{
		Id: id, Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
		ParamsJson: `{"url":` + jsonString(url) + `,"select":` + jsonString(sel) + `}`,
	}
}

func subURL(hostport string) string { return "http://" + hostport + "/s/" + subToken }

// lines joins the links of a subscription.
func lines(links ...string) string { return strings.Join(links, "\n") + "\n" }

// memberKeys is the keys of the members of a record, in order.
func memberKeys(h *harness, id string) []string {
	var out []string
	for _, m := range h.runtime().Egresses[id].Members {
		out = append(out, m.Key)
	}
	return out
}

// A subscription is fetched, cached and read: its servers become members in
// its order, each once (a server twice, by its key, is one member), and a line
// that cannot be read is left out. A refresh that brings the same servers, in
// another order or under other names, keeps the instance and the ports of the
// members and only reorders the chain; one that brings another server makes a
// new generation.
func TestSubscriptionMembersKeepTheirPortsAcrossRefreshes(t *testing.T) {
	h := newHarness(t)
	a, b, c := vless("a.example.com", 443, "A"), vless("b.example.com", 443, "B"), vless("c.example.com", 443, "C")
	srv, hostport := newSubServer(t, lines(a, b, vless("a.example.com", 443, "A again"), "garbage://line", c))
	h.apply(h.providerState(1, subEgress("sub", subURL(hostport), "all")))
	h.pass()

	ka, kb, kc := keyOf(t, a), keyOf(t, b), keyOf(t, c)
	if got := memberKeys(h, "sub"); !slices.Equal(got, []string{ka, kb, kc}) {
		t.Fatalf("members = %v, want %v", got, []string{ka, kb, kc})
	}
	rec := h.runtime().Egresses["sub"]
	ports := map[string]uint16{}
	var chain []string
	for _, m := range rec.Members {
		ports[m.Key] = m.Port
		chain = append(chain, "sub/"+m.Key+"=socks5:"+addr(m.Port))
	}
	if got := chainMembers(h.fakeEdge(1).lastConfig(t), "alt"); !slices.Equal(got, chain) {
		t.Errorf("chain alt = %v, want %v", got, chain)
	}
	cache := filepath.Join(h.paths.EgressDir("sub"), "subscription.txt")
	data, err := os.ReadFile(cache)
	if err != nil || !strings.Contains(string(data), "garbage://line") {
		t.Errorf("cached subscription = %q, %v", data, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(cache); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("cache: %v, %v; want mode 0600", info, err)
		}
	}
	if srv.agent != "Mozilla/5.0" {
		t.Errorf("User-Agent = %q", srv.agent)
	}
	evs := h.eventsOf("subscription_refreshed")
	if len(evs) != 1 || evs[0].GetDetails()["servers"] != "4" || evs[0].GetDetails()["failed_lines"] != "1" {
		t.Errorf("subscription_refreshed events = %v", evs)
	}

	// Not before six hours.
	h.clock.Advance(6*time.Hour - time.Minute)
	h.pass()
	if n := srv.hitCount(); n != 1 {
		t.Errorf("fetched %d times before six hours", n)
	}

	// The same servers, in another order and under other names.
	srv.set(lines(vless("c.example.com", 443, "C2"), vless("a.example.com", 443, "A2"), vless("b.example.com", 443, "B2")), 0)
	h.clock.Advance(time.Minute)
	h.pass()
	if n := srv.hitCount(); n != 2 {
		t.Fatalf("fetched %d times after six hours, want 2", n)
	}
	rec2 := h.runtime().Egresses["sub"]
	if rec2.Generation != 1 || rec2.Hash != rec.Hash {
		t.Errorf("record = %+v, want generation 1 still", rec2)
	}
	if got := memberKeys(h, "sub"); !slices.Equal(got, []string{kc, ka, kb}) {
		t.Errorf("members = %v, want the new order", got)
	}
	for _, m := range rec2.Members {
		if m.Port != ports[m.Key] {
			t.Errorf("member %s moved from port %d to %d", m.Key, ports[m.Key], m.Port)
		}
	}
	chain = nil
	for _, k := range []string{kc, ka, kb} {
		chain = append(chain, "sub/"+k+"=socks5:"+addr(ports[k]))
	}
	if got := chainMembers(h.fakeEdge(1).lastConfig(t), "alt"); !slices.Equal(got, chain) {
		t.Errorf("chain alt = %v, want %v", got, chain)
	}

	// A new server: a new generation with all four.
	d := vless("d.example.com", 443, "D")
	srv.set(lines(a, b, c, d), 0)
	h.clock.Advance(6 * time.Hour)
	h.pass()
	if rec := h.runtime().Egresses["sub"]; rec.Generation != 2 || len(rec.Members) != 4 {
		t.Errorf("record = %+v, want g2 with four members", rec)
	}
	assertNoEgressSecretsInEvents(t, h)
}

// The selection of a subscription picks its members: the first server, or
// those whose name holds a text.
func TestSubscriptionSelect(t *testing.T) {
	a, b, c := vless("a.example.com", 443, "Amsterdam-1"), vless("b.example.com", 443, "Berlin"), vless("c.example.com", 443, "amsterdam-2")
	for _, tc := range []struct {
		sel  string
		want []string
	}{
		{"all", []string{a, b, c}},
		{"", []string{a, b, c}},
		{"first", []string{a}},
		{"name:AMSTERDAM", []string{a, c}},
		{"name:berlin", []string{b}},
	} {
		t.Run(tc.sel, func(t *testing.T) {
			h := newHarness(t)
			_, hostport := newSubServer(t, lines("not a link", a, b, c))
			h.apply(h.providerState(1, subEgress("sub", subURL(hostport), tc.sel)))
			h.pass()
			var want []string
			for _, l := range tc.want {
				want = append(want, keyOf(t, l))
			}
			if got := memberKeys(h, "sub"); !slices.Equal(got, want) {
				t.Errorf("members = %v, want %v", got, want)
			}
		})
	}
}

// A selection that picks nothing leaves the egress without an instance.
func TestSubscriptionSelectingNothing(t *testing.T) {
	h := newHarness(t)
	_, hostport := newSubServer(t, lines(vless("a.example.com", 443, "A")))
	h.apply(h.providerState(1, subEgress("sub", subURL(hostport), "name:zzz")))
	h.pass()
	if c := h.container("postern-egr-sub-g1"); c != nil {
		t.Errorf("container = %+v", c)
	}
	if evs := h.eventsOf("egress_failed"); len(evs) != 1 || !strings.Contains(evs[0].GetMessage(), "no server") {
		t.Errorf("egress_failed events = %v", evs)
	}
}

// An egress has 64 members at the most; the rest are left out, and said so.
func TestSubscriptionMembersAreCapped(t *testing.T) {
	h := newHarness(t)
	var links []string
	for i := range 70 {
		links = append(links, vless("s"+strconv.Itoa(i)+".example.com", 443, "s"))
	}
	_, hostport := newSubServer(t, lines(links...))
	h.apply(h.providerState(1, subEgress("sub", subURL(hostport), "all")))
	h.pass()
	if got := memberKeys(h, "sub"); len(got) != 64 || got[0] != keyOf(t, links[0]) || got[63] != keyOf(t, links[63]) {
		t.Errorf("members = %d (%v...), want the first 64", len(got), got[:min(len(got), 2)])
	}
	if evs := h.eventsOf("egress_members_capped"); len(evs) != 1 || evs[0].GetDetails()["left_out"] != "6" {
		t.Errorf("egress_members_capped events = %v", evs)
	}
}

// A refresh that fails keeps what the cache has; it is said once, and tried
// again after a while, not at every pass.
func TestSubscriptionFailureKeepsTheCache(t *testing.T) {
	h := newHarness(t)
	a := vless("a.example.com", 443, "A")
	srv, hostport := newSubServer(t, lines(a))
	h.apply(h.providerState(1, subEgress("sub", subURL(hostport), "all")))
	h.pass()

	for name, set := range map[string]func(){
		"an error answer": func() { srv.set("", http.StatusInternalServerError) },
		"no server in it": func() { srv.set("nothing here\n", 0) },
		"too large":       func() { srv.set(strings.Repeat("x", 1<<20+1), 0) },
	} {
		t.Run(name, func(t *testing.T) {
			set()
			failed := len(h.eventsOf("subscription_failed"))
			h.clock.Advance(6 * time.Hour)
			h.pass()
			if got := memberKeys(h, "sub"); !slices.Equal(got, []string{keyOf(t, a)}) {
				t.Errorf("members = %v, want those of the cache", got)
			}
			if rec := h.runtime().Egresses["sub"]; rec.Generation != 1 {
				t.Errorf("record = %+v", rec)
			}
			evs := h.eventsOf("subscription_failed")
			if len(evs) != failed+1 {
				t.Fatalf("subscription_failed events = %d, want one more than %d", len(evs), failed)
			}
			if text := protoText(evs[len(evs)-1]); strings.Contains(text, subToken) {
				t.Errorf("the event holds the token of the URL: %s", text)
			}
			hits := srv.hitCount()
			h.clock.Advance(subscriptionRetryAfter - time.Second)
			h.pass()
			if srv.hitCount() != hits {
				t.Error("tried again before the retry delay")
			}
			h.clock.Advance(time.Second)
			h.pass()
			if srv.hitCount() != hits+1 {
				t.Error("not tried again after the retry delay")
			}
			if len(h.eventsOf("subscription_failed")) != failed+1 {
				t.Error("the same failure was reported again")
			}
		})
	}

	// It works again: refreshed, and a later failure is reported again.
	srv.set(lines(a), 0)
	h.clock.Advance(subscriptionRetryAfter)
	h.pass()
	if n := len(h.eventsOf("subscription_refreshed")); n != 2 {
		t.Errorf("subscription_refreshed events = %d, want 2", n)
	}
}

// Another URL is fetched at once, whatever the age of the cache.
func TestSubscriptionOfAnotherURLIsFetchedAtOnce(t *testing.T) {
	h := newHarness(t)
	_, first := newSubServer(t, lines(vless("a.example.com", 443, "A")))
	h.apply(h.providerState(1, subEgress("sub", subURL(first), "all")))
	h.pass()
	b := vless("b.example.com", 443, "B")
	srv2, second := newSubServer(t, lines(b))
	h.apply(h.providerState(2, subEgress("sub", subURL(second), "all")))
	h.pass()
	if srv2.hitCount() != 1 {
		t.Fatalf("the new URL was fetched %d times", srv2.hitCount())
	}
	if got := memberKeys(h, "sub"); !slices.Equal(got, []string{keyOf(t, b)}) {
		t.Errorf("members = %v", got)
	}
}

// A subscription that no chain in use takes is not fetched.
func TestSubscriptionOfAnUnusedEgressIsNotFetched(t *testing.T) {
	h := newHarness(t)
	srv, hostport := newSubServer(t, lines(vless("a.example.com", 443, "A")))
	st := h.baseState(1)
	st.Egresses = append(st.Egresses, subEgress("sub", subURL(hostport), "all"))
	st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "spare", MemberEgressIds: []string{"sub"}})
	h.apply(st)
	h.pass()
	if n := srv.hitCount(); n != 0 {
		t.Errorf("fetched %d times", n)
	}
}

// When the node cannot fetch a subscription itself, it goes through the members
// of its default chain that are up, in their order (Global Constraints).
func TestSubscriptionIsFetchedThroughAMemberOfTheDefaultChain(t *testing.T) {
	h := newHarness(t)
	srv, hostport := newSubServer(t, lines(vless("a.example.com", 443, "A")))
	_, port, _ := net.SplitHostPort(hostport)
	var direct atomic.Int32
	h.r.dialDirect = func(context.Context, string, string) (net.Conn, error) {
		direct.Add(1)
		return nil, errors.New("blocked")
	}
	up, down := startSOCKS(t, port), startSOCKS(t, port)

	st := h.providerState(1, subEgress("sub", "http://sub.test:"+port+"/s/"+subToken, "all"))
	st.Egresses = append(st.Egresses,
		&nodev1.Egress{Id: "dead", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"` + down.addr + `"}`},
		&nodev1.Egress{Id: "live", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"` + up.addr + `"}`},
	)
	st.Chains[0].MemberEgressIds = []string{"dead", "live"}
	h.fakeEdge(1).setHealth(
		&edgev1.MemberHealth{ChainId: "default", MemberKey: "dead", Status: "down"},
		&edgev1.MemberHealth{ChainId: "default", MemberKey: "live", Status: "up"},
	)
	h.apply(st)
	h.pass()
	h.pass() // the cache is fresh: no second fetch
	if srv.hitCount() != 1 {
		t.Fatalf("the subscription was fetched %d times, want once", srv.hitCount())
	}
	if direct.Load() == 0 {
		t.Error("the node did not try to fetch it itself first")
	}
	if up.count() != 1 || down.count() != 0 {
		t.Errorf("the member that is up was asked %d times, the one that is down %d times", up.count(), down.count())
	}
	if rec := h.runtime().Egresses["sub"]; rec.Generation != 1 {
		t.Errorf("record = %+v", rec)
	}
}

// testSOCKS is a SOCKS5 server on the loopback that takes every CONNECT to
// the loopback port of the test's web server.
type testSOCKS struct {
	addr  string
	mu    sync.Mutex
	conns int
}

func (s *testSOCKS) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func startSOCKS(t *testing.T, port string) *testSOCKS {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	s := &testSOCKS{addr: l.Addr().String()}
	srv := &socks5.Server{
		Dial: func(ctx context.Context, _ socks5.Request) (net.Conn, error) {
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, "tcp", "127.0.0.1:"+port)
		},
		Logger: slog.New(slog.DiscardHandler),
	}
	go func() { _ = srv.Serve(l) }()
	return s
}

// The error of a fetch never holds its URL, which may hold a token.
func TestFetchErrorsHideTheURL(t *testing.T) {
	inner := errors.New("dial tcp 203.0.113.9:443: connect: connection refused")
	err := fetchError(&url.Error{Op: "Get", URL: "https://sub.example.com/s/" + subToken, Err: inner})
	if strings.Contains(err.Error(), subToken) || !errors.Is(err, inner) {
		t.Errorf("fetchError = %v", err)
	}
	if err := fetchError(inner); err.Error() != inner.Error() {
		t.Errorf("fetchError of another error = %v", err)
	}
}

// The wait after a failed fetch counts from the end of the fetch, however long
// it took.
func TestSubscriptionRetryCountsFromTheEndOfTheFetch(t *testing.T) {
	h := newHarness(t)
	srv, hostport := newSubServer(t, "")
	srv.set("", http.StatusInternalServerError)
	h.r.dialDirect = func(ctx context.Context, network, addr string) (net.Conn, error) {
		h.clock.Advance(16 * time.Minute) // a slow fetch
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	h.apply(h.providerState(1, subEgress("sub", subURL(hostport), "all")))
	h.pass()
	if srv.hitCount() != 1 {
		t.Fatalf("fetched %d times", srv.hitCount())
	}
	h.r.dialDirect = nil
	h.pass()
	if srv.hitCount() != 1 {
		t.Fatal("a slow fetch that failed was tried again at once")
	}
	h.clock.Advance(subscriptionRetryAfter - time.Second)
	h.pass()
	if srv.hitCount() != 1 {
		t.Error("tried again before the retry delay")
	}
	h.clock.Advance(time.Second)
	h.pass()
	if srv.hitCount() != 2 {
		t.Errorf("fetched %d times after the retry delay, want 2", srv.hitCount())
	}
}

// After a failure, a corrected URL is fetched at once.
func TestSubscriptionOfACorrectedURLIsFetchedAtOnce(t *testing.T) {
	h := newHarness(t)
	srv, hostport := newSubServer(t, lines(vless("a.example.com", 443, "A")))
	h.apply(h.providerState(1, subEgress("sub", "http://"+hostport+"/wrong/"+subToken+"x", "all")))
	h.pass()
	if srv.hitCount() != 1 || len(h.eventsOf("subscription_failed")) != 1 {
		t.Fatalf("fetched %d times, failures %v", srv.hitCount(), h.eventsOf("subscription_failed"))
	}
	h.apply(h.providerState(2, subEgress("sub", subURL(hostport), "all")))
	h.pass()
	if srv.hitCount() != 2 {
		t.Fatalf("the corrected URL: fetched %d times, want 2", srv.hitCount())
	}
	if rec := h.runtime().Egresses["sub"]; rec.Generation != 1 {
		t.Errorf("record = %+v", rec)
	}
	if n := len(h.r.subRetry); n != 0 {
		t.Errorf("%d failures are remembered", n)
	}
}

// The panel asks for a refresh with another refresh nonce (Ruling S2-17): the
// subscription is fetched at once, whatever the age of the cache; the same
// nonce again fetches nothing. A failed refresh waits as any failure does, but
// a newer request is fetched at once.
func TestSubscriptionRefreshNonce(t *testing.T) {
	h := newHarness(t)
	a, b := vless("a.example.com", 443, "A"), vless("b.example.com", 443, "B")
	srv, hostport := newSubServer(t, lines(a))
	withNonce := func(gen, nonce uint64) {
		e := subEgress("sub", subURL(hostport), "all")
		e.RefreshNonce = nonce
		h.apply(h.providerState(gen, e))
	}
	withNonce(1, 0)
	h.pass()
	h.pass()
	if srv.hitCount() != 1 {
		t.Fatalf("fetched %d times, want once", srv.hitCount())
	}

	srv.set(lines(a, b), 0)
	withNonce(2, 7)
	h.pass()
	if srv.hitCount() != 2 {
		t.Fatalf("a refresh was asked: fetched %d times, want 2", srv.hitCount())
	}
	if rec := h.runtime().Egresses["sub"]; rec.SubscriptionNonce != 7 || len(rec.Members) != 2 {
		t.Errorf("record = %+v, want nonce 7 and both servers", rec)
	}
	withNonce(3, 7)
	h.pass()
	if srv.hitCount() != 2 {
		t.Errorf("the same nonce: fetched %d times, want still 2", srv.hitCount())
	}

	srv.set("", http.StatusBadGateway)
	withNonce(4, 8)
	h.pass()
	h.pass()
	if srv.hitCount() != 3 {
		t.Fatalf("a refresh that fails: fetched %d times, want 3", srv.hitCount())
	}
	withNonce(5, 9)
	h.pass()
	if srv.hitCount() != 4 {
		t.Errorf("a newer request after a failure: fetched %d times, want 4", srv.hitCount())
	}
	if rec := h.runtime().Egresses["sub"]; rec.Generation != 2 || rec.SubscriptionNonce != 7 {
		t.Errorf("record = %+v, want generation 2 still, of nonce 7", rec)
	}
}

// closedPort is a loopback port on which nothing listens.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()
	return port
}

// A fetch tries three members of the default chain at the most after the
// direct route, and gives up when its time is over.
func TestSubscriptionFetchIsBounded(t *testing.T) {
	h := newHarness(t)
	h.r.dialDirect = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("blocked") }
	dead := closedPort(t)
	st := h.providerState(1, subEgress("sub", "http://sub.test:"+dead+"/s/"+subToken, "all"))
	var members []*testSOCKS
	var ids []string
	var health []*edgev1.MemberHealth
	for i := range 5 {
		s := startSOCKS(t, dead)
		id := "m" + strconv.Itoa(i)
		members, ids = append(members, s), append(ids, id)
		st.Egresses = append(st.Egresses, &nodev1.Egress{Id: id, Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"` + s.addr + `"}`})
		health = append(health, &edgev1.MemberHealth{ChainId: "default", MemberKey: id, Status: "up"})
	}
	st.Chains[0].MemberEgressIds = ids
	h.fakeEdge(1).setHealth(health...)
	h.apply(st)
	h.pass()
	for i, s := range members {
		want := 0
		if i < 3 {
			want = 1
		}
		if s.count() != want {
			t.Errorf("member %d was asked %d times, want %d", i, s.count(), want)
		}
	}
	evs := h.eventsOf("subscription_failed")
	if len(evs) != 1 || !strings.Contains(evs[0].GetMessage(), "through m2") || strings.Contains(evs[0].GetMessage(), "m3") {
		t.Errorf("subscription_failed events = %v", evs)
	}

	// A direct route that takes the whole time leaves none for the members.
	h2 := newHarness(t)
	h2.r.fetchBudget = 200 * time.Millisecond
	h2.r.dialDirect = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	live := startSOCKS(t, dead)
	st2 := h2.providerState(1, subEgress("sub", "http://sub.test:"+dead+"/s/"+subToken, "all"))
	st2.Egresses = append(st2.Egresses, &nodev1.Egress{Id: "live", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"` + live.addr + `"}`})
	st2.Chains[0].MemberEgressIds = []string{"live"}
	h2.fakeEdge(1).setHealth(&edgev1.MemberHealth{ChainId: "default", MemberKey: "live", Status: "up"})
	h2.apply(st2)
	start := time.Now()
	h2.pass()
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("the pass took %v", d)
	}
	if live.count() != 0 {
		t.Errorf("the member was asked %d times after the time was over", live.count())
	}
	if evs := h2.eventsOf("subscription_failed"); len(evs) != 1 || !strings.Contains(evs[0].GetMessage(), "not tried") {
		t.Errorf("subscription_failed events = %v", evs)
	}
}

// A subscription fetched is in the runtime record on disk at once, before the
// pass goes on to start its instance.
func TestSubscriptionFetchedIsRecordedAtOnce(t *testing.T) {
	h := newHarness(t)
	_, hostport := newSubServer(t, lines(vless("a.example.com", 443, "A")))
	var seen atomic.Bool
	h.xray.setReady(func(context.Context, providers.Instance) error {
		rt, err := h.store.LoadRuntime()
		if err == nil && !rt.Egresses["sub"].SubscriptionFetched.IsZero() {
			seen.Store(true)
		}
		return nil
	})
	h.apply(h.providerState(1, subEgress("sub", subURL(hostport), "all")))
	h.pass()
	if !seen.Load() {
		t.Error("the fetch was not in the record on disk while the instance started")
	}
}

// The cap of 64 members is taken after the members that the provider cannot
// take are left out: the servers after them take their places.
func TestSubscriptionMembersAreCappedAfterTheInvalidOnes(t *testing.T) {
	h := newHarness(t)
	var links []string
	for i := range 3 {
		links = append(links, vless("127.0.0.1", 1000+i, "loop"))
	}
	for i := range 67 {
		links = append(links, vless("s"+strconv.Itoa(i)+".example.com", 443, "s"))
	}
	_, hostport := newSubServer(t, lines(links...))
	h.apply(h.providerState(1, subEgress("sub", subURL(hostport), "all")))
	h.pass()
	got := memberKeys(h, "sub")
	if len(got) != 64 || got[0] != keyOf(t, links[3]) || got[63] != keyOf(t, links[66]) {
		t.Errorf("members = %d (%v...), want the 64 valid ones after the loopback", len(got), got[:min(len(got), 2)])
	}
	if evs := h.eventsOf("egress_members_capped"); len(evs) != 1 || evs[0].GetDetails()["left_out"] != "3" {
		t.Errorf("egress_members_capped events = %v", evs)
	}
	if evs := h.eventsOf("egress_member_invalid"); len(evs) != 3 {
		t.Errorf("egress_member_invalid events = %d, want 3", len(evs))
	}
}
