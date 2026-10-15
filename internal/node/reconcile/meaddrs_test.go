package reconcile

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// What getProxyConfig and getProxyConfigV6 look like: a comment, the lines of
// the middle proxies by datacenter, a default.
const (
	proxyConfigV4 = `# force_probability 10 10
default 2;
proxy_for 1 149.154.175.50:8888;
proxy_for 1 203.0.113.7:8888;
proxy_for -1 203.0.113.7:8888;
proxy_for 2 203.0.113.8:8888;
proxy_for 2 198.51.100.300:8888;
proxy_for 4 not-an-address:8888;
proxy_for 5;
proxy_for x 203.0.113.9:8888;
proxy_for 3 127.0.0.1:8888;
`
	proxyConfigV6 = `default 2;
proxy_for 1 [2001:db8::d]:8888;
proxy_for 2 [2001:db8::e]:80;
proxy_for 3 2001:db8::f:8888;
`
)

// The lines of the middle proxies are read, by address and port; a line that
// is not one is left out, and so is an address that no middle proxy has (the
// loopback).
func TestParseProxyConfig(t *testing.T) {
	got, skipped := parseProxyConfig([]byte(proxyConfigV4))
	if want := []string{"149.154.175.50:8888", "203.0.113.7:8888", "203.0.113.8:8888"}; !slices.Equal(got, want) {
		t.Errorf("addresses = %v, want %v", got, want)
	}
	if skipped != 5 {
		t.Errorf("skipped = %d, want 5", skipped)
	}
	got, skipped = parseProxyConfig([]byte(proxyConfigV6))
	if want := []string{"[2001:db8::d]:8888", "[2001:db8::e]:80"}; !slices.Equal(got, want) || skipped != 1 {
		t.Errorf("addresses = %v (skipped %d), want %v (1)", got, skipped, want)
	}
	if got, _ := parseProxyConfig([]byte("<html>not a config</html>")); len(got) != 0 {
		t.Errorf("addresses of junk = %v", got)
	}
}

// meServers serves getProxyConfig and getProxyConfigV6.
func meServers(t *testing.T, v4, v6 string) (*subServer, *subServer, []string) {
	t.Helper()
	s4, a4 := newSubServer(t, v4)
	s6, a6 := newSubServer(t, v6)
	s4.path, s6.path = "/getProxyConfig", "/getProxyConfigV6"
	return s4, s6, []string{"http://" + a4 + "/getProxyConfig", "http://" + a6 + "/getProxyConfigV6"}
}

// The agent fetches the middle-proxy lists at its start and every six hours,
// sends their addresses to the edge, and keeps the last good list on disk; a
// list that fails or reads as nothing keeps the last good one.
func TestMiddleProxyAddresses(t *testing.T) {
	h := newHarness(t)
	s4, s6, sources := meServers(t, proxyConfigV4, proxyConfigV6)
	h.r.MEConfigURLs = sources
	h.apply(h.baseState(1))
	h.pass()

	want := []string{"149.154.175.50:8888", "203.0.113.7:8888", "203.0.113.8:8888", "[2001:db8::d]:8888", "[2001:db8::e]:80"}
	if got := h.fakeEdge(1).lastConfig(t).GetMeAddrs(); !slices.Equal(got, want) {
		t.Errorf("me_addrs = %v, want %v", got, want)
	}
	data, err := os.ReadFile(h.paths.MEAddrsPath())
	if err != nil || !strings.Contains(string(data), `"203.0.113.8:8888"`) || !strings.Contains(string(data), `"[2001:db8::e]:80"`) {
		t.Errorf("me-addrs.json = %s, %v", data, err)
	}
	if evs := h.eventsOf("me_addrs_refreshed"); len(evs) != 1 || evs[0].GetDetails()["addresses"] != "5" {
		t.Errorf("me_addrs_refreshed events = %v", evs)
	}

	// Not again before six hours.
	h.clock.Advance(6*time.Hour - time.Second)
	h.pass()
	if s4.hitCount() != 1 || s6.hitCount() != 1 {
		t.Errorf("fetched %d and %d times before six hours", s4.hitCount(), s6.hitCount())
	}

	// A list that fails, and one that reads as nothing: the last good ones
	// stay, on the edge and on disk.
	s4.set("", http.StatusBadGateway)
	s6.set("<html>maintenance</html>", 0)
	h.clock.Advance(time.Second)
	h.pass()
	if s4.hitCount() != 2 || s6.hitCount() != 2 {
		t.Fatalf("fetched %d and %d times after six hours", s4.hitCount(), s6.hitCount())
	}
	if got := h.fakeEdge(1).lastConfig(t).GetMeAddrs(); !slices.Equal(got, want) {
		t.Errorf("me_addrs after failures = %v, want the last good %v", got, want)
	}
	if after, _ := os.ReadFile(h.paths.MEAddrsPath()); string(after) != string(data) {
		t.Errorf("me-addrs.json changed after failures:\n%s", after)
	}
	evs := h.eventsOf("me_addrs_failed")
	if len(evs) != 2 || evs[0].GetDetails()["list"] != "getProxyConfig" || evs[1].GetDetails()["list"] != "getProxyConfigV6" {
		t.Fatalf("me_addrs_failed events = %v, want one per list, by its name", evs)
	}

	// Tried again after a while, not at every pass; reported once.
	h.pass()
	if s4.hitCount() != 2 {
		t.Error("tried again at once")
	}
	h.clock.Advance(meRetryAfter)
	h.pass()
	if s4.hitCount() != 3 {
		t.Error("not tried again after the retry delay")
	}
	if n := len(h.eventsOf("me_addrs_failed")); n != 2 {
		t.Errorf("me_addrs_failed events = %d, want still 2", n)
	}

	// A new agent has the last good list at once, from the disk, while the
	// lists still fail.
	h.r = h.newReconciler()
	h.r.MEConfigURLs = sources
	h.pass()
	if got := h.fakeEdge(1).lastConfig(t).GetMeAddrs(); !slices.Equal(got, want) {
		t.Errorf("me_addrs after a restart = %v, want %v", got, want)
	}

	// The lists work again: refreshed, and taken.
	s4.set(strings.ReplaceAll(proxyConfigV4, "203.0.113.8", "203.0.113.9"), 0)
	s6.set(proxyConfigV6, 0)
	h.clock.Advance(meRetryAfter)
	h.pass()
	if got := h.fakeEdge(1).lastConfig(t).GetMeAddrs(); !slices.Contains(got, "203.0.113.9:8888") || slices.Contains(got, "203.0.113.8:8888") {
		t.Errorf("me_addrs = %v, want the new list", got)
	}
}

// While the agent knows no middle proxy at all, a fresh node, a list that
// failed is tried again after a minute, then after twice as long each time, up
// to fifteen minutes; once it knows some, after fifteen. The wait counts from
// the end of the fetch, however long it took.
func TestMiddleProxyListRetries(t *testing.T) {
	h := newHarness(t)
	s4, s6, sources := meServers(t, proxyConfigV4, proxyConfigV6)
	s4.set("", http.StatusBadGateway)
	s6.set("", http.StatusBadGateway)
	h.r.MEConfigURLs = sources
	h.apply(h.baseState(1))
	h.pass()
	if s4.hitCount() != 1 || s6.hitCount() != 1 {
		t.Fatalf("fetched %d and %d times", s4.hitCount(), s6.hitCount())
	}
	hits := 1
	for _, wait := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute} {
		h.clock.Advance(wait - time.Second)
		h.pass()
		if s4.hitCount() != hits {
			t.Fatalf("tried again before %v (%d times)", wait, s4.hitCount())
		}
		h.clock.Advance(time.Second)
		h.pass()
		if hits++; s4.hitCount() != hits || s6.hitCount() != hits {
			t.Fatalf("after %v: fetched %d and %d times, want %d", wait, s4.hitCount(), s6.hitCount(), hits)
		}
	}

	// getProxyConfig works: the agent knows middle proxies, and the other list
	// waits fifteen minutes, its back-off of no consequence any more.
	h2 := newHarness(t)
	s4, s6, sources = meServers(t, proxyConfigV4, proxyConfigV6)
	s4.set("", http.StatusBadGateway)
	s6.set("", http.StatusBadGateway)
	h2.r.MEConfigURLs = sources
	h2.apply(h2.baseState(1))
	h2.pass()
	h2.clock.Advance(time.Minute)
	h2.pass()
	s4.set(proxyConfigV4, 0)
	h2.clock.Advance(2 * time.Minute)
	h2.pass()
	if s4.hitCount() != 3 || s6.hitCount() != 3 {
		t.Fatalf("fetched %d and %d times, want 3 and 3", s4.hitCount(), s6.hitCount())
	}
	h2.clock.Advance(4 * time.Minute)
	h2.pass()
	if s6.hitCount() != 3 {
		t.Error("getProxyConfigV6 was tried again after four minutes while the agent knows middle proxies")
	}
	h2.clock.Advance(meRetryAfter - 4*time.Minute)
	h2.pass()
	if s6.hitCount() != 4 {
		t.Errorf("getProxyConfigV6 fetched %d times after fifteen minutes, want 4", s6.hitCount())
	}

	// A fetch that takes twenty minutes and fails is not tried again at once.
	h2.r.dialDirect = func(ctx context.Context, network, addr string) (net.Conn, error) {
		h2.clock.Advance(20 * time.Minute)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	h2.clock.Advance(meRetryAfter)
	h2.pass()
	if s6.hitCount() != 5 {
		t.Fatalf("getProxyConfigV6 fetched %d times, want 5", s6.hitCount())
	}
	h2.r.dialDirect = nil
	h2.pass()
	if s6.hitCount() != 5 {
		t.Error("a slow fetch that failed was tried again at once")
	}
}

// A newer desired state cuts a fetch short between two routes: the pass
// starts over at once, and the list is not taken for failed.
func TestAFetchIsCutShortByANewerState(t *testing.T) {
	h := newHarness(t)
	srv, hostport := newSubServer(t, lines(vless("a.example.com", 443, "A")))
	_, port, _ := net.SplitHostPort(hostport)
	live := startSOCKS(t, port)
	kick := make(chan struct{}, 1)
	h.r.dialDirect = func(context.Context, string, string) (net.Conn, error) {
		select {
		case kick <- struct{}{}:
		default:
		}
		return nil, errors.New("blocked")
	}
	st := h.providerState(1, subEgress("sub", "http://sub.test:"+port+"/s/"+subToken, "all"))
	st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "live", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"` + live.addr + `"}`})
	st.Chains[0].MemberEgressIds = []string{"live"}
	h.fakeEdge(1).setHealth(&edgev1.MemberHealth{ChainId: "default", MemberKey: "live", Status: "up"})
	h.apply(st)

	err := h.r.reconcileOnce(context.Background(), &kicks{ch: kick})
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("pass = %v, want it interrupted", err)
	}
	if live.count() != 0 || srv.hitCount() != 0 {
		t.Errorf("after the interruption: the member was asked %d times, the server %d times", live.count(), srv.hitCount())
	}
	if evs := h.eventsOf("subscription_failed"); len(evs) != 0 {
		t.Errorf("an interrupted fetch was reported failed: %v", evs)
	}

	// The next pass fetches it at once, through the member.
	h.pass()
	if live.count() != 1 || srv.hitCount() != 1 {
		t.Errorf("the next pass: the member was asked %d times, the server %d times; want once", live.count(), srv.hitCount())
	}
	if rec := h.runtime().Egresses["sub"]; rec.Generation != 1 {
		t.Errorf("record = %+v", rec)
	}
}
