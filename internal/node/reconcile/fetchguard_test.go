package reconcile

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// resolverTo is a resolver that answers every A question with ip and no
// other question, as a hostile or rebound DNS name does.
func resolverTo(t *testing.T, ip [4]byte) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true},
				Questions: q.Questions,
			}
			if q.Questions[0].Type == dnsmessage.TypeA {
				resp.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: ip},
				}}
			}
			if b, err := resp.Pack(); err == nil {
				_, _ = pc.WriteTo(b, from)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp4", pc.LocalAddr().String())
	}}
}

// The direct route of a subscription fetch goes to public addresses only, as
// artifact downloads do: a redirect to loopback or to the metadata service, a
// name that resolves to a private address, and a redirect to a url with
// credentials or another scheme are refused, and the inner service is never
// reached.
func TestSubscriptionFetchReachesPublicAddressesOnly(t *testing.T) {
	var innerHits atomic.Int32
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerHits.Add(1)
		_, _ = w.Write([]byte("secret"))
	}))
	t.Cleanup(inner.Close)
	cases := []struct {
		name, location, url string
		resolver            bool
		want                string
	}{
		{name: "redirect to loopback", location: inner.URL + "/", want: "public addresses only"},
		{name: "redirect to metadata", location: "http://169.254.169.254/latest/meta-data/", want: "public addresses only"},
		{name: "name resolves to a private address", url: "http://sub.example.test:80/s", resolver: true, want: "public addresses only"},
		{name: "redirect with credentials", location: "http://user:pw@" + inner.Listener.Addr().String() + "/", want: "without credentials"},
		{name: "redirect to another scheme", location: "file:///etc/passwd", want: "without credentials"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, c.location, http.StatusFound)
			}))
			t.Cleanup(origin.Close)
			originAP := netip.MustParseAddrPort(origin.Listener.Addr().String())
			// Only the origin passes; with credentials the inner server would
			// pass too, so the url check alone must refuse that redirect.
			h.r.fetchAllowDial = func(ap netip.AddrPort) bool {
				return ap == originAP || (strings.Contains(c.location, "@") && ap.String() == inner.Listener.Addr().String())
			}
			raw := origin.URL + "/s"
			if c.resolver {
				h.r.Resolver = resolverTo(t, [4]byte{10, 0, 0, 1})
				raw = c.url
			}
			before := innerHits.Load()
			body, err := h.r.get(context.Background(), h.r.directDialer(), raw, 1<<20)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("get = %q, %v; want an error with %q", body, err, c.want)
			}
			if innerHits.Load() != before {
				t.Fatal("the inner service was reached")
			}
		})
	}
}
