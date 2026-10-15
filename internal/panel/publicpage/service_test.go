package publicpage

import (
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// panelv1PageWith is an enabled page on the public host with a title and no
// item.
func panelv1PageWith(title string) *panelv1.PublicPage {
	return &panelv1.PublicPage{Enabled: true, Host: publicHost, Title: title}
}

func TestUpdateAndGetRoundTrip(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()

	resp, err := e.admin.GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{}))
	if err != nil {
		t.Fatalf("GetPublicPage: %v", err)
	}
	if !proto.Equal(resp.Msg.GetPage(), f.page) {
		t.Errorf("GetPublicPage = %v\nwant %v", resp.Msg.GetPage(), f.page)
	}
	if got := e.auditLog(); len(got) != 1 || got[0] != "public_page.update public_page "+e.adminID {
		t.Errorf("audit log = %v", got)
	}

	// The host is stored in its canonical form, texts trimmed, the defaults
	// filled in.
	got := e.setPage(&panelv1.PublicPage{Host: " Proxies.Example.TEST ", Title: "  t  ",
		Items: []*panelv1.PublicPageItem{{ProxyId: f.tls.ID, PublicName: " A ", PublicNote: " n\nn "}}})
	want := &panelv1.PublicPage{Host: publicHost, Title: "t", Unavailable: store.PublicUnavailableMark, DefaultLocale: localeRU,
		Items: []*panelv1.PublicPageItem{{ProxyId: f.tls.ID, PublicName: "A", PublicNote: "n\nn"}}}
	if !proto.Equal(got, want) {
		t.Errorf("stored page = %v\nwant %v", got, want)
	}
	stored, err := e.db.PublicPage(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Enabled || stored.Host != publicHost || len(stored.Items) != 1 {
		t.Errorf("the database holds %+v", stored)
	}
}

func TestAnonymousIsRefused(t *testing.T) {
	e := newEnv(t)
	_, err := e.anon.GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{}))
	_ = wantCode(t, err, connect.CodeUnauthenticated)
	_, err = e.anon.UpdatePublicPage(e.ctx, connect.NewRequest(&panelv1.UpdatePublicPageRequest{Page: &panelv1.PublicPage{Host: publicHost}}))
	_ = wantCode(t, err, connect.CodeUnauthenticated)
	if p, _ := e.db.PublicPage(e.ctx); p.Host != "" {
		t.Error("an anonymous update was stored")
	}
}

func TestUpdateValidation(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	long := func(n int, s string) string { return strings.Repeat(s, n) }
	item := func(id, name, note string) []*panelv1.PublicPageItem {
		return []*panelv1.PublicPageItem{{ProxyId: id, PublicName: name, PublicNote: note}}
	}
	for _, c := range []struct {
		name string
		page *panelv1.PublicPage
		code connect.Code
		msg  string
	}{
		{"enabled without a host", &panelv1.PublicPage{Enabled: true}, connect.CodeInvalidArgument, "needs a host"},
		{"host without a dot", &panelv1.PublicPage{Host: "proxies"}, connect.CodeInvalidArgument, "DNS name"},
		{"host with a port", &panelv1.PublicPage{Host: "proxies.example.test:443"}, connect.CodeInvalidArgument, "DNS name"},
		{"host with a scheme", &panelv1.PublicPage{Host: "https://proxies.example.test"}, connect.CodeInvalidArgument, "DNS name"},
		{"host with a path", &panelv1.PublicPage{Host: "proxies.example.test/x"}, connect.CodeInvalidArgument, "DNS name"},
		{"an IPv4 address", &panelv1.PublicPage{Host: "203.0.113.10"}, connect.CodeInvalidArgument, "DNS name"},
		{"an IPv6 address", &panelv1.PublicPage{Host: "2001:db8::1"}, connect.CodeInvalidArgument, "DNS name"},
		{"an IPv6 address in brackets", &panelv1.PublicPage{Host: "[2001:db8::1]"}, connect.CodeInvalidArgument, "DNS name"},
		{"a trailing dot", &panelv1.PublicPage{Host: "proxies.example.test."}, connect.CodeInvalidArgument, "DNS name"},
		{"an empty label", &panelv1.PublicPage{Host: "proxies..example.test"}, connect.CodeInvalidArgument, "DNS name"},
		{"a label of 64", &panelv1.PublicPage{Host: long(64, "a") + ".example.test"}, connect.CodeInvalidArgument, "DNS name"},
		{"254 bytes", &panelv1.PublicPage{Host: strings.TrimSuffix(strings.Repeat(long(50, "a")+".", 5), ".") + ".ab"}, connect.CodeInvalidArgument, "DNS name"},
		{"an underscore", &panelv1.PublicPage{Host: "pro_xies.example.test"}, connect.CodeInvalidArgument, "DNS name"},
		{"a space inside", &panelv1.PublicPage{Host: "pro xies.example.test"}, connect.CodeInvalidArgument, "DNS name"},
		{"title of 121 bytes", &panelv1.PublicPage{Title: long(121, "a")}, connect.CodeInvalidArgument, "title has more than 120 bytes"},
		{"title of 121 bytes in Cyrillic", &panelv1.PublicPage{Title: long(61, "я")}, connect.CodeInvalidArgument, "title has more than 120 bytes"},
		{"title with a control character", &panelv1.PublicPage{Title: "a\x01b"}, connect.CodeInvalidArgument, "control"},
		{"body over 16 KiB", &panelv1.PublicPage{BodyMd: long(16385, "a")}, connect.CodeInvalidArgument, "body_md has more than"},
		{"unavailable of another value", &panelv1.PublicPage{Unavailable: "sometimes"}, connect.CodeInvalidArgument, "unavailable must be"},
		{"a locale the page lacks", &panelv1.PublicPage{DefaultLocale: "de"}, connect.CodeInvalidArgument, "default_locale must be"},
		{"101 items", &panelv1.PublicPage{Items: make([]*panelv1.PublicPageItem, 101)}, connect.CodeInvalidArgument, "at most 100 items"},
		{"a proxy that does not exist", &panelv1.PublicPage{Items: item("01K6Y00000000000000000000Z", "", "")}, connect.CodeNotFound, "no such proxy"},
		{"an empty proxy id", &panelv1.PublicPage{Items: item("", "", "")}, connect.CodeNotFound, "no such proxy"},
		{"a proxy twice", &panelv1.PublicPage{Items: append(item(f.tls.ID, "a", ""), item(f.tls.ID, "b", "")...)}, connect.CodeInvalidArgument, "names a proxy that an item before it names"},
		{"a name of 65 characters", &panelv1.PublicPage{Items: item(f.tls.ID, long(65, "я"), "")}, connect.CodeInvalidArgument, "public_name has more than 64 characters"},
		{"a note of 281 characters", &panelv1.PublicPage{Items: item(f.tls.ID, "a", long(281, "я"))}, connect.CodeInvalidArgument, "public_note has more than 280 characters"},
		{"a name with a line break", &panelv1.PublicPage{Items: item(f.tls.ID, "a\nb", "")}, connect.CodeInvalidArgument, "control"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.admin.UpdatePublicPage(e.ctx, connect.NewRequest(&panelv1.UpdatePublicPageRequest{Page: c.page}))
			ce := wantCode(t, err, c.code)
			if !strings.Contains(ce.Message(), c.msg) {
				t.Errorf("message %q, want it to say %q", ce.Message(), c.msg)
			}
		})
	}
	// Nothing of that was stored.
	resp, err := e.admin.GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{}))
	if err != nil || !proto.Equal(resp.Msg.GetPage(), f.page) {
		t.Errorf("the page changed: %v, %v", resp.Msg.GetPage(), err)
	}
	// The limits themselves are fine.
	e.setPage(&panelv1.PublicPage{Host: long(63, "a") + "." + long(63, "b") + "." + long(63, "c") + "." + long(57, "d") + ".ab",
		Title: long(60, "я"), BodyMd: long(16384, "a"),
		Items: item(f.tls.ID, long(64, "я"), long(280, "я"))})
	if got := e.auditLog(); len(got) != 2 {
		t.Errorf("audit log = %v, want the two updates that went through", got)
	}
}

// A public host that an earlier admin request used, or that this one uses, is
// refused.
func TestHostOfTheAdminIsRefused(t *testing.T) {
	e := newEnv(t)
	e.fixture()

	// An admin was served on adminHost (any authenticated request will do).
	if _, err := e.adminAs(adminHost+":8443").GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{})); err != nil {
		t.Fatalf("GetPublicPage as %s: %v", adminHost, err)
	}
	hosts, err := e.db.AdminHosts(e.ctx)
	if err != nil || len(hosts) != 2 || hosts[0].Host != adminHost {
		t.Fatalf("admin hosts = %v, %v; want %s newest and the loopback of the other requests", hosts, err, adminHost)
	}

	// From another host now: refused all the same.
	_, err = e.adminAs("other.example.test").UpdatePublicPage(e.ctx, connect.NewRequest(&panelv1.UpdatePublicPageRequest{
		Page: &panelv1.PublicPage{Host: "Panel.Example.Test"},
	}))
	ce := wantCode(t, err, connect.CodeInvalidArgument)
	if ce.Message() != errAdminHost.Error() {
		t.Errorf("message %q, want %q", ce.Message(), errAdminHost.Error())
	}

	// The host of the request that saves it.
	_, err = e.adminAs("fresh.example.test").UpdatePublicPage(e.ctx, connect.NewRequest(&panelv1.UpdatePublicPageRequest{
		Page: &panelv1.PublicPage{Host: "fresh.example.test"},
	}))
	ce = wantCode(t, err, connect.CodeInvalidArgument)
	if ce.Message() != errAdminHost.Error() {
		t.Errorf("message %q, want %q", ce.Message(), errAdminHost.Error())
	}

	// Anonymous requests record nothing.
	_, _ = e.anon.GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{}))
	resp, body := e.get("GET", "/", "nobody.example.test", nil)
	_ = body
	if resp.StatusCode == 0 {
		t.Fatal("no response")
	}
	hosts, _ = e.db.AdminHosts(e.ctx)
	for _, h := range hosts {
		if h.Host == "nobody.example.test" {
			t.Error("an anonymous request's host was recorded")
		}
	}
	if p, _ := e.db.PublicPage(e.ctx); p.Host != publicHost {
		t.Error("the refused host was stored")
	}
}

// A name is written at most once an hour, and the newest time is kept then.
func TestAdminHostsAreWrittenOnceAnHour(t *testing.T) {
	e := newEnv(t)
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	now := t0
	e.svc.now = func() time.Time { return now }
	client := e.adminAs(adminHost)
	call := func() {
		t.Helper()
		if _, err := client.GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{})); err != nil {
			t.Fatal(err)
		}
	}
	seen := func() int64 {
		t.Helper()
		hosts, err := e.db.AdminHosts(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hosts {
			if h.Host == adminHost {
				return h.LastSeenUnix
			}
		}
		return 0
	}
	call()
	if got := seen(); got != t0.Unix() {
		t.Fatalf("after the first request last_seen = %d, want %d", got, t0.Unix())
	}
	now = t0.Add(30 * time.Minute)
	call()
	if got := seen(); got != t0.Unix() {
		t.Errorf("after a request within the hour last_seen = %d, want still %d", got, t0.Unix())
	}
	now = t0.Add(61 * time.Minute)
	call()
	if got := seen(); got != now.Unix() {
		t.Errorf("after a request an hour later last_seen = %d, want %d", got, now.Unix())
	}
}
