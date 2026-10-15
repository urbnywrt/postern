package publicpage

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
)

// ask sends the question for domain from peer, with extra headers, and returns
// the response.
func ask(h http.Handler, peer, rawQuery string, header http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+AskRoute+"?"+rawQuery, nil)
	r.RemoteAddr = peer
	for k, v := range header {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAskApprovesOnlyThePanelsNames(t *testing.T) {
	e := newEnv(t)
	if err := e.db.RecordAdminHost(e.ctx, adminHost, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := e.svc.AskHandler(nil)
	const peer = "127.0.0.1:50000"
	q := func(name string) string { return "domain=" + url.QueryEscape(name) }

	// The page has its host but is off: only the admin's name is approved.
	e.setPage(&panelv1.PublicPage{Host: publicHost})
	cases := []struct {
		query string
		want  int
	}{
		{q(adminHost), http.StatusOK},
		{q(strings.ToUpper(adminHost) + "."), http.StatusOK},
		{q(publicHost), http.StatusNotFound},
		{q("other.example.test"), http.StatusNotFound},
		{"", http.StatusBadRequest},
		{q(""), http.StatusBadRequest},
		{q("192.0.2.1"), http.StatusBadRequest},
		{q("localhost"), http.StatusBadRequest},
		{q("bad_name.example.test"), http.StatusBadRequest},
		{q(" " + adminHost), http.StatusBadRequest},
		{q(adminHost + ":443"), http.StatusBadRequest},
	}
	for _, c := range cases {
		w := ask(h, peer, c.query, nil)
		if w.Code != c.want {
			t.Errorf("ask %q = %d, want %d", c.query, w.Code, c.want)
		}
		if w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("ask %q: body %q, Cache-Control %q", c.query, w.Body.String(), w.Header().Get("Cache-Control"))
		}
	}

	// Enabled, the page's host is approved too.
	e.setPage(&panelv1.PublicPage{Host: publicHost, Enabled: true})
	if w := ask(h, peer, q(publicHost), nil); w.Code != http.StatusOK {
		t.Errorf("ask for the enabled page = %d, want 200", w.Code)
	}
	if w := ask(h, "[::1]:50000", q("Proxies.Example.Test."), nil); w.Code != http.StatusOK {
		t.Errorf("ask over IPv6 loopback = %d, want 200", w.Code)
	}

	// The name is never logged above debug.
	for line := range strings.SplitSeq(e.logs.String(), "\n") {
		if strings.Contains(line, "other.example.test") && !strings.Contains(line, "level=DEBUG") {
			t.Errorf("the name is logged above debug: %s", line)
		}
	}
}

func TestAskAnswersOnlyTheProxy(t *testing.T) {
	e := newEnv(t)
	if err := e.db.RecordAdminHost(e.ctx, adminHost, time.Now()); err != nil {
		t.Fatal(err)
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	h := e.svc.AskHandler(trusted)
	query := "domain=" + adminHost

	cases := []struct {
		name   string
		peer   string
		header http.Header
		want   int
	}{
		{"loopback", "127.0.0.1:1", nil, http.StatusOK},
		{"another loopback", "127.0.0.2:1", nil, http.StatusOK},
		{"IPv4 in IPv6", "[::ffff:127.0.0.1]:1", nil, http.StatusOK},
		{"trusted proxy", "192.0.2.7:1", nil, http.StatusOK},
		{"stranger", "198.51.100.9:1", nil, http.StatusNotFound},
		{"stranger that names the loopback", "198.51.100.9:1",
			http.Header{"X-Forwarded-For": {"127.0.0.1"}}, http.StatusNotFound},
		{"a visitor relayed by the proxy", "127.0.0.1:1",
			http.Header{"X-Forwarded-For": {"203.0.113.5"}}, http.StatusNotFound},
		{"relayed, Forwarded", "127.0.0.1:1",
			http.Header{"Forwarded": {"for=203.0.113.5"}}, http.StatusNotFound},
		{"relayed, an empty X-Forwarded-For", "127.0.0.1:1",
			http.Header{"X-Forwarded-For": {""}}, http.StatusNotFound},
		{"no address", "", nil, http.StatusNotFound},
	}
	for _, c := range cases {
		if w := ask(h, c.peer, query, c.header); w.Code != c.want {
			t.Errorf("%s: %d, want %d", c.name, w.Code, c.want)
		}
	}
	// A stranger learns nothing, not even that the name is bad.
	if w := ask(h, "198.51.100.9:1", "", nil); w.Code != http.StatusNotFound {
		t.Errorf("stranger without a name: %d, want 404", w.Code)
	}
}
