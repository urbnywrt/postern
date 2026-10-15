package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
)

const (
	publicHost  = "proxies.example.test"
	publicCSP   = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	proxySecret = "00112233445566778899aabbccddeeff" // gitleaks:allow (a made-up test value)
)

// doAs sends a request whose Host header is host, without cookies.
func (p *panel) doAs(host, method, path string) (*http.Response, string) {
	p.t.Helper()
	req, err := http.NewRequest(method, p.url(path), nil)
	if err != nil {
		p.t.Fatal(err)
	}
	req.Host = host
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Body = io.NopCloser(strings.NewReader("{}"))
	}
	resp, err := p.plain.Do(req)
	if err != nil {
		p.t.Fatalf("%s %s as %s: %v", method, path, host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		p.t.Fatal(err)
	}
	return resp, string(data)
}

// publicPageFixture makes a node that is online with a link host, a listener and
// a proxy, through the API where it can, and saves a public page that lists the
// proxy. It returns the id of the proxy.
func publicPageFixture(t *testing.T, p *panel, b *browser, enabled bool) string {
	t.Helper()
	ctx := context.Background()
	nodeID, _ := b.createNode("n1")
	if _, err := p.srv.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
		n.Status, n.LinkHost = store.NodeStatusOnline, "proxy.example.com"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	listeners := panelv1connect.NewListenerServiceClient(b.http, p.ts.URL+"/api")
	l, err := listeners.CreateListener(ctx, connect.NewRequest(&panelv1.CreateListenerRequest{NodeId: nodeID, Port: 443}))
	if err != nil {
		t.Fatalf("CreateListener: %v", err)
	}
	proxies := panelv1connect.NewProxyServiceClient(b.http, p.ts.URL+"/api")
	pr, err := proxies.CreateProxy(ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: nodeID, ListenerId: l.Msg.GetListener().GetId(), Name: "alpha", Domain: "www.example.com", Secret: proxySecret,
	}))
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	id := pr.Msg.GetProxy().GetId()
	pages := panelv1connect.NewPublicPageServiceClient(b.http, p.ts.URL+"/api")
	if _, err := pages.UpdatePublicPage(ctx, connect.NewRequest(&panelv1.UpdatePublicPageRequest{Page: &panelv1.PublicPage{
		Enabled: enabled, Host: publicHost, Title: "Proxies", Unavailable: store.PublicUnavailableMark, DefaultLocale: "ru",
		Items: []*panelv1.PublicPageItem{{ProxyId: id, PublicName: "Alpha"}},
	}})); err != nil {
		t.Fatalf("UpdatePublicPage: %v", err)
	}
	return id
}

// A request for the host of the page gets the page and nothing of the admin;
// every other host gets the admin as before.
func TestPublicPageHostRouting(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	publicPageFixture(t, p, b, true)

	for _, host := range []string{publicHost, "Proxies.Example.Test", publicHost + ":8443", publicHost + ".", "PROXIES.EXAMPLE.TEST.:80"} {
		resp, body := p.doAs(host, http.MethodGet, "/")
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "tg://proxy?server=proxy.example.com") || !strings.Contains(body, `<span class="city">Alpha</span>`) {
			t.Errorf("GET / as %s: %d, body %.200q; want the page", host, resp.StatusCode, body)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("GET / as %s: Content-Type %q", host, ct)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); csp != publicCSP {
			t.Errorf("GET / as %s: the policy is %q, not the page's own", host, csp)
		}
		if resp.Header.Get("X-Robots-Tag") == "" || resp.Header.Get("CDN-Cache-Control") != "no-store" {
			t.Errorf("GET / as %s: X-Robots-Tag %q, CDN-Cache-Control %q", host, resp.Header.Get("X-Robots-Tag"), resp.Header.Get("CDN-Cache-Control"))
		}
	}

	// Nothing of the admin on that host: the API, the setup, the login, the
	// files of the SPA are 404s in plain text, with the page's headers; a POST
	// never reaches the API.
	for _, path := range []string{"/api/postern.panel.v1.HealthService/Check", "/api/", "/api", "/setup", "/login", "/index.html", "/assets/index-abc123.js", "/nodes/x", "/api/node-kit/amd64"} {
		resp, body := p.doAs(publicHost, http.MethodGet, path)
		if resp.StatusCode != http.StatusNotFound || body != "not found\n" {
			t.Errorf("GET %s on the public host: %d %q, want 404 not found", path, resp.StatusCode, body)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Errorf("GET %s on the public host: Content-Type %q", path, ct)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); csp != publicCSP {
			t.Errorf("GET %s on the public host: the policy is %q", path, csp)
		}
	}
	resp, body := p.doAs(publicHost, http.MethodPost, healthCheck)
	if resp.StatusCode != http.StatusMethodNotAllowed || strings.Contains(body, "{") {
		t.Errorf("POST %s on the public host: %d %q, want 405 and no JSON", healthCheck, resp.StatusCode, body)
	}
	resp, body = p.doAs(publicHost, http.MethodGet, "/robots.txt")
	if resp.StatusCode != http.StatusOK || body != "User-agent: *\nDisallow: /\n" {
		t.Errorf("robots.txt: %d %q", resp.StatusCode, body)
	}

	// Every other host is the admin as before. A name with two trailing dots
	// is another name: HostOf drops one dot, as a resolver would, and no more.
	for _, host := range []string{"panel.example.test", "www." + publicHost, publicHost + "..", "127.0.0.1:8080", "[::1]:8080", ""} {
		resp, _ := p.doAs(host, http.MethodGet, "/")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Security-Policy") != contentSecurityPolicy {
			t.Errorf("GET / as %q: %d, policy %q; want the admin", host, resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
		}
		resp, body := p.doAs(host, http.MethodPost, healthCheck)
		if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != "{}" {
			t.Errorf("health check as %q: %d %q", host, resp.StatusCode, body)
		}
	}
	// The admin's cookie does nothing on the public host.
	req, _ := http.NewRequest(http.MethodGet, p.url("/api/postern.panel.v1.ProxyService/ListProxies"), nil)
	req.Host = publicHost
	req.Header.Set("Cookie", b.cookieHeader())
	resp2, err := p.plain.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("an admin's request on the public host: %d, want 404", resp2.StatusCode)
	}
}

// A host that is configured but disabled serves nothing: not the page, and not
// the admin either.
func TestPublicPageDisabledHostServesNothing(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	publicPageFixture(t, p, b, false)
	for _, path := range []string{"/", "/robots.txt", "/index.html", "/api/postern.panel.v1.HealthService/Check"} {
		resp, body := p.doAs(publicHost, http.MethodGet, path)
		if resp.StatusCode != http.StatusNotFound || body != "not found\n" || resp.Header.Get("Content-Security-Policy") != publicCSP {
			t.Errorf("GET %s on the disabled host: %d %q, policy %q", path, resp.StatusCode, body, resp.Header.Get("Content-Security-Policy"))
		}
	}
	resp, _ := p.doAs("panel.example.test", http.MethodGet, "/")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Security-Policy") != contentSecurityPolicy {
		t.Errorf("the admin on another host: %d", resp.StatusCode)
	}
}

// With POSTERN_PUBLIC_PAGE=off the admin is served on the host of the page too,
// and the page on none.
func TestPublicPageOff(t *testing.T) {
	p := newPanel(t, func(c *Config) { c.PublicPageOff = true })
	b := p.signIn()
	publicPageFixture(t, p, b, true)
	resp, body := p.doAs(publicHost, http.MethodGet, "/")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Security-Policy") != contentSecurityPolicy || strings.Contains(body, "tg://") {
		t.Errorf("GET / on the public host with routing off: %d, policy %q; want the admin", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}
	resp, body = p.doAs(publicHost, http.MethodPost, healthCheck)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != "{}" {
		t.Errorf("the API on the public host with routing off: %d %q", resp.StatusCode, body)
	}
	if !strings.Contains(p.logs.String(), "POSTERN_PUBLIC_PAGE=off") {
		t.Error("the log does not say that the routing is off")
	}
}

// The name an admin reaches the panel by cannot become the host of the page.
func TestPublicPageRefusesTheAdminsHost(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	// The admin was served on panel.example.test once.
	req, _ := http.NewRequest(http.MethodPost, p.url(listProxies), strings.NewReader("{}"))
	req.Host = "panel.example.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", b.cookieHeader())
	resp, err := p.plain.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListProxies as panel.example.test: %d", resp.StatusCode)
	}

	pages := panelv1connect.NewPublicPageServiceClient(b.http, p.ts.URL+"/api")
	_, err = pages.UpdatePublicPage(context.Background(), connect.NewRequest(&panelv1.UpdatePublicPageRequest{
		Page: &panelv1.PublicPage{Host: "panel.example.test"},
	}))
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument || !strings.Contains(ce.Message(), "admin pages are served on this name") {
		t.Fatalf("UpdatePublicPage with the admin's host: %v, want invalid_argument naming the admin pages", err)
	}
}

// The on-demand TLS question is answered on every Host, the page's own
// included, and with the routing of the page off too: the reverse proxy sends
// the Host of its ask URL, which may be anything.
func TestTLSAskIsAnsweredOnEveryHost(t *testing.T) {
	for _, off := range []bool{false, true} {
		p := newPanel(t, func(c *Config) { c.PublicPageOff = off })
		b := p.signIn()
		publicPageFixture(t, p, b, true)
		for _, host := range []string{"127.0.0.1:8080", publicHost, "panel.example.test", ""} {
			resp, body := p.doAs(host, http.MethodGet, "/api/tls/ask?domain="+publicHost)
			if resp.StatusCode != http.StatusOK || body != "" || resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("routing off %v, ask as %q: %d %q, Cache-Control %q; want 200, no body, no-store",
					off, host, resp.StatusCode, body, resp.Header.Get("Cache-Control"))
			}
			resp, _ = p.doAs(host, http.MethodGet, "/api/tls/ask?domain=other.example.test")
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("routing off %v, ask for another name as %q: %d, want 404", off, host, resp.StatusCode)
			}
		}
	}
}
