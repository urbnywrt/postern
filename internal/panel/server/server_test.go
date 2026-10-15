package server

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/webui"
	"github.com/urbnywrt/postern/internal/pki"
)

// wantHeaders is what every response carries.
var wantHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
	"X-Frame-Options":         "DENY",
	"X-Content-Type-Options":  "nosniff",
	"Referrer-Policy":         "no-referrer",
}

// The policy closes what default-src does not cover (the base URL, the target of
// a form), narrows plug-in content, which default-src 'self' would let come from
// the panel's own origin, to none, and gives each directive once: a browser takes
// the first of two and ignores the other.
func TestContentSecurityPolicyDirectives(t *testing.T) {
	got := map[string]string{}
	for _, d := range strings.Split(contentSecurityPolicy, ";") {
		name, value, _ := strings.Cut(strings.TrimSpace(d), " ")
		if _, dup := got[name]; dup {
			t.Errorf("the directive %q is given twice", name)
		}
		got[name] = value
	}
	for name, want := range map[string]string{
		"default-src":     "'self'",
		"frame-ancestors": "'none'",
		"base-uri":        "'self'",
		"form-action":     "'self'",
		"object-src":      "'none'",
	} {
		if got[name] != want {
			t.Errorf("%s is %q, want %q", name, got[name], want)
		}
	}
}

func checkSecurityHeaders(t *testing.T, what string, resp *http.Response) {
	t.Helper()
	for name, want := range wantHeaders {
		got := resp.Header.Values(name)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: %s = %q, want exactly [%q]", what, name, got, want)
		}
	}
}

// errorBody reads the Connect error that a response carries.
func errorBody(t *testing.T, body string) (code, message string) {
	t.Helper()
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("the body is not a Connect error: %v: %q", err, body)
	}
	return e.Code, e.Message
}

func TestHealthCheck(t *testing.T) {
	p := newPanel(t)

	resp, body := p.post(healthCheck, `{}`)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != `{}` {
		t.Errorf("Check: status %d, body %q, want 200 and {}", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Check: Content-Type %q", ct)
	}

	// And as the generated client calls it, which is how the SPA does.
	client := panelv1connect.NewHealthServiceClient(p.plain, p.url("/api"))
	if _, err := client.Check(context.Background(), connect.NewRequest(&panelv1.CheckRequest{})); err != nil {
		t.Errorf("Check through the client: %v", err)
	}
}

// Every response has the security headers, whoever wrote it: the SPA, the API,
// the router for a path it does not know, the middleware that refuses a call,
// and a handler of its own such as the download of a bundle.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	id, bundle := b.createNode("n1")

	type req struct {
		name, method, path, body string
		browser                  bool
		status                   int
	}
	for _, c := range []req{
		{"the SPA", "GET", "/", "", false, 200},
		{"a path of the SPA", "GET", "/nodes/" + id, "", false, 200},
		{"a file of the SPA", "GET", "/index.html", "", false, 200},
		{"the SPA, HEAD", "HEAD", "/", "", false, 200},
		{"the SPA, a method it does not have", "POST", "/", "{}", false, 405},
		{"health check", "POST", healthCheck, "{}", false, 200},
		{"a bad request to a procedure", "POST", healthCheck, "{", false, 400},
		{"an unknown API path", "GET", "/api/nope", "", false, 404},
		{"the API root", "GET", "/api/", "", false, 404},
		{"a procedure without a session", "POST", listProxies, "{}", false, 401},
		{"a bundle without a session", "GET", bundle, "", false, 401},
		{"a procedure with a session", "POST", listProxies, "{}", true, 200},
		{"a bundle with a session", "GET", bundle, "", true, 200},
		{"a bundle of a node that is not there", "GET", "/api/nodes/nope/bundle.tar", "", true, 404},
		{"the node kit without a session", "GET", "/api/node-kit/amd64", "", false, 401},
		// A panel of a test has no kit.
		{"the node kit with a session", "GET", "/api/node-kit/amd64", "", true, 404},
		{"the node kit, a method it does not have", "POST", "/api/node-kit/amd64", "", true, 405},
	} {
		t.Run(c.name, func(t *testing.T) {
			var resp *http.Response
			var hdr map[string]string
			if c.body != "" {
				hdr = map[string]string{"Content-Type": "application/json"}
			}
			if c.browser {
				resp, _ = b.do(c.method, c.path, strings.NewReader(c.body), hdr)
			} else {
				resp, _ = p.do(c.method, c.path, strings.NewReader(c.body), hdr)
			}
			if resp.StatusCode != c.status {
				t.Errorf("%s %s: status %d, want %d", c.method, c.path, resp.StatusCode, c.status)
			}
			checkSecurityHeaders(t, c.method+" "+c.path, resp)
		})
	}
}

// Whatever the path is, if it is not the API and it is not a file of the UI, the
// page is the UI, so that its router decides what to show.
func TestUnknownPathServesTheIndex(t *testing.T) {
	p := newPanel(t)
	index, err := fs.ReadFile(webui.FS(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/index.html", "/setup", "/login", "/nodes", "/proxies/01ABC", "/some/where/that/is/not/there", "/not-there.html"} {
		resp, body := p.get(path)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", path, resp.StatusCode)
		}
		if body != string(index) {
			t.Errorf("GET %s: not the index of the UI: %.80q", path, body)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("GET %s: Content-Type %q", path, ct)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("GET %s: Cache-Control %q, want no-cache, so that an update of the panel is seen at once", path, cc)
		}
	}
	// What is embedded in a source tree is the placeholder.
	if !strings.Contains(string(index), "<script") {
		if resp, body := p.get("/anything"); resp.StatusCode != 200 || !strings.Contains(body, "Postern UI not built") {
			t.Errorf("the placeholder is not served: %d %.80q", resp.StatusCode, body)
		}
	}

	resp, body := p.do(http.MethodHead, "/some/where", nil, nil)
	if resp.StatusCode != http.StatusOK || body != "" {
		t.Errorf("HEAD: status %d with %d bytes of body, want 200 and none", resp.StatusCode, len(body))
	}
}

// The API has no page to fall back to: what it does not know is a 404 that the
// client can read.
func TestUnknownAPIPathIsAJSON404(t *testing.T) {
	p := newPanel(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/nope"},
		{"POST", "/api/nope"},
		{"GET", "/api/"},
		{"GET", "/api"},
		{"GET", "/api/nodes/x/y/z"},
		{"DELETE", "/api/nodes/x/bundle.tar.gz"},
		{"GET", "/api/postern.panel.v1"},
	} {
		resp, body := p.do(c.method, c.path, nil, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: status %d, want 404; body %.80q", c.method, c.path, resp.StatusCode, body)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s %s: Content-Type %q, want JSON", c.method, c.path, ct)
		}
		if code, msg := errorBody(t, body); code != "not_found" || msg != routeNotFoundMessage {
			t.Errorf("%s %s: error %q %q, want not_found %q", c.method, c.path, code, msg, routeNotFoundMessage)
		}
	}
	// The SPA is not under /api: a path that only starts like it is a page.
	resp, body := p.get("/apix")
	if resp.StatusCode != http.StatusOK || strings.Contains(body, routeNotFoundMessage) {
		t.Errorf("/apix: status %d, want the page", resp.StatusCode)
	}
}

func TestUnauthenticatedProxyServiceCallIs401(t *testing.T) {
	p := newPanel(t)
	resp, body := p.post(listProxies, `{}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401; body %q", resp.StatusCode, body)
	}
	if code, _ := errorBody(t, body); code != "unauthenticated" {
		t.Errorf("code %q, want unauthenticated", code)
	}
	// A cookie that is not a session of this panel is no better.
	resp, _ = p.do(http.MethodPost, listProxies, strings.NewReader(`{}`), map[string]string{
		"Content-Type": "application/json",
		"Cookie":       "postern_session=" + strings.Repeat("A", 43),
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("with an unknown session: status %d, want 401", resp.StatusCode)
	}
}

// procedures lists every procedure of the panel API that the proto files define,
// so that a service that is added to them and not mounted, or mounted without the
// middleware, is found.
func procedures(t *testing.T) []string {
	t.Helper()
	var list []string
	protoregistry.GlobalFiles.RangeFilesByPackage("postern.panel.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			svc := fd.Services().Get(i)
			for j := range svc.Methods().Len() {
				list = append(list, "/"+string(svc.FullName())+"/"+string(svc.Methods().Get(j).Name()))
			}
		}
		return true
	})
	slices.Sort(list)
	for _, want := range []string{
		"/postern.panel.v1.HealthService/Check",
		"/postern.panel.v1.AuthService/Login",
		"/postern.panel.v1.NodeService/ListNodes",
		"/postern.panel.v1.ListenerService/ListListeners",
		"/postern.panel.v1.ProxyService/ListProxies",
		"/postern.panel.v1.StatsService/ProxySeries",
		"/postern.panel.v1.GeoIPService/GetGeoIP",
		"/postern.panel.v1.GeoIPService/RefreshGeoIP",
		"/postern.panel.v1.GeoIPService/SetGeoIPEnabled",
		"/postern.panel.v1.SettingsService/GetStatsSettings",
		"/postern.panel.v1.SettingsService/UpdateStatsSettings",
		"/postern.panel.v1.SettingsService/GetStorage",
		"/postern.panel.v1.VersionService/ListComponents",
		"/postern.panel.v1.DeployService/Install",
	} {
		if !slices.Contains(list, want) {
			t.Fatalf("the proto files do not define %s; found %v", want, list)
		}
	}
	return list
}

// publicProcedures are the procedures that need no session.
var publicProcedures = []string{
	"/postern.panel.v1.HealthService/Check",
	"/postern.panel.v1.AuthService/GetSetupStatus",
	"/postern.panel.v1.AuthService/Setup",
	"/postern.panel.v1.AuthService/Login",
	"/postern.panel.v1.JoinService/Join",
}

// Every service of the API is mounted, and every procedure that is not public is
// behind the session.
func TestEveryProcedureIsMountedAndGuarded(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	list := procedures(t)

	for _, proc := range list {
		resp, body := p.post("/api"+proc, `{}`)
		if slices.Contains(publicProcedures, proc) {
			// Login and Join answer an empty request with 401 of their own.
			if resp.StatusCode == http.StatusUnauthorized && !strings.HasSuffix(proc, "/Login") && !strings.HasSuffix(proc, "/Join") {
				t.Errorf("%s is public, and the panel asked for a session: %s", proc, body)
			}
			if strings.Contains(body, routeNotFoundMessage) {
				t.Errorf("%s is not mounted", proc)
			}
			continue
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a session: status %d, want 401; body %.100q", proc, resp.StatusCode, body)
		}
	}

	// With a session every procedure reaches its handler: none gets the 404 of the
	// router. Logout goes last, since it ends the session.
	logoutLast(list)
	for _, proc := range list {
		resp, body := b.post("/api"+proc, `{}`)
		if strings.Contains(body, routeNotFoundMessage) {
			t.Errorf("%s is not mounted: %d %s", proc, resp.StatusCode, body)
		}
		if resp.StatusCode == http.StatusUnauthorized && !strings.HasSuffix(proc, "/Login") && !strings.HasSuffix(proc, "/Join") {
			t.Errorf("%s with a session: unauthenticated: %s", proc, body)
		}
	}
}

// The bundle of a node holds its private key: only an admin gets it.
func TestBundleDownloadNeedsAnAdmin(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	id, bundle := b.createNode("edge")
	if want := "/api/nodes/" + id + "/bundle.tar"; bundle != want {
		t.Fatalf("CreateNode gave the bundle URL %q, want %q", bundle, want)
	}

	// Nobody: 401, a Connect error, and no key.
	resp, body := p.get(bundle)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: status %d, want 401", resp.StatusCode)
	}
	if code, _ := errorBody(t, body); code != "unauthenticated" {
		t.Errorf("without a session: error code %q, want unauthenticated", code)
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Error("the refusal carries a key")
	}
	// A cookie that is not a session of this panel.
	resp, _ = p.do(http.MethodGet, bundle, nil, map[string]string{"Cookie": "postern_session=" + strings.Repeat("A", 43)})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("with an unknown session: status %d, want 401", resp.StatusCode)
	}
	// Another method of the same path is not the download.
	if resp, _ := b.do(http.MethodPost, bundle, nil, nil); resp.StatusCode == http.StatusOK {
		t.Error("a POST got the bundle")
	}

	// An admin: the tar, as an attachment, that is not stored anywhere.
	resp, body = b.get(bundle)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with a session: status %d, body %.80q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/x-tar" {
		t.Errorf("Content-Type %q", got)
	}
	if disp, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err != nil || disp != "attachment" || params["filename"] != "postern-node-bundle.tar" {
		t.Errorf("Content-Disposition %q", resp.Header.Get("Content-Disposition"))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", got)
	}
	parsed, err := pki.ParseBundleTar([]byte(body))
	if err != nil {
		t.Fatalf("the bundle does not parse: %v", err)
	}
	if parsed.NodeID != id || parsed.MgmtPort != 61443 {
		t.Errorf("bundle of node %q on port %d, want %q on 61443", parsed.NodeID, parsed.MgmtPort, id)
	}
	checkSecurityHeaders(t, "bundle", resp)

	// After the session ends the download is closed again.
	if _, err := b.auth.Logout(context.Background(), connect.NewRequest(&panelv1.LogoutRequest{})); err != nil {
		t.Fatal(err)
	}
	if resp, _ := b.get(bundle); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("after the logout: status %d, want 401", resp.StatusCode)
	}
}

// writeNodeKit lays out a node kit in a new directory, as the panel image has
// it, with a binary for each of arches, and returns the directory.
func writeNodeKit(t *testing.T, arches ...string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"install.sh": "#!/usr/bin/env bash\n", "launcher.sh": "#!/bin/sh\n", "compose.yaml": "services: {}\n"}
	for _, arch := range arches {
		files[arch+"/postern-node"] = "\x7fELF " + arch + "\n"
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The panel serves the node kit of its configuration to admins, and says at
// start which architectures it has.
func TestNodeKit(t *testing.T) {
	p := newPanel(t, func(c *Config) { c.NodeKitDir = writeNodeKit(t, "arm64") })
	b := p.signIn()
	if logs := p.logs.String(); !strings.Contains(logs, "arches=arm64") || !strings.Contains(logs, "dir="+p.cfg.NodeKitDir) {
		t.Errorf("the log does not say which kits the panel has:\n%s", logs)
	}

	resp, body := b.get("/api/node-kit/arm64")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/x-tar" {
		t.Fatalf("GET the kit: status %d, Content-Type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	tr := tar.NewReader(strings.NewReader(body))
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("the kit is not a tar: %v", err)
			}
			break
		}
		names = append(names, hdr.Name)
	}
	if want := []string{"postern-node", "install.sh", "launcher.sh", "compose.yaml"}; !slices.Equal(names, want) {
		t.Errorf("the kit holds %q, want %q", names, want)
	}
	checkSecurityHeaders(t, "the node kit", resp)

	if resp, _ := b.get("/api/node-kit/amd64"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a kit that the panel does not have: status %d, want 404", resp.StatusCode)
	}
	if resp, _ := p.get("/api/node-kit/arm64"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("without a session: status %d, want 401", resp.StatusCode)
	}
	// What is not the route of the kit is a 404 of the API.
	if resp, body := b.get("/api/node-kit/"); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, routeNotFoundMessage) {
		t.Errorf("GET /api/node-kit/: status %d, body %.80q, want the 404 of the API", resp.StatusCode, body)
	}

	// The API offers what is there.
	id, _ := b.createNode("edge")
	install, err := b.node.GetNodeInstall(context.Background(), connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: id}))
	if err != nil {
		t.Fatalf("GetNodeInstall: %v", err)
	}
	var available []string
	for _, k := range install.Msg.GetKits() {
		if k.GetAvailable() {
			available = append(available, k.GetArch())
		}
	}
	if !slices.Equal(available, []string{"arm64"}) {
		t.Errorf("GetNodeInstall offers the kits of %v, want [arm64]", available)
	}
}

// The write deadline of a kit download, a quarter of an hour, reaches the
// connection through everything that the server puts in front of the handler
// of the kit: the security headers, the sessions, the routes of the API. A
// wrapper of the ResponseWriter on the way that hid the deadline would leave the
// download without a bound, and nothing else would tell.
func TestNodeKitHasAWriteDeadlineThroughTheServer(t *testing.T) {
	p := newPanel(t, func(c *Config) { c.NodeKitDir = writeNodeKit(t, "arm64") })
	cookie := p.signIn().cookieHeader()
	h := p.srv.Handler()

	before := time.Now()
	spy := serveSpied(h, http.MethodGet, "/api/node-kit/arm64", map[string]string{"Cookie": cookie})
	after := time.Now()
	if spy.Code != http.StatusOK || spy.Header().Get("Content-Type") != "application/x-tar" {
		t.Fatalf("GET the kit: status %d, Content-Type %q", spy.Code, spy.Header().Get("Content-Type"))
	}
	if len(spy.deadlines) != 1 {
		t.Fatalf("%d write deadlines were set, want 1: %v", len(spy.deadlines), spy.deadlines)
	}
	if d := spy.deadlines[0]; d.Before(before.Add(15*time.Minute)) || d.After(after.Add(15*time.Minute)) {
		t.Errorf("the write deadline is %v, want 15 minutes after the request, between %v and %v",
			d, before.Add(15*time.Minute), after.Add(15*time.Minute))
	}
}

// A panel without a kit, which is what go run makes, says so at start and
// is not the worse for it.
func TestNoNodeKit(t *testing.T) {
	p := newPanel(t, func(c *Config) { c.NodeKitDir = filepath.Join(t.TempDir(), "not-there") })
	var lines []string
	for _, line := range strings.Split(p.logs.String(), "\n") {
		if strings.Contains(line, "node kit") {
			lines = append(lines, line)
		}
	}
	// One line, and not a warning.
	if len(lines) != 1 || !strings.Contains(lines[0], "level=INFO") || !strings.Contains(lines[0], "no node kit") ||
		!strings.Contains(lines[0], "dir="+p.cfg.NodeKitDir) {
		t.Errorf("the log does not say in one line of information that there is no kit: %q", lines)
	}
	if resp, _ := p.signIn().get("/api/node-kit/amd64"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET the kit: status %d, want 404", resp.StatusCode)
	}
}

// The panel logs what it does, and no secret: not the setup token, not the key
// of a node, not the password.
func TestLogsHoldNoSecrets(t *testing.T) {
	p := newPanel(t)
	token, _ := p.srv.auth.SetupToken()
	b := p.signIn()
	_, bundle := b.createNode("edge")
	_, body := b.get(bundle)

	logs := p.logs.String()
	if logs == "" {
		t.Fatal("the panel logged nothing")
	}
	for what, secret := range map[string]string{
		"the setup token": token,
		"the password":    adminPassword,
		"a private key":   "PRIVATE KEY",
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log holds %s", what)
		}
	}
	if parsed, err := pki.ParseBundleTar([]byte(body)); err == nil && strings.Contains(logs, string(parsed.KeyPEM)) {
		t.Error("the log holds the key of a node")
	}
}
