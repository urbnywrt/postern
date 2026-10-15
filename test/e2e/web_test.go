//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines/telemt/site"
	"github.com/urbnywrt/postern/internal/node/state"
)

// caddyImage is the web server in front of the http-upstream listener: Caddy,
// pinned by its version and the digest of its index.
const caddyImage = "caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"

// webBasePath is the base path of the WEB proxy behind Caddy.
const webBasePath = "e2e/tg"

// TestWebProxyPlacements runs the WEB proxies of slice 3 in their two
// placements, with certificates of a test CA made by the test (no ACME):
//
//  1. the panel and a node, as TestPanelToNodeFakeTLS has them. A WEB proxy
//     needs a domain whose A record is a public address of the node, which
//     the panel and the node both check over DNS-over-HTTPS: the domains are
//     names of sslip.io that resolve to the public IPv4 address that the node
//     found (web.<a-b-c-d>.sslip.io); without one the test is skipped;
//  2. a tls listener with a fake-TLS proxy on it, which passes L1;
//  3. a WEB proxy on the same listener, cert_mode imported with a certificate
//     of the test CA: the panel names its SHA-256, pushes it to the node, and
//     the node serves the route. Over HTTP/2 through the edge, with the test
//     CA as the only root, GET / is the index page of the decoy site that the
//     node generated for the proxy, and an unknown path its 404 page with
//     status 404; telemt's /v1/runtime/web/status reports the WEB listener
//     accepting; the fake-TLS proxy on the listener still passes L1;
//  4. an http-upstream listener on 127.0.0.1 that trusts 127.0.0.1, a WEB
//     proxy under a base path on it, and Caddy on the host network in front of
//     it with the snippet that the panel generates, a certificate of the test
//     CA for its site: /<base> without the slash goes to telemt and is not
//     redirected, and a path under the base gets the proxy's decoy 404 page,
//     both over HTTP/2; telemt reports its WEB listener accepting;
//  5. the panel stops, and no log of the run holds a secret of it (the
//     secrets of the proxies, the keys of the certificates).
func TestWebProxyPlacements(t *testing.T) {
	e := newEnv(t)

	// 1. The panel, the node and the domains.
	p := e.startPanel()
	a := newAPI(p.base)
	e.signIn(a, p.token)
	node := e.newNode(a)
	ip := e.nodePublicIPv4(a, node.GetId())
	dashed := strings.ReplaceAll(ip.String(), ".", "-")
	e.secret(dashed) // the address of the machine, in the names
	webDomain := "web." + dashed + ".sslip.io"
	upDomain := "up." + dashed + ".sslip.io"
	ca := newTestCA(e)

	// 2. The tls listener and the fake-TLS proxy.
	lport := e.freePort("127.0.0.1", 10000, 19999)
	lr, err := a.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{
		NodeId: node.GetId(), Kind: "tls", BindIp: "127.0.0.1", Port: uint32(lport),
	}))
	if err != nil {
		e.fatalf("CreateListener tls: %v", err)
	}
	listenerID := lr.Msg.GetListener().GetId()
	ftHex := hex.EncodeToString(randomBytes(16))
	e.mustNotLeak("the secret of the fake-TLS proxy", ftHex)
	ft, err := a.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: node.GetId(), ListenerId: listenerID, Name: "e2e-faketls", Domain: proxyDomain, Secret: ftHex,
	}))
	if err != nil {
		e.fatalf("CreateProxy faketls: %v", err)
	}
	ftID := ft.Msg.GetProxy().GetId()
	e.waitServing(a, ftID, 8*time.Minute)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(lport))
	ftSecret := mustHex(ftHex)
	if attempts, err := probeUntil(e.ctx, addr, proxyDomain, ftSecret, 30*time.Second); err != nil {
		e.fatalf("probe.FakeTLS through the edge: %v (%d attempts)", err, attempts)
	}
	e.logf("the fake-TLS proxy on 127.0.0.1:%d passes L1", lport)

	// 3. The WEB proxy on the same listener, with an imported certificate.
	chain, key := ca.issue(webDomain)
	webHex := hex.EncodeToString(randomBytes(16))
	e.mustNotLeak("the secret of the WEB proxy on the tls listener", webHex)
	wr, err := a.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: node.GetId(), ListenerId: listenerID, Name: "e2e-web", Domain: webDomain, Secret: webHex,
		Type: "web", Web: &panelv1.WebSettingsInput{CertMode: "imported", CertFullchainPem: chain, CertKeyPem: key},
	}))
	if err != nil {
		e.fatalf("CreateProxy web on the tls listener: %v", err)
	}
	web := wr.Msg.GetProxy()
	sum := sha256.Sum256(chain)
	if got, want := web.GetWeb().GetCertSha256(), hex.EncodeToString(sum[:]); got != want {
		e.fatalf("the WEB proxy names the certificate %q, want the SHA-256 of the imported chain %q", got, want)
	}
	e.waitServing(a, web.GetId(), 3*time.Minute)
	e.logf("the WEB proxy %s on the tls listener serves with the imported certificate", web.GetId())

	decoy := site.Generate(web.GetId())
	edge := ca.client(addr)
	e.expectPage(edge, "https://"+webDomain+"/", http.StatusOK, decoy[site.IndexFile], "the decoy's index page through the edge")
	e.expectPage(edge, "https://"+webDomain+"/postern-e2e-no-such-page.txt", http.StatusNotFound, decoy[site.NotFoundFile],
		"an unknown path through the edge")
	e.expectWebAccepting(a, web.GetId())
	if attempts, err := probeUntil(e.ctx, addr, proxyDomain, ftSecret, 10*time.Second); err != nil {
		e.fatalf("probe.FakeTLS next to the WEB proxy: %v (%d attempts)", err, attempts)
	}
	e.logf("the fake-TLS proxy on the same listener still passes L1")

	// 4. The http-upstream listener, its WEB proxy and Caddy in front.
	uport := e.freePort("127.0.0.1", 10000, 19999)
	ur, err := a.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{
		NodeId: node.GetId(), Kind: "http-upstream", BindIp: "127.0.0.1", Port: uint32(uport),
		TrustedCidrs: []string{"127.0.0.1/32"},
	}))
	if err != nil {
		e.fatalf("CreateListener http-upstream: %v", err)
	}
	upHex := hex.EncodeToString(randomBytes(16))
	e.mustNotLeak("the secret of the WEB proxy behind Caddy", upHex)
	upr, err := a.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: node.GetId(), ListenerId: ur.Msg.GetListener().GetId(), Name: "e2e-web-upstream", Domain: upDomain,
		Secret: upHex, Type: "web", Web: &panelv1.WebSettingsInput{BasePath: webBasePath},
	}))
	if err != nil {
		e.fatalf("CreateProxy web on the http-upstream listener: %v", err)
	}
	up := upr.Msg.GetProxy()
	e.waitServing(a, up.GetId(), 3*time.Minute)
	snippets, err := a.proxies.GetWebSnippets(e.ctx, connect.NewRequest(&panelv1.GetWebSnippetsRequest{Id: up.GetId()}))
	if err != nil {
		e.fatalf("GetWebSnippets: %v", err)
	}
	caddyPort := e.startCaddy(ca, upDomain, snippets.Msg.GetCaddy())
	front := ca.client(net.JoinHostPort("127.0.0.1", strconv.Itoa(caddyPort)))
	upDecoy := site.Generate(up.GetId())
	base := "https://" + upDomain + "/" + webBasePath // as a browser has it on 443
	e.expectPage(front, base, http.StatusNotFound, upDecoy[site.NotFoundFile], "/"+webBasePath+" without the slash through Caddy")
	e.expectPage(front, base+"/postern-e2e-no-such-page.txt", http.StatusNotFound, upDecoy[site.NotFoundFile],
		"an unknown path under the base through Caddy")
	e.expectWebAccepting(a, up.GetId())
	if attempts, err := probeUntil(e.ctx, addr, proxyDomain, ftSecret, 10*time.Second); err != nil {
		e.fatalf("probe.FakeTLS after the http-upstream placement: %v (%d attempts)", err, attempts)
	}

	// 5. No secret in any log.
	if err := p.stop(15 * time.Second); err != nil {
		e.errorf("the panel did not stop cleanly: %v", err)
	}
	e.checkLogs()
}

// nodePublicIPv4 waits a minute at the most for the node to report a public
// IPv4 address, which the domains of the WEB proxies resolve to; without one
// (no Internet for the echo services) the test is skipped.
func (e *env) nodePublicIPv4(a *api, nodeID string) netip.Addr {
	e.t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		n, err := e.getNode(e.ctx, a, nodeID)
		if err != nil {
			e.fatalf("%v", err)
		}
		for _, s := range n.GetPublicIps() {
			if ip, err := netip.ParseAddr(s); err == nil && ip.Is4() {
				return ip
			}
		}
		if time.Now().After(deadline) {
			e.skipf("the node reports no public IPv4 address, which the domains of WEB proxies must resolve to")
		}
		select {
		case <-e.ctx.Done():
			e.fatalf("waiting for the public address of the node: %v", e.ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// expectPage gets url with c, until it is answered over HTTP/2 with status
// and the body want, for 30 s; a redirect fails at once.
func (e *env) expectPage(c *http.Client, url string, status int, want []byte, what string) {
	e.t.Helper()
	if len(want) == 0 {
		e.fatalf("%s: the expected page is empty", what)
	}
	e.waitFor(what, 30*time.Second, time.Second, func(ctx context.Context) (bool, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false, "", err
		}
		resp, err := c.Do(req)
		if err != nil {
			return false, err.Error(), nil
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return false, err.Error(), nil
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return false, "", fmt.Errorf("redirected: %s to %q", resp.Status, resp.Header.Get("Location"))
		}
		got := fmt.Sprintf("%s %s, %d bytes", resp.Proto, resp.Status, len(body))
		if len(body) < 64 && !bytes.Equal(body, want) {
			got += fmt.Sprintf(" %q from %q", body, resp.Header.Get("Server"))
		}
		if resp.ProtoMajor != 2 || resp.StatusCode != status || !bytes.Equal(body, want) {
			return false, got + fmt.Sprintf(" (want HTTP/2.0 %d with the %d bytes of the page)", status, len(want)), nil
		}
		return true, got, nil
	})
}

// expectWebAccepting waits until telemt's /v1/runtime/web/status, on the API
// of the engine of the proxy, reports its WEB listener running and accepting
// connections.
func (e *env) expectWebAccepting(a *api, proxyID string) {
	e.t.Helper()
	gen := e.proxyOf(a, proxyID).GetStatus().GetInstanceGeneration()
	path := filepath.Join(state.Paths{Home: e.home}.InstancesDir(),
		"eng-"+strings.ToLower(proxyID)+"-g"+strconv.FormatUint(gen, 10), "config.toml")
	copied, remove, err := e.copyNodeFile(e.ctx, path)
	if err != nil {
		e.fatalf("the config of the engine of proxy %s: %v", proxyID, err)
	}
	cfg, err := os.ReadFile(copied)
	remove()
	if err != nil {
		e.fatalf("%v", err)
	}
	listen := regexp.MustCompile(`(?m)^listen = "([^"]+)"`).FindSubmatch(cfg)
	token := regexp.MustCompile(`(?m)^auth_header = "([^"]+)"`).FindSubmatch(cfg)
	if listen == nil || token == nil {
		e.fatalf("the config of the engine of proxy %s has no API listen address or token", proxyID)
	}
	e.secret(string(token[1]))
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	e.waitFor("telemt's WEB status of proxy "+proxyID, 30*time.Second, time.Second, func(ctx context.Context) (bool, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+string(listen[1])+"/v1/runtime/web/status", nil)
		if err != nil {
			return false, "", err
		}
		req.Header.Set("Authorization", string(token[1]))
		resp, err := hc.Do(req)
		if err != nil {
			return false, err.Error(), nil
		}
		defer func() { _ = resp.Body.Close() }()
		var st struct {
			OK   bool `json:"ok"`
			Data struct {
				Lifecycle string   `json:"lifecycle"`
				Listeners []string `json:"listeners"`
				Enabled   bool     `json:"effective_config_enabled"`
				Ingress   struct {
					Accepting bool   `json:"accepting_connections"`
					Reason    string `json:"reason"`
				} `json:"ingress"`
			} `json:"data"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&st); err != nil {
			return false, fmt.Sprintf("%s: %v", resp.Status, err), nil
		}
		d := st.Data
		got := fmt.Sprintf("%s: lifecycle %q, web enabled %v, listeners %v, accepting %v %s",
			resp.Status, d.Lifecycle, d.Enabled, d.Listeners, d.Ingress.Accepting, d.Ingress.Reason)
		return st.OK && d.Lifecycle == "running" && d.Enabled && len(d.Listeners) > 0 && d.Ingress.Accepting, got, nil
	})
}

// startCaddy runs Caddy on the host network, on 127.0.0.1 and a free port,
// with a site for domain whose certificate is one of ca and the snippet of
// the panel inside, and returns its port once it listens.
func (e *env) startCaddy(ca *testCA, domain, snippet string) int {
	e.t.Helper()
	if !strings.Contains(snippet, "header_up X-Forwarded-For {remote_host}") {
		e.fatalf("the Caddy snippet does not set X-Forwarded-For:\n%s", snippet)
	}
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Minute)
	defer cancel()
	if ok, err := e.docker.ImageExists(ctx, caddyImage); err != nil {
		e.fatalf("looking for the Caddy image: %v", err)
	} else if !ok {
		if err := e.docker.Pull(ctx, caddyImage); err != nil {
			e.fatalf("pulling the Caddy image: %v", err)
		}
	}
	httpsPort := e.freePort("127.0.0.1", 42000, 42999)
	httpPort := e.freePort("127.0.0.1", 43000, 43999)
	dir := filepath.Join(e.work, "caddy")
	if err := os.Mkdir(dir, 0o755); err != nil {
		e.fatalf("%v", err)
	}
	chain, key := ca.issue(domain)
	e.writeFile(filepath.Join(dir, "site.pem"), chain, 0o644)
	e.writeFile(filepath.Join(dir, "site-key.pem"), key, 0o644)
	caddyfile := fmt.Sprintf(`{
	admin off
	auto_https off
	http_port %d
	https_port %d
}

https://%s {
	bind 127.0.0.1
	tls /etc/caddy/site.pem /etc/caddy/site-key.pem
%s
	handle {
		respond "the site in front" 200
	}
}
`, httpPort, httpsPort, domain, snippet)
	e.writeFile(filepath.Join(dir, "Caddyfile"), []byte(caddyfile), 0o644)
	id, err := e.docker.Create(ctx, dockerapi.ContainerSpec{
		Name:          "postern-e2e-" + e.run + "-caddy",
		Image:         caddyImage,
		NetworkMode:   "host",
		RestartPolicy: "no",
		Entrypoint:    []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
		Binds:         []string{dir + ":/etc/caddy:ro"},
		Labels:        map[string]string{labelRun: e.run},
	})
	if err != nil {
		e.fatalf("creating the Caddy container: %v", err)
	}
	e.t.Cleanup(func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rcancel()
		_ = e.docker.Remove(rctx, id, true)
	})
	if err := e.docker.Start(ctx, id); err != nil {
		e.fatalf("starting Caddy: %v", err)
	}
	hostPort := net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort))
	e.waitFor("Caddy at "+hostPort, 30*time.Second, 250*time.Millisecond, func(ctx context.Context) (bool, string, error) {
		d, err := e.docker.Inspect(ctx, id)
		if err != nil {
			return false, "", err
		}
		if d.State != "running" {
			return false, "", fmt.Errorf("its container is %s (exit code %d): %s", d.State, d.ExitCode, e.containerLog(ctx, id))
		}
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", hostPort)
		if err != nil {
			return false, "not listening yet", nil
		}
		_ = c.Close()
		return true, "listening", nil
	})
	return httpsPort
}

// testCA is a certificate authority of the run: the certificates of the WEB
// proxies and of the site in front come from it, and the clients of the test
// trust it alone.
type testCA struct {
	e    *env
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	pool *x509.CertPool
}

func newTestCA(e *env) *testCA {
	e.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.fatalf("%v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Postern e2e test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		e.fatalf("%v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		e.fatalf("%v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{e: e, cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pool: pool}
}

// issue makes a certificate for domain: the chain (leaf, then the CA) and the
// key, PEM. The key must not leak.
func (ca *testCA) issue(domain string) (chain, keyPEM []byte) {
	e := ca.e
	e.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.fatalf("%v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		e.fatalf("%v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		e.fatalf("%v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		e.fatalf("%v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	leaks, err := keyLeaks(keyPEM)
	if err != nil {
		e.fatalf("%v", err)
	}
	e.mustNotLeak("the key of the certificate of "+domain, leaks...)
	chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.pem...)
	return chain, keyPEM
}

// client is an HTTPS client that trusts the CA alone and connects to addr
// whatever the host of the URL, which it sends as the server name: HTTP/2
// when the server offers it, and no redirect followed.
func (ca *testCA) client(addr string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			TLSClientConfig:   &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
