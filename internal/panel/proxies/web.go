package proxies

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/preflight"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/webrules"
)

// This file holds what is particular to WEB proxies: their settings as a
// request gives them, the imported certificate (Ruling S3-1: stored sealed,
// pushed to the node with PutCertificate), the preflight of the domain, the
// links and the snippets for a web server in front of an http-upstream
// listener (design spec 5.4).

// certAAD is the additional data that the imported certificate of a proxy
// (the chain and the key alike) is sealed with: it opens for its own proxy
// only (Ruling S3-1).
func certAAD(proxyID string) []byte {
	return []byte("cert:" + proxyID)
}

// A CertPusher sends the imported certificates of a node to it. The service
// tells it about every node whose imported certificate changed; the pusher
// does its work on its own, and the node serves the route once it has the
// chain that the state names.
type CertPusher interface {
	PushCertificates(nodeID string)
}

// DomainChecker checks the domain of a WEB proxy before it is stored
// (preflight.Checker): the A record is an address of the node, and not one of
// Cloudflare.
type DomainChecker interface {
	CheckDomain(ctx context.Context, domain string, nodeIPs []string) (netip.Addr, error)
}

// SetDomainChecker sets what checks the domain of a WEB proxy before it is
// stored; nil checks nothing (tests, or a panel without DNS).
func (s *Service) SetDomainChecker(c DomainChecker) { s.domains = c }

// SetCertPusher sets what sends imported certificates to the nodes; nil
// sends nothing (the pusher of the node manager sends them at every
// connection all the same).
func (s *Service) SetCertPusher(p CertPusher) { s.certs = p }

// webSettings are the WEB settings of a request, checked on their own
// (checkWebSettings). What depends on the listener and the domain of the
// proxy is checked when they are known (applyWeb).
type webSettings struct {
	basePath, secretMode, carrier, certMode, dnsCredentialID, acmeEmail string
	// chain and key are the certificate given, or nil.
	chain, key []byte
}

// checkWebSettings checks the WEB settings of a request on their own.
func checkWebSettings(in *panelv1.WebSettingsInput) (webSettings, error) {
	var w webSettings
	if in == nil {
		return w, invalid("a web proxy needs web settings")
	}
	w.basePath = strings.TrimSpace(in.GetBasePath())
	if err := preflight.CheckBasePath(w.basePath); err != nil {
		return w, invalid("%v", err)
	}
	w.secretMode = webrules.SecretMode(strings.TrimSpace(in.GetSecretMode()))
	if err := webrules.CheckSecretMode(w.secretMode); err != nil {
		return w, invalid("%v", err)
	}
	w.carrier = webrules.Carrier(strings.TrimSpace(in.GetCarrier()))
	if err := webrules.CheckCarrier(w.carrier); err != nil {
		return w, invalid("%v", err)
	}
	switch w.certMode = strings.TrimSpace(in.GetCertMode()); w.certMode {
	case "":
		w.certMode = webrules.CertModeACME
	case webrules.CertModeACME, webrules.CertModeImported:
	default:
		return w, invalid("cert_mode must be %s or %s", webrules.CertModeACME, webrules.CertModeImported)
	}
	w.dnsCredentialID = strings.TrimSpace(in.GetDnsCredentialId())
	if w.dnsCredentialID != "" && !validID(w.dnsCredentialID) {
		return w, invalid("dns_credential_id is not an id")
	}
	var err error
	if w.acmeEmail, err = checkACMEEmail(in.GetAcmeEmail()); err != nil {
		return w, err
	}
	w.chain, w.key = in.GetCertFullchainPem(), in.GetCertKeyPem()
	if (len(w.chain) == 0) != (len(w.key) == 0) {
		return w, invalid("cert_fullchain_pem and cert_key_pem go together")
	}
	return w, nil
}

// errCertificate marks a stored certificate that cannot be opened: a fault of
// the panel (another master key), not of the data.
var errCertificate = errors.New("an imported certificate cannot be opened")

// applyWeb puts the WEB settings w on p, which is on a listener of nd, with
// the rules that depend on the listener and the domain: on an http-upstream
// listener the base path is required and the certificate belongs to the web
// server in front (no cert mode, credential or certificate is kept); on a tls
// listener cert mode acme-dns01 needs a DNS credential that exists, and
// imported a certificate, the one given or, when none is, the one stored
// (checked again for the domain). The imported certificate is sealed for the
// proxy. It reports whether the stored certificate changed.
func (s *Service) applyWeb(ctx context.Context, nd *nodeData, p *store.Proxy, w webSettings) (certChanged bool, err error) {
	l := nd.listener(p.ListenerID)
	if l == nil {
		return false, notFound("listener on the node")
	}
	p.WebBasePath, p.WebSecretMode, p.WebCarrier = w.basePath, w.secretMode, w.carrier
	if l.Kind == store.ListenerKindHTTPUpstream {
		if p.WebBasePath == "" {
			return false, invalid("base_path is required on an http-upstream listener: the proxy lives under a path of the site in front")
		}
		p.CertMode, p.DNSCredentialID, p.ACMEEmail = "", "", ""
		return clearCert(p), nil
	}
	p.CertMode, p.ACMEEmail = w.certMode, w.acmeEmail
	switch w.certMode {
	case webrules.CertModeACME:
		if w.dnsCredentialID == "" {
			return false, invalid("cert_mode %s needs a dns_credential_id", webrules.CertModeACME)
		}
		if _, loaded := nd.tokens[w.dnsCredentialID]; !loaded {
			c, err := s.db.DNSCredentialByID(ctx, w.dnsCredentialID)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return false, notFound("dns credential")
				}
				return false, s.fail("could not read a dns credential", err)
			}
			token, err := OpenDNSToken(s.key, c)
			if err != nil {
				return false, s.fail("could not open a dns credential", err)
			}
			// The state of the node after the change carries the token.
			nd.tokens[c.ID] = token
			delete(nd.badTokens, c.ID)
		}
		p.DNSCredentialID = w.dnsCredentialID
		return clearCert(p), nil
	case webrules.CertModeImported:
		p.DNSCredentialID = ""
		chain, key := w.chain, w.key
		given := len(chain) > 0
		if !given {
			if p.CertChainEnc == nil {
				return false, invalid("cert_mode %s needs cert_fullchain_pem and cert_key_pem", webrules.CertModeImported)
			}
			if chain, key, err = openCert(s.key, p); err != nil {
				return false, s.fail("could not open an imported certificate", err)
			}
		}
		cert, err := preflight.CheckCertificate(chain, key, p.Domain, s.now())
		if err != nil {
			return false, invalid("certificate: %v", err)
		}
		if !given && cert.SHA256 == p.CertSHA256 {
			return false, nil
		}
		if p.CertChainEnc, err = seal.Seal(s.key, chain, certAAD(p.ID)); err != nil {
			return false, s.fail("could not seal a certificate", err)
		}
		if p.CertKeyEnc, err = seal.Seal(s.key, key, certAAD(p.ID)); err != nil {
			return false, s.fail("could not seal a certificate key", err)
		}
		p.CertSHA256, p.CertNotAfter = cert.SHA256, cert.NotAfter
		return true, nil
	}
	return false, invalid("cert_mode must be %s or %s", webrules.CertModeACME, webrules.CertModeImported)
}

// clearCert forgets the imported certificate of a proxy and reports whether
// there was one.
func clearCert(p *store.Proxy) bool {
	had := p.CertChainEnc != nil
	p.CertChainEnc, p.CertKeyEnc, p.CertSHA256, p.CertNotAfter = nil, nil, "", time.Time{}
	return had
}

// openCert opens the sealed certificate of a proxy.
func openCert(key seal.Key, p *store.Proxy) (chain, priv []byte, err error) {
	if chain, err = seal.Open(key, p.CertChainEnc, certAAD(p.ID)); err != nil {
		return nil, nil, fmt.Errorf("%w: proxy %s: %w", errCertificate, p.ID, err)
	}
	if priv, err = seal.Open(key, p.CertKeyEnc, certAAD(p.ID)); err != nil {
		return nil, nil, fmt.Errorf("%w: proxy %s: %w", errCertificate, p.ID, err)
	}
	return chain, priv, nil
}

// checkWebDomainFree refuses the domain of a WEB proxy that another WEB
// proxy of the panel, on any node, has (as the edge compares names,
// state.FoldDomain): an A record points to one node, and the certificate of
// a domain is issued for one. except is the proxy itself.
func (s *Service) checkWebDomainFree(ctx context.Context, domain, except string) error {
	all, err := s.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return s.readError("proxies", err)
	}
	want := state.FoldDomain(domain)
	for _, other := range all {
		if other.ID != except && other.Type == store.ProxyTypeWeb && state.FoldDomain(other.Domain) == want {
			return connect.NewError(connect.CodeAlreadyExists, errors.New("another WEB proxy of the panel has the domain (letter case aside)"))
		}
	}
	return nil
}

// preflightProxyDomain checks the domain of a WEB proxy of a node with the
// domain checker, when there is one: a finding is FAILED_PRECONDITION in its
// words; a lookup that failed is one too, since the proxy could not be served
// without the record either, but says so. It reads the node itself and runs
// outside the lock of the node data: a lookup takes up to 15 s, and nothing
// else of the panel waits for it. The public addresses of the node that it
// uses may change meanwhile, which the node's own check at apply covers.
// A node that has not reported its public addresses yet gets the check
// without the match of the domain with them, and a warning that says so.
func (s *Service) preflightProxyDomain(ctx context.Context, nodeID, domain string) ([]string, error) {
	if s.domains == nil {
		return nil, nil
	}
	n, err := s.db.NodeByID(ctx, nodeID)
	if err != nil {
		return nil, s.readError("node", err)
	}
	if _, err := s.domains.CheckDomain(ctx, domain, n.PublicIPs); err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if len(n.PublicIPs) == 0 {
		return []string{fmt.Sprintf("node %s has not reported its public IP addresses yet: the A record of %s was not compared with them; "+
			"check that it points to the node", n.Name, domain)}, nil
	}
	return nil, nil
}

// certWarnDays is how close to its end an imported certificate is warned of.
const certWarnDays = 21

// certWarnings warns of the imported certificate of a WEB proxy that expires
// within certWarnDays: Postern does not renew an imported certificate.
func (s *Service) certWarnings(p *store.Proxy) []string {
	if p.Type != store.ProxyTypeWeb || p.CertMode != webrules.CertModeImported || p.CertNotAfter.IsZero() {
		return nil
	}
	left := p.CertNotAfter.Sub(s.now())
	if left > certWarnDays*24*time.Hour {
		return nil
	}
	return []string{fmt.Sprintf("the imported certificate of %s expires on %s, in %d days, and Postern does not renew an imported "+
		"certificate: import a new one in time, or add a DNS credential of the zone and switch the proxy to cert_mode %s, "+
		"which the node renews itself", p.Domain, p.CertNotAfter.UTC().Format("2006-01-02"), max(int(left.Hours()/24), 0), webrules.CertModeACME)}
}

// webProto is the WEB settings of a proxy as the API shows them: no
// certificate and no credential.
func webProto(p *store.Proxy) *panelv1.WebSettings {
	if p.Type != store.ProxyTypeWeb {
		return nil
	}
	w := &panelv1.WebSettings{
		BasePath:        p.WebBasePath,
		SecretMode:      webrules.SecretMode(p.WebSecretMode),
		Carrier:         webrules.Carrier(p.WebCarrier),
		CertMode:        p.CertMode,
		DnsCredentialId: p.DNSCredentialID,
		AcmeEmail:       p.ACMEEmail,
		CertSha256:      p.CertSHA256,
	}
	if !p.CertNotAfter.IsZero() {
		w.CertNotAfterUnix = p.CertNotAfter.Unix()
	}
	return w
}

// GetWebSnippets returns the configuration of the web server in front of an
// http-upstream listener for a WEB proxy on it.
func (s *Service) GetWebSnippets(ctx context.Context, req *connect.Request[panelv1.GetWebSnippetsRequest]) (*connect.Response[panelv1.GetWebSnippetsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	p, err := s.db.ProxyByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, s.readError("proxy", err)
	}
	l, err := s.db.ListenerByID(ctx, p.ListenerID)
	if err != nil {
		return nil, s.readError("listener", err)
	}
	if p.Type != store.ProxyTypeWeb || l.Kind != store.ListenerKindHTTPUpstream {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("snippets are for a WEB proxy on an http-upstream listener: the node terminates TLS for the other proxies itself"))
	}
	addr := net.JoinHostPort(l.BindIP, strconv.FormatUint(uint64(l.Port), 10))
	return connect.NewResponse(&panelv1.GetWebSnippetsResponse{
		Caddy: CaddySnippet(p.WebBasePath, addr),
		Nginx: NginxSnippet(p.WebBasePath, addr),
	}), nil
}

// CaddySnippet is the Caddyfile fragment, inside the site block of the
// domain, that hands the base path of a WEB proxy to the http-upstream
// listener at addr: the whole subtree with "handle" (never "handle_path",
// which strips the prefix that telemt expects), and the path without a slash
// (which "/<base>/*" does not match) too, so that it does not become a 301.
// Caddy passes Host as it is; X-Forwarded-For is set to the client address.
func CaddySnippet(basePath, addr string) string {
	base := "/" + basePath
	proxy := "\treverse_proxy " + addr + " {\n" +
		"\t\theader_up X-Forwarded-For {remote_host}\n" +
		"\t\tflush_interval -1\n" +
		"\t\ttransport http {\n" +
		"\t\t\tread_timeout 90s\n" +
		"\t\t\twrite_timeout 90s\n" +
		"\t\t}\n" +
		"\t}\n"
	return "# Telegram WEB proxy under " + base + " (Postern): the whole subtree goes to the node unchanged.\n" +
		"handle " + base + "/* {\n" + proxy + "}\n" +
		"handle " + base + " {\n" + proxy + "}\n"
}

// NginxSnippet is the nginx fragment, inside the server block of the domain,
// that hands the base path of a WEB proxy to the http-upstream listener at
// addr: "location ^~ /<base>/" with a proxy_pass that has no URI (so nothing
// is rewritten), plus "location = /<base>" for the path without a slash, so
// that nginx does not answer it with a 301 (outside the contract of telemt).
// Host is passed, X-Forwarded-For set to the client address; buffering is
// off and the timeouts are above the 65 s that WebSocket liveness needs.
func NginxSnippet(basePath, addr string) string {
	base := "/" + basePath
	proxy := "\t\tproxy_pass http://" + addr + ";\n" +
		"\t\tproxy_http_version 1.1;\n" +
		"\t\tproxy_set_header Host $host;\n" +
		"\t\tproxy_set_header X-Forwarded-For $remote_addr;\n" +
		"\t\tproxy_set_header Upgrade $http_upgrade;\n" +
		"\t\tproxy_set_header Connection $http_connection;\n" +
		"\t\tproxy_buffering off;\n" +
		"\t\tproxy_request_buffering off;\n" +
		"\t\tproxy_connect_timeout 5s;\n" +
		"\t\tproxy_send_timeout 90s;\n" +
		"\t\tproxy_read_timeout 90s;\n" +
		"\t\tclient_max_body_size 2m;\n" +
		"\t\taccess_log off;\n"
	return "\t# Telegram WEB proxy under " + base + " (Postern): the whole subtree goes to the node unchanged.\n" +
		"\tlocation ^~ " + base + "/ {\n" + proxy + "\t}\n" +
		"\tlocation = " + base + " {\n" + proxy + "\t}\n"
}
