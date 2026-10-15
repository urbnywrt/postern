package telemt

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt/overrides"
	"github.com/urbnywrt/postern/internal/engines/telemt/site"
	"github.com/urbnywrt/postern/internal/webrules"
)

const (
	// publicDir is the directory of the decoy site in the instance directory,
	// publicMount where the container sees it (decoy.directory).
	publicDir   = "public"
	publicMount = instanceMount + "/" + publicDir
	// webUser is the name of the one user of a WEB instance, in access.users
	// and the profile of the vhost.
	webUser = "p"
)

// renderWeb writes the telemt config of a WEB proxy (plan: Global Constraints
// of slice 3; spec 5.4). It differs from a fake-TLS one in what the edge does
// for it: the edge terminates TLS (or the web server in front does, for an
// http-upstream placement) and proxies plain HTTP to telemt's web listener on
// the instance's loopback port, naming the client in X-Forwarded-For, which
// telemt trusts from 127.0.0.1 only. No PROXY protocol, no [censorship]: the
// vhost serves the decoy site to every request that is not the proxy's.
//
// The vhost is the proxy's domain in lowercase ASCII, under base_path when
// one is set, with public_addr the public IPv4 address of the domain's A
// record, which the reconciler fills in (the panel may name it), and port 443.
// The one profile is user p with the proxy's secret, in secret_mode plain or
// dd. carrier and carriers default to https and [https-lanes].
//
// Everything else is as for fake TLS: silent log, no address discovery, the
// control API on loopback, both upstreams through the edge's SOCKS port.
func renderWeb(in engines.Instance) ([]byte, error) {
	p := in.Proxy
	if e := p.GetEngine(); e != nodev1.Engine_ENGINE_UNSPECIFIED && e != nodev1.Engine_ENGINE_TELEMT {
		return nil, fmt.Errorf("telemt: the proxy is bound to engine %s", e)
	}
	overridden, err := parseOverrides(p.GetEngineOverridesJson())
	if err != nil {
		return nil, err
	}
	w := p.GetWeb()
	if w == nil {
		return nil, errors.New("telemt: a WEB proxy has no web settings")
	}
	if !isHex(p.GetSecret(), 32) {
		return nil, errors.New("telemt: the proxy secret must be exactly 32 hex characters")
	}
	if tag := p.GetAdTag(); tag != "" && !isHex(tag, 32) {
		return nil, errors.New("telemt: the ad tag must be empty or exactly 32 hex characters")
	}
	host, err := webrules.CertDomain(p.GetDomain())
	if err != nil {
		return nil, fmt.Errorf("telemt: %w", err)
	}
	if err := webrules.CheckBasePath(w.GetBasePath()); err != nil {
		return nil, fmt.Errorf("telemt: %w", err)
	}
	if err := webrules.CheckSecretMode(w.GetSecretMode()); err != nil {
		return nil, fmt.Errorf("telemt: %w", err)
	}
	if err := webrules.CheckCarrier(w.GetCarrier()); err != nil {
		return nil, fmt.Errorf("telemt: %w", err)
	}
	if err := webrules.CheckCarriers(w.GetCarriers()); err != nil {
		return nil, fmt.Errorf("telemt: %w", err)
	}
	publicIP, err := webrules.ParsePublicAddr(w.GetPublicAddr())
	if err != nil {
		return nil, fmt.Errorf("telemt: %w (the public address of the domain is not known yet)", err)
	}
	var natIP string
	if p.GetUseMiddleProxy() && p.GetNatIp() != "" {
		a, err := parseNATIP(p.GetNatIp())
		if err != nil {
			return nil, err
		}
		natIP = a.String()
	}
	if err := checkPorts(in); err != nil {
		return nil, err
	}
	if err := checkToken(in.APIToken); err != nil {
		return nil, err
	}

	var t tomlWriter
	t.table("general")
	t.boolean("use_middle_proxy", p.GetUseMiddleProxy())
	t.str("log_level", "silent")
	t.str("data_path", dataMount)
	if tag := p.GetAdTag(); tag != "" {
		t.str("ad_tag", tag)
	}
	if natIP != "" {
		t.str("middle_proxy_nat_ip", natIP)
		t.boolean("middle_proxy_nat_probe", false)
	}
	if err := t.writeOverrides(overridden.In(overrides.General)); err != nil {
		return nil, err
	}

	t.table("general.links")
	t.strings("show")

	t.table("network")
	t.boolean("stun_use", false)
	t.strings("http_ip_detect_urls")

	t.array("server.listeners")
	t.str("ip", "127.0.0.1")
	t.integer("port", int(in.ListenPort))
	t.str("transport", "web")
	t.boolean("proxy_protocol", false)
	t.boolean("reuse_allow", false)
	t.str("web_client_ip_source", "x_forwarded_for")
	t.strings("web_trusted_proxy_cidrs", "127.0.0.1/32")

	t.table("server.api")
	t.boolean("enabled", true)
	t.str("listen", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.APIPort))))
	t.strings("whitelist", "127.0.0.1/32")
	t.str("auth_header", in.APIToken)

	t.table("web")
	t.boolean("enabled", true)
	t.str("carrier", webrules.Carrier(w.GetCarrier()))
	t.strings("carriers", webrules.Carriers(w.GetCarriers())...)

	t.array("web.vhosts")
	t.str("host", host)
	if bp := w.GetBasePath(); bp != "" {
		t.str("base_path", bp)
	}
	t.str("public_addr", webrules.PublicAddr(publicIP))

	t.table("web.vhosts.decoy")
	t.str("mode", "static_directory")
	t.str("directory", publicMount)
	t.str("index", site.IndexFile)

	t.array("web.vhosts.profiles")
	t.str("user", webUser)
	t.str("secret_mode", webrules.SecretMode(w.GetSecretMode()))

	t.table("access.users")
	t.str(webUser, p.GetSecret())

	socks := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.SocksPort)))
	t.array("upstreams")
	t.str("type", "socks5")
	t.str("address", socks)
	t.array("upstreams")
	t.str("type", "socks5")
	t.str("address", socks)
	t.str("scopes", "me, fetch")

	return []byte(t.String()), nil
}

// decoyFiles are the files of the decoy site of the proxy, under public/.
func decoyFiles(p *nodev1.Proxy) map[string][]byte {
	files := map[string][]byte{}
	for name, data := range site.Generate(p.GetId()) {
		files[publicDir+"/"+name] = data
	}
	return files
}
