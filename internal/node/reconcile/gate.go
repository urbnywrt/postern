package reconcile

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/probe"
	"github.com/urbnywrt/postern/internal/socks5"
)

// The checks of the way out of a new engine generation (spec 5.5), after its
// readiness and its L1 probe, before the route of its proxy moves to it. The L1
// probe proves the engine and its secret; it does not go out. So:
//
//  1. a datacenter answers req_pq_multi with its resPQ through the SOCKS port
//     of the new generation, that is through the edge and the proxy's chain
//     (probe.DCPing): the datacenters of the chain's health check, in order,
//     until one answers;
//  2. with the middle proxy, an HTTPS GET of getProxySecret through the same
//     SOCKS port answers 200: the engine needs it for the middle proxy;
//  3. L2 (probe.L2): a client's view of the whole way, through the test
//     listener of the proxy's listener, where a probe route of the edge leads
//     the proxy's domain to the new generation, the route itself still being
//     the old generation's; to the datacenter that answered in 1.
//
// An edge that runs another version than the agent may not know probe routes
// (EdgeConfig.probe_routes): L2 then goes straight to the new generation's
// port, with a PROXY header as the edge sends it, as the L1 probe does.

const (
	// defaultGateTimeout bounds the check of the datacenters through a new
	// generation.
	defaultGateTimeout = 30 * time.Second
	// gateDCTimeout bounds the check of one datacenter.
	gateDCTimeout = 10 * time.Second
	// defaultProxySecretURL is what the engine fetches for the middle proxy.
	defaultProxySecretURL = "https://core.telegram.org/getProxySecret" //nolint:gosec // a public URL, not a credential
	// maxProxySecret bounds what is read of the proxy secret.
	maxProxySecret = 64 << 10
	// fallbackDC is the datacenter L2 asks for when the one that answered is not
	// one of the default five.
	fallbackDC = 2
)

// L2Prober runs the L2 probe (probe.L2) against addr: the fake-TLS handshake
// with sni and secret (16 bytes), then req_pq_multi for datacenter dc through
// the proxy, and returns nil when its resPQ came back. src, when it is valid,
// is sent in a PROXY v2 header first.
type L2Prober func(ctx context.Context, addr, sni string, secret []byte, dc int16, src netip.AddrPort) error

// gate runs the checks of the way out of a new generation (see above). pr is
// the proxy as the generation was rendered.
func (p *pass) gate(pr *nodev1.Proxy, in engines.Instance) error {
	socks := loopback(in.SocksPort)
	dc, err := p.gateDC(pr, socks)
	if err != nil {
		return err
	}
	if pr.GetUseMiddleProxy() {
		ctx, cancel := context.WithTimeout(p.ctx, fetchTimeout)
		err := p.r.proxySecretCheck()(ctx, socks)
		cancel()
		if err != nil {
			return fmt.Errorf("the middle proxy: the proxy secret does not come through the SOCKS port of the new generation: %w", err)
		}
	}
	if isWeb(pr) {
		return nil // L2 speaks fake TLS to the engine; a web listener speaks HTTP
	}
	return p.gateL2(pr, in, dc)
}

// gateDC checks the datacenters through the SOCKS port socks, in order, until
// one answers, and returns its number (1 to 5 for the default ones, 2 for any
// other).
func (p *pass) gateDC(pr *nodev1.Proxy, socks string) (int16, error) {
	ctx, cancel := context.WithTimeout(p.ctx, orDefault(p.r.gateTimeout, defaultGateTimeout))
	defer cancel()
	var last error
	for _, dc := range p.gateDCs(pr) {
		dctx, dcancel := context.WithTimeout(ctx, gateDCTimeout)
		err := p.r.pingDC(dctx, socks, dc)
		dcancel()
		if err == nil {
			return dcNumber(dc), nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if p.ctx.Err() != nil {
		return 0, p.ctx.Err()
	}
	return 0, fmt.Errorf("no datacenter answered through the SOCKS port of the new generation (its way out): %v", last)
}

// gateDCs are the datacenters of the health check of the proxy's chain (see
// ProxyDCs).
func (p *pass) gateDCs(pr *nodev1.Proxy) []string { return ProxyDCs(p.st, pr) }

// ProxyDCs are the datacenters the checks of the way out of proxy pr ask, in
// order: those of the health check of its chain, of the node's check when that
// has none (see healthCheck), or the default ones.
func ProxyDCs(st *nodev1.NodeState, pr *nodev1.Proxy) []string {
	chainID := cmp.Or(pr.GetEgressChainId(), st.GetSettings().GetDefaultChainId())
	for _, c := range st.GetChains() {
		if c.GetId() == chainID && len(c.GetCheck().GetDcAddrs()) > 0 {
			return c.GetCheck().GetDcAddrs()
		}
	}
	chains := map[string]*nodev1.EgressChain{}
	for _, c := range st.GetChains() {
		chains[c.GetId()] = c
	}
	if hc := healthCheck(chains, st.GetSettings().GetDefaultChainId()); len(hc.GetDcAddrs()) > 0 {
		return hc.GetDcAddrs()
	}
	return egress.DefaultHealthCheck().GetDcAddrs()
}

// dcNumber is the number of a datacenter of the default ones (DC1 to DC5), or
// fallbackDC.
func dcNumber(addr string) int16 {
	if i := slices.Index(egress.DefaultHealthCheck().GetDcAddrs(), addr); i >= 0 {
		return int16(i + 1)
	}
	return fallbackDC
}

// pingDC is PingDC through r.socksDial when it is set.
func (r *Reconciler) pingDC(ctx context.Context, socks, dc string) error {
	if r.socksDial == nil {
		return PingDC(ctx, socks, dc)
	}
	return pingDCVia(ctx, r.socksDial, socks, dc)
}

// PingDC connects to the datacenter dc through the SOCKS port socksAddr,
// without a user name (the ordinary traffic of an engine), and exchanges
// req_pq_multi/resPQ with it: what the gate checks first. A SOCKS server that
// acknowledges the CONNECT without reaching the datacenter fails it, since
// only a datacenter answers the request.
func PingDC(ctx context.Context, socksAddr, dc string) error {
	return pingDCVia(ctx, func(ctx context.Context, socks, target string) (net.Conn, error) {
		return socks5.Dial(ctx, socks, "", "", target)
	}, socksAddr, dc)
}

func pingDCVia(ctx context.Context, dial func(ctx context.Context, socks, target string) (net.Conn, error), socks, dc string) error {
	conn, err := dial(ctx, socks, dc)
	if err != nil {
		return fmt.Errorf("CONNECT to %s: %w", dc, err)
	}
	defer func() { _ = conn.Close() }()
	if err := probe.DCPing(ctx, conn); err != nil {
		return fmt.Errorf("%s: %w", dc, err)
	}
	return nil
}

// proxySecretCheck is the check of the proxy secret: r.proxySecret, or
// checkProxySecret.
func (r *Reconciler) proxySecretCheck() func(ctx context.Context, socks string) error {
	if r.proxySecret != nil {
		return r.proxySecret
	}
	return r.checkProxySecret
}

// checkProxySecret is ProxySecretCheck at r.proxySecretURL with r.gateTLS.
func (r *Reconciler) checkProxySecret(ctx context.Context, socks string) error {
	return proxySecretGet(ctx, socks, cmp.Or(r.proxySecretURL, defaultProxySecretURL), r.gateTLS)
}

// ProxySecretCheck makes an HTTPS GET of getProxySecret through the SOCKS port
// socksAddr, without a user name, and wants 200: what the gate checks for a
// proxy with the middle proxies.
func ProxySecretCheck(ctx context.Context, socksAddr string) error {
	return proxySecretGet(ctx, socksAddr, defaultProxySecretURL, nil)
}

func proxySecretGet(ctx context.Context, socks, url string, tlsConf *tls.Config) error {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return socks5.Dial(ctx, socks, "", "", addr)
		},
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: fetchTimeout,
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", fetchUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return fetchError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProxySecret))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// gateL2 runs L2 against the new generation for datacenter dc: through the
// test listener of the proxy's listener and a probe route of the edge, or
// straight to the engine through an edge that may not know probe routes. It
// tries a few times, as the L1 probe does.
func (p *pass) gateL2(pr *nodev1.Proxy, in engines.Instance, dc int16) error {
	secret, err := hex.DecodeString(pr.GetSecret())
	if err != nil {
		return errors.New("the proxy secret is not hex")
	}
	addr, src := loopback(in.ListenPort), probeSource
	if p.edgeTakesProbeRoutes() {
		port := p.rt.Ports[state.TestListenerPortKey(pr.GetListenerId())]
		if port == 0 {
			return errors.New("L2: the listener of the proxy has no test listener")
		}
		addr, src = loopback(port), netip.AddrPort{}
		st := p.starting[pr.GetId()]
		st.probe, st.listen = true, in.ListenPort
		p.starting[pr.GetId()] = st
		if err := p.pushEdgeConfig(); err != nil {
			return fmt.Errorf("L2: giving the edge the probe route: %w", err)
		}
	}
	attempts := orDefault(p.r.probeAttempts, defaultProbeAttempts)
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			if err := sleep(p.ctx, orDefault(p.r.readyPoll, defaultReadyPoll)); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(p.ctx, orDefault(p.r.probeTimeout, defaultProbeTimeout))
		last = p.r.L2(ctx, addr, pr.GetDomain(), secret, dc, src)
		cancel()
		if last == nil {
			return nil
		}
		if p.ctx.Err() != nil {
			return p.ctx.Err()
		}
	}
	return fmt.Errorf("the L2 probe through the edge to DC%d failed: %v", dc, last)
}

// edgeTakesProbeRoutes reports whether the current edge runs the agent's
// version, which knows probe routes; a node whose version is not known (a test)
// takes it that it does.
func (p *pass) edgeTakesProbeRoutes() bool {
	return p.r.Version == "" || p.r.edgeVersionOK
}
