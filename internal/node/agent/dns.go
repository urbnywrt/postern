package agent

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/urbnywrt/postern/internal/edge/dns"
	"github.com/urbnywrt/postern/internal/node/reconcile"
)

// nodeResolver is how the agent resolves the names it needs itself, for its own
// HTTP clients: through the DNS forwarder of the edge while the edge says that
// it runs, since UDP port 53 may be blocked on the node, and with the host's
// nameservers otherwise.
type nodeResolver struct {
	sw         *dns.Switch
	forwarder  string // where the forwarder answers, dns.ListenAddr
	resolvConf string // the host's resolv.conf
	log        *slog.Logger
}

func newNodeResolver(opt Options, log *slog.Logger) *nodeResolver {
	r := &nodeResolver{sw: opt.dnsSwitch, forwarder: opt.dnsForwarder, resolvConf: opt.resolvConf, log: log}
	if r.sw == nil {
		r.sw = dns.NewSwitch()
	}
	if r.forwarder == "" {
		r.forwarder = dns.ListenAddr
	}
	if r.resolvConf == "" {
		r.resolvConf = hostResolvConf
	}
	return r
}

// edgeDNS is told whether the forwarder of the current edge runs, and makes the
// lookups of the agent go to it, or to the host's nameservers. A change is
// logged.
func (r *nodeResolver) edgeDNS(up bool) {
	target := ""
	if up {
		target = r.forwarder
	}
	if !r.sw.Use(target) {
		return
	}
	if up {
		r.log.Info("agent: names are resolved through the DNS forwarder of the edge", "forwarder", r.forwarder)
	} else {
		r.log.Info("agent: names are resolved with the nameservers of the host: the DNS forwarder of the edge does not run")
	}
}

// hostNameservers are the nameservers of the host's resolv.conf, but the
// forwarder: the fallback of the forwarder.
func (r *nodeResolver) hostNameservers() []string { return dns.HostNameservers(r.resolvConf) }

// edgeDNSUp asks an edge whether its DNS forwarder runs. answered is false when
// the edge did not answer in time: that tells nothing of its forwarder.
func edgeDNSUp(ctx context.Context, edge reconcile.EdgeClient) (up, answered bool) {
	ctx, cancel := context.WithTimeout(ctx, edgeDNSTimeout)
	defer cancel()
	h, err := edge.Health(ctx)
	if err != nil {
		return false, false
	}
	return h.GetDns(), true
}

// onEdgeDNS is the OnEdgeDNS of the reconciler: the agent resolves through the
// forwarder while the edge says that it runs. The first time it does, a public
// IPv4 address that the start could not find is looked up again, once, in the
// background (run): on a node where UDP port 53 is blocked the lookup at the
// start could not resolve the echo services. An address found then goes to the
// reconciler, and a pass is asked for (kick).
func onEdgeDNS(ctx context.Context, r *nodeResolver, rec *reconcile.Reconciler, info *hostInfo, run func(func()), kick func(), log *slog.Logger) func(up bool) {
	known := rec.NodePublicIPv4 != ""
	var tried atomic.Bool
	return func(up bool) {
		r.edgeDNS(up)
		if !up || known || !tried.CompareAndSwap(false, true) {
			return
		}
		run(func() {
			ip := info.refreshPublicIPv4(ctx)
			if ip == "" {
				log.Warn("agent: the node's public IPv4 address is still not known; engines that use the middle proxy get no NAT address")
				return
			}
			rec.SetNodePublicIPv4(ip)
			log.Info("agent: the node's public IPv4 address is known now", "ip", ip)
			kick()
		})
	}
}
