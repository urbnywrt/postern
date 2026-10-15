package diag

import (
	"context"
	"net"
	"net/netip"
	"strconv"
)

// checkBound is ingress.bound: every listener is among the addresses the
// running edge says it is bound to (Health.bound).
func checkBound(ctx context.Context, env *Env) []Result {
	listeners := env.Listeners()
	if len(listeners) == 0 {
		return nil
	}
	failAll := func(summary, evidence string) []Result {
		out := make([]Result, 0, len(listeners))
		for _, l := range listeners {
			out = append(out, Result{Target: ListenerTarget(l.GetId()), Status: Fail, Summary: summary, Evidence: evidence,
				Hint: "the edge carries every listener; see the edge's log"})
		}
		return out
	}
	e := env.edge()
	if e == nil {
		return failAll("no edge runs", "the runtime record names no edge generation")
	}
	h, err := e.Health(ctx)
	if err != nil {
		return failAll("the edge does not answer", err.Error())
	}
	bound := map[netip.AddrPort]bool{}
	for _, b := range h.GetBound() {
		if ap, err := netip.ParseAddrPort(b); err == nil {
			bound[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = true
		}
	}
	why := map[string]string{}
	for _, f := range h.GetListenerFailures() {
		why[f.GetListenerId()] = f.GetReason()
	}
	var out []Result
	for _, l := range listeners {
		r := Result{Target: ListenerTarget(l.GetId())}
		a, err := netip.ParseAddr(l.GetBindIp())
		if err != nil || l.GetPort() == 0 || l.GetPort() > 65535 {
			r.Status, r.Summary = Skip, "the listener has no address"
			out = append(out, r)
			continue
		}
		addr := net.JoinHostPort(a.Unmap().String(), strconv.Itoa(int(l.GetPort())))
		if bound[netip.AddrPortFrom(a.Unmap(), uint16(l.GetPort()))] {
			r.Status, r.Summary = OK, "the edge listens on "+addr
		} else {
			r.Status, r.Summary = Fail, "the edge does not listen on "+addr
			r.Evidence = why[l.GetId()]
			if r.Evidence == "" {
				r.Evidence = "not among the addresses the edge is bound to"
			}
			r.Hint = "another process may hold the port (see host.ports), or the address is not the node's (see host.public_ips)"
		}
		out = append(out, r)
	}
	return out
}
