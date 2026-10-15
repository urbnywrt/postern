package edge

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/urbnywrt/postern/internal/edge/rules"
)

// Listeners of kind http-upstream.
//
// A WEB proxy may sit under a path of a site that another web server serves on
// the node, Caddy or nginx, which owns the certificate and terminates TLS. That
// server passes the requests of the base path on, as plain HTTP, to a listener
// of kind http-upstream on the loopback interface, which serves the web routes
// of the listener by the Host of each request. Only the web servers that the
// listener trusts (trusted_cidrs) are served: the connection of any other
// address is closed as it is accepted, before anything is read from it.
//
// The server in front of the listener is the only one that sees the client:
// the client of a request is found in its X-Forwarded-For from the right, past
// the addresses of the trusted servers (see forwardedClient). A request that
// names no client there is refused with 400: the edge never takes the server
// for the client. A request is a connection of its proxy for the limits and
// the counters, held
// from its start to its end (a WebSocket for its whole life), and for its
// client; a request of a client of the blacklist is refused with 403, and one
// over the limits of the proxy with 503. A Host that the listener has no web
// route for is answered 421 Misdirected Request. The request goes to the
// backend as one of a web route does (webproxy.go), with its client alone in
// X-Forwarded-For.
//
// The listener binds a loopback or private address, and trusts such addresses
// only (rules.CheckUpstreamBind, rules.CheckUpstreamTrusted). Its connections
// count among all the connections of the edge (the total cap of ingress.go),
// and may be half of them at most, so that a slow web server in front of the
// listener cannot make the edge refuse fake TLS at accept (Ruling S3-4); one
// over either is closed as it is accepted, as on a tls listener. The caps on
// the connections before their hello do not hold for them, which have no hello
// to send. The requests share the places among the requests in flight with
// those of the web routes, and the client of a request is its source there
// (see takeWebSlot).

// acceptUpstream takes the connection c, which the http-upstream listener l at
// addr accepted from peer.
func (e *Edge) acceptUpstream(addr netip.AddrPort, l *listenerEntry, c net.Conn, peer netip.AddrPort) {
	if !l.trusted.contains(peer.Addr()) {
		_ = c.Close()
		if e.warns.allow("untrusted "+addr.String(), e.now()) {
			e.log.Warn("edge: a connection to an http-upstream listener from an address that it does not trust was closed; the web server in front of it has to be among its trusted CIDRs",
				"listener", l.id, "peer", peer.Addr())
		}
		return
	}
	tk, over := e.ingress.admitHeld(c)
	if tk == nil {
		_ = c.Close()
		e.log.Debug("edge: connection over the caps closed", "listener", l.id, "client", peer.Addr(), "cap", over)
		if over == capTotal {
			e.warnCaps()
		} else if e.capWarns.allow("upstream half", e.now()) {
			e.log.Warn("edge: the http-upstream listeners hold half of the connections that the edge may hold, and the others of theirs are closed; the other half is for fake TLS",
				"max_upstream", e.ingress.maxUpstream(), "max_conns", e.ingress.maxConns, "refused_total", e.ingress.refusedTotal.Load())
		}
		return
	}
	f := e.conns.add(c)
	if f == nil { // Drain has begun
		tk.release()
		_ = c.Close()
		return
	}
	go func() {
		defer e.conns.remove(f)
		defer tk.release()
		defer e.recoverConn("connection", f.close)
		defer func() { _ = c.Close() }()
		wc := newWebConn(c, addr, peer)
		defer wc.w.stop()
		wc.upstream = true
		if e.web.serve(wc) {
			<-wc.done
		}
	}()
}

// serveUpstream serves a request of a connection of an http-upstream listener,
// by the table in effect as it comes.
func (e *Edge) serveUpstream(rw http.ResponseWriter, req *http.Request, wc *webConn) {
	t := e.table.Load()
	var l *listenerEntry
	if t != nil {
		l = t.listeners[wc.listener]
	}
	if l == nil || l.kind != rules.KindHTTPUpstream || !l.trusted.contains(wc.peer.Addr()) {
		// The listener is gone, or trusts the peer no more: the connection
		// ends without an answer.
		panic(http.ErrAbortHandler)
	}
	name, ok := hostName(req.Host)
	if !ok {
		e.log.Debug("edge: a WEB request with a Host whose port is no port refused", "listener", l.id)
		answer(rw, req, http.StatusBadRequest, true)
		return
	}
	r := l.routes[name]
	if r == nil || r.kind != routeWeb {
		answer(rw, req, http.StatusMisdirectedRequest, true)
		return
	}
	client, ok := forwardedClient(req.Header["X-Forwarded-For"], l.trusted)
	if !ok {
		// Never the peer in its place: every user would be one device, and
		// the blacklist would see none of them. What the header held is not
		// logged.
		if e.warns.allow("no client "+wc.listener.String(), e.now()) {
			e.log.Warn("edge: a request to an http-upstream listener names no client in X-Forwarded-For and is refused; the web server in front of the listener must set X-Forwarded-For",
				"listener", l.id, "peer", wc.peer.Addr())
		}
		answer(rw, req, http.StatusBadRequest, true)
		return
	}
	if t.blacklist.contains(client) {
		e.log.Debug("edge: a request of a blacklisted client refused", "listener", l.id, "client", client)
		answer(rw, req, http.StatusForbidden, true)
		return
	}
	src, ok := e.takeWebSlot(rw, req, client)
	if !ok {
		return
	}
	defer e.giveWebSlot(src)
	tg := &webTarget{route: r, client: client, keepHost: true}
	if r.stats != nil {
		ls, over := r.stats.admit(client, r.backendKey, r.limits, e.now(), t.deviceIdle)
		if ls == nil {
			e.log.Debug("edge: a request over a limit of its proxy refused", "proxy", r.proxyID, "limit", over, "client", client)
			answer(rw, req, http.StatusServiceUnavailable, true)
			return
		}
		defer func() { ls.release(e.now()) }()
		tg.ls = ls
	}
	e.proxyWeb(rw, req, tg)
}

// hostName returns the name in the Host of a request, without its port and
// folded (rules.FoldName), or "" when the Host names no host by a name: an
// IPv6 address, in brackets or not, or nothing at all, which no route has. An
// IPv4 address passes for a name, and folds to itself. It reports false when
// the Host has a port that is no port, a number from 0 to 65535, or a colon
// that is neither that of a port nor one of an IPv6 address
// (web.example.com:443:443): such a Host is no Host at all.
func hostName(host string) (string, bool) {
	if h, port, err := net.SplitHostPort(host); err == nil {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", false
		}
		host = h
	} else if strings.Contains(host, ":") && !isIPv6(host) {
		return "", false
	}
	name, _ := rules.FoldName(host)
	return name, true
}

// isIPv6 reports whether host is an IPv6 address, in brackets or not.
func isIPv6(host string) bool {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Is6()
}

// forwardedClient finds the client of a request in its X-Forwarded-For, the
// list of the addresses that the request came from, each web server on its way
// adding the one it saw at the right. The header may come in several lines,
// which make one list in their order, each a list separated by commas. The list
// is read from the right, and the addresses of trusted, the web servers of the
// node, are passed over: the first other address is the client, or, when every
// address is a trusted one, the first of the list. Whatever is left of the
// client is the client's own to write, and is not looked at. It reports false
// when there is no list, or when no address stands where the client is to be.
func forwardedClient(values []string, trusted cidrSet) (netip.Addr, bool) {
	var hops []string
	for _, v := range values {
		hops = append(hops, strings.Split(v, ",")...)
	}
	if len(hops) == 0 {
		return netip.Addr{}, false
	}
	var a netip.Addr
	for i := len(hops) - 1; i >= 0; i-- {
		var ok bool
		if a, ok = parseForwardedAddr(strings.TrimSpace(hops[i])); !ok {
			return netip.Addr{}, false
		}
		if !trusted.contains(a) {
			return a, true
		}
	}
	return a, true // every hop is trusted: the first one
}

// parseForwardedAddr reads an address of X-Forwarded-For: an IP address, or an
// IPv4 address and a port, or an IPv6 address in brackets and a port. One with
// a zone is none. An IPv4-mapped address is the IPv4 address.
func parseForwardedAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		ap, perr := netip.ParseAddrPort(s)
		if perr != nil {
			return netip.Addr{}, false
		}
		a = ap.Addr()
	}
	if a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}
