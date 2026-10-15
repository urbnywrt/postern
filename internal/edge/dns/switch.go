package dns

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
)

// Switch is a resolver for the node's own names, in the edge and in the agent:
// its queries go to one DNS server while it is told to use it (the forwarder,
// ListenAddr), and to the nameservers of /etc/resolv.conf, as the resolver of
// the system's would, while it is not. It is safe for concurrent use, and a
// change applies to the queries that begin after it.
type Switch struct {
	target atomic.Pointer[string]
	res    *net.Resolver
}

// NewSwitch returns a switch that uses the nameservers of /etc/resolv.conf.
func NewSwitch() *Switch {
	s := &Switch{}
	// The resolver of Go, which the node's static binaries use anyway: it takes
	// the options and the search list of /etc/resolv.conf, and lets dial pick
	// where each query goes.
	s.res = &net.Resolver{PreferGo: true, Dial: s.dial}
	return s
}

func (s *Switch) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if t := s.Target(); t != "" {
		address = t
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Resolver returns the resolver of the switch. It is the same one for the life
// of the switch, so a net.Dialer can be given it once.
func (s *Switch) Resolver() *net.Resolver { return s.res }

// Use makes the queries go to the DNS server at addr ("ip:port"), or to the
// nameservers of /etc/resolv.conf when addr is "". It reports whether that is a
// change.
func (s *Switch) Use(addr string) bool {
	old := s.target.Swap(&addr)
	return (old == nil && addr != "") || (old != nil && *old != addr)
}

// Target returns the server the queries go to, "" for the nameservers of
// /etc/resolv.conf.
func (s *Switch) Target() string {
	if p := s.target.Load(); p != nil {
		return *p
	}
	return ""
}

// maxNameservers is how many nameservers of a resolv.conf are used, as the C
// libraries do (MAXNS).
const maxNameservers = 3

// Nameservers returns the nameservers of a resolv.conf file: the addresses of
// its "nameserver" lines, in order, without duplicates and without the
// forwarder's own address, the first three. A line that does not hold an IP
// address is skipped. The stub of systemd-resolved, 127.0.0.53, is a
// nameserver like any other: on the host's network it is reachable.
func Nameservers(resolvConf []byte) []string {
	var out []string
	for line := range strings.Lines(string(resolvConf)) {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil || a.Unmap() == forwarderAddr.Addr() {
			continue
		}
		s := a.Unmap().String()
		if slices.Contains(out, s) {
			continue
		}
		out = append(out, s)
		if len(out) == maxNameservers {
			break
		}
	}
	return out
}

// HostNameservers returns the Nameservers of the resolv.conf file at path, nil
// when it cannot be read. The agent runs on the host's network, where its
// /etc/resolv.conf is the host's.
func HostNameservers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil
	}
	return Nameservers(data)
}
