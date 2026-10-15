// Package rules holds the rules for the values of an edge configuration
// (edgev1.EdgeConfig) that two parties apply: the edge, which parses a
// configuration and refuses it whole for one value it cannot take, and the
// node agent, which validates a desired state before it takes it and must never
// take one whose configuration its edge would refuse. One implementation of
// each rule keeps the two from drifting apart: server names and their folded
// form, the kinds and actions of a listener, bind addresses, ports, address
// prefixes, mask targets, and the addresses and credentials of the members of
// egress chains.
//
// The values come from outside: nothing here panics on any input, and an
// error never quotes more than 70 bytes of it.
package rules

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// The kinds of a listener.
const (
	KindTLS          = "tls"
	KindHTTPUpstream = "http-upstream"
)

// The actions of a listener for a stranger, a connection for a server name it
// has no route for.
const (
	StrangerMask   = "mask"
	StrangerReject = "reject"
	StrangerDrop   = "drop"
)

// The actions of a listener for a connection that does not open with TLS.
const (
	NonTLSDrop    = "drop"
	NonTLSHTTP400 = "http400"
)

// ValidListenerKind reports whether s is the kind of a listener.
func ValidListenerKind(s string) bool { return s == KindTLS || s == KindHTTPUpstream }

// ValidStrangerAction reports whether s is an action for strangers.
func ValidStrangerAction(s string) bool {
	return s == StrangerMask || s == StrangerReject || s == StrangerDrop
}

// ValidNonTLSAction reports whether s is an action for what is not TLS.
func ValidNonTLSAction(s string) bool { return s == NonTLSDrop || s == NonTLSHTTP400 }

// MaskPort is the port of a mask target that names none, and the one a
// stranger is masked to by its own server name.
const MaskPort = "443"

// ---- server names --------------------------------------------------------------

// The limits of a server name: the DNS takes no longer name, nor label. The dot
// at the end of a fully qualified name counts in MaxNameLen.
const (
	MaxNameLen  = 253
	MaxLabelLen = 63
)

// A NameProblem is what makes a string no server name, as CheckName finds it.
type NameProblem int

// The problems of a name, in the order CheckName looks for them.
const (
	NameOK         NameProblem = iota
	NameEmpty                  // the empty string
	NameTooLong                // more than MaxNameLen bytes
	NameLongLabel              // a label of more than MaxLabelLen bytes
	NameEmptyLabel             // a dot at the start, two dots in a row, two at the end, or a dot alone
	NameBadByte                // a byte that is not an ASCII letter, a digit, a hyphen or a dot
)

// CheckName tells whether name is a server name that the edge takes, and what
// makes it none: at most 253 bytes, the one dot at the end that a fully
// qualified name may have counted, of ASCII letters, digits, hyphens and
// dots, in labels of 1 to 63 bytes. A server name from a ClientHello is
// whatever bytes the client put there, up to 64 KiB of them; one that is no
// name is never looked up, logged or dialed. The first problem found from the
// start of the name is the one reported.
func CheckName(name string) NameProblem {
	switch {
	case name == "":
		return NameEmpty
	case len(name) > MaxNameLen:
		return NameTooLong
	}
	name = strings.TrimSuffix(name, ".")
	label := 0 // the length of the current label so far
	for i := range len(name) {
		switch c := name[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-':
			if label++; label > MaxLabelLen {
				return NameLongLabel
			}
		case c == '.':
			if label == 0 {
				return NameEmptyLabel
			}
			label = 0
		default:
			return NameBadByte
		}
	}
	if label == 0 {
		return NameEmptyLabel // nothing but a dot, or a dot after a dot at the end
	}
	return NameOK
}

// Fold is the form in which the edge compares server names: ASCII letters in
// lower case, and without the one dot that a fully qualified name may end with.
// Names that fold to one form are one name: the edge routes them alike, and two
// routes of a listener for one name make it refuse its configuration. Only
// ASCII letters fold (strings.ToLower would also make a k of the Kelvin sign,
// U+212A), and any other byte stays what it is, so that two strings that are
// no names never fold to one. Fold does not check that s is a name: see
// FoldName.
func Fold(s string) string {
	s = strings.TrimSuffix(s, ".")
	for i := range len(s) {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// FoldName returns the folded form of a server name (Fold), or false when name
// is no server name (CheckName); then it must be taken for no name at all.
func FoldName(name string) (string, bool) {
	if CheckName(name) != NameOK {
		return "", false
	}
	return Fold(name), true
}

// ---- addresses -----------------------------------------------------------------

// ParsePort returns p as a port: 1 to 65535.
func ParsePort(p uint32) (uint16, error) {
	if p == 0 || p > math.MaxUint16 {
		return 0, fmt.Errorf("port %d is out of range", p)
	}
	return uint16(p), nil
}

// ParseBindIP returns the address a listener binds: an IP address, an
// IPv4-mapped one being the IPv4 address it maps.
func ParseBindIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("bind address %.70q is not an IP address", s)
	}
	return ip.Unmap(), nil
}

// ParsePrefix reads an address prefix of a blacklist or of the trusted
// addresses of a listener: a prefix in CIDR notation, whose host bits may be
// set ("192.0.2.7/24" is 192.0.2.0/24), or a single address, which is the
// prefix of its whole length. An address with a zone is none: the zone would
// swallow anything behind the "%", a "/64" included. The prefix is returned
// masked, and one of IPv4-mapped addresses as the IPv4 prefix it maps.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%.70q is neither a CIDR prefix nor an IP address", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

// ParseMaskTarget reads the mask target of a listener and returns it as
// host:port: the port 443 when it names none, an IP address as its plain form
// (an IPv4-mapped one as the IPv4 address), a host name folded (FoldName). ""
// stays "": the stranger's own server name is the target then.
func ParseMaskTarget(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, MaskPort // no port given, or something SplitHostPort cannot read, judged below
	} else {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", fmt.Errorf("mask target %.70q: bad port", s)
		}
		port = strconv.FormatUint(n, 10)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(ip.Unmap().String(), port), nil
	}
	name, ok := FoldName(host)
	if !ok {
		return "", fmt.Errorf("mask target %.70q: not an IP address or a host name", s)
	}
	return net.JoinHostPort(name, port), nil
}

// ---- http-upstream listeners ---------------------------------------------------

// upstreamRanges are the address ranges of the loopback interfaces and of the
// private networks (RFC 1918, RFC 4193 unique local), the only ones where an
// http-upstream listener may be and whose peers it may trust.
var upstreamRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
}

// upstreamRangeList names upstreamRanges in an error.
const upstreamRangeList = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1, fc00::/7"

// CheckUpstreamBind checks the bind address of an http-upstream listener (as
// ParseBindIP returns it). Such a listener takes plain HTTP, and believes the
// client addresses that its trusted peers put in X-Forwarded-For: it is for
// the web server of the node, or of its private network, and must not be
// reachable from anywhere else. Its address is a loopback or a private one;
// the unspecified address, which binds every interface, is not.
func CheckUpstreamBind(ip netip.Addr) error {
	if ip = ip.Unmap(); ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	return fmt.Errorf("an http-upstream listener takes plain HTTP and believes X-Forwarded-For, so it must bind a loopback or private address (%s), not %s",
		upstreamRangeList, ip)
}

// CheckUpstreamTrusted checks a trusted prefix of an http-upstream listener (as
// ParsePrefix returns it): it must lie whole inside the loopback or the private
// ranges. A peer of the prefix is believed when it says who the client is;
// only the web servers of the node, or of its private network, are.
func CheckUpstreamTrusted(p netip.Prefix) error {
	p = p.Masked()
	for _, r := range upstreamRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return nil
		}
	}
	return fmt.Errorf("an http-upstream listener may trust only the loopback or private addresses (%s) of the web servers in front of it, and %s is not inside them",
		upstreamRangeList, p)
}

// ---- members of egress chains --------------------------------------------------

// ParseHostPort splits addr, "host:port", into the host, which is an IP address
// or a name, and the port, which is from 1 to 65535: the address of the proxy
// of a member of an egress chain, or of a Telegram DC that the health check of
// the chains dials. It refuses a host that could not stand in the authority of
// a request, or in a CONNECT line: one with a space or a control character,
// which could end the line and start another, and one with a character of the
// syntax of a URL. Brackets are for an IPv6 address, and an IPv6 address needs
// them. The errors do not quote addr: it is written next to credentials.
func ParseHostPort(addr string) (host string, port uint16, err error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, errors.New("not in the form host:port")
	}
	p, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || p == 0 {
		return "", 0, errors.New("the port is not a number from 1 to 65535")
	}
	if host == "" {
		return "", 0, errors.New("the host is empty")
	}
	for i := range len(host) {
		if c := host[i]; c <= ' ' || c == 0x7f || strings.IndexByte(`/\@#?[]%`, c) >= 0 {
			return "", 0, errors.New("the host has a character that a host cannot have")
		}
	}
	bracketed := strings.HasPrefix(addr, "[")
	if ip, perr := netip.ParseAddr(host); perr == nil {
		if bracketed != ip.Is6() {
			return "", 0, errors.New("brackets are for IPv6 addresses, and IPv6 addresses need them")
		}
	} else if bracketed || strings.Contains(host, ":") {
		return "", 0, errors.New("the host in brackets is not an IPv6 address")
	}
	return host, uint16(p), nil
}

// MaxSOCKS5Credential is the longest user name, and the longest password, of a
// SOCKS5 proxy: the protocol gives each one byte of length (RFC 1929).
const MaxSOCKS5Credential = 255

// CheckSOCKS5Credentials checks the user name and the password of a member of
// kind socks5. The errors never quote them.
func CheckSOCKS5Credentials(username, password string) error {
	if len(username) > MaxSOCKS5Credential {
		return fmt.Errorf("username is longer than %d bytes", MaxSOCKS5Credential)
	}
	if len(password) > MaxSOCKS5Credential {
		return fmt.Errorf("password is longer than %d bytes", MaxSOCKS5Credential)
	}
	return nil
}

// MaxHTTPCredential is the longest user name, and the longest password, of an
// HTTP proxy: the two go in a header of every CONNECT (Basic authentication),
// which a proxy bounds. The panel, the node and the edge hold them to it alike.
const MaxHTTPCredential = 1024

// CheckHTTPCredentials checks the user name and the password of a member of
// kind http: at most MaxHTTPCredential bytes each, and no colon in the user
// name, which Basic authentication joins to the password with one. The errors
// never quote them.
func CheckHTTPCredentials(username, password string) error {
	if len(username) > MaxHTTPCredential {
		return fmt.Errorf("username is longer than %d bytes", MaxHTTPCredential)
	}
	if len(password) > MaxHTTPCredential {
		return fmt.Errorf("password is longer than %d bytes", MaxHTTPCredential)
	}
	if strings.Contains(username, ":") {
		return errors.New("username must not contain a colon")
	}
	return nil
}
