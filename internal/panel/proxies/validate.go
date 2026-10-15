package proxies

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/rules"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/webrules"
)

// This file holds the rules for what admins send (the check functions, whose
// errors are Connect errors of code invalid_argument) and validateState, which
// checks a whole desired state by the rules of the node itself before the
// panel sends it: a node refuses a state as a whole when one part of it is
// wrong, so the panel must never send such a state.

// Limits on what an admin types.
const (
	maxNameChars = 64
	maxNoteChars = 1024
	maxHostLen   = 253 // a DNS name
	maxLabelLen  = 63
	secretHexLen = 32 // 16 bytes
)

func invalid(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

// checkName returns the name of a proxy without the spaces around it: at most
// 64 characters of valid UTF-8 without control characters. It may be empty.
func checkName(s string) (string, error) {
	name := strings.TrimSpace(s)
	switch {
	case !utf8.ValidString(name):
		return "", invalid("name is not valid UTF-8")
	case utf8.RuneCountInString(name) > maxNameChars:
		return "", invalid("name has more than %d characters", maxNameChars)
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return "", invalid("name has a control character")
	}
	return name, nil
}

// checkNote accepts a note of at most 1024 characters of valid UTF-8.
func checkNote(s string) (string, error) {
	switch {
	case !utf8.ValidString(s):
		return "", invalid("note is not valid UTF-8")
	case utf8.RuneCountInString(s) > maxNoteChars:
		return "", invalid("note has more than %d characters", maxNoteChars)
	}
	return s, nil
}

// checkHost returns the host without the spaces around it, if it is an IP
// address or a host name. field names it in the error. It is the rule of the
// link host of a node.
func checkHost(field, s string) (string, error) {
	host := strings.TrimSpace(s)
	if !validHost(host) {
		return "", invalid("%s must be an IP address (IPv6 without brackets) or a host name, without a scheme, port or path", field)
	}
	return host, nil
}

// validHost reports whether host is an IP address without a zone, or a host
// name (see validHostName).
func validHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	return validHostName(host)
}

// validHostName reports whether s is a host name: dot-separated labels of 1 to
// 63 letters, digits and hyphens, which do not start or end with a hyphen, at
// most 253 characters in all, and a last label that is not all digits (that
// would be a mistyped IPv4 address).
func validHostName(s string) bool {
	if s == "" || len(s) > maxHostLen {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !isLetterDigitHyphen(label[i]) {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.ContainsFunc(last, func(r rune) bool { return r < '0' || r > '9' })
}

func isLetterDigitHyphen(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

// checkDomain returns the domain of a proxy without the spaces around it, as it
// is otherwise: a host name of plain ASCII, not an IP address, and without a
// trailing dot. The domain is the server name that the clients of the proxy
// send, and the edge only routes host names. Letter case is kept: the links
// carry the domain as it is stored. Domains are compared in the form in which
// the edge compares server names, state.FoldDomain: two proxies of a listener
// cannot have domains of the same form.
func checkDomain(s string) (string, error) {
	d := strings.TrimSpace(s)
	if !validHostName(d) {
		return "", invalid("domain must be a host name such as www.example.com: letters, digits, hyphens and dots, at most %d characters, no dot at the end", maxHostLen)
	}
	return d, nil
}

// checkBindIP returns the bind address of a listener in its usual form: an
// IPv4 address that a node can listen on, 0.0.0.0 for all of them, which is
// also what empty means. An http-upstream listener takes plain HTTP and
// believes X-Forwarded-For, so its address is a loopback or a private one
// (rules.CheckUpstreamBind), 127.0.0.1 when empty.
func checkBindIP(kind, s string) (string, error) {
	s = strings.TrimSpace(s)
	if kind == store.ListenerKindHTTPUpstream {
		if s == "" {
			s = "127.0.0.1"
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			return "", invalid("bind_ip must be an IPv4 address")
		}
		if err := rules.CheckUpstreamBind(ip); err != nil {
			return "", invalid("bind_ip: %v", err)
		}
		return ip.String(), nil
	}
	if s == "" {
		return "0.0.0.0", nil
	}
	ip, err := netip.ParseAddr(s)
	switch {
	case err != nil:
		return "", invalid("bind_ip must be an IPv4 address")
	case !ip.Is4():
		return "", invalid("bind_ip: IPv6 listeners are not supported")
	case !listenable(ip):
		return "", invalid("bind_ip cannot be listened on: it must be 0.0.0.0, a loopback or a unicast address")
	}
	return ip.String(), nil
}

// listenable reports whether a node can listen on ip.
func listenable(ip netip.Addr) bool {
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsGlobalUnicast()
}

// checkPort accepts a port of 1 to 65535.
func checkPort(p uint32) error {
	if p < 1 || p > 65535 {
		return invalid("port must be 1 to 65535")
	}
	return nil
}

// The loopback ports that a node keeps for its own services: engines, their
// APIs, the SOCKS ports of the edge and of the egresses, and service ports
// (test listeners, http-upstream is not among them). A listener on 0.0.0.0 or
// 127.0.0.1 there, an http-upstream one too, would collide with one of them,
// so the node refuses it (as its state validator does).
const (
	internalPortFirst = 20000
	internalPortLast  = 40999
)

var loopback4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// internalPort reports whether a listener on ip and port would take a port of
// the internal loopback ranges of the node.
func internalPort(ip netip.Addr, port uint32) bool {
	return (ip.IsUnspecified() || ip == loopback4) && port >= internalPortFirst && port <= internalPortLast
}

// checkListenerAddress refuses a bind address (checked by checkBindIP) and a
// port that are in the internal loopback ranges of the node.
func checkListenerAddress(bindIP string, port uint32) error {
	if ip, err := netip.ParseAddr(bindIP); err == nil && internalPort(ip, port) {
		return invalid("port %d on %s is in the internal loopback range of the node, %d-%d: take another port or a specific address",
			port, ip, internalPortFirst, internalPortLast)
	}
	return nil
}

// checkMgmtPort refuses a listener on the management port of its node, where
// its agent listens on every address: the edge could not listen there, and the
// node would fail to apply every state that has the listener. That holds in
// mode hidden too (Ruling S4-7): MgmtPort stays the plain port there, which the
// agent opens again when the panel has not reached it for 15 minutes, and which
// a switch back to mode port needs free.
func checkMgmtPort(n *store.Node, port uint32) error {
	if n.MgmtPort != 0 && port == n.MgmtPort {
		return invalid("port %d is the management port of the node: its agent listens there, on every address", port)
	}
	return nil
}

// checkMaskTarget returns the mask target of a listener without the spaces
// around it: empty, a host, or a host and a port as host:port ([IPv6]:port).
// The edge adds port 443 to a host without one. A target on the internal
// loopback ports of the node is refused: the edge would relay strangers to an
// engine, its API or a SOCKS port of the node.
func checkMaskTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	host, port := s, uint64(443)
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return "", invalid("mask_target: the port must be 1 to 65535")
		}
		host, port = h, n
	}
	if !validHost(host) {
		return "", invalid("mask_target must be a host or host:port")
	}
	if internalTarget(host, port) {
		return "", invalid("mask_target must not be an internal port of the node (%d-%d on the loopback)", internalPortFirst, internalPortLast)
	}
	return s, nil
}

// internalTarget reports whether dialing host and port on a node reaches an
// internal port of the node: a loopback or unspecified address (which Linux
// dials as the host itself), or localhost, on 20000-40999.
func internalTarget(host string, port uint64) bool {
	if port < internalPortFirst || port > internalPortLast {
		return false
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsUnspecified()
}

// checkKind returns the kind of a new listener: tls, which is also what empty
// means, or http-upstream.
func checkKind(s string) (string, error) {
	switch s {
	case "", store.ListenerKindTLS:
		return store.ListenerKindTLS, nil
	case store.ListenerKindHTTPUpstream:
		return store.ListenerKindHTTPUpstream, nil
	}
	return "", invalid("kind must be tls or http-upstream")
}

// maxTrustedCIDRs bounds the trusted CIDRs of a listener.
const maxTrustedCIDRs = 32

// checkTrustedCIDRs returns the trusted CIDRs of a listener of kind, each in
// its masked form (rules.ParsePrefix: a prefix, or a single address as a
// prefix of its whole length), without duplicates. An http-upstream listener
// needs at least one, and each must lie inside the loopback or private
// ranges (rules.CheckUpstreamTrusted): a peer inside them chooses its own
// identity, so they name the web servers in front of the listener only. A
// tls listener has none.
func checkTrustedCIDRs(kind string, cidrs []string) ([]string, error) {
	if kind != store.ListenerKindHTTPUpstream {
		if len(cidrs) > 0 {
			return nil, invalid("trusted_cidrs are for http-upstream listeners only")
		}
		return nil, nil
	}
	if len(cidrs) > maxTrustedCIDRs {
		return nil, invalid("trusted_cidrs: at most %d entries", maxTrustedCIDRs)
	}
	var out []string
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := rules.ParsePrefix(c)
		if err != nil {
			return nil, invalid("trusted_cidrs: %v", err)
		}
		if err := rules.CheckUpstreamTrusted(p); err != nil {
			return nil, invalid("trusted_cidrs: %v", err)
		}
		if s := p.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, invalid("an http-upstream listener needs trusted_cidrs: the addresses of the web servers in front of it, such as 127.0.0.1/32")
	}
	return out, nil
}

// checkProxyType returns the type of a new proxy: faketls, which is also what
// empty means, or web.
func checkProxyType(s string) (string, error) {
	switch s {
	case "", store.ProxyTypeFakeTLS:
		return store.ProxyTypeFakeTLS, nil
	case store.ProxyTypeWeb:
		return store.ProxyTypeWeb, nil
	}
	return "", invalid("type must be faketls or web")
}

// checkWebDomain returns the domain of a WEB proxy as checkDomain does, and
// also makes sure that it names a certificate and a vhost: two labels at
// least (webrules.CertDomain).
func checkWebDomain(s string) (string, error) {
	d, err := checkDomain(s)
	if err != nil {
		return "", err
	}
	if _, err := webrules.CertDomain(d); err != nil {
		return "", invalid("domain: %v", err)
	}
	return d, nil
}

// maxEmailLen bounds the ACME contact.
const maxEmailLen = 254

// checkACMEEmail returns the contact of the ACME account without the spaces
// around it: empty, or something like an address (one @, no spaces or control
// characters), which the CA judges for real.
func checkACMEEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	at := strings.Index(s, "@")
	switch {
	case len(s) > maxEmailLen:
		return "", invalid("acme_email is longer than %d characters", maxEmailLen)
	case at <= 0 || at == len(s)-1 || strings.Count(s, "@") != 1:
		return "", invalid("acme_email must be an email address, or empty")
	case strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }):
		return "", invalid("acme_email has a space or a control character")
	}
	return s, nil
}

// checkStrangerAction returns the stranger action of a listener: mask, which is
// also what empty means, reject or drop.
func checkStrangerAction(s string) (string, error) {
	switch s {
	case "":
		return store.StrangerMask, nil
	case store.StrangerMask, store.StrangerReject, store.StrangerDrop:
		return s, nil
	}
	return "", invalid("stranger_action must be mask, reject or drop")
}

// checkNonTLSAction returns the action of a listener for what is not TLS: drop,
// which is also what empty means, or http400.
func checkNonTLSAction(s string) (string, error) {
	switch s {
	case "":
		return store.NonTLSDrop, nil
	case store.NonTLSDrop, store.NonTLSHTTP400:
		return s, nil
	}
	return "", invalid("non_tls_action must be drop or http400")
}

// checkSecret returns a proxy secret without the spaces around it: exactly 32
// hex digits, in the case they are given in. The error does not quote it.
func checkSecret(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !isHex(s, secretHexLen) {
		return "", invalid("secret must be exactly %d hex digits", secretHexLen)
	}
	return s, nil
}

// checkAdTag returns an ad tag without the spaces around it: empty, or exactly
// 32 hex digits.
func checkAdTag(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s != "" && !isHex(s, secretHexLen) {
		return "", invalid("ad_tag must be empty or exactly %d hex digits", secretHexLen)
	}
	return s, nil
}

// checkMiddleProxy returns the middle-proxy setting of a proxy without the spaces
// around it: auto, on or off. Empty is auto.
func checkMiddleProxy(s string) (string, error) {
	switch s = strings.TrimSpace(s); s {
	case "":
		return store.MiddleProxyAuto, nil
	case store.MiddleProxyAuto, store.MiddleProxyOn, store.MiddleProxyOff:
		return s, nil
	}
	return "", invalid("use_middle_proxy must be auto, on or off")
}

// isHex reports whether s is exactly n hex digits, in either case.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// validID accepts 1 to 64 characters of [A-Za-z0-9._-], starting with a letter
// or a digit: the ids that a node takes (internal/node/state), safe in a
// container name, a label and a path element. ULIDs are such ids.
func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// ---- the rules of the node for a whole state --------------------------------

// errStateRefused marks the error of validateState.
var errStateRefused = errors.New("the node would refuse its state")

// stateError lists every problem that the node would find in a state, in the
// node's words. Its text never holds a secret, an ad tag or the parameters of
// an egress: the node's messages quote none of them.
type stateError struct {
	problems []string
}

func (e *stateError) Error() string {
	return errStateRefused.Error() + ": " + strings.Join(e.problems, "; ")
}

func (e *stateError) Unwrap() error { return errStateRefused }

// validateState checks a desired state by the rules of the node itself:
// state.Validate, which a node applies to every state that it is given before
// it takes it, with the rules of its edge among them (mask targets, trusted
// CIDRs, the members of egress chains, as the edge parses them) and the
// whitelist of engine overrides that the telemt driver renders from
// (internal/engines/telemt/overrides, with the ranges of the values and none
// of the keys that Postern owns). A node refuses a state as a whole when one
// part of it is wrong, so the panel never sends one that it would refuse.
// There is one validator of a state, so the two cannot drift apart.
//
// What the panel knows and the node cannot is checked elsewhere: the rows
// that a state is made of, where it is made (assemble refuses a stored value
// that this version does not know, rather than send it as not set), and what
// an admin asks for, where it is asked (the check functions of this file, and
// the checks of the services against the other rows of the panel, such as the
// management port of the node).
//
// It returns nil or a *stateError with every problem found.
func validateState(st *nodev1.NodeState) error {
	err := state.Validate(st, enginesSupport)
	var ve *state.ValidationError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ve):
		return &stateError{problems: ve.Problems}
	}
	return &stateError{problems: []string{err.Error()}}
}

// enginesSupport says which proxies an engine serves, as the engine drivers of
// a node of this version say it when the node validates a state: fake-TLS and
// WEB proxies on telemt (internal/engines/telemt), and fake-TLS proxies on mtg
// (internal/engines/mtg, on a node with the capability engine-mtg), which is
// all that the panel makes.
func enginesSupport(e nodev1.Engine, t nodev1.ProxyType) bool {
	switch e {
	case nodev1.Engine_ENGINE_TELEMT:
		return t == nodev1.ProxyType_PROXY_TYPE_FAKETLS || t == nodev1.ProxyType_PROXY_TYPE_WEB
	case nodev1.Engine_ENGINE_MTG:
		return t == nodev1.ProxyType_PROXY_TYPE_FAKETLS
	}
	return false
}
