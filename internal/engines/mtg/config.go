package mtg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/netpolicy"
)

// ErrOverridesUnsupported is returned by Render for a proxy whose
// engine_overrides_json is not empty: the overrides are telemt's, and mtg
// takes none.
var ErrOverridesUnsupported = errors.New("engine overrides are not supported by mtg")

const (
	// configFile is the name of the rendered config in the instance directory.
	configFile = "config.toml"

	// Where the container sees things (see Container).
	binaryMount   = "/opt/engine/mtg"
	instanceMount = "/etc/mtg"
	configMount   = instanceMount + "/" + configFile

	maxDomainLen = 253

	// tolerateTimeSkewness is how far off the clock of a client may be. A
	// fake-TLS ClientHello carries the client's time, and both engines refuse a
	// hello whose time is too far from their own:
	//
	//   - telemt 3.5.13 accepts now - time within [TIME_SKEW_MIN, TIME_SKEW_MAX]
	//     = [-2 min, +2 min] (src/protocol/tls.rs, the constants; checked in
	//     src/proxy/handshake/tls_auth.rs; ignore_time_skew is false, the
	//     default, in the telemt driver's config);
	//   - mtg v2.2.8 accepts |now - time| <= tolerate-time-skewness
	//     (mtglib/internal/tls/fake/client_side.go), 3 s by default and 5 s in
	//     its example config.
	//
	// Two minutes for mtg too, so that a switch between the engines keeps out no
	// client whose clock is off. (telemt also lets in a time below 120, from
	// clients that send their uptime instead; mtg has no setting for that.)
	tolerateTimeSkewness = "2m"
)

// FrontingPort is the port of the fronting target of a proxy whose mask target
// override names none, and of the proxy domain: HTTPS.
const FrontingPort = 443

// renderFakeTLS writes the mtg config of a fake-TLS proxy.
//
// The file holds what the instance needs, in the order and with the values of
// the plan (Task 4), and nothing else:
//
//   - mtg listens on two loopback ports only: the proxy port, with the PROXY
//     protocol (v1 and v2), and the Prometheus statistics, which Ready reads.
//   - Its only proxy is the edge's SOCKS port, so its connections to Telegram
//     go through the edge. Its fronting connections do not (see the package
//     documentation): they go to the fronting address that the agent passes,
//     Instance.FrontingAddr, which [domain-fronting] always names, ip and
//     port, once frontingAddr has held it to the edge's destination policy.
//     mtg never resolves or picks its fronting target itself (Ruling S5-10).
//   - dns = "" leaves name resolution to the resolver of the container (mtg
//     drops the empty string while it reads the file, and builds a caching
//     resolver on the system's configuration: /etc/resolv.conf). With the
//     fronting address named, mtg has no name to resolve: the addresses of
//     Telegram are built in, and its proxy is an address.
//   - Nothing that would make mtg reach out on its own: no block list (on by
//     default in mtg's example, F7), no allow list, no doppelganger URLs, no
//     auto-update, no statsd.
//   - debug = false: mtg logs at the warning level then, and its configuration,
//     secret included, only at the debug level.
//
// What mtg cannot do is refused: other proxy types, the promo tag, the middle
// proxy and its NAT address, engine overrides, a mask target that is not a
// public IP address, and an instance without a public fronting address that
// agrees with the mask target. Secrets never appear in an error.
func renderFakeTLS(in engines.Instance) ([]byte, error) {
	p := in.Proxy
	if p == nil {
		return nil, errors.New("mtg: no proxy to render")
	}
	if p.GetType() != nodev1.ProxyType_PROXY_TYPE_FAKETLS {
		return nil, fmt.Errorf("mtg: cannot serve a %s proxy: mtg serves fake TLS only", p.GetType())
	}
	if e := p.GetEngine(); e != nodev1.Engine_ENGINE_UNSPECIFIED && e != nodev1.Engine_ENGINE_MTG {
		return nil, fmt.Errorf("mtg: the proxy is bound to engine %s", e)
	}
	if p.GetAdTag() != "" {
		return nil, errors.New("mtg: mtg has no promo (ad) tag: remove the ad tag or keep telemt")
	}
	if p.GetUseMiddleProxy() {
		return nil, errors.New("mtg: mtg has no middle proxy: turn the middle proxy off or keep telemt")
	}
	if p.GetNatIp() != "" {
		return nil, errors.New("mtg: a NAT address is a setting of the middle proxy, which mtg does not have: remove it or keep telemt")
	}
	if err := checkOverrides(p.GetEngineOverridesJson()); err != nil {
		return nil, err
	}
	if err := checkSecret(p.GetSecret()); err != nil {
		return nil, err
	}
	if err := checkName("proxy domain", p.GetDomain()); err != nil {
		return nil, err
	}
	front, err := frontingAddr(in.FrontingAddr, p.GetMaskTargetOverride())
	if err != nil {
		return nil, err
	}
	if err := checkPorts(in); err != nil {
		return nil, err
	}

	var w tomlWriter
	w.boolean("debug", false)
	// The secret of the link, byte for byte: "ee", the secret as it is stored,
	// the lower-case hex of the UTF-8 domain. mtg reads the domain back out of it
	// and wants it as the server name of a client's hello.
	w.str("secret", links.FakeTLSSecret(p.GetSecret(), p.GetDomain()))
	w.str("bind-to", loopback(in.ListenPort))
	w.boolean("proxy-protocol-listener", true)
	w.integer("concurrency", 8192)
	w.str("prefer-ip", "prefer-ipv4")
	w.boolean("auto-update", false)
	w.str("tolerate-time-skewness", tolerateTimeSkewness)
	w.boolean("allow-fallback-on-unknown-dc", false)

	// Always both: without ip mtg would resolve the proxy domain itself and
	// connect, from the node, to whatever the answer is.
	w.table("domain-fronting")
	w.str("ip", front.Addr().String())
	w.integer("port", int(front.Port()))

	w.table("network")
	w.str("dns", "")
	w.strings("proxies", "socks5://"+loopback(in.SocksPort))

	// As in mtg v2.2.8's example config.
	w.table("network.timeout")
	w.str("tcp", "5s")
	w.str("http", "10s")
	w.str("idle", "5m")
	w.str("handshake", "10s")

	w.table("defense.anti-replay")
	w.boolean("enabled", true)

	w.table("defense.blocklist")
	w.boolean("enabled", false)

	w.table("defense.allowlist")
	w.boolean("enabled", false)

	w.table("defense.doppelganger")
	w.strings("urls")

	w.table("stats.statsd")
	w.boolean("enabled", false)

	w.table("stats.prometheus")
	w.boolean("enabled", true)
	w.str("bind-to", loopback(in.APIPort))
	w.str("http-path", "/")
	w.str("metric-prefix", "mtg")

	return []byte(w.String()), nil
}

// ---- validation ---------------------------------------------------------------

// checkOverrides accepts an empty engine_overrides_json (also "{}" and "null"),
// and refuses any key: manual engine parameters are not supported.
func checkOverrides(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return errors.New("mtg: engine_overrides_json is not a JSON object")
	}
	if len(m) > 0 {
		return fmt.Errorf("mtg: %w", ErrOverridesUnsupported)
	}
	return nil
}

// checkSecret accepts 32 hex digits in either case, the secret as the link has
// it, and refuses 32 zeros: mtg does not start with a key of zeros
// (mtglib.Secret.Valid), and prints the whole secret when it says so.
func checkSecret(s string) error {
	if !isHex(s, 32) {
		return errors.New("mtg: the proxy secret must be exactly 32 hex characters")
	}
	if strings.Trim(s, "0") == "" {
		return errors.New("mtg: the proxy secret is all zeros, which mtg does not start with")
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// checkName is the character policy for the domain of a fake-TLS proxy, the
// same as the telemt driver's, so that a domain one engine takes the other
// takes as well: not empty, at most 253 bytes of UTF-8, and nothing that has no
// business in a name (white space, control characters, slashes, quotes,
// backslashes, bidirectional controls). Letters of any script are fine: mtg
// gets the domain as UTF-8 bytes inside the secret.
func checkName(what, s string) error {
	switch {
	case s == "":
		return fmt.Errorf("mtg: the %s is empty", what)
	case len(s) > maxDomainLen:
		return fmt.Errorf("mtg: the %s is longer than %d bytes", what, maxDomainLen)
	case !utf8.ValidString(s):
		return fmt.Errorf("mtg: the %s is not valid UTF-8", what)
	}
	for _, r := range s {
		if r == '/' || r == '\\' || r == '"' || unicode.IsSpace(r) || unicode.IsControl(r) || isBidiControl(r) {
			return fmt.Errorf("mtg: the %s %.64q has a character that is not allowed in a name", what, s)
		}
	}
	return nil
}

// isBidiControl reports the characters that reorder the text around them.
func isBidiControl(r rune) bool {
	return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 || r == 0x200E || r == 0x200F || r == 0x061C
}

// ParseMaskTarget reads a proxy's mask_target_override the way mtg takes it:
// an IP address, with or without a port (FrontingPort when it names none), as
// in 192.0.2.10, 192.0.2.10:8443, 2001:db8::10, [2001:db8::10]:8443. An IPv4
// address in the form of IPv6 comes back as IPv4. It refuses an empty
// override, a host name (mtg v2.2.8 fronts to an IP address only: its
// [domain-fronting] has no key for a name, F6), a zone, a bad port, and an
// address that is not public (see nonPublic).
//
// For a proxy with an override, the agent passes what this returns as
// Instance.FrontingAddr, and Render checks that the two agree.
func ParseMaskTarget(s string) (netip.AddrPort, error) {
	if s == "" {
		return netip.AddrPort{}, errors.New("mtg: no mask target")
	}
	host, port := s, FrontingPort
	if _, err := netip.ParseAddr(s); err != nil {
		h, p, serr := net.SplitHostPort(s)
		if serr != nil {
			return netip.AddrPort{}, notAnIP(s)
		}
		n, ok := parsePort(p)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("mtg: the mask target %.64q has no valid port", s)
		}
		host, port = h, n
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, notAnIP(s)
	}
	if a.Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("mtg: the mask target %.64q has an IPv6 zone", s)
	}
	a = a.Unmap()
	if kind := nonPublic(a); kind != "" {
		return netip.AddrPort{}, fmt.Errorf("mtg: the mask target %s is not a public address (%s): mtg would connect to it directly from the node", a, kind)
	}
	return netip.AddrPortFrom(a, uint16(port)), nil
}

// frontingAddr checks the fronting address that the agent passes (Ruling
// S5-10) and returns it with an IPv4 address in the form of IPv6 as IPv4. It
// has to be an IP address and a port that the edge's destination policy lets
// an engine connect to, and the mask target override's address and port when
// the proxy has one, or else an address of the proxy domain on FrontingPort.
// Without it, mtg would resolve the domain itself and connect to whatever the
// answer is; so Render refuses rather than leave the choice to mtg. An
// override that mtg cannot take is refused first, with what is wrong with it.
func frontingAddr(addr netip.AddrPort, override string) (netip.AddrPort, error) {
	var want netip.AddrPort
	if override != "" {
		var err error
		if want, err = ParseMaskTarget(override); err != nil {
			return netip.AddrPort{}, err
		}
	}
	a := addr.Addr()
	switch {
	case !a.IsValid():
		return netip.AddrPort{}, errors.New("mtg: no fronting address: the agent passes the address of the mask target, or one of the proxy domain that it resolved, and mtg must not resolve or pick it itself")
	case a.Zone() != "":
		return netip.AddrPort{}, fmt.Errorf("mtg: the fronting address %s has an IPv6 zone", addr)
	case addr.Port() == 0:
		return netip.AddrPort{}, fmt.Errorf("mtg: the fronting address %s has no port", a)
	}
	addr = netip.AddrPortFrom(a.Unmap(), addr.Port())
	if kind := nonPublic(addr.Addr()); kind != "" {
		return netip.AddrPort{}, fmt.Errorf("mtg: the fronting address %s is not a public address (%s): mtg would connect to it directly from the node", addr, kind)
	}
	switch {
	case want.IsValid() && addr != want:
		return netip.AddrPort{}, fmt.Errorf("mtg: the fronting address %s is not the mask target override's, %s", addr, want)
	case !want.IsValid() && addr.Port() != FrontingPort:
		return netip.AddrPort{}, fmt.Errorf("mtg: the fronting address %s of the proxy domain is not on port %d", addr, FrontingPort)
	}
	return addr, nil
}

func notAnIP(s string) error {
	return fmt.Errorf("mtg: the mask target %.64q is not an IP address: mtg v2.2.8 fronts to an IP address only", s)
}

// parsePort reads a decimal port, 1 to 65535, with nothing else around it.
func parsePort(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// nonPublic says what kind of address a is when it is not one mtg may front
// to, and returns "" for a public address. mtg connects to its fronting target
// directly from the node (see the package documentation), so a target on the
// node's loopback or in the networks around it would be reached from outside
// through the proxy port. It applies to a mask target override and to the
// fronting address alike.
//
// It is the destination policy that the edge's SOCKS ports apply to the
// engines' connections (egress.DestinationAllowed), netpolicy.NonPublic: no
// loopback, private (RFC 1918, unique local), link-local, multicast,
// unspecified, "this network", broadcast or carrier-grade NAT address, nothing
// that is not an address at all, and an IPv6 address that carries an IPv4
// address is judged as that address. The tests keep the two in step.
func nonPublic(a netip.Addr) string { return netpolicy.NonPublic(a) }

func checkPorts(in engines.Instance) error {
	for _, p := range []struct {
		what string
		port uint16
	}{{"listen", in.ListenPort}, {"statistics (API)", in.APIPort}, {"SOCKS", in.SocksPort}} {
		if p.port == 0 {
			return fmt.Errorf("mtg: no %s port", p.what)
		}
	}
	if in.ListenPort == in.APIPort || in.ListenPort == in.SocksPort || in.APIPort == in.SocksPort {
		return errors.New("mtg: the listen, statistics and SOCKS ports must all be different")
	}
	return nil
}

// ---- writing TOML -------------------------------------------------------------

// tomlWriter writes the few TOML constructs the config needs: one-line
// "key = value" pairs at the top and under table headers. Every string goes
// through quote, so a value cannot end its string or start a new line.
type tomlWriter struct {
	b strings.Builder
}

func (w *tomlWriter) String() string { return w.b.String() }

func (w *tomlWriter) table(name string) {
	if w.b.Len() > 0 {
		w.b.WriteByte('\n')
	}
	w.b.WriteString("[" + name + "]\n")
}

func (w *tomlWriter) str(key, value string) {
	w.b.WriteString(key + " = " + quote(value) + "\n")
}

func (w *tomlWriter) boolean(key string, value bool) {
	w.b.WriteString(key + " = " + strconv.FormatBool(value) + "\n")
}

func (w *tomlWriter) integer(key string, value int) {
	w.b.WriteString(key + " = " + strconv.Itoa(value) + "\n")
}

// strings writes an array of strings; none gives an empty array.
func (w *tomlWriter) strings(key string, values ...string) {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = quote(v)
	}
	w.b.WriteString(key + " = [" + strings.Join(quoted, ", ") + "]\n")
}

// quote returns s as a TOML basic string: in double quotes, with the quote and
// the backslash escaped and every control character written as an escape, so
// the result is a single line that reads back as exactly s. Every value the
// config holds is checked or made by the driver (hex, IP addresses, port
// numbers, fixed words); quote is the second line of defence.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
