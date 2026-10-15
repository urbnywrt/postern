package telemt

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

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt/overrides"
)

const (
	// configFile is the name of the rendered config in the instance directory.
	configFile = "config.toml"

	// Where the container sees things (see Container).
	binaryMount   = "/opt/engine/telemt"
	instanceMount = "/etc/telemt"
	configMount   = instanceMount + "/" + configFile
	// dataMount is telemt's data_path: it makes the directory the working
	// directory of the process, so every cache telemt keeps (TLS fronts, the
	// proxy secret and config snapshots for the middle proxy, beobachten) lands
	// inside the instance directory, the only writable place besides /tmp.
	dataMount = instanceMount + "/data"

	maxDomainLen = 253
)

// renderFakeTLS writes the telemt config of a fake-TLS proxy.
//
// The file holds exactly what the instance needs and nothing else:
//
//   - telemt listens on two loopback ports only: the proxy port (accepting
//     connections from the edge, with a PROXY protocol header that carries the
//     client's address) and the control API. Nothing else is bound: no
//     [server] port, which would default to 443.
//   - Everything telemt connects to goes out through the edge's SOCKS port: two
//     socks5 upstreams, never a direct one. A request that telemt tags with a
//     scope can only take the second, which lists "me, fetch"; the others take
//     the first. (telemt 3.5.13 was seen to tag the TLS-front fetch "fetch" and
//     nothing else: its middle-proxy connections carry no scope.)
//   - log_level silent, and no startup banner: at any level telemt prints the
//     tg:// link of every user, secret included, and the container log would
//     keep it.
//   - No lookup of its own address, neither with STUN (stun_use = false) nor over
//     HTTP (http_ip_detect_urls = []). By default telemt probes its public address
//     at every start with UDP to 13 public servers and keeps its listeners closed
//     for 5 to 6 s meanwhile; and when that is switched off it falls back to
//     asking the public lookup services of its default list over HTTPS. Both go
//     out directly, around the SOCKS port. The address the middle proxy needs is
//     the agent's to supply (middle_proxy_nat_ip), not telemt's to find out.
//
// The engine overrides of the proxy (package overrides, the whitelist that the
// node and the panel check against as well) are written to [general] and
// [censorship] after the lines above, in the order of the table, and Postern's
// own lines stay as they are: a key that Postern writes is refused as owned. The
// one line that an override may give a value to is tls_emulation, which Postern
// writes as true.
//
// Secrets (the proxy secret, the API token) are written as they are and never
// appear in an error.
func renderFakeTLS(in engines.Instance) ([]byte, error) {
	p := in.Proxy
	if p == nil {
		return nil, errors.New("telemt: no proxy to render")
	}
	if p.GetType() != nodev1.ProxyType_PROXY_TYPE_FAKETLS {
		return nil, fmt.Errorf("telemt: cannot render a %s proxy", p.GetType())
	}
	if e := p.GetEngine(); e != nodev1.Engine_ENGINE_UNSPECIFIED && e != nodev1.Engine_ENGINE_TELEMT {
		return nil, fmt.Errorf("telemt: the proxy is bound to engine %s", e)
	}
	overridden, err := parseOverrides(p.GetEngineOverridesJson())
	if err != nil {
		return nil, err
	}

	if !isHex(p.GetSecret(), 32) {
		return nil, errors.New("telemt: the proxy secret must be exactly 32 hex characters")
	}
	if tag := p.GetAdTag(); tag != "" && !isHex(tag, 32) {
		return nil, errors.New("telemt: the ad tag must be empty or exactly 32 hex characters")
	}
	if err := checkName("proxy domain", p.GetDomain()); err != nil {
		return nil, err
	}
	maskHost, maskPort := p.GetDomain(), 0
	if override := p.GetMaskTargetOverride(); override != "" {
		var err error
		if maskHost, maskPort, err = parseMaskTarget(override); err != nil {
			return nil, err
		}
	}
	// A NAT address only means something to the middle proxy.
	var natIP netip.Addr
	if p.GetUseMiddleProxy() && p.GetNatIp() != "" {
		var err error
		if natIP, err = parseNATIP(p.GetNatIp()); err != nil {
			return nil, err
		}
	}
	if err := checkPorts(in); err != nil {
		return nil, err
	}
	if err := checkToken(in.APIToken); err != nil {
		return nil, err
	}

	var w tomlWriter
	w.table("general")
	w.boolean("use_middle_proxy", p.GetUseMiddleProxy())
	w.str("log_level", "silent")
	w.str("data_path", dataMount)
	if tag := p.GetAdTag(); tag != "" {
		w.str("ad_tag", tag)
	}
	if natIP.IsValid() {
		w.str("middle_proxy_nat_ip", natIP.String())
		// The NAT probe is a STUN exchange over UDP, which a SOCKS port cannot
		// carry: it would go out directly and find the wrong address.
		w.boolean("middle_proxy_nat_probe", false)
	}
	if err := w.writeOverrides(overridden.In(overrides.General)); err != nil {
		return nil, err
	}

	w.table("general.modes")
	w.boolean("classic", false)
	w.boolean("secure", false)
	w.boolean("tls", true)

	w.table("general.links")
	w.strings("show")

	w.table("network")
	w.boolean("stun_use", false)
	w.strings("http_ip_detect_urls")

	w.table("server")
	w.strings("proxy_protocol_trusted_cidrs", "127.0.0.1/32")

	w.array("server.listeners")
	w.str("ip", "127.0.0.1")
	w.integer("port", int(in.ListenPort))
	w.boolean("proxy_protocol", true)

	w.table("server.api")
	w.boolean("enabled", true)
	w.str("listen", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.APIPort))))
	w.strings("whitelist", "127.0.0.1/32")
	w.str("auth_header", in.APIToken)

	w.table("censorship")
	w.str("tls_domain", p.GetDomain())
	w.boolean("mask", true)
	// The line is Postern's, with true as its default: an override of the key gives
	// it its value, and is not written again below.
	tlsEmulation := true
	if v, ok := overridden.Get(tlsEmulationKey); ok {
		tlsEmulation = v.Bool
	}
	w.boolean(tlsEmulationKey, tlsEmulation)
	w.str("mask_host", maskHost)
	if maskPort != 0 {
		w.integer("mask_port", maskPort)
	}
	w.str("tls_fetch_scope", "fetch")
	if err := w.writeOverrides(overridden.In(overrides.Censorship), tlsEmulationKey); err != nil {
		return nil, err
	}

	w.table("access.users")
	w.str("p", p.GetSecret())

	socks := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.SocksPort)))
	w.array("upstreams")
	w.str("type", "socks5")
	w.str("address", socks)
	w.array("upstreams")
	w.str("type", "socks5")
	w.str("address", socks)
	w.str("scopes", "me, fetch")

	return []byte(w.String()), nil
}

// ---- validation ---------------------------------------------------------------

// tlsEmulationKey is the one whitelisted override that Postern writes a line for
// itself (see renderFakeTLS).
const tlsEmulationKey = "tls_emulation"

// parseOverrides reads engine_overrides_json against the whitelist of package
// overrides, which the node and the panel read as well. Empty, "{}" and "null"
// are no overrides. Anything else that is not on the whitelist, or has a value
// outside it, is an error that says every problem, without repeating a value.
func parseOverrides(raw string) (overrides.Set, error) {
	set, problems := overrides.Parse(raw)
	if len(problems) == 0 {
		return set, nil
	}
	msgs := make([]string, len(problems))
	for i, p := range problems {
		msgs[i] = p.Msg
	}
	return nil, errors.New("telemt: " + strings.Join(msgs, "; "))
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

// checkName is the character policy for the domain of a fake-TLS proxy and for a
// mask host. telemt needs a non-empty name without spaces or slashes; on top of
// that nothing is accepted that has no business in a name or that would make the
// config file hard to read for a person (control characters, line breaks, quotes,
// backslashes, bidirectional overrides). Letters of any script are fine: domains
// are used as they are, in UTF-8.
func checkName(what, s string) error {
	switch {
	case s == "":
		return fmt.Errorf("telemt: the %s is empty", what)
	case len(s) > maxDomainLen:
		return fmt.Errorf("telemt: the %s is longer than %d bytes", what, maxDomainLen)
	case !utf8.ValidString(s):
		return fmt.Errorf("telemt: the %s is not valid UTF-8", what)
	}
	for _, r := range s {
		if r == '/' || r == '\\' || r == '"' || unicode.IsSpace(r) || unicode.IsControl(r) || isBidiControl(r) {
			return fmt.Errorf("telemt: the %s %.64q has a character that is not allowed in a name", what, s)
		}
	}
	return nil
}

// isBidiControl reports the characters that reorder the text around them.
func isBidiControl(r rune) bool {
	return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 || r == 0x200E || r == 0x200F || r == 0x061C
}

// parseMaskTarget splits mask_target_override, "host", "host:port", an IP
// address or "[v6]:port", into telemt's mask_host and, when a port is named,
// mask_port (port is 0 otherwise).
func parseMaskTarget(s string) (host string, port int, err error) {
	if a, perr := netip.ParseAddr(s); perr == nil {
		if a.Zone() != "" {
			return "", 0, fmt.Errorf("telemt: the mask target %.64q has an IPv6 zone", s)
		}
		return s, 0, nil
	}
	if h, p, serr := net.SplitHostPort(s); serr == nil {
		n, ok := parsePort(p)
		if !ok {
			return "", 0, fmt.Errorf("telemt: the mask target %.64q has no valid port", s)
		}
		if a, perr := netip.ParseAddr(h); perr == nil {
			if a.Zone() != "" {
				return "", 0, fmt.Errorf("telemt: the mask target %.64q has an IPv6 zone", s)
			}
		} else if err := checkMaskHost(h); err != nil {
			return "", 0, err
		}
		return h, n, nil
	}
	if err := checkMaskHost(s); err != nil {
		return "", 0, err
	}
	return s, 0, nil
}

// checkMaskHost accepts a host name for mask_host: a domain, which cannot hold a
// colon (that would be a port, or an IPv6 address in a form that is not valid
// here) or a bracket.
func checkMaskHost(h string) error {
	if strings.ContainsAny(h, ":[]") {
		return fmt.Errorf("telemt: the mask target host %.64q is neither a name nor an IP address", h)
	}
	return checkName("mask target host", h)
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

// parseNATIP reads the address telemt should present to the middle proxy: a
// usable unicast address, not a loopback, unspecified, link-local or multicast
// one, and without a zone.
func parseNATIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || !a.Unmap().IsGlobalUnicast() {
		return netip.Addr{}, fmt.Errorf("telemt: the NAT address %.64q is not a usable unicast IP address", s)
	}
	return a.Unmap(), nil
}

func checkPorts(in engines.Instance) error {
	for _, p := range []struct {
		what string
		port uint16
	}{{"listen", in.ListenPort}, {"API", in.APIPort}, {"SOCKS", in.SocksPort}} {
		if p.port == 0 {
			return fmt.Errorf("telemt: no %s port", p.what)
		}
	}
	if in.ListenPort == in.APIPort || in.ListenPort == in.SocksPort || in.APIPort == in.SocksPort {
		return errors.New("telemt: the listen, API and SOCKS ports must all be different")
	}
	return nil
}

// checkToken accepts an API token that is safe in an HTTP header and in a TOML
// string without escaping: printable ASCII, no space, no quote, no backslash.
// An empty one is refused because telemt then does not check the header at all.
func checkToken(tok string) error {
	if tok == "" {
		return errors.New("telemt: no API token (telemt would not check the Authorization header)")
	}
	for i := 0; i < len(tok); i++ {
		if c := tok[i]; c <= ' ' || c >= 0x7f || c == '"' || c == '\\' {
			return errors.New("telemt: the API token has a character that is not allowed (use printable ASCII without spaces, quotes or backslashes)")
		}
	}
	return nil
}

// ---- writing TOML -------------------------------------------------------------

// tomlWriter writes the few TOML constructs the config needs, always as plain
// single-line "key = value" pairs under table headers. Every string goes through
// quote, so a value cannot end its string or start a new line, whatever it holds.
type tomlWriter struct {
	b strings.Builder
}

func (w *tomlWriter) String() string { return w.b.String() }

func (w *tomlWriter) header(open, name, closing string) {
	if w.b.Len() > 0 {
		w.b.WriteByte('\n')
	}
	w.b.WriteString(open + name + closing + "\n")
}

func (w *tomlWriter) table(name string) { w.header("[", name, "]") }
func (w *tomlWriter) array(name string) { w.header("[[", name, "]]") }

func (w *tomlWriter) str(key, value string) {
	w.b.WriteString(key + " = " + quote(value) + "\n")
}

func (w *tomlWriter) boolean(key string, value bool) {
	w.b.WriteString(key + " = " + strconv.FormatBool(value) + "\n")
}

func (w *tomlWriter) integer(key string, value int) {
	w.b.WriteString(key + " = " + strconv.Itoa(value) + "\n")
}

// writeOverrides writes engine overrides, each as the line of its kind, except the
// keys in skip, which the caller has written already. A kind that it has no line
// for is an error: a key of the table that is dropped from the config without a
// word would be a setting that an admin made and that does nothing.
func (w *tomlWriter) writeOverrides(values []overrides.Value, skip ...string) error {
	for _, v := range values {
		if slices.Contains(skip, v.Key) {
			continue
		}
		switch v.Kind {
		case overrides.Bool:
			w.boolean(v.Key, v.Bool)
		case overrides.Int:
			w.integer(v.Key, int(v.Int))
		case overrides.Enum, overrides.Dir:
			w.str(v.Key, v.Str)
		default:
			return fmt.Errorf("telemt: engine override %q is of a kind that the renderer has no line for", v.Key)
		}
	}
	return nil
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
// the backslash escaped and every control character written as an escape, so the
// result is a single line that reads back as exactly s. The input must be valid
// UTF-8 (the validators above see to that); anything else is not valid TOML.
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
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
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
