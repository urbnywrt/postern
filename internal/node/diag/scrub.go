package diag

import (
	"cmp"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/node/state"
)

// Redacted stands for a secret, RedactedIP for a client address.
const (
	Redacted   = "***"
	RedactedIP = "<ip>"
)

// minSecret is the shortest value taken out as a secret: shorter ones would
// cut ordinary words out of the text.
const minSecret = 8

// The addresses the IP redactor keeps whatever the state says: the node's own
// service addresses (the engines' and the DNS forwarder's loopback), the
// datacenters of Telegram and the DoH endpoints.
var (
	serviceAddrs = []netip.Addr{
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.IPv6Loopback(),
	}
	// dcPrefixes are the networks of Telegram's datacenters (AS62041,
	// AS59930, AS62014, AS211157, AS44907).
	dcPrefixes = []netip.Prefix{
		netip.MustParsePrefix("149.154.160.0/20"), netip.MustParsePrefix("91.108.4.0/22"),
		netip.MustParsePrefix("91.108.8.0/22"), netip.MustParsePrefix("91.108.12.0/22"),
		netip.MustParsePrefix("91.108.16.0/22"), netip.MustParsePrefix("91.108.20.0/22"),
		netip.MustParsePrefix("91.108.56.0/22"), netip.MustParsePrefix("91.105.192.0/23"),
		netip.MustParsePrefix("95.161.64.0/20"), netip.MustParsePrefix("185.76.151.0/24"),
		netip.MustParsePrefix("2001:b28:f23c::/46"), netip.MustParsePrefix("2001:67c:4e8::/48"),
		netip.MustParsePrefix("2a0a:f280::/32"),
	}
)

// Scrubber takes secrets and client addresses out of text (Global
// Constraints, Diagnostics): proxy secrets in every form a link or a log
// writes them, ad tags, engine API tokens, egress parameter values, WARP
// tokens and DNS credentials become ***; every IP literal that is not one of
// the node's service addresses, its public IPs, a DC address, a DoH endpoint
// or an egress member's address becomes <ip>.
type Scrubber struct {
	secrets *regexp.Regexp // nil: none
	keep    map[netip.Addr]bool
}

// NewScrubber makes the scrubber of the desired state st and the runtime
// record rt (either may be nil). keep are more addresses to keep: the node's
// public IPs.
func NewScrubber(st *nodev1.NodeState, rt *state.Runtime, keep []netip.Addr) *Scrubber {
	s := &Scrubber{keep: map[netip.Addr]bool{}}
	for _, a := range serviceAddrs {
		s.keep[a] = true
	}
	for _, a := range keep {
		s.keep[a.Unmap()] = true
	}
	for _, e := range doh.DefaultEndpoints {
		if u, err := url.Parse(e); err == nil {
			if a, err := netip.ParseAddr(u.Hostname()); err == nil {
				s.keep[a] = true
			}
		}
	}
	var b secretSet
	for _, p := range st.GetProxies() {
		b.proxySecret(p.GetSecret(), p.GetDomain())
		b.add(p.GetAdTag())
		if w := p.GetWeb(); w != nil {
			b.value(w.GetDnsCredential())
		}
	}
	for _, c := range st.GetChains() {
		for _, dc := range c.GetCheck().GetDcAddrs() {
			s.keepLiteral(dc)
		}
	}
	for _, e := range st.GetEgresses() {
		for _, v := range jsonStrings(e.GetParamsJson()) {
			if s.keepLiteral(v) {
				continue // a member's address
			}
			if u, err := url.Parse(v); err == nil && u.Host != "" {
				s.keepLiteral(u.Hostname())
			}
			b.value(v)
		}
	}
	if rt != nil {
		for _, in := range rt.Instances {
			b.add(in.APIToken)
		}
		for _, e := range rt.Egresses {
			b.value(e.SubscriptionURL)
		}
	}
	s.secrets = b.compile()
	return s
}

// WithSecrets returns a scrubber that also takes out values (WARP tokens and
// keys, which the agent reads from the egresses' account files).
func (s *Scrubber) WithSecrets(values ...string) *Scrubber {
	var b secretSet
	if s.secrets != nil {
		b.raw = append(b.raw, s.secrets.String())
	}
	for _, v := range values {
		b.value(v)
	}
	return &Scrubber{secrets: b.compile(), keep: s.keep}
}

// blindPattern is what Strict takes out besides the known secrets: every run
// of 22 or more characters of the base64 (std or url) alphabet, which holds
// every hex and base64 form of a 16-byte secret and of longer tokens.
const blindPattern = `[A-Za-z0-9+/_-]{22,}={0,2}`

// Strict returns a scrubber that also takes out whatever may be a secret
// (blindPattern), for text some of whose secrets could not be read: it takes
// out more than it must rather than let one through.
func (s *Scrubber) Strict() *Scrubber {
	if s == nil {
		s = NewScrubber(nil, nil, nil)
	}
	b := secretSet{raw: []string{blindPattern}}
	if s.secrets != nil {
		b.raw = append([]string{s.secrets.String()}, b.raw...)
	}
	return &Scrubber{secrets: b.compile(), keep: s.keep}
}

// withKeep returns a scrubber that also keeps the address a.
func (s *Scrubber) withKeep(a netip.Addr) *Scrubber {
	out := &Scrubber{keep: map[netip.Addr]bool{a.Unmap(): true}}
	if s == nil {
		for _, k := range serviceAddrs {
			out.keep[k] = true
		}
		return out
	}
	out.secrets = s.secrets
	for k := range s.keep {
		out.keep[k] = true
	}
	return out
}

// keepLiteral keeps the address of v, an IP or an IP and a port, and reports
// whether v was one.
func (s *Scrubber) keepLiteral(v string) bool {
	v = strings.TrimSpace(v)
	if ap, err := netip.ParseAddrPort(v); err == nil {
		s.keep[ap.Addr().Unmap()] = true
		return true
	}
	if a, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
		s.keep[a.Unmap()] = true
		return true
	}
	return false
}

// Clean returns text without secrets and client addresses. A nil scrubber
// redacts every address but the service ones and takes no secret out.
func (s *Scrubber) Clean(text string) string {
	if s == nil {
		s = NewScrubber(nil, nil, nil)
	}
	if s.secrets != nil {
		text = s.secrets.ReplaceAllLiteralString(text, Redacted)
	}
	return s.redactIPs(text)
}

// ---- secrets ----------------------------------------------------------------------

// secretSet collects the needles of the scrubber: literal ones (case
// sensitive: base64 and free text) and hexadecimal ones (any letter case).
type secretSet struct {
	lit, hex []string
	raw      []string // alternations of an earlier scrubber
}

func (b *secretSet) add(v string) {
	if len(v) < minSecret {
		return
	}
	if isHex(v) {
		b.hex = append(b.hex, strings.ToLower(v))
		return
	}
	b.lit = append(b.lit, v)
}

// value adds a free-form secret value, and its parts when it is a URL (the
// user and the password, the query values) or JSON (its strings).
func (b *secretSet) value(v string) {
	if len(v) < minSecret {
		return
	}
	b.add(v)
	if strings.HasPrefix(strings.TrimSpace(v), "{") || strings.HasPrefix(strings.TrimSpace(v), "[") {
		for _, s := range jsonStrings(v) {
			b.add(s)
		}
		return
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" {
		return
	}
	if u.User != nil {
		b.add(u.User.Username())
		pw, _ := u.User.Password()
		b.add(pw)
	}
	for _, vs := range u.Query() {
		for _, q := range vs {
			b.add(q)
		}
	}
	b.add(u.Fragment)
	if u.RawQuery != "" {
		b.add(u.RawQuery)
	}
}

// proxySecret adds a proxy secret (hex, 16 bytes) in every form it is written:
// hex, the fake-TLS link secret ("ee" + secret + hex(domain)) in hex and in
// base64, base64 std and url with and without padding, and the WEB forms ("dd"
// + hex, base64url_nopad(0x70‖secret), base64url_nopad(0x70‖0xdd‖secret)).
func (b *secretSet) proxySecret(secretHex, domain string) {
	if secretHex == "" {
		return
	}
	b.add(secretHex)
	b.add("dd" + secretHex)
	raw, err := hex.DecodeString(secretHex)
	if err != nil || len(raw) == 0 {
		return
	}
	ee := links.FakeTLSSecret(strings.ToLower(secretHex), domain)
	b.add(ee)
	eeRaw, _ := hex.DecodeString(ee)
	for _, data := range [][]byte{raw, eeRaw, append([]byte{0xdd}, raw...), append([]byte{0x70}, raw...), append([]byte{0x70, 0xdd}, raw...)} {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			b.add(enc.EncodeToString(data))
		}
	}
}

// compile makes one regular expression of the needles, the longest first, so
// that a longer form is taken out whole before a shorter one inside it.
func (b *secretSet) compile() *regexp.Regexp {
	byLen := func(a, c string) int { return cmp.Or(cmp.Compare(len(c), len(a)), strings.Compare(a, c)) }
	slices.SortFunc(b.lit, byLen)
	slices.SortFunc(b.hex, byLen)
	b.lit, b.hex = slices.Compact(b.lit), slices.Compact(b.hex)
	var parts []string
	if len(b.hex) > 0 {
		q := make([]string, len(b.hex))
		for i, h := range b.hex {
			q[i] = regexp.QuoteMeta(h)
		}
		parts = append(parts, "(?i:"+strings.Join(q, "|")+")")
	}
	for _, l := range b.lit {
		parts = append(parts, regexp.QuoteMeta(l))
	}
	parts = append(parts, b.raw...)
	if len(parts) == 0 {
		return nil
	}
	return regexp.MustCompile(strings.Join(parts, "|"))
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// jsonStrings are the strings of a JSON document, keys aside, at any depth;
// none when raw is not JSON.
func jsonStrings(raw string) []string {
	var v any
	if raw == "" || json.Unmarshal([]byte(raw), &v) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// ---- IP redactor ------------------------------------------------------------------

// ipCandidate finds what may be an IP literal: dotted IPv4, or a run of hex
// digits and colons with at least two colons, possibly ending in a dotted
// IPv4 (v4-mapped), possibly with a zone.
var ipCandidate = regexp.MustCompile(`(?i)[0-9a-f]*:[0-9a-f:]*:(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]*)(?:%[0-9a-z_.-]+)?|\d{1,3}(?:\.\d{1,3}){3}`)

func (s *Scrubber) redactIPs(text string) string {
	locs := ipCandidate.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return text
	}
	var out strings.Builder
	last := 0
	for _, loc := range locs {
		i, j := loc[0], loc[1]
		// The candidate, then its suffixes after each colon, longest first: a
		// label and a colon before an IPv6 address ("from:2001:db8::1") make
		// a candidate that is no address, while its suffix is one. The first
		// that is an address decides: redacted, or kept whole.
		for start := i; start < j; start++ {
			if start > i && text[start-1] != ':' {
				continue
			}
			v := s.classify(text, start, j)
			if v == notAddr {
				continue
			}
			if v == redactAddr {
				out.WriteString(text[last:start])
				out.WriteString(RedactedIP)
				last = j
			}
			break
		}
	}
	if last == 0 {
		return text
	}
	out.WriteString(text[last:])
	return out.String()
}

// What classify finds a candidate to be.
const (
	notAddr = iota
	keepAddr
	redactAddr
)

// classify tells whether text[i:j] is an address to redact: a literal on its
// own (not a part of a longer word or version number) that is not kept.
func (s *Scrubber) classify(text string, i, j int) int {
	if i > 0 && (wordByte(text[i-1]) || text[i-1] == '.') {
		return notAddr
	}
	if j < len(text) && wordByte(text[j]) {
		return notAddr
	}
	if j+1 < len(text) && text[j] == '.' && isDigit(text[j+1]) {
		return notAddr // a version number with more parts
	}
	a, err := netip.ParseAddr(text[i:j])
	if err != nil {
		return notAddr
	}
	return s.classifyAddr(a)
}

// classifyAddr tells whether an address is kept or redacted.
func (s *Scrubber) classifyAddr(a netip.Addr) int {
	a = a.WithZone("").Unmap()
	if a.IsUnspecified() || s.keep[a] {
		return keepAddr
	}
	for _, p := range dcPrefixes {
		if p.Contains(a) {
			return keepAddr
		}
	}
	return redactAddr
}

func wordByte(c byte) bool {
	return isDigit(c) || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_'
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isHexDigit(c byte) bool {
	return isDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}
