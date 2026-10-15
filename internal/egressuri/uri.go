// Package egressuri parses the share links that describe proxy servers
// (vless://, vmess://, trojan:// and ss://) and the subscriptions that list
// them.
//
// Parse reads one link and ParseSubscription a whole subscription body. Both
// return Server values, and neither touches the network.
//
// A link holds credentials, so an error of this package never repeats the link,
// a credential or any other text taken from it. It names the scheme and the
// field that is wrong, and nothing more. The one exception is the scheme of a
// link this package cannot read, which is named when it is short and looks like
// a scheme.
package egressuri

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Protocol names, as Server.Protocol carries them.
const (
	protoVLESS  = "vless"
	protoVMess  = "vmess"
	protoTrojan = "trojan"
	protoSS     = "shadowsocks"
)

// defaultPort is the port of a vless or trojan link that has none.
const defaultPort = 443

// utf8BOM is the byte order mark that some editors and servers put in front of
// a text.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Server is one proxy server as a share link describes it.
//
// A Server that Parse returns always has a Protocol, an Address, a Port other
// than 0, a Network and a Security from the lists below, and what its protocol
// authenticates with: an ID (vless, vmess), a Password (trojan) or a Method and
// a Password (shadowsocks). Every string is valid UTF-8 without control
// characters. A field that the link does not set is empty, except for Network
// and Security, which default to tcp and none (tls for trojan).
//
// A Server holds credentials, so it does not print them: String, GoString and
// LogValue show the Key, the Protocol and the Name and nothing else. That makes
// fmt (%v, %+v, %#v and %s, so also the errors and messages built with them) and
// slog (its text and JSON handlers) safe for a Server and for a *Server, and fmt
// and the text handler of slog safe for slices and maps of them and for exported
// struct fields that hold them. These are not covered, so log Key() and a count
// there:
//   - encoding/json marshals every field (the members of an egress are saved
//     that way, so Server has no MarshalJSON), and so does slog's JSON handler
//     for a slice, a map or a struct that holds servers;
//   - fmt cannot call methods on an unexported struct field, so a Server held
//     by value in one prints in full, and a verb that is invalid for a struct
//     (%d, %t and the like, which go vet reports) dumps the fields;
//   - a nil *Server given to slog makes LogValue panic: slog recovers, and logs
//     the panic with its stack trace in place of the server (fmt prints <nil>).
type Server struct {
	Protocol string // vless | vmess | trojan | shadowsocks
	Name     string // fragment (#name), URL-decoded; the "ps" of a vmess link
	Address  string // host name or IP literal as the link wrote it; an IPv6 address has no brackets
	Port     uint16
	ID       string // vless/vmess uuid
	Password string // trojan / shadowsocks
	Method   string // shadowsocks cipher; the "scy" of a vmess link, empty when it has none
	Flow     string // vless flow, e.g. xtls-rprx-vision
	Network  string // tcp | ws | grpc | xhttp | httpupgrade
	Security string // none | tls | reality

	// The transport and TLS settings, as the link spells them. A vmess link
	// keeps the service name of grpc in its "path"; it is returned in
	// ServiceName and Path stays empty.
	SNI, Fingerprint, PublicKey, ShortID, SpiderX, Path, Host, ServiceName, Mode, ALPN string

	Extra         string // xhttp "extra" JSON, raw
	AllowInsecure bool
}

// Key returns a stable name for the server: the first 12 hex digits of the
// SHA-256 of "protocol|address|port|id", where the id is the uuid of a vless or
// vmess server and empty for the others. An egress names the members of a
// subscription by it, so that they keep their ports when the subscription is
// refreshed. Everything else, the name and the transport and TLS settings
// included, can change without making another server.
//
// The password is not part of it. Keys are logged everywhere, and an unsalted
// hash of a password would let anyone who reads a log guess a weak one offline.
// So a trojan or shadowsocks server is named by its address and port alone, and
// two accounts on one address and port are one member. The id of a vless or vmess
// server is hashed as it is, which is safe for a random uuid and not for the
// short custom ids that Xray also accepts.
//
// The address is folded first, so that two spellings of one address name one
// server: ASCII upper case in a host name becomes lower case (other characters
// are left alone), and an IP address is written the way netip writes it, an IPv6
// address in lower case and compressed. HOST.example.com and host.example.com,
// 2001:DB8::1 and 2001:db8:0::1, have the same key. Address itself is not changed.
func (s *Server) Key() string {
	in := s.Protocol + "|" + foldAddress(s.Address) + "|" + strconv.FormatUint(uint64(s.Port), 10) + "|" + s.ID
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:6])
}

// foldAddress is the address as Key uses it, see there.
func foldAddress(address string) string {
	if ip, err := netip.ParseAddr(address); err == nil {
		return ip.String()
	}
	return asciiLower(address)
}

// asciiLower turns the ASCII upper-case letters of s into lower case and leaves
// every other byte alone: host names are case-insensitive in ASCII only.
func asciiLower(s string) string {
	upper := strings.IndexFunc(s, func(r rune) bool { return 'A' <= r && r <= 'Z' })
	if upper < 0 {
		return s
	}
	b := []byte(s)
	for i := upper; i < len(b); i++ {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// String returns a description of the server that leaves out everything but its
// key, protocol and name: no address, no credential, no setting of the
// transport. It is what fmt prints for a Server or a *Server.
func (s Server) String() string {
	return "egressuri.Server{key=" + s.Key() + ", protocol=" + s.Protocol + ", name=" + strconv.Quote(s.Name) + "}"
}

// GoString is String for %#v, which would otherwise print every field.
func (s Server) GoString() string { return s.String() }

// LogValue makes slog log the key, the protocol and the name of the server, as
// the group key, protocol and name, and nothing else.
func (s Server) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("key", s.Key()),
		slog.String("protocol", s.Protocol),
		slog.String("name", s.Name),
	)
}

// Parse reads one share link:
//
//	vless://id@host:port?type=&security=&sni=&fp=&pbk=&sid=&spx=&flow=&path=&host=&serviceName=&mode=&alpn=&extra=#name
//	vmess://base64(json)
//	trojan://password@host:port?sni=&type=&path=&host=&security=#name
//	ss://base64(method:password)@host:port#name, or ss://method:password@host:port#name
//
// The scheme and the names in a query are not case-sensitive; the fields of the
// JSON of a vmess link are. peer and servername are aliases of sni, and insecure
// of allowInsecure; headerType is ignored, like every parameter that is not
// listed. An IPv6 address is written in brackets. The port is 443 when a vless
// or trojan link has none, and required in the others.
//
// What Server cannot hold is refused instead of dropped: a vmess alterId other
// than 0, a shadowsocks plugin, a vless encryption other than none and a network
// or security that Server does not list are errors.
func Parse(uri string) (*Server, error) {
	uri = strings.TrimSpace(uri)
	if strings.ContainsFunc(uri, unicode.IsControl) {
		return nil, errors.New("invalid URI: control character")
	}
	scheme, rest, found := strings.Cut(uri, "://")
	if !found {
		return nil, errors.New("invalid URI: missing scheme")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(rest)
	case "vmess":
		return parseVMess(rest)
	case "trojan":
		return parseTrojan(rest)
	case "ss":
		return parseSS(rest)
	}
	return nil, unsupportedScheme(scheme)
}

// linkError is the error for a link of the given scheme. msg is a fixed text
// that names the field at fault. It must never be built from the link, which
// holds credentials.
func linkError(scheme, msg string) error {
	return errors.New(scheme + ": " + msg)
}

// unsupportedScheme names the scheme of a link that this package cannot read,
// but only when it is short and looks like a scheme. Anything else might be a
// credential that landed in the wrong place.
func unsupportedScheme(scheme string) error {
	if len(scheme) <= 16 && isSchemeName(scheme) {
		return errors.New("unsupported scheme " + strconv.Quote(strings.ToLower(scheme)))
	}
	return errors.New("unsupported scheme")
}

func isSchemeName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// ---- vless and trojan ------------------------------------------------------

func parseVLESS(rest string) (*Server, error) {
	const scheme = "vless"
	l := splitLink(rest)
	id, err := credential(scheme, "id", l.user)
	if err != nil {
		return nil, err
	}
	host, port, err := endpoint(scheme, l.hostPort, defaultPort)
	if err != nil {
		return nil, err
	}
	s := &Server{Protocol: protoVLESS, Name: l.name, Address: host, Port: port, ID: id}

	f := newQueryFields(scheme, l.query)
	// A vless encryption other than none changes the protocol, and Server has
	// no field for it: a link that needs it cannot work as a plain one.
	if enc := f.str("encryption"); enc != "" && !strings.EqualFold(enc, "none") {
		f.fail("encryption not supported")
	}
	s.Flow = f.str("flow")
	f.stream(s, "none")
	if f.err != nil {
		return nil, f.err
	}
	return s, nil
}

func parseTrojan(rest string) (*Server, error) {
	const scheme = "trojan"
	l := splitLink(rest)
	password, err := credential(scheme, "password", l.user)
	if err != nil {
		return nil, err
	}
	host, port, err := endpoint(scheme, l.hostPort, defaultPort)
	if err != nil {
		return nil, err
	}
	s := &Server{Protocol: protoTrojan, Name: l.name, Address: host, Port: port, Password: password}

	f := newQueryFields(scheme, l.query)
	f.stream(s, "tls")
	if f.err != nil {
		return nil, f.err
	}
	return s, nil
}

// link is a URL-style link cut into its parts. Only the name is decoded.
type link struct {
	user     string // userinfo, percent-encoded
	hostPort string
	afterAt  string // what follows the userinfo, up to the query: the host and port, and a path
	query    string // percent-encoded
	name     string
}

// splitLink cuts what follows "scheme://". The fragment is the name, the query
// goes after the first "?", the userinfo ends at the last "@" (a password may
// hold a "/" or an "@"), and whatever follows the host and port up to the query
// is a path, which share links do not use.
func splitLink(rest string) link {
	rest, frag, _ := strings.Cut(rest, "#")
	rest, query, _ := strings.Cut(rest, "?")
	var user string
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		user, rest = rest[:i], rest[i+1:]
	}
	hostPort, _, _ := strings.Cut(rest, "/")
	return link{user: user, hostPort: hostPort, afterAt: rest, query: query, name: fragmentName(frag)}
}

// fragmentName decodes the fragment of a link into a name. A fragment that is
// not valid percent-encoding is taken as it is, since a name is only shown.
func fragmentName(frag string) string {
	name, err := url.PathUnescape(frag)
	if err != nil {
		name = frag
	}
	return cleanName(name)
}

// cleanName makes a name for display of text that came from a link: bytes that
// are not UTF-8 become U+FFFD, control characters become spaces, and the ends
// are trimmed.
func cleanName(name string) string {
	name = strings.ToValidUTF8(name, string(utf8.RuneError))
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, name)
	return strings.TrimSpace(name)
}

// credential decodes the userinfo of a vless or trojan link, the id or the
// password, which is all of the userinfo.
func credential(scheme, field, raw string) (string, error) {
	if raw == "" {
		return "", linkError(scheme, "missing "+field)
	}
	v, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(v) || strings.ContainsFunc(v, unicode.IsControl) {
		return "", linkError(scheme, "invalid "+field)
	}
	return v, nil
}

// endpoint reads host[:port] or [ipv6][:port]. A missing port is fallback, or an
// error when fallback is 0. The host is returned as written, without the
// brackets of an IPv6 address.
func endpoint(scheme, hostPort string, fallback uint16) (string, uint16, error) {
	if hostPort == "" {
		return "", 0, linkError(scheme, "missing address")
	}
	var host, portText string
	var hasPort bool
	if hostPort[0] == '[' {
		end := strings.IndexByte(hostPort, ']')
		if end < 0 || !isIPv6(hostPort[1:end]) {
			return "", 0, linkError(scheme, "invalid address")
		}
		host = hostPort[1:end]
		switch tail := hostPort[end+1:]; {
		case tail == "":
		case tail[0] == ':':
			portText, hasPort = tail[1:], true
		default:
			return "", 0, linkError(scheme, "invalid address")
		}
	} else {
		host, portText, hasPort = strings.Cut(hostPort, ":")
		if host == "" {
			return "", 0, linkError(scheme, "missing address")
		}
		// A second colon is an IPv6 address that is not in brackets.
		if !validHost(host) || strings.Contains(portText, ":") {
			return "", 0, linkError(scheme, "invalid address")
		}
	}
	if !hasPort {
		if fallback == 0 {
			return "", 0, linkError(scheme, "missing port")
		}
		return host, fallback, nil
	}
	port, ok := parsePort(portText)
	if !ok {
		return "", 0, linkError(scheme, "invalid port")
	}
	return host, port, nil
}

// parsePort reads a port: decimal digits, 1 to 65535.
func parsePort(text string) (uint16, bool) {
	n, err := strconv.ParseUint(text, 10, 16)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint16(n), true
}

// isIPv6 reports whether s is an IPv6 address without a zone.
func isIPv6(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6() && addr.Zone() == ""
}

// validHost reports whether s can be the host of a link: not empty, no longer
// than a DNS name, UTF-8, and free of spaces, control and format characters, and
// of the characters that delimit the parts of a URL.
func validHost(s string) bool {
	if s == "" || len(s) > 253 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || strings.ContainsRune(`/\?#@[]:%`, r) {
			return false
		}
	}
	return true
}

// ---- parameters ------------------------------------------------------------

// fields reads the parameters of a link: the query of a vless or trojan link,
// or the JSON object of a vmess link. The first problem is kept in err and the
// reads after it return zero values, so that a caller can read everything and
// look at err once.
type fields struct {
	scheme string
	fold   bool              // names are case-insensitive, as in a query; in the JSON of vmess they are exact
	vals   map[string]string // decoded and trimmed values, the empty ones left out
	bad    map[string]bool   // names whose value cannot be read
	err    error
}

// newQueryFields reads a percent-encoded query. When a name repeats, the first
// value that is not empty is used. Values that are not valid UTF-8 are marked
// bad, and an error comes only if the link asks for them.
func newQueryFields(scheme, query string) *fields {
	f := &fields{scheme: scheme, fold: true, vals: map[string]string{}, bad: map[string]bool{}}
	for pair := range strings.SplitSeq(query, "&") {
		name, raw, _ := strings.Cut(pair, "=")
		name = strings.ToLower(name)
		if _, seen := f.vals[name]; name == "" || seen || f.bad[name] {
			continue
		}
		value, err := url.QueryUnescape(raw)
		switch {
		case err != nil || !utf8.ValidString(value):
			f.bad[name] = true
		case strings.TrimSpace(value) != "":
			f.vals[name] = strings.TrimSpace(value)
		}
	}
	return f
}

// newJSONFields reads the values of a JSON object that are strings, numbers,
// booleans or null. A string, a number and a boolean are taken as text, null
// counts as not set, and an object or an array is marked bad.
func newJSONFields(scheme string, obj map[string]json.RawMessage) *fields {
	f := &fields{scheme: scheme, vals: map[string]string{}, bad: map[string]bool{}}
	for name, raw := range obj {
		value, ok := jsonScalar(raw)
		switch {
		case !ok:
			f.bad[name] = true
		case value != "":
			f.vals[name] = value
		}
	}
	return f
}

// jsonScalar returns a JSON string, number or boolean as trimmed text, and ""
// for null.
func jsonScalar(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	switch {
	case len(raw) == 0 || string(raw) == "null":
		return "", true
	case raw[0] == '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		return strings.TrimSpace(s), true
	case raw[0] == '{' || raw[0] == '[':
		return "", false
	}
	return string(raw), true // a number, true or false
}

func (f *fields) key(name string) string {
	if f.fold {
		return strings.ToLower(name)
	}
	return name
}

// fail records the first problem. msg is a fixed text, see linkError.
func (f *fields) fail(msg string) {
	if f.err == nil {
		f.err = linkError(f.scheme, msg)
	}
}

// str returns the value of the first of names that is set, or "". A value that
// cannot be read, or that has a control character, is an error naming that
// parameter.
func (f *fields) str(names ...string) string {
	if f.err != nil {
		return ""
	}
	for _, name := range names {
		key := f.key(name)
		v := f.vals[key]
		if f.bad[key] || strings.ContainsFunc(v, unicode.IsControl) {
			f.fail("invalid " + name)
			return ""
		}
		if v != "" {
			return v
		}
	}
	return ""
}

// text is str for a name shown to people: it never fails, a value that cannot be
// read counts as none, and control characters are left for cleanName.
func (f *fields) text(name string) string {
	return f.vals[f.key(name)]
}

// has reports whether the link sets name at all, even to a value that cannot be
// read.
func (f *fields) has(name string) bool {
	key := f.key(name)
	return f.vals[key] != "" || f.bad[key]
}

// flag reads a boolean parameter: 1 or true is on, anything else is off.
func (f *fields) flag(names ...string) bool {
	switch strings.ToLower(f.str(names...)) {
	case "1", "true":
		return true
	}
	return false
}

// network reads the transport: tcp (also spelled raw), ws, grpc, xhttp (also
// spelled splithttp) or httpupgrade. Nothing means tcp.
func (f *fields) network(name string) string {
	switch v := strings.ToLower(f.str(name)); v {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "grpc", "xhttp", "httpupgrade":
		return v
	case "splithttp":
		return "xhttp"
	}
	f.fail("unsupported network")
	return ""
}

// security reads none, tls or reality; nothing means def.
func (f *fields) security(name, def string) string {
	switch v := strings.ToLower(f.str(name)); v {
	case "":
		return def
	case "none", "tls", "reality":
		return v
	}
	f.fail("unsupported security")
	return ""
}

// stream reads the transport and security parameters that vless and trojan
// links share.
func (f *fields) stream(s *Server, defaultSecurity string) {
	s.Network = f.network("type")
	s.Security = f.security("security", defaultSecurity)
	s.SNI = f.str("sni", "peer", "servername")
	s.Fingerprint = f.str("fp")
	s.PublicKey = f.str("pbk")
	s.ShortID = f.str("sid")
	s.SpiderX = f.str("spx")
	s.Path = f.str("path")
	s.Host = f.str("host")
	s.ServiceName = f.str("serviceName")
	s.Mode = f.str("mode")
	s.ALPN = f.str("alpn")
	s.Extra = f.extra("extra")
	s.AllowInsecure = f.flag("allowInsecure", "insecure")
	if f.err == nil && s.Security == "reality" && s.PublicKey == "" {
		f.fail("missing pbk for reality")
	}
}

// extra reads the xhttp "extra" parameter, a JSON object. It may be spread over
// several lines, so it is the one parameter that may hold line breaks and
// indentation; the JSON is compacted, which leaves no control character in it
// but those that a JSON string can hold, and those are refused.
func (f *fields) extra(name string) string {
	if f.err != nil {
		return ""
	}
	key := f.key(name)
	if f.bad[key] {
		f.fail("invalid " + name)
		return ""
	}
	v := f.vals[key]
	if v == "" {
		return ""
	}
	var compact bytes.Buffer
	if !strings.HasPrefix(v, "{") || json.Compact(&compact, []byte(v)) != nil || strings.ContainsFunc(compact.String(), unicode.IsControl) {
		f.fail("invalid " + name)
		return ""
	}
	return compact.String()
}

// ---- shadowsocks -----------------------------------------------------------

func parseSS(rest string) (*Server, error) {
	const scheme = "ss"
	l := splitLink(rest)
	if newQueryFields(scheme, l.query).has("plugin") {
		return nil, linkError(scheme, "plugins not supported")
	}
	if l.user == "" && isLegacySS(l.afterAt) {
		return nil, linkError(scheme, "legacy form not supported")
	}
	method, password, err := ssCredentials(l.user)
	if err != nil {
		return nil, err
	}
	host, port, err := endpoint(scheme, l.hostPort, 0)
	if err != nil {
		return nil, err
	}
	return &Server{
		Protocol: protoSS, Name: l.name, Address: host, Port: port,
		Method: method, Password: password, Network: "tcp", Security: "none",
	}, nil
}

// isLegacySS reports whether what follows "ss://" (up to the query) is the old
// form of the link, base64(method:password@host:port), instead of
// userinfo@host:port: there is no userinfo, and the text decodes from base64, in
// either alphabet, to text that holds an "@". A "/" at the end is tried both
// ways, since it may start a path or be the last character of standard base64.
func isLegacySS(afterAt string) bool {
	text, err := url.PathUnescape(afterAt)
	if err != nil {
		return false
	}
	for _, candidate := range []string{text, strings.TrimSuffix(text, "/")} {
		if raw, ok := decodeBase64(candidate); ok && bytes.IndexByte(raw, '@') >= 0 {
			return true
		}
	}
	return false
}

// ssCredentials reads the userinfo of an ss:// link: "method:password" written
// out and percent-encoded (the form of AEAD-2022 keys), or its base64 (SIP002).
// Base64 comes in either alphabet, with or without padding, and the padding may
// be percent-encoded. It returns the method and the password.
func ssCredentials(user string) (string, string, error) {
	const scheme = "ss"
	if user == "" {
		return "", "", linkError(scheme, "missing userinfo")
	}
	text, err := url.PathUnescape(user)
	if err != nil {
		return "", "", linkError(scheme, "invalid userinfo")
	}
	if !strings.Contains(text, ":") {
		raw, ok := decodeBase64(text)
		if !ok {
			return "", "", linkError(scheme, "invalid userinfo")
		}
		text = string(raw)
	}
	method, password, found := strings.Cut(text, ":")
	switch {
	case !found || !utf8.ValidString(text) || strings.ContainsFunc(text, unicode.IsControl):
		return "", "", linkError(scheme, "invalid userinfo")
	case method == "":
		return "", "", linkError(scheme, "missing method")
	case password == "":
		return "", "", linkError(scheme, "missing password")
	}
	return method, password, nil
}

// ---- vmess -----------------------------------------------------------------

// parseVMess reads vmess://base64(json) with the fields of the share-link
// format of v2rayN: add, port, id, aid, scy, net, host, path, tls, sni, alpn,
// fp and ps. The port and aid may be numbers or strings.
func parseVMess(rest string) (*Server, error) {
	const scheme = "vmess"
	payload, frag, _ := strings.Cut(rest, "#")
	payload, _, _ = strings.Cut(payload, "?")
	if payload == "" {
		return nil, linkError(scheme, "missing payload")
	}
	text, err := url.PathUnescape(payload)
	if err != nil {
		return nil, linkError(scheme, "invalid base64")
	}
	data, ok := decodeBase64(text)
	if !ok {
		return nil, linkError(scheme, "invalid base64")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &obj) != nil || obj == nil {
		return nil, linkError(scheme, "invalid json")
	}

	f := newJSONFields(scheme, obj)
	s := &Server{Protocol: protoVMess}
	if add := f.str("add"); add == "" {
		f.fail("missing add")
	} else if host, valid := vmessHost(add); !valid {
		f.fail("invalid add")
	} else {
		s.Address = host
	}
	s.Port = f.port("port")
	if s.ID = f.str("id"); s.ID == "" {
		f.fail("missing id")
	}
	// Only alterId 0, the AEAD form of vmess, is supported.
	if aid := f.str("aid"); aid != "" {
		if n, err := strconv.ParseFloat(aid, 64); err != nil || n != 0 {
			f.fail("alterId not supported")
		}
	}
	s.Method = f.str("scy")
	s.Network = f.network("net")
	switch strings.ToLower(f.str("tls")) {
	case "", "none":
		s.Security = "none"
	case "tls":
		s.Security = "tls"
	default:
		f.fail("unsupported security")
	}
	s.SNI = f.str("sni")
	s.Fingerprint = f.str("fp")
	s.ALPN = f.str("alpn")
	s.Host = f.str("host")
	s.Path = f.str("path")
	if s.Network == "grpc" {
		s.ServiceName, s.Path = s.Path, ""
	}
	s.AllowInsecure = f.flag("allowInsecure", "insecure")
	if s.Name = cleanName(f.text("ps")); s.Name == "" {
		s.Name = fragmentName(frag)
	}
	if f.err != nil {
		return nil, f.err
	}
	return s, nil
}

// port reads a port that is a JSON number or string.
func (f *fields) port(name string) uint16 {
	text := f.str(name)
	if text == "" {
		f.fail("missing " + name)
		return 0
	}
	port, ok := parsePort(text)
	if !ok {
		f.fail("invalid " + name)
	}
	return port
}

// vmessHost reads the "add" of a vmess link: a host name, an IPv4 address or an
// IPv6 address, with brackets or without.
func vmessHost(add string) (string, bool) {
	if inner, ok := strings.CutPrefix(add, "["); ok {
		inner, ok = strings.CutSuffix(inner, "]")
		return inner, ok && isIPv6(inner)
	}
	return add, isIPv6(add) || validHost(add)
}

// ---- base64 ----------------------------------------------------------------

var base64Encodings = [...]*base64.Encoding{
	base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding,
}

// decodeBase64 decodes s with the standard or the URL alphabet, padded or not.
// Line breaks inside s are ignored.
func decodeBase64(s string) ([]byte, bool) {
	for _, enc := range base64Encodings {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}
