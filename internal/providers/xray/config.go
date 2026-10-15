package xray

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/providers"
)

// The config file this driver writes. Every field name, and every value that
// Xray checks, is that of Xray v26.3.27: infra/conf/{xray,log,socks,router,
// vless,vmess,trojan,shadowsocks,wireguard,transport_internet}.go, and the
// documentation of that version (xtls.github.io). A transport over TCP is
// "raw" (its current name). REALITY's key is rendered as "publicKey", which
// v26.3.27 reads as well as its new name "password", and older releases read
// too (Ruling S2-13).
//
// Some values pass Xray's own check and make it panic: a REALITY spiderX that
// url.Parse refuses (at load), and downloadSettings without an address or with
// another network than xhttp (at the first dial through the member, after the
// instance is up). They are refused here as well.

const (
	configFile = "config.json"
	// blockTag is the default outbound: anything that no rule routes (nothing
	// should) is dropped, never sent through some member.
	blockTag = "block"
	// wireGuardMTU is the MTU of the WARP tunnel.
	wireGuardMTU = 1280
)

type config struct {
	Log       logConfig  `json:"log"`
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
	Routing   routing    `json:"routing"`
}

// logConfig: warnings and errors only, and no access log, which would write a
// line for every connection.
type logConfig struct {
	Access   string `json:"access"`
	LogLevel string `json:"loglevel"`
}

type inbound struct {
	Tag      string        `json:"tag"`
	Listen   string        `json:"listen"`
	Port     uint16        `json:"port"`
	Protocol string        `json:"protocol"`
	Settings socksSettings `json:"settings"`
}

type socksSettings struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
}

type outbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       any             `json:"settings,omitempty"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
}

// vnextSettings is the outbound of VLESS and VMess: one server, one user.
type vnextSettings struct {
	Vnext []vnext `json:"vnext"`
}

type vnext struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Users   []any  `json:"users"`
}

type vlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

type vmessUser struct {
	ID       string `json:"id"`
	Security string `json:"security"`
}

// serversSettings is the outbound of Trojan and Shadowsocks: one server.
type serversSettings struct {
	Servers []server `json:"servers"`
}

type server struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Method   string `json:"method,omitempty"`
	Password string `json:"password"`
}

type wireGuardSettings struct {
	SecretKey string          `json:"secretKey"`
	Address   []string        `json:"address"`
	Peers     []wireGuardPeer `json:"peers"`
	// Reserved is an array: [3]byte marshals to numbers, as Xray wants them.
	Reserved [3]byte `json:"reserved"`
	MTU      int     `json:"mtu"`
	// NoKernelTun keeps Xray on its userspace network stack. The container has
	// no capabilities and could not make a kernel TUN device anyway; on the host
	// network such a device, and its routes, would be the host's.
	NoKernelTun bool `json:"noKernelTun"`
}

type wireGuardPeer struct {
	PublicKey  string   `json:"publicKey"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowedIPs"`
}

type streamSettings struct {
	Network     string           `json:"network"`
	Security    string           `json:"security"`
	TLS         *tlsSettings     `json:"tlsSettings,omitempty"`
	Reality     *realitySettings `json:"realitySettings,omitempty"`
	WS          *pathHost        `json:"wsSettings,omitempty"`
	HTTPUpgrade *pathHost        `json:"httpupgradeSettings,omitempty"`
	GRPC        *grpcSettings    `json:"grpcSettings,omitempty"`
	XHTTP       *xhttpSettings   `json:"xhttpSettings,omitempty"`
}

type tlsSettings struct {
	ServerName  string   `json:"serverName,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	ALPN        []string `json:"alpn,omitempty"`
}

type realitySettings struct {
	ServerName  string `json:"serverName,omitempty"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type pathHost struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type grpcSettings struct {
	ServiceName string `json:"serviceName,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}

type xhttpSettings struct {
	Path  string          `json:"path,omitempty"`
	Host  string          `json:"host,omitempty"`
	Mode  string          `json:"mode,omitempty"`
	Extra json.RawMessage `json:"extra,omitempty"`
}

type routing struct {
	Rules []rule `json:"rules"`
}

type rule struct {
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

// ---- rendering ----------------------------------------------------------------

// renderConfig makes the config.json of an instance: per member a SOCKS5 inbound
// on 127.0.0.1:<port> (no authentication, no UDP), tagged in-<key>, routed by
// one rule to the outbound out-<key> made from its server or its WARP account.
// No rule needs geoip or geosite data.
func renderConfig(in providers.Instance) ([]byte, error) {
	if err := providers.CheckEgressID(in.EgressID); err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	if err := providers.CheckMembers(in.Members); err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	if err := checkKind(in); err != nil {
		return nil, err
	}

	cfg := config{
		Log:       logConfig{Access: "none", LogLevel: "warning"},
		Inbounds:  []inbound{},
		Outbounds: []outbound{{Tag: blockTag, Protocol: "blackhole"}},
		Routing:   routing{Rules: []rule{}},
	}
	var bad []*providers.MemberError
	for _, m := range in.Members {
		var out outbound
		var merr *providers.MemberError
		if m.WARP != nil {
			out, merr = warpOutbound(m)
		} else {
			out, merr = serverOutbound(m)
		}
		if merr != nil {
			bad = append(bad, merr)
			continue
		}
		inTag, outTag := "in-"+m.Key, "out-"+m.Key
		out.Tag = outTag
		cfg.Inbounds = append(cfg.Inbounds, inbound{
			Tag: inTag, Listen: "127.0.0.1", Port: m.Port, Protocol: "socks",
			Settings: socksSettings{Auth: "noauth", UDP: false},
		})
		cfg.Outbounds = append(cfg.Outbounds, out)
		cfg.Routing.Rules = append(cfg.Routing.Rules, rule{InboundTag: []string{inTag}, OutboundTag: outTag})
	}
	if err := providers.JoinMemberErrors(bad); err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	return buf.Bytes(), nil
}

// checkKind checks that the members fit the kind of the egress.
func checkKind(in providers.Instance) error {
	servers := func() error {
		for _, m := range in.Members {
			if m.Server == nil || m.WARP != nil {
				return fmt.Errorf("xray: member %s of a %s egress must have a server and no WARP account", m.Key, in.Kind)
			}
		}
		return nil
	}
	switch in.Kind {
	case nodev1.EgressKind_EGRESS_KIND_XRAY_URI:
		if len(in.Members) != 1 {
			return fmt.Errorf("xray: an XRAY_URI egress has one member, not %d", len(in.Members))
		}
		return servers()
	case nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION:
		return servers()
	case nodev1.EgressKind_EGRESS_KIND_WARP:
		if len(in.Members) != 1 {
			return fmt.Errorf("xray: a WARP egress has one member, not %d", len(in.Members))
		}
		if m := in.Members[0]; m.WARP == nil || m.Server != nil {
			return fmt.Errorf("xray: member %s of a WARP egress must have a WARP account and no server", m.Key)
		}
		return nil
	}
	return fmt.Errorf("xray: cannot serve an egress of kind %s", in.Kind)
}

// serverOutbound makes the outbound of a member with a server.
func serverOutbound(m providers.Member) (outbound, *providers.MemberError) {
	s := m.Server
	bad := func(field, reason string) (outbound, *providers.MemberError) {
		return outbound{}, &providers.MemberError{Key: m.Key, Field: field, Reason: reason}
	}
	if err := providers.CheckServerAddress(s.Address); err != nil {
		return bad("address", err.Error())
	}
	if s.Port == 0 {
		return bad("port", "missing")
	}

	var out outbound
	switch s.Protocol {
	case "vless":
		if !validID(s.ID) {
			return bad("id", "not an id Xray takes (a UUID, or 1 to 30 bytes of text)")
		}
		if !slices.Contains(vlessFlows, s.Flow) {
			return bad("flow", "not a flow of VLESS in Xray (xtls-rprx-vision, xtls-rprx-vision-udp443)")
		}
		out = outbound{Protocol: "vless", Settings: vnextSettings{Vnext: []vnext{{
			Address: s.Address, Port: s.Port,
			Users: []any{vlessUser{ID: s.ID, Encryption: "none", Flow: s.Flow}},
		}}}}
	case "vmess":
		if !validID(s.ID) {
			return bad("id", "not an id Xray takes (a UUID, or 1 to 30 bytes of text)")
		}
		out = outbound{Protocol: "vmess", Settings: vnextSettings{Vnext: []vnext{{
			Address: s.Address, Port: s.Port,
			Users: []any{vmessUser{ID: s.ID, Security: vmessSecurity(s.Method)}},
		}}}}
	case "trojan":
		if s.Password == "" {
			return bad("password", "missing")
		}
		if s.Flow != "" {
			return bad("flow", "Trojan has no flow in Xray")
		}
		out = outbound{Protocol: "trojan", Settings: serversSettings{Servers: []server{{
			Address: s.Address, Port: s.Port, Password: s.Password,
		}}}}
	case "shadowsocks":
		method, ok := ssMethod(s.Method)
		if !ok {
			return bad("method", "not a cipher of Shadowsocks in Xray")
		}
		if s.Password == "" {
			return bad("password", "missing")
		}
		if keyLen, is2022 := ss2022KeyLen[method]; is2022 && !valid2022Key(method, keyLen, s.Password) {
			return bad("password", fmt.Sprintf("not a key of %s (base64 keys of %d bytes or more, separated by ':')", method, keyLen))
		}
		out = outbound{Protocol: "shadowsocks", Settings: serversSettings{Servers: []server{{
			Address: s.Address, Port: s.Port, Method: method, Password: s.Password,
		}}}}
	default:
		return bad("protocol", "not a protocol of this driver")
	}

	st, merr := streamFor(m.Key, s)
	if merr != nil {
		return outbound{}, merr
	}
	out.StreamSettings = st
	return out, nil
}

// streamFor makes the stream settings of a server: its transport and its
// security.
func streamFor(key string, s *egressuri.Server) (*streamSettings, *providers.MemberError) {
	bad := func(field, reason string) (*streamSettings, *providers.MemberError) {
		return nil, &providers.MemberError{Key: key, Field: field, Reason: reason}
	}
	st := &streamSettings{}
	pathHostOf := func() *pathHost {
		if s.Path == "" && s.Host == "" {
			return nil
		}
		return &pathHost{Path: s.Path, Host: s.Host}
	}
	switch s.Network {
	case "tcp":
		st.Network = "raw"
	case "ws":
		st.Network = "ws"
		st.WS = pathHostOf()
	case "httpupgrade":
		st.Network = "httpupgrade"
		st.HTTPUpgrade = pathHostOf()
	case "grpc":
		st.Network = "grpc"
		multi, ok := grpcMultiMode(s.Mode)
		if !ok {
			return bad("mode", "not a gRPC mode (gun, multi)")
		}
		if s.ServiceName != "" || multi {
			st.GRPC = &grpcSettings{ServiceName: s.ServiceName, MultiMode: multi}
		}
	case "xhttp":
		st.Network = "xhttp"
		mode, ok := xhttpMode(s.Mode)
		if !ok {
			return bad("mode", "not an XHTTP mode (auto, packet-up, stream-up, stream-one)")
		}
		var extra json.RawMessage
		if s.Extra != "" {
			if reason := checkExtra(s.Extra, mode); reason != "" {
				return bad("extra", reason)
			}
			extra = json.RawMessage(s.Extra)
		}
		if s.Path != "" || s.Host != "" || mode != "" || extra != nil {
			st.XHTTP = &xhttpSettings{Path: s.Path, Host: s.Host, Mode: mode, Extra: extra}
		}
	default:
		return bad("type", "not a transport of this driver")
	}

	switch s.Security {
	case "none":
		st.Security = "none"
	case "tls":
		// The link's allowInsecure is not rendered: Xray v26.3.27 refuses the
		// whole config with "allowInsecure" after 2026-06-01 (it was replaced by
		// pinnedPeerCertSha256, which links do not carry). The certificate is
		// checked, and the member works if it verifies.
		st.Security = "tls"
		fp, ok := tlsFingerprint(s.Fingerprint)
		if !ok {
			return bad("fp", "not a TLS fingerprint Xray knows")
		}
		alpn, ok := splitALPN(s.ALPN)
		if !ok {
			return bad("alpn", "an empty or overlong protocol name")
		}
		st.TLS = &tlsSettings{ServerName: s.SNI, Fingerprint: fp, ALPN: alpn}
	case "reality":
		if !realityNetworks[st.Network] {
			return bad("security", "REALITY works over raw (tcp), XHTTP and gRPC only")
		}
		st.Security = "reality"
		r, field, reason := realityOf(s.SNI, s.Fingerprint, s.PublicKey, s.ShortID, s.SpiderX)
		if r == nil {
			return bad(field, reason)
		}
		st.Reality = r
	default:
		return bad("security", "not a security of this driver")
	}
	return st, nil
}

// realityNetworks are the networks (as rendered) REALITY works over: Xray
// refuses the others ("REALITY only supports RAW, XHTTP and gRPC for now").
var realityNetworks = map[string]bool{"raw": true, "xhttp": true, "grpc": true}

// realityOf makes REALITY settings, or says which field Xray would refuse and
// why (the client side of REALITYConfig.Build).
func realityOf(sni, fp, key, shortID, spiderX string) (r *realitySettings, field, reason string) {
	fingerprint, ok := realityFingerprint(fp)
	if !ok {
		return nil, "fp", "not a fingerprint REALITY takes (not unsafe, not hellogolang, one Xray knows)"
	}
	if key == "" {
		return nil, "pbk", "missing"
	}
	if k, err := base64.RawURLEncoding.DecodeString(key); err != nil || len(k) != 32 {
		return nil, "pbk", "not 32 bytes of unpadded URL-safe base64"
	}
	if len(shortID) > 16 {
		return nil, "sid", "longer than 16 hex digits"
	}
	if _, err := hex.DecodeString(shortID); err != nil {
		return nil, "sid", "not an even number of hex digits"
	}
	if spiderX != "" && spiderX[0] != '/' {
		return nil, "spx", "does not start with /"
	}
	// REALITYConfig.Build reads the query of spiderX with u, _ :=
	// url.Parse(spiderX); u.Query(): what url.Parse refuses makes Xray panic.
	if _, err := url.Parse(spiderX); err != nil {
		return nil, "spx", "not a path that can be parsed as a URL"
	}
	return &realitySettings{ServerName: sni, Fingerprint: fingerprint, PublicKey: key, ShortID: shortID, SpiderX: spiderX}, "", ""
}

// warpOutbound makes the WireGuard outbound of a WARP member: the account's key
// and addresses (/32 and /128), its endpoint as the one peer with every address
// routed to it, its reserved bytes, an MTU of 1280, and Xray's own network stack.
func warpOutbound(m providers.Member) (outbound, *providers.MemberError) {
	a := m.WARP
	bad := func(field, reason string) (outbound, *providers.MemberError) {
		return outbound{}, &providers.MemberError{Key: m.Key, Field: field, Reason: reason}
	}
	if err := a.Validate(); err != nil {
		// Never holds a credential. The field is named here already.
		return bad("account", strings.TrimPrefix(err.Error(), "warp: account: "))
	}
	host, _, err := net.SplitHostPort(a.Endpoint)
	if err != nil {
		return bad("endpoint", "not host:port")
	}
	if err := providers.CheckServerAddress(host); err != nil {
		return bad("endpoint", err.Error())
	}
	addrs := []string{a.AddrV4 + "/32"}
	if a.AddrV6 != "" {
		addrs = append(addrs, a.AddrV6+"/128")
	}
	return outbound{Protocol: "wireguard", Settings: wireGuardSettings{
		SecretKey: a.PrivateKey,
		Address:   addrs,
		Peers: []wireGuardPeer{{
			PublicKey: a.PeerPublicKey, Endpoint: a.Endpoint, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
		Reserved:    a.Reserved,
		MTU:         wireGuardMTU,
		NoKernelTun: true,
	}}, nil
}

// ---- what Xray v26.3.27 takes ---------------------------------------------------

// vlessFlows are the flows of VLESSOutboundConfig.Build (infra/conf/vless.go).
var vlessFlows = []string{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}

// validID is Xray's common/uuid.ParseString: 32 to 36 bytes are a UUID, read as
// five groups of hex digits (8-4-4-4-12), each optionally preceded by a dash,
// with what follows the fifth group ignored; 1 to 30 bytes of any text are
// mapped to a UUID; anything else is refused.
func validID(id string) bool {
	if l := len(id); l < 32 || l > 36 {
		return l >= 1 && l <= 30
	}
	text := id
	for _, group := range []int{8, 4, 4, 4, 12} {
		if len(text) > 0 && text[0] == '-' {
			text = text[1:]
		}
		if len(text) < group {
			return false
		}
		if _, err := hex.DecodeString(text[:group]); err != nil {
			return false
		}
		text = text[group:]
	}
	return true
}

// vmessSecurity is the security of a VMess user from the link's "scy": what
// VMessAccount.Build knows, and auto for anything else, as Xray takes it.
func vmessSecurity(scy string) string {
	switch s := strings.ToLower(scy); s {
	case "aes-128-gcm", "chacha20-poly1305", "auto", "none", "zero":
		return s
	}
	return "auto"
}

// ssMethods are the ciphers of cipherFromString (infra/conf/shadowsocks.go,
// which lowercases), and ss2022KeyLen the methods of Shadowsocks 2022
// (sing-shadowsocks v0.2.7 shadowaead_2022.List, compared as they are spelled)
// with their key length.
var (
	ssMethods = []string{
		"aes-128-gcm", "aead_aes_128_gcm", "aes-256-gcm", "aead_aes_256_gcm",
		"chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305",
		"xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305",
		"none", "plain",
	}
	ss2022KeyLen = map[string]int{
		"2022-blake3-aes-128-gcm":       16,
		"2022-blake3-aes-256-gcm":       32,
		"2022-blake3-chacha20-poly1305": 32,
	}
)

// ssMethod returns the method in lower case (Xray compares the 2022 methods as
// they are spelled, so they must be) and whether Xray knows it.
func ssMethod(m string) (string, bool) {
	m = strings.ToLower(m)
	_, is2022 := ss2022KeyLen[m]
	return m, is2022 || slices.Contains(ssMethods, m)
}

// valid2022Key is shadowaead_2022.NewWithPassword: keys separated by ':', each
// in padded standard base64 and at least keyLen bytes long (a longer one is
// derived), and only one for chacha20.
func valid2022Key(method string, keyLen int, password string) bool {
	keys := strings.Split(password, ":")
	if method == "2022-blake3-chacha20-poly1305" && len(keys) > 1 {
		return false
	}
	for _, k := range keys {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) < keyLen {
			return false
		}
	}
	return true
}

// fingerprints are the uTLS fingerprints of Xray v26.3.27
// (transport/internet/tls/tls.go): the keys of PresetFingerprints,
// ModernFingerprints and OtherFingerprints, which GetFingerprint looks up after
// TLSConfig.Build has lowercased the name.
var fingerprints = []string{
	// PresetFingerprints
	"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
	"random", "randomized", "randomizednoalpn",
	// ModernFingerprints
	"hellofirefox_99", "hellofirefox_102", "hellofirefox_105", "hellofirefox_120",
	"hellochrome_83", "hellochrome_87", "hellochrome_96", "hellochrome_100", "hellochrome_102",
	"hellochrome_106_shuffle", "hellochrome_120", "hellochrome_131",
	"helloios_13", "helloios_14", "helloedge_85", "helloedge_106",
	"hellosafari_16_0", "hello360_11_0", "helloqq_11_1",
	// OtherFingerprints
	"hellogolang", "hellorandomized", "hellorandomizedalpn", "hellorandomizednoalpn",
	"hellofirefox_auto", "hellofirefox_55", "hellofirefox_56", "hellofirefox_63", "hellofirefox_65",
	"hellochrome_auto", "hellochrome_58", "hellochrome_62", "hellochrome_70", "hellochrome_72",
	"helloios_auto", "helloios_11_1", "helloios_12_1", "helloandroid_11_okhttp",
	"helloedge_auto", "hellosafari_auto", "hello360_auto", "hello360_7_5", "helloqq_auto",
	"hellochrome_100_psk", "hellochrome_112_psk_shuf", "hellochrome_114_padding_psk_shuf",
	"hellochrome_115_pq", "hellochrome_115_pq_psk", "hellochrome_120_pq",
}

// Fingerprints returns the names of the TLS fingerprints the pinned Xray knows,
// in lower case. A link's fp is one of them (any case), or empty for chrome; TLS
// also takes "unsafe" (Go's own TLS), REALITY takes neither "unsafe" nor
// "hellogolang".
func Fingerprints() []string { return slices.Clone(fingerprints) }

// tlsFingerprint is the fingerprint of TLS settings: chrome for none, else the
// name in lower case when TLSConfig.Build takes it.
func tlsFingerprint(fp string) (string, bool) {
	fp = strings.ToLower(fp)
	switch {
	case fp == "":
		return "chrome", true
	case fp == "unsafe", slices.Contains(fingerprints, fp):
		return fp, true
	}
	return "", false
}

// realityFingerprint is tlsFingerprint for REALITY, which refuses unsafe and
// hellogolang. REALITY needs a fingerprint: chrome stands in for none, as Xray
// would take it.
func realityFingerprint(fp string) (string, bool) {
	fp = strings.ToLower(fp)
	switch {
	case fp == "":
		return "chrome", true
	case fp == "hellogolang":
		return "", false
	case slices.Contains(fingerprints, fp):
		return fp, true
	}
	return "", false
}

// splitALPN reads the comma-separated ALPN of a link.
func splitALPN(s string) ([]string, bool) {
	if strings.TrimSpace(s) == "" {
		return nil, true
	}
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" || len(p) > 255 {
			return nil, false
		}
		out = append(out, p)
	}
	return out, true
}

// grpcMultiMode reads the gRPC mode of a link: gun (or none) and multi.
func grpcMultiMode(mode string) (multi, ok bool) {
	switch strings.ToLower(mode) {
	case "", "gun":
		return false, true
	case "multi":
		return true, true
	}
	return false, false
}

// xhttpMode reads the XHTTP mode of a link (SplitHTTPConfig.Build compares the
// lower case names).
func xhttpMode(mode string) (string, bool) {
	switch m := strings.ToLower(mode); m {
	case "", "auto", "packet-up", "stream-up", "stream-one":
		return m, true
	}
	return "", false
}

// ---- the XHTTP extra --------------------------------------------------------------

// xhttpCommon mirrors the fields of SplitHTTPConfig of Xray v26.3.27
// (infra/conf/transport_internet.go) that an XHTTP extra, and the xhttpSettings
// of a downloadSettings, may set, but for host, path, mode, extra and
// downloadSettings: the same fields with the same types, so that decoding fails
// where Xray's encoding/json decoding fails.
type xhttpCommon struct {
	Headers              map[string]string `json:"headers"`
	XPaddingBytes        int32Range        `json:"xPaddingBytes"`
	XPaddingObfsMode     bool              `json:"xPaddingObfsMode"`
	XPaddingKey          string            `json:"xPaddingKey"`
	XPaddingHeader       string            `json:"xPaddingHeader"`
	XPaddingPlacement    string            `json:"xPaddingPlacement"`
	XPaddingMethod       string            `json:"xPaddingMethod"`
	UplinkHTTPMethod     string            `json:"uplinkHTTPMethod"`
	SessionPlacement     string            `json:"sessionPlacement"`
	SessionKey           string            `json:"sessionKey"`
	SeqPlacement         string            `json:"seqPlacement"`
	SeqKey               string            `json:"seqKey"`
	UplinkDataPlacement  string            `json:"uplinkDataPlacement"`
	UplinkDataKey        string            `json:"uplinkDataKey"`
	UplinkChunkSize      int32Range        `json:"uplinkChunkSize"`
	NoGRPCHeader         bool              `json:"noGRPCHeader"`
	NoSSEHeader          bool              `json:"noSSEHeader"`
	ScMaxEachPostBytes   int32Range        `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs int32Range        `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   int64             `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs int32Range        `json:"scStreamUpServerSecs"`
	ServerMaxHeaderBytes int32             `json:"serverMaxHeaderBytes"`
	Xmux                 xmuxExtra         `json:"xmux"`
}

type xmuxExtra struct {
	MaxConcurrency   int32Range `json:"maxConcurrency"`
	MaxConnections   int32Range `json:"maxConnections"`
	CMaxReuseTimes   int32Range `json:"cMaxReuseTimes"`
	HMaxRequestTimes int32Range `json:"hMaxRequestTimes"`
	HMaxReusableSecs int32Range `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int64      `json:"hKeepAlivePeriod"`
}

// xhttpExtra is the extra of a link as Xray decodes it: fields Xray does not
// know are ignored by both. The extra's own host, path and mode are decoded
// (Xray refuses the whole config when one is not a string) and then not used:
// those of the link win. An extra in the extra is not read by Xray. Its
// downloadSettings is checked on its own, strictly.
type xhttpExtra struct {
	Host string `json:"host"`
	Path string `json:"path"`
	Mode string `json:"mode"`
	xhttpCommon
	DownloadSettings json.RawMessage `json:"downloadSettings"`
}

// downloadSettings is the allowlist of what the downloadSettings of an extra may
// set, decoded strictly: a field it does not list (the settings of other
// transports, ...) is refused, not passed to Xray unchecked; sockopt and
// finalmask are taken only when null or empty. Address and port are where the
// download goes; the network must be XHTTP, whose settings Xray reads from
// xhttpSettings, or from splithttpSettings when there is no xhttpSettings.
type downloadSettings struct {
	Address   *string         `json:"address"`
	Port      uint16          `json:"port"`
	Network   *string         `json:"network"`
	Security  string          `json:"security"`
	TLS       *tlsExtra       `json:"tlsSettings"`
	Reality   *realityExtra   `json:"realitySettings"`
	XHTTP     *downloadXHTTP  `json:"xhttpSettings"`
	SplitHTTP *downloadXHTTP  `json:"splithttpSettings"`
	Sockopt   json.RawMessage `json:"sockopt"`
	FinalMask json.RawMessage `json:"finalmask"`
}

// downloadXHTTP is the xhttpSettings of a downloadSettings, which Xray builds
// as a SplitHTTPConfig of its own. Its extra and downloadSettings, which Xray
// would read, are not listed, so they are refused.
type downloadXHTTP struct {
	Host string `json:"host"`
	Path string `json:"path"`
	Mode string `json:"mode"`
	xhttpCommon
}

type tlsExtra struct {
	AllowInsecure bool        `json:"allowInsecure"`
	ServerName    string      `json:"serverName"`
	Fingerprint   string      `json:"fingerprint"`
	ALPN          *stringList `json:"alpn"`
	// Show is not a field of Xray's TLSConfig, which ignores it, whatever it
	// holds; panels write it.
	Show json.RawMessage `json:"show"`
}

type realityExtra struct {
	Show        bool   `json:"show"`
	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	Password    string `json:"password"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

// int32Range is Xray's Int32Range (infra/conf/common.go): a JSON integer, or a
// string holding an integer or a range "a-b"; the smaller end is from.
type int32Range struct{ from, to int32 }

func (r *int32Range) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		lo, hi, ok := parseRange(s)
		if !ok {
			return errors.New("not an integer range")
		}
		r.from, r.to = min(lo, hi), max(lo, hi)
		return nil
	}
	var n int32
	if err := json.Unmarshal(data, &n); err != nil {
		return errors.New("not an integer range")
	}
	r.from, r.to = n, n
	return nil
}

// parseRange reads "n" or "a-b", where a may be negative.
func parseRange(s string) (lo, hi int32, ok bool) {
	if n, err := strconv.ParseInt(s, 10, 32); err == nil {
		return int32(n), int32(n), true
	}
	for i := 1; i < len(s); i++ {
		if s[i] != '-' {
			continue
		}
		a, err1 := strconv.ParseInt(s[:i], 10, 32)
		b, err2 := strconv.ParseInt(s[i+1:], 10, 32)
		if err1 == nil && err2 == nil {
			return int32(a), int32(b), true
		}
	}
	return 0, 0, false
}

// stringList is Xray's StringList: an array of strings or one string with
// commas.
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*l = list
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.New("not a list of strings")
	}
	*l = strings.Split(s, ",")
	return nil
}

// isNull reports whether a raw JSON value is absent or null, which Xray takes
// for "not set".
func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null"
}

// emptyObject reports whether a raw JSON value is absent, null or an object
// without members.
func emptyObject(raw json.RawMessage) bool {
	if isNull(raw) {
		return true
	}
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && len(m) == 0
}

// duplicateKey reports whether an object of the JSON text, at any depth, holds
// a key twice, as encoding/json, and so Xray, matches keys: without regard to
// case, Unicode's folding included (it takes "ſockopt" for "sockopt"). Xray
// decodes the members of such a key into one value, so that a check of the
// last one would not see what the others bring. Text that is not JSON counts as
// a duplicate: it is refused either way.
func duplicateKey(text []byte) bool {
	type frame struct {
		object, wantKey bool
		keys            map[string]bool
	}
	var stack []*frame
	// value marks that a value has ended in the innermost frame.
	value := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return len(stack) > 0 // the text ends inside an object or an array
		}
		if err != nil {
			return true
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				stack = append(stack, &frame{object: d == '{', wantKey: d == '{', keys: map[string]bool{}})
			default:
				stack = stack[:len(stack)-1]
				value()
			}
			continue
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].wantKey {
			key := foldKey(tok.(string))
			if stack[n-1].keys[key] {
				return true
			}
			stack[n-1].keys[key] = true
			stack[n-1].wantKey = false
			continue
		}
		value()
	}
}

// foldKey folds a key as encoding/json does to match it to a field: ASCII
// letters to upper case, other runes to the upper case of their lower case.
func foldKey(key string) string {
	var b strings.Builder
	for _, r := range key {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
			continue
		}
		b.WriteRune(unicode.ToUpper(unicode.ToLower(r)))
	}
	return b.String()
}

// checkExtra checks an XHTTP extra the way SplitHTTPConfig.Build would, for the
// mode of the link, and returns why Xray would refuse it, or would panic over it
// ("" when neither). The download of a downloadSettings must go to an address a
// member may use (providers.CheckServerAddress).
func checkExtra(raw, mode string) string {
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return "not a JSON object"
	}
	if duplicateKey([]byte(raw)) {
		return "a key appears twice in an object (in any case)"
	}
	var e xhttpExtra
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return decodeReason(err)
	}
	if mode == "" {
		mode = "auto"
	}
	if reason := checkXHTTP(e.xhttpCommon, mode); reason != "" {
		return reason
	}
	if !isNull(e.DownloadSettings) {
		if mode == "stream-one" {
			return "downloadSettings cannot be used in mode stream-one"
		}
		if reason := checkDownload(e.DownloadSettings); reason != "" {
			return "downloadSettings: " + reason
		}
	}
	return ""
}

// checkXHTTP checks the fields of a SplitHTTPConfig that its Build checks, for
// its mode. No reason repeats a value.
func checkXHTTP(c xhttpCommon, mode string) string {
	for name := range c.Headers {
		if strings.EqualFold(name, "host") {
			return "headers cannot hold Host"
		}
	}
	if (c.XPaddingBytes != int32Range{}) && (c.XPaddingBytes.from <= 0 || c.XPaddingBytes.to <= 0) {
		return "xPaddingBytes cannot be 0 or less"
	}
	if !slices.Contains([]string{"", "cookie", "header", "query", "queryInHeader"}, c.XPaddingPlacement) {
		return "xPaddingPlacement is not one Xray knows"
	}
	if !slices.Contains([]string{"", "repeat-x", "tokenish"}, c.XPaddingMethod) {
		return "xPaddingMethod is not one Xray knows"
	}
	if !slices.Contains([]string{"", "path", "cookie", "header", "query"}, c.SessionPlacement) {
		return "sessionPlacement is not one Xray knows"
	}
	if !slices.Contains([]string{"", "path", "cookie", "header", "query"}, c.SeqPlacement) {
		return "seqPlacement is not one Xray knows"
	}
	if !slices.Contains([]string{"", "auto", "body", "cookie", "header"}, c.UplinkDataPlacement) {
		return "uplinkDataPlacement is not one Xray knows"
	}
	if (c.UplinkDataPlacement == "cookie" || c.UplinkDataPlacement == "header") && mode != "packet-up" {
		return "uplinkDataPlacement " + c.UplinkDataPlacement + " needs mode packet-up"
	}
	if strings.EqualFold(c.UplinkHTTPMethod, "GET") && mode != "packet-up" {
		return "uplinkHTTPMethod GET needs mode packet-up"
	}
	if c.ServerMaxHeaderBytes < 0 {
		return "serverMaxHeaderBytes is negative"
	}
	if c.Xmux.MaxConnections.to > 0 && c.Xmux.MaxConcurrency.to > 0 {
		return "xmux cannot limit both maxConnections and maxConcurrency"
	}
	return ""
}

// checkDownload checks the downloadSettings of an extra, strictly. Xray v26.3.27
// takes a downloadSettings without an address, or with another network than
// XHTTP, and then panics at the first dial through the member (the splithttp
// dialer dereferences its destination and asserts its settings are XHTTP's): so
// both are required here, with everything else this driver checks.
func checkDownload(raw json.RawMessage) string {
	var d downloadSettings
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return decodeReason(err)
	}
	if d.Address == nil || *d.Address == "" {
		return "address missing"
	}
	if err := providers.CheckServerAddress(*d.Address); err != nil {
		return "address: " + err.Error()
	}
	if d.Port == 0 {
		return "port missing"
	}
	if d.Network == nil {
		return "network missing (it must be xhttp)"
	}
	if n := strings.ToLower(*d.Network); n != "xhttp" && n != "splithttp" {
		return "network is not xhttp"
	}
	if !emptyObject(d.Sockopt) {
		return "sockopt is taken only when it is empty"
	}
	if !emptyObject(d.FinalMask) {
		return "finalmask is taken only when it is empty"
	}
	switch strings.ToLower(d.Security) {
	case "", "none":
	case "tls":
		if t := d.TLS; t != nil {
			if t.AllowInsecure {
				return "tlsSettings: allowInsecure is removed from Xray"
			}
			if _, ok := tlsFingerprint(t.Fingerprint); !ok {
				return "tlsSettings: not a TLS fingerprint Xray knows"
			}
			if t.ALPN != nil {
				for _, p := range *t.ALPN {
					if p == "" || len(p) > 255 {
						return "tlsSettings: alpn has an empty or overlong protocol name"
					}
				}
			}
		}
	case "reality":
		r := d.Reality
		if r == nil {
			return "realitySettings missing"
		}
		key := r.PublicKey
		if r.Password != "" {
			key = r.Password
		}
		if rs, field, reason := realityOf(r.ServerName, r.Fingerprint, key, r.ShortID, r.SpiderX); rs == nil {
			return "realitySettings: " + field + ": " + reason
		}
	default:
		return "security is not one Xray knows"
	}
	// Xray builds xhttpSettings, or splithttpSettings when there is no
	// xhttpSettings; both are decoded, so both are checked.
	for _, s := range []struct {
		name string
		x    *downloadXHTTP
	}{{"xhttpSettings", d.XHTTP}, {"splithttpSettings", d.SplitHTTP}} {
		if s.x == nil {
			continue
		}
		if !slices.Contains([]string{"", "auto", "packet-up", "stream-up", "stream-one"}, s.x.Mode) {
			return s.name + ": mode is not one Xray knows"
		}
		mode := s.x.Mode
		if mode == "" {
			mode = "auto"
		}
		if reason := checkXHTTP(s.x.xhttpCommon, mode); reason != "" {
			return s.name + ": " + reason
		}
	}
	return ""
}

// decodeReason says why the decoding of an extra failed, naming the field by
// the mirrors' own names only: the path of a decode error holds the keys of the
// input as they are spelled (a header name, say), which is text of the link.
func decodeReason(err error) string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		if path := safeFieldPath(typeErr.Field); path != "" {
			return "the value of " + path + " is not of the type Xray takes"
		}
		return "a value is not of the type Xray takes"
	}
	// An unknown field (the error quotes it), a malformed range or list, or
	// broken JSON: nothing of it is repeated.
	return "a field this driver does not check, or a value Xray cannot read"
}

// safeFieldPath keeps the leading elements of the path of a decode error that
// are field names of the mirrors, in the mirrors' spelling, and stops after
// headers, whose keys are the input's own.
func safeFieldPath(field string) string {
	var keep []string
	for elem := range strings.SplitSeq(field, ".") {
		name, ok := mirrorFields[strings.ToLower(elem)]
		if !ok {
			break
		}
		keep = append(keep, name)
		if name == "headers" {
			break
		}
	}
	return strings.Join(keep, ".")
}

// mirrorFields are the JSON names of the fields of the mirrors above, by their
// lower case (encoding/json matches names without regard to case).
var mirrorFields = func() map[string]string {
	names := map[string]string{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := range t.NumField() {
			f := t.Field(i)
			if f.Anonymous {
				walk(f.Type)
				continue
			}
			if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
				names[strings.ToLower(name)] = name
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeFor[xhttpExtra]())
	walk(reflect.TypeFor[downloadSettings]())
	return names
}()
