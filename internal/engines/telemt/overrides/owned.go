package overrides

import "strings"

// The keys that Postern owns: it writes them itself, or it keeps them out of the
// config for a reason, and an override of one is refused with that reason.
//
// A key that is here is not whitelisted, and a whitelisted key is not here (a
// test sees to it). A key that is in neither is simply not supported: telemt has
// many more keys than the whitelist, and most of them are nobody's business yet.

// The reasons, which end up in the messages to admins.
const (
	whyLogLevel = "telemt prints the tg:// link of every user, secret included, at any level above silent, and the container log would keep it"
	whyLookup   = "Postern keeps telemt from looking up its own address, which it would do directly, around the SOCKS port of the edge: there is no STUN, and the address the middle proxy needs is supplied by the agent"
	whyFiles    = "telemt would write a file, and the root file system of its container is read-only: the instance directory is the one place that it may write to, and data_path points there"
	whyListener = "Postern writes the listeners: telemt accepts connections from the edge on one loopback port, and nothing else is bound"
	whyUpstream = "Postern writes the upstreams: everything that telemt connects to leaves through the SOCKS port of the edge, never directly"
	whyUsers    = "Postern writes the users: one user, with the secret of the proxy"
	whyAdTag    = "the ad tag is a setting of the proxy"
	whyNAT      = "the NAT address is the nat_ip of the proxy, or else the exit address of its egress"
	whyMiddle   = "whether the engine uses the middle proxies of Telegram is a setting of the proxy (use_middle_proxy: auto, on or off)"
	whyData     = "the instance directory is Postern's: it is the one place that the engine may write to, and data_path points there"
	whyDomain   = "the domain of the proxy and the host that strangers are masked to are set from the proxy and from its listener"
	whyModes    = "Postern serves fake TLS only: the classic and secure modes stay off"
	whyLinks    = "telemt would print the tg:// links, secrets included, and the container log would keep them"
	whyAPI      = "the control API is the agent's: it is bound to loopback, for the agent only, with a token of the agent's own"
	whyNetwork  = "Postern writes [network] to keep telemt from looking up its own address (see stun_use)"
)

// ownedKeys are the keys that are owned, each with its reason.
var ownedKeys = map[string]string{
	"log_level": whyLogLevel,

	// No lookup of the address of the engine, by STUN or over HTTP.
	"network":                       whyNetwork,
	"stun_use":                      whyLookup,
	"stun_servers":                  whyLookup,
	"stun_tcp_fallback":             whyLookup,
	"stun_nat_probe_concurrency":    whyLookup,
	"stun_iface_mismatch_ignore":    whyLookup,
	"middle_proxy_nat_probe":        whyLookup,
	"middle_proxy_nat_stun":         whyLookup,
	"middle_proxy_nat_stun_servers": whyLookup,
	"http_ip_detect_urls":           whyLookup,
	"cache_public_ip_path":          whyLookup,

	// No files outside the instance directory.
	"beobachten":                  whyFiles,
	"beobachten_minutes":          whyFiles,
	"beobachten_flush_secs":       whyFiles,
	"beobachten_file":             whyFiles,
	"unknown_dc_file_log_enabled": whyFiles,
	"unknown_dc_log_path":         whyFiles,
	"data_path":                   whyData,

	// Listeners.
	"server":                           whyListener,
	"listeners":                        whyListener,
	"port":                             whyListener,
	"max_connections":                  whyListener,
	"accept_permit_timeout_ms":         whyListener,
	"client_mss":                       whyListener,
	"client_mss_bulk":                  whyListener,
	"proxy_protocol":                   whyListener,
	"proxy_protocol_header_timeout_ms": whyListener,
	"proxy_protocol_trusted_cidrs":     whyListener,
	"announce":                         whyListener,
	"announce_ip":                      whyListener,
	"reuse_allow":                      whyListener,
	"conntrack_control":                whyListener,

	// Upstreams.
	"upstreams": whyUpstream,
	"scopes":    whyUpstream,

	// Users and what hangs on them.
	"access": whyUsers,
	"users":  whyUsers,

	// What the proxy itself sets.
	"ad_tag":              whyAdTag,
	"middle_proxy_nat_ip": whyNAT,
	"use_middle_proxy":    whyMiddle,
	"tls_domain":          whyDomain,
	"tls_domains":         whyDomain,
	"mask":                whyDomain,
	"mask_host":           whyDomain,
	"mask_port":           whyDomain,
	"mask_unix_sock":      whyDomain,
	"tls_fetch_scope":     whyDomain,
	"classic":             whyModes,
	"secure":              whyModes,
	"tls":                 whyModes,
	"show":                whyLinks,
	"show_link":           whyLinks,
	"public_host":         whyLinks,
	"public_port":         whyLinks,

	// The control API.
	"api":         whyAPI,
	"admin_api":   whyAPI,
	"auth_header": whyAPI,
	"whitelist":   whyAPI,
}

// ownedPrefixes catch the keys of a family, so that a key that a later telemt
// adds to it is owned as well. They are checked after ownedKeys. None of them
// begins any whitelisted key.
var ownedPrefixes = []struct{ prefix, reason string }{
	{"beobachten", whyFiles},
	{"stun", whyLookup},
	{"middle_proxy_nat_", whyLookup},
	{"listen", whyListener},
	{"proxy_protocol", whyListener},
	{"metrics_", whyListener},
	{"synlimit", whyListener},
	{"user_", whyUsers},
}

// Owned reports whether Postern owns a key of the telemt config, and gives the
// reason that an override of it is refused for. The match is exact: a key in
// another letter case, or with spaces around it, is not telemt's key.
func Owned(key string) (reason string, ok bool) {
	if reason, ok := ownedKeys[key]; ok {
		return reason, true
	}
	for _, p := range ownedPrefixes {
		if strings.HasPrefix(key, p.prefix) {
			return p.reason, true
		}
	}
	return "", false
}
