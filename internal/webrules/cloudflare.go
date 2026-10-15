package webrules

import "net/netip"

// CloudflareRanges are the addresses of Cloudflare's proxy as published when
// this version was built (https://www.cloudflare.com/ips-v4 and ips-v6): a
// domain that resolves to one of them is behind the orange cloud, which a WEB
// proxy on a tls listener cannot be. The panel's preflight refreshes its copy
// from the published lists; the node's web.dns check uses these.
var CloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
}

var cloudflarePrefixes = func() []netip.Prefix {
	out := make([]netip.Prefix, len(CloudflareRanges))
	for i, s := range CloudflareRanges {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}()

// IsCloudflare reports whether addr is in CloudflareRanges.
func IsCloudflare(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range cloudflarePrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
