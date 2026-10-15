// Package panelurl is the rule for the address that a node reaches the panel
// at: one rule for the panel, which renders the install command, and for the
// node, which reads it from POSTERN_JOIN. It imports nothing of the panel, so
// that the node binary can use it.
package panelurl

import (
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Check checks the address that a node reaches the panel at and returns it in
// its normal form: https://host[:port], the scheme and the host in lower
// case, without a trailing "/". It takes no path other than "/", no query, no
// fragment and no user name, and http:// only for a loopback host
// (127.0.0.0/8, ::1 or localhost). What it returns holds only lower-case
// letters, digits and ".-:/[]", so that it is safe in the quotes of a rendered
// command. Its errors never quote the input.
func Check(raw string) (string, error) {
	const form = "it must be https://host[:port], or http:// for a loopback host"
	if raw == "" {
		return "", errors.New("it is empty: " + form)
	}
	if strings.ContainsAny(raw, "?#@\\ '\"") || strings.IndexFunc(raw, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", errors.New(form + ", with no query, fragment, user name or other characters")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return "", errors.New(form)
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New(form + ", with no path")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", errors.New(form)
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New(form + ": the port is empty")
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", errors.New("the port must be a number from 1 to 65535")
		}
	}
	loopback := host == "localhost"
	shown := host
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", errors.New(form + ", with no IPv6 zone")
		}
		if addr.Is4In6() {
			return "", errors.New(form + ", with an IPv4 address in its own form")
		}
		loopback = addr.IsLoopback()
		if addr.Is6() {
			shown = "[" + addr.String() + "]"
		} else {
			shown = addr.String()
		}
	} else if strings.Contains(u.Host, "[") || !hostNameRe.MatchString(host) || len(host) > 253 {
		return "", errors.New(form + ": the host is neither an IP address nor a host name")
	}
	if scheme == "http" && !loopback {
		return "", errors.New("http:// is only for a loopback host: use https://")
	}
	out := scheme + "://" + shown
	if port != "" {
		out += ":" + port
	}
	return out, nil
}

// hostNameRe is a host name in lower case: labels of letters, digits and
// hyphens.
var hostNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
