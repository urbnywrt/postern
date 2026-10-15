package telemt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Support code of the integration test that needs no Docker: reading what the
// watcher container reports, and handling the engine's log. It lives in a file
// without the integration build tag so that a plain `go test` covers it, and not
// only the machines that have a daemon.

// ---- addresses as /proc writes them ----------------------------------------------

// procAddr writes an address the way /proc/net/{tcp,tcp6,udp,udp6} does: hex,
// each 32-bit word of the address in host (little endian) byte order, then the
// port in hex. It is written independently of parseProcAddr, as a cross-check.
func procAddr(t *testing.T, ip string, port uint16) string {
	t.Helper()
	a, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatal(err)
	}
	raw := a.AsSlice()
	var b strings.Builder
	for w := 0; w < len(raw); w += 4 {
		for i := 3; i >= 0; i-- {
			fmt.Fprintf(&b, "%02X", raw[w+i])
		}
	}
	return fmt.Sprintf("%s:%04X", b.String(), port)
}

func TestParseProcAddr(t *testing.T) {
	tests := []struct {
		ip   string
		port uint16
		hex  string // what the kernel prints, spelled out by hand for the known cases
	}{
		{"127.0.0.1", 8080, "0100007F:1F90"},
		{"0.0.0.0", 0, "00000000:0000"},
		{"203.0.113.9", 443, "097100CB:01BB"},
		{"192.0.2.1", 53, "010200C0:0035"},
		{"::", 0, "00000000000000000000000000000000:0000"},
		{"::1", 25000, "00000000000000000000000001000000:61A8"},
		{"2001:db8::1", 443, "B80D0120000000000000000001000000:01BB"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := procAddr(t, tt.ip, tt.port); got != tt.hex {
				t.Fatalf("test encoder: %s:%d = %s, want %s", tt.ip, tt.port, got, tt.hex)
			}
			ap, err := parseProcAddr(tt.hex)
			if err != nil {
				t.Fatal(err)
			}
			want := netip.AddrPortFrom(netip.MustParseAddr(tt.ip), tt.port)
			if ap != want {
				t.Errorf("parseProcAddr(%s) = %v, want %v", tt.hex, ap, want)
			}
		})
	}

	// IPv4 inside an IPv6 socket is ::ffff:a.b.c.d, in the same word order.
	ap, err := parseProcAddr("0000000000000000FFFF00000100007F:1F90")
	if err != nil {
		t.Fatal(err)
	}
	if ap.Addr().Unmap() != netip.MustParseAddr("127.0.0.1") || ap.Port() != 8080 {
		t.Errorf("v4-mapped loopback parsed as %v", ap)
	}

	for _, bad := range []string{"", "0100007F", "0100007F:", ":1F90", "0100007F:ZZZZ", "0100007F:10000", "01007F:1F90", "GG00007F:1F90", "0100007F:1F90:1"} {
		if ap, err := parseProcAddr(bad); err == nil {
			t.Errorf("parseProcAddr(%q) = %v, want an error", bad, ap)
		}
	}
}

// parseProcAddr reads an address from /proc/net/tcp, tcp6, udp or udp6, "<hex
// ip>:<hex port>", where the address is written as 32-bit words in host (little
// endian) byte order.
func parseProcAddr(s string) (netip.AddrPort, error) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("no colon")
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", ipHex)
	}
	for w := 0; w < len(raw); w += 4 {
		slices.Reverse(raw[w : w+4])
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// ---- the report of the watcher ----------------------------------------------------

func TestParseWatchReport(t *testing.T) {
	const zero = "00000000:0000"
	zero6 := "00000000000000000000000000000000:0000"
	at := func(ip string, port uint16) string { return procAddr(t, ip, port) }
	lo := func(port uint16) string { return at("127.0.0.1", port) }

	line := func(file, local, remote, state string) string {
		return "/proc/net/" + file + " " + local + " " + remote + " " + state
	}
	report := func(lines ...string) string { return "found 4242\n" + strings.Join(lines, "\n") + "\n" }

	tests := []struct {
		name      string
		out       string
		found     bool
		listening []string // "ip:port", sorted
		outside   []string
	}{
		{
			name:      "only listening sockets",
			out:       report(line("tcp", lo(20123), zero, "0A"), line("tcp", lo(25123), zero, "0A")),
			found:     true,
			listening: []string{"127.0.0.1:20123", "127.0.0.1:25123"},
		},
		{
			name:      "listening sockets that differ only in the port are two",
			out:       report(line("tcp", lo(2), zero, "0A"), line("tcp", lo(1), zero, "0A")),
			found:     true,
			listening: []string{"127.0.0.1:1", "127.0.0.1:2"},
		},
		{
			name:      "the same socket twice is one",
			out:       report(line("tcp", lo(20123), zero, "0A"), line("tcp", lo(20123), zero, "0A")),
			found:     true,
			listening: []string{"127.0.0.1:20123"},
		},
		{
			name:      "a listener on an ipv6 socket, also the v4-mapped kind",
			out:       report(line("tcp6", at("::1", 30000), zero6, "0A"), line("tcp6", at("::ffff:127.0.0.1", 30001), zero6, "0A")),
			found:     true,
			listening: []string{"127.0.0.1:30001", "[::1]:30000"},
		},
		{
			name: "connections between loopback addresses",
			out: report(
				line("tcp", lo(20123), zero, "0A"),
				line("tcp", lo(20123), lo(40000), "01"),
				line("tcp", at("127.0.0.9", 5), at("127.0.0.1", 6), "01"),
				line("tcp6", at("::1", 5), at("::1", 6), "01"),
				line("tcp6", at("::ffff:127.0.0.1", 5), at("::ffff:127.0.0.1", 6), "01")),
			found:     true,
			listening: []string{"127.0.0.1:20123"},
		},
		{
			name:  "unconnected and bound-only udp sockets are not connections",
			out:   report(line("udp", at("192.0.2.7", 40001), zero, "07"), line("udp6", at("::", 40002), zero6, "07")),
			found: true,
		},
		{
			name:  "dns is let through, over udp and tcp, v4 and v6",
			out:   report(line("udp", at("192.0.2.7", 40001), at("192.0.2.53", 53), "01"), line("tcp", at("192.0.2.7", 40002), at("192.0.2.53", 53), "01"), line("udp6", at("2001:db8::7", 40003), at("2001:db8::53", 53), "01")),
			found: true,
		},
		{
			name:      "a connection to a public address",
			out:       report(line("tcp", lo(20123), zero, "0A"), line("tcp", at("192.0.2.7", 40001), at("203.0.113.9", 443), "01")),
			found:     true,
			listening: []string{"127.0.0.1:20123"},
			outside:   []string{"tcp ESTABLISHED, remote port 443"},
		},
		{
			name: "a connection that is being set up, a closing one, and a udp flow",
			out: report(
				line("tcp", at("192.0.2.7", 40001), at("198.51.100.1", 443), "02"),
				line("tcp", at("192.0.2.7", 40002), at("198.51.100.1", 443), "08"),
				line("udp", at("192.0.2.7", 40003), at("198.51.100.2", 19302), "01")),
			found:   true,
			outside: []string{"tcp SYN_SENT, remote port 443", "tcp CLOSE_WAIT, remote port 443", "udp connected, remote port 19302"},
		},
		{
			name:    "a public ipv6 address",
			out:     report(line("tcp6", at("2001:db8::7", 40001), at("2001:db8::1", 8443), "01")),
			found:   true,
			outside: []string{"tcp6 ESTABLISHED, remote port 8443"},
		},
		{
			name:    "a v4-mapped public address",
			out:     report(line("tcp6", at("::ffff:192.0.2.7", 40001), at("::ffff:203.0.113.9", 443), "01")),
			found:   true,
			outside: []string{"tcp6 ESTABLISHED, remote port 443"},
		},
		{
			name:    "a public address on port 80 is not dns",
			out:     report(line("tcp", at("192.0.2.7", 40001), at("203.0.113.9", 80), "01")),
			found:   true,
			outside: []string{"tcp ESTABLISHED, remote port 80"},
		},
		{
			name:    "a udp socket with a state of its own",
			out:     report(line("udp", at("192.0.2.7", 40001), at("203.0.113.9", 4000), "0A")),
			found:   true,
			outside: []string{"udp state 0A, remote port 4000"},
		},
		{name: "the engine was never found", out: "", found: false},
		{name: "found, nothing seen yet", out: "found 7\n", found: true},
		{
			name:      "blank lines and padding are fine",
			out:       "\n found 1 \n\n  " + line("tcp", lo(20123), zero, "0A") + "  \n\n",
			found:     true,
			listening: []string{"127.0.0.1:20123"},
		},
		{
			name:      "lower case hex",
			out:       report(line("tcp", strings.ToLower(lo(20123)), strings.ToLower(zero), "0a")),
			found:     true,
			listening: []string{"127.0.0.1:20123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWatchReport(tt.out)
			if err != nil {
				t.Fatal(err)
			}
			if got.Found != tt.found {
				t.Errorf("Found = %v, want %v", got.Found, tt.found)
			}
			var listening []string
			for _, ap := range got.Listening {
				listening = append(listening, ap.String())
			}
			if !slices.Equal(listening, tt.listening) {
				t.Errorf("Listening = %q, want %q (sorted)", listening, tt.listening)
			}
			slices.Sort(got.Outside)
			want := slices.Clone(tt.outside)
			slices.Sort(want)
			if !slices.Equal(got.Outside, want) {
				t.Errorf("Outside = %q, want %q", got.Outside, want)
			}
		})
	}
}

// A report that cannot be read must not be taken for "nothing outside": that
// would let the check pass on garbage.
func TestParseWatchReportRejectsGarbage(t *testing.T) {
	ok := "0100007F:1F90"
	for _, out := range []string{
		"found 1\nthis is not a socket line\n",
		"found 1\n/proc/net/tcp " + ok + " " + ok + "\n",               // no state
		"found 1\n/proc/net/tcp " + ok + " 0A\n",                       // the old format, without the local address
		"found 1\n/proc/net/tcp " + ok + " " + ok + " 0A extra\n",      // too much
		"found 1\n/proc/net/tcp XXXXXXXX:1F90 " + ok + " 0A\n",         // bad local address
		"found 1\n/proc/net/tcp " + ok + " XXXXXXXX:1F90 0A\n",         // bad remote address
		"found 1\n/proc/net/tcp " + ok + " " + ok + " ZZ\n",            // bad state
		"found 1\n/proc/net/tcp " + ok + " " + ok + " 0A0A\n",          // state of two bytes
		"found 1\n/proc/net/tcp " + ok + " " + ok + " 0\n",             // state of half a byte
		"found 1\n/proc/net/tcp 0100007F:99999 " + ok + " 0A\n",        // port out of range
		"found 1\n/proc/net/tcp 0100007F " + ok + " 0A\n",              // no port
		"found 1\n/proc/net/tcp 01007F:1F90 " + ok + " 0A\n",           // three bytes of address
		"found 1\n/proc/net/tcp " + ok + " " + ok + " 0A\n\ngarbage\n", // garbage after good lines
	} {
		if got, err := parseWatchReport(out); err == nil {
			t.Errorf("parseWatchReport(%q) = %+v, want an error", out, got)
		}
	}
}

// The addresses of an outside socket are not part of what is reported: the
// message ends up in test output, and the machine's own address does not belong
// there.
func TestParseWatchReportDoesNotRepeatAddresses(t *testing.T) {
	got, err := parseWatchReport("found 1\n/proc/net/tcp " + procAddr(t, "192.0.2.7", 40001) + " " + procAddr(t, "203.0.113.9", 443) + " 01\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Outside) != 1 {
		t.Fatalf("Outside = %q, want one socket", got.Outside)
	}
	for _, s := range got.Outside {
		for _, secret := range []string{"203.0.113.9", "192.0.2.7", "097100CB", "070200C0"} {
			if strings.Contains(s, secret) {
				t.Errorf("%q repeats an address (%s)", s, secret)
			}
		}
	}
}

// watchReport is what the watcher container of the integration test reports
// about the engine process: the sockets it held while the watcher looked.
type watchReport struct {
	// Found says that the watcher found the engine process.
	Found bool
	// Listening are the addresses the engine listens on over TCP, as far as the
	// watcher saw: sorted, each once, IPv4-mapped IPv6 addresses as IPv4.
	Listening []netip.AddrPort
	// Outside lists the sockets connected to something outside the loopback, each
	// as "<proto> <state>, remote port <n>": never with the address, which is the
	// address of the machine the test runs on, or of a third party. Connections to
	// port 53 are left out: telemt resolves host names itself, through the system
	// resolver (to be replaced by a resolver of the node's own in a later slice).
	Outside []string
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// parseWatchReport reads the output of the watcher: a line "found <pid>" once it
// has found the engine, and then one line per distinct socket, "/proc/net/<proto>
// <local address> <remote address> <state>", the last three as the kernel writes
// them. Anything it cannot read is an error, so that garbage is never taken for
// "nothing outside".
func parseWatchReport(out string) (watchReport, error) {
	var r watchReport
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
			continue
		case f[0] == "found":
			r.Found = true
			continue
		case len(f) != 4:
			return r, fmt.Errorf("unexpected line %q", line)
		}
		proto := path.Base(f[0])
		local, err := parseProcAddr(f[1])
		if err != nil {
			return r, fmt.Errorf("line %q: local address: %w", line, err)
		}
		remote, err := parseProcAddr(f[2])
		if err != nil {
			return r, fmt.Errorf("line %q: remote address: %w", line, err)
		}
		state := strings.ToUpper(f[3])
		if b, err := hex.DecodeString(state); err != nil || len(b) != 1 {
			return r, fmt.Errorf("line %q: bad state", line)
		}
		isTCP := strings.HasPrefix(proto, "tcp")
		if isTCP && state == "0A" {
			ap := netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
			if !slices.Contains(r.Listening, ap) {
				r.Listening = append(r.Listening, ap)
			}
			continue
		}
		// (netip takes ::ffff:a.b.c.d for a.b.c.d in both of these.)
		if remote.Addr().IsUnspecified() || remote.Addr().IsLoopback() || remote.Port() == 53 {
			continue
		}
		name := tcpStates[state]
		switch {
		case !isTCP && state == "01":
			name = "connected"
		case !isTCP && state == "07":
			name = "unconnected"
		case !isTCP || name == "":
			name = "state " + state
		}
		r.Outside = append(r.Outside, fmt.Sprintf("%s %s, remote port %d", proto, name, remote.Port()))
	}
	slices.SortFunc(r.Listening, func(a, b netip.AddrPort) int { return strings.Compare(a.String(), b.String()) })
	return r, nil
}

// ---- the engine's log -------------------------------------------------------------

// A line of telemt's log as it is on the wire: coloured, with the address behind
// the colour code of the next field, so right behind the letter "m" of an escape
// sequence. (Telemt colours its output even when it is not a terminal.)
const sampleLogLine = "\x1b[2m2026-10-04T03:26:02.066956Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2mtelemt::network::probe\x1b[0m\x1b[2m:\x1b[0m " +
	"STUN unavailable, using HTTP public IPv4 fallback \x1b[3mpublic_ip\x1b[0m\x1b[2m=\x1b[0m203.0.113.9"

func TestStripANSI(t *testing.T) {
	if got, want := stripANSI("\x1b[2m12:00\x1b[0m \x1b[1;32mOK\x1b[0m plain"), "12:00 OK plain"; got != want {
		t.Errorf("stripANSI = %q, want %q", got, want)
	}
	if got := stripANSI("no escapes at all"); got != "no escapes at all" {
		t.Errorf("stripANSI changed a plain line: %q", got)
	}
	if got := stripANSI(sampleLogLine); strings.Contains(got, "\x1b") || !strings.HasSuffix(got, "public_ip=203.0.113.9") {
		t.Errorf("stripANSI(sample) = %q", got)
	}
}

func TestMaskIPv4(t *testing.T) {
	tests := map[string]string{
		"public_ip=203.0.113.9":          "public_ip=x.x.x.x",
		"m203.0.113.9m":                  "mx.x.x.xm", // letters around an address do not hide it
		"a 192.0.2.1 and 198.51.100.250": "a x.x.x.x and x.x.x.x",
		"127.0.0.1:20123":                "x.x.x.x:20123",
		"version 3.5.13 is not one":      "version 3.5.13 is not one", // three groups only
		"nothing to see":                 "nothing to see",
	}
	for in, want := range tests {
		if got := maskIPv4(in); got != want {
			t.Errorf("maskIPv4(%q) = %q, want %q", in, got, want)
		}
	}
}

// This is the leak the first run of the integration test showed: with the
// colour codes in the line, an address that sits behind one was not masked.
func TestDiscoveryLinesMaskAddressesBehindColourCodes(t *testing.T) {
	got := discoveryLines(sampleLogLine)
	if strings.Contains(got, "203.0.113.9") {
		t.Errorf("discoveryLines repeats the address:\n%s", got)
	}
	if !strings.Contains(got, "STUN unavailable, using HTTP public IPv4 fallback") || !strings.Contains(got, "x.x.x.x") {
		t.Errorf("discoveryLines lost the line:\n%s", got)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("discoveryLines keeps the colour codes:\n%q", got)
	}
}

func TestDiscoveryLines(t *testing.T) {
	log := strings.Join([]string{
		"MAESTRO: Telemt MTProxy v3.5.13",
		"2026-10-04T03:26:01Z INFO telemt::network::probe: STUN probe is disabled by network.stun_use=false",
		"2026-10-04T03:26:01Z INFO telemt::maestro::listeners::bind: Listening on TCP endpoint addr=127.0.0.1:20123",
		"2026-10-04T03:26:02Z INFO telemt::network::probe: STUN-Quorum reached, IP: 203.0.113.9",
		"2026-10-04T03:26:02Z INFO telemt::network::probe: stun probe failed error=timeout stun=192.0.2.7:3478",
		"2026-10-04T03:26:02Z INFO telemt::network::probe: using http public IPv4 fallback public_ip=198.51.100.4",
		"2026-10-04T03:26:03Z WARN telemt::tls_front: TLS-front fetch not ready within timeout",
	}, "\n")
	got := discoveryLines(log)
	lines := strings.Split(got, "\n")
	if len(lines) != 4 {
		t.Fatalf("discoveryLines kept %d lines, want the 4 about STUN and the HTTP lookup:\n%s", len(lines), got)
	}
	for _, addr := range []string{"203.0.113.9", "192.0.2.7", "198.51.100.4"} {
		if strings.Contains(got, addr) {
			t.Errorf("discoveryLines repeats %s:\n%s", addr, got)
		}
	}
	if strings.Contains(got, "127.0.0.1") || strings.Contains(got, "Listening") {
		t.Errorf("discoveryLines kept a line that is not about the lookup:\n%s", got)
	}
	if got := discoveryLines("nothing about it\nat all"); got != "  (none)" {
		t.Errorf("discoveryLines of an unrelated log = %q, want the none marker", got)
	}
}

var (
	ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	// No \b around it: the colour codes of telemt's log put a letter right
	// before an address, and a word boundary would then let it through.
	ipv4Address = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
)

// stripANSI removes colour codes from a line of telemt's log.
func stripANSI(s string) string { return ansiEscape.ReplaceAllString(s, "") }

// maskIPv4 blanks out IPv4 addresses.
func maskIPv4(s string) string { return ipv4Address.ReplaceAllString(s, "x.x.x.x") }

// discoveryLines returns the lines of a log that are about telemt looking up its
// own address (STUN, or HTTP), without colour codes and with IPv4 addresses
// blanked out, indented for a message.
func discoveryLines(log string) string {
	var out []string
	for line := range strings.SplitSeq(stripANSI(log), "\n") {
		if u := strings.ToUpper(line); strings.Contains(u, "STUN") || strings.Contains(u, "HTTP PUBLIC") {
			out = append(out, "  "+maskIPv4(line))
		}
	}
	if len(out) == 0 {
		return "  (none)"
	}
	return strings.Join(out, "\n")
}
