package proxyproto_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"testing/iotest"
	"time"

	"github.com/urbnywrt/postern/internal/proxyproto"
)

// ---------------------------------------------------------------------------
// Wire-format helpers. Everything the tests expect from the encoder is spelled
// out by hand, byte by byte, after the specification (HAProxy, "The PROXY
// protocol", section 2.2), so that the tests share no code with the encoder and
// the parser they check.
// ---------------------------------------------------------------------------

// signature is the 12-byte block that opens every v2 header, in the hex form of
// the specification. TestSignatureSpelling ties it to its string form.
var signature = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

const (
	verCmdProxy = 0x21 // version 2, command PROXY
	verCmdLocal = 0x20 // version 2, command LOCAL
	famTCP4     = 0x11 // AF_INET, STREAM
	famTCP6     = 0x21 // AF_INET6, STREAM

	fixedLen   = 16   // signature, version/command, family, length
	maxPayload = 1024 // the longest payload ReadV2 accepts
)

// mapped is the 12-byte prefix of an IPv4-mapped IPv6 address.
var mapped = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

// Sample addresses, all from the documentation ranges.
var (
	v4Src = ap("192.0.2.10:51000") // port 51000 is 0xc738
	v4Dst = ap("198.51.100.1:443") // port 443 is 0x01bb
	v6Src = ap("[2001:db8::1]:51000")
	v6Dst = ap("[2001:db8:ffff::2]:443")
)

// tail stands for the bytes that follow the header on a real connection, here
// the start of a TLS ClientHello. Tests append it to a header to see that the
// parser leaves it alone.
var tail = []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03}

var (
	errReset  = errors.New("connection reset by peer")
	errSilent = errors.New("peer fell silent")
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func u16(v int) []byte {
	if v < 0 || v > 0xffff {
		panic(fmt.Sprintf("u16(%d): out of range", v))
	}
	return []byte{byte(v >> 8), byte(v)}
}

// rawHeader assembles a header from its parts: signature, version/command byte,
// family byte, length field and payload. The length field is a parameter of its
// own so that a test can lie about it; framed fills in the true length.
func rawHeader(verCmd, fam byte, length int, payload []byte) []byte {
	return cat(signature, []byte{verCmd, fam}, u16(length), payload)
}

func framed(verCmd, fam byte, payload []byte) []byte {
	return rawHeader(verCmd, fam, len(payload), payload)
}

// addrBlock4 and addrBlock6 lay out the address block of an IPv4 and an IPv6
// header: source address, destination address, source port, destination port.
func addrBlock4(src, dst netip.AddrPort) []byte {
	s, d := src.Addr().As4(), dst.Addr().As4()
	return cat(s[:], d[:], u16(int(src.Port())), u16(int(dst.Port())))
}

func addrBlock6(src, dst netip.AddrPort) []byte {
	s, d := src.Addr().As16(), dst.Addr().As16()
	return cat(s[:], d[:], u16(int(src.Port())), u16(int(dst.Port())))
}

// tlv encodes one TLV vector: type, two-byte length, value.
func tlv(typ byte, value []byte) []byte { return cat([]byte{typ}, u16(len(value)), value) }

// scripted serves its chunks, one Read call each, and fails every Read after
// them with err. It stands for a peer that sent exactly those bytes and then
// fell silent or dropped: a ReadV2 that needs one byte more than its verdict
// requires gets err instead of the verdict.
type scripted struct {
	chunks [][]byte
	err    error
}

func (s *scripted) Read(p []byte) (int, error) {
	if len(s.chunks) == 0 {
		return 0, s.err
	}
	n := copy(p, s.chunks[0])
	if n == len(s.chunks[0]) {
		s.chunks = s.chunks[1:]
	} else {
		s.chunks[0] = s.chunks[0][n:]
	}
	return n, nil
}

// callRecorder keeps every Write call apart.
type callRecorder struct{ calls [][]byte }

func (c *callRecorder) Write(p []byte) (int, error) {
	c.calls = append(c.calls, bytes.Clone(p))
	return len(p), nil
}

// fixedWriter reports n bytes written (all of them when n is out of range) and
// err, whatever it is given.
type fixedWriter struct {
	n   int
	err error
}

func (w fixedWriter) Write(p []byte) (int, error) {
	n := w.n
	if n < 0 || n > len(p) {
		n = len(p)
	}
	return n, w.err
}

// mustRead parses header followed by tail and requires that ReadV2 accepts it
// and consumes exactly the header, no more and no less.
func mustRead(t *testing.T, header []byte) *proxyproto.Header {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(cat(header, tail)))
	h, err := proxyproto.ReadV2(r)
	if err != nil {
		t.Fatalf("ReadV2(%x): %v", header, err)
	}
	if rest, err := io.ReadAll(r); err != nil || !bytes.Equal(rest, tail) {
		t.Fatalf("ReadV2(%x) left %x (read error %v) behind the header, want exactly %x", header, rest, err, tail)
	}
	return h
}

// addrCases covers every combination of address families the encoder handles.
var addrCases = []struct {
	name     string
	src, dst netip.AddrPort
}{
	{"ipv4", v4Src, v4Dst},
	{"ipv6", v6Src, v6Dst},
	{"ipv4 source, ipv6 destination", v4Src, v6Dst},
	{"ipv6 source, ipv4 destination", v6Src, v4Dst},
	{"ipv4-mapped pair", ap("[::ffff:192.0.2.10]:51000"), ap("[::ffff:198.51.100.1]:443")},
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

func TestSignatureSpelling(t *testing.T) {
	if got, want := string(signature), "\r\n\r\n\x00\r\nQUIT\n"; got != want {
		t.Fatalf("test helper: signature = %q, want %q", got, want)
	}
}

// The complete header for each case of TestHeaderV2Golden, byte by byte.
var (
	wantIPv4 = cat(signature, []byte{0x21, 0x11, 0x00, 0x0c},
		[]byte{192, 0, 2, 10}, []byte{198, 51, 100, 1}, []byte{0xc7, 0x38}, []byte{0x01, 0xbb})

	wantIPv6 = cat(signature, []byte{0x21, 0x21, 0x00, 0x24},
		[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
		[]byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02},
		[]byte{0xc7, 0x38}, []byte{0x01, 0xbb})

	// An IPv4 source with an IPv6 destination: both go out as IPv6.
	wantV4ToV6 = cat(signature, []byte{0x21, 0x21, 0x00, 0x24},
		mapped, []byte{192, 0, 2, 10},
		[]byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02},
		[]byte{0xc7, 0x38}, []byte{0x01, 0xbb})

	wantV6ToV4 = cat(signature, []byte{0x21, 0x21, 0x00, 0x24},
		[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
		mapped, []byte{198, 51, 100, 1},
		[]byte{0xc7, 0x38}, []byte{0x01, 0xbb})
)

// TestHeaderV2Golden pins the exact bytes of every kind of header the encoder
// produces.
func TestHeaderV2Golden(t *testing.T) {
	tests := []struct {
		name     string
		src, dst netip.AddrPort
		want     []byte
	}{
		{"ipv4", v4Src, v4Dst, wantIPv4},
		{"ipv6", v6Src, v6Dst, wantIPv6},
		{"ipv4 source, ipv6 destination: both as ipv6", v4Src, v6Dst, wantV4ToV6},
		{"ipv6 source, ipv4 destination: both as ipv6", v6Src, v4Dst, wantV6ToV4},
		{
			"ipv4-mapped addresses count as ipv4",
			ap("[::ffff:192.0.2.10]:51000"), ap("[::ffff:198.51.100.1]:443"),
			wantIPv4,
		},
		{
			"ipv4-mapped source with an ipv6 destination",
			ap("[::ffff:192.0.2.10]:51000"), v6Dst,
			wantV4ToV6,
		},
		{
			"ports at both ends of the range",
			ap("192.0.2.10:0"), ap("198.51.100.1:65535"),
			cat(signature, []byte{0x21, 0x11, 0x00, 0x0c},
				[]byte{192, 0, 2, 10}, []byte{198, 51, 100, 1}, []byte{0x00, 0x00}, []byte{0xff, 0xff}),
		},
		{"the zone of an ipv6 address is dropped", ap("[2001:db8::1%eth0]:51000"), v6Dst, wantIPv6},
		{
			"invalid addresses go out as the unspecified address",
			netip.AddrPort{}, netip.AddrPort{},
			cat(signature, []byte{0x21, 0x21, 0x00, 0x24}, make([]byte, 32), make([]byte, 4)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxyproto.HeaderV2(tt.src, tt.dst); !bytes.Equal(got, tt.want) {
				t.Errorf("HeaderV2(%v, %v)\n got %x\nwant %x", tt.src, tt.dst, got, tt.want)
			}
		})
	}
}

func TestHeaderV2Signature(t *testing.T) {
	for _, tt := range addrCases {
		t.Run(tt.name, func(t *testing.T) {
			h := proxyproto.HeaderV2(tt.src, tt.dst)
			if len(h) < fixedLen {
				t.Fatalf("HeaderV2 returned %d bytes, fewer than the %d of the fixed part", len(h), fixedLen)
			}
			if got, want := string(h[:12]), "\r\n\r\n\x00\r\nQUIT\n"; got != want {
				t.Errorf("signature = %q, want %q", got, want)
			}
		})
	}
}

func TestHeaderV2VersionAndCommand(t *testing.T) {
	for _, tt := range addrCases {
		t.Run(tt.name, func(t *testing.T) {
			h := proxyproto.HeaderV2(tt.src, tt.dst)
			if len(h) < fixedLen {
				t.Fatalf("HeaderV2 returned %d bytes, fewer than the %d of the fixed part", len(h), fixedLen)
			}
			if h[12] != 0x21 {
				t.Errorf("version and command byte = %#02x, want 0x21 (version 2, PROXY)", h[12])
			}
		})
	}
}

// TestHeaderV2Length checks the family byte and that the length field counts
// exactly the bytes after the fixed part.
func TestHeaderV2Length(t *testing.T) {
	tests := []struct {
		name     string
		src, dst netip.AddrPort
		fam      byte
		length   int
	}{
		{"ipv4", v4Src, v4Dst, famTCP4, 12},
		{"ipv6", v6Src, v6Dst, famTCP6, 36},
		{"ipv4 source, ipv6 destination", v4Src, v6Dst, famTCP6, 36},
		{"ipv6 source, ipv4 destination", v6Src, v4Dst, famTCP6, 36},
		{"ipv4-mapped pair", ap("[::ffff:192.0.2.10]:51000"), ap("[::ffff:198.51.100.1]:443"), famTCP4, 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := proxyproto.HeaderV2(tt.src, tt.dst)
			if len(h) != fixedLen+tt.length {
				t.Fatalf("len(HeaderV2) = %d, want %d", len(h), fixedLen+tt.length)
			}
			if h[13] != tt.fam {
				t.Errorf("family byte = %#02x, want %#02x", h[13], tt.fam)
			}
			if got := int(h[14])<<8 | int(h[15]); got != tt.length {
				t.Errorf("length field = %d, want %d", got, tt.length)
			}
		})
	}
}

func TestWriteV2(t *testing.T) {
	for _, tt := range addrCases {
		t.Run(tt.name, func(t *testing.T) {
			var w callRecorder
			if err := proxyproto.WriteV2(&w, tt.src, tt.dst); err != nil {
				t.Fatalf("WriteV2: %v", err)
			}
			// One Write call: the header goes out whole, never torn by the
			// caller's own writes into two segments.
			if want := proxyproto.HeaderV2(tt.src, tt.dst); len(w.calls) != 1 || !bytes.Equal(w.calls[0], want) {
				t.Errorf("WriteV2 wrote %x in %d calls, want %x in one", bytes.Join(w.calls, nil), len(w.calls), want)
			}
		})
	}
}

func TestWriteV2WriterFailures(t *testing.T) {
	tests := []struct {
		name string
		w    io.Writer
		want error
	}{
		{"write fails", fixedWriter{n: 0, err: errReset}, errReset},
		{"write fails half way", fixedWriter{n: 7, err: errReset}, errReset},
		{"short write without an error", fixedWriter{n: 27}, io.ErrShortWrite}, // an IPv4 header is 28 bytes
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := proxyproto.WriteV2(tt.w, v4Src, v4Dst); !errors.Is(err, tt.want) {
				t.Errorf("WriteV2 = %v, want %v", err, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Encoder and parser together
// ---------------------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		src, dst netip.AddrPort
		want     proxyproto.Header
	}{
		{"ipv4", v4Src, v4Dst, proxyproto.Header{Src: v4Src, Dst: v4Dst}},
		{"ipv6", v6Src, v6Dst, proxyproto.Header{Src: v6Src, Dst: v6Dst}},
		{
			// The IPv4 side comes back in its mapped form: it travelled as IPv6.
			"mixed: ipv4 source, ipv6 destination",
			v4Src, v6Dst,
			proxyproto.Header{Src: ap("[::ffff:192.0.2.10]:51000"), Dst: v6Dst},
		},
		{
			"mixed: ipv6 source, ipv4 destination",
			v6Src, v4Dst,
			proxyproto.Header{Src: v6Src, Dst: ap("[::ffff:198.51.100.1]:443")},
		},
		{
			"an ipv4-mapped pair travels as ipv4",
			ap("[::ffff:192.0.2.10]:51000"), ap("[::ffff:198.51.100.1]:443"),
			proxyproto.Header{Src: v4Src, Dst: v4Dst},
		},
		{
			"the zone of an ipv6 address is lost",
			ap("[2001:db8::1%eth0]:51000"), v6Dst,
			proxyproto.Header{Src: v6Src, Dst: v6Dst},
		},
		{
			"ports at both ends of the range",
			ap("192.0.2.10:0"), ap("198.51.100.1:65535"),
			proxyproto.Header{Src: ap("192.0.2.10:0"), Dst: ap("198.51.100.1:65535")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := proxyproto.WriteV2(&buf, tt.src, tt.dst); err != nil {
				t.Fatalf("WriteV2: %v", err)
			}
			h := mustRead(t, buf.Bytes())
			if *h != tt.want {
				t.Errorf("ReadV2 = %+v, want %+v", *h, tt.want)
			}
		})
	}
}

// randomAddrPort returns an arbitrary IPv4, IPv6 or IPv4-mapped IPv6 address
// with an arbitrary port.
func randomAddrPort(rng *rand.Rand) netip.AddrPort {
	port := uint16(rng.Uint32())
	var b [16]byte
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	switch rng.IntN(3) {
	case 0:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[:4])), port)
	case 1:
		return netip.AddrPortFrom(netip.AddrFrom16(b), port)
	default:
		return netip.AddrPortFrom(netip.AddrFrom16(netip.AddrFrom4([4]byte(b[:4])).As16()), port)
	}
}

// TestRoundTripRandom sends arbitrary address pairs through the encoder and the
// parser. The expected family is worked out here independently: IPv4 when both
// addresses are IPv4 (mapped or not), IPv6 otherwise.
func TestRoundTripRandom(t *testing.T) {
	isV4 := func(a netip.Addr) bool { return a.Is4() || a.Is4In6() }
	rng := rand.New(rand.NewPCG(7, 11))
	for range 2000 {
		src, dst := randomAddrPort(rng), randomAddrPort(rng)
		wantFam, wantLen := byte(famTCP6), 36
		if isV4(src.Addr()) && isV4(dst.Addr()) {
			wantFam, wantLen = famTCP4, 12
		}

		hdr := proxyproto.HeaderV2(src, dst)
		if len(hdr) != fixedLen+wantLen || hdr[12] != 0x21 || hdr[13] != wantFam {
			t.Fatalf("HeaderV2(%v, %v) = %x, want version/command 0x21, family %#02x, %d bytes of payload", src, dst, hdr, wantFam, wantLen)
		}

		h := mustRead(t, hdr)
		if h.Local || h.Src.Port() != src.Port() || h.Dst.Port() != dst.Port() ||
			h.Src.Addr().Unmap() != src.Addr().Unmap() || h.Dst.Addr().Unmap() != dst.Addr().Unmap() {
			t.Fatalf("round trip of %v -> %v gave %+v", src, dst, *h)
		}
		// The decoded form follows the family on the wire.
		if wantFam == famTCP4 && (!h.Src.Addr().Is4() || !h.Dst.Addr().Is4()) {
			t.Fatalf("round trip of %v -> %v gave %+v, want IPv4 addresses", src, dst, *h)
		}
		if wantFam == famTCP6 && (!h.Src.Addr().Is6() || !h.Dst.Addr().Is6()) {
			t.Fatalf("round trip of %v -> %v gave %+v, want IPv6 addresses", src, dst, *h)
		}
	}
}

// TestHeaderOverConn is the intended use: the sender writes the header and then
// the connection's own bytes; the receiver reads the header and carries on with
// the same bufio.Reader.
func TestHeaderOverConn(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	sent := make(chan error, 1)
	go func() {
		if err := proxyproto.WriteV2(client, v4Src, v4Dst); err != nil {
			sent <- err
			return
		}
		_, err := client.Write(tail)
		sent <- err
	}()

	r := bufio.NewReader(server)
	h, err := proxyproto.ReadV2(r)
	if err != nil {
		t.Fatalf("ReadV2: %v", err)
	}
	if want := (proxyproto.Header{Src: v4Src, Dst: v4Dst}); *h != want {
		t.Errorf("ReadV2 = %+v, want %+v", *h, want)
	}
	got := make([]byte, len(tail))
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, tail) {
		t.Errorf("after the header read %x (error %v), want %x", got, err, tail)
	}
	if err := <-sent; err != nil {
		t.Errorf("sender: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Parser: accepted headers
// ---------------------------------------------------------------------------

func TestReadV2(t *testing.T) {
	mappedSrc := ap("[::ffff:192.0.2.10]:51000")
	tests := []struct {
		name string
		in   []byte
		want proxyproto.Header
	}{
		{"ipv4", framed(verCmdProxy, famTCP4, addrBlock4(v4Src, v4Dst)), proxyproto.Header{Src: v4Src, Dst: v4Dst}},
		{"ipv6", framed(verCmdProxy, famTCP6, addrBlock6(v6Src, v6Dst)), proxyproto.Header{Src: v6Src, Dst: v6Dst}},
		{
			// What is on the wire is what comes back; Unmap is the caller's call.
			"an ipv4-mapped address in an ipv6 header is returned as sent",
			framed(verCmdProxy, famTCP6, addrBlock6(mappedSrc, v6Dst)),
			proxyproto.Header{Src: mappedSrc, Dst: v6Dst},
		},
		{
			"ports at both ends of the range",
			framed(verCmdProxy, famTCP4, addrBlock4(ap("192.0.2.10:0"), ap("198.51.100.1:65535"))),
			proxyproto.Header{Src: ap("192.0.2.10:0"), Dst: ap("198.51.100.1:65535")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if h := mustRead(t, tt.in); *h != tt.want {
				t.Errorf("ReadV2 = %+v, want %+v", *h, tt.want)
			}
		})
	}
}

// TestReadV2Local covers the LOCAL command: the sender opened the connection
// itself, so the header says nothing about a client. Whatever follows the fixed
// part is discarded, address block and family included.
func TestReadV2Local(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"no payload", framed(verCmdLocal, 0x00, nil)},
		{"an address block is ignored", framed(verCmdLocal, famTCP4, addrBlock4(v4Src, v4Dst))},
		{"the family is ignored", framed(verCmdLocal, 0x99, []byte("ignored"))},
		{"payload of the largest size", framed(verCmdLocal, 0x00, make([]byte, maxPayload))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mustRead(t, tt.in)
			if want := (proxyproto.Header{Local: true}); *h != want {
				t.Errorf("ReadV2 = %+v, want %+v", *h, want)
			}
		})
	}
}

// TestReadV2SkipsTLVs hangs TLV vectors behind the address block. The parser
// consumes them by the length field and does not look inside.
func TestReadV2SkipsTLVs(t *testing.T) {
	block4 := addrBlock4(v4Src, v4Dst)
	block6 := addrBlock6(v6Src, v6Dst)
	want4 := proxyproto.Header{Src: v4Src, Dst: v4Dst}
	want6 := proxyproto.Header{Src: v6Src, Dst: v6Dst}

	// PP2_TYPE_SSL: client flags, verify result, then a nested TLV.
	ssl := tlv(0x20, cat([]byte{0x01}, []byte{0, 0, 0, 0}, tlv(0x21, []byte("TLSv1.3"))))

	tests := []struct {
		name string
		in   []byte
		want proxyproto.Header
	}{
		{"a noop after an ipv4 block", framed(verCmdProxy, famTCP4, cat(block4, tlv(0x04, make([]byte, 5)))), want4},
		{"an empty noop", framed(verCmdProxy, famTCP4, cat(block4, tlv(0x04, nil))), want4},
		{
			"several tlvs after an ipv6 block",
			framed(verCmdProxy, famTCP6, cat(block6,
				tlv(0x01, []byte("h2")), tlv(0x02, []byte("www.example.com")), tlv(0x04, make([]byte, 3)), ssl)),
			want6,
		},
		{
			// The receiver may ignore what it does not understand, and the
			// framing of the vectors is not its business.
			"a tlv area that is not a chain of tlvs",
			framed(verCmdProxy, famTCP4, cat(block4, []byte{0x04, 0xff, 0xff, 0x01})),
			want4,
		},
		{
			"a payload of the largest size",
			framed(verCmdProxy, famTCP6, cat(block6, tlv(0x04, make([]byte, maxPayload-len(block6)-3)))),
			want6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if h := mustRead(t, tt.in); *h != tt.want {
				t.Errorf("ReadV2 = %+v, want %+v", *h, tt.want)
			}
		})
	}
}

// TestReadV2ReaderShapes feeds the same header, TLVs included, through readers
// that deliver it in every awkward way, and through the smallest buffer bufio
// allows: the parser must not depend on how the bytes arrive.
func TestReadV2ReaderShapes(t *testing.T) {
	in := framed(verCmdProxy, famTCP6, cat(addrBlock6(v6Src, v6Dst), tlv(0x04, make([]byte, 20))))
	want := proxyproto.Header{Src: v6Src, Dst: v6Dst}

	whole := func(r io.Reader) io.Reader { return r }
	shapes := []struct {
		name string
		wrap func(io.Reader) io.Reader
		size int
	}{
		{"all at once", whole, 4096},
		{"one byte per read", iotest.OneByteReader, 4096},
		{"half of the request per read", iotest.HalfReader, 4096},
		{"final data and EOF together", iotest.DataErrReader, 4096},
		{"smallest buffer", whole, 16},
		{"smallest buffer, one byte per read", iotest.OneByteReader, 16},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			r := bufio.NewReaderSize(s.wrap(bytes.NewReader(cat(in, tail))), s.size)
			h, err := proxyproto.ReadV2(r)
			if err != nil {
				t.Fatalf("ReadV2: %v", err)
			}
			if *h != want {
				t.Errorf("ReadV2 = %+v, want %+v", *h, want)
			}
			if rest, err := io.ReadAll(r); err != nil || !bytes.Equal(rest, tail) {
				t.Errorf("ReadV2 left %x (read error %v) behind the header, want %x", rest, err, tail)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Parser: rejected input
// ---------------------------------------------------------------------------

func TestReadV2Rejects(t *testing.T) {
	block4 := addrBlock4(v4Src, v4Dst)
	block6 := addrBlock6(v6Src, v6Dst)

	type testCase struct {
		name string
		in   []byte
		want error // matched with errors.Is
	}
	tests := []testCase{
		// Not a v2 header at all.
		{"v1 header, tcp4", []byte("PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\n"), proxyproto.ErrNoSignature},
		{"v1 header, tcp6", []byte("PROXY TCP6 2001:db8::1 2001:db8:ffff::2 51000 443\r\n"), proxyproto.ErrNoSignature},
		{"v1 header, unknown", []byte("PROXY UNKNOWN\r\n"), proxyproto.ErrNoSignature},
		{"http request", []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"), proxyproto.ErrNoSignature},
		{"http request after a blank line", []byte("\r\nGET / HTTP/1.1\r\n\r\n"), proxyproto.ErrNoSignature},
		{"tls client hello", cat([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03}, make([]byte, 40)), proxyproto.ErrNoSignature},
		{"zeros", make([]byte, 64), proxyproto.ErrNoSignature},
		{"0xff bytes", bytes.Repeat([]byte{0xff}, 64), proxyproto.ErrNoSignature},
		{"a stray byte before the signature", cat([]byte{'x'}, framed(verCmdProxy, famTCP4, block4)), proxyproto.ErrNoSignature},
		{"the start of the signature, then text", cat(signature[:4], []byte("GET / HTTP/1.1\r\n")), proxyproto.ErrNoSignature},

		// The signature is there, the rest is not acceptable.
		{"version 0", framed(0x01, famTCP4, block4), proxyproto.ErrMalformed},
		{"version 1", framed(0x11, famTCP4, block4), proxyproto.ErrMalformed},
		{"version 3", framed(0x31, famTCP4, block4), proxyproto.ErrMalformed},
		{"version 15", framed(0xf1, famTCP4, block4), proxyproto.ErrMalformed},
		{"command 2", framed(0x22, famTCP4, block4), proxyproto.ErrMalformed},
		{"command 15", framed(0x2f, famTCP4, block4), proxyproto.ErrMalformed},
		{"unspecified family, no block", framed(verCmdProxy, 0x00, nil), proxyproto.ErrMalformed},
		{"unspecified family with a block", framed(verCmdProxy, 0x00, block4), proxyproto.ErrMalformed},
		{"unspecified transport over ipv4", framed(verCmdProxy, 0x10, block4), proxyproto.ErrMalformed},
		{"unspecified transport over ipv6", framed(verCmdProxy, 0x20, block6), proxyproto.ErrMalformed},
		{"datagram over ipv4", framed(verCmdProxy, 0x12, block4), proxyproto.ErrMalformed},
		{"datagram over ipv6", framed(verCmdProxy, 0x22, block6), proxyproto.ErrMalformed},
		{"unix stream", framed(verCmdProxy, 0x31, make([]byte, 216)), proxyproto.ErrMalformed},
		{"unix datagram", framed(verCmdProxy, 0x32, make([]byte, 216)), proxyproto.ErrMalformed},
		{"unknown family 4", framed(verCmdProxy, 0x41, block4), proxyproto.ErrMalformed},
		{"unknown family and transport", framed(verCmdProxy, 0xff, block4), proxyproto.ErrMalformed},
		{"ipv4 with no block", framed(verCmdProxy, famTCP4, nil), proxyproto.ErrMalformed},
		{"ipv4 block one byte short", framed(verCmdProxy, famTCP4, block4[:len(block4)-1]), proxyproto.ErrMalformed},
		{"ipv6 with no block", framed(verCmdProxy, famTCP6, nil), proxyproto.ErrMalformed},
		{"ipv6 block one byte short", framed(verCmdProxy, famTCP6, block6[:len(block6)-1]), proxyproto.ErrMalformed},
		{"ipv6 with an ipv4-sized block", framed(verCmdProxy, famTCP6, block4), proxyproto.ErrMalformed},

		// The payload limit: 1024 is accepted (see TestReadV2SkipsTLVs), more is not.
		{"proxy payload one byte over the limit", framed(verCmdProxy, famTCP6, cat(block6, make([]byte, maxPayload+1-len(block6)))), proxyproto.ErrMalformed},
		{"proxy payload of 4096 bytes", framed(verCmdProxy, famTCP4, cat(block4, make([]byte, 4096-len(block4)))), proxyproto.ErrMalformed},
		{"local payload one byte over the limit", framed(verCmdLocal, 0x00, make([]byte, maxPayload+1)), proxyproto.ErrMalformed},
		{"proxy length field 65535", rawHeader(verCmdProxy, famTCP4, 65535, block4), proxyproto.ErrMalformed},
		{"local length field 65535", rawHeader(verCmdLocal, 0x00, 65535, nil), proxyproto.ErrMalformed},

		// Nothing at all.
		{"empty input", nil, io.EOF},
	}
	// One altered byte anywhere in the signature.
	for i := range signature {
		in := bytes.Clone(framed(verCmdProxy, famTCP4, block4))
		in[i] ^= 0x01
		tests = append(tests, testCase{fmt.Sprintf("signature byte %d altered", i), in, proxyproto.ErrNoSignature})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewReader(tt.in))
			h, err := proxyproto.ReadV2(r)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ReadV2 error = %v, want %v", err, tt.want)
			}
			if h != nil {
				t.Errorf("ReadV2 returned the header %+v together with the error %v", *h, err)
			}
			// Not v2: nothing was consumed, so a caller could still treat the
			// stream as something else.
			if errors.Is(tt.want, proxyproto.ErrNoSignature) {
				if rest, rerr := io.ReadAll(r); rerr != nil || !bytes.Equal(rest, tt.in) {
					t.Errorf("after ErrNoSignature %d of %d bytes are left, want all of them", len(rest), len(tt.in))
				}
			}
		})
	}
}

// TestReadV2Truncated cuts valid headers off at every possible length. A stream
// that ends before its first byte is a plain io.EOF; one that ends anywhere
// inside a header is io.ErrUnexpectedEOF.
func TestReadV2Truncated(t *testing.T) {
	headers := []struct {
		name string
		in   []byte
	}{
		{"ipv4 with a noop", framed(verCmdProxy, famTCP4, cat(addrBlock4(v4Src, v4Dst), tlv(0x04, make([]byte, 5))))},
		{"ipv6", framed(verCmdProxy, famTCP6, addrBlock6(v6Src, v6Dst))},
		{"local with a payload", framed(verCmdLocal, 0x00, []byte("0123456789"))},
	}
	for _, h := range headers {
		t.Run(h.name, func(t *testing.T) {
			for k := range h.in {
				want := io.ErrUnexpectedEOF
				if k == 0 {
					want = io.EOF
				}
				got, err := proxyproto.ReadV2(bufio.NewReader(bytes.NewReader(h.in[:k])))
				if err != want || got != nil {
					t.Errorf("cut after %d of %d bytes: ReadV2 = %v, %v; want nil, %v", k, len(h.in), got, err, want)
				}
			}
		})
	}
}

// TestReadV2DoesNotWaitForMore plays peers that send a few bytes and then say
// nothing. Whenever those bytes already decide the outcome, ReadV2 must return
// it at once instead of waiting for more: otherwise one connection that opens
// with a short plain-text request, or announces a header it will never send,
// holds the listener until its deadline.
func TestReadV2DoesNotWaitForMore(t *testing.T) {
	tests := []struct {
		name   string
		chunks [][]byte // what the peer sends before it goes quiet
		want   error
	}{
		{"v1 header: the first byte decides", [][]byte{[]byte("P")}, proxyproto.ErrNoSignature},
		{"http request: the first byte decides", [][]byte{[]byte("G")}, proxyproto.ErrNoSignature},
		{"tls record: the first byte decides", [][]byte{{0x16}}, proxyproto.ErrNoSignature},
		{"a wrong third byte", [][]byte{signature[:2], {0x00}}, proxyproto.ErrNoSignature},
		{"a wrong last signature byte", [][]byte{signature[:11], {0x00}}, proxyproto.ErrNoSignature},

		// Bytes that are right so far prove nothing: the silence is the answer.
		{"a true prefix of the signature", [][]byte{signature[:7]}, errSilent},
		{"the whole signature and nothing else", [][]byte{signature}, errSilent},

		// Everything the fixed part can tell is told before the payload is read.
		{"unsupported version", [][]byte{rawHeader(0x11, famTCP4, 12, nil)}, proxyproto.ErrMalformed},
		{"unknown command", [][]byte{rawHeader(0x2f, famTCP4, 12, nil)}, proxyproto.ErrMalformed},
		{"unsupported family", [][]byte{rawHeader(verCmdProxy, 0x31, 216, nil)}, proxyproto.ErrMalformed},
		{"block too short for the family", [][]byte{rawHeader(verCmdProxy, famTCP6, 12, nil)}, proxyproto.ErrMalformed},
		{"proxy payload over the limit", [][]byte{rawHeader(verCmdProxy, famTCP4, 65535, nil)}, proxyproto.ErrMalformed},
		{"local payload over the limit", [][]byte{rawHeader(verCmdLocal, 0x00, maxPayload+1, nil)}, proxyproto.ErrMalformed},

		// A header that is fine so far but whose payload never comes.
		{"payload announced, never sent", [][]byte{rawHeader(verCmdProxy, famTCP4, 12, nil)}, errSilent},
		{"half a payload", [][]byte{rawHeader(verCmdProxy, famTCP4, 12, make([]byte, 6))}, errSilent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := proxyproto.ReadV2(bufio.NewReader(&scripted{chunks: tt.chunks, err: errSilent}))
			if !errors.Is(err, tt.want) || h != nil {
				t.Errorf("ReadV2 = %v, %v; want nil, %v", h, err, tt.want)
			}
		})
	}
}

// TestReadV2BoundsAllocation checks that a length field is judged before any
// memory is set aside for it. Headers that announce 64 KiB of payload are
// rejected by the thousand; if each one cost the 64 KiB it announces, the bytes
// allocated would be a hundred times what a bounded parser needs.
func TestReadV2BoundsAllocation(t *testing.T) {
	inputs := [][]byte{
		rawHeader(verCmdProxy, famTCP4, 65535, nil),
		rawHeader(verCmdProxy, famTCP6, 65535, nil),
		rawHeader(verCmdLocal, 0x00, 65535, nil),
		rawHeader(verCmdProxy, famTCP4, maxPayload+1, nil),
	}
	const rounds = 250

	rd := bytes.NewReader(nil)
	br := bufio.NewReaderSize(rd, 4096)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range rounds {
		for _, in := range inputs {
			rd.Reset(in)
			br.Reset(rd)
			if _, err := proxyproto.ReadV2(br); !errors.Is(err, proxyproto.ErrMalformed) {
				t.Fatalf("ReadV2(%x) error = %v, want %v", in, err, proxyproto.ErrMalformed)
			}
		}
	}
	runtime.ReadMemStats(&after)

	// A bounded parser spends a few hundred bytes per rejection, on the error
	// text; an unbounded one would spend some 47 MiB here.
	if got := after.TotalAlloc - before.TotalAlloc; got > 2<<20 {
		t.Errorf("rejecting %d oversized headers allocated %d bytes: the length must be checked before anything is allocated", rounds*len(inputs), got)
	}
}

// TestReadV2PassesReaderErrorsThrough breaks the connection after every
// possible number of bytes of a valid header. The error of the reader comes
// back as it is: not as a verdict on the header, and not as io.EOF, so that the
// caller can tell a dropped connection or an expired deadline from a bad peer.
func TestReadV2PassesReaderErrorsThrough(t *testing.T) {
	in := framed(verCmdProxy, famTCP6, cat(addrBlock6(v6Src, v6Dst), tlv(0x04, make([]byte, 4))))
	for k := range in {
		var chunks [][]byte
		if k > 0 {
			chunks = [][]byte{in[:k]}
		}
		h, err := proxyproto.ReadV2(bufio.NewReader(&scripted{chunks: chunks, err: errReset}))
		if !errors.Is(err, errReset) || h != nil {
			t.Errorf("connection lost after %d of %d bytes: ReadV2 = %v, %v; want nil, %v", k, len(in), h, err, errReset)
		}
	}
}

// TestReadV2ReadDeadline is the case of a peer that stalls half way through the
// signature, under a real connection deadline.
func TestReadV2ReadDeadline(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	go func() { _, _ = client.Write(signature[:5]) }()
	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	h, err := proxyproto.ReadV2(bufio.NewReader(server))
	if !errors.Is(err, os.ErrDeadlineExceeded) || h != nil {
		t.Errorf("ReadV2 = %v, %v; want nil and a deadline error", h, err)
	}
}

// ---------------------------------------------------------------------------
// Fuzzing
// ---------------------------------------------------------------------------

// oracleV2 reads data against the rules of the specification in one pass over
// the whole buffer, in plain direct style and without sharing logic with
// ReadV2. It returns what ReadV2 must return and how many bytes the header
// takes. The rules, in the order ReadV2 applies them: the first wrong byte of
// the signature decides on its own; the fixed part must be complete; version,
// command, payload length and, for PROXY, family and block size are judged from
// the fixed part alone, before the payload is looked at; only then must the
// payload be complete.
func oracleV2(data []byte) (hdr *proxyproto.Header, used int, err error) {
	if len(data) == 0 {
		return nil, 0, io.EOF
	}
	for i := 0; i < len(data) && i < len(signature); i++ {
		if data[i] != signature[i] {
			return nil, 0, proxyproto.ErrNoSignature
		}
	}
	if len(data) < fixedLen {
		return nil, 0, io.ErrUnexpectedEOF
	}

	verCmd, fam := data[12], data[13]
	length := int(data[14])<<8 | int(data[15])
	if verCmd>>4 != 2 || verCmd&0x0f > 1 || length > maxPayload {
		return nil, 0, proxyproto.ErrMalformed
	}
	proxied := verCmd&0x0f == 1
	if proxied {
		switch {
		case fam == 0x11 && length >= 12:
		case fam == 0x21 && length >= 36:
		default:
			return nil, 0, proxyproto.ErrMalformed
		}
	}
	if len(data) < fixedLen+length {
		return nil, 0, io.ErrUnexpectedEOF
	}

	used = fixedLen + length
	if !proxied {
		return &proxyproto.Header{Local: true}, used, nil
	}
	p := data[fixedLen:used]
	port := func(i int) uint16 { return uint16(p[i])<<8 | uint16(p[i+1]) }
	if fam == 0x11 {
		return &proxyproto.Header{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[0:4])), port(8)),
			Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[4:8])), port(10)),
		}, used, nil
	}
	return &proxyproto.Header{
		Src: netip.AddrPortFrom(netip.AddrFrom16([16]byte(p[0:16])), port(32)),
		Dst: netip.AddrPortFrom(netip.AddrFrom16([16]byte(p[16:32])), port(34)),
	}, used, nil
}

// checkReadV2 verifies the contract of ReadV2 on arbitrary data: no panic, the
// verdict of oracleV2, no header together with an error, exactly the header
// consumed on success and nothing consumed on ErrNoSignature, and a header that
// survives being encoded again.
func checkReadV2(t *testing.T, data []byte) {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(data))
	h, err := proxyproto.ReadV2(r)
	rest, rerr := io.ReadAll(r)
	if rerr != nil {
		t.Fatalf("reading what ReadV2 left: %v", rerr)
	}
	want, wantUsed, wantErr := oracleV2(data)

	if wantErr != nil {
		if !errors.Is(err, wantErr) {
			t.Fatalf("ReadV2(%x) error = %v, want %v", data, err, wantErr)
		}
		if h != nil {
			t.Fatalf("ReadV2(%x) returned the header %+v together with the error %v", data, *h, err)
		}
		if wantErr == proxyproto.ErrNoSignature && !bytes.Equal(rest, data) {
			t.Fatalf("ReadV2(%x) consumed %d bytes before ErrNoSignature", data, len(data)-len(rest))
		}
		return
	}

	if err != nil {
		t.Fatalf("ReadV2(%x) = %v, want the header %+v", data, err, *want)
	}
	if *h != *want {
		t.Fatalf("ReadV2(%x) = %+v, want %+v", data, *h, *want)
	}
	if got := len(data) - len(rest); got != wantUsed || !bytes.Equal(rest, data[wantUsed:]) {
		t.Fatalf("ReadV2(%x) consumed %d bytes, want exactly the %d of the header", data, got, wantUsed)
	}

	if h.Local {
		return
	}
	again, err := proxyproto.ReadV2(bufio.NewReader(bytes.NewReader(proxyproto.HeaderV2(h.Src, h.Dst))))
	if err != nil {
		t.Fatalf("the header read from %x does not survive HeaderV2: %v", data, err)
	}
	if again.Local || again.Src.Port() != h.Src.Port() || again.Dst.Port() != h.Dst.Port() ||
		again.Src.Addr().Unmap() != h.Src.Addr().Unmap() || again.Dst.Addr().Unmap() != h.Dst.Addr().Unmap() {
		t.Fatalf("header %+v read from %x became %+v after HeaderV2", *h, data, *again)
	}
}

// FuzzReadV2 feeds arbitrary bytes to ReadV2 and holds it to checkReadV2.
func FuzzReadV2(f *testing.F) {
	block4 := addrBlock4(v4Src, v4Dst)
	block6 := addrBlock6(v6Src, v6Dst)
	withTLV := framed(verCmdProxy, famTCP4, cat(block4, tlv(0x04, make([]byte, 5))))

	seeds := [][]byte{
		framed(verCmdProxy, famTCP4, block4),
		framed(verCmdProxy, famTCP6, block6),
		proxyproto.HeaderV2(v4Src, v6Dst),
		proxyproto.HeaderV2(v6Src, v4Dst),
		cat(withTLV, tail),
		framed(verCmdLocal, 0x00, nil),
		framed(verCmdLocal, famTCP4, block4),
		framed(verCmdLocal, 0x99, []byte("ignored")),
		framed(verCmdProxy, famTCP6, cat(block6, tlv(0x04, make([]byte, maxPayload-len(block6)-3)))),
		framed(verCmdProxy, famTCP6, cat(block6, make([]byte, maxPayload+1-len(block6)))),
		rawHeader(verCmdProxy, famTCP4, 65535, nil),
		rawHeader(verCmdProxy, famTCP4, 12, nil),
		rawHeader(verCmdLocal, 0x00, 1025, nil),
		framed(0x11, famTCP4, block4),
		framed(0x2f, famTCP4, block4),
		framed(verCmdProxy, 0x00, nil),
		framed(verCmdProxy, 0x12, block4),
		framed(verCmdProxy, 0x31, make([]byte, 216)),
		framed(verCmdProxy, famTCP4, block4[:11]),
		framed(verCmdProxy, famTCP6, block4),
		[]byte("PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\n"),
		[]byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
		[]byte("\r\n\r\nGET"),
		cat(signature, []byte{0x21}),
		signature,
		signature[:5],
		{0x16, 0x03, 0x01},
		{},
	}
	// Every way of cutting a header short.
	for k := range withTLV {
		seeds = append(seeds, withTLV[:k])
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		checkReadV2(t, data)
	})
}
