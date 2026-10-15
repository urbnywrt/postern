package tlsx_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/urbnywrt/postern/internal/tlsx"
)

// defaultMax is the limit the edge router passes: 64 KiB of ClientHello bytes.
const defaultMax = 65536

// ---------------------------------------------------------------------------
// Wire-format helpers. They are written out by hand, deliberately without
// cryptobyte, so that the tests share no code with the parser they check.
// ---------------------------------------------------------------------------

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func u16(v int) []byte {
	if v < 0 || v > 0xffff {
		panic(fmt.Sprintf("u16(%d): out of range", v))
	}
	return []byte{byte(v >> 8), byte(v)}
}

func u24(v int) []byte {
	if v < 0 || v > 0xffffff {
		panic(fmt.Sprintf("u24(%d): out of range", v))
	}
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

// lp8 and lp16 prefix b with its length, in one and two bytes.
func lp8(b []byte) []byte {
	if len(b) > 0xff {
		panic("lp8: too long")
	}
	return cat([]byte{byte(len(b))}, b)
}

func lp16(b []byte) []byte { return cat(u16(len(b)), b) }

// extension encodes one TLS extension: type, length, data.
func extension(typ int, data []byte) []byte { return cat(u16(typ), lp16(data)) }

// nameEntry encodes one ServerName: a name_type and a length-prefixed name.
func nameEntry(nameType byte, name string) []byte {
	return cat([]byte{nameType}, lp16([]byte(name)))
}

func hostName(name string) []byte { return nameEntry(0, name) }

// serverNameExt encodes a server_name extension (type 0) with the given entries.
func serverNameExt(entries ...[]byte) []byte { return extension(0, lp16(cat(entries...))) }

// alpnExt encodes an application_layer_protocol_negotiation extension (type 16).
func alpnExt(protos ...string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, lp8([]byte(p))...)
	}
	return extension(16, lp16(list))
}

// paddingExt encodes a padding extension (type 21) with n bytes of data.
func paddingExt(n int) []byte { return extension(21, make([]byte, n)) }

// helloPrefix is the part of a ClientHello body that precedes the extensions.
func helloPrefix() []byte {
	return cat(
		[]byte{3, 3},                         // legacy_version
		bytes.Repeat([]byte{0xaa}, 32),       // random
		lp8(bytes.Repeat([]byte{0xbb}, 32)),  // legacy_session_id
		lp16([]byte{0x13, 0x01, 0xc0, 0x2b}), // cipher_suites
		lp8([]byte{0}),                       // legacy_compression_methods
	)
}

// helloBody builds a ClientHello body (a handshake message without its 4-byte
// header) whose extension block holds the given, already encoded, extensions.
func helloBody(exts ...[]byte) []byte { return cat(helloPrefix(), lp16(cat(exts...))) }

// handshakeMsg wraps body in a ClientHello handshake header.
func handshakeMsg(body []byte) []byte { return cat([]byte{1}, u24(len(body)), body) }

// record frames fragment as a TLS record of the given content type and version.
func record(typ byte, version int, fragment []byte) []byte {
	return cat([]byte{typ}, u16(version), lp16(fragment))
}

// recordHeader is a record header alone, for tests that never supply the body.
func recordHeader(typ byte, version, length int) []byte {
	return cat([]byte{typ}, u16(version), u16(length))
}

// helloRecord is a complete ClientHello in a single record.
func helloRecord(body []byte) []byte { return record(0x16, 0x0301, handshakeMsg(body)) }

// handshakeBytes joins the fragments of a run of handshake records.
func handshakeBytes(t testing.TB, stream []byte) []byte {
	t.Helper()
	var hs []byte
	for len(stream) > 0 {
		if len(stream) < 5 || stream[0] != 0x16 {
			t.Fatalf("not a clean run of handshake records: %s", head(stream))
		}
		n := int(stream[3])<<8 | int(stream[4])
		if len(stream) < 5+n {
			t.Fatalf("record is cut short: %s", head(stream))
		}
		hs = append(hs, stream[5:5+n]...)
		stream = stream[5+n:]
	}
	return hs
}

// frame splits the handshake bytes hs into records whose fragments have the
// given sizes; whatever remains goes into one last record.
func frame(t testing.TB, hs []byte, sizes ...int) []byte {
	t.Helper()
	var out []byte
	for _, n := range sizes {
		if n <= 0 || n >= len(hs) {
			t.Fatalf("cannot cut %d bytes off a %d-byte handshake", n, len(hs))
		}
		out = append(out, record(0x16, 0x0301, hs[:n])...)
		hs = hs[n:]
	}
	return append(out, record(0x16, 0x0301, hs)...)
}

// reframe re-frames the handshake carried by the records in raw, see frame.
func reframe(t testing.TB, raw []byte, sizes ...int) []byte {
	t.Helper()
	return frame(t, handshakeBytes(t, raw), sizes...)
}

// oracleBody is a second, independent implementation of the record layer. It
// returns the ClientHello body carried by raw, which must be a clean run of
// handshake records holding exactly one complete ClientHello and nothing else
// but, possibly, trailing handshake bytes in the last record.
func oracleBody(raw []byte) (body []byte, ok bool) {
	var hs []byte
	for len(raw) > 0 {
		if len(raw) < 5 || raw[0] != 0x16 {
			return nil, false
		}
		n := int(raw[3])<<8 | int(raw[4])
		if n == 0 || len(raw) < 5+n {
			return nil, false
		}
		hs = append(hs, raw[5:5+n]...)
		raw = raw[5+n:]
	}
	if len(hs) < 4 || hs[0] != 1 {
		return nil, false
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+n {
		return nil, false
	}
	return hs[4 : 4+n], true
}

// head renders the start of b for failure messages.
func head(b []byte) string {
	if len(b) > 48 {
		return fmt.Sprintf("%x... (%d bytes)", b[:48], len(b))
	}
	return fmt.Sprintf("%x", b)
}

// dump renders b in full, up to 4 KiB, so that a failure can be reproduced.
func dump(b []byte) string {
	if len(b) > 4096 {
		return head(b)
	}
	return fmt.Sprintf("%x", b)
}

// closeAll closes the connections and ignores the errors: it is only used on
// pipes whose other end may have hung up already.
func closeAll(conns ...net.Conn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

// ---------------------------------------------------------------------------
// Real ClientHellos and the crypto/tls oracle
// ---------------------------------------------------------------------------

// realConfig is the client the task specifies for the main test.
func realConfig() *tls.Config {
	return &tls.Config{ServerName: "www.example.com", NextProtos: []string{"h2", "http/1.1"}}
}

// recordingConn remembers every byte written through it.
type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written []byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.written = append(c.written, p[:n]...)
	c.mu.Unlock()
	return n, err
}

func (c *recordingConn) sent() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.written)
}

// captureClientHello runs a crypto/tls client with cfg against a net.Pipe and
// returns the bytes of the one TLS record it sends first. The record is framed
// by this helper alone (it needs only the length field), not by the package
// under test.
func captureClientHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	defer closeAll(cli, srv)
	_ = srv.SetDeadline(time.Now().Add(10 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Client(cli, cfg).Handshake() // fails once srv is closed below
	}()

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(srv, hdr); err != nil {
		t.Fatalf("capturing a ClientHello: %v", err)
	}
	frag := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(srv, frag); err != nil {
		t.Fatalf("capturing a ClientHello: %v", err)
	}
	_ = srv.Close()
	<-done

	if len(frag) < 4 || 4+(int(frag[1])<<16|int(frag[2])<<8|int(frag[3])) != len(frag) {
		t.Fatalf("crypto/tls did not send its ClientHello as one complete record")
	}
	return append(hdr, frag...)
}

var errStopHandshake = errors.New("stop after the ClientHello")

// goView feeds raw to a crypto/tls server and returns what crypto/tls makes of
// the ClientHello. accepted is false when crypto/tls rejects the hello before
// it would pick a certificate.
func goView(raw []byte) (serverName string, protos []string, accepted bool) {
	cli, srv := net.Pipe()
	defer closeAll(cli, srv)
	_ = srv.SetDeadline(time.Now().Add(10 * time.Second))
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))

	go func() {
		_, _ = cli.Write(raw)
		_, _ = io.Copy(io.Discard, cli) // swallow the alert the server sends
	}()
	cfg := &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			accepted = true
			serverName, protos = h.ServerName, h.SupportedProtos
			return nil, errStopHandshake
		},
	}
	_ = tls.Server(srv, cfg).Handshake()
	return serverName, protos, accepted
}

// ---------------------------------------------------------------------------
// Invariants that must hold for every input
// ---------------------------------------------------------------------------

// countingReader counts the bytes handed to its caller.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// readChecked runs ReadClientHello over data and verifies what has to be true
// whatever the outcome: a non-nil result whose Raw is exactly what was taken
// from the reader (so a prefix of the input), never more than maxBytes read,
// and errors that fit what happened. It returns the result for further checks.
func readChecked(t testing.TB, data []byte, maxBytes int) (*tlsx.ClientHello, error) {
	t.Helper()
	cr := &countingReader{r: bytes.NewReader(data)}
	ch, err := tlsx.ReadClientHello(cr, maxBytes)
	if ch == nil {
		t.Fatalf("ReadClientHello returned a nil *ClientHello (err = %v); input %s", err, dump(data))
	}
	if !bytes.Equal(ch.Raw, data[:cr.n]) {
		t.Fatalf("Raw (%d bytes) is not the %d bytes consumed from the reader (err = %v); input %s",
			len(ch.Raw), cr.n, err, dump(data))
	}
	if limit := max(maxBytes, 0); cr.n > limit {
		t.Fatalf("consumed %d bytes with maxBytes = %d; input %s", cr.n, maxBytes, dump(data))
	}
	if err != nil && (ch.SNI != "" || ch.ALPN != nil) {
		t.Fatalf("SNI %q / ALPN %q set although err = %v", ch.SNI, ch.ALPN, err)
	}

	switch {
	case err == nil:
		body, ok := oracleBody(ch.Raw)
		if !ok {
			t.Fatalf("success, but Raw is not a clean run of handshake records holding a ClientHello: %s", head(ch.Raw))
		}
		sni, alpn, perr := tlsx.ParseClientHelloBody(body)
		if perr != nil {
			t.Fatalf("success, but ParseClientHelloBody rejects the body: %v", perr)
		}
		if sni != ch.SNI || !reflect.DeepEqual(alpn, ch.ALPN) {
			t.Fatalf("result SNI %q ALPN %q differs from parsing the body: SNI %q ALPN %q", ch.SNI, ch.ALPN, sni, alpn)
		}
	case errors.Is(err, tlsx.ErrNotTLS):
		// Only ever raised for the first record: by its first byte, or by a
		// version that no TLS record carries.
		raw := ch.Raw
		byType := len(raw) == 1 && raw[0] != 0x16
		byVersion := len(raw) == 5 && raw[0] == 0x16 && raw[1] != 3
		if !byType && !byVersion {
			t.Fatalf("ErrNotTLS with Raw = %s", head(raw))
		}
	case errors.Is(err, tlsx.ErrTooLarge), errors.Is(err, tlsx.ErrMalformed):
		// nothing more to check
	case errors.Is(err, io.EOF):
		if len(data) != 0 || len(ch.Raw) != 0 {
			t.Fatalf("io.EOF after %d bytes of a %d-byte input; it is only right before the first byte", len(ch.Raw), len(data))
		}
	case errors.Is(err, io.ErrUnexpectedEOF):
		if cr.n != len(data) || cr.n == 0 {
			t.Fatalf("io.ErrUnexpectedEOF after %d of %d bytes", cr.n, len(data))
		}
	default:
		t.Fatalf("unexpected error %v; input %s", err, dump(data))
	}
	return ch, err
}

// checkParseClientHelloBody runs ParseClientHelloBody over body and verifies
// what has to be true whatever the outcome, including agreement with crypto/tls
// wherever crypto/tls accepts the hello.
func checkParseClientHelloBody(t testing.TB, body []byte) {
	t.Helper()
	sni, alpn, err := tlsx.ParseClientHelloBody(body)
	if err != nil {
		if !errors.Is(err, tlsx.ErrMalformed) {
			t.Fatalf("error %v is not ErrMalformed; body %s", err, dump(body))
		}
		if sni != "" || alpn != nil {
			t.Fatalf("SNI %q / ALPN %q returned together with %v", sni, alpn, err)
		}
	} else {
		if sni != "" && !bytes.Contains(body, []byte(sni)) {
			t.Fatalf("SNI %q is not part of the body %s", sni, dump(body))
		}
		if alpn != nil && len(alpn) == 0 {
			t.Fatalf("empty, non-nil ALPN list for body %s", dump(body))
		}
		for _, p := range alpn {
			if p == "" || !bytes.Contains(body, []byte(p)) {
				t.Fatalf("ALPN entry %q is empty or not part of the body %s", p, dump(body))
			}
		}
	}

	// crypto/tls is the oracle. Whenever it accepts a hello we must accept it
	// too and read the same names out of it. The other direction does not hold:
	// crypto/tls is stricter about, for one, trailing dots and repeated entries.
	if len(body) > 16000 {
		return // would not fit a single plaintext record
	}
	goSNI, goALPN, accepted := goView(helloRecord(body))
	if !accepted {
		return
	}
	if err != nil {
		t.Fatalf("crypto/tls accepts this ClientHello, ParseClientHelloBody does not (%v); body %x", err, body)
	}
	if sni != goSNI || !slices.Equal(alpn, goALPN) {
		t.Fatalf("crypto/tls reads SNI %q ALPN %q, ParseClientHelloBody reads SNI %q ALPN %q; body %x",
			goSNI, goALPN, sni, alpn, body)
	}
}

// ---------------------------------------------------------------------------
// ReadClientHello
// ---------------------------------------------------------------------------

// TestRealClientHello reads the ClientHello of a real crypto/tls client from a
// live net.Pipe and compares Raw with what the client wrote.
func TestRealClientHello(t *testing.T) {
	cliEnd, srvEnd := net.Pipe()
	defer closeAll(cliEnd, srvEnd)
	_ = srvEnd.SetDeadline(time.Now().Add(10 * time.Second))

	rec := &recordingConn{Conn: cliEnd}
	done := make(chan error, 1)
	go func() { done <- tls.Client(rec, realConfig()).Handshake() }()

	ch, err := tlsx.ReadClientHello(srvEnd, defaultMax)

	// The client now waits for a ServerHello that never comes. Hang up, so its
	// handshake ends and the recording of what it sent is complete.
	_ = srvEnd.Close()
	if herr := <-done; herr == nil {
		t.Fatal("the client handshake unexpectedly succeeded")
	}
	if err != nil {
		t.Fatalf("ReadClientHello: %v", err)
	}

	sent := rec.sent()
	if len(sent) == 0 || sent[0] != 0x16 {
		t.Fatalf("the client sent %s", head(sent))
	}
	if !bytes.Equal(ch.Raw, sent) {
		t.Errorf("Raw is %d bytes, the client sent %d; they differ", len(ch.Raw), len(sent))
	}
	if ch.SNI != "www.example.com" {
		t.Errorf("SNI = %q, want %q", ch.SNI, "www.example.com")
	}
	if want := []string{"h2", "http/1.1"}; !slices.Equal(ch.ALPN, want) {
		t.Errorf("ALPN = %q, want %q", ch.ALPN, want)
	}
}

// TestAgreesWithCryptoTLS reads hellos of several real client configurations
// and requires the same SNI and ALPN as crypto/tls's own server parser.
func TestAgreesWithCryptoTLS(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".example.com"
	tests := []struct {
		name    string
		cfg     *tls.Config
		wantSNI string
	}{
		{"sni and alpn", realConfig(), "www.example.com"},
		{"name is returned as sent", &tls.Config{ServerName: "WWW.Example.COM", NextProtos: []string{"h2"}}, "WWW.Example.COM"},
		{"sni only", &tls.Config{ServerName: "www.example.com"}, "www.example.com"},
		{"alpn only", &tls.Config{ServerName: "192.0.2.1", NextProtos: []string{"h2", "http/1.1", "acme-tls/1"}}, ""},
		{"neither", &tls.Config{ServerName: "198.51.100.7"}, ""},
		{"tls 1.2 only", &tls.Config{ServerName: "www.example.com", NextProtos: []string{"http/1.1"}, MaxVersion: tls.VersionTLS12}, "www.example.com"},
		{"long name", &tls.Config{ServerName: long}, long},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := captureClientHello(t, tt.cfg)
			ch, err := readChecked(t, raw, defaultMax)
			if err != nil {
				t.Fatalf("ReadClientHello: %v", err)
			}
			if !bytes.Equal(ch.Raw, raw) {
				t.Errorf("Raw differs from the %d captured bytes", len(raw))
			}
			if ch.SNI != tt.wantSNI {
				t.Errorf("SNI = %q, want %q", ch.SNI, tt.wantSNI)
			}
			goSNI, goALPN, accepted := goView(raw)
			if !accepted {
				t.Fatal("crypto/tls rejects its own client's ClientHello")
			}
			if ch.SNI != goSNI || !slices.Equal(ch.ALPN, goALPN) {
				t.Errorf("SNI %q ALPN %q, but crypto/tls reads SNI %q ALPN %q", ch.SNI, ch.ALPN, goSNI, goALPN)
			}
			if !slices.Equal(ch.ALPN, tt.cfg.NextProtos) {
				t.Errorf("ALPN = %q, want %q", ch.ALPN, tt.cfg.NextProtos)
			}
		})
	}
}

func TestFragmentedAcrossRecords(t *testing.T) {
	single := captureClientHello(t, realConfig())
	hs := handshakeBytes(t, single)

	tests := []struct {
		name  string
		sizes []int // fragment sizes; the last record takes the rest
	}{
		{"three uneven records", []int{100, 700}},
		{"handshake header split across records", []int{2, 300}},
		{"handshake type alone in the first record", []int{1, 3}},
		{"one byte, one byte, the rest", []int{1, 1}},
		{"last record holds a single byte", []int{len(hs) - 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := frame(t, hs, tt.sizes...)
			ch, err := readChecked(t, data, defaultMax)
			if err != nil {
				t.Fatalf("ReadClientHello: %v", err)
			}
			if !bytes.Equal(ch.Raw, data) {
				t.Errorf("Raw is %d bytes, want the %d re-framed bytes", len(ch.Raw), len(data))
			}
			if ch.SNI != "www.example.com" || !slices.Equal(ch.ALPN, []string{"h2", "http/1.1"}) {
				t.Errorf("SNI %q ALPN %q", ch.SNI, ch.ALPN)
			}
		})
	}

	t.Run("every byte in its own record", func(t *testing.T) {
		sizes := slices.Repeat([]int{1}, len(hs)-1)
		data := frame(t, hs, sizes...)
		ch, err := readChecked(t, data, defaultMax)
		if err != nil {
			t.Fatalf("ReadClientHello: %v", err)
		}
		if !bytes.Equal(ch.Raw, data) || ch.SNI != "www.example.com" {
			t.Errorf("Raw %d bytes (want %d), SNI %q", len(ch.Raw), len(data), ch.SNI)
		}
	})

	t.Run("hello larger than one record", func(t *testing.T) {
		// A hello with 20000 bytes of padding does not fit one record, so a
		// sender has to cut it at the 16 KiB record size.
		big := handshakeMsg(helloBody(serverNameExt(hostName("www.example.com")), alpnExt("h2"), paddingExt(20000)))
		data := frame(t, big, 16384)
		ch, err := readChecked(t, data, defaultMax)
		if err != nil {
			t.Fatalf("ReadClientHello: %v", err)
		}
		if !bytes.Equal(ch.Raw, data) || ch.SNI != "www.example.com" || !slices.Equal(ch.ALPN, []string{"h2"}) {
			t.Errorf("Raw %d bytes (want %d), SNI %q ALPN %q", len(ch.Raw), len(data), ch.SNI, ch.ALPN)
		}
	})

	t.Run("record versions may differ", func(t *testing.T) {
		data := cat(record(0x16, 0x0301, hs[:50]), record(0x16, 0x0303, hs[50:]))
		ch, err := readChecked(t, data, defaultMax)
		if err != nil || ch.SNI != "www.example.com" {
			t.Fatalf("SNI %q, err %v", ch.SNI, err)
		}
	})
}

func TestNotTLS(t *testing.T) {
	const request = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"

	rd := strings.NewReader(request)
	ch, err := tlsx.ReadClientHello(rd, defaultMax)
	if !errors.Is(err, tlsx.ErrNotTLS) {
		t.Fatalf("err = %v, want ErrNotTLS", err)
	}
	if string(ch.Raw) != "G" {
		t.Errorf("Raw = %q, want %q", ch.Raw, "G")
	}
	if got := len(request) - rd.Len(); got != 1 {
		t.Errorf("read %d bytes from the connection, want exactly 1", got)
	}

	// After one byte the connection is silent, and reading on would end in this
	// error instead of ErrNotTLS (or, on a real connection, in a timeout).
	t.Run("decides on the first byte without waiting for more", func(t *testing.T) {
		r := io.MultiReader(strings.NewReader("G"), iotest.ErrReader(errors.New("read past the first byte")))
		ch, err := tlsx.ReadClientHello(r, defaultMax)
		if !errors.Is(err, tlsx.ErrNotTLS) || string(ch.Raw) != "G" {
			t.Fatalf("err = %v, Raw = %q", err, ch.Raw)
		}
	})

	// The first byte is covered by a budget of one, and enough to tell.
	t.Run("one byte of budget is enough to tell", func(t *testing.T) {
		ch, err := readChecked(t, []byte(request), 1)
		if !errors.Is(err, tlsx.ErrNotTLS) || string(ch.Raw) != "G" {
			t.Fatalf("err = %v, Raw = %q", err, ch.Raw)
		}
	})

	for _, first := range []byte{0x00, 0x14, 0x15, 0x17, 0x80, 'P', 'S', 0xff} {
		t.Run(fmt.Sprintf("first byte %02x", first), func(t *testing.T) {
			data := append([]byte{first}, helloRecord(helloBody())[1:]...)
			ch, err := readChecked(t, data, defaultMax)
			if !errors.Is(err, tlsx.ErrNotTLS) {
				t.Fatalf("err = %v, want ErrNotTLS", err)
			}
			if !bytes.Equal(ch.Raw, []byte{first}) {
				t.Errorf("Raw = %x, want just the first byte", ch.Raw)
			}
		})
	}

	// A handshake record type with a version that no TLS record carries is not
	// TLS either, but the header has to be read to see it.
	for _, version := range []int{0x0000, 0x0002, 0x0200, 0x0400, 0xffff} {
		t.Run(fmt.Sprintf("record version %04x", version), func(t *testing.T) {
			data := cat(recordHeader(0x16, version, 40), make([]byte, 40))
			ch, err := readChecked(t, data, defaultMax)
			if !errors.Is(err, tlsx.ErrNotTLS) {
				t.Fatalf("err = %v, want ErrNotTLS", err)
			}
			if !bytes.Equal(ch.Raw, data[:5]) {
				t.Errorf("Raw = %x, want the 5 header bytes", ch.Raw)
			}
		})
	}

	// Every version a ClientHello record really carries is fine.
	for _, version := range []int{0x0300, 0x0301, 0x0302, 0x0303} {
		t.Run(fmt.Sprintf("record version %04x accepted", version), func(t *testing.T) {
			data := record(0x16, version, handshakeMsg(helloBody(serverNameExt(hostName("www.example.com")))))
			ch, err := readChecked(t, data, defaultMax)
			if err != nil || ch.SNI != "www.example.com" {
				t.Fatalf("SNI %q, err %v", ch.SNI, err)
			}
		})
	}
}

func TestTooLarge(t *testing.T) {
	hello := captureClientHello(t, realConfig())

	// Handshake bytes that announce a message of n bytes, followed by zeros.
	announce := func(n, have int) []byte {
		hs := make([]byte, have)
		copy(hs, cat([]byte{1}, u24(n)))
		return hs
	}

	t.Run("the budget is exactly the size of the hello", func(t *testing.T) {
		ch, err := readChecked(t, hello, len(hello))
		if err != nil || !bytes.Equal(ch.Raw, hello) {
			t.Fatalf("maxBytes = len(hello): err = %v", err)
		}
		if _, err := readChecked(t, hello, len(hello)-1); !errors.Is(err, tlsx.ErrTooLarge) {
			t.Fatalf("maxBytes = len(hello)-1: err = %v, want ErrTooLarge", err)
		}
	})

	tests := []struct {
		name    string
		data    []byte
		max     int
		wantErr error
		wantRaw int // bytes expected to have been consumed
	}{
		{"nothing may be read", hello, 0, tlsx.ErrTooLarge, 0},
		{"negative budget", hello, -1, tlsx.ErrTooLarge, 0},
		{"minimum int budget", hello, math.MinInt, tlsx.ErrTooLarge, 0},
		{"one byte of budget", hello, 1, tlsx.ErrTooLarge, 1},
		{"budget ends inside the record header", hello, 3, tlsx.ErrTooLarge, 1},
		{"budget is the record header", hello, 5, tlsx.ErrTooLarge, 5},
		{"record declares more than the budget leaves", cat(recordHeader(0x16, 0x0301, 0x1000)), 100, tlsx.ErrTooLarge, 5},
		{
			"handshake length above the limit",
			record(0x16, 0x0301, announce(70000, 50)), defaultMax, tlsx.ErrTooLarge, 55,
		},
		{
			"handshake length above a small limit",
			record(0x16, 0x0301, announce(300, 50)), 299, tlsx.ErrTooLarge, -1,
		},
		{
			// 19000 bytes announced, within the 19010 allowed, but the four
			// record headers it takes to carry them push the total over.
			"headers push the total over the budget",
			frame(t, announce(19000, 19004), 5000, 5000, 5000), 19010, tlsx.ErrTooLarge, 3*5005 + 5,
		},
		{
			// With exactly enough budget the same data gets past the size checks
			// and is only rejected for its content.
			"budget covers the announced length and the headers",
			frame(t, announce(19000, 19004), 5000, 5000, 5000), 19004 + 4*5, tlsx.ErrMalformed, 19024,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := readChecked(t, tt.data, tt.max)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantRaw >= 0 && len(ch.Raw) != tt.wantRaw {
				t.Errorf("consumed %d bytes, want %d", len(ch.Raw), tt.wantRaw)
			}
		})
	}
}

func TestNoSNI(t *testing.T) {
	tests := []struct {
		name     string
		data     func(t *testing.T) []byte
		wantALPN []string
	}{
		{
			// IP literals are never sent as a server name.
			"real client without a server name",
			func(t *testing.T) []byte { return captureClientHello(t, &tls.Config{ServerName: "192.0.2.1"}) },
			nil,
		},
		{
			"real client with ALPN but no server name",
			func(t *testing.T) []byte {
				return captureClientHello(t, &tls.Config{ServerName: "192.0.2.1", NextProtos: []string{"h2"}})
			},
			[]string{"h2"},
		},
		{"no extension block at all", func(*testing.T) []byte { return helloRecord(helloPrefix()) }, nil},
		{"empty extension block", func(*testing.T) []byte { return helloRecord(helloBody()) }, nil},
		{
			"only unrelated extensions",
			func(*testing.T) []byte {
				return helloRecord(helloBody(extension(0x0a0a, nil), extension(0x002b, []byte{2, 3, 4})))
			},
			nil,
		},
		{
			"server_name without a host_name",
			func(*testing.T) []byte { return helloRecord(helloBody(serverNameExt(nameEntry(1, "ignored.example")))) },
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.data(t)
			ch, err := readChecked(t, data, defaultMax)
			if err != nil {
				t.Fatalf("ReadClientHello: %v (a missing SNI is not an error)", err)
			}
			if ch.SNI != "" {
				t.Errorf("SNI = %q, want empty", ch.SNI)
			}
			if !reflect.DeepEqual(ch.ALPN, tt.wantALPN) {
				t.Errorf("ALPN = %#v, want %#v", ch.ALPN, tt.wantALPN)
			}
			if !bytes.Equal(ch.Raw, data) {
				t.Errorf("Raw differs from the input")
			}
		})
	}
}

func TestTruncated(t *testing.T) {
	captured := captureClientHello(t, realConfig())
	inputs := map[string][]byte{
		"one record":           captured,
		"three records":        reframe(t, captured, 2, 300),
		"hello above 16K":      frame(t, handshakeMsg(helloBody(serverNameExt(hostName("www.example.com")), paddingExt(16400))), 16384),
		"tiny first record":    reframe(t, captured, 1),
		"ends in padding only": helloRecord(helloBody(serverNameExt(hostName("www.example.com")), paddingExt(40))),
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			// A hello cut off anywhere is an I/O condition, not a protocol
			// error: no bytes at all is io.EOF, a partial one is unexpected EOF.
			for n := 0; n < len(data); n++ {
				ch, err := readChecked(t, data[:n], defaultMax)
				want := io.ErrUnexpectedEOF
				if n == 0 {
					want = io.EOF
				}
				if !errors.Is(err, want) {
					t.Fatalf("cut after %d of %d bytes: err = %v, want %v", n, len(data), err, want)
				}
				if !bytes.Equal(ch.Raw, data[:n]) {
					t.Fatalf("cut after %d bytes: Raw has %d bytes", n, len(ch.Raw))
				}
			}
		})
	}

	// The same cut applied to the body only: the records are complete but the
	// handshake message inside is not, so the hello is malformed. The one
	// exception is a cut exactly before the extension block, which is a valid
	// (extension-less) ClientHello.
	t.Run("body", func(t *testing.T) {
		body, ok := oracleBody(captured)
		if !ok {
			t.Fatal("cannot extract the body of the captured hello")
		}
		off := 2 + 32                                     // legacy_version, random
		off += 1 + int(body[off])                         // legacy_session_id
		off += 2 + (int(body[off])<<8 | int(body[off+1])) // cipher_suites
		off += 1 + int(body[off])                         // legacy_compression_methods
		for n := 0; n <= len(body); n++ {
			sni, _, err := tlsx.ParseClientHelloBody(body[:n])
			switch {
			case n == len(body):
				if err != nil || sni != "www.example.com" {
					t.Fatalf("complete body: SNI %q, err %v", sni, err)
				}
			case n == off:
				if err != nil || sni != "" {
					t.Fatalf("body without its extension block: SNI %q, err %v", sni, err)
				}
			default:
				if !errors.Is(err, tlsx.ErrMalformed) {
					t.Fatalf("body cut to %d of %d bytes: err = %v, want ErrMalformed", n, len(body), err)
				}
			}
		}
	})
}

func TestMalformedRecords(t *testing.T) {
	body := helloBody(serverNameExt(hostName("www.example.com")))
	msg := handshakeMsg(body)

	tests := []struct {
		name    string
		data    []byte
		wantRaw int // bytes expected to have been consumed; -1 not to check
	}{
		{"zero-length record", recordHeader(0x16, 0x0301, 0), 5},
		{"record one byte above 16384+256", recordHeader(0x16, 0x0301, 16384+256+1), 5},
		{"record of 65535 bytes", recordHeader(0x16, 0x0301, 65535), 5},
		{"ServerHello instead of ClientHello", record(0x16, 0x0303, cat([]byte{2}, msg[1:])), len(msg) + 5},
		{"HelloRequest", record(0x16, 0x0303, cat([]byte{0}, msg[1:])), len(msg) + 5},
		{"handshake type 255", record(0x16, 0x0303, cat([]byte{255}, msg[1:])), len(msg) + 5},
		{"wrong type is spotted on the first fragment byte", record(0x16, 0x0301, []byte{2}), 6},
		{"declared length 0", record(0x16, 0x0301, []byte{1, 0, 0, 0}), 9},
		{"declared length cuts the hello short", record(0x16, 0x0301, handshakeMsg(body[:10])), -1},
		{"extension block overruns the body", helloRecord(cat(helloPrefix(), u16(3), []byte{0, 0, 9})), -1},
		{"garbage in a well-framed hello", helloRecord(bytes.Repeat([]byte{0xff}, 100)), -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := readChecked(t, tt.data, defaultMax)
			if !errors.Is(err, tlsx.ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
			if tt.wantRaw >= 0 && len(ch.Raw) != tt.wantRaw {
				t.Errorf("consumed %d bytes, want %d", len(ch.Raw), tt.wantRaw)
			}
		})
	}

	// Anything but a handshake record before the hello is complete is an error.
	for _, typ := range []byte{0x00, 0x14, 0x15, 0x17, 0x18, 0xff} {
		t.Run(fmt.Sprintf("record type %02x before the hello is complete", typ), func(t *testing.T) {
			first := record(0x16, 0x0301, msg[:10])
			data := cat(first, record(typ, 0x0303, msg[10:]))
			ch, err := readChecked(t, data, defaultMax)
			if !errors.Is(err, tlsx.ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
			if !bytes.HasPrefix(ch.Raw, first) || len(ch.Raw) > len(first)+5 {
				t.Errorf("Raw = %s, want the first record and at most the next header", head(ch.Raw))
			}
		})
	}

	// A record at exactly the limit is fine; the length check is not off by one.
	t.Run("record of exactly 16384+256 bytes", func(t *testing.T) {
		const limit = 16384 + 256
		m0 := len(handshakeMsg(helloBody(serverNameExt(hostName("www.example.com")), paddingExt(0))))
		full := handshakeMsg(helloBody(serverNameExt(hostName("www.example.com")), paddingExt(limit-m0)))
		if len(full) != limit {
			t.Fatalf("test setup: fragment is %d bytes, want %d", len(full), limit)
		}
		data := record(0x16, 0x0301, full)
		ch, err := readChecked(t, data, defaultMax)
		if err != nil || ch.SNI != "www.example.com" {
			t.Fatalf("SNI %q, err %v", ch.SNI, err)
		}
	})
}

// TestStopsAtEndOfClientHello pins what happens around the end of the hello:
// nothing after its last record is read, and bytes that share that record with
// the end of the hello are kept in Raw.
func TestStopsAtEndOfClientHello(t *testing.T) {
	hello := captureClientHello(t, realConfig())

	t.Run("later bytes stay on the connection", func(t *testing.T) {
		const tail = "early data that must reach the engine"
		rd := bytes.NewReader(append(slices.Clone(hello), tail...))
		ch, err := tlsx.ReadClientHello(rd, defaultMax)
		if err != nil {
			t.Fatalf("ReadClientHello: %v", err)
		}
		if !bytes.Equal(ch.Raw, hello) {
			t.Errorf("Raw is %d bytes, want the %d bytes of the hello", len(ch.Raw), len(hello))
		}
		if rd.Len() != len(tail) {
			t.Errorf("%d bytes left on the connection, want %d", rd.Len(), len(tail))
		}
	})

	t.Run("bytes sharing the last record are kept", func(t *testing.T) {
		msg := handshakeMsg(helloBody(serverNameExt(hostName("www.example.com"))))
		data := record(0x16, 0x0301, cat(msg, []byte{0xde, 0xad, 0xbe, 0xef}))
		ch, err := readChecked(t, data, defaultMax)
		if err != nil || ch.SNI != "www.example.com" {
			t.Fatalf("SNI %q, err %v", ch.SNI, err)
		}
		if !bytes.Equal(ch.Raw, data) {
			t.Errorf("Raw is %d bytes, want the whole %d-byte record", len(ch.Raw), len(data))
		}
	})
}

// TestReaderQuirks makes sure short reads and EOF delivered together with the
// last data are handled.
func TestReaderQuirks(t *testing.T) {
	data := reframe(t, captureClientHello(t, realConfig()), 5, 400)
	wrappers := map[string]func(io.Reader) io.Reader{
		"one byte at a time": iotest.OneByteReader,
		"half reads":         iotest.HalfReader,
		"EOF with the data":  iotest.DataErrReader,
	}
	for name, wrap := range wrappers {
		t.Run(name, func(t *testing.T) {
			ch, err := tlsx.ReadClientHello(wrap(bytes.NewReader(data)), defaultMax)
			if err != nil {
				t.Fatalf("ReadClientHello: %v", err)
			}
			if !bytes.Equal(ch.Raw, data) || ch.SNI != "www.example.com" {
				t.Errorf("Raw %d bytes (want %d), SNI %q", len(ch.Raw), len(data), ch.SNI)
			}
		})
	}
}

// TestReadErrors checks that errors of the connection itself come back as they
// are, together with the bytes read before them.
func TestReadErrors(t *testing.T) {
	hello := captureClientHello(t, realConfig())

	t.Run("read error", func(t *testing.T) {
		boom := errors.New("connection reset")
		for _, cut := range []int{0, 1, 4, 5, 6, 100, len(hello) - 1} {
			r := io.MultiReader(bytes.NewReader(hello[:cut]), iotest.ErrReader(boom))
			ch, err := tlsx.ReadClientHello(r, defaultMax)
			if !errors.Is(err, boom) {
				t.Fatalf("cut %d: err = %v, want the reader's error", cut, err)
			}
			if !bytes.Equal(ch.Raw, hello[:cut]) {
				t.Fatalf("cut %d: Raw has %d bytes", cut, len(ch.Raw))
			}
		}
	})

	t.Run("deadline in the middle of the hello", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer closeAll(cli, srv)

		const sentBytes = 100
		written := make(chan struct{})
		go func() {
			_, _ = cli.Write(hello[:sentBytes]) // returns once the reader has taken all of it
			close(written)
		}()
		go func() {
			<-written
			_ = srv.SetReadDeadline(time.Now()) // the client has gone quiet
		}()

		ch, err := tlsx.ReadClientHello(srv, defaultMax)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("err = %v, want a deadline error", err)
		}
		if !bytes.Equal(ch.Raw, hello[:sentBytes]) {
			t.Errorf("Raw has %d bytes, want the %d that were sent", len(ch.Raw), sentBytes)
		}
	})
}

// mutate returns a damaged copy of data: a byte flipped, a byte inserted, a
// stretch removed, the tail cut off or a field overwritten with 0xffff.
func mutate(rng *rand.Rand, data []byte) []byte {
	out := slices.Clone(data)
	if len(out) == 0 {
		return out
	}
	switch rng.IntN(5) {
	case 0:
		out[rng.IntN(len(out))] ^= byte(1 + rng.IntN(255))
	case 1:
		out = slices.Insert(out, rng.IntN(len(out)+1), byte(rng.IntN(256)))
	case 2:
		i := rng.IntN(len(out))
		out = slices.Delete(out, i, i+rng.IntN(len(out)-i+1))
	case 3:
		out = out[:rng.IntN(len(out)+1)]
	case 4:
		i := rng.IntN(len(out))
		out[i] = 0xff
		if i+1 < len(out) {
			out[i+1] = 0xff
		}
	}
	return out
}

// TestCorruptedInput throws damaged hellos at both functions. It is a small,
// reproducible stand-in for the fuzz targets that runs with every go test.
func TestCorruptedInput(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261004, 1))
	body := helloBody(
		extension(0x0a0a, nil),
		serverNameExt(hostName("www.example.com")),
		extension(0x002b, []byte{2, 3, 4}),
		alpnExt("h2", "http/1.1"),
		paddingExt(100),
	)
	single := helloRecord(body)
	seeds := [][]byte{
		single,
		reframe(t, single, 3, 200),
		reframe(t, single, 1, 1, 1, 1),
		helloRecord(helloPrefix()),
	}

	for i := 0; i < 4000; i++ {
		data := seeds[rng.IntN(len(seeds))]
		for k := 1 + rng.IntN(3); k > 0; k-- {
			data = mutate(rng, data)
		}
		budget := defaultMax
		if rng.IntN(3) == 0 {
			budget = rng.IntN(len(single)*2 + 1)
		}
		_, _ = readChecked(t, data, budget)
	}

	for i := 0; i < 4000; i++ {
		b := body
		for k := 1 + rng.IntN(3); k > 0; k-- {
			b = mutate(rng, b)
		}
		checkParseClientHelloBody(t, b)
	}
}

// ---------------------------------------------------------------------------
// ParseClientHelloBody
// ---------------------------------------------------------------------------

func TestParseClientHelloBody(t *testing.T) {
	prefix := helloPrefix()
	sniOnly := serverNameExt(hostName("www.example.com"))

	tests := []struct {
		name     string
		body     []byte
		wantSNI  string
		wantALPN []string
		wantErr  error
	}{
		// Well-formed hellos.
		{name: "no extension block", body: prefix},
		{name: "empty extension block", body: cat(prefix, u16(0))},
		{name: "server_name only", body: helloBody(sniOnly), wantSNI: "www.example.com"},
		{name: "alpn only", body: helloBody(alpnExt("h2", "http/1.1")), wantALPN: []string{"h2", "http/1.1"}},
		{
			name: "both, among unrelated extensions",
			body: helloBody(
				extension(0x0a0a, nil), extension(0x002b, []byte{2, 3, 4}), sniOnly,
				extension(0x0017, nil), alpnExt("h2"), extension(0xff01, []byte{0}),
			),
			wantSNI: "www.example.com", wantALPN: []string{"h2"},
		},
		{
			name:    "sni is returned exactly as sent",
			body:    helloBody(serverNameExt(hostName("WWW.Example.COM."))),
			wantSNI: "WWW.Example.COM.",
		},
		{
			name:    "name types other than host_name are skipped",
			body:    helloBody(serverNameExt(nameEntry(1, "ignored.example"), nameEntry(255, "x"), hostName("www.example.com"))),
			wantSNI: "www.example.com",
		},
		{
			name:    "the first host_name wins",
			body:    helloBody(serverNameExt(hostName("first.example.com"), hostName("second.example.com"))),
			wantSNI: "first.example.com",
		},
		{
			name: "unknown extensions are not inspected",
			body: helloBody(extension(0x1234, []byte{1, 2, 3}), extension(0x0001, []byte{0xff}), extension(0xfe0d, nil)),
		},
		{
			name: "repeated unknown extensions are tolerated",
			body: helloBody(extension(0x0a0a, nil), extension(0x0a0a, []byte{0})),
		},
		{
			name:     "alpn keeps the order and every entry",
			body:     helloBody(alpnExt("http/1.1", "h2", "x", "h2")),
			wantALPN: []string{"http/1.1", "h2", "x", "h2"},
		},

		// A repeated extension we read is ambiguous.
		{name: "repeated server_name extension", body: helloBody(sniOnly, serverNameExt(hostName("other.example"))), wantErr: tlsx.ErrMalformed},
		{name: "repeated alpn extension", body: helloBody(alpnExt("h2"), alpnExt("http/1.1")), wantErr: tlsx.ErrMalformed},

		// server_name defects.
		{name: "empty server_name extension", body: helloBody(extension(0, nil)), wantErr: tlsx.ErrMalformed},
		{name: "empty server_name list", body: helloBody(extension(0, u16(0))), wantErr: tlsx.ErrMalformed},
		{name: "empty host_name", body: helloBody(serverNameExt(hostName(""))), wantErr: tlsx.ErrMalformed},
		{name: "empty name of another type", body: helloBody(serverNameExt(nameEntry(1, ""), hostName("www.example.com"))), wantErr: tlsx.ErrMalformed},
		{
			name:    "name longer than the list",
			body:    helloBody(extension(0, lp16(cat([]byte{0}, u16(20), []byte("short"))))),
			wantErr: tlsx.ErrMalformed,
		},
		{name: "entry cut after its name_type", body: helloBody(extension(0, lp16([]byte{0}))), wantErr: tlsx.ErrMalformed},
		{
			name:    "entry cut inside its name length",
			body:    helloBody(extension(0, lp16([]byte{0, 0}))),
			wantErr: tlsx.ErrMalformed,
		},
		{
			name:    "bytes after the server_name list",
			body:    helloBody(extension(0, cat(lp16(hostName("www.example.com")), []byte{0}))),
			wantErr: tlsx.ErrMalformed,
		},
		{
			name:    "list longer than the extension data",
			body:    helloBody(extension(0, cat(u16(100), hostName("x.example")))),
			wantErr: tlsx.ErrMalformed,
		},
		{
			name:    "damaged entry after a good host_name",
			body:    helloBody(extension(0, lp16(cat(hostName("www.example.com"), []byte{0, 0})))),
			wantErr: tlsx.ErrMalformed,
		},

		// ALPN defects.
		{name: "empty alpn extension", body: helloBody(extension(16, nil)), wantErr: tlsx.ErrMalformed},
		{name: "empty alpn list", body: helloBody(extension(16, u16(0))), wantErr: tlsx.ErrMalformed},
		{
			name:    "empty alpn protocol",
			body:    helloBody(extension(16, lp16(cat(lp8([]byte("h2")), []byte{0})))),
			wantErr: tlsx.ErrMalformed,
		},
		{name: "protocol longer than the list", body: helloBody(extension(16, lp16([]byte{5, 'h', '2'}))), wantErr: tlsx.ErrMalformed},
		{
			name:    "bytes after the alpn list",
			body:    helloBody(extension(16, cat(lp16(lp8([]byte("h2"))), []byte{0}))),
			wantErr: tlsx.ErrMalformed,
		},

		// Extension block defects.
		{
			name:    "extension data overruns the block",
			body:    cat(prefix, lp16(cat(u16(0x17), u16(10), []byte{1, 2}))),
			wantErr: tlsx.ErrMalformed,
		},
		{name: "extension header cut short", body: cat(prefix, lp16([]byte{0x00, 0x17, 0x00})), wantErr: tlsx.ErrMalformed},
		{name: "extension type alone", body: cat(prefix, lp16([]byte{0x00, 0x17})), wantErr: tlsx.ErrMalformed},
		{name: "bytes after the extension block", body: cat(helloBody(alpnExt("h2")), []byte{0}), wantErr: tlsx.ErrMalformed},
		{name: "one stray byte instead of an extension block", body: cat(prefix, []byte{0}), wantErr: tlsx.ErrMalformed},
		{name: "extension block longer than the body", body: cat(prefix, u16(100), []byte{0, 0}), wantErr: tlsx.ErrMalformed},

		// Fixed part defects.
		{name: "empty body", body: nil, wantErr: tlsx.ErrMalformed},
		{name: "version and random cut short", body: prefix[:20], wantErr: tlsx.ErrMalformed},
		{name: "no session id length", body: prefix[:34], wantErr: tlsx.ErrMalformed},
		{
			name:    "session id longer than the body",
			body:    cat([]byte{3, 3}, make([]byte, 32), []byte{32}, make([]byte, 5)),
			wantErr: tlsx.ErrMalformed,
		},
		{
			name:    "odd cipher_suites length",
			body:    cat([]byte{3, 3}, make([]byte, 32), lp8(nil), lp16([]byte{0x13, 0x01, 0xc0}), lp8([]byte{0})),
			wantErr: tlsx.ErrMalformed,
		},
		{name: "no compression methods field", body: prefix[:len(prefix)-2], wantErr: tlsx.ErrMalformed},
		{name: "compression methods cut short", body: prefix[:len(prefix)-1], wantErr: tlsx.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sni, alpn, err := tlsx.ParseClientHelloBody(tt.body)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if sni != "" || alpn != nil {
					t.Errorf("SNI %q ALPN %q returned together with an error", sni, alpn)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sni != tt.wantSNI {
				t.Errorf("SNI = %q, want %q", sni, tt.wantSNI)
			}
			if !reflect.DeepEqual(alpn, tt.wantALPN) {
				t.Errorf("ALPN = %#v, want %#v", alpn, tt.wantALPN)
			}
		})
	}
}

// TestParseClientHelloBodyKeepsNoReferences makes sure the results do not
// alias the input, which the caller may reuse.
func TestParseClientHelloBodyKeepsNoReferences(t *testing.T) {
	body := helloBody(serverNameExt(hostName("www.example.com")), alpnExt("h2"))
	sni, alpn, err := tlsx.ParseClientHelloBody(body)
	if err != nil {
		t.Fatal(err)
	}
	for i := range body {
		body[i] = 'X'
	}
	if sni != "www.example.com" || !slices.Equal(alpn, []string{"h2"}) {
		t.Errorf("results changed with the input: SNI %q ALPN %q", sni, alpn)
	}
}
