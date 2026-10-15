package probe

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const testSNI = "www.example.com"

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails
	return b
}

// ---- the server half of fake TLS ----------------------------------------------

// fakeServer is the server half of MTProto fake TLS on a loopback port, written
// after mtg v2.2.8 (mtglib/internal/tls/fake: ReadClientHello, SendServerHello)
// and telemt 3.5.13 (src/protocol/tls.rs: validate_tls_handshake,
// build_server_hello_with_cipher), independently of the code under test. It
// reads the ClientHello record the way they do, checks the client digest with
// its secret, and answers with a ServerHello record, a ChangeCipherSpec record
// and one ApplicationData record, the ServerHello random being
// HMAC-SHA256(secret, client random || answer). Unlike them it does not judge
// the timestamp in the digest (telemt allows two minutes either way): it only
// reports it, so that a test can tell what the client sent.
type fakeServer struct {
	// secret checks the client digest and signs the answer.
	secret []byte
	// answerAnyway makes the server answer a ClientHello whose digest does not
	// verify with its secret, signing with that secret all the same: a server
	// that does not know the client's secret but answers in the shape of a
	// fake-TLS server. telemt does that when it cannot reach its masking host,
	// which otherwise gets such a connection.
	answerAnyway bool
	// proxyHeader makes the server read a PROXY protocol v2 header first.
	proxyHeader bool
	// hold makes the server read the ClientHello and then say nothing until
	// the test ends.
	hold bool
	// answer, when set, replaces the regular answer with what it returns; nil
	// closes the connection without a word.
	answer func(c *conversation) []byte
	// hangUp makes the server close the connection right after its answer
	// instead of waiting for the client to.
	hangUp bool
	// after, when set, takes the connection over once the answer is out: the
	// rest of the conversation is its. done is closed when the test ends.
	after func(conn net.Conn, done <-chan struct{})

	addr          string
	conversations chan *conversation
}

// conversation is what the server made of one connection.
type conversation struct {
	proxySrc, proxyDst netip.AddrPort // from the PROXY header
	proxyFamily        byte           // of the PROXY header: 0x11 TCP over IPv4, 0x21 over IPv6
	record             []byte         // the ClientHello record as it came
	hello              *parsedHello
	digestOK           bool   // the client random verifies with the server's secret
	timestamp          uint32 // the time in the client digest, when it verifies
	err                error  // why the server gave up on the connection
}

func startFakeServer(t *testing.T, s fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &s
	srv.addr = ln.Addr().String()
	srv.conversations = make(chan *conversation, 16)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { srv.serve(conn, done) })
		}
	})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	})
	return srv
}

func (s *fakeServer) serve(conn net.Conn, done <-chan struct{}) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	c := s.converse(conn)
	var answer []byte
	if c.err == nil {
		switch {
		case s.hold:
			s.report(c)
			<-done
			return
		case s.answer != nil:
			answer = s.answer(c)
		case c.digestOK || s.answerAnyway:
			answer = regularAnswer(s.secret, c.hello)
		}
	}
	s.report(c)
	if answer == nil {
		return
	}
	if _, err := conn.Write(answer); err != nil || s.hangUp {
		return
	}
	if s.after != nil {
		s.after(conn, done)
		return
	}
	_, _ = io.Copy(io.Discard, conn) // until the client hangs up
}

func (s *fakeServer) report(c *conversation) {
	select {
	case s.conversations <- c:
	default:
	}
}

// converse reads what the client sends before the server answers.
func (s *fakeServer) converse(conn net.Conn) *conversation {
	c := &conversation{}
	if s.proxyHeader {
		if c.proxySrc, c.proxyDst, c.proxyFamily, c.err = readProxyV2(conn); c.err != nil {
			return c
		}
	}
	if c.record, c.err = readTLSRecord(conn); c.err != nil {
		return c
	}
	if c.hello, c.err = parseClientHello(c.record); c.err != nil {
		return c
	}
	c.digestOK, c.timestamp = clientDigest(c.record, s.secret)
	return c
}

// next returns what the server made of the next connection.
func (s *fakeServer) next(t *testing.T) *conversation {
	t.Helper()
	select {
	case c := <-s.conversations:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("the server saw no connection")
		return nil
	}
}

// readProxyV2 reads a PROXY protocol v2 header with the PROXY command for TCP
// over IPv4 or IPv6 (HAProxy's specification, section 2.2).
func readProxyV2(r io.Reader) (src, dst netip.AddrPort, family byte, err error) {
	var hdr [16]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return src, dst, 0, fmt.Errorf("PROXY header: %w", err)
	}
	if string(hdr[:12]) != "\r\n\r\n\x00\r\nQUIT\n" {
		return src, dst, 0, errors.New("no PROXY v2 signature")
	}
	if hdr[12] != 0x21 {
		return src, dst, 0, fmt.Errorf("PROXY version and command %#02x, want 0x21", hdr[12])
	}
	family = hdr[13]
	payload := make([]byte, binary.BigEndian.Uint16(hdr[14:]))
	if _, err = io.ReadFull(r, payload); err != nil {
		return src, dst, 0, fmt.Errorf("PROXY addresses: %w", err)
	}
	switch {
	case family == 0x11 && len(payload) == 12:
		src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(payload[0:4])), binary.BigEndian.Uint16(payload[8:10]))
		dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(payload[4:8])), binary.BigEndian.Uint16(payload[10:12]))
	case family == 0x21 && len(payload) == 36:
		src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(payload[0:16])), binary.BigEndian.Uint16(payload[32:34]))
		dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(payload[16:32])), binary.BigEndian.Uint16(payload[34:36]))
	default:
		return src, dst, 0, fmt.Errorf("PROXY family %#02x with %d bytes of addresses", family, len(payload))
	}
	return src, dst, family, nil
}

// readTLSRecord reads one TLS record, header included.
func readTLSRecord(r io.Reader) ([]byte, error) {
	rec := make([]byte, 5)
	if _, err := io.ReadFull(r, rec); err != nil {
		return nil, fmt.Errorf("record header: %w", err)
	}
	rec = append(rec, make([]byte, binary.BigEndian.Uint16(rec[3:5]))...)
	if _, err := io.ReadFull(r, rec[5:]); err != nil {
		return nil, fmt.Errorf("record: %w", err)
	}
	return rec, nil
}

// clientDigest checks the client random of a ClientHello record the way mtg's
// ReadClientHello and telemt's validate_tls_handshake do: the HMAC-SHA256 of the
// record with the random zeroed, XORed with the random, must be 28 zero bytes
// followed by a little-endian timestamp.
func clientDigest(rec, secret []byte) (ok bool, timestamp uint32) {
	zeroed := bytes.Clone(rec)
	clear(zeroed[11:43])
	mac := hmac.New(sha256.New, secret)
	mac.Write(zeroed)
	sum := mac.Sum(nil)
	for i := range sum {
		sum[i] ^= rec[11+i]
	}
	return bytes.Equal(sum[:28], make([]byte, 28)), binary.LittleEndian.Uint32(sum[28:])
}

// ---- parsing a ClientHello ----------------------------------------------------

// parsedHello is a ClientHello record taken apart.
type parsedHello struct {
	recordVersion uint16
	random        []byte
	sessionID     []byte
	cipherSuites  []uint16
	compression   []byte
	extensions    []uint16 // types, in order
	sni           string   // the first host_name
	alpn          []string
	versions      []uint16          // supported_versions
	keyShares     map[uint16][]byte // key_share: group to key
	padding       int               // length of the padding extension, -1 without one
}

// cursor reads big-endian fields off a byte slice and remembers running out.
type cursor struct {
	b   []byte
	bad bool
}

func (c *cursor) bytes(n int) []byte {
	if n < 0 || n > len(c.b) {
		c.bad, c.b = true, nil
		return nil
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}

func (c *cursor) u8() int {
	b := c.bytes(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (c *cursor) u16() int {
	b := c.bytes(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func (c *cursor) u24() int {
	b := c.bytes(3)
	if b == nil {
		return 0
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

func (c *cursor) vec8() []byte  { return c.bytes(c.u8()) }
func (c *cursor) vec16() []byte { return c.bytes(c.u16()) }

// parseClientHello takes a ClientHello record apart, checking every length the
// way a strict server would.
func parseClientHello(rec []byte) (*parsedHello, error) {
	h := &parsedHello{padding: -1, keyShares: map[uint16][]byte{}}

	c := &cursor{b: rec}
	if typ := c.u8(); typ != 0x16 {
		return nil, fmt.Errorf("record type %#02x, want a handshake record", typ)
	}
	h.recordVersion = uint16(c.u16())
	body := c.vec16()
	if c.bad || len(c.b) != 0 {
		return nil, errors.New("the record length does not match")
	}

	c = &cursor{b: body}
	if typ := c.u8(); typ != 0x01 {
		return nil, fmt.Errorf("handshake type %#02x, want a ClientHello", typ)
	}
	msg := c.bytes(c.u24())
	if c.bad || len(c.b) != 0 {
		return nil, errors.New("the handshake length does not match the record")
	}

	c = &cursor{b: msg}
	if v := c.u16(); v != 0x0303 {
		return nil, fmt.Errorf("legacy_version %#04x, want 0x0303", v)
	}
	h.random = c.bytes(32)
	h.sessionID = c.vec8()
	suites := c.vec16()
	if len(suites)%2 != 0 {
		return nil, errors.New("odd cipher suites length")
	}
	for i := 0; i+1 < len(suites); i += 2 {
		h.cipherSuites = append(h.cipherSuites, binary.BigEndian.Uint16(suites[i:]))
	}
	h.compression = c.vec8()
	exts := c.vec16()
	if c.bad || len(c.b) != 0 {
		return nil, errors.New("the extensions do not end the hello")
	}

	e := &cursor{b: exts}
	for len(e.b) > 0 && !e.bad {
		typ := uint16(e.u16())
		data := e.vec16()
		if e.bad {
			break
		}
		if slices.Contains(h.extensions, typ) {
			return nil, fmt.Errorf("extension %#04x appears twice", typ)
		}
		h.extensions = append(h.extensions, typ)

		d := &cursor{b: data}
		switch typ {
		case 0x0000: // server_name
			list := &cursor{b: d.vec16()}
			for len(list.b) > 0 && !list.bad {
				nameType := list.u8()
				name := list.vec16()
				if nameType == 0 && h.sni == "" {
					h.sni = string(name)
				}
			}
			d.bad = d.bad || list.bad
		case 0x0010: // application_layer_protocol_negotiation
			list := &cursor{b: d.vec16()}
			for len(list.b) > 0 && !list.bad {
				h.alpn = append(h.alpn, string(list.vec8()))
			}
			d.bad = d.bad || list.bad
		case 0x002b: // supported_versions
			list := &cursor{b: d.vec8()}
			for len(list.b) > 0 && !list.bad {
				h.versions = append(h.versions, uint16(list.u16()))
			}
			d.bad = d.bad || list.bad
		case 0x0033: // key_share
			list := &cursor{b: d.vec16()}
			for len(list.b) > 0 && !list.bad {
				group := uint16(list.u16())
				h.keyShares[group] = list.vec16()
			}
			d.bad = d.bad || list.bad
		case 0x0015: // padding
			if !bytes.Equal(data, make([]byte, len(data))) {
				return nil, errors.New("the padding is not all zero")
			}
			h.padding = len(data)
			d.b = nil
		default:
			d.b = nil
		}
		if d.bad || len(d.b) != 0 {
			return nil, fmt.Errorf("extension %#04x is malformed", typ)
		}
	}
	if e.bad {
		return nil, errors.New("the extension block is malformed")
	}
	return h, nil
}

// ---- answers ------------------------------------------------------------------

// tlsRecord returns a TLS record.
func tlsRecord(typ byte, version uint16, payload []byte) []byte {
	rec := []byte{typ, byte(version >> 8), byte(version)}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(payload)))
	return append(rec, payload...)
}

// serverHello returns the ServerHello record of mtg's SendServerHello and
// telemt's build_server_hello_with_cipher, its random still zero: legacy
// version TLS 1.2, the client's session id echoed, TLS_AES_128_GCM_SHA256, no
// compression, and the extensions supported_versions (TLS 1.3) and key_share
// (x25519).
func serverHello(sessionID []byte) []byte {
	m := []byte{0x03, 0x03}
	m = append(m, make([]byte, 32)...)
	m = append(m, byte(len(sessionID)))
	m = append(m, sessionID...)
	m = append(m, 0x13, 0x01, 0x00)
	m = append(m,
		0x00, 0x2e, // extensions, 46 bytes
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions: TLS 1.3
		0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, // key_share: x25519, 32 bytes
	)
	m = append(m, randomBytes(32)...)
	msg := append([]byte{0x02, byte(len(m) >> 16), byte(len(m) >> 8), byte(len(m))}, m...)
	return tlsRecord(0x16, 0x0303, msg)
}

var changeCipherSpec = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

// appData returns an ApplicationData record of n random bytes.
func appData(n int) []byte { return tlsRecord(0x17, 0x0303, randomBytes(n)) }

// signed joins records into an answer and sets the random of the ServerHello
// that opens it to HMAC-SHA256(secret, clientRandom || answer).
func signed(secret, clientRandom []byte, records ...[]byte) []byte {
	answer := bytes.Join(records, nil)
	mac := hmac.New(sha256.New, secret)
	mac.Write(clientRandom)
	mac.Write(answer)
	copy(answer[11:43], mac.Sum(nil))
	return answer
}

// regularAnswer is what mtg and telemt answer a ClientHello with: ServerHello,
// ChangeCipherSpec and one ApplicationData record of 2500 to 4700 bytes (mtg's
// default noise), signed with secret.
func regularAnswer(secret []byte, h *parsedHello) []byte {
	return signed(secret, h.random, serverHello(h.sessionID), changeCipherSpec, appData(2500+mrand.IntN(2200)))
}

// ---- the ClientHello ----------------------------------------------------------

func TestClientHello(t *testing.T) {
	secret := randomBytes(16)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	for _, sni := range []string{
		testSNI,
		"пример.example",                   // sent as it is: the UTF-8 bytes of the domain, as clients do
		strings.Repeat("ab.", 80) + "abc",  // 243 bytes: the longest name that still gets padding
		strings.Repeat("ab.", 80) + "abcd", // 244 bytes: no room left for it
		strings.Repeat("ab.", 83) + "test", // 253 bytes, the longest name
	} {
		t.Run(fmt.Sprintf("%d bytes", len(sni)), func(t *testing.T) {
			rec, err := clientHello(sni, secret, now)
			if err != nil {
				t.Fatal(err)
			}
			h, err := parseClientHello(rec)
			if err != nil {
				t.Fatalf("the ClientHello does not parse: %v", err)
			}

			// What every fake-TLS server relies on.
			if h.recordVersion != 0x0301 {
				t.Errorf("record version %#04x, want 0x0301 (mtg refuses anything else)", h.recordVersion)
			}
			if h.sni != sni {
				t.Errorf("server name %q, want %q", h.sni, sni)
			}
			if len(h.sessionID) != 32 || rec[43] != 32 {
				t.Errorf("session id of %d bytes, want 32 (the official MTProxy echoes client_hello+44 as a 32-byte id)", len(h.sessionID))
			}
			// The official MTProxy reads the cipher suites at offset 76 and takes
			// the first one that is not GREASE, which must be a TLS 1.3 suite;
			// telemt wants one of the three anywhere in the list.
			if n := int(binary.BigEndian.Uint16(rec[76:])); n != 2*len(h.cipherSuites) || rec[78] != 0x13 || rec[79] < 1 || rec[79] > 3 {
				t.Errorf("cipher suites at offset 76: % x, want a TLS 1.3 suite first", rec[76:80])
			}
			for _, cs := range []uint16{0x1301, 0x1302, 0x1303} {
				if !slices.Contains(h.cipherSuites, cs) {
					t.Errorf("cipher suite %#04x not offered", cs)
				}
			}
			if !bytes.Equal(h.compression, []byte{0}) {
				t.Errorf("compression methods % x, want only null", h.compression)
			}
			if len(h.versions) == 0 || h.versions[0] != 0x0304 {
				t.Errorf("supported_versions %04x, want TLS 1.3 first (telemt answers a TLS 1.2 client in another shape)", h.versions)
			}
			if key := h.keyShares[0x001d]; len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
				t.Errorf("x25519 key share % x, want a 32-byte key (telemt refuses a hello without a usable one)", key)
			}
			if !slices.Equal(h.alpn, []string{"h2", "http/1.1"}) {
				t.Errorf("ALPN %q, want h2 and http/1.1", h.alpn)
			}

			// Padded to 517 bytes, the size of tdlib's hello, when there is room.
			unpadded := len(rec)
			if h.padding >= 0 {
				unpadded -= 4 + h.padding
			}
			switch {
			case unpadded < 513 && len(rec) != 517:
				t.Errorf("%d bytes, want 517: the padding is missing or wrong", len(rec))
			case unpadded >= 513 && h.padding >= 0:
				t.Errorf("a padding extension of %d bytes in a hello of %d bytes", h.padding, len(rec))
			}

			// The digest: the HMAC of the record with the random zeroed, its
			// last four bytes XORed with the time.
			ok, ts := clientDigest(rec, secret)
			if !ok {
				t.Fatal("the client random is not the HMAC of the record")
			}
			if ts != uint32(now.Unix()) {
				t.Errorf("timestamp %d, want %d", ts, now.Unix())
			}
			if ok, _ := clientDigest(rec, randomBytes(16)); ok {
				t.Error("the digest verifies with another secret")
			}
		})
	}

	t.Run("fresh every time", func(t *testing.T) {
		a, err := clientHello(testSNI, secret, now)
		if err != nil {
			t.Fatal(err)
		}
		b, err := clientHello(testSNI, secret, now)
		if err != nil {
			t.Fatal(err)
		}
		ha, _ := parseClientHello(a)
		hb, _ := parseClientHello(b)
		if bytes.Equal(ha.sessionID, hb.sessionID) || bytes.Equal(ha.keyShares[0x001d], hb.keyShares[0x001d]) || bytes.Equal(ha.random, hb.random) {
			t.Error("two hellos share a session id, key share or random: servers refuse a replayed random")
		}
	})
}

// ---- the PROXY header ---------------------------------------------------------

func TestAppendProxyHeaderV2(t *testing.T) {
	const sig = "0d0a0d0a000d0a515549540a"
	tests := []struct {
		name     string
		src, dst string
		want     string // hex
	}{
		{
			name: "IPv4",
			src:  "192.0.2.10:4321", dst: "127.0.0.1:20001",
			want: sig + "21" + "11" + "000c" + "c000020a" + "7f000001" + "10e1" + "4e21",
		},
		{
			name: "IPv4-mapped addresses count as IPv4",
			src:  "[::ffff:192.0.2.10]:4321", dst: "[::ffff:127.0.0.1]:20001",
			want: sig + "21" + "11" + "000c" + "c000020a" + "7f000001" + "10e1" + "4e21",
		},
		{
			name: "IPv6",
			src:  "[2001:db8::1]:4321", dst: "[::1]:20001",
			want: sig + "21" + "21" + "0024" + "20010db8000000000000000000000001" + "00000000000000000000000000000001" + "10e1" + "4e21",
		},
		{
			name: "mixed families go out as IPv6",
			src:  "[2001:db8::1]:4321", dst: "127.0.0.1:20001",
			want: sig + "21" + "21" + "0024" + "20010db8000000000000000000000001" + "00000000000000000000ffff7f000001" + "10e1" + "4e21",
		},
		{
			name: "what the reconciler sends",
			src:  "127.0.0.1:1", dst: "127.0.0.1:20001",
			want: sig + "21" + "11" + "000c" + "7f000001" + "7f000001" + "0001" + "4e21",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := []byte("before")
			got := appendProxyHeaderV2(bytes.Clone(prefix), netip.MustParseAddrPort(tt.src), netip.MustParseAddrPort(tt.dst))
			if !bytes.HasPrefix(got, prefix) {
				t.Fatalf("the header does not go after what is already there: %x", got)
			}
			if h := hex.EncodeToString(got[len(prefix):]); h != tt.want {
				t.Errorf("header\n got %s\nwant %s", h, tt.want)
			}
		})
	}
}

// ---- the probe ----------------------------------------------------------------

func TestFakeTLS(t *testing.T) {
	secret := randomBytes(16)
	at := func(tm time.Time) func() time.Time { return func() time.Time { return tm } }
	clock := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		server  fakeServer
		sni     string // testSNI when empty
		now     func() time.Time
		wantErr error // nil for success
	}{
		{name: "the server knows the secret", server: fakeServer{secret: secret}, now: at(clock)},
		{name: "the longest server name", server: fakeServer{secret: secret}, sni: strings.Repeat("ab.", 83) + "test", now: at(clock)},
		{name: "a server with another secret", server: fakeServer{secret: randomBytes(16), answerAnyway: true}, now: at(clock), wantErr: ErrBadServerDigest},
		// The client checks no time: its clock only goes into the ClientHello,
		// for the server to judge. These skews would make telemt refuse.
		{name: "client clock a day behind", server: fakeServer{secret: secret}, now: at(clock.Add(-24 * time.Hour))},
		{name: "client clock a day ahead", server: fakeServer{secret: secret}, now: at(clock.Add(24 * time.Hour))},
		{name: "client clock at the epoch", server: fakeServer{secret: secret}, now: at(time.Unix(0, 0))},
		{name: "the system clock by default", server: fakeServer{secret: secret}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startFakeServer(t, tt.server)
			sni := cmp.Or(tt.sni, testSNI)
			before := time.Now()
			err := FakeTLS(t.Context(), srv.addr, sni, secret, Options{Timeout: 5 * time.Second, Now: tt.now})
			after := time.Now()
			if !errors.Is(err, tt.wantErr) { // errors.Is(err, nil) holds for a nil err only
				t.Fatalf("FakeTLS: %v, want %v", err, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), hex.EncodeToString(secret)) {
				t.Errorf("the error gives the secret away: %v", err)
			}

			c := srv.next(t)
			if c.err != nil {
				t.Fatalf("the server could not read the ClientHello: %v", c.err)
			}
			if c.hello.sni != sni {
				t.Errorf("the server saw server name %q, want %q", c.hello.sni, sni)
			}
			if bytes.Equal(tt.server.secret, secret) {
				if !c.digestOK {
					t.Fatal("the client digest does not verify with the shared secret")
				}
				if tt.now != nil {
					if want := uint32(tt.now().Unix()); c.timestamp != want {
						t.Errorf("timestamp %d, want %d from Options.Now", c.timestamp, want)
					}
				} else if ts := int64(c.timestamp); ts < before.Unix() || ts > after.Unix() {
					t.Errorf("timestamp %d, want the time of the call (%d to %d)", ts, before.Unix(), after.Unix())
				}
			}
		})
	}
}

func TestFakeTLSAnswers(t *testing.T) {
	secret := randomBytes(16)
	other := randomBytes(16)
	alert := func(desc byte) []byte { return tlsRecord(0x15, 0x0303, []byte{2, desc}) }

	tests := []struct {
		name    string
		answer  func(c *conversation) []byte
		hangUp  bool   // the server closes the connection after the answer
		wantErr error  // matched with errors.Is; nil means any error, or none when wantMsg is empty too
		wantMsg string // part of the error text
	}{
		{
			name: "the answer of mtg and telemt",
			answer: func(c *conversation) []byte {
				return signed(secret, c.hello.random, serverHello(c.hello.sessionID), changeCipherSpec, appData(4000))
			},
		},
		{
			name: "the largest application data record",
			answer: func(c *conversation) []byte {
				return signed(secret, c.hello.random, serverHello(c.hello.sessionID), changeCipherSpec, appData(65535))
			},
		},
		{
			name: "an empty application data record",
			answer: func(c *conversation) []byte {
				return signed(secret, c.hello.random, serverHello(c.hello.sessionID), changeCipherSpec, appData(0))
			},
		},
		{
			// What follows the first ApplicationData record is the server's
			// next data, which Telegram's clients hand to MTProto.
			name: "records after the answer are not covered",
			answer: func(c *conversation) []byte {
				a := signed(secret, c.hello.random, serverHello(c.hello.sessionID), changeCipherSpec, appData(3000))
				return append(a, appData(100)...)
			},
		},
		{
			name: "signed with another secret",
			answer: func(c *conversation) []byte {
				return signed(other, c.hello.random, serverHello(c.hello.sessionID), changeCipherSpec, appData(3000))
			},
			wantErr: ErrBadServerDigest,
		},
		{
			name: "signed without the client random",
			answer: func(c *conversation) []byte {
				return signed(secret, nil, serverHello(c.hello.sessionID), changeCipherSpec, appData(3000))
			},
			wantErr: ErrBadServerDigest,
		},
		{
			name: "signed for another ClientHello",
			answer: func(c *conversation) []byte {
				return signed(secret, randomBytes(32), serverHello(c.hello.sessionID), changeCipherSpec, appData(3000))
			},
			wantErr: ErrBadServerDigest,
		},
		{
			// telemt's optional NewSessionTicket records are covered by its
			// digest; Telegram's clients check the first three records only.
			name: "the digest covers a record after the answer",
			answer: func(c *conversation) []byte {
				return signed(secret, c.hello.random, serverHello(c.hello.sessionID), changeCipherSpec, appData(3000), appData(80))
			},
			wantErr: ErrBadServerDigest,
		},
		{
			name:    "a TLS alert",
			answer:  func(*conversation) []byte { return alert(112) },
			wantMsg: "alert 112",
		},
		{
			name: "a TLS alert after the ServerHello",
			answer: func(c *conversation) []byte {
				return append(serverHello(c.hello.sessionID), alert(40)...)
			},
			wantMsg: "alert 40",
		},
		{
			name:    "application data first",
			answer:  func(*conversation) []byte { return appData(100) },
			wantMsg: "record",
		},
		{
			name: "a ServerHello in a TLS 1.0 record",
			answer: func(c *conversation) []byte {
				sh := serverHello(c.hello.sessionID)
				sh[2] = 0x01
				return signed(secret, c.hello.random, sh, changeCipherSpec, appData(3000))
			},
			wantMsg: "version",
		},
		{
			name: "a handshake record too short for a ServerHello",
			answer: func(c *conversation) []byte {
				return append(tlsRecord(0x16, 0x0303, randomBytes(37)), changeCipherSpec...)
			},
			wantMsg: "short",
		},
		{
			name: "no ChangeCipherSpec",
			answer: func(c *conversation) []byte {
				return signed(secret, c.hello.random, serverHello(c.hello.sessionID), appData(3000))
			},
			wantMsg: "ChangeCipherSpec",
		},
		{
			name: "a ChangeCipherSpec with another payload",
			answer: func(c *conversation) []byte {
				return signed(secret, c.hello.random, serverHello(c.hello.sessionID), tlsRecord(0x14, 0x0303, []byte{2}), appData(3000))
			},
			wantMsg: "ChangeCipherSpec",
		},
		{
			name: "two ChangeCipherSpec records",
			answer: func(c *conversation) []byte {
				return signed(secret, c.hello.random, serverHello(c.hello.sessionID), changeCipherSpec, changeCipherSpec, appData(3000))
			},
			wantMsg: "ApplicationData",
		},
		{
			// gotd accepts up to 16 of these; Telegram's clients accept none.
			name: "another handshake record before ChangeCipherSpec",
			answer: func(c *conversation) []byte {
				return signed(secret, c.hello.random, serverHello(c.hello.sessionID), tlsRecord(0x16, 0x0303, []byte{0x0b, 0, 0, 0}), changeCipherSpec, appData(3000))
			},
			wantMsg: "ChangeCipherSpec",
		},
		{
			name:    "plain HTTP",
			answer:  func(*conversation) []byte { return []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") },
			wantMsg: "record",
		},
		{
			name:    "the connection closed without an answer",
			answer:  func(*conversation) []byte { return nil },
			wantErr: io.EOF,
		},
		{
			name: "the connection closed inside the answer",
			answer: func(c *conversation) []byte {
				return append(serverHello(c.hello.sessionID), changeCipherSpec[:3]...)
			},
			hangUp:  true,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name: "the connection closed after the ServerHello",
			answer: func(c *conversation) []byte {
				return serverHello(c.hello.sessionID)
			},
			hangUp:  true,
			wantErr: io.ErrUnexpectedEOF,
		},
	}
	const timeout = 5 * time.Second
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startFakeServer(t, fakeServer{secret: secret, answer: tt.answer, hangUp: tt.hangUp})
			start := time.Now()
			err := FakeTLS(t.Context(), srv.addr, testSNI, secret, Options{Timeout: timeout})
			elapsed := time.Since(start)
			if c := srv.next(t); c.err != nil {
				t.Fatalf("the server could not read the ClientHello: %v", c.err)
			}

			success := tt.wantErr == nil && tt.wantMsg == ""
			switch {
			case success && err != nil:
				t.Fatalf("FakeTLS: %v, want success", err)
			case success:
				return
			case err == nil:
				t.Fatal("FakeTLS succeeded, want an error")
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Errorf("FakeTLS: %v, want %v", err, tt.wantErr)
			case tt.wantErr == nil && errors.Is(err, ErrBadServerDigest):
				t.Errorf("FakeTLS: %v, want an error about the shape of the answer", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("FakeTLS: %q, want it to mention %q", err, tt.wantMsg)
			}
			if !strings.HasPrefix(err.Error(), "probe: ") || strings.Count(err.Error(), "probe:") != 1 {
				t.Errorf("FakeTLS: %q, want the prefix %q, once", err, "probe: ")
			}
			// Every answer here is complete: the verdict comes from what the
			// server sent, not from running out of time.
			if errors.Is(err, context.DeadlineExceeded) || elapsed > timeout/2 {
				t.Errorf("FakeTLS took %v and returned %v: it waited for more than the server sent", elapsed, err)
			}
		})
	}
}

func TestFakeTLSProxyHeader(t *testing.T) {
	secret := randomBytes(16)
	tests := []struct {
		name       string
		src        string
		wantFamily byte
		wantSrc    string
		wantDst    func(server netip.AddrPort) netip.AddrPort
	}{
		{
			name: "IPv4", src: "192.0.2.10:4321", wantFamily: 0x11, wantSrc: "192.0.2.10:4321",
			wantDst: func(s netip.AddrPort) netip.AddrPort { return s },
		},
		{
			name: "what the reconciler sends", src: "127.0.0.1:1", wantFamily: 0x11, wantSrc: "127.0.0.1:1",
			wantDst: func(s netip.AddrPort) netip.AddrPort { return s },
		},
		{
			name: "IPv4-mapped source", src: "[::ffff:192.0.2.10]:4321", wantFamily: 0x11, wantSrc: "192.0.2.10:4321",
			wantDst: func(s netip.AddrPort) netip.AddrPort { return s },
		},
		{
			name: "IPv6 source, IPv4 server", src: "[2001:db8::1]:4321", wantFamily: 0x21, wantSrc: "[2001:db8::1]:4321",
			wantDst: func(s netip.AddrPort) netip.AddrPort {
				return netip.AddrPortFrom(netip.AddrFrom16(s.Addr().As16()), s.Port())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startFakeServer(t, fakeServer{secret: secret, proxyHeader: true})
			src := netip.MustParseAddrPort(tt.src)
			if err := FakeTLS(t.Context(), srv.addr, testSNI, secret, Options{ProxyHeader: &src, Timeout: 5 * time.Second}); err != nil {
				t.Fatalf("FakeTLS: %v", err)
			}
			c := srv.next(t)
			if c.err != nil {
				t.Fatalf("server: %v", c.err)
			}
			server := netip.MustParseAddrPort(srv.addr)
			if c.proxyFamily != tt.wantFamily {
				t.Errorf("family %#02x, want %#02x", c.proxyFamily, tt.wantFamily)
			}
			if got := c.proxySrc.String(); got != tt.wantSrc {
				t.Errorf("source %s, want %s", got, tt.wantSrc)
			}
			if want := tt.wantDst(server); c.proxyDst != want {
				t.Errorf("destination %s, want %s, the address the probe connected to", c.proxyDst, want)
			}
		})
	}

	t.Run("none unless asked for", func(t *testing.T) {
		// A server that reads a TLS record first, like the edge's listeners.
		srv := startFakeServer(t, fakeServer{secret: secret})
		if err := FakeTLS(t.Context(), srv.addr, testSNI, secret, Options{Timeout: 5 * time.Second}); err != nil {
			t.Fatalf("FakeTLS: %v", err)
		}
		if c := srv.next(t); c.err != nil {
			t.Fatalf("server: %v", c.err)
		}
	})
}

func TestFakeTLSTimeout(t *testing.T) {
	secret := randomBytes(16)
	tests := []struct {
		name    string
		timeout time.Duration
		ctx     func(t *testing.T) context.Context
		want    time.Duration
	}{
		{
			name: "Options.Timeout", timeout: 300 * time.Millisecond, want: 300 * time.Millisecond,
			ctx: func(t *testing.T) context.Context { return t.Context() },
		},
		{
			name: "the deadline of the context", timeout: 0, want: 300 * time.Millisecond,
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startFakeServer(t, fakeServer{secret: secret, hold: true})
			start := time.Now()
			err := FakeTLS(tt.ctx(t), srv.addr, testSNI, secret, Options{Timeout: tt.timeout})
			elapsed := time.Since(start)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("FakeTLS: %v, want context.DeadlineExceeded", err)
			}
			if elapsed < tt.want || elapsed > tt.want+2*time.Second {
				t.Errorf("FakeTLS returned after %v, want about %v", elapsed, tt.want)
			}
			if c := srv.next(t); c.err != nil {
				t.Errorf("server: %v", c.err)
			}
		})
	}
}

func TestFakeTLSCanceled(t *testing.T) {
	secret := randomBytes(16)
	srv := startFakeServer(t, fakeServer{secret: secret, hold: true})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	time.AfterFunc(200*time.Millisecond, cancel)

	start := time.Now()
	err := FakeTLS(ctx, srv.addr, testSNI, secret, Options{Timeout: 10 * time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("FakeTLS: %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("FakeTLS returned %v after the cancellation", elapsed)
	}
}

func TestFakeTLSConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	err = FakeTLS(t.Context(), addr, testSNI, randomBytes(16), Options{Timeout: 5 * time.Second})
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("FakeTLS: %v, want the connection refused", err)
	}
	if !strings.HasPrefix(err.Error(), "probe: ") {
		t.Errorf("FakeTLS: %q, want the prefix %q", err, "probe: ")
	}
}

func TestFakeTLSArguments(t *testing.T) {
	long := randomBytes(17)
	zero := netip.AddrPort{}
	tests := []struct {
		name   string
		secret []byte
		sni    string
		opt    Options
		want   string
	}{
		{name: "no secret", secret: nil, sni: testSNI, want: "16 bytes"},
		{name: "short secret", secret: randomBytes(15), sni: testSNI, want: "16 bytes"},
		{name: "long secret", secret: long, sni: testSNI, want: "16 bytes"},
		{name: "no server name", secret: randomBytes(16), sni: "", want: "server name"},
		{name: "server name too long", secret: randomBytes(16), sni: strings.Repeat("a", 254), want: "server name"},
		{name: "invalid PROXY source", secret: randomBytes(16), sni: testSNI, opt: Options{ProxyHeader: &zero}, want: "PROXY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Port 1 refuses: an argument that slipped through would fail with
			// a connection error instead.
			err := FakeTLS(t.Context(), "127.0.0.1:1", tt.sni, tt.secret, tt.opt)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("FakeTLS: %v, want an error about the %s", err, tt.want)
			}
			if len(tt.secret) > 0 && strings.Contains(err.Error(), hex.EncodeToString(tt.secret)) {
				t.Errorf("the error gives the secret away: %v", err)
			}
		})
	}
}

func TestOptionsDefaults(t *testing.T) {
	for _, tt := range []struct {
		timeout, want time.Duration
	}{{0, 10 * time.Second}, {-time.Second, 10 * time.Second}, {3 * time.Second, 3 * time.Second}} {
		if got := (Options{Timeout: tt.timeout}).timeout(); got != tt.want {
			t.Errorf("Options{Timeout: %v}.timeout() = %v, want %v", tt.timeout, got, tt.want)
		}
	}

	fixed := time.Date(2001, 9, 9, 1, 46, 40, 0, time.UTC)
	if got := (Options{Now: func() time.Time { return fixed }}).now(); !got.Equal(fixed) {
		t.Errorf("Options{Now: fixed}.now() = %v, want %v", got, fixed)
	}
	before := time.Now()
	got := (Options{}).now()
	if got.Before(before) || got.After(time.Now()) {
		t.Errorf("Options{}.now() = %v, want the current time", got)
	}
}
