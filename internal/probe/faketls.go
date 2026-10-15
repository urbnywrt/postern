// Package probe checks MTProto proxies from the client's side.
//
// FakeTLS is the L1 probe of the design: the client half of the MTProto
// fake-TLS handshake, the one of "ee" secrets, run against an engine on its
// loopback port or against a listener of the node's edge. It needs no internet
// access and shows two things: that the connection reaches a fake-TLS server,
// and that the server knows the proxy secret. It is the readiness gate of
// blue-green engine swaps and the first step of the end-to-end tests.
// Handshake is the same handshake on a connection that the caller opened and
// keeps: the end-to-end tests hold such a connection open through the edge.
//
// L2 goes on from the handshake to Telegram itself. Through the proxy it opens
// an obfuscated2 connection to a datacenter and sends the first message of
// MTProto's key exchange, req_pq_multi, which only a datacenter answers, with
// resPQ: the L2 probe of the design, the whole path as a client sees it. DCPing
// is the same exchange without a proxy, on a connection to a datacenter that
// the caller opened, directly or through an egress member. The health checks of
// egress members rest on it, because a member that acknowledges a connection
// (Xray's SOCKS inbound does so before it has connected anywhere) has not yet
// shown that it reaches anything.
//
// # The handshake
//
// What the client sends and checks is what Telegram's own client library does,
// tdlib (td/mtproto/TlsInit.cpp), and the Go client of gotd
// (github.com/gotd/td/mtproxy/faketls); what the server expects and answers is
// what mtg v2 (github.com/9seconds/mtg/v2/mtglib/internal/tls/fake) and telemt
// (src/protocol/tls.rs) do:
//
//  1. The client sends one TLS record holding a ClientHello for the proxy's
//     domain. Its 32-byte random is
//
//     HMAC-SHA256(secret, the record with the random zeroed) XOR (28 zero bytes || uint32le(unix time))
//
//     A server that knows the secret recomputes the HMAC, wants the 28 zero
//     bytes, compares the time with its own clock (telemt allows two minutes
//     either way) and refuses a random it has seen before. A server that does
//     not know the secret takes the connection for a browser's and passes it
//     on to its masking host.
//
//  2. The server answers with three records: a ServerHello handshake record, a
//     ChangeCipherSpec record, and one ApplicationData record that stands in
//     for the encrypted certificate. The random of the ServerHello is
//
//     HMAC-SHA256(secret, client random || the three records with that random zeroed)
//
//     which only a server that knows the secret and has seen this very
//     ClientHello can produce. Whatever follows the three records is not
//     covered: it is the server's first data.
//
// The answer must have exactly the shape Telegram's clients accept: tdlib
// matches the bytes 16 03 03, then 14 03 03 00 01 01 17 03 03, and computes the
// HMAC over what they frame. An answer in any other shape fails the probe even
// when its digest would verify, because a client could not connect through
// that server either. (gotd is more lenient: it lets other handshake records
// come before the ChangeCipherSpec.)
package probe

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

// Options tunes FakeTLS. The zero value is ready to use.
type Options struct {
	// ProxyHeader, when set, is the source address of a PROXY protocol v2
	// header that FakeTLS sends ahead of the ClientHello; the destination is
	// the address it connected to. Engines take connections from the edge only
	// with that header (telemt listens with proxy_protocol = true); the edge's
	// own listeners take none.
	ProxyHeader *netip.AddrPort
	// Timeout bounds the whole probe: connecting, sending the ClientHello and
	// reading the answer. Zero or less means 10 seconds. A deadline of the
	// context that comes sooner applies as well.
	Timeout time.Duration
	// Now is the clock that dates the ClientHello; nil means time.Now. The
	// server compares the date with its own clock; the client checks no time
	// at all.
	Now func() time.Time
}

// ErrBadServerDigest is the error of FakeTLS when the server answers in the
// shape of a fake-TLS server but the random of its ServerHello is not the
// digest of the secret: the server does not know the secret. That is the
// answer of telemt 3.5.13 to a secret it does not know when it cannot reach
// its masking host, and of a TLS 1.3 server that the connection reached
// instead, a masking host for example.
var ErrBadServerDigest = errors.New("probe: server digest mismatch")

const (
	defaultTimeout = 10 * time.Second

	secretLen = 16
	// maxSNILen is the longest server name FakeTLS sends: the longest domain
	// name, which is also as long as the node lets a proxy domain be.
	maxSNILen = 253

	recordHeaderLen = 5 // type, version, length

	recordTypeChangeCipherSpec = 0x14
	recordTypeAlert            = 0x15
	recordTypeHandshake        = 0x16
	recordTypeApplicationData  = 0x17

	handshakeTypeClientHello = 0x01

	// randomOffset is where the 32-byte random sits in a ClientHello or
	// ServerHello record: after the record header, the handshake type and
	// length (4 bytes) and the legacy version (2 bytes).
	randomOffset = recordHeaderLen + 4 + 2
	randomLen    = 32

	// helloSize is the size the ClientHello record is padded to when it is
	// smaller than 513 bytes, as tdlib does: a record of 512 bytes.
	helloSize = 517
)

// FakeTLS connects to addr, sends a PROXY v2 header first when
// opt.ProxyHeader is set, performs the client side of the MTProto fake-TLS
// handshake for the server name sni with the 16-byte proxy secret, and checks
// the server's answer. It returns nil only when the server proved that it
// knows the secret. It is Handshake on a connection of its own, which it
// closes before it returns.
//
// Otherwise the error says what went wrong: ErrBadServerDigest for an answer
// of the right shape with the wrong digest; an error that names the TLS alert
// or the record that came instead of the expected one; io.EOF (wrapped) when
// the server closed the connection without answering, io.ErrUnexpectedEOF
// (wrapped) when it closed it in the middle of its answer;
// context.DeadlineExceeded or context.Canceled (wrapped) when the probe ran out
// of time or was canceled. The error never contains the secret, and the probe
// logs nothing.
func FakeTLS(ctx context.Context, addr, sni string, secret []byte, opt Options) error {
	if err := checkArguments(sni, secret, opt); err != nil {
		return err
	}
	return dialAndRun(ctx, addr, opt, func(conn net.Conn) error {
		return Handshake(conn, sni, secret, opt)
	})
}

// dialAndRun connects to addr and runs probe on the connection, which it closes
// when probe returns; the whole of it has opt.Timeout, or less when ctx says
// so. It returns the error of probe as failure makes it.
func dialAndRun(ctx context.Context, addr string, opt Options, probe func(conn net.Conn) error) error {
	ctx, cancel := context.WithTimeout(ctx, opt.timeout())
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return failure(ctx, fmt.Errorf("probe: connecting: %w", err))
	}
	defer func() { _ = conn.Close() }()
	// I/O stops at the deadline of ctx, and at once when ctx is canceled. The
	// deadline is ctx's alone: probe sees the connection through ctxDeadline,
	// so that the deadline Handshake sets for itself cannot undo a
	// cancellation that came first.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	return failure(ctx, probe(ctxDeadline{conn}))
}

// Handshake performs the client side of the MTProto fake-TLS handshake for
// the server name sni with the 16-byte proxy secret on conn, a connection to
// the server that the caller opened, and checks the server's answer exactly as
// FakeTLS does. When opt.ProxyHeader is set, a PROXY v2 header goes out first,
// to the address conn is connected to. It returns nil only when the server
// proved that it knows the secret.
//
// The handshake has opt.Timeout to finish (10 seconds when it is zero or
// less): Handshake sets the deadline of conn for it. When the handshake
// succeeds, Handshake clears the deadline again and leaves conn right after
// the server's answer, at the first byte of the data that comes after it, so
// the connection can carry on: a client goes on to speak MTProto there, and a
// test can hold the connection open. Handshake never closes conn; after an
// error, conn is of no further use.
//
// The errors are those of FakeTLS, except that running out of time is an
// error that wraps os.ErrDeadlineExceeded. The error never contains the
// secret, and Handshake logs nothing.
func Handshake(conn net.Conn, sni string, secret []byte, opt Options) error {
	if err := checkArguments(sni, secret, opt); err != nil {
		return err
	}
	if conn == nil {
		return errors.New("probe: there is no connection")
	}
	if err := conn.SetDeadline(time.Now().Add(opt.timeout())); err != nil {
		return fmt.Errorf("probe: setting the deadline of the connection: %w", err)
	}
	var prefix []byte
	if opt.ProxyHeader != nil {
		prefix = appendProxyHeaderV2(nil, *opt.ProxyHeader, remoteAddrPort(conn))
	}
	switch err := handshake(conn, prefix, sni, secret, opt.now()); {
	case errors.Is(err, ErrBadServerDigest):
		return ErrBadServerDigest
	case err != nil:
		return fmt.Errorf("probe: %w", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("probe: clearing the deadline of the connection: %w", err)
	}
	return nil
}

// checkArguments reports what is wrong with the arguments of FakeTLS and
// Handshake, before anything goes out.
func checkArguments(sni string, secret []byte, opt Options) error {
	if len(secret) != secretLen {
		return fmt.Errorf("probe: the secret must be %d bytes, not %d", secretLen, len(secret))
	}
	if sni == "" || len(sni) > maxSNILen {
		return fmt.Errorf("probe: the server name must be 1 to %d bytes long", maxSNILen)
	}
	if opt.ProxyHeader != nil && !opt.ProxyHeader.Addr().IsValid() {
		return errors.New("probe: the source address for the PROXY header is not valid")
	}
	return nil
}

// ctxDeadline is the connection of FakeTLS and L2 as Handshake sees it: its
// deadline follows the context of the probe, and the deadlines Handshake sets
// are dropped.
type ctxDeadline struct{ net.Conn }

func (ctxDeadline) SetDeadline(time.Time) error      { return nil }
func (ctxDeadline) SetReadDeadline(time.Time) error  { return nil }
func (ctxDeadline) SetWriteDeadline(time.Time) error { return nil }

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return defaultTimeout
	}
	return o.Timeout
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

// failure makes err, the outcome of connecting, of Handshake or of the
// exchange of L2 or DCPing, the error the probe returns. When the probe ran
// out of time or was canceled, the error wraps the context's error as well, so
// that errors.Is finds context.DeadlineExceeded or context.Canceled next to the
// I/O error that it caused. ErrBadServerDigest and ErrBadResPQ are verdicts on
// what the server sent and stay as they are.
func failure(ctx context.Context, err error) error {
	switch {
	case err == nil, errors.Is(err, ErrBadServerDigest), errors.Is(err, ErrBadResPQ):
		return err
	case ctx.Err() != nil:
		return fmt.Errorf("%w (%w)", err, ctx.Err())
	case errors.Is(err, os.ErrDeadlineExceeded):
		// The connection's deadline, which is ctx's, passed a moment before
		// ctx noticed.
		return fmt.Errorf("%w (%w)", err, context.DeadlineExceeded)
	}
	return err
}

// remoteAddrPort returns the address conn is connected to, or the zero value
// when it is not a TCP connection.
func remoteAddrPort(conn net.Conn) netip.AddrPort {
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort()
	}
	return netip.AddrPort{}
}

// handshake runs the fake-TLS handshake on rw: it writes prefix (a PROXY
// header, or nothing) and the ClientHello in a single write, then reads the
// server's answer and checks it. It reads exactly the three records of the
// answer and nothing after them, so the connection can carry on.
func handshake(rw io.ReadWriter, prefix []byte, sni string, secret []byte, now time.Time) error {
	hello, err := clientHello(sni, secret, now)
	if err != nil {
		return err
	}
	if _, err := rw.Write(append(prefix, hello...)); err != nil {
		return fmt.Errorf("sending the ClientHello: %w", err)
	}
	return readServerAnswer(rw, hello[randomOffset:randomOffset+randomLen], secret)
}

// ---- the ClientHello ----------------------------------------------------------

// helloCipherSuites are the cipher suites the ClientHello offers: the three TLS
// 1.3 suites first, then Chrome's TLS 1.2 suites, in the order of tdlib's
// template. telemt answers with one of the TLS 1.3 suites and refuses a hello
// without them; the official MTProxy wants the first suite that is not GREASE
// to be one of them.
var helloCipherSuites = [...]uint16{
	0x1301, 0x1302, 0x1303, // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
	0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
}

// helloFixedExtensions are the extensions of the ClientHello that are the same
// every time, written out whole (type, length, body). They are the extensions of
// tdlib's template (Chrome's) except for what a fake-TLS server does without:
// GREASE, ALPS, encrypted_client_hello and the X25519MLKEM768 key share (telemt
// answers an X25519 share as well). The server name and the X25519 key share,
// which change, come before them; the padding comes last.
const helloFixedExtensions = "" +
	"\x00\x17\x00\x00" + // extended_master_secret
	"\xff\x01\x00\x01\x00" + // renegotiation_info: no previous connection
	"\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18" + // supported_groups: x25519, secp256r1, secp384r1
	"\x00\x0b\x00\x02\x01\x00" + // ec_point_formats: uncompressed
	"\x00\x23\x00\x00" + // session_ticket: none yet
	"\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1" + // application_layer_protocol_negotiation: h2, http/1.1
	"\x00\x05\x00\x05\x01\x00\x00\x00\x00" + // status_request: OCSP
	"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01" + // signature_algorithms
	"\x00\x12\x00\x00" + // signed_certificate_timestamp
	"\x00\x2d\x00\x02\x01\x01" + // psk_key_exchange_modes: psk_dhe_ke
	"\x00\x2b\x00\x05\x04\x03\x04\x03\x03" + // supported_versions: TLS 1.3, TLS 1.2
	"\x00\x1b\x00\x03\x02\x00\x02" // compress_certificate: brotli

const (
	extServerName = 0x0000
	extKeyShare   = 0x0033
	extPadding    = 0x0015
	groupX25519   = 0x001d
)

// clientHello returns a ClientHello record for the server name sni, dated now
// and signed with secret: a TLS 1.3 hello in a TLS 1.0 record, the way
// browsers and tdlib send it, with a fresh 32-byte session id and a fresh
// X25519 key share. Its random is the digest (see the package documentation).
func clientHello(sni string, secret []byte, now time.Time) ([]byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("making the key share: %w", err)
	}
	var sessionID [32]byte
	_, _ = rand.Read(sessionID[:]) // never fails

	b := make([]byte, 0, helloSize+len(sni))
	b = append(b, recordTypeHandshake, 3, 1, 0, 0) // record header; its length is set below
	b = append(b, handshakeTypeClientHello, 0, 0, 0)
	b = append(b, 3, 3)                       // legacy_version: TLS 1.2
	b = append(b, make([]byte, randomLen)...) // random: the digest, set below
	b = append(b, byte(len(sessionID)))
	b = append(b, sessionID[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(2*len(helloCipherSuites)))
	for _, cs := range helloCipherSuites {
		b = binary.BigEndian.AppendUint16(b, cs)
	}
	b = append(b, 1, 0) // compression_methods: null only
	extensions := len(b)
	b = append(b, 0, 0) // their length, set below

	// server_name: one host_name, the bytes of sni as they are.
	b = binary.BigEndian.AppendUint16(b, extServerName)
	b = binary.BigEndian.AppendUint16(b, uint16(len(sni)+5))
	b = binary.BigEndian.AppendUint16(b, uint16(len(sni)+3))
	b = append(b, 0) // host_name
	b = binary.BigEndian.AppendUint16(b, uint16(len(sni)))
	b = append(b, sni...)
	// key_share: X25519.
	pub := key.PublicKey().Bytes()
	b = binary.BigEndian.AppendUint16(b, extKeyShare)
	b = binary.BigEndian.AppendUint16(b, uint16(len(pub)+6))
	b = binary.BigEndian.AppendUint16(b, uint16(len(pub)+4))
	b = binary.BigEndian.AppendUint16(b, groupX25519)
	b = binary.BigEndian.AppendUint16(b, uint16(len(pub)))
	b = append(b, pub...)
	b = append(b, helloFixedExtensions...)
	// padding up to helloSize, when there is room for it.
	if len(b) < helloSize-4 {
		n := helloSize - 4 - len(b)
		b = binary.BigEndian.AppendUint16(b, extPadding)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
		b = append(b, make([]byte, n)...)
	}

	binary.BigEndian.PutUint16(b[3:], uint16(len(b)-recordHeaderLen))
	n := len(b) - recordHeaderLen - 4
	b[6], b[7], b[8] = byte(n>>16), byte(n>>8), byte(n)
	binary.BigEndian.PutUint16(b[extensions:], uint16(len(b)-extensions-2))

	mac := hmac.New(sha256.New, secret)
	mac.Write(b)
	digest := mac.Sum(nil)
	ts := binary.LittleEndian.Uint32(digest[randomLen-4:]) ^ uint32(now.Unix())
	binary.LittleEndian.PutUint32(digest[randomLen-4:], ts)
	copy(b[randomOffset:], digest)
	return b, nil
}

// ---- the answer ---------------------------------------------------------------

// readServerAnswer reads the server's answer to the ClientHello whose random
// is clientRandom (ServerHello, ChangeCipherSpec, ApplicationData) and checks
// the digest in the random of the ServerHello. It reads exactly these three
// records. Each record must be what its place calls for, which is known from
// its header: a server that answers otherwise is caught before more of its
// answer is waited for.
func readServerAnswer(r io.Reader, clientRandom, secret []byte) error {
	answer, err := readRecord(r, nil, recordTypeHandshake)
	if err != nil {
		return err
	}
	if len(answer) < randomOffset+randomLen {
		return fmt.Errorf("the server's handshake record is too short for a ServerHello (%d bytes)", len(answer)-recordHeaderLen)
	}
	ccs := len(answer)
	if answer, err = readRecord(r, answer, recordTypeChangeCipherSpec); err != nil {
		return err
	}
	if len(answer)-ccs != recordHeaderLen+1 || answer[len(answer)-1] != 1 {
		return errors.New("the server's ChangeCipherSpec record does not hold the single byte 1")
	}
	if answer, err = readRecord(r, answer, recordTypeApplicationData); err != nil {
		return err
	}

	var got [randomLen]byte
	copy(got[:], answer[randomOffset:])
	clear(answer[randomOffset : randomOffset+randomLen])
	mac := hmac.New(sha256.New, secret)
	mac.Write(clientRandom)
	mac.Write(answer)
	if !hmac.Equal(mac.Sum(nil), got[:]) {
		return ErrBadServerDigest
	}
	return nil
}

// readRecord reads the next record of the server's answer, which must be of
// type want in a TLS 1.2 record (version 3.3, the only one fake-TLS servers
// send and Telegram's clients take), and returns answer with the whole record
// appended. A TLS alert in its place makes an error that names the alert.
func readRecord(r io.Reader, answer []byte, want byte) ([]byte, error) {
	var hdr [recordHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if answer == nil && errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("the server closed the connection without answering: %w", err)
		}
		return nil, readError(err)
	}
	typ, n := hdr[0], int(binary.BigEndian.Uint16(hdr[3:]))
	if typ == recordTypeAlert && hdr[1] == 3 && n == 2 {
		var alert [2]byte
		if _, err := io.ReadFull(r, alert[:]); err != nil {
			return nil, readError(err)
		}
		return nil, fmt.Errorf("the server answered with TLS alert %d%s", alert[1], alertName(alert[1]))
	}
	if typ != want {
		return nil, fmt.Errorf("the server sent a record of type %#02x where %s belongs", typ, recordName(want))
	}
	if hdr[1] != 3 || hdr[2] != 3 {
		return nil, fmt.Errorf("the server's %s has version %d.%d, not 3.3", recordName(want), hdr[1], hdr[2])
	}
	start := len(answer)
	answer = append(answer, hdr[:]...)
	answer = append(answer, make([]byte, n)...)
	if _, err := io.ReadFull(r, answer[start+recordHeaderLen:]); err != nil {
		return nil, readError(err)
	}
	return answer, nil
}

// readError is err, from reading inside the answer: an end of the stream there
// is unexpected.
func readError(err error) error {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("reading the server's answer: %w", err)
}

func recordName(typ byte) string {
	switch typ {
	case recordTypeHandshake:
		return "a handshake record (ServerHello)"
	case recordTypeChangeCipherSpec:
		return "a ChangeCipherSpec record"
	case recordTypeApplicationData:
		return "an ApplicationData record"
	}
	return "another record"
}

// alertName names the alerts a server is likely to send instead of an answer:
// unrecognized_name is what the edge sends for a server name it does not route.
func alertName(desc byte) string {
	switch desc {
	case 40:
		return " (handshake_failure)"
	case 70:
		return " (protocol_version)"
	case 80:
		return " (internal_error)"
	case 112:
		return " (unrecognized_name)"
	}
	return ""
}

// ---- PROXY protocol -----------------------------------------------------------

// proxySignature opens every PROXY protocol v2 header.
const proxySignature = "\r\n\r\n\x00\r\nQUIT\n"

// appendProxyHeaderV2 appends to b the PROXY protocol v2 header (HAProxy's
// specification, section 2.2) for a TCP connection from src to dst, with the
// PROXY command and no TLVs. It is IPv4 when both addresses are IPv4, an
// IPv4-mapped IPv6 address counting as IPv4, and IPv6 otherwise, IPv4
// addresses then going out in their mapped form. It writes the same bytes as
// proxyproto.HeaderV2 of the edge, which this copy is to give way to.
func appendProxyHeaderV2(b []byte, src, dst netip.AddrPort) []byte {
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	b = append(b, proxySignature...)
	b = append(b, 0x21) // version 2, PROXY
	if s.Is4() && d.Is4() {
		b = append(b, 0x11, 0, 12) // TCP over IPv4, 12 bytes of addresses
		s4, d4 := s.As4(), d.As4()
		b = append(b, s4[:]...)
		b = append(b, d4[:]...)
	} else {
		b = append(b, 0x21, 0, 36) // TCP over IPv6, 36 bytes of addresses
		s16, d16 := s.As16(), d.As16()
		b = append(b, s16[:]...)
		b = append(b, d16[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, src.Port())
	return binary.BigEndian.AppendUint16(b, dst.Port())
}
