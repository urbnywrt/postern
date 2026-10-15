package probe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

// The server half of the L2 exchange, written from the descriptions of the
// protocols (core.telegram.org: "MTProto transports", "Transport
// obfuscation", "Creating an Authorization Key") and from the servers that
// speak them (the official MTProxy, mtg v2), independently of the code under
// test:
//
// A client opens an obfuscated2 connection with 64 bytes. The server takes its
// decryption key from bytes 8..40 of them and the IV from bytes 40..56, and its
// encryption key and IV from the same 48 bytes reversed; with a proxy secret
// each key is the SHA-256 of the key followed by the secret. The ciphers are
// AES-256-CTR. Decrypting the 64 bytes with the decryption stream gives the
// transport tag at 56..60 and the datacenter at 60..62 (int16, little endian),
// and the stream goes on with the client's data: frames of the intermediate
// transports, a 4-byte little-endian length and that many bytes, of which the
// last 0 to 15 are padding in the padded variant. The first message of the key
// exchange is an unencrypted message, auth_key_id 0 (8 bytes), message_id (8),
// message_data_length (4) and the data, here req_pq_multi#be7e8ef1
// nonce:int128; the datacenter answers resPQ#05162463 nonce:int128
// server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long>.

const (
	testReqPQMulti = 0xbe7e8ef1
	testResPQ      = 0x05162463
	testVector     = 0x1cb5c415
)

// dcServer is the server half of obfuscated2 and of the first message of
// MTProto's key exchange: a Telegram datacenter as far as req_pq_multi goes, or,
// behind the fake-TLS proxy of startFakeProxy, the proxy and the datacenter at
// once.
type dcServer struct {
	// secret goes into the keys: the proxy secret behind a proxy, nil for a
	// datacenter. startFakeProxy sets it to the proxy's.
	secret []byte
	// answer, when set, returns what the server answers instead of a resPQ to
	// the request: the plaintext stream, frames and all, which goes out
	// encrypted. nil closes the connection without a word.
	answer func(s *dcSession) []byte
	// raw, when set, returns bytes that go out as they are instead of an
	// answer: not encrypted, and behind the proxy outside of any TLS record.
	raw func(s *dcSession) []byte
	// hold makes the server read the request and then say nothing until the
	// test ends.
	hold bool
	// hangUp makes the server close the connection right after its answer
	// instead of waiting for the client to.
	hangUp bool
	// recordSize, behind the proxy, sends the answer in TLS records of that
	// many bytes, after an empty record; 0 sends it in one record.
	recordSize int
	// repeat makes the server answer every further req_pq_multi of the
	// connection with its resPQ, as a datacenter does, instead of reading
	// nothing more of it.
	repeat bool
}

// dcSession is what the server made of one connection.
type dcSession struct {
	header   [64]byte // the header as it came
	tag      uint32   // the transport tag in the header
	dc       int16    // the datacenter in the header
	frameLen int      // the length of the client's frame: the message and the padding
	frame    []byte   // the client's frame, decrypted

	// The message in the frame.
	authKeyID, msgID uint64
	dataLen          uint32
	crc              uint32
	nonce            [16]byte

	// Behind the proxy only.
	ccs     bool  // the client's first record after the handshake was a ChangeCipherSpec
	records []int // the payload sizes of the client's application data records

	err error // why the server gave up on the connection
}

// serve reads the header and the request from r and answers on w: the data
// stream of the connection, which is conn itself for a datacenter and the TLS
// records on conn behind the proxy. Raw bytes go out on conn. It calls report
// once, with what it made of the connection, when it has read the request or
// given up on it; before it holds the connection, and before the answer goes
// out. done is closed when the test ends.
func (d dcServer) serve(conn net.Conn, r io.Reader, w io.Writer, done <-chan struct{}, report func(*dcSession)) {
	s := &dcSession{}
	enc, dec, err := d.readRequest(r, s)
	if err != nil {
		s.err = err
		report(s)
		return
	}

	var out, raw []byte
	switch {
	case d.hold:
		report(s)
		<-done
		return
	case d.raw != nil:
		raw = d.raw(s)
	case d.answer != nil:
		out = d.answer(s)
	default:
		out = dcFrame(s.tag, resPQMessage(s.nonce))
	}
	report(s)

	switch {
	case raw != nil:
		if _, err := conn.Write(raw); err != nil {
			return
		}
	case out != nil:
		enc.XORKeyStream(out, out)
		if _, err := w.Write(out); err != nil {
			return
		}
	default:
		return // closes the connection without a word
	}
	if d.hangUp {
		return
	}
	for d.repeat {
		frame, err := readClientFrame(cipher.StreamReader{S: dec, R: r})
		if err != nil || len(frame) < 40 {
			return
		}
		var nonce [16]byte
		copy(nonce[:], frame[24:40])
		answer := dcFrame(s.tag, resPQMessage(nonce))
		enc.XORKeyStream(answer, answer)
		if _, err := w.Write(answer); err != nil {
			return
		}
	}
	_, _ = io.Copy(io.Discard, conn) // until the client hangs up
}

// readRequest reads the header and the first frame, decrypts them and takes
// the message apart into s. It returns the stream that encrypts the answer,
// and the one that decrypts what the client sends after the first frame.
func (d dcServer) readRequest(r io.Reader, s *dcSession) (enc, dec cipher.Stream, err error) {
	if _, err := io.ReadFull(r, s.header[:]); err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	reversed := make([]byte, 48)
	for i := range reversed {
		reversed[i] = s.header[55-i]
	}
	dec = serverStream(s.header[8:40], s.header[40:56], d.secret)
	enc = serverStream(reversed[:32], reversed[32:], d.secret)

	var plain [64]byte
	dec.XORKeyStream(plain[:], s.header[:])
	s.tag = binary.LittleEndian.Uint32(plain[56:60])
	s.dc = int16(binary.LittleEndian.Uint16(plain[60:62]))

	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, nil, fmt.Errorf("frame length: %w", err)
	}
	dec.XORKeyStream(length[:], length[:])
	s.frameLen = int(binary.LittleEndian.Uint32(length[:]))
	if s.frameLen < 40 || s.frameLen > 1024 {
		return nil, nil, fmt.Errorf("a frame of %d bytes, not a req_pq_multi", s.frameLen)
	}
	s.frame = make([]byte, s.frameLen)
	if _, err := io.ReadFull(r, s.frame); err != nil {
		return nil, nil, fmt.Errorf("frame: %w", err)
	}
	dec.XORKeyStream(s.frame, s.frame)

	m := s.frame
	s.authKeyID = binary.LittleEndian.Uint64(m[0:8])
	s.msgID = binary.LittleEndian.Uint64(m[8:16])
	s.dataLen = binary.LittleEndian.Uint32(m[16:20])
	s.crc = binary.LittleEndian.Uint32(m[20:24])
	copy(s.nonce[:], m[24:40])
	return enc, dec, nil
}

// readClientFrame reads a frame of the intermediate transports, padded or not,
// from the decrypted stream of the client.
func readClientFrame(r io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(length[:])
	if n > 1024 {
		return nil, fmt.Errorf("a frame of %d bytes, not a req_pq_multi", n)
	}
	frame := make([]byte, n)
	_, err := io.ReadFull(r, frame)
	return frame, err
}

// serverStream is an AES-256-CTR stream with key, or with the SHA-256 of key
// and secret when there is a secret.
func serverStream(key, iv, secret []byte) cipher.Stream {
	if secret != nil {
		h := sha256.New()
		h.Write(key)
		h.Write(secret)
		key = h.Sum(nil)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // a 32-byte key always makes a cipher
	}
	return cipher.NewCTR(block, iv)
}

// ---- messages and frames of the server -------------------------------------------

// testFingerprint is a fingerprint of an RSA key, of the shape a datacenter
// lists in resPQ.
const testFingerprint = 0x0123456789abcdef

// resPQMessage is the unencrypted message of a resPQ for nonce, as a datacenter
// answers req_pq_multi with it.
func resPQMessage(nonce [16]byte) []byte {
	return plainMessage(0, serverMsgID(), resPQBody(nonce, testFingerprint))
}

// serverMsgID is the message_id of an answer of a server: the time, 1 mod 4.
func serverMsgID() uint64 { return uint64(time.Now().Unix())<<32 | 1 }

// plainMessage wraps body in an unencrypted message.
func plainMessage(authKeyID, msgID uint64, body []byte) []byte {
	m := binary.LittleEndian.AppendUint64(nil, authKeyID)
	m = binary.LittleEndian.AppendUint64(m, msgID)
	m = binary.LittleEndian.AppendUint32(m, uint32(len(body)))
	return append(m, body...)
}

// resPQBody is resPQ#05162463 nonce server_nonce pq
// server_public_key_fingerprints, with a pq of 8 bytes (in TL, a length byte,
// the bytes, and padding to a multiple of 4).
func resPQBody(nonce [16]byte, fingerprints ...uint64) []byte {
	b := binary.LittleEndian.AppendUint32(nil, testResPQ)
	b = append(b, nonce[:]...)
	b = append(b, randomBytes(16)...) // server_nonce
	b = append(b, 8, 0x17, 0xed, 0x48, 0x94, 0x1a, 0x08, 0xf9, 0x81, 0, 0, 0)
	b = binary.LittleEndian.AppendUint32(b, testVector)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(fingerprints)))
	for _, f := range fingerprints {
		b = binary.LittleEndian.AppendUint64(b, f)
	}
	return b
}

// dcFrame frames payload for the transport of tag: a length and the payload,
// in the padded variant followed by 0 to 15 random bytes.
func dcFrame(tag uint32, payload []byte) []byte {
	pad := 0
	if tag == 0xdddddddd {
		pad = mrand.IntN(16)
	}
	return paddedFrame(payload, pad)
}

// paddedFrame frames payload with pad random bytes after it.
func paddedFrame(payload []byte, pad int) []byte {
	f := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)+pad))
	f = append(f, payload...)
	return append(f, randomBytes(pad)...)
}

// le32 is v in four little-endian bytes.
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// ---- a datacenter on a port ------------------------------------------------------

// fakeDC is a dcServer on a loopback port: a datacenter.
type fakeDC struct {
	addr     string
	sessions chan *dcSession
}

func startFakeDC(t *testing.T, d dcServer) *fakeDC {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDC{addr: ln.Addr().String(), sessions: make(chan *dcSession, 16)}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				d.serve(conn, conn, conn, done, func(s *dcSession) { report(f.sessions, s) })
			})
		}
	})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	})
	return f
}

func report(sessions chan<- *dcSession, s *dcSession) {
	select {
	case sessions <- s:
	default:
	}
}

// next returns what the server made of the next connection.
func (f *fakeDC) next(t *testing.T) *dcSession {
	t.Helper()
	return nextSession(t, f.sessions)
}

func nextSession(t *testing.T, sessions <-chan *dcSession) *dcSession {
	t.Helper()
	select {
	case s := <-sessions:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the server saw no request")
		return nil
	}
}

// ---- a fake-TLS proxy ------------------------------------------------------------

// fakeProxy is a fake-TLS proxy on a loopback port: the server half of the
// fake-TLS handshake (fakeServer), and after it, in TLS records, a dcServer
// with the proxy's secret, which answers for the datacenter behind the proxy.
type fakeProxy struct {
	*fakeServer
	sessions chan *dcSession
}

// startFakeProxy starts a proxy whose handshake is that of tls and whose
// datacenter is d. The secret of tls is d's as well.
func startFakeProxy(t *testing.T, tls fakeServer, d dcServer) *fakeProxy {
	t.Helper()
	d.secret = tls.secret
	sessions := make(chan *dcSession, 16)
	tls.after = func(conn net.Conn, done <-chan struct{}) {
		rec := &serverRecords{conn: conn, size: d.recordSize}
		d.serve(conn, rec, rec, done, func(s *dcSession) {
			s.ccs, s.records = rec.ccs, rec.records
			report(sessions, s)
		})
	}
	return &fakeProxy{fakeServer: startFakeServer(t, tls), sessions: sessions}
}

// session returns what the datacenter half made of the next connection.
func (p *fakeProxy) session(t *testing.T) *dcSession {
	t.Helper()
	return nextSession(t, p.sessions)
}

// serverRecords is the record layer of the fake-TLS proxy once the handshake is
// over, as telemt and mtg have it: the client's first record must be a
// ChangeCipherSpec, the ones after it application data, and what the server
// sends goes out in application data records.
type serverRecords struct {
	conn    net.Conn
	size    int   // see dcServer.recordSize
	ccs     bool  // the ChangeCipherSpec came
	records []int // the payload sizes of the client's application data records
	buf     []byte
}

func (s *serverRecords) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		rec, err := readTLSRecord(s.conn)
		if err != nil {
			return 0, err
		}
		switch {
		case !s.ccs:
			if !bytes.Equal(rec, changeCipherSpec) {
				return 0, fmt.Errorf("the client's first record starts % x, not a ChangeCipherSpec", rec[:min(len(rec), 6)])
			}
			s.ccs = true
		case rec[0] != 0x17 || rec[1] != 3 || rec[2] != 3:
			return 0, fmt.Errorf("the client sent a record of type %#02x, version %d.%d", rec[0], rec[1], rec[2])
		default:
			s.records = append(s.records, len(rec)-5)
			s.buf = rec[5:]
		}
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *serverRecords) Write(p []byte) (int, error) {
	var out []byte
	if s.size <= 0 {
		out = tlsRecord(0x17, 0x0303, p)
	} else {
		out = tlsRecord(0x17, 0x0303, nil)
		for rest := p; len(rest) > 0; {
			n := min(len(rest), s.size)
			out = append(out, tlsRecord(0x17, 0x0303, rest[:n])...)
			rest = rest[n:]
		}
	}
	if _, err := s.conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
