// Package probetest is a Telegram datacenter for tests, as far as the exchange
// of probe.DCPing goes: the server half of obfuscated2 without a secret and of
// req_pq_multi → resPQ. A test of code that checks a way to the datacenters
// with DCPing, as the health checks of the egress do, points it at one.
//
// It is written from the descriptions of the protocols (core.telegram.org:
// "Transport obfuscation", "MTProto transports", "Creating an Authorization
// Key"), independently of package probe. The client opens the connection with
// 64 bytes; the server decrypts with the key in bytes 8..40 of them and the IV
// in 40..56, and encrypts with the key and the IV taken alike from the same 48
// bytes reversed, AES-256-CTR both ways. Decrypting the 64 bytes gives the
// transport tag at 56..60, 0xeeeeeeee for the intermediate transport, and the
// stream goes on with the frame of the request: a 4-byte little-endian length
// and an unencrypted message, auth_key_id 0, message_id, message_data_length,
// req_pq_multi#be7e8ef1 and the 16 bytes of the nonce. A datacenter answers
// with resPQ#05162463 for that nonce, in a frame of its own.
package probetest

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Mode is how a datacenter answers req_pq_multi.
type Mode int

const (
	Answers    Mode = iota // with the resPQ for the request
	HangsUp                // closes the connection after the request, without a word
	WrongNonce             // with a resPQ for another nonce
	Silent                 // reads the request and says nothing until the client hangs up
)

// connTimeout bounds a connection of a Server, so that a client that stops
// does not keep it for ever.
const connTimeout = 10 * time.Second

// Serve serves one connection of a client of probe.DCPing in mode, and closes
// it. answering, when it is not nil, is called just before the answer goes out:
// a test with a clock of its own moves it there, for the latency of the answer.
// A connection whose first bytes are not the request of DCPing is closed.
func Serve(c net.Conn, mode Mode, answering func()) {
	defer func() { _ = c.Close() }()
	var hdr [64]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	var rev [48]byte
	for i := range rev {
		rev[i] = hdr[55-i]
	}
	dec := ctr(hdr[8:40], hdr[40:56])
	enc := ctr(rev[:32], rev[32:])
	var plain [64]byte
	dec.XORKeyStream(plain[:], hdr[:])
	if binary.LittleEndian.Uint32(plain[56:60]) != 0xeeeeeeee {
		return // not the transport of a ping of a datacenter
	}
	var length [4]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return
	}
	dec.XORKeyStream(length[:], length[:])
	n := binary.LittleEndian.Uint32(length[:])
	if n < 40 || n > 1024 {
		return
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(c, frame); err != nil {
		return
	}
	dec.XORKeyStream(frame, frame)
	if binary.LittleEndian.Uint64(frame) != 0 || binary.LittleEndian.Uint32(frame[20:]) != 0xbe7e8ef1 {
		return // not req_pq_multi
	}
	var nonce [16]byte
	copy(nonce[:], frame[24:40])

	switch mode {
	case HangsUp:
		return
	case Silent:
		_, _ = io.Copy(io.Discard, c)
		return
	case WrongNonce:
		nonce[0] ^= 0xff
	}
	msg := resPQ(nonce)
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(msg)))
	out = append(out, msg...)
	enc.XORKeyStream(out, out)
	if answering != nil {
		answering()
	}
	if _, err := c.Write(out); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, c) // until the client hangs up
}

func ctr(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // a key of 32 bytes always makes a cipher
	}
	return cipher.NewCTR(block, iv)
}

// resPQ is the unencrypted message of a resPQ for nonce, with a pq of 8 bytes
// and one fingerprint, as a datacenter answers req_pq_multi.
func resPQ(nonce [16]byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, 0x05162463)
	body = append(body, nonce[:]...)
	body = append(body, make([]byte, 16)...)                                        // server_nonce
	body = append(body, 8, 0x17, 0xed, 0x48, 0x94, 0x1a, 0x08, 0xf9, 0x81, 0, 0, 0) // pq, padded to 12 bytes
	body = binary.LittleEndian.AppendUint32(body, 0x1cb5c415)                       // Vector<long>
	body = binary.LittleEndian.AppendUint32(body, 1)
	body = binary.LittleEndian.AppendUint64(body, 0x0123456789abcdef)
	m := binary.LittleEndian.AppendUint64(nil, 0)                            // auth_key_id
	m = binary.LittleEndian.AppendUint64(m, uint64(time.Now().Unix())<<32|1) // message_id of a server
	m = binary.LittleEndian.AppendUint32(m, uint32(len(body)))
	return append(m, body...)
}

// Pipe returns the client end of a connection to a datacenter of mode over a
// net.Pipe: what a fake dialer hands out for a datacenter.
func Pipe(mode Mode) net.Conn {
	near, far := net.Pipe()
	go Serve(far, mode, nil)
	return near
}

// Server is a datacenter on a port of 127.0.0.1, which can be closed and opened
// again at the same address.
type Server struct {
	mode      Mode
	answering func()
	addr      string
	accepted  atomic.Int32
	mu        sync.Mutex
	ln        net.Listener
}

// NewServer starts a datacenter of mode on a port of 127.0.0.1; answering is
// that of Serve. Close stops it.
func NewServer(mode Mode, answering func()) (*Server, error) {
	s := &Server{mode: mode, answering: answering}
	if err := s.listen("127.0.0.1:0"); err != nil {
		return nil, err
	}
	return s, nil
}

// Addr is the address of the datacenter, "127.0.0.1:<port>".
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Accepted is the number of connections that the datacenter took.
func (s *Server) Accepted() int { return int(s.accepted.Load()) }

// Close stops taking connections; the ones it has are served to their end. It
// may be called again.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	s.ln = nil
	return err
}

// Reopen takes connections again at the same address after Close.
func (s *Server) Reopen() error { return s.listen(s.Addr()) }

func (s *Server) listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln, s.addr = ln, ln.Addr().String()
	s.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			_ = c.SetDeadline(time.Now().Add(connTimeout))
			go Serve(c, s.mode, s.answering)
		}
	}()
	return nil
}
