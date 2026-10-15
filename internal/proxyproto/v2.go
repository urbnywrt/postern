// Package proxyproto implements version 2 of the PROXY protocol: the binary
// header with which a relay tells the server behind it where a connection really
// comes from.
//
// The edge router prepends the header when it forwards a client connection to an
// MTProto engine or to the agent's hidden management listener, so that they see
// the address of the client and not the loopback address of the router.
// HeaderV2 and WriteV2 build the header. ReadV2 parses it on the receiving side
// that this project runs itself. The format is the one of section 2.2 of "The
// PROXY protocol, versions 1 & 2" by HAProxy.
//
// Only TCP is supported. ReadV2 faces peers that cannot be trusted and is strict
// in what it takes: a version 2 header with the PROXY or the LOCAL command, over
// IPv4 or IPv6. It never falls back to the text header of version 1 and never
// guesses.
package proxyproto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

var (
	// ErrNoSignature means that the stream does not open with the signature of a
	// v2 header: it carries a v1 text header, another protocol, or garbage.
	ErrNoSignature = errors.New("proxyproto: missing v2 signature")
	// ErrMalformed means that the stream opens with the v2 signature but the
	// header is not one ReadV2 accepts: wrong version, unknown command,
	// unsupported family or transport, or a payload that is too long or too
	// short for what the header says.
	ErrMalformed = errors.New("proxyproto: malformed v2 header")
)

const (
	// signature opens every v2 header. No other protocol starts like this, so a
	// receiver that expects the header can tell at once when it is not there.
	signature = "\r\n\r\n\x00\r\nQUIT\n"

	// fixedLen is the part of a header that comes before the payload: the
	// signature, the version and command byte, the family and transport byte,
	// and the two-byte payload length.
	fixedLen = len(signature) + 1 + 1 + 2

	// The version and command byte holds the version in its upper four bits and
	// the command in its lower four.
	versionV2 = 2
	cmdLocal  = 0 // the sender opened the connection itself, not for a client
	cmdProxy  = 1 // the connection was relayed; the payload names its endpoints

	// The family and transport byte holds the address family in its upper four
	// bits and the transport protocol in its lower four.
	famTCP4 = 0x11 // AF_INET, STREAM
	famTCP6 = 0x21 // AF_INET6, STREAM

	// The payload of a PROXY header opens with the address block: source
	// address, destination address, source port, destination port.
	addrLen4 = 4 + 4 + 2 + 2
	addrLen6 = 16 + 16 + 2 + 2

	// maxPayload is the longest payload ReadV2 reads. A header from HeaderV2 has
	// 12 or 36 bytes of it; the rest of the allowance is for the TLV vectors of
	// other senders, and keeps what a peer can make the receiver hold small.
	maxPayload = 1024
)

// Header is a decoded PROXY v2 header.
type Header struct {
	// Src is the address the relay accepted the connection from, the client's;
	// Dst is the address it accepted the connection on. Both are exactly as they
	// were on the wire: a client that was relayed in an IPv6 header with an
	// IPv4-mapped address (::ffff:192.0.2.1) keeps that form, and Unmap on the
	// address gives the IPv4 address. Both are the zero value when Local is set.
	Src, Dst netip.AddrPort
	// Local is set for the LOCAL command: the sender opened the connection on its
	// own account and not for a client, and the header says nothing about any.
	// The receiver then goes by the addresses of the connection itself.
	Local bool
}

// HeaderV2 returns the PROXY v2 header for a connection from src to dst, with the
// PROXY command and the STREAM transport. It is IPv4 when src and dst both are,
// and IPv6 otherwise: when the families differ, the IPv4 address goes out in its
// IPv4-mapped IPv6 form. An IPv4-mapped IPv6 address counts as IPv4, so a client
// that reached a dual-stack socket over IPv4 is relayed as IPv4. Zones are not
// carried.
//
// HeaderV2 does not fail and does not panic. An invalid address, such as the zero
// netip.AddrPort, goes out as the unspecified IPv6 address (::).
func HeaderV2(src, dst netip.AddrPort) []byte {
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()

	var b []byte
	if s.Is4() && d.Is4() {
		b = appendFixed(make([]byte, 0, fixedLen+addrLen4), famTCP4, addrLen4)
		s4, d4 := s.As4(), d.As4()
		b = append(b, s4[:]...)
		b = append(b, d4[:]...)
	} else {
		b = appendFixed(make([]byte, 0, fixedLen+addrLen6), famTCP6, addrLen6)
		s16, d16 := s.As16(), d.As16()
		b = append(b, s16[:]...)
		b = append(b, d16[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, src.Port())
	return binary.BigEndian.AppendUint16(b, dst.Port())
}

// appendFixed appends the fixed part of a PROXY header whose payload is length
// bytes long.
func appendFixed(b []byte, fam byte, length uint16) []byte {
	b = append(b, signature...)
	b = append(b, versionV2<<4|cmdProxy, fam)
	return binary.BigEndian.AppendUint16(b, length)
}

// WriteV2 writes the header HeaderV2 builds for src and dst to w in a single
// Write call. It returns the error of w; a write that stops short without one
// is io.ErrShortWrite.
func WriteV2(w io.Writer, src, dst netip.AddrPort) error {
	b := HeaderV2(src, dst)
	n, err := w.Write(b)
	if err == nil && n < len(b) {
		err = io.ErrShortWrite
	}
	return err
}

// ReadV2 reads one PROXY v2 header from the start of r.
//
// It takes exactly the header from r. On success the next byte r returns is the
// first one after it, the first byte of whatever the relay forwards. r may hold
// bytes beyond the header already, so the caller carries on reading through r,
// not through the connection underneath. ReadV2 puts no limit on how long a read
// may take; that is for a read deadline on the connection.
//
// What it accepts is narrow on purpose:
//
//   - The version is 2 and the command is PROXY or LOCAL.
//   - For PROXY the family and transport are IPv4 or IPv6 over STREAM (TCP), and
//     the payload holds the address block for that family. Anything else, such
//     as an unspecified family, UDP or a UNIX socket, is rejected.
//   - For LOCAL the family and the payload are ignored, as the specification
//     says. The result has Local set and zero addresses.
//   - The payload is at most 1024 bytes long. Whatever follows the address block
//     is a chain of TLV vectors. They are consumed by the length field and
//     skipped: they are not interpreted, and their own framing is not checked.
//
// The signature is checked one byte at a time, and everything that the 16 bytes
// of the fixed part allow to judge is judged before the payload is read. A peer
// whose first byte is wrong, or whose header is unacceptable, gets its verdict at
// once and is not waited on for more. Lengths are checked before anything is
// allocated.
//
// The returned *Header is nil when err is not nil. The error is one of:
//
//   - ErrNoSignature: the stream does not open with the v2 signature. Nothing
//     has been consumed from r.
//   - ErrMalformed: the signature is there but the header is not acceptable. The
//     error text says why.
//   - Any error of r, unchanged. If r ends before the first byte this is io.EOF;
//     if it ends later, inside the header, it is io.ErrUnexpectedEOF.
//
// After an error other than ErrNoSignature, r may have lost part of the header,
// so the connection is not fit for anything but closing.
func ReadV2(r *bufio.Reader) (*Header, error) {
	// Peek rather than read: a stream that turns out not to be v2 is left intact,
	// and the first wrong byte decides, so a peer that sent the start of a v1
	// header or of an HTTP request is not kept waiting for twelve bytes.
	for i := range len(signature) {
		b, err := r.Peek(i + 1)
		if err != nil {
			if i > 0 {
				err = noEOF(err) // some bytes of the signature came: cut off inside it
			}
			return nil, err
		}
		if b[i] != signature[i] {
			return nil, ErrNoSignature
		}
	}

	var fixed [fixedLen]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, noEOF(err) // the signature is in, so the header has begun
	}
	verCmd, fam := fixed[len(signature)], fixed[len(signature)+1]
	length := int(binary.BigEndian.Uint16(fixed[len(signature)+2:]))

	if v := verCmd >> 4; v != versionV2 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrMalformed, v)
	}
	cmd := verCmd & 0x0f
	if cmd != cmdLocal && cmd != cmdProxy {
		return nil, fmt.Errorf("%w: unknown command %d", ErrMalformed, cmd)
	}
	if length > maxPayload {
		return nil, fmt.Errorf("%w: payload of %d bytes exceeds the limit of %d", ErrMalformed, length, maxPayload)
	}
	if cmd == cmdProxy {
		var need int // the size of the address block
		switch fam {
		case famTCP4:
			need = addrLen4
		case famTCP6:
			need = addrLen6
		default:
			return nil, fmt.Errorf("%w: unsupported family and transport 0x%02x", ErrMalformed, fam)
		}
		if length < need {
			return nil, fmt.Errorf("%w: payload of %d bytes is too short for the address block of %d", ErrMalformed, length, need)
		}
	}

	payload := make([]byte, length) // length is at most maxPayload here
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, noEOF(err) // the header has begun, so even a clean EOF is a cut-off
	}
	if cmd == cmdLocal {
		return &Header{Local: true}, nil
	}

	h := &Header{}
	if fam == famTCP4 {
		h.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(payload[0:4])), binary.BigEndian.Uint16(payload[8:10]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(payload[4:8])), binary.BigEndian.Uint16(payload[10:12]))
	} else { // famTCP6: no other family got past the checks above
		h.Src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(payload[0:16])), binary.BigEndian.Uint16(payload[32:34]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(payload[16:32])), binary.BigEndian.Uint16(payload[34:36]))
	}
	return h, nil
}

// noEOF reports a stream that ends inside a header as io.ErrUnexpectedEOF. Other
// errors are left as they are.
func noEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
