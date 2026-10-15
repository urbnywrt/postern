// Package tlsx reads and parses the TLS ClientHello of connections from
// untrusted peers.
//
// The edge router peeks at the start of every incoming connection to learn
// which server name the client asks for, then replays those exact bytes to the
// backend it picked. ReadClientHello is built for that: it takes from the
// connection only the TLS records of the ClientHello, never more than a byte
// budget, and hands back every byte it took.
package tlsx

import (
	"errors"
	"io"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

var (
	// ErrNotTLS means that the peer did not open with a TLS handshake record.
	ErrNotTLS = errors.New("tlsx: not a TLS handshake")
	// ErrTooLarge means that the ClientHello does not fit into the byte budget.
	ErrTooLarge = errors.New("tlsx: client hello too large")
	// ErrMalformed means that the peer opened with a TLS handshake record but
	// did not send a well-formed ClientHello.
	ErrMalformed = errors.New("tlsx: malformed client hello")
)

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01

	recordHeaderLen    = 5 // type(1) version(2) length(2)
	handshakeHeaderLen = 4 // type(1) length(3)

	// maxRecordLen is the longest record fragment accepted: the 2^14 bytes of
	// plaintext TLS allows, plus the 256 bytes of overhead RFC 8446 grants a
	// protected record.
	maxRecordLen = 1<<14 + 256

	extServerName    = 0  // RFC 6066, section 3
	extALPN          = 16 // RFC 7301, section 3.1
	nameTypeHostName = 0

	// initialBuf is the space reserved up front for the bytes read, enough for
	// a typical ClientHello. readStep caps how far the buffer is grown ahead of
	// data that has actually arrived, so that a record header announcing 16 KiB
	// costs nothing until the peer sends them.
	initialBuf = 2048
	readStep   = 4096
)

// ClientHello is the part of a client's first flight the edge router cares for.
type ClientHello struct {
	// SNI is the first host_name of the server_name extension, exactly as the
	// client sent it: not lowercased and not checked for what it contains, so
	// it is untrusted input. It is empty when the hello carries no server name.
	SNI string
	// ALPN lists the protocols of the ALPN extension in the order the client
	// sent them. It is nil when the hello carries no such extension.
	ALPN []string
	// Raw holds every byte read from the connection, in order, so that the
	// caller can replay it verbatim.
	Raw []byte
}

// ReadClientHello reads TLS records from r until one complete ClientHello
// handshake message is assembled; the message may span several records. Raw
// holds every byte read from r, in order, so that the caller can replay the
// connection verbatim.
//
// Reading stops with the record that completes the ClientHello: whatever the
// client sends after its hello stays unread, while bytes that share that last
// record with the end of the hello are consumed and kept in Raw. At most
// maxBytes bytes are read from r in total, record headers included; a
// maxBytes below 1 allows no read at all. Bounding the time the read may take
// is up to the caller, with a read deadline on the connection.
//
// The returned *ClientHello is never nil. When err is not nil only Raw is set,
// to the bytes consumed so far; they are a prefix of the stream, so replaying
// Raw followed by the rest of the connection reproduces what the peer sent.
// The error is one of:
//
//   - ErrNotTLS: the first byte is not that of a handshake record (0x16), or
//     the record version is not 3.x. A wrong first byte is reported after
//     reading that byte alone, so a peer that sends a short plain-text request
//     and waits is not kept waiting for a record header.
//   - ErrMalformed: a record is empty or longer than 16384+256 bytes, the
//     handshake message is not a ClientHello, a record that is not a handshake
//     record arrives before the hello is complete, or the hello itself is
//     rejected by [ParseClientHelloBody].
//   - ErrTooLarge: the hello announces, or needs, more than maxBytes bytes.
//   - Any error of r. If r ends before the first byte this is io.EOF, if it
//     ends later it is io.ErrUnexpectedEOF.
func ReadClientHello(r io.Reader, maxBytes int) (*ClientHello, error) {
	s := &stream{r: r, limit: max(maxBytes, 0)}
	s.buf = make([]byte, 0, min(s.limit, initialBuf))

	body, err := s.clientHelloBody()
	if err != nil {
		return &ClientHello{Raw: s.buf}, err
	}
	sni, alpn, err := ParseClientHelloBody(body)
	if err != nil {
		return &ClientHello{Raw: s.buf}, err
	}
	return &ClientHello{SNI: sni, ALPN: alpn, Raw: s.buf}, nil
}

// stream reads from r under a byte budget and remembers everything it read.
type stream struct {
	r     io.Reader
	limit int    // total number of bytes that may be read from r
	buf   []byte // every byte read from r so far
}

// read appends the next n bytes of the stream to buf. It reads nothing when
// that would exceed the budget.
func (s *stream) read(n int) error {
	if n > s.limit-len(s.buf) {
		return ErrTooLarge
	}
	for n > 0 {
		step := min(n, readStep)
		s.buf = slices.Grow(s.buf, step)
		got, err := io.ReadFull(s.r, s.buf[len(s.buf):len(s.buf)+step])
		s.buf = s.buf[:len(s.buf)+got]
		if err != nil {
			if errors.Is(err, io.EOF) && len(s.buf) > 0 {
				err = io.ErrUnexpectedEOF // cut off in the middle of the hello
			}
			return err
		}
		n -= step
	}
	return nil
}

// clientHelloBody reads records until their fragments hold one complete
// ClientHello handshake message and returns the body of that message.
func (s *stream) clientHelloBody() ([]byte, error) {
	var hs []byte // handshake bytes gathered from the record fragments so far
	for first := true; ; first = false {
		fragment, err := s.readRecord(first)
		if err != nil {
			return nil, err
		}
		hs = append(hs, fragment...)

		// hs is not empty: a record never is.
		if hs[0] != handshakeTypeClientHello {
			return nil, ErrMalformed
		}
		if len(hs) < handshakeHeaderLen {
			continue // the handshake header itself is split across records
		}
		n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if n > s.limit {
			return nil, ErrTooLarge
		}
		if len(hs) >= handshakeHeaderLen+n {
			return hs[handshakeHeaderLen : handshakeHeaderLen+n], nil
		}
	}
}

// readRecord reads one TLS record and returns its fragment. The fragment
// aliases s.buf and is only valid until the next read. The first record is
// held to a stricter standard: it must look like the start of a TLS handshake
// at all, which decides between ErrNotTLS and ErrMalformed.
func (s *stream) readRecord(first bool) ([]byte, error) {
	start := len(s.buf)

	// Look at the type before asking for the rest of the header.
	if err := s.read(1); err != nil {
		return nil, err
	}
	if s.buf[start] != recordTypeHandshake {
		if first {
			return nil, ErrNotTLS
		}
		return nil, ErrMalformed
	}
	if err := s.read(recordHeaderLen - 1); err != nil {
		return nil, err
	}
	header := s.buf[start : start+recordHeaderLen]
	if first && header[1] != 3 {
		return nil, ErrNotTLS // no TLS record carries another major version
	}
	n := int(header[3])<<8 | int(header[4])
	if n == 0 || n > maxRecordLen {
		return nil, ErrMalformed
	}
	if err := s.read(n); err != nil {
		return nil, err
	}
	return s.buf[start+recordHeaderLen:], nil
}

// ParseClientHelloBody extracts the server name and the offered ALPN protocols
// from the body of a ClientHello: the handshake message without its 4-byte
// type and length header.
//
// The structure is validated: every length must be consistent, the extension
// block must end the body, and the server_name and ALPN extensions must be well
// formed and appear at most once. Whatever is wrong is reported as ErrMalformed,
// with sni and alpn left empty. A hello without an extension block is valid, as
// it is for TLS 1.2 and older. Other extensions are skipped unread.
//
// sni is the first host_name entry of the server_name extension, exactly as
// the client sent it: not lowercased, and not checked for what it contains.
// Entries of other name types are skipped and entries after the first host_name
// are ignored. sni is empty when the hello carries no server name. alpn is nil
// when it carries no ALPN extension. Neither refers to body.
//
// Every hello that crypto/tls accepts is accepted here with the same names.
// The converse does not hold: this function lets through, for example, repeated
// host_name entries, a trailing dot in the name and repeated extensions it does
// not read.
func ParseClientHelloBody(body []byte) (sni string, alpn []string, err error) {
	s := cryptobyte.String(body)

	var sessionID, cipherSuites, compressionMethods cryptobyte.String
	if !s.Skip(2+32) || // legacy_version, random
		!s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) || len(cipherSuites)%2 != 0 ||
		!s.ReadUint8LengthPrefixed(&compressionMethods) {
		return "", nil, ErrMalformed
	}
	if s.Empty() {
		return "", nil, nil // no extensions, which a hello may do before TLS 1.3
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return "", nil, ErrMalformed
	}

	var seenServerName, seenALPN bool
	for !extensions.Empty() {
		var extType uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&data) {
			return "", nil, ErrMalformed
		}
		var ok bool
		switch extType {
		case extServerName:
			// Two server_name extensions leave open which one is meant.
			if seenServerName {
				return "", nil, ErrMalformed
			}
			seenServerName = true
			sni, ok = parseServerName(data)
		case extALPN:
			if seenALPN {
				return "", nil, ErrMalformed
			}
			seenALPN = true
			alpn, ok = parseALPN(data)
		default:
			continue
		}
		if !ok {
			return "", nil, ErrMalformed
		}
	}
	return sni, alpn, nil
}

// parseServerName returns the first host_name of the data of a server_name
// extension (RFC 6066, section 3), or "" if the list holds none. ok is false
// if the data is malformed.
func parseServerName(data cryptobyte.String) (host string, ok bool) {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || list.Empty() || !data.Empty() {
		return "", false
	}
	var found bool
	for !list.Empty() {
		var nameType uint8
		var name cryptobyte.String
		if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) || name.Empty() {
			return "", false
		}
		if nameType == nameTypeHostName && !found {
			host, found = string(name), true
		}
	}
	return host, true
}

// parseALPN returns the protocol names in the data of an ALPN extension
// (RFC 7301, section 3.1). ok is false if the data is malformed.
func parseALPN(data cryptobyte.String) (protos []string, ok bool) {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || list.Empty() || !data.Empty() {
		return nil, false
	}
	for !list.Empty() {
		var proto cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
			return nil, false
		}
		protos = append(protos, string(proto))
	}
	return protos, true
}
