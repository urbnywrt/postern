package probe

// obfuscated2 is the transport obfuscation of MTProto: the client opens the
// connection with 64 bytes that carry the keys of the connection, and
// everything after them is AES-256-CTR, one stream each way. It is what
// Telegram's clients speak to a datacenter directly and to an MTProto proxy, in
// the clear or, with a fake-TLS secret, inside TLS records.
//
// The client draws the 64 bytes of the header, hdr, at random, except that
// bytes 56..60 are the tag of the transport that follows (the framing of the
// messages) and bytes 60..62 the datacenter, an int16 in little endian. The
// client encrypts with the key hdr[8:40] and the IV hdr[40:56], and decrypts
// with the key and the IV taken in the same way from those 48 bytes reversed.
// With a proxy secret, each key is SHA-256(key || secret) instead, which only a
// server that knows the secret can reproduce. The header goes out as
// hdr[0:56] followed by the last 8 bytes of hdr encrypted: the encryption
// stream starts with the header, so the first byte of data is encrypted with
// byte 64 of the stream. The server decrypts the header with the client's key
// and finds the tag and the datacenter. (tdlib, td/mtproto/TcpTransport.cpp:
// ObfuscatedTransport::init; the server half: the official MTProxy,
// net/net-tcp-rpc-ext-server.c.)
//
// The bytes the client draws must not make the connection look like another
// protocol to the server: the first byte is not 0xef (the abridged transport),
// the first four are not HEAD, POST, GET or OPTI (HTTP), 16 03 01 02 (a TLS
// handshake record) or a tag of the intermediate transports, and bytes 4..8 are
// not all zero.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	obfuscated2HeaderLen = 64

	// tagIntermediate is the tag of the intermediate transport: frames of a
	// 4-byte little-endian length and the message. DCPing speaks it.
	tagIntermediate uint32 = 0xeeeeeeee
	// tagPaddedIntermediate is the tag of the padded intermediate transport:
	// the same frames with 0 to 15 random bytes after the message, which the
	// length covers. Telegram's clients speak it through a proxy with a "dd"
	// or fake-TLS secret, and so does L2.
	tagPaddedIntermediate uint32 = 0xdddddddd

	// maxHeaderDraws bounds the draws of a header. A random source that is
	// any good needs a second draw for about one header in 256 (a first byte
	// of 0xef), and 32 draws practically never.
	maxHeaderDraws = 32
)

// obfuscated2 is the client end of an obfuscated2 connection.
type obfuscated2 struct {
	// header is the first 64 bytes the client sends.
	header [obfuscated2HeaderLen]byte
	// enc encrypts what the client sends after the header; dec decrypts what
	// the server sends.
	enc, dec cipher.Stream
}

// obfuscated2Keys are the keys and IVs of a connection: enc for what the client
// sends, dec for what the server sends.
type obfuscated2Keys struct {
	encKey [32]byte
	encIV  [16]byte
	decKey [32]byte
	decIV  [16]byte
}

// newObfuscated2 opens the client end of a connection whose header draws its
// random bytes from random and carries tag and dc. With a secret (the 16 bytes
// of a proxy secret) the keys are hashed with it; without one, as to a
// datacenter, they are not.
func newObfuscated2(random io.Reader, tag uint32, dc int16, secret []byte) (*obfuscated2, error) {
	hdr, err := drawObfuscated2Header(random, tag, dc)
	if err != nil {
		return nil, err
	}
	k := deriveObfuscated2Keys(&hdr, secret)
	o := &obfuscated2{header: hdr}
	if o.enc, err = newCTR(k.encKey[:], k.encIV[:]); err != nil {
		return nil, err
	}
	if o.dec, err = newCTR(k.decKey[:], k.decIV[:]); err != nil {
		return nil, err
	}
	var sealed [obfuscated2HeaderLen]byte
	o.enc.XORKeyStream(sealed[:], hdr[:])
	copy(o.header[56:], sealed[56:])
	return o, nil
}

// drawObfuscated2Header draws the 64 bytes of a header from random until they
// may go out, and writes tag and dc into them.
func drawObfuscated2Header(random io.Reader, tag uint32, dc int16) ([obfuscated2HeaderLen]byte, error) {
	var hdr [obfuscated2HeaderLen]byte
	for range maxHeaderDraws {
		if _, err := io.ReadFull(random, hdr[:]); err != nil {
			return hdr, fmt.Errorf("drawing the obfuscated2 header: %w", err)
		}
		if mayStartHeader(hdr[:8]) {
			binary.LittleEndian.PutUint32(hdr[56:], tag)
			binary.LittleEndian.PutUint16(hdr[60:], uint16(dc))
			return hdr, nil
		}
	}
	return hdr, errors.New("drawing the obfuscated2 header: the random source gives no header that may go out")
}

// mayStartHeader reports whether a header may start with the 8 bytes of b: see
// the top of this file.
func mayStartHeader(b []byte) bool {
	if b[0] == 0xef {
		return false
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0x44414548, // HEAD
		0x54534f50, // POST
		0x20544547, // GET and a space
		0x4954504f, // OPTI
		0x02010316, // 16 03 01 02
		tagPaddedIntermediate,
		tagIntermediate:
		return false
	}
	return binary.LittleEndian.Uint32(b[4:]) != 0
}

// deriveObfuscated2Keys derives the keys and IVs of the connection that the
// header hdr opens, hashing the keys with secret when there is one.
func deriveObfuscated2Keys(hdr *[obfuscated2HeaderLen]byte, secret []byte) obfuscated2Keys {
	var k obfuscated2Keys
	copy(k.encKey[:], hdr[8:40])
	copy(k.encIV[:], hdr[40:56])
	// The server's direction: hdr[8:56] reversed, a key and an IV.
	for i := range k.decKey {
		k.decKey[i] = hdr[55-i]
	}
	for i := range k.decIV {
		k.decIV[i] = hdr[23-i]
	}
	if len(secret) > 0 {
		k.encKey = withSecret(k.encKey, secret)
		k.decKey = withSecret(k.decKey, secret)
	}
	return k
}

// withSecret is SHA-256(key || secret).
func withSecret(key [32]byte, secret []byte) [32]byte {
	h := sha256.New()
	h.Write(key[:])
	h.Write(secret)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// newCTR returns the AES-256-CTR stream of key and iv.
func newCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("obfuscated2: %w", err)
	}
	return cipher.NewCTR(block, iv), nil
}
