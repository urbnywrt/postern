package probe

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"testing/iotest"
)

// The vectors start from a fixed header and a fixed secret: byte i of the
// header is 7i+3 and byte i of the secret is 200-9i (both mod 256), and the
// tag and the datacenter go on top of the header at 56..62.
func vectorHeader(tag uint32, dc int16) [64]byte {
	var b [64]byte
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	binary.LittleEndian.PutUint32(b[56:], tag)
	binary.LittleEndian.PutUint16(b[60:], uint16(dc))
	return b
}

func vectorSecret() []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(200 - 9*i)
	}
	return b
}

// obfuscated2Vectors were computed outside Go, with Python's hashlib for
// SHA-256 and `openssl enc -aes-256-ctr -nosalt -nopad` over zero bytes for the
// key streams (OpenSSL 3.0.13):
//
//	key = hdr[8:40], iv = hdr[40:56]; rev = hdr[8:56] reversed;
//	server key = rev[0:32], server iv = rev[32:48]; with the secret each key is
//	sha256(key || secret); wire = hdr[0:56] || (hdr[56:64] XOR stream[56:64])
var obfuscated2Vectors = []struct {
	name   string
	tag    uint32
	dc     int16
	secret bool
	wire   string // the header as it goes out
	sent   string // the client's key stream right after the header, 32 bytes
	recv   string // the server's key stream from its start, 32 bytes
}{
	{
		name: "no secret, intermediate, datacenter 0",
		tag:  0xeeeeeeee, dc: 0,
		wire: "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d8427a3e26ac9db9f1d",
		sent: "90a57ab4dd9e957d69ebdb1307d4e4292a12b2f0e72c7bafca8f4dca26f912a1",
		recv: "2064aaf65bc017aa009c2ef46694423c1e6435fd2e43314da16b9b992b6443b1",
	},
	{
		name: "secret, padded intermediate, datacenter 2",
		tag:  0xdddddddd, dc: 2, secret: true,
		wire: "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d841f26f5ffb091477f",
		sent: "d790b48c37b3b941de8f5bd9181db7c2e37bdd9ac00561d40c6443c5d1109fba",
		recv: "b750628e213b870be2fbc02ca890a4ab153b53d5b9ce9ddedd386302338f6cdf",
	},
	{
		name: "secret, padded intermediate, media datacenter -4",
		tag:  0xdddddddd, dc: -4, secret: true,
		wire: "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d841f26f5ff4e6e477f",
		sent: "d790b48c37b3b941de8f5bd9181db7c2e37bdd9ac00561d40c6443c5d1109fba",
		recv: "b750628e213b870be2fbc02ca890a4ab153b53d5b9ce9ddedd386302338f6cdf",
	},
}

// referenceKeys derives the keys and IVs of a header step by step, as the
// protocol describes them: the client's from bytes 8..56, the server's from the
// same bytes reversed, each key hashed with the secret when there is one.
func referenceKeys(hdr [64]byte, secret []byte) (encKey, encIV, decKey, decIV []byte) {
	encKey, encIV = bytes.Clone(hdr[8:40]), bytes.Clone(hdr[40:56])
	reversed := make([]byte, 48)
	for i := range reversed {
		reversed[i] = hdr[55-i]
	}
	decKey, decIV = reversed[:32], reversed[32:]
	if secret != nil {
		h := sha256.New()
		h.Write(encKey)
		h.Write(secret)
		encKey = h.Sum(nil)
		h = sha256.New()
		h.Write(decKey)
		h.Write(secret)
		decKey = h.Sum(nil)
	}
	return encKey, encIV, decKey, decIV
}

// referenceStream returns the first n bytes of the AES-256-CTR key stream of
// key and iv, block by block: block i is AES(key, iv + i), the IV read as a
// 128-bit big-endian counter.
func referenceStream(t *testing.T, key, iv []byte, n int) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	counter := [16]byte(iv)
	var out []byte
	for len(out) < n {
		var ks [16]byte
		block.Encrypt(ks[:], counter[:])
		out = append(out, ks[:]...)
		for i := 15; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
	return out[:n]
}

func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func TestObfuscated2Vectors(t *testing.T) {
	for _, v := range obfuscated2Vectors {
		t.Run(v.name, func(t *testing.T) {
			var secret []byte
			if v.secret {
				secret = vectorSecret()
			}
			hdr := vectorHeader(v.tag, v.dc)
			// The random source hands out the fixed header; the tag and the
			// datacenter are the code's to set.
			random := vectorHeader(0, 0)
			o, err := newObfuscated2(bytes.NewReader(random[:]), v.tag, v.dc, secret)
			if err != nil {
				t.Fatal(err)
			}

			// The keys, against the step-by-step derivation.
			encKey, encIV, decKey, decIV := referenceKeys(hdr, secret)
			k := deriveObfuscated2Keys(&hdr, secret)
			for _, c := range []struct {
				what      string
				got, want []byte
			}{
				{"the client's key", k.encKey[:], encKey},
				{"the client's IV", k.encIV[:], encIV},
				{"the server's key", k.decKey[:], decKey},
				{"the server's IV", k.decIV[:], decIV},
			} {
				if !bytes.Equal(c.got, c.want) {
					t.Errorf("%s does not match the step-by-step derivation", c.what)
				}
			}

			// The header on the wire: in the clear up to byte 56, the tag and
			// the datacenter encrypted with the first 64 bytes of the stream.
			clientStream := referenceStream(t, encKey, encIV, 96)
			wantWire := append(bytes.Clone(hdr[:56]), xor(hdr[56:], clientStream[56:64])...)
			if got := hex.EncodeToString(o.header[:]); got != v.wire {
				t.Errorf("header\n got %s\nwant %s (computed outside Go)", got, v.wire)
			}
			if !bytes.Equal(o.header[:], wantWire) {
				t.Errorf("header\n got %x\nwant %x (step by step)", o.header, wantWire)
			}

			// The client's stream goes on after the 64 bytes of the header; the
			// server's starts from its beginning.
			sent := make([]byte, 32)
			o.enc.XORKeyStream(sent, sent)
			if got := hex.EncodeToString(sent); got != v.sent {
				t.Errorf("client stream after the header\n got %s\nwant %s (computed outside Go)", got, v.sent)
			}
			if !bytes.Equal(sent, clientStream[64:]) {
				t.Errorf("client stream after the header does not match the step-by-step stream")
			}
			recv := make([]byte, 32)
			o.dec.XORKeyStream(recv, recv)
			if got := hex.EncodeToString(recv); got != v.recv {
				t.Errorf("server stream\n got %s\nwant %s (computed outside Go)", got, v.recv)
			}
			if !bytes.Equal(recv, referenceStream(t, decKey, decIV, 32)) {
				t.Errorf("server stream does not match the step-by-step stream")
			}
		})
	}
}

// forbiddenStarts are the first four bytes no header may have: what servers
// take for HTTP, for TLS or for a connection of the plain transports.
var forbiddenStarts = [][]byte{
	[]byte("HEAD"), []byte("POST"), []byte("GET "), []byte("OPTI"),
	{0x16, 0x03, 0x01, 0x02},
	{0xdd, 0xdd, 0xdd, 0xdd},
	{0xee, 0xee, 0xee, 0xee},
}

func TestObfuscated2HeaderConstraints(t *testing.T) {
	secret := randomBytes(16)
	seen := make(map[[64]byte]bool)
	for i := range 10000 {
		tag, dc, s := uint32(tagIntermediate), int16(i%11-5), []byte(nil)
		if i%2 == 1 {
			tag, s = tagPaddedIntermediate, secret
		}
		o, err := newObfuscated2(rand.Reader, tag, dc, s)
		if err != nil {
			t.Fatal(err)
		}
		wire := o.header
		if wire[0] == 0xef {
			t.Fatalf("header %d starts with 0xef, the mark of the abridged transport: % x", i, wire[:8])
		}
		for _, f := range forbiddenStarts {
			if bytes.Equal(wire[:4], f) {
				t.Fatalf("header %d starts with % x", i, f)
			}
		}
		if bytes.Equal(wire[4:8], []byte{0, 0, 0, 0}) {
			t.Fatalf("header %d has zero bytes 4..8: % x", i, wire[:8])
		}
		if seen[wire] {
			t.Fatalf("header %d came twice", i)
		}
		seen[wire] = true

		// What the server finds in it: the tag and the datacenter. The keys
		// come from bytes 8..56, which go out in the clear.
		var hdr [64]byte
		copy(hdr[:], wire[:56])
		key, iv, _, _ := referenceKeys(hdr, s)
		plain := xor(wire[56:], referenceStream(t, key, iv, 64)[56:])
		if got := binary.LittleEndian.Uint32(plain); got != tag {
			t.Fatalf("header %d: the server finds tag %#08x, want %#08x", i, got, tag)
		}
		if got := int16(binary.LittleEndian.Uint16(plain[4:])); got != dc {
			t.Fatalf("header %d: the server finds datacenter %d, want %d", i, got, dc)
		}
	}
}

// zeros reads zero bytes forever.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestObfuscated2DrawsAgain(t *testing.T) {
	good := vectorHeader(0, 0)
	draw := func(start ...byte) []byte {
		b := good
		copy(b[:], start)
		return b[:]
	}
	var source []byte
	source = append(source, draw(0xef)...)
	for _, f := range forbiddenStarts {
		source = append(source, draw(f...)...)
	}
	source = append(source, draw(good[0], good[1], good[2], good[3], 0, 0, 0, 0)...)
	source = append(source, good[:]...)

	o, err := newObfuscated2(bytes.NewReader(source), tagIntermediate, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(o.header[:56], good[:56]) {
		t.Errorf("header starts % x, want the first draw that may go out, % x", o.header[:8], good[:8])
	}

	t.Run("a source of nothing but forbidden headers", func(t *testing.T) {
		if _, err := newObfuscated2(zeros{}, tagIntermediate, 2, nil); err == nil {
			t.Fatal("newObfuscated2 succeeded with a source of zeros")
		}
	})
	t.Run("a failing source", func(t *testing.T) {
		boom := errors.New("boom")
		if _, err := newObfuscated2(iotest.ErrReader(boom), tagIntermediate, 2, nil); !errors.Is(err, boom) {
			t.Fatalf("newObfuscated2: %v, want the error of the source", err)
		}
	})
}
