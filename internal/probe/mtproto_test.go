package probe

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestMessageID(t *testing.T) {
	const sec = 1790000000
	tests := []struct {
		name string
		now  time.Time
		want uint64
	}{
		{name: "a whole second", now: time.Unix(sec, 0), want: sec << 32},
		{name: "half a second", now: time.Unix(sec, 500_000_000), want: sec<<32 | 0x80000000},
		{name: "a nanosecond", now: time.Unix(sec, 1), want: sec<<32 | 4},
		{name: "the last nanosecond", now: time.Unix(sec, 999_999_999), want: sec<<32 | 0xfffffff8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := messageID(tt.now)
			if got != tt.want {
				t.Errorf("messageID = %#x, want %#x", got, tt.want)
			}
			if got%4 != 0 {
				t.Errorf("messageID = %#x, not a multiple of 4", got)
			}
			if got>>32 != sec {
				t.Errorf("messageID = %#x, its upper half is not the Unix time %d", got, sec)
			}
		})
	}

	t.Run("it never goes back within a second", func(t *testing.T) {
		prev := uint64(0)
		for ns := 0; ns < 1e9; ns += 7_777_777 {
			id := messageID(time.Unix(sec, int64(ns)))
			if id < prev {
				t.Fatalf("messageID at %d ns = %#x, before %#x", ns, id, prev)
			}
			prev = id
		}
	})
}

func TestReqPQMulti(t *testing.T) {
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}
	got := reqPQMulti(0x6a3c3d5f00000004, &nonce)
	want := "0000000000000000" + // auth_key_id: none
		"040000005f3d3c6a" + // message_id, little endian
		"14000000" + // message_data_length: 20
		"f18e7ebe" + // req_pq_multi#be7e8ef1
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" // nonce
	if h := hex.EncodeToString(got); h != want {
		t.Errorf("req_pq_multi\n got %s\nwant %s", h, want)
	}
}

// ---- frames -------------------------------------------------------------------

func TestAppendFrame(t *testing.T) {
	payload := randomBytes(40)

	t.Run("intermediate", func(t *testing.T) {
		got, err := appendFrame([]byte("before"), tagIntermediate, payload, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte("before"), le32(40)...)
		want = append(want, payload...)
		if !bytes.Equal(got, want) {
			t.Errorf("frame\n got % x\nwant % x", got, want)
		}
	})

	t.Run("padded intermediate", func(t *testing.T) {
		seen := make(map[int]int)
		for range 1000 {
			got, err := appendFrame(nil, tagPaddedIntermediate, payload, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) < 4+len(payload) {
				t.Fatalf("a frame of %d bytes for a payload of %d", len(got), len(payload))
			}
			n := int(binary.LittleEndian.Uint32(got))
			if n != len(got)-4 {
				t.Fatalf("frame length %d, but %d bytes follow it", n, len(got)-4)
			}
			if !bytes.Equal(got[4:44], payload) {
				t.Fatalf("the payload is not at the start of the frame: % x", got[4:44])
			}
			seen[n-len(payload)]++
		}
		for pad := range 16 {
			if seen[pad] == 0 {
				t.Errorf("no frame of 1000 has %d bytes of padding: the padding is not 0 to 15 random bytes (%v)", pad, seen)
			}
		}
		if len(seen) != 16 {
			t.Errorf("padding lengths %v, want 0 to 15 only", seen)
		}
	})

	t.Run("a failing random source", func(t *testing.T) {
		boom := errors.New("boom")
		if _, err := appendFrame(nil, tagPaddedIntermediate, payload, iotest.ErrReader(boom)); !errors.Is(err, boom) {
			t.Fatalf("appendFrame: %v, want the error of the source", err)
		}
	})
}

func TestReadFrame(t *testing.T) {
	payload := randomBytes(84)
	tests := []struct {
		name     string
		stream   []byte
		want     []byte // the payload, when the frame is good
		wantErr  error  // matched with errors.Is
		wantBad  bool   // a badAnswer
		wantMsg  string // part of the error text
		wantRest int    // what is left of the stream after the frame
	}{
		{name: "a frame", stream: append(le32(84), payload...), want: payload},
		{name: "a frame and more", stream: append(append(le32(84), payload...), 1, 2, 3), want: payload, wantRest: 3},
		{name: "the longest frame", stream: append(le32(65536), make([]byte, 65536)...), want: make([]byte, 65536)},
		{name: "a frame too long", stream: append(le32(65537), make([]byte, 65537)...), wantBad: true, wantMsg: "65537", wantRest: 65537},
		{name: "a quick ack", stream: le32(0x80000001), wantBad: true, wantMsg: "2147483649"},
		{name: "an empty frame", stream: le32(0), wantBad: true, wantMsg: "0 bytes"},
		{name: "a frame of three bytes", stream: append(le32(3), 1, 2, 3), wantBad: true, wantMsg: "3 bytes", wantRest: 3},
		{name: "nothing at all", stream: nil, wantErr: io.EOF, wantMsg: "without answering"},
		{name: "half a length", stream: []byte{84, 0}, wantErr: io.ErrUnexpectedEOF},
		{name: "half a frame", stream: append(le32(84), payload[:40]...), wantErr: io.ErrUnexpectedEOF},
	}
	// Each stream is read whole and one byte at a time: DCPing reads a TCP
	// connection, which hands out what has come so far.
	passes := []struct {
		name string
		wrap func(io.Reader) io.Reader
	}{
		{name: "whole", wrap: func(r io.Reader) io.Reader { return r }},
		{name: "one byte at a time", wrap: iotest.OneByteReader},
	}
	for _, tt := range tests {
		for _, pass := range passes {
			t.Run(tt.name+", "+pass.name, func(t *testing.T) {
				r := bytes.NewReader(tt.stream)
				got, err := readFrame(pass.wrap(r))
				var bad badAnswer
				switch {
				case tt.want != nil:
					if err != nil {
						t.Fatalf("readFrame: %v", err)
					}
					if !bytes.Equal(got, tt.want) {
						t.Errorf("payload of %d bytes, want %d", len(got), len(tt.want))
					}
				case err == nil:
					t.Fatalf("readFrame read %d bytes, want an error", len(got))
				case tt.wantBad && !errors.As(err, &bad):
					t.Errorf("readFrame: %v, want a bad answer", err)
				case !tt.wantBad && errors.As(err, &bad):
					t.Errorf("readFrame: %v, want no verdict on the answer", err)
				case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
					t.Errorf("readFrame: %v, want %v", err, tt.wantErr)
				}
				if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("readFrame: %q, want it to mention %q", err, tt.wantMsg)
				}
				// A frame that is too long is refused on its length, unread.
				if r.Len() != tt.wantRest {
					t.Errorf("%d bytes left after the frame, want %d", r.Len(), tt.wantRest)
				}
			})
		}
	}
}

// ---- the answer ---------------------------------------------------------------

func TestCheckResPQ(t *testing.T) {
	var nonce, other [16]byte
	copy(nonce[:], randomBytes(16))
	copy(other[:], randomBytes(16))
	msgID := serverMsgID()
	body := resPQBody(nonce, testFingerprint)
	// A body cut at n bytes, in a message whose length says so.
	cut := func(n int) []byte { return plainMessage(0, msgID, body[:n]) }

	tests := []struct {
		name    string
		payload []byte
		wantMsg string // part of the error text; "" for a resPQ that passes
	}{
		{name: "a resPQ", payload: plainMessage(0, msgID, body)},
		{name: "a resPQ with padding after it", payload: append(plainMessage(0, msgID, body), randomBytes(15)...)},
		{name: "a resPQ with three fingerprints", payload: plainMessage(0, msgID, resPQBody(nonce, 1, 2, 3))},
		{name: "a resPQ with no fingerprint", payload: plainMessage(0, msgID, resPQBody(nonce))},
		{
			name:    "a resPQ with a long pq",
			payload: plainMessage(0, msgID, longPQ(nonce)),
		},
		{name: "another nonce", payload: plainMessage(0, msgID, resPQBody(other, testFingerprint)), wantMsg: "nonce"},
		{name: "another constructor", payload: plainMessage(0, msgID, append(le32(0xa7eff811), body[4:]...)), wantMsg: "0xa7eff811"},
		{name: "an encrypted message", payload: plainMessage(0x1122334455667788, msgID, body), wantMsg: "auth_key_id"},
		{name: "a transport error", payload: le32(0xfffffe6c), wantMsg: "-404"},
		{name: "a transport error with padding", payload: append(le32(0xfffffe53), 1, 2, 3), wantMsg: "-429"},
		{name: "a frame too short for a message", payload: append(le32(8), 0, 0, 0, 0), wantMsg: "too short"},
		{name: "a frame of three bytes", payload: []byte{1, 2, 3}, wantMsg: "too short"},
		{
			name:    "a message longer than its frame",
			payload: plainMessage(0, msgID, body)[:60],
			wantMsg: "message_data_length",
		},
		{name: "no constructor", payload: cut(2), wantMsg: "too short"},
		{name: "half a nonce", payload: cut(12), wantMsg: "too short"},
		{name: "no server_nonce", payload: cut(20), wantMsg: "server_nonce"},
		{name: "no pq", payload: cut(36), wantMsg: "pq"},
		{name: "half a pq", payload: cut(42), wantMsg: "pq"},
		{name: "no fingerprints", payload: cut(48), wantMsg: "fingerprints"},
		{name: "half the fingerprints", payload: cut(len(body) - 4), wantMsg: "fingerprints"},
		{
			name:    "fingerprints in a vector of another type",
			payload: plainMessage(0, msgID, append(bytes.Clone(body[:48]), append(le32(0x12345678), body[52:]...)...)),
			wantMsg: "fingerprints",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkResPQ(tt.payload, &nonce)
			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("checkResPQ: %v, want a pass", err)
				}
				return
			}
			var bad badAnswer
			if !errors.As(err, &bad) {
				t.Fatalf("checkResPQ: %v, want a bad answer", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("checkResPQ: %q, want it to mention %q", err, tt.wantMsg)
			}
			for _, n := range [][16]byte{nonce, other} {
				if strings.Contains(err.Error(), hex.EncodeToString(n[:])) || strings.Contains(err.Error(), string(n[:])) {
					t.Errorf("the error gives a nonce away: %q", err)
				}
			}
		})
	}
}

// longPQ is a resPQ body whose pq is 300 bytes, in the long form of TL bytes:
// 254, a 3-byte length, the bytes, padding to a multiple of 4.
func longPQ(nonce [16]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, testResPQ)
	b = append(b, nonce[:]...)
	b = append(b, randomBytes(16)...)
	b = append(b, 254, 0x2c, 0x01, 0x00) // 300
	b = append(b, randomBytes(300)...)
	b = binary.LittleEndian.AppendUint32(b, testVector)
	b = binary.LittleEndian.AppendUint32(b, 1)
	return binary.LittleEndian.AppendUint64(b, testFingerprint)
}
