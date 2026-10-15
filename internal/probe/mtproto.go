package probe

// The first message of MTProto's key exchange, and the frames that carry it.
//
// A client without an authorization key starts the exchange with
// req_pq_multi#be7e8ef1 nonce:int128 = ResPQ in an unencrypted message:
// auth_key_id 0 (int64), message_id (int64), message_data_length (int32) and
// the data, all little endian. The datacenter answers with resPQ#05162463
// nonce:int128 server_nonce:int128 pq:bytes
// server_public_key_fingerprints:Vector<long> = ResPQ, the nonce being the
// client's (core.telegram.org/mtproto/auth_key, /mtproto/description). The
// answer takes no key, but only a datacenter gives it: it is the cheapest proof
// that a connection reaches one.
//
// The intermediate transports put each message in a frame: its length, a
// 4-byte little-endian integer, and the message; in the padded variant 0 to 15
// random bytes follow the message, and the length covers them. A frame that
// holds a negative 32-bit number instead of a message, padded or not, is an
// error code of the transport, -404 for instance
// (core.telegram.org/mtproto/mtproto-transports).

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	crcReqPQMulti uint32 = 0xbe7e8ef1
	crcResPQ      uint32 = 0x05162463
	crcVector     uint32 = 0x1cb5c415

	nonceLen = 16
	// plainHeaderLen is the size of the header of an unencrypted message:
	// auth_key_id, message_id and message_data_length.
	plainHeaderLen = 8 + 8 + 4

	// maxFrameLen is the longest frame the probe reads. A resPQ takes less
	// than a hundred bytes.
	maxFrameLen = 64 << 10
	// maxPadding is the most padding the padded intermediate transport puts
	// after a message.
	maxPadding = 15
)

// badAnswer is the verdict on an answer that came but is not the resPQ that was
// asked for, in words. DCPing and L2 return it as ErrBadResPQ.
type badAnswer string

func (e badAnswer) Error() string { return string(e) }

// messageID is the message_id of a message sent at now: the Unix time in units
// of 2^-32 seconds, rounded down to a multiple of 4, as clients make it.
func messageID(now time.Time) uint64 {
	frac := (uint64(now.Nanosecond()) << 32) / 1e9
	return (uint64(now.Unix())<<32 | frac) &^ 3
}

// reqPQMulti returns req_pq_multi for nonce in an unencrypted message with
// msgID.
func reqPQMulti(msgID uint64, nonce *[nonceLen]byte) []byte {
	m := make([]byte, 0, plainHeaderLen+4+nonceLen)
	m = binary.LittleEndian.AppendUint64(m, 0) // auth_key_id: none
	m = binary.LittleEndian.AppendUint64(m, msgID)
	m = binary.LittleEndian.AppendUint32(m, 4+nonceLen)
	m = binary.LittleEndian.AppendUint32(m, crcReqPQMulti)
	return append(m, nonce[:]...)
}

// appendFrame appends to b the frame of the transport with tag that carries
// message: in the padded variant with 0 to 15 bytes of padding, its length and
// its bytes drawn from random.
func appendFrame(b []byte, tag uint32, message []byte, random io.Reader) ([]byte, error) {
	var padding [maxPadding]byte
	pad := 0
	if tag == tagPaddedIntermediate {
		var n [1]byte
		if _, err := io.ReadFull(random, n[:]); err != nil {
			return nil, fmt.Errorf("drawing the padding: %w", err)
		}
		pad = int(n[0]) % (maxPadding + 1)
		if _, err := io.ReadFull(random, padding[:pad]); err != nil {
			return nil, fmt.Errorf("drawing the padding: %w", err)
		}
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(message)+pad))
	b = append(b, message...)
	return append(b, padding[:pad]...), nil
}

// readFrame reads a frame of the intermediate transports from r, padded or
// not, and returns what it carries. It reads exactly the frame. A length that
// no answer can have is refused before anything more is read.
func readFrame(r io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("the server closed the connection without answering req_pq_multi: %w", err)
		}
		return nil, answerError(err)
	}
	switch n := binary.LittleEndian.Uint32(length[:]); {
	case n > maxFrameLen:
		return nil, badAnswer(fmt.Sprintf("a frame of %d bytes, longer than %d", n, maxFrameLen))
	case n < 4:
		return nil, badAnswer(fmt.Sprintf("a frame of %d bytes, too short for a message or an error code", n))
	default:
		frame := make([]byte, n)
		if _, err := io.ReadFull(r, frame); err != nil {
			return nil, answerError(err)
		}
		return frame, nil
	}
}

// answerError is err, from reading inside the answer: an end of the stream
// there is unexpected.
func answerError(err error) error {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("reading the answer to req_pq_multi: %w", err)
}

// checkResPQ checks that frame, what the server's first frame carries, is the
// resPQ for nonce: an unencrypted message holding a resPQ, whole, with that
// nonce. Bytes after the message (padding) are no concern of it. The verdict
// never shows a nonce.
func checkResPQ(frame []byte, nonce *[nonceLen]byte) error {
	if len(frame) < plainHeaderLen {
		// Too short for a message: an error code of the transport, maybe
		// followed by padding.
		if len(frame) >= 4 {
			if code := int32(binary.LittleEndian.Uint32(frame)); code < 0 {
				return badAnswer(fmt.Sprintf("the server answered with transport error %d", code))
			}
		}
		return badAnswer(fmt.Sprintf("a frame of %d bytes, too short for a message", len(frame)))
	}
	if binary.LittleEndian.Uint64(frame) != 0 {
		return badAnswer("an encrypted message (its auth_key_id is not 0)")
	}
	n, data := binary.LittleEndian.Uint32(frame[16:]), frame[plainHeaderLen:]
	if uint64(n) > uint64(len(data)) {
		return badAnswer(fmt.Sprintf("the message_data_length of the message is %d, but the frame holds %d bytes", n, len(data)))
	}
	return checkResPQData(data[:n], nonce)
}

// checkResPQData checks the data of an unencrypted message: a resPQ for nonce,
// every field of it there.
func checkResPQData(b []byte, nonce *[nonceLen]byte) error {
	if len(b) < 4 {
		return badAnswer(fmt.Sprintf("a message of %d bytes, too short for a constructor", len(b)))
	}
	if crc := binary.LittleEndian.Uint32(b); crc != crcResPQ {
		return badAnswer(fmt.Sprintf("a message with constructor 0x%08x, not resPQ", crc))
	}
	b = b[4:]
	if len(b) < nonceLen {
		return badAnswer("the resPQ is too short for its nonce")
	}
	if !bytes.Equal(b[:nonceLen], nonce[:]) {
		return badAnswer("a resPQ for another nonce")
	}
	b = b[nonceLen:]
	if len(b) < nonceLen {
		return badAnswer("the resPQ is cut short in server_nonce")
	}
	b, ok := skipTLBytes(b[nonceLen:])
	if !ok {
		return badAnswer("the resPQ is cut short in pq")
	}
	if len(b) < 8 {
		return badAnswer("the resPQ is cut short before server_public_key_fingerprints")
	}
	if crc := binary.LittleEndian.Uint32(b); crc != crcVector {
		return badAnswer(fmt.Sprintf("the server_public_key_fingerprints of the resPQ have constructor 0x%08x, not that of a vector", crc))
	}
	if count := binary.LittleEndian.Uint32(b[4:]); uint64(count)*8 > uint64(len(b)-8) {
		return badAnswer(fmt.Sprintf("the resPQ is cut short in its %d server_public_key_fingerprints", count))
	}
	return nil
}

// skipTLBytes returns b after the value of the TL type bytes it starts with: a
// length (a byte below 254, or 254 and three bytes), that many bytes, and
// padding to a multiple of 4. It reports false when b ends before the value
// does.
func skipTLBytes(b []byte) ([]byte, bool) {
	if len(b) == 0 || b[0] == 255 {
		return nil, false
	}
	n, head := int(b[0]), 1
	if b[0] == 254 {
		if len(b) < 4 {
			return nil, false
		}
		n, head = int(b[1])|int(b[2])<<8|int(b[3])<<16, 4
	}
	end := (head + n + 3) &^ 3
	if end > len(b) {
		return nil, false
	}
	return b[end:], true
}
