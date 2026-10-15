package probe

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ErrBadResPQ is wrapped by the errors of DCPing and L2 when an answer to
// req_pq_multi came, but not the resPQ for it: another message, a resPQ for
// another nonce, an error code of the transport, a frame that cannot be an
// answer (too short, or longer than 64 KiB), or, inside fake TLS, a record that
// is not application data, more than 16 empty records in a row, or a TLS alert
// (which the error wraps as an *AlertError as well). The text after it says
// which. A connection that ends, or runs out of time, before an answer is
// complete is not this error.
var ErrBadResPQ = errors.New("probe: the answer is not a valid resPQ")

// AlertError is a TLS alert that a fake-TLS server sent after the handshake,
// where L2 waited for its answer. The error of L2 wraps it next to
// ErrBadResPQ: errors.Is(err, ErrBadResPQ) holds as for any other wrong
// answer, and errors.As finds the alert.
type AlertError struct {
	Level       byte // 1 for a warning, 2 for a fatal alert
	Description byte // what the alert says: 80 is internal_error, for instance
}

func (e *AlertError) Error() string {
	return fmt.Sprintf("the server sent TLS alert %d%s, level %d", e.Description, alertName(e.Description), e.Level)
}

const (
	// dcPingDatacenter is the datacenter in the header of DCPing. Only a
	// proxy looks at the field, to pick the datacenter: the five datacenters
	// of the health targets answer alike with 0, 2, -2, 5 and 999 in it
	// (TestIntegrationDCPing, online).
	dcPingDatacenter = 0

	// maxRecordPayload is the most data L2 puts in one TLS record: 2^14
	// bytes, the limit of TLS.
	maxRecordPayload = 16384
	// maxEmptyRecords is the most empty application data records in a row
	// that L2 takes from a server.
	maxEmptyRecords = 16
)

// DCPing runs obfuscated2 (no secret, tag 0xeeeeeeee) + req_pq_multi over conn,
// which is already connected to a datacenter (directly or through an egress
// member), and returns when a resPQ with the same nonce arrives. It sets and
// clears deadlines on conn.
//
// The exchange has until the deadline of ctx, or 10 seconds when ctx has none,
// and stops at once when ctx is canceled. The request goes out in a single
// write, the header of the connection carrying datacenter 0, and DCPing reads
// exactly the frame of the answer: a resPQ for a fresh random nonce proves that
// a datacenter is at the other end, whatever acknowledged the connection on
// the way. Before it returns, DCPing clears the deadline of conn, so after a
// success conn is right after the answer and can carry on; it never closes
// conn.
//
// The error says what went wrong. It wraps ErrBadResPQ when an answer came but
// is not the resPQ for the request (the text says what came instead); io.EOF
// when the connection ended without an answer and io.ErrUnexpectedEOF when it
// ended inside one; and context.DeadlineExceeded or context.Canceled, next to
// the I/O error they caused, when the time ran out or ctx was canceled. The
// error never contains a key or the nonce, and DCPing logs nothing.
func DCPing(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return errors.New("probe: there is no connection")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("probe: setting the deadline of the connection: %w", err)
	}
	// A cancellation moves the deadline into the past, which stops the
	// exchange wherever it is. The deadline is cleared once that cannot
	// happen any more.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		_ = conn.SetDeadline(time.Unix(1, 0))
	})
	err := ping(conn, conn, tagIntermediate, dcPingDatacenter, nil, time.Now())
	if !stop() {
		<-interrupted
	}
	if cerr := conn.SetDeadline(time.Time{}); cerr != nil && err == nil {
		err = fmt.Errorf("clearing the deadline of the connection: %w", cerr)
	}
	return failure(ctx, pingError(err))
}

// L2 dials addr, does the fake-TLS handshake with sni and secret (as FakeTLS), then
// speaks obfuscated2 with the secret (tag 0xdddddddd, dc) inside TLS application-data
// records and returns when the datacenter's resPQ comes back through the proxy.
//
// It is the L2 probe of the design: a Telegram client's view of the whole path,
// from the listener (the edge's, or an engine's loopback port) through the
// engine and its way out to the datacenter dc (1 to 5, negative for a media
// datacenter), which the proxy picks by the header. The options are those of
// FakeTLS: opt.ProxyHeader sends a PROXY v2 header first, opt.Timeout bounds the
// whole probe (connecting, the handshake and the exchange), and opt.Now dates
// the ClientHello and the request.
//
// Once the handshake is over L2 sends what tdlib sends: a ChangeCipherSpec
// record, then application data records of at most 16384 bytes, which carry
// the obfuscated2 header and the request in a frame of the padded intermediate
// transport, all in a single write. It reads the server's application data
// records and decrypts their contents.
//
// The errors of the handshake are those of FakeTLS, ErrBadServerDigest among
// them. The errors of the exchange are those of DCPing; in place of the
// answer, a record other than application data, or more than 16 empty ones in
// a row, wraps ErrBadResPQ as well, and a TLS alert wraps both ErrBadResPQ and
// an *AlertError that says which alert came. The error never contains the
// secret, a key or the nonce, and L2 logs nothing.
func L2(ctx context.Context, addr, sni string, secret []byte, dc int16, opt Options) error {
	if err := checkArguments(sni, secret, opt); err != nil {
		return err
	}
	return dialAndRun(ctx, addr, opt, func(conn net.Conn) error {
		if err := Handshake(conn, sni, secret, opt); err != nil {
			return err
		}
		return pingError(ping(&recordWriter{w: conn}, &recordReader{r: conn}, tagPaddedIntermediate, dc, secret, opt.now()))
	})
}

// ping opens an obfuscated2 connection for datacenter dc with the transport of
// tag (keyed with the proxy secret when there is one), sends req_pq_multi for a
// fresh nonce dated now on w in a single write, reads the first frame of the
// answer from r and checks that it is the resPQ for the request.
func ping(w io.Writer, r io.Reader, tag uint32, dc int16, secret []byte, now time.Time) error {
	o, err := newObfuscated2(rand.Reader, tag, dc, secret)
	if err != nil {
		return err
	}
	var nonce [nonceLen]byte
	_, _ = rand.Read(nonce[:]) // never fails

	out := make([]byte, 0, obfuscated2HeaderLen+4+plainHeaderLen+4+nonceLen+maxPadding)
	out = append(out, o.header[:]...)
	if out, err = appendFrame(out, tag, reqPQMulti(messageID(now), &nonce), rand.Reader); err != nil {
		return err
	}
	o.enc.XORKeyStream(out[obfuscated2HeaderLen:], out[obfuscated2HeaderLen:])
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("sending req_pq_multi: %w", err)
	}

	frame, err := readFrame(cipher.StreamReader{S: o.dec, R: r})
	if err != nil {
		return err
	}
	return checkResPQ(frame, &nonce)
}

// pingError makes err, the outcome of ping, an error of DCPing or L2: a
// verdict on the answer becomes ErrBadResPQ with the verdict after it, and a
// TLS alert wraps both ErrBadResPQ and the *AlertError.
func pingError(err error) error {
	var (
		bad   badAnswer
		alert *AlertError
	)
	switch {
	case err == nil:
		return nil
	case errors.As(err, &alert):
		return fmt.Errorf("%w: %w", ErrBadResPQ, alert)
	case errors.As(err, &bad):
		return fmt.Errorf("%w: %s", ErrBadResPQ, string(bad))
	}
	return fmt.Errorf("probe: %w", err)
}

// ---- TLS records after the handshake ----------------------------------------------

// clientChangeCipherSpec is the record a fake-TLS client sends once, ahead of
// its first data.
var clientChangeCipherSpec = []byte{recordTypeChangeCipherSpec, 3, 3, 0, 1, 1}

// recordWriter sends what is written to it the way a fake-TLS client sends its
// data once the handshake is over: in TLS 1.2 application data records of at
// most maxRecordPayload bytes, after a ChangeCipherSpec record ahead of the
// first. Each Write goes out in a single write.
type recordWriter struct {
	w       io.Writer
	started bool // the ChangeCipherSpec went out
}

func (rw *recordWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(clientChangeCipherSpec)+len(p)+recordHeaderLen*(len(p)/maxRecordPayload+1))
	if !rw.started {
		out = append(out, clientChangeCipherSpec...)
		rw.started = true
	}
	for rest := p; len(rest) > 0; {
		n := min(len(rest), maxRecordPayload)
		out = append(out, recordTypeApplicationData, 3, 3, byte(n>>8), byte(n))
		out = append(out, rest[:n]...)
		rest = rest[n:]
	}
	if _, err := rw.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// recordReader reads the data a fake-TLS server sends once the handshake is
// over: the payloads of TLS 1.2 application data records, in order, and up to
// maxEmptyRecords empty ones in a row. Anything else is a verdict on the
// answer: a TLS alert is an *AlertError; a record of another type or version,
// or one empty record too many, is a badAnswer. A record is at most 64 KiB
// long by its header. The stream ends cleanly, with io.EOF, only between
// records.
type recordReader struct {
	r     io.Reader
	left  int // what is left of the payload of the current record
	empty int // the empty records in a row since the last one with data
}

func (rr *recordReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for rr.left == 0 {
		var hdr [recordHeaderLen]byte
		if _, err := io.ReadFull(rr.r, hdr[:]); err != nil {
			return 0, err // io.EOF between records, io.ErrUnexpectedEOF inside a header
		}
		n := int(binary.BigEndian.Uint16(hdr[3:]))
		switch {
		case hdr[0] == recordTypeAlert && n == 2:
			var alert [2]byte
			if _, err := io.ReadFull(rr.r, alert[:]); err != nil {
				return 0, unexpectedEOF(err)
			}
			return 0, &AlertError{Level: alert[0], Description: alert[1]}
		case hdr[0] == recordTypeAlert:
			return 0, badAnswer(fmt.Sprintf("the server sent an alert record of %d bytes", n))
		case hdr[0] != recordTypeApplicationData:
			return 0, badAnswer(fmt.Sprintf("the server sent a record of type %#02x where application data belongs", hdr[0]))
		case hdr[1] != 3 || hdr[2] != 3:
			return 0, badAnswer(fmt.Sprintf("the server sent an application data record of version %d.%d, not 3.3", hdr[1], hdr[2]))
		case n == 0:
			// A server that sent nothing but empty records would hold the
			// probe until its deadline.
			if rr.empty++; rr.empty > maxEmptyRecords {
				return 0, badAnswer(fmt.Sprintf("the server sent more than %d empty application data records in a row", maxEmptyRecords))
			}
			continue
		}
		rr.empty, rr.left = 0, n
	}
	if len(p) > rr.left {
		p = p[:rr.left]
	}
	n, err := rr.r.Read(p)
	rr.left -= n
	if err == io.EOF {
		// The end of the stream is clean only at the end of a record.
		err = nil
		if rr.left > 0 {
			err = io.ErrUnexpectedEOF
		}
	}
	return n, err
}

// unexpectedEOF is err with io.EOF made io.ErrUnexpectedEOF.
func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
