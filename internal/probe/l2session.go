package probe

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"
)

// L2Session is an L2 probe that stays open: one connection through a
// fake-TLS proxy to a datacenter, on which req_pq_multi goes out again
// whenever Ping is called. It is what a Telegram client that keeps its
// connection looks like to the proxy, and a test holds one over a change of
// the proxy to prove that the connection survives it while traffic flows.
type L2Session struct {
	mu     sync.Mutex
	conn   net.Conn
	o      *obfuscated2
	w      *recordWriter
	r      cipher.StreamReader
	now    func() time.Time
	opened bool // the obfuscated2 header went out
}

// OpenL2 dials addr, does the fake-TLS handshake with sni and secret (as
// FakeTLS), and asks the datacenter dc once, as L2 does: it returns the
// session once the datacenter's resPQ came back through the proxy. opt.Timeout
// bounds all of that; opt.ProxyHeader and opt.Now are as in L2. The errors are
// those of L2. The caller closes the session.
func OpenL2(ctx context.Context, addr, sni string, secret []byte, dc int16, opt Options) (*L2Session, error) {
	if err := checkArguments(sni, secret, opt); err != nil {
		return nil, err
	}
	o, err := newObfuscated2(rand.Reader, tagPaddedIntermediate, dc, secret)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, opt.timeout())
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, failure(ctx, fmt.Errorf("probe: connecting: %w", err))
	}
	if err := Handshake(conn, sni, secret, opt); err != nil {
		_ = conn.Close()
		return nil, failure(ctx, err)
	}
	s := &L2Session{conn: conn, o: o, w: &recordWriter{w: conn}, now: opt.now}
	s.r = cipher.StreamReader{S: o.dec, R: &recordReader{r: conn}}
	if err := s.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return s, nil
}

// Ping sends req_pq_multi for a fresh nonce on the session and returns when
// the datacenter's resPQ for it came back. It has until the deadline of ctx,
// or 10 seconds when ctx has none, and stops at once when ctx is canceled.
// The errors are those of the exchange of L2; after one, the session is of no
// further use.
func (s *L2Session) Ping(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	deadline, _ := ctx.Deadline()
	if err := s.conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("probe: setting the deadline of the connection: %w", err)
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		_ = s.conn.SetDeadline(time.Unix(1, 0))
	})
	err := s.exchange()
	if !stop() {
		<-interrupted
	}
	if cerr := s.conn.SetDeadline(time.Time{}); cerr != nil && err == nil {
		err = fmt.Errorf("clearing the deadline of the connection: %w", cerr)
	}
	return failure(ctx, pingError(err))
}

// exchange sends one request, after the header on the first, and reads its
// answer.
func (s *L2Session) exchange() error {
	var nonce [nonceLen]byte
	_, _ = rand.Read(nonce[:]) // never fails
	var out []byte
	if !s.opened {
		out = append(out, s.o.header[:]...)
	}
	start := len(out)
	out, err := appendFrame(out, tagPaddedIntermediate, reqPQMulti(messageID(s.now()), &nonce), rand.Reader)
	if err != nil {
		return err
	}
	s.o.enc.XORKeyStream(out[start:], out[start:])
	if _, err := s.w.Write(out); err != nil {
		return fmt.Errorf("sending req_pq_multi: %w", err)
	}
	s.opened = true
	frame, err := readFrame(s.r)
	if err != nil {
		return err
	}
	return checkResPQ(frame, &nonce)
}

// Close closes the connection of the session.
func (s *L2Session) Close() error {
	return s.conn.Close()
}
