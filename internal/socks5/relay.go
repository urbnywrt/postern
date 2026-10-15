package socks5

import (
	"io"
	"net"
)

// closeWriter is what a connection must be able to do for a half-close: tell its
// peer that nothing more will be sent, and go on receiving. *net.TCPConn and
// *tls.Conn can.
type closeWriter interface {
	CloseWrite() error
}

// Relay copies data between a and b in both directions, until each direction has
// come to its end. Then it closes both connections and returns the number of
// bytes copied from a to b and from b to a.
//
// A direction ends when its source reports the end of the stream, or fails. At
// the end of a stream Relay passes the news to the other connection with
// CloseWrite, if that connection has one, and the opposite direction goes on: a
// peer that has sent its request and half-closed still gets its answer. The relay
// is over when the other peer ends its stream in turn.
//
// A connection without CloseWrite cannot be told that the stream has ended in
// any other way than by closing it, and so the end of one direction ends both,
// and what is in flight to the closed side is lost. The same goes for any
// failure: when a copy fails, both connections are closed, so that the opposite
// direction does not wait for a peer that is gone. A wrapper around a connection
// that is meant for a relay should pass CloseWrite on.
//
// Relay puts no limit on how long it takes. It returns when the two peers are
// done, and closing either connection from outside is what ends it at once.
func Relay(a, b net.Conn) (aToB, bToA int64) {
	toA := make(chan int64, 1)
	go func() { toA <- forward(a, b) }()
	aToB = forward(b, a)
	bToA = <-toA
	_ = a.Close()
	_ = b.Close()
	return aToB, bToA
}

// forward copies from src to dst until the end of src, and returns the number of
// bytes copied. See Relay for what it does when the copy ends.
func forward(dst, src net.Conn) int64 {
	n, err := io.Copy(dst, src)
	if err == nil {
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			return n
		}
	}
	_ = dst.Close()
	_ = src.Close()
	return n
}
