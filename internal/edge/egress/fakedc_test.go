package egress

import (
	"net"
	"testing"

	"github.com/urbnywrt/postern/internal/probe/probetest"
)

// The datacenters of these tests are those of probetest: they answer
// probe.DCPing as a datacenter does, or fail it in one of the ways that the
// checks of the members must tell apart.

type dcMode = probetest.Mode

const (
	dcAnswers    = probetest.Answers    // with the resPQ for the request
	dcHangsUp    = probetest.HangsUp    // closes the connection after the request, without a word
	dcWrongNonce = probetest.WrongNonce // with a resPQ for another nonce
	dcSilent     = probetest.Silent     // reads the request and says nothing until the client hangs up
)

// dcPipe returns a connection to a datacenter of the given mode, over a pipe:
// what a fake dialer hands out for a datacenter.
func dcPipe(mode dcMode) net.Conn { return probetest.Pipe(mode) }

// startFakeDC starts a datacenter of the given mode on a loopback port, which
// closes when the test ends. answering, when it is set, is called just before
// each answer goes out.
func startFakeDC(t *testing.T, mode dcMode, answering func()) *probetest.Server {
	t.Helper()
	s, err := probetest.NewServer(mode, answering)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
