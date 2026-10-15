package control

import (
	"context"
	"net"
	"net/http"

	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
)

// NewClient returns a client of the control service of the edge whose unix
// socket is at socketPath, for the node agent. It speaks the Connect protocol
// over HTTP/1.1 and has no deadline of its own: those are the contexts of the
// calls.
//
// Every call is a connection of its own. The calls are few, one every ten
// seconds, a connection to a unix socket costs next to nothing, and no
// connection is left idle that an edge which has exited could leave dead. The
// socket does not have to exist when the client is made, and may be replaced
// by the one of another process while the client lives.
//
// The client holds no resource that needs closing.
func NewClient(socketPath string) edgev1connect.EdgeControlServiceClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
		Protocols:         http1Only(),
	}
	// The host of the URL is of no use: the dialer ignores it, and goes to the
	// socket.
	return edgev1connect.NewEdgeControlServiceClient(&http.Client{Transport: transport}, "http://edge.test")
}

func http1Only() *http.Protocols {
	var p http.Protocols
	p.SetHTTP1(true)
	return &p
}
