//go:build !linux || mips || mipsle || mips64 || mips64le || sparc64

package edge

import "net"

// reusePort reports whether listeners are bound with SO_REUSEPORT. The edge
// runs on Linux; elsewhere it builds, for tools and tests of other packages,
// but binds plain sockets.
const reusePort = false

// listenConfig returns the configuration of every listening socket of the
// edge: the default one here.
func listenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
