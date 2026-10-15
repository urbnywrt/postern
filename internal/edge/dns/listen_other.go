//go:build !linux || mips || mipsle || mips64 || mips64le || sparc64

package dns

import "net"

// listenConfig returns the configuration of the sockets of the forwarder: the
// default one here. The edge runs on Linux; elsewhere it builds, for tools and
// tests of other packages, but binds plain sockets.
func listenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
