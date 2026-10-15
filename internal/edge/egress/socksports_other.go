//go:build !linux || mips || mipsle || mips64 || mips64le || sparc64

package egress

import "syscall"

// reusePort reports whether the ports are bound with SO_REUSEPORT. The edge runs on
// Linux; elsewhere it builds, for tools and tests of other packages, but binds
// plain sockets.
const reusePort = false

// reusePortControl is nil: the sockets are plain.
var reusePortControl func(network, address string, c syscall.RawConn) error
