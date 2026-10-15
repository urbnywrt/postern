//go:build !(mips || mipsle || mips64 || mips64le || sparc64)

package egress

import (
	"os"
	"syscall"
)

// soReusePort is SO_REUSEPORT of <asm-generic/socket.h>. The syscall package does
// not define it for every architecture. The value holds for every Linux
// architecture of the generic socket options, amd64 and arm64 among them; the
// build constraint above leaves out the few that differ, which get
// socksports_other.go.
const soReusePort = 0xf

// reusePort reports whether the ports are bound with SO_REUSEPORT, so that the next
// generation of the edge can bind the same ports while the old one drains.
const reusePort = true

// reusePortControl sets SO_REUSEPORT on a socket before it is bound.
func reusePortControl(_, _ string, rc syscall.RawConn) error {
	var opErr error
	err := rc.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
			opErr = os.NewSyscallError("setsockopt SO_REUSEPORT", err)
		}
	})
	if err != nil {
		return err
	}
	return opErr
}
