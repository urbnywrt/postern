//go:build linux && !(mips || mipsle || mips64 || mips64le || sparc64)

package dns

import (
	"net"
	"os"
	"syscall"
)

// soReusePort is SO_REUSEPORT of <asm-generic/socket.h>, which the syscall
// package does not define. The value holds for every Linux architecture of the
// generic socket options, amd64 and arm64 among them; the build constraint
// leaves out the few that differ, which get listen_other.go.
const soReusePort = 0xf

// listenConfig returns the configuration of the sockets of the forwarder:
// SO_REUSEADDR and SO_REUSEPORT set before bind, as the listeners of the edge
// have them, so that the edge generation that takes over binds 127.0.0.2:53
// while the old one still holds it.
func listenConfig() net.ListenConfig {
	return net.ListenConfig{Control: setReuse}
}

func setReuse(_, _ string, rc syscall.RawConn) error {
	var opErr error
	err := rc.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			opErr = os.NewSyscallError("setsockopt SO_REUSEADDR", err)
			return
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
			opErr = os.NewSyscallError("setsockopt SO_REUSEPORT", err)
		}
	})
	if err != nil {
		return err
	}
	return opErr
}
