//go:build !(mips || mipsle || mips64 || mips64le || sparc64)

package edge

import (
	"net"
	"os"
	"syscall"
)

// soReusePort is SO_REUSEPORT of <asm-generic/socket.h>. The syscall package
// does not define it. The value holds for every Linux architecture of the
// generic socket options, amd64 and arm64 among them; the build constraint
// above leaves out the few that differ, which get listener_other.go.
const soReusePort = 0xf

// reusePort reports whether listeners are bound with SO_REUSEPORT, so that
// another process, or another Edge of this one, can bind the same address. That
// is how a new generation of the edge takes the ports over while the old one
// drains.
const reusePort = true

// listenConfig returns the configuration of every listening socket of the
// edge: SO_REUSEADDR and SO_REUSEPORT set before bind.
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
