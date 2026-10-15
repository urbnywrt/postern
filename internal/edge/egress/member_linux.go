//go:build linux

package egress

import (
	"fmt"
	"os"
	"syscall"
)

// bindDeviceSupported reports whether a member can be tied to an interface.
const bindDeviceSupported = true

// bindToDevice ties the socket of c to the interface dev (SO_BINDTODEVICE), so
// that whatever is sent on it leaves through that interface, whatever the routing
// table says. It is how a member uses an interface that was brought up outside
// Postern, a WireGuard or OpenVPN tunnel, wg0 or tun0: a direct member for its
// connections to the targets, a proxy member for the ones to its proxy.
//
// It is called on a socket that has not connected yet, from the Control hook of
// a net.Dialer. The kernel lets a process without CAP_NET_RAW do this since Linux
// 5.7, as long as the socket is not tied to a device already. On an older kernel
// the process needs the capability, and the dial of a member that is tied to an
// interface fails with EPERM until it has it: the node agent gives the edge
// container CAP_NET_RAW while a member of a chain is tied to an interface.
func bindToDevice(c syscall.RawConn, dev string) error {
	var opErr error
	if err := c.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
	}); err != nil {
		return err
	}
	if opErr != nil {
		return fmt.Errorf("egress: cannot bind the socket to the device %q: %w", dev, os.NewSyscallError("setsockopt SO_BINDTODEVICE", opErr))
	}
	return nil
}
