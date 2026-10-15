//go:build !linux

package egress

import (
	"errors"
	"syscall"
)

// bindDeviceSupported reports whether a member can be tied to an interface. The
// edge runs on Linux; elsewhere it builds, for tools and tests of other
// packages, without the option.
const bindDeviceSupported = false

func bindToDevice(syscall.RawConn, string) error {
	return errors.New("egress: SO_BINDTODEVICE is available on Linux only")
}
