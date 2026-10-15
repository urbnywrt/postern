//go:build linux

package egress

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// SO_BINDTODEVICE is the privileged part of a direct member that is tied to an
// interface. These tests check that the option reaches the socket, and what they
// need of the machine they run on they take from the kernel: an unprivileged
// process may set the option on a socket that is not yet tied to a device since
// Linux 5.7, and where it may not, the tests skip.

func TestBindDeviceIsApplied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dial := func(device string) error {
		d, err := NewMemberDialer(&edgev1.ChainMember{Key: "d", Kind: "direct", BindDevice: device}, time.Second)
		if err != nil {
			t.Fatalf("NewMemberDialer(%q): %v", device, err)
		}
		conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
		if err == nil {
			_ = conn.Close()
		}
		return err
	}

	// A device that does not exist makes the kernel refuse the option, and that
	// refusal reaches the caller of the dial: the option was set on the socket.
	err = dial("pstn-nodev0")
	switch {
	case errors.Is(err, syscall.EPERM):
		t.Skipf("SO_BINDTODEVICE is not permitted here: %v", err)
	case !errors.Is(err, syscall.ENODEV):
		t.Fatalf("dial through a device that does not exist: error %v, want ENODEV", err)
	}

	// The loopback interface exists everywhere, and a connection to a loopback
	// address goes out through it.
	if err := dial("lo"); err != nil {
		t.Errorf("dial through lo: %v", err)
	}
}

func TestBindToDeviceNamesTheDeviceInItsError(t *testing.T) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error { return bindToDevice(c, "pstn-nodev0") }}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		_ = ln.Close()
		t.Fatal("bindToDevice accepted a device that does not exist")
	}
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("SO_BINDTODEVICE is not permitted here: %v", err)
	}
	if !errors.Is(err, syscall.ENODEV) {
		t.Errorf("error %v, want ENODEV", err)
	}
	if !strings.Contains(err.Error(), "pstn-nodev0") {
		t.Errorf("error %q does not name the device", err)
	}
}

func TestMemberWithADeviceAcceptsOnlyValidNames(t *testing.T) {
	for _, kind := range []string{KindDirect, KindSOCKS5, KindHTTP} {
		member := func(dev string) *edgev1.ChainMember {
			return &edgev1.ChainMember{Key: "d", Kind: kind, Addr: "127.0.0.1:1080", BindDevice: dev}
		}
		for _, dev := range []string{"lo", "eth0", "wg0", "tun0", "enp0s31f6", "a-b_c.d", "abcdefghijklmno"} { // up to 15 bytes
			if _, err := NewMemberDialer(member(dev), time.Second); err != nil {
				t.Errorf("%s, device %q: %v", kind, dev, err)
			}
		}
		for _, dev := range []string{"abcdefghijklmnop", "a b", "a/b", "a\x00b", "a\nb"} {
			if _, err := NewMemberDialer(member(dev), time.Second); err == nil {
				t.Errorf("%s, device %q was accepted", kind, dev)
			}
		}
	}
}

// A proxy member ties the connection to its proxy to bind_device, as a direct
// member ties the one to its target.
func TestBindDeviceIsAppliedToTheConnectionOfAProxyMember(t *testing.T) {
	echo := startEcho(t)
	proxies := map[string]string{
		KindSOCKS5: startSOCKS5(t, (&requestLog{target: echo}).dial),
		KindHTTP:   startNotingProxy(t, KindHTTP).addr,
	}
	for _, kind := range []string{KindSOCKS5, KindHTTP} {
		t.Run(kind, func(t *testing.T) {
			dial := func(device string) error {
				d, err := NewMemberDialer(&edgev1.ChainMember{Key: "p", Kind: kind, Addr: proxies[kind], BindDevice: device}, time.Second)
				if err != nil {
					t.Fatalf("NewMemberDialer(%q): %v", device, err)
				}
				conn, err := d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
				if err == nil {
					_ = conn.Close()
				}
				return err
			}
			err := dial("pstn-nodev0")
			switch {
			case errors.Is(err, syscall.EPERM):
				t.Skipf("SO_BINDTODEVICE is not permitted here: %v", err)
			case !errors.Is(err, syscall.ENODEV):
				t.Fatalf("dial through a device that does not exist: error %v, want ENODEV", err)
			}
			if !strings.Contains(err.Error(), "pstn-nodev0") {
				t.Errorf("error %q does not name the device", err)
			}
			if err := dial("lo"); err != nil {
				t.Errorf("dial through lo: %v", err)
			}
		})
	}
}
