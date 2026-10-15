//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
)

// TestHiddenManagement runs hidden management (spec §5.3) for real:
//
//  1. a node, and a tls listener on 127.0.0.1 without a proxy (the edge runs
//     for it all the same);
//  2. the panel switches the node to hidden with a management SNI and the
//     listener's port: its live check is GetInfo through the edge with that
//     SNI, so a switch that answers ok has reached the agent there; the plain
//     management port is closed afterwards, and a change of the state still
//     reaches the node, through the public port;
//  3. a TLS client with the management SNI and no client certificate is
//     refused at the handshake: the agent asks for the certificate that only
//     the panel has, and the edge passes the connection to it;
//  4. the panel switches back: the plain port answers again, the SNI is gone,
//     and a change of the state reaches the node.
func TestHiddenManagement(t *testing.T) {
	e := newEnv(t)
	p := e.startPanel()
	a := newAPI(p.base)
	e.signIn(a, p.token)

	// 1. The node and its listener.
	node := e.newNode(a)
	plain := net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(node.GetMgmtPort()), 10))
	lport := e.freePort("127.0.0.1", 10000, 19999)
	var listenerID string
	desired := e.change(a, node.GetId(), "CreateListener", func(ctx context.Context) error {
		r, err := a.listeners.CreateListener(ctx, connect.NewRequest(&panelv1.CreateListenerRequest{
			NodeId: node.GetId(), Kind: "tls", BindIp: "127.0.0.1", Port: uint32(lport),
		}))
		if err == nil {
			listenerID = r.Msg.GetListener().GetId()
		}
		return err
	})
	e.waitNodeApplied(a, node.GetId(), desired, 3*time.Minute)

	// 2. To hidden.
	sni := "mgmt-" + e.run + ".example.net"
	e.switchMgmt(a, node.GetId(), "hidden", sni, uint32(lport))
	n, err := e.getNode(e.ctx, a, node.GetId())
	if err != nil {
		e.fatalf("%v", err)
	}
	if n.GetMgmtMode() != "hidden" || n.GetMgmtSni() != sni || n.GetMgmtPublicPort() != uint32(lport) {
		e.fatalf("after the switch to hidden the node has mode %q, SNI %q, public port %d", n.GetMgmtMode(), n.GetMgmtSni(), n.GetMgmtPublicPort())
	}
	e.waitFor("the plain management port closed", time.Minute, 500*time.Millisecond, func(ctx context.Context) (bool, string, error) {
		if err := dialOnce(ctx, plain); err != nil {
			return true, "closed: " + err.Error(), nil
		}
		return false, "open", nil
	})
	desired = e.change(a, node.GetId(), "UpdateListener", func(ctx context.Context) error {
		_, err := a.listeners.UpdateListener(ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: listenerID, StrangerAction: ptr("reject")}))
		return err
	})
	e.waitNodeApplied(a, node.GetId(), desired, 2*time.Minute)
	e.logf("hidden: the plain port %s is closed, and the panel reaches the node through 127.0.0.1:%d with SNI %s", plain, lport, sni)

	// 3. A stranger with the management SNI and no client certificate.
	how := e.strangerRefused(net.JoinHostPort("127.0.0.1", strconv.Itoa(lport)), sni)
	e.logf("a TLS client with the management SNI and no client certificate is refused: %s", how)

	// 4. Back to port.
	e.switchMgmt(a, node.GetId(), "port", "", 0)
	if n, err = e.getNode(e.ctx, a, node.GetId()); err != nil {
		e.fatalf("%v", err)
	}
	if n.GetMgmtMode() != "port" || n.GetMgmtSni() != "" || n.GetMgmtPublicPort() != 0 {
		e.fatalf("after the switch back the node has mode %q, SNI %q, public port %d", n.GetMgmtMode(), n.GetMgmtSni(), n.GetMgmtPublicPort())
	}
	if err := dialOnce(e.ctx, plain); err != nil {
		e.fatalf("the plain management port %s after the switch back: %v", plain, err)
	}
	desired = e.change(a, node.GetId(), "UpdateListener", func(ctx context.Context) error {
		_, err := a.listeners.UpdateListener(ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: listenerID, StrangerAction: ptr("mask")}))
		return err
	})
	e.waitNodeApplied(a, node.GetId(), desired, 2*time.Minute)
	e.logf("port: the plain port %s answers again, and the panel reaches the node there", plain)
}

// switchMgmt calls SetNodeMgmtMode and fails the test with the reason when
// the switch did not work.
func (e *env) switchMgmt(a *api, nodeID, mode, sni string, port uint32) {
	e.t.Helper()
	started := time.Now()
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	r, err := a.nodes.SetNodeMgmtMode(ctx, connect.NewRequest(&panelv1.SetNodeMgmtModeRequest{
		NodeId: nodeID, Mode: mode, MgmtSni: sni, PublicPort: port,
	}))
	if err != nil {
		e.fatalf("SetNodeMgmtMode(%s): %v", mode, err)
	}
	if !r.Msg.GetOk() {
		e.fatalf("SetNodeMgmtMode(%s) failed its check: %s", mode, r.Msg.GetReason())
	}
	e.logf("the panel switched the management of the node to %s in %.1fs", mode, time.Since(started).Seconds())
}

// waitNodeApplied waits until the node is online and reports the desired
// generation as applied.
func (e *env) waitNodeApplied(a *api, nodeID string, desired uint64, timeout time.Duration) {
	e.t.Helper()
	e.waitFor(fmt.Sprintf("generation %d applied", desired), timeout, time.Second, func(ctx context.Context) (bool, string, error) {
		n, err := e.getNode(ctx, a, nodeID)
		if err != nil {
			return false, "", err
		}
		status := fmt.Sprintf("%s, applied %d of %d", n.GetStatus(), n.GetAppliedGeneration(), n.GetDesiredGeneration())
		if n.GetLastError() != "" {
			status += ": " + n.GetLastError()
		}
		return n.GetStatus() == "online" && n.GetAppliedGeneration() >= desired, status, nil
	})
}

// strangerRefused makes a TLS connection to addr with the SNI and no client
// certificate, and fails the test unless the agent refuses it at the
// handshake. In TLS 1.3 the client may finish its side of the handshake
// before the server has looked at the (missing) certificate: the refusal is
// then the alert that the first read gets. It says how it was refused.
func (e *env) strangerRefused(addr, sni string) string {
	e.t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true, // a stranger that does not know the CA of the panel
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "the handshake failed: " + err.Error()
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	switch {
	case err == nil:
		e.fatalf("a TLS client with SNI %s and no client certificate got data from %s", sni, addr)
	case errors.Is(err, os.ErrDeadlineExceeded):
		e.fatalf("a TLS client with SNI %s and no client certificate was neither refused nor answered by %s in 10 s", sni, addr)
	}
	return "the server ended the handshake: " + err.Error()
}

// dialOnce makes a TCP connection to addr and closes it.
func dialOnce(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}
