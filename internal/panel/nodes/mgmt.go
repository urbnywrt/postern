package nodes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// This file switches the management of a node between mode port and mode
// hidden (spec §5.3, Ruling S4-7).
//
// Where the manager connects follows the stored public port, not the mode
// (targetOf): a node with a public port and a management SNI is reached
// through the edge, mgmt_host:mgmt_public_port with that SNI, and any other on
// mgmt_host:mgmt_port. A switch stores the mode and the public port in an order
// that keeps the manager on a path that is open while the node takes each
// state:
//
//   - to hidden: the SNI alone (the node opens the hidden listener and its
//     route; the manager stays on the plain port), a check through the public
//     port, then the mode and the public port together (the manager moves to
//     the public port; the node closes the plain one);
//   - to port: the mode alone (the node opens the plain port again; the
//     manager stays on the public port), a check on the plain port, then the
//     SNI and the public port cleared (the manager moves to the plain port; the
//     node drops the hidden listener).
//
// A check that fails puts back what was stored before the call.

// MgmtWriter stores the management settings of a node: its mode, its
// management SNI and its public port, checked against the rest of its state
// as the node would check it. It raises the desired generation of the node
// and notifies the manager when the state of the node changes. Errors are
// Connect errors whose message says why. proxies.Service is the one.
type MgmtWriter interface {
	WriteMgmt(ctx context.Context, nodeID, mode, sni string, publicPort uint32) error
}

// SetMgmtWriter sets what stores the management settings. Without one,
// SetMgmtMode refuses.
func (m *Manager) SetMgmtWriter(w MgmtWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mgmtWriter = w
}

func (m *Manager) getMgmtWriter() MgmtWriter {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mgmtWriter
}

// errSwitchRunning is a switch of a node while another one of it runs.
var errSwitchRunning = errors.New("a switch of the management of this node is running already")

// mgmtSettings are the three stored management settings of a node.
type mgmtSettings struct {
	mode, sni string
	port      uint32
}

func mgmtOf(n *store.Node) mgmtSettings {
	return mgmtSettings{mode: n.MgmtMode, sni: n.MgmtSNI, port: n.MgmtPublicPort}
}

// SetMgmtMode switches the management of a node to mode (store.MgmtModePort or
// store.MgmtModeHidden; sni and publicPort are for hidden), with a live check of
// the new path. It returns why the node is not in that mode afterwards, "" when
// it is; the stored mode is then what it was before. err is for what is not
// about the node: an unknown node, no writer, or a fault of the panel.
//
// It runs synchronously, one switch of a node at a time, and gives up after
// a minute. It does not stop when ctx is canceled: a switch half done is put
// back first.
func (m *Manager) SetMgmtMode(ctx context.Context, nodeID, mode, sni string, publicPort uint32) (string, error) {
	w := m.getMgmtWriter()
	if w == nil {
		return "", errors.New("nodes: the panel has no writer of management settings")
	}
	if !m.lockSwitch(nodeID) {
		return errSwitchRunning.Error(), nil
	}
	defer m.unlockSwitch(nodeID)

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.cfg.switchTimeout)
	defer cancel()
	n, err := m.db.NodeByID(ctx, nodeID)
	if err != nil {
		return "", err
	}
	s := &mgmtSwitch{m: m, w: w, n: n, before: mgmtOf(n)}
	switch mode {
	case store.MgmtModeHidden:
		return s.toHidden(ctx, sni, publicPort)
	case store.MgmtModePort:
		return s.toPort(ctx)
	}
	return "", fmt.Errorf("nodes: unknown management mode %q", mode)
}

func (m *Manager) lockSwitch(nodeID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.switching[nodeID] {
		return false
	}
	if m.switching == nil {
		m.switching = map[string]bool{}
	}
	m.switching[nodeID] = true
	return true
}

func (m *Manager) unlockSwitch(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.switching, nodeID)
}

// mgmtSwitch is one switch of a node.
type mgmtSwitch struct {
	m      *Manager
	w      MgmtWriter
	n      *store.Node
	before mgmtSettings
}

func (s *mgmtSwitch) toHidden(ctx context.Context, sni string, publicPort uint32) (string, error) {
	b := s.before
	if b.mode == store.MgmtModeHidden {
		if b.sni == sni && b.port == publicPort {
			return "", nil
		}
		return "the node is in mode hidden already: switch it to port first to take another SNI or port", nil
	}
	if reason, err := s.checkListener(ctx, publicPort); reason != "" || err != nil {
		return reason, err
	}
	// The SNI alone: the node opens the hidden listener and routes the SNI to
	// it, while the manager stays on the plain port.
	if reason, err := s.write(ctx, mgmtSettings{mode: store.MgmtModePort, sni: sni}); reason != "" || err != nil {
		return reason, err
	}
	if reason, err := s.waitApplied(ctx); reason != "" || err != nil {
		return s.restore(reason, err)
	}
	addr := net.JoinHostPort(s.n.MgmtHost, strconv.FormatUint(uint64(publicPort), 10))
	if reason := s.check(ctx, addr, sni); reason != "" {
		return s.restore("the agent did not answer through port "+strconv.FormatUint(uint64(publicPort), 10)+" with SNI "+sni+": "+reason, nil)
	}
	// The manager moves to the public port, and the node closes the plain one.
	if reason, err := s.write(ctx, mgmtSettings{mode: store.MgmtModeHidden, sni: sni, port: publicPort}); reason != "" || err != nil {
		return s.restore(reason, err)
	}
	return "", nil
}

func (s *mgmtSwitch) toPort(ctx context.Context) (string, error) {
	b := s.before
	if b.mode != store.MgmtModeHidden {
		if b.sni != "" || b.port != 0 {
			// What a switch to hidden that the panel did not finish left.
			return s.write(ctx, mgmtSettings{mode: store.MgmtModePort})
		}
		return "", nil
	}
	// The mode alone: the node opens the plain port again, and the manager
	// stays on the public port.
	if reason, err := s.write(ctx, mgmtSettings{mode: store.MgmtModePort, sni: b.sni, port: b.port}); reason != "" || err != nil {
		return reason, err
	}
	if reason, err := s.waitApplied(ctx); reason != "" || err != nil {
		return s.restore(reason, err)
	}
	if reason := s.check(ctx, net.JoinHostPort(s.n.MgmtHost, strconv.FormatUint(uint64(s.n.MgmtPort), 10)), nodeDNSName(s.n.ID)); reason != "" {
		return s.restore("the agent did not answer on its management port "+strconv.FormatUint(uint64(s.n.MgmtPort), 10)+": "+reason, nil)
	}
	// The manager moves to the plain port, and the node drops the hidden
	// listener.
	if reason, err := s.write(ctx, mgmtSettings{mode: store.MgmtModePort}); reason != "" || err != nil {
		return s.restore(reason, err)
	}
	return "", nil
}

// checkListener says why publicPort cannot carry the management of the node:
// it is not the port of one of its tls listeners. The writer checks it again
// when it stores the port.
func (s *mgmtSwitch) checkListener(ctx context.Context, publicPort uint32) (string, error) {
	ls, err := s.m.db.ListListeners(ctx, s.n.ID)
	if err != nil {
		return "", err
	}
	for _, l := range ls {
		if l.Kind == store.ListenerKindTLS && l.Port == publicPort {
			return "", nil
		}
	}
	return fmt.Sprintf("port %d is not a public tls listener of the node", publicPort), nil
}

// write stores settings through the writer. A refusal of the writer is a
// reason; anything else is an error.
func (s *mgmtSwitch) write(ctx context.Context, ms mgmtSettings) (string, error) {
	err := s.w.WriteMgmt(ctx, s.n.ID, ms.mode, ms.sni, ms.port)
	var ce *connect.Error
	switch {
	case err == nil:
		return "", nil
	case errors.As(err, &ce) && ce.Code() == connect.CodeNotFound:
		return "", store.ErrNotFound
	case errors.As(err, &ce) && ce.Code() != connect.CodeInternal && ce.Code() != connect.CodeUnknown:
		return ce.Message(), nil
	}
	return "", err
}

// restore puts back the settings from before the switch, after a check that
// failed (reason) or an error, and returns the two. It has a time of its own:
// the switch may have run out of its own.
func (s *mgmtSwitch) restore(reason string, err error) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.m.cfg.callTimeout)
	defer cancel()
	if why, werr := s.write(ctx, s.before); why != "" || werr != nil {
		s.m.log.Error("could not put back the management settings of a node after a failed switch",
			"node", s.n.ID, "refused", why, "err", werr)
	}
	return reason, err
}

// waitApplied waits until the node reports the desired generation of the
// panel as applied, and says why not when it does not in time.
func (s *mgmtSwitch) waitApplied(ctx context.Context) (string, error) {
	n, err := s.m.db.NodeByID(ctx, s.n.ID)
	if err != nil {
		return "", err
	}
	want := n.DesiredGeneration
	tick := time.NewTicker(s.m.cfg.switchPoll)
	defer tick.Stop()
	for n.AppliedGeneration < want {
		select {
		case <-ctx.Done():
			reason := fmt.Sprintf("the node did not apply generation %d in time (it has %d)", want, n.AppliedGeneration)
			if why := lastError(n); why != "" {
				reason += ": " + why
			}
			return reason, nil
		case <-tick.C:
		}
		next, err := s.m.db.NodeByID(ctx, s.n.ID)
		switch {
		case err == nil:
			n = next
		case ctx.Err() == nil:
			return "", err
		}
	}
	return "", nil
}

// check connects to the agent at addr with the TLS SNI sni, as the manager
// connects (the CA and the pinned certificate, no host name), and calls
// GetInfo. It returns why that failed, "" when it worked.
func (s *mgmtSwitch) check(ctx context.Context, addr, sni string) string {
	t, err := targetOf(s.n)
	if err != nil {
		return err.Error()
	}
	t.addr, t.serverName = addr, sni
	if err := s.m.probe(ctx, t); err != nil {
		return err.Error()
	}
	return ""
}

// MgmtSwitcher switches the management mode of a node, as
// [Manager.SetMgmtMode] does.
type MgmtSwitcher interface {
	SetMgmtMode(ctx context.Context, nodeID, mode, sni string, publicPort uint32) (string, error)
}

// WithMgmtSwitcher gives the service what switches the management mode of a
// node: the Manager. Without it SetNodeMgmtMode is unimplemented.
func WithMgmtSwitcher(m MgmtSwitcher) Option {
	return func(s *Service) { s.switcher = m }
}

// SetNodeMgmtMode switches the management of a node between mode port and
// mode hidden, with a live check of the new path (see [Manager.SetMgmtMode]).
// Every call that gets that far is audited as node.mgmt_mode, with the mode,
// whether it worked and why not.
func (s *Service) SetNodeMgmtMode(ctx context.Context, req *connect.Request[panelv1.SetNodeMgmtModeRequest]) (*connect.Response[panelv1.SetNodeMgmtModeResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.switcher == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("this panel cannot switch the management of nodes"))
	}
	msg := req.Msg
	mode, sni, port := msg.GetMode(), "", uint32(0)
	switch mode {
	case store.MgmtModePort:
	case store.MgmtModeHidden:
		sni = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(msg.GetMgmtSni()), "."))
		if _, err := netip.ParseAddr(sni); err == nil || !validHost(sni) {
			return nil, invalid("mgmt_sni must be a host name")
		}
		if port = msg.GetPublicPort(); port < 1 || port > 65535 {
			return nil, invalid("public_port must be 1 to 65535")
		}
	default:
		return nil, invalid("mode must be %s or %s", store.MgmtModePort, store.MgmtModeHidden)
	}
	if _, err := s.db.NodeByID(ctx, msg.GetNodeId()); err != nil {
		return nil, s.storeError("could not read a node", err)
	}

	reason, err := s.switcher.SetMgmtMode(ctx, msg.GetNodeId(), mode, sni, port)
	if err != nil {
		return nil, s.storeError("could not switch the management of a node", err)
	}
	details := map[string]string{"mode": mode, "ok": strconv.FormatBool(reason == "")}
	if mode == store.MgmtModeHidden {
		details["mgmt_sni"], details["public_port"] = sni, strconv.FormatUint(uint64(port), 10)
	}
	if reason != "" {
		details["reason"] = reason
		s.log.Warn("a switch of the management of a node failed", "node", msg.GetNodeId(), "mode", mode, "reason", reason)
	}
	s.auditDetails(ctx, admin.ID, "node.mgmt_mode", msg.GetNodeId(), details)

	n, err := s.db.NodeByID(ctx, msg.GetNodeId())
	if err != nil {
		return nil, s.storeError("could not read a node", err)
	}
	return connect.NewResponse(&panelv1.SetNodeMgmtModeResponse{Ok: reason == "", Reason: reason, Node: s.proto(ctx, n)}), nil
}

// hiddenFailLimit is how many connections in a row through the public port of
// a node in hidden management may fail before the manager also tries its plain
// management port, which the agent opens again when the panel has not reached
// it through the hidden path for 15 minutes.
const hiddenFailLimit = 3

// probe connects to the agent at t, as the manager connects, calls GetInfo
// and closes the connection.
func (m *Manager) probe(ctx context.Context, t target) error {
	client, closeAll, err := m.newClient(ctx, t)
	if err != nil {
		return err
	}
	defer closeAll()
	ctx, cancel := context.WithTimeout(ctx, m.cfg.callTimeout)
	defer cancel()
	_, err = client.GetInfo(ctx, connect.NewRequest(&nodev1.GetInfoRequest{}))
	return err
}

// plainTargetOf returns the plain management target of a node that t reaches
// through its public port (hidden is true then): the same host and pin, the
// management port, and the name in the certificate as the SNI.
func plainTargetOf(n *store.Node, t target) (plain target, hidden bool) {
	if n.MgmtPublicPort == 0 || n.MgmtSNI == "" {
		return target{}, false
	}
	return target{
		addr:       net.JoinHostPort(n.MgmtHost, strconv.FormatUint(uint64(n.MgmtPort), 10)),
		serverName: nodeDNSName(n.ID),
		pin:        t.pin,
	}, true
}

// hiddenFallback follows the connection of a runner through the public port
// (established, err). After hiddenFailLimit failures in a row it tries the
// plain port, once each time that the public port fails again; a session
// there records the node.mgmt_fallback warning, runs until the hidden path
// answers again (it looks at every resync), and is what the call returns.
// When the plain port does not answer either, what the public port did is
// returned.
func (r *runner) hiddenFallback(ctx context.Context, hidden, plain target, established bool, err error) (bool, error) {
	switch {
	case established:
		r.hiddenFails = 0
		return established, err
	case errors.Is(err, errReconnect), errors.Is(err, errNodeGone):
		return established, err
	}
	r.hiddenFails++
	if r.hiddenFails < hiddenFailLimit {
		return false, err
	}
	est, perr := r.connect(ctx, plain, &hidden)
	if est {
		return true, perr
	}
	r.log.Debug("the plain management port does not answer either", "err", perr)
	return false, err
}
