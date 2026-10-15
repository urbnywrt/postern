package nodes

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// fakeHidden is the hidden management of a fake node: a public port that
// takes the management SNI while the node has one, as the edge routes it, and
// a plain port that closes while the state says mgmt_hidden_only. The fields
// are under the lock of the node.
type fakeHidden struct {
	ln          net.Listener
	sni         string // the management SNI of the last state; "" for none
	plainClosed bool   // the last state said mgmt_hidden_only
	publicDown  bool   // the public port closes every connection (a broken route)
	plainDown   bool   // the plain port stays closed (an agent that cannot open it)
	publicDials int
}

func (h *fakeHidden) take(s *nodev1.NodeSettings) {
	h.sni = s.GetMgmtSni()
	h.plainClosed = s.GetMgmtHiddenOnly() || h.plainDown
}

// publicConn is a connection that came in through the public port.
type publicConn struct{ *trackedConn }

// enableHidden gives the node hidden management, before it serves: its
// states are applied at once, and their settings followed.
func (f *fakeNode) enableHidden() uint32 {
	f.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatalf("listen: %v", err)
	}
	f.hidden = &fakeHidden{ln: ln}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			c := publicConn{&trackedConn{Conn: raw, f: f}}
			f.mu.Lock()
			f.hidden.publicDials++
			open := f.up && f.serving && f.hidden.sni != "" && !f.hidden.publicDown
			if open {
				f.conns[c.trackedConn] = struct{}{}
			}
			f.mu.Unlock()
			if !open {
				_ = raw.Close()
				continue
			}
			select {
			case f.inner.conns <- c:
			case <-f.inner.done:
				_ = c.Close()
				return
			}
		}
	}()
	f.t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return uint32(ln.Addr().(*net.TCPAddr).Port)
}

// checkSNI refuses a handshake through the public port with another SNI than
// the management SNI, as the edge would route it elsewhere.
func (f *fakeNode) checkSNI(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if _, ok := hello.Conn.(publicConn); !ok {
		return nil, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if hello.ServerName != f.hidden.sni {
		return nil, errors.New("no route for this SNI")
	}
	return nil, nil
}

func (f *fakeNode) hiddenState() fakeHidden {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.hidden
}

func (f *fakeNode) setHidden(fn func(h *fakeHidden)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.hidden)
}

// mgmtBuilder builds states with the management settings of the stored node.
type mgmtBuilder struct{ db *store.DB }

func (b mgmtBuilder) Build(ctx context.Context, nodeID string, generation uint64) (*nodev1.NodeState, error) {
	n, err := b.db.NodeByID(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	return &nodev1.NodeState{Generation: generation, Settings: &nodev1.NodeSettings{
		MgmtSni:        n.MgmtSNI,
		MgmtHiddenOnly: n.MgmtMode == store.MgmtModeHidden,
	}}, nil
}

// fakeWriter is the MgmtWriter of proxies.Service, without the state checks:
// it refuses the SNI refuse.
type fakeWriter struct {
	db     *store.DB
	m      *Manager
	refuse string
}

func (w *fakeWriter) WriteMgmt(ctx context.Context, nodeID, mode, sni string, publicPort uint32) error {
	if sni != "" && sni == w.refuse {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("mgmt_sni "+sni+" is the domain of a proxy"))
	}
	if _, err := w.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
		n.MgmtMode, n.MgmtSNI, n.MgmtPublicPort = mode, sni, publicPort
		return nil
	}); err != nil {
		return err
	}
	if _, err := w.db.NextNodeGeneration(ctx, nodeID); err != nil {
		return err
	}
	w.m.Notify(nodeID)
	return nil
}

// hiddenSetup is a manager connected to a fake node with hidden management,
// and a tls listener of the node on its public port.
type hiddenSetup struct {
	p      *testPanel
	m      *Manager
	f      *fakeNode
	n      *store.Node
	public uint32
	writer *fakeWriter
}

func newHiddenSetup(t *testing.T, tune ...func(*timing)) *hiddenSetup {
	t.Helper()
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	public := f.enableHidden()
	n := p.addNode("n1", f)
	if err := p.db.CreateListener(context.Background(), &store.Listener{NodeID: n.ID, Port: public}); err != nil {
		t.Fatal(err)
	}
	m := p.newManager()
	for _, f := range tune {
		f(&m.cfg)
	}
	m.SetStateBuilder(mgmtBuilder{db: p.db})
	w := &fakeWriter{db: p.db, m: m}
	m.SetMgmtWriter(w)
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)
	return &hiddenSetup{p: p, m: m, f: f, n: n, public: public, writer: w}
}

func (s *hiddenSetup) switchTo(mode, sni string, port uint32) string {
	s.p.t.Helper()
	reason, err := s.m.SetMgmtMode(context.Background(), s.n.ID, mode, sni, port)
	if err != nil {
		s.p.t.Fatalf("SetMgmtMode(%s): %v", mode, err)
	}
	return reason
}

func (s *hiddenSetup) wantStored(mode, sni string, port uint32) {
	s.p.t.Helper()
	n := s.p.node(s.n.ID)
	if n.MgmtMode != mode || n.MgmtSNI != sni || n.MgmtPublicPort != port {
		s.p.t.Errorf("stored mode %q sni %q port %d, want %q %q %d", n.MgmtMode, n.MgmtSNI, n.MgmtPublicPort, mode, sni, port)
	}
}

// The manager answers through the client of its connection.
func (s *hiddenSetup) waitManagerAnswers() {
	s.p.t.Helper()
	waitFor(s.p.t, "the manager connected", func() bool {
		c, err := s.m.Client(s.n.ID)
		if err != nil {
			return false
		}
		_, err = c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
		return err == nil
	})
}

// A switch to hidden checks the public port with the SNI before it stores the
// mode, and the manager then reaches the node there while the plain port is
// closed; the switch back opens the plain port, checks it, and drops the SNI.
func TestSwitchMgmtToHiddenAndBack(t *testing.T) {
	s := newHiddenSetup(t)
	const sni = "mgmt.example.net"

	if reason := s.switchTo(store.MgmtModeHidden, sni, s.public); reason != "" {
		t.Fatalf("switch to hidden: %s", reason)
	}
	s.wantStored(store.MgmtModeHidden, sni, s.public)
	waitFor(t, "the plain port closed", func() bool { return s.f.hiddenState().plainClosed })
	dials := s.f.hiddenState().publicDials
	s.f.closeConns() // the manager reconnects, and only the public port is open
	s.waitManagerAnswers()
	if s.f.hiddenState().publicDials <= dials {
		t.Error("the manager did not reconnect through the public port")
	}
	if reason := s.switchTo(store.MgmtModeHidden, sni, s.public); reason != "" {
		t.Errorf("the same switch again: %s", reason)
	}

	if reason := s.switchTo(store.MgmtModePort, "", 0); reason != "" {
		t.Fatalf("switch to port: %s", reason)
	}
	s.wantStored(store.MgmtModePort, "", 0)
	waitFor(t, "the hidden route gone", func() bool { h := s.f.hiddenState(); return !h.plainClosed && h.sni == "" })
	s.f.closeConns()
	s.waitManagerAnswers()
}

// A check that fails leaves the mode as it was, and says why: the public port
// that does not carry the SNI, and the plain port that stays closed.
func TestSwitchMgmtFailedCheckKeepsTheMode(t *testing.T) {
	s := newHiddenSetup(t)
	const sni = "mgmt.example.net"

	s.f.setHidden(func(h *fakeHidden) { h.publicDown = true })
	reason := s.switchTo(store.MgmtModeHidden, sni, s.public)
	if !strings.Contains(reason, "did not answer through port") {
		t.Errorf("reason = %q, want the failed check", reason)
	}
	s.wantStored(store.MgmtModePort, "", 0)
	waitFor(t, "the SNI taken back", func() bool { return s.f.hiddenState().sni == "" })

	s.f.setHidden(func(h *fakeHidden) { h.publicDown = false })
	if reason := s.switchTo(store.MgmtModeHidden, sni, s.public); reason != "" {
		t.Fatalf("switch to hidden: %s", reason)
	}
	s.f.setHidden(func(h *fakeHidden) { h.plainDown = true })
	reason = s.switchTo(store.MgmtModePort, "", 0)
	if !strings.Contains(reason, "did not answer on its management port") {
		t.Errorf("reason = %q, want the failed check", reason)
	}
	s.wantStored(store.MgmtModeHidden, sni, s.public)
	s.waitManagerAnswers()
}

// What the panel can tell without the node is refused before anything is
// stored: a port that is no tls listener of the node, an SNI that the writer
// refuses, and a second switch of the node while one runs.
func TestSwitchMgmtRefusals(t *testing.T) {
	s := newHiddenSetup(t)
	gen := s.p.node(s.n.ID).DesiredGeneration

	if reason := s.switchTo(store.MgmtModeHidden, "mgmt.example.net", s.public+1); !strings.Contains(reason, "not a public tls listener") {
		t.Errorf("reason = %q, want the port refused", reason)
	}
	s.writer.refuse = "cdn.example.com"
	if reason := s.switchTo(store.MgmtModeHidden, "cdn.example.com", s.public); !strings.Contains(reason, "domain of a proxy") {
		t.Errorf("reason = %q, want the writer's refusal", reason)
	}
	if !s.m.lockSwitch(s.n.ID) {
		t.Fatal("lockSwitch of an idle node")
	}
	if reason := s.switchTo(store.MgmtModePort, "", 0); !strings.Contains(reason, "running already") {
		t.Errorf("reason = %q, want a running switch", reason)
	}
	s.m.unlockSwitch(s.n.ID)
	s.wantStored(store.MgmtModePort, "", 0)
	if g := s.p.node(s.n.ID).DesiredGeneration; g != gen {
		t.Errorf("refused switches raised the generation to %d from %d", g, gen)
	}
}

// fakeSwitcher is a MgmtSwitcher that notes what it was asked.
type fakeSwitcher struct {
	reason string
	asked  []string
}

func (f *fakeSwitcher) SetMgmtMode(_ context.Context, nodeID, mode, sni string, port uint32) (string, error) {
	f.asked = append(f.asked, strings.Join([]string{nodeID, mode, sni}, " "))
	return f.reason, nil
}

// SetNodeMgmtMode checks the request, hands it to the switcher, answers with
// its reason, and audits it.
func TestSetNodeMgmtModeService(t *testing.T) {
	sw := &fakeSwitcher{}
	a := newAPI(t, WithMgmtSwitcher(sw))
	n := a.create(&panelv1.CreateNodeRequest{Name: "n1", MgmtHost: "198.51.100.1"}).GetNode()
	ctx := context.Background()
	call := func(req *panelv1.SetNodeMgmtModeRequest) (*panelv1.SetNodeMgmtModeResponse, error) {
		resp, err := a.nodes.SetNodeMgmtMode(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	for _, req := range []*panelv1.SetNodeMgmtModeRequest{
		{NodeId: n.GetId(), Mode: "other"},
		{NodeId: n.GetId(), Mode: "hidden", PublicPort: 443},
		{NodeId: n.GetId(), Mode: "hidden", MgmtSni: "198.51.100.7", PublicPort: 443},
		{NodeId: n.GetId(), Mode: "hidden", MgmtSni: "mgmt.example.net"},
	} {
		_, err := call(req)
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	_, err := call(&panelv1.SetNodeMgmtModeRequest{NodeId: "nope", Mode: "port"})
	wantCode(t, err, connect.CodeNotFound)
	_, err = a.anon.SetNodeMgmtMode(ctx, connect.NewRequest(&panelv1.SetNodeMgmtModeRequest{NodeId: n.GetId(), Mode: "port"}))
	wantCode(t, err, connect.CodeUnauthenticated)

	resp, err := call(&panelv1.SetNodeMgmtModeRequest{NodeId: n.GetId(), Mode: "hidden", MgmtSni: " Mgmt.Example.NET. ", PublicPort: 443})
	if err != nil || !resp.GetOk() || resp.GetNode().GetId() != n.GetId() {
		t.Fatalf("SetNodeMgmtMode = %v, %v", resp, err)
	}
	sw.reason = "the agent did not answer"
	resp, err = call(&panelv1.SetNodeMgmtModeRequest{NodeId: n.GetId(), Mode: "port"})
	if err != nil || resp.GetOk() || resp.GetReason() != sw.reason {
		t.Fatalf("SetNodeMgmtMode = %v, %v; want the reason", resp, err)
	}
	if want := []string{n.GetId() + " hidden mgmt.example.net", n.GetId() + " port "}; strings.Join(sw.asked, "|") != strings.Join(want, "|") {
		t.Errorf("asked %q, want %q", sw.asked, want)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(a.dbPath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT target, details FROM audit_log WHERE action = 'node.mgmt_mode' ORDER BY ts, rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var target, details string
		if err := rows.Scan(&target, &details); err != nil {
			t.Fatal(err)
		}
		got = append(got, target+" "+details)
	}
	if len(got) != 2 || !strings.Contains(got[0], `"ok":"true"`) || !strings.Contains(got[1], `"reason":"the agent did not answer"`) {
		t.Errorf("audit = %q", got)
	}
}

// When the public port of a node in hidden management stops answering, the
// manager tries the plain port after a few failures, and once the agent has
// opened it (its own fallback) reaches the node there, with a warning; when the
// hidden path answers again, it goes back to it.
func TestHiddenPathDownFallsBackToThePlainPort(t *testing.T) {
	s := newHiddenSetup(t, func(c *timing) { c.resyncEvery = 20 * time.Millisecond })
	const sni = "mgmt.example.net"
	if reason := s.switchTo(store.MgmtModeHidden, sni, s.public); reason != "" {
		t.Fatalf("switch to hidden: %s", reason)
	}
	waitFor(t, "the plain port closed", func() bool { return s.f.hiddenState().plainClosed })

	// The route is gone, and the agent has opened its plain port again.
	s.f.setHidden(func(h *fakeHidden) { h.publicDown, h.plainClosed = true, false })
	s.f.closeConns()
	waitFor(t, "the fallback warning", func() bool { return slices.Contains(s.p.eventKinds(s.n.ID), "node.mgmt_fallback") })
	s.waitManagerAnswers()
	s.wantStored(store.MgmtModeHidden, sni, s.public)

	// The route is back: the manager leaves the plain port.
	s.f.setHidden(func(h *fakeHidden) { h.publicDown = false })
	waitFor(t, "the manager back on the hidden path", func() bool {
		return strings.Contains(s.p.logs.String(), "the hidden management path answers again")
	})
	s.f.setHidden(func(h *fakeHidden) { h.plainClosed = true })
	s.f.closeConns()
	s.waitManagerAnswers()
}
