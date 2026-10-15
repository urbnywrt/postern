package proxies

import (
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// WriteMgmt stores the management settings, raises the generation and the
// state carries them; it refuses a port that is no tls listener of the node and
// a management SNI that is a domain of a proxy there, and then writes nothing.
func TestWriteMgmt(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	gen := e.generation(n.ID)

	refused := []struct {
		sni  string
		port uint32
		want string
	}{
		{"mgmt.example.net", 8443, "not a public tls listener"},
		{strings.ToUpper(p.GetDomain()), 443, p.GetDomain()},
	}
	for _, c := range refused {
		err := e.svc.WriteMgmt(e.ctx, n.ID, store.MgmtModeHidden, c.sni, c.port)
		if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(strings.ToLower(err.Error()), c.want) {
			t.Errorf("WriteMgmt(%q, %d) = %v, want failed_precondition naming %q", c.sni, c.port, err, c.want)
		}
	}
	if got := e.node(n.ID); got.MgmtSNI != "" || got.MgmtPublicPort != 0 || got.DesiredGeneration != gen {
		t.Fatalf("refused writes left sni %q, port %d, generation %d (was %d)", got.MgmtSNI, got.MgmtPublicPort, got.DesiredGeneration, gen)
	}

	if err := e.svc.WriteMgmt(e.ctx, n.ID, store.MgmtModeHidden, "mgmt.example.net", 443); err != nil {
		t.Fatalf("WriteMgmt: %v", err)
	}
	got := e.node(n.ID)
	if got.MgmtMode != store.MgmtModeHidden || got.MgmtSNI != "mgmt.example.net" || got.MgmtPublicPort != 443 || got.DesiredGeneration <= gen {
		t.Fatalf("after WriteMgmt: mode %q sni %q port %d generation %d", got.MgmtMode, got.MgmtSNI, got.MgmtPublicPort, got.DesiredGeneration)
	}
	st := e.build(n.ID).GetSettings()
	if st.GetMgmtSni() != "mgmt.example.net" || !st.GetMgmtHiddenOnly() {
		t.Errorf("state settings: sni %q hidden_only %v", st.GetMgmtSni(), st.GetMgmtHiddenOnly())
	}

	gen = got.DesiredGeneration
	if err := e.svc.WriteMgmt(e.ctx, n.ID, store.MgmtModeHidden, "mgmt.example.net", 443); err != nil {
		t.Fatalf("WriteMgmt again: %v", err)
	}
	if g := e.generation(n.ID); g != gen {
		t.Errorf("an unchanged write raised the generation to %d from %d", g, gen)
	}
	if err := e.svc.WriteMgmt(e.ctx, n.ID, "other", "", 0); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("WriteMgmt(mode other) = %v, want invalid_argument", err)
	}
}

// The tls listener that carries the hidden management of a node is neither
// deleted nor moved to another port or address; its other settings change, and
// another listener of the node goes as ever.
func TestHiddenManagementListenerStays(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	other := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443})
	if err := e.svc.WriteMgmt(e.ctx, n.ID, store.MgmtModeHidden, "mgmt.example.net", 443); err != nil {
		t.Fatalf("WriteMgmt: %v", err)
	}

	_, err := e.listeners.DeleteListener(e.ctx, connect.NewRequest(&panelv1.DeleteListenerRequest{Id: l.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "hidden management") {
		t.Errorf("DeleteListener: %v, want it to name the hidden management", err)
	}
	for _, req := range []*panelv1.UpdateListenerRequest{
		{Id: l.GetId(), Port: proto.Uint32(9443)},
		{Id: l.GetId(), BindIp: proto.String("198.51.100.7")},
	} {
		_, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(req))
		wantCode(t, err, connect.CodeFailedPrecondition)
	}
	if _, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: l.GetId(), StrangerAction: proto.String("reject")})); err != nil {
		t.Errorf("UpdateListener(stranger_action): %v", err)
	}
	if _, err := e.listeners.DeleteListener(e.ctx, connect.NewRequest(&panelv1.DeleteListenerRequest{Id: other.GetId()})); err != nil {
		t.Errorf("DeleteListener(another listener): %v", err)
	}

	if err := e.svc.WriteMgmt(e.ctx, n.ID, store.MgmtModePort, "", 0); err != nil {
		t.Fatalf("WriteMgmt(port): %v", err)
	}
	if _, err := e.listeners.DeleteListener(e.ctx, connect.NewRequest(&panelv1.DeleteListenerRequest{Id: l.GetId()})); err != nil {
		t.Errorf("DeleteListener after the switch back: %v", err)
	}
}
