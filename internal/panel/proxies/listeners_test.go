package proxies

import (
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestServicesNeedAnAdmin(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	calls := map[string]func() error{
		"ListListeners": func() error {
			_, err := e.anonListeners.ListListeners(e.ctx, connect.NewRequest(&panelv1.ListListenersRequest{}))
			return err
		},
		"CreateListener": func() error {
			_, err := e.anonListeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443}))
			return err
		},
		"ListProxies": func() error {
			_, err := e.anonProxies.ListProxies(e.ctx, connect.NewRequest(&panelv1.ListProxiesRequest{}))
			return err
		},
		"GetProxyLinks": func() error {
			_, err := e.anonProxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: "x"}))
			return err
		},
		"ProxyLive": func() error {
			_, err := e.anonStats.ProxyLive(e.ctx, connect.NewRequest(&panelv1.ProxyLiveRequest{ProxyId: "x"}))
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { wantCode(t, call(), connect.CodeUnauthenticated) })
	}

	// The handlers check for themselves, whatever mounts them.
	if _, err := e.svc.ListListeners(e.ctx, connect.NewRequest(&panelv1.ListListenersRequest{})); err == nil {
		t.Error("ListListeners without the middleware: no error")
	} else {
		wantCode(t, err, connect.CodeUnauthenticated)
	}
	if got := e.generation(n.ID); got != 0 {
		t.Errorf("desired generation = %d after refused calls, want 0", got)
	}
}

func TestCreateListenerDefaults(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")

	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	want := &panelv1.Listener{
		Id:             l.GetId(),
		NodeId:         n.ID,
		Kind:           "tls",
		BindIp:         "0.0.0.0",
		Port:           443,
		StrangerAction: "mask",
		NonTlsAction:   "drop",
		CreatedUnix:    l.GetCreatedUnix(),
		UpdatedUnix:    l.GetUpdatedUnix(),
	}
	if !proto.Equal(l, want) {
		t.Errorf("listener = %v, want %v", l, want)
	}
	if l.GetCreatedUnix() == 0 {
		t.Error("created_unix is 0")
	}
	if got := e.generation(n.ID); got != 1 {
		t.Errorf("desired generation = %d, want 1", got)
	}
	if got := e.notes.got(); !slices.Equal(got, []string{n.ID}) {
		t.Errorf("notified %v, want [%s]", got, n.ID)
	}

	stored, err := e.db.ListenerByID(e.ctx, l.GetId())
	if err != nil {
		t.Fatalf("ListenerByID: %v", err)
	}
	if stored.BindIP != "0.0.0.0" || stored.Port != 443 || stored.Kind != "tls" {
		t.Errorf("stored listener = %+v", stored)
	}
}

func TestCreateListenerKeepsWhatItIsGiven(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{
		NodeId:           n.ID,
		Kind:             "tls",
		BindIp:           " 198.51.100.7 ",
		Port:             8443,
		LinkHostOverride: "Proxy.Example.COM",
		StrangerAction:   "reject",
		MaskTarget:       "[2001:db8::1]:8443",
		NonTlsAction:     "http400",
	})
	if l.GetBindIp() != "198.51.100.7" || l.GetPort() != 8443 || l.GetLinkHostOverride() != "Proxy.Example.COM" ||
		l.GetStrangerAction() != "reject" || l.GetMaskTarget() != "[2001:db8::1]:8443" || l.GetNonTlsAction() != "http400" {
		t.Errorf("listener = %v", l)
	}
}

func TestCreateListenerRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	tests := []struct {
		name string
		req  *panelv1.CreateListenerRequest
		code connect.Code
	}{
		{"port 0", &panelv1.CreateListenerRequest{NodeId: n.ID}, connect.CodeInvalidArgument},
		{"port above 65535", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 65536}, connect.CodeInvalidArgument},
		{"IPv6 bind address", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, BindIp: "2001:db8::1"}, connect.CodeInvalidArgument},
		{"IPv6 wildcard", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, BindIp: "::"}, connect.CodeInvalidArgument},
		{"IPv4-mapped IPv6", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, BindIp: "::ffff:198.51.100.7"}, connect.CodeInvalidArgument},
		{"bind address is a name", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, BindIp: "node.example.com"}, connect.CodeInvalidArgument},
		{"multicast bind address", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, BindIp: "224.0.0.1"}, connect.CodeInvalidArgument},
		{"link-local bind address", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, BindIp: "169.254.0.1"}, connect.CodeInvalidArgument},
		{"broadcast bind address", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, BindIp: "255.255.255.255"}, connect.CodeInvalidArgument},
		{"http-upstream", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 40001, Kind: "http-upstream"}, connect.CodeInvalidArgument},
		{"unknown kind", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, Kind: "udp"}, connect.CodeInvalidArgument},
		{"unknown stranger action", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, StrangerAction: "bounce"}, connect.CodeInvalidArgument},
		{"unknown non-TLS action", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, NonTlsAction: "http500"}, connect.CodeInvalidArgument},
		{"link host with a scheme", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, LinkHostOverride: "https://proxy.example.com"}, connect.CodeInvalidArgument},
		{"link host with a port", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, LinkHostOverride: "proxy.example.com:443"}, connect.CodeInvalidArgument},
		{"mask target with a space", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, MaskTarget: "mask .example.com"}, connect.CodeInvalidArgument},
		{"mask target with port 0", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, MaskTarget: "mask.example.com:0"}, connect.CodeInvalidArgument},
		{"mask target with a bad port", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, MaskTarget: "mask.example.com:https"}, connect.CodeInvalidArgument},
		{"internal port on 0.0.0.0", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 20000}, connect.CodeInvalidArgument},
		{"internal port on 0.0.0.0, middle", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 30000}, connect.CodeInvalidArgument},
		{"internal port on 127.0.0.1", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 40999, BindIp: "127.0.0.1"}, connect.CodeInvalidArgument},
		{"mask target on an internal port", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, MaskTarget: "127.0.0.1:35000"}, connect.CodeInvalidArgument},
		{"mask target on an internal port of localhost", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, MaskTarget: "LocalHost:25000"}, connect.CodeInvalidArgument},
		{"mask target on an internal port of 0.0.0.0", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, MaskTarget: "0.0.0.0:30000"}, connect.CodeInvalidArgument},
		{"mask target on an internal port of ::ffff:127.0.0.1", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, MaskTarget: "[::ffff:127.0.0.1]:20000"}, connect.CodeInvalidArgument},
		{"no node", &panelv1.CreateListenerRequest{Port: 443}, connect.CodeNotFound},
		{"unknown node", &panelv1.CreateListenerRequest{NodeId: "01K6Y00000000000000000000Z", Port: 443}, connect.CodeNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(tc.req))
			wantCode(t, err, tc.code)
		})
	}
	if got := e.generation(n.ID); got != 0 {
		t.Errorf("desired generation = %d after refused calls, want 0", got)
	}
	if got := e.notes.count(); got != 0 {
		t.Errorf("%d notifications after refused calls, want 0", got)
	}
}

func TestListenersOfANodeDoNotOverlap(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	other := e.addNode("n2", "203.0.113.20")

	e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443, BindIp: "198.51.100.7"})

	refused := []struct {
		name string
		req  *panelv1.CreateListenerRequest
	}{
		{"the same address", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443}},
		{"a specific address next to 0.0.0.0", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, BindIp: "198.51.100.8"}},
		{"0.0.0.0 next to a specific address", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443}},
		{"the same specific address", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443, BindIp: "198.51.100.7"}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(tc.req))
			wantCode(t, err, connect.CodeAlreadyExists)
		})
	}

	// What does fit.
	e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443, BindIp: "198.51.100.8"})
	e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443, BindIp: "127.0.0.1"})
	e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 9443})
	e.createListener(&panelv1.CreateListenerRequest{NodeId: other.ID, Port: 443})
	e.createListener(&panelv1.CreateListenerRequest{NodeId: other.ID, Port: 8443, BindIp: "198.51.100.7"})

	resp, err := e.listeners.ListListeners(e.ctx, connect.NewRequest(&panelv1.ListListenersRequest{NodeId: n.ID}))
	if err != nil {
		t.Fatalf("ListListeners: %v", err)
	}
	if got := len(resp.Msg.GetListeners()); got != 5 {
		t.Errorf("node 1 has %d listeners, want 5", got)
	}
	all, err := e.listeners.ListListeners(e.ctx, connect.NewRequest(&panelv1.ListListenersRequest{}))
	if err != nil {
		t.Fatalf("ListListeners: %v", err)
	}
	if got := len(all.Msg.GetListeners()); got != 7 {
		t.Errorf("there are %d listeners in all, want 7", got)
	}
	if got := e.generation(n.ID); got != 5 {
		t.Errorf("desired generation of node 1 = %d, want 5 (one per listener)", got)
	}
}

func TestUpdateListener(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	l1 := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	l2 := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443, BindIp: "198.51.100.7"})
	gen := e.generation(n.ID)

	resp, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{
		Id:               l1.GetId(),
		Port:             proto.Uint32(9443),
		LinkHostOverride: proto.String("edge.example.com"),
		StrangerAction:   proto.String("drop"),
	}))
	if err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	got := resp.Msg.GetListener()
	if got.GetPort() != 9443 || got.GetLinkHostOverride() != "edge.example.com" || got.GetStrangerAction() != "drop" ||
		got.GetBindIp() != "0.0.0.0" || got.GetNonTlsAction() != "drop" {
		t.Errorf("updated listener = %v", got)
	}
	if g := e.generation(n.ID); g != gen+1 {
		t.Errorf("desired generation = %d, want %d", g, gen+1)
	}

	// An empty value means what it means at creation: no override, mask.
	resp, err = e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{
		Id: l1.GetId(), LinkHostOverride: proto.String(""), StrangerAction: proto.String(""),
	}))
	if err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	if got := resp.Msg.GetListener(); got.GetLinkHostOverride() != "" || got.GetStrangerAction() != "mask" {
		t.Errorf("listener after resetting = %v", got)
	}

	// Moving onto the port of the other listener, next to its address.
	_, err = e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: l1.GetId(), Port: proto.Uint32(8443)}))
	wantCode(t, err, connect.CodeAlreadyExists)
	// A listener does not collide with itself.
	if _, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: l2.GetId(), Port: proto.Uint32(8443)})); err != nil {
		t.Errorf("UpdateListener to its own port: %v", err)
	}

	before := e.generation(n.ID)
	for _, tc := range []struct {
		name string
		req  *panelv1.UpdateListenerRequest
		code connect.Code
	}{
		{"bad port", &panelv1.UpdateListenerRequest{Id: l1.GetId(), Port: proto.Uint32(0)}, connect.CodeInvalidArgument},
		{"IPv6", &panelv1.UpdateListenerRequest{Id: l1.GetId(), BindIp: proto.String("2001:db8::2")}, connect.CodeInvalidArgument},
		{"bad action", &panelv1.UpdateListenerRequest{Id: l1.GetId(), NonTlsAction: proto.String("x")}, connect.CodeInvalidArgument},
		{"unknown listener", &panelv1.UpdateListenerRequest{Id: "01K6Y00000000000000000000Z", Port: proto.Uint32(1)}, connect.CodeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(tc.req))
			wantCode(t, err, tc.code)
		})
	}
	if g := e.generation(n.ID); g != before {
		t.Errorf("desired generation = %d after refused updates, want %d", g, before)
	}
}

// TestListenersStayOutOfTheInternalPorts: on 0.0.0.0 and 127.0.0.1 the ports
// 20000-40999 belong to the node itself (engines, SOCKS ports, test
// listeners), which refuses a listener there.
func TestListenersStayOutOfTheInternalPorts(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	for _, req := range []*panelv1.CreateListenerRequest{
		{NodeId: n.ID, Port: 19999, MaskTarget: "127.0.0.1:8443"}, // a decoy site on the node is fine
		{NodeId: n.ID, Port: 41000, MaskTarget: "localhost"},
		{NodeId: n.ID, Port: 30000, BindIp: "198.51.100.7", MaskTarget: "198.51.100.9:30000"},
		{NodeId: n.ID, Port: 30001, BindIp: "127.0.0.2"},
	} {
		e.createListener(req)
	}
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	_, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: l.GetId(), Port: proto.Uint32(25000)}))
	wantCode(t, err, connect.CodeInvalidArgument)
	s := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 35000, BindIp: "198.51.100.8"})
	_, err = e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: s.GetId(), BindIp: proto.String("127.0.0.1")}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// A listener on the management port of its node is refused: the agent listens
// there on every address, so the edge could not, and the node would fail to
// apply its state for good. Ports of other nodes are no concern. A node in
// hidden management keeps its plain port (the fallback and the switch back open
// it again), so it is refused there too.
func TestListenersStayOffTheManagementPort(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10") // management port 61000
	other := &store.Node{Name: "n2", MgmtHost: "198.51.100.2", MgmtPort: 62000, LinkHost: "203.0.113.20"}
	if err := e.db.CreateNode(e.ctx, other); err != nil {
		t.Fatal(err)
	}
	hidden := &store.Node{Name: "n3", MgmtHost: "198.51.100.3", MgmtPort: 443, MgmtMode: store.MgmtModeHidden, LinkHost: "203.0.113.30"}
	if err := e.db.CreateNode(e.ctx, hidden); err != nil {
		t.Fatal(err)
	}

	for _, req := range []*panelv1.CreateListenerRequest{
		{NodeId: n.ID, Port: 61000},
		{NodeId: n.ID, Port: 61000, BindIp: "198.51.100.7"},
		{NodeId: n.ID, Port: 61000, BindIp: "127.0.0.1"},
	} {
		_, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(req))
		wantCode(t, err, connect.CodeInvalidArgument)
		if !strings.Contains(err.Error(), "management port") {
			t.Errorf("CreateListener on %s:%d: %v, want it to name the management port", req.GetBindIp(), req.GetPort(), err)
		}
	}
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	gen := e.generation(n.ID)
	_, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: l.GetId(), Port: proto.Uint32(61000)}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if g := e.generation(n.ID); g != gen {
		t.Errorf("desired generation = %d after refused calls, want %d", g, gen)
	}

	e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 62000})
	e.createListener(&panelv1.CreateListenerRequest{NodeId: other.ID, Port: 61000})
	_, err = e.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{NodeId: hidden.ID, Port: 443}))
	wantCode(t, err, connect.CodeInvalidArgument)
	e.createListener(&panelv1.CreateListenerRequest{NodeId: hidden.ID, Port: 8443})
}

// The answer of a listener names the processes other than Postern that the node
// said hold its address. The listener is stored all the same: a proxy that moves
// to Postern from a server that still serves it needs that.
func TestListenerAnswersNameWhatHoldsItsPort(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	owners := []store.PortOwner{
		{Bind: "0.0.0.0", Port: 80, Owner: "nginx (pid 812)"},
		{Bind: "198.51.100.7", Port: 8443, Owner: "caddy (container web)"},
		{Bind: "::", Port: 9443, Owner: "unknown"},
		{Bind: "2001:db8::7", Port: 7443, Owner: "nginx (pid 812)"},
		{Bind: "::ffff:198.51.100.9", Port: 6443, Owner: "haproxy (pid 90)"},
		{Bind: "0.0.0.0", Port: 443, Owner: "postern-edge-g1"},
		{Bind: "127.0.0.1", Port: 4443, Owner: "postern-agent"},
		{Bind: "0.0.0.0", Port: 3443, Owner: "stunnel (pid 77)"},
	}
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(s *store.Node) error { s.HostInfo.PortOwners = owners; return nil }); err != nil {
		t.Fatal(err)
	}
	owner := func(bind string, port uint32, name string) *panelv1.PortOwner {
		return &panelv1.PortOwner{Bind: bind, Port: port, Owner: name}
	}

	for _, tc := range []struct {
		name string
		req  *panelv1.CreateListenerRequest
		want []*panelv1.PortOwner
	}{
		{"all addresses, where another process has all addresses", &panelv1.CreateListenerRequest{Port: 80}, []*panelv1.PortOwner{owner("0.0.0.0", 80, "nginx (pid 812)")}},
		{"another address than the process", &panelv1.CreateListenerRequest{Port: 8443, BindIp: "198.51.100.8"}, nil},
		{"the address of the process", &panelv1.CreateListenerRequest{Port: 8443, BindIp: "198.51.100.7"}, []*panelv1.PortOwner{owner("198.51.100.7", 8443, "caddy (container web)")}},
		{"an address, where a process has every address of both families", &panelv1.CreateListenerRequest{Port: 9443, BindIp: "198.51.100.7"}, []*panelv1.PortOwner{owner("::", 9443, "unknown")}},
		{"all addresses, where a process has one IPv6 address", &panelv1.CreateListenerRequest{Port: 7443}, nil},
		{"all addresses, where a process has an IPv4-mapped address", &panelv1.CreateListenerRequest{Port: 6443}, []*panelv1.PortOwner{owner("::ffff:198.51.100.9", 6443, "haproxy (pid 90)")}},
		{"the port of the edge", &panelv1.CreateListenerRequest{Port: 443}, nil},
		{"a port of the agent", &panelv1.CreateListenerRequest{Port: 4443}, nil},
		{"a free port", &panelv1.CreateListenerRequest{Port: 5443}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.NodeId = n.ID
			gen := e.generation(n.ID)
			resp, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(tc.req))
			if err != nil {
				t.Fatalf("CreateListener: %v", err)
			}
			if got := resp.Msg.GetPortTakenBy(); !slices.EqualFunc(got, tc.want, func(a, b *panelv1.PortOwner) bool { return proto.Equal(a, b) }) {
				t.Errorf("port_taken_by = %v, want %v", got, tc.want)
			}
			if g := e.generation(n.ID); g != gen+1 {
				t.Errorf("desired generation = %d, want %d: the listener is stored", g, gen+1)
			}
		})
	}

	// An update says the same of the address that the listener moves to.
	resp, err := e.listeners.ListListeners(e.ctx, connect.NewRequest(&panelv1.ListListenersRequest{NodeId: n.ID}))
	if err != nil {
		t.Fatal(err)
	}
	var free *panelv1.Listener
	for _, l := range resp.Msg.GetListeners() {
		if l.GetPort() == 5443 {
			free = l
		}
	}
	moved, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: free.GetId(), Port: proto.Uint32(3443)}))
	if err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	if got := moved.Msg.GetPortTakenBy(); len(got) != 1 || got[0].GetOwner() != "stunnel (pid 77)" {
		t.Errorf("port_taken_by after a move = %v, want stunnel", got)
	}
	back, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: free.GetId(), Port: proto.Uint32(5443)}))
	if err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	if got := back.Msg.GetPortTakenBy(); len(got) != 0 {
		t.Errorf("port_taken_by on a free port = %v, want none", got)
	}
}

func TestUpdateListenerWithoutAChangeKeepsTheGeneration(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	gen, calls := e.generation(n.ID), e.notes.count()

	resp, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: l.GetId(), Port: proto.Uint32(443)}))
	if err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	if !proto.Equal(resp.Msg.GetListener(), l) {
		t.Errorf("listener = %v, want it unchanged: %v", resp.Msg.GetListener(), l)
	}
	if g := e.generation(n.ID); g != gen {
		t.Errorf("desired generation = %d, want %d: nothing changed", g, gen)
	}
	if c := e.notes.count(); c != calls {
		t.Errorf("%d notifications, want %d", c, calls)
	}
}

func TestDeleteListener(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	used := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	free := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443})
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: used.GetId()})
	gen := e.generation(n.ID)

	_, err := e.listeners.DeleteListener(e.ctx, connect.NewRequest(&panelv1.DeleteListenerRequest{Id: used.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if g := e.generation(n.ID); g != gen {
		t.Errorf("desired generation = %d after a refused delete, want %d", g, gen)
	}

	if _, err := e.listeners.DeleteListener(e.ctx, connect.NewRequest(&panelv1.DeleteListenerRequest{Id: free.GetId()})); err != nil {
		t.Fatalf("DeleteListener: %v", err)
	}
	if g := e.generation(n.ID); g != gen+1 {
		t.Errorf("desired generation = %d, want %d", g, gen+1)
	}
	if _, err := e.db.ListenerByID(e.ctx, free.GetId()); err == nil {
		t.Error("the listener is still there")
	}
	_, err = e.listeners.DeleteListener(e.ctx, connect.NewRequest(&panelv1.DeleteListenerRequest{Id: free.GetId()}))
	wantCode(t, err, connect.CodeNotFound)
}
