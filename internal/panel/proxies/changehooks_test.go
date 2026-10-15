package proxies

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// hookCalls records the change hooks of the service.
type hookCalls struct {
	mu      sync.Mutex
	befores []string
	afters  []string
	locked  bool // Before ran under the lock of the node data
	during  func()
}

func (h *hookCalls) hooks() ChangeHooks {
	return ChangeHooks{
		Before: func(_ context.Context, nodeID, scope, change string) string {
			free := nodeDataMu.TryLock()
			if free {
				nodeDataMu.Unlock()
			}
			h.mu.Lock()
			h.locked = h.locked || !free
			h.befores = append(h.befores, nodeID+" "+scope+" "+change)
			f := h.during
			h.mu.Unlock()
			if f != nil {
				f()
			}
			return "run-1"
		},
		After: func(nodeID, scope, change, before string, gen uint64) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.afters = append(h.afters, fmt.Sprintf("%s %s %s %s %d", nodeID, scope, change, before, gen))
		},
	}
}

func (h *hookCalls) got() ([]string, []string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.befores), slices.Clone(h.afters), h.locked
}

// An edit of a proxy's chain or scope chains runs Before outside the lock,
// with the proxy's scope, commits, and tells After of the generation; another
// edit runs no hook.
func TestProxyEgressEditsRunTheHooks(t *testing.T) {
	e := newEnv(t)
	h := &hookCalls{}
	e.svc.SetChangeHooks(h.hooks())
	n := e.mustEgressNode("n", CapEgressXray)
	eg := e.addEgress(goldenE2, store.EgressKindSOCKS5, "", `{"addr":"198.51.100.9:1080"}`, 0)
	e.addChain(goldenC1, "", store.ChainCheck{}, eg.ID)
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443})
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "hooks.example.com"})
	notes := e.notes.count()

	chain := goldenC1
	resp, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), EgressChainId: &chain}))
	if err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if got := resp.Msg.GetBeforeRunId(); got != "run-1" {
		t.Errorf("before_run_id %q, want run-1", got)
	}
	befores, afters, locked := h.got()
	scope := "proxy:" + p.GetId()
	if !slices.Equal(befores, []string{n.ID + " " + scope + " proxy.update egress_chain_id"}) || locked {
		t.Errorf("befores %v (under the lock: %v)", befores, locked)
	}
	if want := fmt.Sprintf("%s %s proxy.update egress_chain_id run-1 %d", n.ID, scope, e.generation(n.ID)); !slices.Equal(afters, []string{want}) {
		t.Errorf("afters %v, want %s", afters, want)
	}
	if e.storedProxy(p.GetId()).EgressChainID != goldenC1 || e.notes.count() != notes+1 {
		t.Error("the edit was not committed and notified")
	}

	// A name runs no hook; scope chains do.
	renamed := "renamed"
	if resp, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), Name: &renamed})); err != nil {
		t.Fatal(err)
	} else if got := resp.Msg.GetBeforeRunId(); got != "" {
		t.Errorf("a rename has the before-run %q", got)
	}
	if b, _, _ := h.got(); len(b) != 1 {
		t.Errorf("a rename ran the hooks: %v", b)
	}
	if _, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(),
		EgressScopeChains: &panelv1.ScopeChains{Chains: map[string]string{"fetch": goldenC1}}})); err != nil {
		t.Fatal(err)
	}
	if b, _, _ := h.got(); len(b) != 2 || !strings.HasSuffix(b[1], "proxy.update egress_scope_chains") {
		t.Errorf("scope chains: %v", b)
	}
}

// A change that the data no longer takes after the before-run is refused:
// nothing is written, no generation raised, no After.
func TestProxyEditRefusedWhenTheDataChangedMeanwhile(t *testing.T) {
	e := newEnv(t)
	h := &hookCalls{}
	e.svc.SetChangeHooks(h.hooks())
	n := e.mustEgressNode("n", CapEgressXray)
	eg := e.addEgress(goldenE2, store.EgressKindSOCKS5, "", `{"addr":"198.51.100.9:1080"}`, 0)
	e.addChain(goldenC1, "", store.ChainCheck{}, eg.ID)
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443})
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "hooks.example.com"})
	h.mu.Lock()
	h.during = func() {
		if err := e.db.DeleteChain(e.ctx, goldenC1); err != nil {
			t.Errorf("DeleteChain: %v", err)
		}
	}
	h.mu.Unlock()
	gen := e.generation(n.ID)

	chain := goldenC1
	_, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), EgressChainId: &chain}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "the data changed meanwhile") {
		t.Errorf("error %v", err)
	}
	if e.storedProxy(p.GetId()).EgressChainID != "" || e.generation(n.ID) != gen {
		t.Error("the refused change was stored")
	}
	if _, afters, _ := h.got(); len(afters) != 0 {
		t.Errorf("afters %v", afters)
	}
}

func TestWithoutChangeHooks(t *testing.T) {
	s := &Service{}
	s.SetChangeHooks(ChangeHooks{After: func(string, string, string, string, uint64) {}})
	if _, on := s.hooks.get(context.Background()); !on {
		t.Error("the hooks are off")
	}
	if _, on := s.hooks.get(WithoutChangeHooks(context.Background())); on {
		t.Error("the hooks run on a context without them")
	}
}

func TestProxyEditHookFields(t *testing.T) {
	base := chainsAndPin{chain: "c1", scopes: map[string]string{"me": "c2"}, policy: store.EnginePolicyChannel}
	for _, tc := range []struct {
		next chainsAndPin
		want string
	}{
		{base, ""},
		{chainsAndPin{chain: "c1", scopes: map[string]string{"me": "c2"}, policy: store.EnginePolicyPinned, version: "3.5.2"}, "proxy.update engine_version"},
		{chainsAndPin{chain: "", scopes: nil, policy: store.EnginePolicyChannel}, "proxy.update egress_chain_id,egress_scope_chains"},
	} {
		h := proxyEditHook("p", base, tc.next)
		got := ""
		if h != nil {
			got = h.change
			if h.scope != "proxy:p" {
				t.Errorf("scope %s", h.scope)
			}
		}
		if got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.next, got, tc.want)
		}
	}
}

// RestartInstance raises the proxy's restart nonce and the node's generation,
// and notifies the node.
func TestRestartInstance(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "cdn.example.com"})
	gen := e.generation(n.ID)
	got, err := e.svc.RestartInstance(e.ctx, p.GetId())
	if err != nil {
		t.Fatalf("RestartInstance: %v", err)
	}
	if got != gen+1 || e.generation(n.ID) != gen+1 || e.storedProxy(p.GetId()).RestartNonce != 1 {
		t.Errorf("generation %d → %d (returned %d), nonce %d", gen, e.generation(n.ID), got, e.storedProxy(p.GetId()).RestartNonce)
	}
	if notes := e.notes.got(); len(notes) == 0 || notes[len(notes)-1] != n.ID {
		t.Errorf("notified %v", notes)
	}
	st, err := e.builder.Build(e.ctx, n.ID, got)
	if err != nil || st.GetProxies()[0].GetRestartNonce() != 1 {
		t.Errorf("the state: %v", err)
	}
	_, err = e.svc.RestartInstance(e.ctx, "01K6Y00000000000000000000Z")
	wantCode(t, err, connect.CodeNotFound)
}
