package egress

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/proxies"
)

// hookRecorder records the change hooks.
type hookRecorder struct {
	mu      sync.Mutex
	befores []string
	afters  []string
	// onBefore runs inside Before, once.
	onBefore func()
}

func (h *hookRecorder) hooks() ChangeHooks {
	return ChangeHooks{
		Before: func(_ context.Context, nodeID, scope, change string) string {
			h.mu.Lock()
			h.befores = append(h.befores, nodeID+" "+scope+" "+change)
			f := h.onBefore
			h.onBefore = nil
			h.mu.Unlock()
			if f != nil {
				f()
			}
			return "before-" + nodeID
		},
		After: func(nodeID, scope, change, before string, gen uint64) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.afters = append(h.afters, fmt.Sprintf("%s %s %s %s %d", nodeID, scope, change, before, gen))
		},
	}
}

func (h *hookRecorder) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.befores, h.afters = nil, nil
}

func (h *hookRecorder) got() ([]string, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, a := slices.Clone(h.befores), slices.Clone(h.afters)
	slices.Sort(b)
	slices.Sort(a)
	return b, a
}

// An edit of an egress runs the hooks on every node that uses it, scope node,
// and on no other; the node edits run them on their node.
func TestEgressEditsRunTheHooks(t *testing.T) {
	e := newEnv(t)
	h := &hookRecorder{}
	e.svc.SetChangeHooks(h.hooks())
	a := e.addNode("a", proxies.CapEgressXray, proxies.CapDNSForwarder)
	b := e.addNode("b", proxies.CapEgressXray)
	idle := e.addNode("idle", proxies.CapEgressXray)
	socks := e.createEgress(&panelv1.CreateEgressRequest{Name: "s", Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080"}})
	chain := e.createChain(&panelv1.CreateChainRequest{Name: "c", MemberIds: []string{socks.GetId()}})
	e.setDefaultChain(a.ID, chain.GetId())
	e.setDefaultChain(b.ID, chain.GetId())
	h.reset() // the default chains ran them too; see below

	idleGen := e.generation(idle.ID)
	resp, err := e.egresses.UpdateEgress(e.ctx, connect.NewRequest(&panelv1.UpdateEgressRequest{Id: socks.GetId(),
		Params: &panelv1.EgressParams{Addr: "198.51.100.10:1080"}}))
	if err != nil {
		t.Fatalf("UpdateEgress: %v", err)
	}
	if got, want := resp.Msg.GetBeforeRunIds(), map[string]string{a.ID: "before-" + a.ID, b.ID: "before-" + b.ID}; !maps.Equal(got, want) {
		t.Errorf("before_run_ids %v, want %v", got, want)
	}
	change := "egress.update egress:" + socks.GetId()
	befores, afters := h.got()
	want := []string{a.ID + " node " + change, b.ID + " node " + change}
	slices.Sort(want)
	if !slices.Equal(befores, want) {
		t.Errorf("befores %v, want %v", befores, want)
	}
	wantAfters := []string{
		fmt.Sprintf("%s node %s before-%s %d", a.ID, change, a.ID, e.generation(a.ID)),
		fmt.Sprintf("%s node %s before-%s %d", b.ID, change, b.ID, e.generation(b.ID)),
	}
	slices.Sort(wantAfters)
	if !slices.Equal(afters, wantAfters) {
		t.Errorf("afters %v, want %v", afters, wantAfters)
	}
	if e.generation(idle.ID) != idleGen {
		t.Error("the node that does not use the egress was raised")
	}

	h.reset()
	dns, err := e.egresses.SetNodeDnsMode(e.ctx, connect.NewRequest(&panelv1.SetNodeDnsModeRequest{NodeId: a.ID, DnsMode: "doh"}))
	if err != nil {
		t.Fatalf("SetNodeDnsMode: %v", err)
	}
	if befores, afters := h.got(); len(befores) != 1 || befores[0] != a.ID+" node node.dns_mode doh" || len(afters) != 1 {
		t.Errorf("dns mode: %v, %v", befores, afters)
	}
	if got := dns.Msg.GetBeforeRunId(); got != "before-"+a.ID {
		t.Errorf("dns mode before_run_id %q", got)
	}
	// The same mode again changes nothing and runs no checks.
	if again, err := e.egresses.SetNodeDnsMode(e.ctx, connect.NewRequest(&panelv1.SetNodeDnsModeRequest{NodeId: a.ID, DnsMode: "doh"})); err != nil || again.Msg.GetBeforeRunId() != "" {
		t.Errorf("an unchanged dns mode: %v, before_run_id %q", err, again.Msg.GetBeforeRunId())
	}
	h.reset()
	def, err := e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: b.ID}))
	if err != nil {
		t.Fatalf("SetNodeDefaultChain: %v", err)
	}
	if befores, afters := h.got(); len(befores) != 1 || befores[0] != b.ID+" node node.default_chain none" || len(afters) != 1 {
		t.Errorf("default chain: %v, %v", befores, afters)
	}
	if got := def.Msg.GetBeforeRunId(); got != "before-"+b.ID {
		t.Errorf("default chain before_run_id %q", got)
	}
	// A refresh of a subscription is not an edit.
	h.reset()
	sub := e.createEgress(&panelv1.CreateEgressRequest{Name: "sub", Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL}})
	subChain := e.createChain(&panelv1.CreateChainRequest{Name: "subs", MemberIds: []string{sub.GetId()}})
	h.reset()
	e.setDefaultChain(idle.ID, subChain.GetId())
	h.reset()
	if _, err := e.egresses.RefreshSubscription(e.ctx, connect.NewRequest(&panelv1.RefreshSubscriptionRequest{Id: sub.GetId()})); err != nil {
		t.Fatalf("RefreshSubscription: %v", err)
	}
	if befores, _ := h.got(); len(befores) != 0 {
		t.Errorf("a refresh ran the hooks: %v", befores)
	}
}

// A change that no longer passes after the before-runs is refused, and
// nothing is written.
func TestEgressEditRefusedWhenTheDataChangedMeanwhile(t *testing.T) {
	e := newEnv(t)
	h := &hookRecorder{}
	e.svc.SetChangeHooks(h.hooks())
	a := e.addNode("a", proxies.CapEgressXray)
	socks := e.createEgress(&panelv1.CreateEgressRequest{Name: "s", Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080"}})
	other := e.createChain(&panelv1.CreateChainRequest{Name: "other", MemberIds: []string{socks.GetId()}})
	gen := e.generation(a.ID)
	h.mu.Lock()
	h.onBefore = func() {
		if _, err := e.chains.DeleteChain(e.ctx, connect.NewRequest(&panelv1.DeleteChainRequest{Id: other.GetId()})); err != nil {
			t.Errorf("DeleteChain: %v", err)
		}
	}
	h.mu.Unlock()
	_, err := e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: a.ID, ChainId: other.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "the data changed meanwhile") {
		t.Errorf("error %v", err)
	}
	if n := e.node(a.ID); n.DefaultChainID != "" || e.generation(a.ID) != gen {
		t.Errorf("stored: default chain %q, generation %d → %d", n.DefaultChainID, gen, e.generation(a.ID))
	}
	if _, afters := h.got(); len(afters) != 0 {
		t.Errorf("afters %v", afters)
	}
}
