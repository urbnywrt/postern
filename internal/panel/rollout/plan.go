package rollout

import (
	"cmp"
	"slices"
	"strings"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// candidate is a proxy that a rollout changes, with its node.
type candidate struct {
	proxy *store.Proxy
	node  *store.Node
}

// plan is the steps and the items of a rollout of proxies.
type plan struct {
	canary  candidate
	nodeIDs []string
	steps   []store.RolloutStep
	items   []store.RolloutItem
}

// itemOf is the item of a proxy as it is now, in a step.
func itemOf(p *store.Proxy, step uint32) store.RolloutItem {
	return store.RolloutItem{
		ProxyID: p.ID, NodeID: p.NodeID, StepIndex: step,
		PrevEngine:  cmp.Or(p.Engine, store.EngineTelemt),
		PrevPolicy:  cmp.Or(p.EngineVersionPolicy, store.EnginePolicyChannel),
		PrevVersion: p.EngineVersion,
		State:       store.ItemPending,
	}
}

// proxySteps orders the proxies of an engine or switch rollout into its
// steps: the canary proxy, then the rest of its node (a step that may be
// empty), then every other node by name. The canary is canaryID when given (an
// enabled proxy of the rollout), else the first enabled proxy, by node name,
// proxy name and id, on a node that is online.
func proxySteps(cands []candidate, canaryID string) (*plan, error) {
	if len(cands) == 0 {
		return nil, refuse("no proxy would change")
	}
	cands = slices.Clone(cands)
	slices.SortFunc(cands, func(a, b candidate) int {
		return cmp.Or(strings.Compare(a.node.Name, b.node.Name), strings.Compare(a.node.ID, b.node.ID),
			strings.Compare(a.proxy.Name, b.proxy.Name), strings.Compare(a.proxy.ID, b.proxy.ID))
	})
	var at int
	if canaryID != "" {
		at = slices.IndexFunc(cands, func(c candidate) bool { return c.proxy.ID == canaryID })
		if at < 0 {
			return nil, invalid("the canary proxy %.40q is not one of the proxies that the rollout changes", canaryID)
		}
		if !cands[at].proxy.Enabled {
			return nil, refuse("the canary proxy %s is disabled", cands[at].proxy.Name)
		}
	} else {
		at = slices.IndexFunc(cands, func(c candidate) bool {
			return c.proxy.Enabled && c.node.Status == store.NodeStatusOnline
		})
		if at < 0 {
			return nil, refuse("no enabled proxy of the rollout is on an online node to go first")
		}
	}
	canary := cands[at]
	p := &plan{canary: canary}
	p.steps = []store.RolloutStep{
		{Index: 0, NodeID: canary.node.ID, ProxyID: canary.proxy.ID},
		{Index: 1, NodeID: canary.node.ID},
	}
	p.nodeIDs = []string{canary.node.ID}
	p.items = append(p.items, itemOf(canary.proxy, 0))
	for _, c := range cands {
		if c.node.ID == canary.node.ID && c.proxy.ID != canary.proxy.ID {
			p.items = append(p.items, itemOf(c.proxy, 1))
		}
	}
	for _, c := range cands {
		if c.node.ID == canary.node.ID {
			continue
		}
		if last := p.steps[len(p.steps)-1]; last.NodeID != c.node.ID {
			p.steps = append(p.steps, store.RolloutStep{Index: uint32(len(p.steps)), NodeID: c.node.ID})
			p.nodeIDs = append(p.nodeIDs, c.node.ID)
		}
		p.items = append(p.items, itemOf(c.proxy, p.steps[len(p.steps)-1].Index))
	}
	return p, nil
}
