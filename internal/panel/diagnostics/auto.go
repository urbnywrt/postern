package diagnostics

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The changes that a node makes by itself (a blue-green it starts, a member
// failover, a NAT-IP roll, a subscription refresh) get a copy of the light
// checks as their before-run, at the first change, and a full after-run
// AfterDelay later. The changes of a node within that window are gathered:
// more than coalesceAbove proxies, or a change of the node itself, make one
// run of the node. A node and scope gets at most one automatic after-run per
// AutoEvery, and none while an operator's change of the node is in progress
// (its own after-run covers it).

type autoKey struct{ node, scope string }

// window is a node's own changes being gathered.
type window struct {
	node    bool            // a change of the node itself
	proxies map[string]bool // the scopes of the proxies that changed
	changes []string        // what changed, the first few
}

// maxWindowChanges bounds what a window keeps of the words of its changes.
const maxWindowChanges = 8

// OnServingChange takes a proxy that its node serves by an instance of
// another generation: the signature of proxies.Ingestor.OnServingChange.
func (c *Changes) OnServingChange(nodeID, proxyID string, fromGen, toGen uint64) {
	c.auto(nodeID, "proxy:"+proxyID, fmt.Sprintf("the node replaced the instance of proxy %s (generation %d → %d)", proxyID, fromGen, toGen))
}

// OnLightChanges takes the changes of a node's light checks: a member of a
// chain that fails over (egress.member to warn, "down, another member of the
// chain up", or back from it to ok) is a change of the node.
func (c *Changes) OnLightChanges(nodeID string, changes []store.CheckChange) {
	for _, ch := range changes {
		if failover(ch) {
			c.auto(nodeID, ScopeNode, "egress member failover: "+checkLabel(ch.Check.CheckID, ch.Check.Target)+" "+ch.From+" → "+ch.Check.Status)
		}
	}
}

// failover says whether a change of a light check is a failover of a member
// of a chain.
func failover(ch store.CheckChange) bool {
	if ch.Check.CheckID != "egress.member" || ch.From == "" || ch.From == ch.Check.Status {
		return false
	}
	to := ch.Check.Status
	return to == StatusWarn || (ch.From == StatusWarn && to == StatusOK)
}

// auto gathers a change that a node made by itself into the node's window,
// and opens one, with its before-run, at the first.
func (c *Changes) auto(nodeID, scope, change string) {
	c.mu.Lock()
	if c.pendingLocked(nodeID) || c.limitedLocked(nodeID, scope) {
		c.mu.Unlock()
		return
	}
	w := c.windows[nodeID]
	open := w == nil
	if open {
		w = &window{proxies: map[string]bool{}}
		c.windows[nodeID] = w
	}
	if scope == ScopeNode {
		w.node = true
	} else {
		w.proxies[scope] = true
	}
	if len(w.changes) < maxWindowChanges {
		w.changes = append(w.changes, change)
	}
	base := c.base
	if open {
		c.wg.Add(1)
	}
	c.mu.Unlock()
	if !open {
		return
	}
	go func() {
		defer c.wg.Done()
		before, err := c.cfg.Runner.CopyLight(base, nodeID, ScopeNode, change)
		if err != nil {
			c.cfg.Log.Warn("could not copy the light checks before a change of the node", "node", nodeID, "err", err)
		}
		ok := sleep(base, c.cfg.AfterDelay)
		scopes, words := c.closeWindow(nodeID)
		if !ok {
			return
		}
		for _, s := range scopes {
			c.runAfter(base, nodeID, s, words, before)
		}
	}()
}

// limitedLocked says whether a node and scope had an automatic after-run
// within AutoEvery. The caller holds c.mu.
func (c *Changes) limitedLocked(nodeID, scope string) bool {
	t, ok := c.lastAuto[autoKey{nodeID, scope}]
	return ok && c.cfg.Now().Sub(t) < c.cfg.AutoEvery
}

// closeWindow ends a node's window: the scopes of its after-runs (one run of
// the node above coalesceAbove proxies), those within their limit, and the
// words of its changes.
func (c *Changes) closeWindow(nodeID string) ([]string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.windows[nodeID]
	delete(c.windows, nodeID)
	if w == nil || c.pendingLocked(nodeID) {
		return nil, ""
	}
	scopes := slices.Sorted(maps.Keys(w.proxies))
	if w.node || len(scopes) > coalesceAbove {
		scopes = []string{ScopeNode}
	}
	now := c.cfg.Now()
	var out []string
	for _, s := range scopes {
		if c.limitedLocked(nodeID, s) {
			continue
		}
		c.lastAuto[autoKey{nodeID, s}] = now
		out = append(out, s)
	}
	for k, t := range c.lastAuto { // forget the limits that are over
		if now.Sub(t) >= c.cfg.AutoEvery {
			delete(c.lastAuto, k)
		}
	}
	words := strings.Join(w.changes, "; ")
	if n := len(w.proxies); n > len(w.changes) {
		words = fmt.Sprintf("%s; and more (%d proxies)", words, n)
	}
	return out, clip(words, 1024)
}
