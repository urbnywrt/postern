package proxies

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// ChangeHooks run a full diagnostic run before and after an operator's edit
// (R6-3). The panel's diagnostics set them at wiring; the services never
// import the diagnostics.
type ChangeHooks struct {
	// Before runs the checks of the scope of a node before a change is
	// committed, outside the lock of the node data, and returns the id of
	// that run ("" for none). It takes at most 90 s and never refuses the
	// change.
	Before func(ctx context.Context, nodeID, scope, change string) (beforeRunID string)
	// After is told of a committed change: the generation that has it. It
	// runs the checks again once the node has applied it, and returns at
	// once.
	After func(nodeID, scope, change, beforeRunID string, generation uint64)
}

func (h ChangeHooks) set() bool { return h.Before != nil || h.After != nil }

// changeHooks holds the hooks of a service.
type changeHooks struct {
	mu sync.Mutex
	h  ChangeHooks
}

func (c *changeHooks) get(ctx context.Context) (ChangeHooks, bool) {
	if hooksOff(ctx) {
		return ChangeHooks{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.h, c.h.set()
}

// SetChangeHooks sets the hooks around the edits of a proxy's egress chains
// and of its version pin.
func (s *Service) SetChangeHooks(h ChangeHooks) {
	s.hooks.mu.Lock()
	defer s.hooks.mu.Unlock()
	s.hooks.h = h
}

type hooksOffKey struct{}

// WithoutChangeHooks marks a context whose changes run no change hooks: a fix
// of the diagnostics, which has its before-run already and runs its own
// after-run.
func WithoutChangeHooks(ctx context.Context) context.Context {
	return context.WithValue(ctx, hooksOffKey{}, true)
}

func hooksOff(ctx context.Context) bool {
	off, _ := ctx.Value(hooksOffKey{}).(bool)
	return off
}

// changedMeanwhile is the error of a change that its second plan, after the
// before-run, no longer takes.
func changedMeanwhile(err error) error {
	var ce *connect.Error
	if errors.As(err, &ce) {
		switch ce.Code() {
		case connect.CodeInternal, connect.CodeCanceled, connect.CodeDeadlineExceeded:
			return err
		}
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("the data changed meanwhile: %s", ce.Message()))
	}
	return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("the data changed meanwhile: %w", err))
}

// hooked is what a step tells the change hooks: the scope and the words of
// the change.
type hooked struct{ scope, change string }

// proxyEditHook is the hook of an UpdateProxy that changes the proxy's egress
// chain, its scope chains or its version pin; nil for another edit.
func proxyEditHook(proxyID string, a, b chainsAndPin) *hooked {
	var fields []string
	if a.chain != b.chain {
		fields = append(fields, "egress_chain_id")
	}
	if !maps.Equal(a.scopes, b.scopes) {
		fields = append(fields, "egress_scope_chains")
	}
	if a.policy != b.policy || a.version != b.version {
		fields = append(fields, "engine_version")
	}
	if len(fields) == 0 {
		return nil
	}
	return &hooked{scope: "proxy:" + proxyID, change: "proxy.update " + strings.Join(fields, ",")}
}

// chainsAndPin are the fields of a proxy whose edit runs the hooks.
type chainsAndPin struct {
	chain           string
	scopes          map[string]string
	policy, version string
}

func pinOf(p *store.Proxy) chainsAndPin {
	return chainsAndPin{chain: p.EgressChainID, scopes: p.EgressScopeChains, policy: p.EngineVersionPolicy, version: p.EngineVersion}
}
