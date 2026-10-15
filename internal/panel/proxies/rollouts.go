package proxies

import (
	"context"
	"errors"
	"slices"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// This file holds what the rollout runner asks of the proxies service besides
// the locked write path (WriteVersions, NotifyChannel): whether proxies may
// switch engine, and which providers a node runs.

// CheckEngineSwitch checks, as CreateProxy and UpdateProxy do, the state of a
// node whose proxies proxyIDs would run engine (pinned at version, or at the
// channel version when version is ""): the rules of the node for the engine
// (mtg: no ad tag, no middle proxies, no telemt overrides, no NAT IP, a mask
// target that is a public IP) and the capabilities the node reports
// (engine-mtg). It changes nothing. A refusal is a Connect error of code
// failed precondition whose message says why.
func (s *Service) CheckEngineSwitch(ctx context.Context, nodeID string, proxyIDs []string, engine, version string) error {
	if _, err := checkEngine(engine); err != nil {
		return err
	}
	nodeDataMu.RLock()
	defer nodeDataMu.RUnlock()
	nd, err := loadNodeData(ctx, s.db, s.key, nodeID)
	if err != nil {
		return s.readError("node", err)
	}
	before, _ := assemble(nd, s.pool)
	found := 0
	for _, p := range nd.proxies {
		if !slices.Contains(proxyIDs, p.ID) {
			continue
		}
		found++
		p.Engine = engine
		if version != "" {
			p.EngineVersionPolicy, p.EngineVersion = store.EnginePolicyPinned, version
		} else {
			p.EngineVersionPolicy, p.EngineVersion = store.EnginePolicyChannel, ""
		}
	}
	if found != len(proxyIDs) {
		return connect.NewError(connect.CodeNotFound, errors.New("a proxy is not on the node"))
	}
	if err := s.checkState(nd, before); err != nil {
		return err
	}
	return nil
}

// NodeProviders returns the providers (xray, psiphon-core) that the state of a
// node runs, sorted: those of the egresses that its proxies and chains use.
func (s *Service) NodeProviders(ctx context.Context, nodeID string) ([]string, error) {
	nodeDataMu.RLock()
	defer nodeDataMu.RUnlock()
	nd, err := loadNodeData(ctx, s.db, s.key, nodeID)
	if err != nil {
		return nil, err
	}
	st, err := assemble(nd, s.pool)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range st.GetEgresses() {
		if p := providerOf(e.GetKind()); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}
