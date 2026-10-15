package server

import (
	"context"
	"testing"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The first start of a panel with the statistics settings stores their
// defaults and gives every node a new generation, before the nodes are
// connected to.
func TestServeStoresTheDefaultStatsSettings(t *testing.T) {
	p := newPanel(t)
	ctx := context.Background()
	n := &store.Node{Name: "n1", MgmtHost: "192.0.2.10", MgmtPort: 61443}
	if err := p.srv.db.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	r := serve(t, p.srv)
	r.ready()
	s, stored, err := p.srv.db.StatsSettings(ctx)
	if err != nil || !stored || s.IPPolicy != store.IPPolicyCountries {
		t.Errorf("settings %+v, stored %v, %v; want the defaults stored", s, stored, err)
	}
	got, err := p.srv.db.NodeByID(ctx, n.ID)
	if err != nil || got.DesiredGeneration != 1 {
		t.Errorf("the node has generation %d (%v), want 1", got.DesiredGeneration, err)
	}
}
