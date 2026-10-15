package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// The fix change_egress goes through UpdateProxy, audited as the UI's own
// edit, with the light copy as its only before-run (the edit's hooks are off);
// the operator's own edit of the chain gets a before-run from the hooks.
func TestChangeEgressFixIsWired(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	ctx, cancel := context.WithCancel(context.Background())
	p.srv.changes.Start(ctx)
	t.Cleanup(func() { cancel(); p.srv.changes.Drain(); p.srv.diag.Drain() })
	db := p.srv.db
	base := p.ts.URL + "/api"
	listeners := panelv1connect.NewListenerServiceClient(b.http, base)
	proxySvc := panelv1connect.NewProxyServiceClient(b.http, base)
	egresses := panelv1connect.NewEgressServiceClient(b.http, base)
	chains := panelv1connect.NewChainServiceClient(b.http, base)
	diag := panelv1connect.NewDiagnosticsServiceClient(b.http, base)

	n := &store.Node{Name: "n", MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: "203.0.113.10"}
	if err := db.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ModifyNode(ctx, n.ID, func(n *store.Node) error {
		seen := time.Now()
		n.HostInfo.Capabilities, n.LastSeenAt = []string{"diagnostics", "egress-xray"}, &seen
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l, err := listeners.CreateListener(ctx, connect.NewRequest(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443}))
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxySvc.CreateProxy(ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.Msg.GetListener().GetId(), Domain: "cdn.example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	proxyID := px.Msg.GetProxy().GetId()
	eg, err := egresses.CreateEgress(ctx, connect.NewRequest(&panelv1.CreateEgressRequest{Name: "s", Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080"}}))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := chains.CreateChain(ctx, connect.NewRequest(&panelv1.CreateChainRequest{Name: "c", MemberIds: []string{eg.Msg.GetEgress().GetId()}}))
	if err != nil {
		t.Fatal(err)
	}
	chainID := ch.Msg.GetChain().GetId()
	if _, err := db.ReplaceNodeChecks(ctx, n.ID, []store.NodeCheck{{CheckID: "e2e.l2", Target: "proxy:" + proxyID, Layer: "e2e", Status: "fail", Fix: "change_egress"}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	resp, err := diag.ApplyFix(ctx, connect.NewRequest(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "e2e.l2", Target: "proxy:" + proxyID, Fix: "change_egress", ChainId: chainID}))
	if err != nil {
		t.Fatalf("ApplyFix: %v", err)
	}
	stored, err := db.ProxyByID(ctx, proxyID)
	if err != nil || stored.EgressChainID != chainID {
		t.Fatalf("the proxy's chain: %v, %v", stored, err)
	}
	node, _ := db.NodeByID(ctx, n.ID)
	if resp.Msg.GetGeneration() != node.DesiredGeneration {
		t.Errorf("generation %d, the node's %d", resp.Msg.GetGeneration(), node.DesiredGeneration)
	}
	beforeRuns := func() int {
		runs, err := db.ListDiagnosticRuns(ctx, n.ID, nil, 50)
		if err != nil {
			t.Fatal(err)
		}
		k := 0
		for _, r := range runs {
			if r.Reason == store.RunBeforeChange {
				k++
			}
		}
		return k
	}
	if got := beforeRuns(); got != 1 {
		t.Errorf("%d before-runs after the fix, want the light copy only", got)
	}
	ro, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(p.dataDir, DatabaseFile))+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	rows, err := ro.Query(`SELECT action FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		seen[action] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !seen["proxy.update"] || !seen["diagnostics.fix"] {
		t.Errorf("audit actions %v", seen)
	}

	// The operator's own edit runs the hooks: a before-run (skipped, the node
	// is offline).
	empty := ""
	if _, err := proxySvc.UpdateProxy(ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: proxyID, EgressChainId: &empty})); err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if got := beforeRuns(); got != 2 {
		t.Errorf("%d before-runs after the operator's edit, want 2", got)
	}
}
