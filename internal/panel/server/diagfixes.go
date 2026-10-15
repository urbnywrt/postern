package server

import (
	"context"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/diagnostics"
	"github.com/urbnywrt/postern/internal/panel/egress"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/proxies"
)

// wireChanges sets the runs before and after the operator's edits on the
// proxy and egress services, and the fixes of the diagnostics, each through
// the service's own mutation. The services reach the diagnostics only through
// these function values.
func wireChanges(changes *diagnostics.Changes, diag *diagnostics.Service, px *proxies.Service, eg *egress.Service, ns *nodes.Service) {
	hooks := proxies.ChangeHooks{Before: changes.Before, After: changes.After}
	px.SetChangeHooks(hooks)
	eg.SetChangeHooks(hooks)
	ns.SetStateWriter(px)
	diag.SetFixes(changes, diagnostics.Actions{
		RestartInstance: px.RestartInstance,
		ReissueCert:     px.ReissueCert,
		RollEdge:        ns.RollEdge,
		// The fixes have their before-run and run their after-run: the
		// edits they make run no hooks of their own.
		ChangeEgress: func(ctx context.Context, proxyID, chainID string) error {
			_, err := px.UpdateProxy(proxies.WithoutChangeHooks(ctx), connect.NewRequest(&panelv1.UpdateProxyRequest{Id: proxyID, EgressChainId: &chainID}))
			return err
		},
		RefreshSubscription: func(ctx context.Context, egressID string) error {
			_, err := eg.RefreshSubscription(ctx, connect.NewRequest(&panelv1.RefreshSubscriptionRequest{Id: egressID}))
			return err
		},
		SetDNSModeDoH: func(ctx context.Context, nodeID string) error {
			_, err := eg.SetNodeDnsMode(proxies.WithoutChangeHooks(ctx), connect.NewRequest(&panelv1.SetNodeDnsModeRequest{NodeId: nodeID, DnsMode: state.DNSModeDoH}))
			return err
		},
	})
}
