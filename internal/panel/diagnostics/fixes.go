package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// The fixes (Global Constraints, the fix catalogue).
const (
	FixRecreateInstance    = "recreate_instance"
	FixRollEdge            = "roll_edge"
	FixChangeEgress        = "change_egress"
	FixRefreshSubscription = "refresh_subscription"
	FixSetDNSModeDoH       = "set_dns_mode_doh"
	FixReissueCert         = "reissue_cert"
)

// Actions are the changes that the fixes make, each through the panel's own
// mutation of it; set at wiring (internal/panel/server), so that the services
// need not import the diagnostics. Those that return a generation return the
// node's desired generation that has the change; for the others it is read
// after them. The errors are Connect errors. A nil action is not available.
type Actions struct {
	// RestartInstance raises a proxy's restart nonce (proxies.Service).
	RestartInstance func(ctx context.Context, proxyID string) (uint64, error)
	// RollEdge raises a node's edge roll nonce (nodes.Service).
	RollEdge func(ctx context.Context, nodeID string) (uint64, error)
	// ChangeEgress sets a proxy's egress chain through UpdateProxy, without
	// its change hooks, audited as the UI's own edit.
	ChangeEgress func(ctx context.Context, proxyID, chainID string) error
	// RefreshSubscription raises a subscription's refresh nonce through
	// RefreshSubscription.
	RefreshSubscription func(ctx context.Context, egressID string) error
	// SetDNSModeDoH sets a node's DNS mode to doh through SetNodeDnsMode,
	// without its change hooks.
	SetDNSModeDoH func(ctx context.Context, nodeID string) error
	// ReissueCert raises a WEB proxy's certificate reissue nonce
	// (proxies.Service), refusing a certificate the node does not issue.
	ReissueCert func(ctx context.Context, proxyID string) (uint64, error)
}

// fixer is what ApplyFix works with.
type fixer struct {
	changes *Changes
	actions Actions
}

// SetFixes makes ApplyFix apply fixes by actions, with the runs around them
// of changes. Without it, ApplyFix is unimplemented. Call it before the
// service serves.
func (s *Service) SetFixes(changes *Changes, actions Actions) {
	s.fixes = &fixer{changes: changes, actions: actions}
}

func failedPrecondition(format string, args ...any) error {
	return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(format, args...))
}

func invalidArgument(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

// plannedFix is a fix checked against the data: the scope of its runs, the
// proxy it is about ("" for none), and the change it makes.
type plannedFix struct {
	scope   string
	proxyID string
	apply   func(ctx context.Context) (uint64, error)
}

// ApplyFix applies the fix that a result offers, on the operator's click: it
// checks that the node can apply it and that the result offers it, keeps the
// run that offered it (or a copy of the light checks) as the before-run, makes
// the change, audits it (diagnostics.fix), records the event
// diagnostics.fix_applied, and has an after-run of the target's scope, related
// to the before-run, once the node has applied the change.
func (s *Service) ApplyFix(ctx context.Context, req *connect.Request[panelv1.ApplyFixRequest]) (*connect.Response[panelv1.ApplyFixResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.fixes == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("this panel applies no fixes"))
	}
	m := req.Msg
	nodeID, checkID, target, fix := m.GetNodeId(), m.GetCheckId(), m.GetTarget(), m.GetFix()
	switch {
	case nodeID == "":
		return nil, invalidArgument("node_id is required")
	case checkID == "":
		return nil, invalidArgument("check_id is required")
	case fix == "":
		return nil, invalidArgument("fix is required")
	}
	if _, ok := fixSpecs[fix]; !ok {
		return nil, invalidArgument("the panel does not know the fix %.64q", fix)
	}
	n, err := s.db.NodeByID(ctx, nodeID)
	if err != nil {
		return nil, s.fail("the node", err)
	}
	if ok, why := FixAvailable(fix, target, n.HostInfo.Capabilities); !ok {
		return nil, failedPrecondition("%s", why)
	}
	if err := s.offered(ctx, m); err != nil {
		return nil, err
	}
	plan, err := s.planFix(ctx, n, m)
	if err != nil {
		return nil, err
	}

	change := "fix " + fix
	ch := s.fixes.changes
	// The node's own changes that the fix brings about are the fix's.
	ch.hold(nodeID, ch.cfg.Now().Add(ch.cfg.BeforeWait+ch.cfg.AfterDelay))
	before := m.GetOfferedRunId()
	if before == "" {
		if before, err = s.runner.CopyLight(ctx, nodeID, plan.scope, change); err != nil {
			return nil, s.fail("could not copy the light checks", err)
		}
	}
	gen, err := plan.apply(ctx)
	if err != nil {
		var ce *connect.Error
		if errors.As(err, &ce) {
			return nil, err
		}
		return nil, s.fail("could not apply a fix", err)
	}

	details := map[string]string{"node": nodeID, "fix": fix, "check_id": checkID, "target": target,
		"before_run_id": before, "generation": strconv.FormatUint(gen, 10)}
	if c := m.GetChainId(); c != "" {
		details["chain_id"] = c
	}
	bg := context.WithoutCancel(ctx)
	auditTarget := "node:" + nodeID
	if target != "" {
		auditTarget = target
	}
	if err := s.db.AppendAudit(bg, &store.AuditEntry{AdminID: admin.ID, Action: "diagnostics.fix", Target: auditTarget, Details: details}); err != nil {
		s.log.Error("could not write the audit log", "action", "diagnostics.fix", "err", err)
	}
	e := &store.Event{NodeID: nodeID, ProxyID: plan.proxyID, Kind: "diagnostics.fix_applied", Severity: "info",
		Message: clip(fmt.Sprintf("fix %s applied to %s for %s", fix, targetName(target), checkLabel(checkID, target)), 1024),
		Details: details}
	if err := s.db.AppendEvent(bg, e); err != nil {
		s.log.Error("could not record a fix", "node", nodeID, "fix", fix, "err", err)
	}
	ch.After(nodeID, plan.scope, change, before, gen)
	return connect.NewResponse(&panelv1.ApplyFixResponse{BeforeRunId: before, Generation: gen}), nil
}

func targetName(target string) string {
	if target == "" {
		return "the node"
	}
	return target
}

// errStale is a fix whose check no longer fails, as far as the panel knows.
func errStale(m *panelv1.ApplyFixRequest) error {
	return failedPrecondition("this fix is stale: %s no longer offers %s; run diagnostics again", checkLabel(m.GetCheckId(), m.GetTarget()), m.GetFix())
}

// failing says whether a status is one that a fix is for.
func failing(status string) bool { return status == StatusWarn || status == StatusFail }

// offered checks that the fix is for a check that still fails. Without an
// offered run, the node's current light check (the same id and target) must
// offer the fix and not pass. With one, the run must have offered it, and
// either the current light check does not pass, or the run is the node's
// latest of its scope and the check failed in it (a check of the full runs
// only). Otherwise the fix is stale (FAILED_PRECONDITION): a click on an old
// result must not restart or roll again.
func (s *Service) offered(ctx context.Context, m *panelv1.ApplyFixRequest) error {
	same := func(id, target string) bool { return id == m.GetCheckId() && target == m.GetTarget() }
	checks, err := s.db.NodeChecks(ctx, m.GetNodeId())
	if err != nil {
		return s.fail("could not read the checks", err)
	}
	var light *store.NodeCheck
	for i := range checks {
		if same(checks[i].CheckID, checks[i].Target) {
			light = &checks[i]
			break
		}
	}
	id := m.GetOfferedRunId()
	if id == "" && light == nil && m.GetCheckId() == checkVersions {
		// panel.versions, which the feed offers as edge.outdated, is the
		// panel's own check: it is checked as it is now.
		n, err := s.db.NodeByID(ctx, m.GetNodeId())
		if err != nil {
			return s.fail("the node", err)
		}
		if x := versions(n); x.Target != m.GetTarget() || x.Fix != m.GetFix() || !failing(x.Status) {
			return errStale(m)
		}
		return nil
	}
	if id == "" {
		if light == nil || light.Fix != m.GetFix() || !failing(light.Status) {
			return errStale(m)
		}
		return nil
	}
	run, err := s.db.DiagnosticRun(ctx, id)
	if err != nil {
		return s.fail("the run", err)
	}
	if run.NodeID != m.GetNodeId() {
		return invalidArgument("the run is of another node")
	}
	var offered *store.DiagnosticResult
	for i := range run.Results {
		if x := &run.Results[i]; same(x.CheckID, x.Target) && x.Fix == m.GetFix() {
			offered = x
			break
		}
	}
	if offered == nil {
		return failedPrecondition("the run did not offer the fix %s for %s", m.GetFix(), checkLabel(m.GetCheckId(), m.GetTarget()))
	}
	if light != nil {
		if failing(light.Status) {
			return nil
		}
		return errStale(m)
	}
	latest, err := s.db.ListDiagnosticRuns(ctx, run.NodeID, []string{run.Scope}, 1)
	if err != nil {
		return s.fail("could not list the runs", err)
	}
	if len(latest) == 1 && latest[0].ID == run.ID && failing(offered.Status) {
		return nil
	}
	return errStale(m)
}

// planFix checks a fix against the data and says what it changes.
func (s *Service) planFix(ctx context.Context, n *store.Node, m *panelv1.ApplyFixRequest) (*plannedFix, error) {
	a := s.fixes.actions
	unavailable := func() error {
		return connect.NewError(connect.CodeUnimplemented, fmt.Errorf("this panel cannot apply the fix %s", m.GetFix()))
	}
	// withGen is an action that returns no generation: the node's is read
	// after it.
	withGen := func(do func(ctx context.Context) error) func(ctx context.Context) (uint64, error) {
		return func(ctx context.Context) (uint64, error) {
			if err := do(ctx); err != nil {
				return 0, err
			}
			got, err := s.db.NodeByID(context.WithoutCancel(ctx), n.ID)
			if err != nil {
				return 0, err
			}
			return got.DesiredGeneration, nil
		}
	}
	switch m.GetFix() {
	case FixRecreateInstance:
		p, err := s.proxyOf(ctx, n, m.GetTarget())
		if err != nil {
			return nil, err
		}
		if a.RestartInstance == nil {
			return nil, unavailable()
		}
		return &plannedFix{scope: "proxy:" + p.ID, proxyID: p.ID, apply: func(ctx context.Context) (uint64, error) {
			return a.RestartInstance(ctx, p.ID)
		}}, nil
	case FixRollEdge:
		if a.RollEdge == nil {
			return nil, unavailable()
		}
		return &plannedFix{scope: ScopeNode, apply: func(ctx context.Context) (uint64, error) { return a.RollEdge(ctx, n.ID) }}, nil
	case FixChangeEgress:
		p, err := s.proxyOf(ctx, n, m.GetTarget())
		if err != nil {
			return nil, err
		}
		chainID := strings.TrimSpace(m.GetChainId())
		if chainID == "" {
			return nil, invalidArgument("chain_id is required: the chain that the proxy is to go out through")
		}
		if err := s.usableChain(ctx, n, p, chainID); err != nil {
			return nil, err
		}
		if a.ChangeEgress == nil {
			return nil, unavailable()
		}
		return &plannedFix{scope: "proxy:" + p.ID, proxyID: p.ID, apply: withGen(func(ctx context.Context) error {
			return a.ChangeEgress(ctx, p.ID, chainID)
		})}, nil
	case FixRefreshSubscription:
		egressID, err := s.subscriptionOf(ctx, m.GetTarget())
		if err != nil {
			return nil, err
		}
		if a.RefreshSubscription == nil {
			return nil, unavailable()
		}
		return &plannedFix{scope: ScopeNode, apply: withGen(func(ctx context.Context) error {
			return a.RefreshSubscription(ctx, egressID)
		})}, nil
	case FixSetDNSModeDoH:
		if n.DNSMode == "doh" {
			return nil, failedPrecondition("the node resolves through DoH already")
		}
		if a.SetDNSModeDoH == nil {
			return nil, unavailable()
		}
		return &plannedFix{scope: ScopeNode, apply: withGen(func(ctx context.Context) error { return a.SetDNSModeDoH(ctx, n.ID) })}, nil
	case FixReissueCert:
		p, err := s.proxyOf(ctx, n, m.GetTarget())
		if err != nil {
			return nil, err
		}
		if p.Type != store.ProxyTypeWeb {
			return nil, failedPrecondition("the proxy is not a WEB proxy: it has no certificate of its own")
		}
		if a.ReissueCert == nil {
			return nil, unavailable()
		}
		return &plannedFix{scope: "proxy:" + p.ID, proxyID: p.ID, apply: func(ctx context.Context) (uint64, error) {
			return a.ReissueCert(ctx, p.ID)
		}}, nil
	}
	return nil, unavailable()
}

// proxyOf is the proxy of a target "proxy:<id>" of the node.
func (s *Service) proxyOf(ctx context.Context, n *store.Node, target string) (*store.Proxy, error) {
	id, _ := strings.CutPrefix(target, "proxy:")
	p, err := s.db.ProxyByID(ctx, id)
	if err != nil {
		return nil, s.fail("the proxy", err)
	}
	if p.NodeID != n.ID {
		return nil, invalidArgument("the proxy is on another node")
	}
	return p, nil
}

// usableChain checks that a chain is one that the proxy's node can use, and
// another than the proxy's own.
func (s *Service) usableChain(ctx context.Context, n *store.Node, p *store.Proxy, chainID string) error {
	c, err := s.db.ChainByID(ctx, chainID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return failedPrecondition("there is no egress chain %.64q", chainID)
	case err != nil:
		return s.fail("could not read a chain", err)
	case c.NodeID != "" && c.NodeID != n.ID:
		return failedPrecondition("the egress chain %q belongs to another node: the proxy cannot go out through it", c.Name)
	case len(c.Members) == 0:
		return failedPrecondition("the egress chain %q has no members", c.Name)
	case p.EgressChainID == c.ID:
		return failedPrecondition("the proxy goes out through the egress chain %q already", c.Name)
	}
	return nil
}

// subscriptionOf is the egress of a member target
// "member:<chain id>/<egress id>[/<member key>]", which must be a
// subscription.
func (s *Service) subscriptionOf(ctx context.Context, target string) (string, error) {
	rest, _ := strings.CutPrefix(target, "member:")
	_, member, ok := strings.Cut(rest, "/")
	egressID, _, _ := strings.Cut(member, "/")
	if !ok || egressID == "" {
		return "", invalidArgument("the target names no member of a chain")
	}
	e, err := s.db.EgressByID(ctx, egressID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", failedPrecondition("the egress of the member is gone")
	case err != nil:
		return "", s.fail("could not read an egress", err)
	case e.Kind != store.EgressKindXraySubscription:
		return "", failedPrecondition("the egress of the member is not a subscription")
	}
	return e.ID, nil
}
