// Package egress is the EgressService and the ChainService of the panel API:
// the egresses, which are the ways out to Telegram, the egress chains, which
// the nodes and their proxies go out through, and the egress settings of a
// node (its default chain and its DNS mode), with the health of the members of
// its chains as the node reports it.
//
// Every change goes through proxies.Service.MutateEgresses, which judges it by
// the desired state of every node that it changes, the node's own rules and its
// capabilities, writes it, and raises the generations of those nodes. A change
// that changes no state of a node (a name, an egress that no chain in use has)
// raises none.
//
// The parameters of an egress are sealed in the database with the AAD
// egress:<id> (proxies.SealEgressParams) and never logged, and their secrets
// never leave the panel: an answer shows the scheme and the host of a share
// link or of the URL of a subscription, and whether a proxy has a password.
//
// Wiring, in the panel:
//
//	svc := egress.NewService(db, key, proxiesService, ingestor, log)
//	mux.Handle(panelv1connect.NewEgressServiceHandler(svc))
//	mux.Handle(panelv1connect.NewChainServiceHandler(svc))
package egress

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// maxNameChars bounds the name of an egress and of a chain.
const maxNameChars = 64

// errInternal is all that a caller is told of an error of the panel itself.
// What it was is in the log.
var errInternal = errors.New("internal error")

// Service is the EgressService and the ChainService of the panel.
//
// Every call needs an admin: the auth middleware refuses calls without a
// session, and the service checks again, so that it is safe however it is
// mounted.
type Service struct {
	db       *store.DB
	key      seal.Key
	states   *proxies.Service
	ingestor *proxies.Ingestor
	log      *slog.Logger
	now      func() time.Time // the clock, replaced by tests

	hooksMu sync.Mutex
	hooks   ChangeHooks
}

// ChangeHooks run a full diagnostic run before and after an edit of an
// egress, of a node's default chain or of its DNS mode, on every node whose
// state the edit changes (scope node): proxies.ChangeHooks.
type ChangeHooks = proxies.ChangeHooks

// SetChangeHooks sets the hooks around UpdateEgress, SetNodeDefaultChain and
// SetNodeDnsMode.
func (s *Service) SetChangeHooks(h ChangeHooks) {
	s.hooksMu.Lock()
	defer s.hooksMu.Unlock()
	s.hooks = h
}

func (s *Service) changeHooks() ChangeHooks {
	s.hooksMu.Lock()
	defer s.hooksMu.Unlock()
	return s.hooks
}

var (
	_ panelv1connect.EgressServiceHandler = (*Service)(nil)
	_ panelv1connect.ChainServiceHandler  = (*Service)(nil)
)

// NewService returns the services on the database. key seals and opens the
// parameters of the egresses, states makes the changes (it judges them by the
// states of the nodes, and tells the nodes), and ingestor, which may be nil,
// knows what the nodes reported of the health of their egresses. A nil log
// discards the log.
func NewService(db *store.DB, key seal.Key, states *proxies.Service, ingestor *proxies.Ingestor, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{db: db, key: key, states: states, ingestor: ingestor, log: log, now: time.Now}
}

// requireAdmin returns the admin of the request, or the error to answer with.
func requireAdmin(ctx context.Context) (*store.Admin, error) {
	a, ok := auth.AdminFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return a, nil
}

// fail turns an error of the panel itself into the error that a caller gets,
// and logs it. A request that is gone or has run out of time says so.
func (s *Service) fail(what string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, errors.New("the request was canceled"))
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, errors.New("the request took too long"))
	}
	s.log.Error(what, "err", err)
	return connect.NewError(connect.CodeInternal, errInternal)
}

// readError maps the error of reading one record.
func (s *Service) readError(what string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return notFound(what)
	}
	return s.fail("could not read a "+what, err)
}

func invalid(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

func notFound(what string) error {
	return connect.NewError(connect.CodeNotFound, fmt.Errorf("no such %s", what))
}

func failedPrecondition(format string, args ...any) error {
	return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(format, args...))
}

// audit records what an admin did. A failure is logged and does not fail the
// call: what it records has happened.
func (s *Service) audit(ctx context.Context, adminID, action, target, nodeID string) {
	entry := &store.AuditEntry{AdminID: adminID, Action: action, Target: target}
	if nodeID != "" {
		entry.Details = map[string]string{"node": nodeID}
	}
	if err := s.db.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		s.log.Error("could not write the audit log", "action", action, "target", target, "err", err)
	}
}

// checkName returns a name without the spaces around it: 1 to 64 characters of
// valid UTF-8 without control characters.
func checkName(s string) (string, error) {
	name := strings.TrimSpace(s)
	switch {
	case name == "":
		return "", invalid("name is empty")
	case !utf8.ValidString(name):
		return "", invalid("name is not valid UTF-8")
	case utf8.RuneCountInString(name) > maxNameChars:
		return "", invalid("name has more than %d characters", maxNameChars)
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return "", invalid("name has a control character")
	}
	return name, nil
}

// paramsError is the Connect error of a check of parameters.
func paramsError(err error) error {
	return connect.NewError(connect.CodeInvalidArgument, err)
}

// ---- EgressService ----------------------------------------------------------------

// maxLoggedIDs bounds the ids of egresses that one log line names.
const maxLoggedIDs = 16

// egressProtos are the API forms of egresses: their parameters without the
// secrets, and the chains that have them. Parameters that cannot be opened
// (another master key) are left out, and logged once for the call, not once
// for each egress.
func (s *Service) egressProtos(es []*store.Egress, chains []*store.EgressChain) []*panelv1.Egress {
	out := make([]*panelv1.Egress, 0, len(es))
	var (
		bad   []string
		first error
	)
	for _, e := range es {
		raw, err := proxies.OpenEgressParams(s.key, e)
		if err != nil {
			if len(bad) < maxLoggedIDs {
				bad = append(bad, e.ID)
			}
			first = cmp.Or(first, err)
			raw = ""
		}
		out = append(out, egressProto(e, raw, chains))
	}
	if first != nil {
		s.log.Error("could not open the parameters of egresses", "egresses", bad, "err", first)
	}
	return out
}

// egressProto is the API form of an egress whose parameters are raw (JSON).
func egressProto(e *store.Egress, raw string, chains []*store.EgressChain) *panelv1.Egress {
	view, passwordSet := paramsView(e.Kind, raw)
	out := &panelv1.Egress{
		Id:          e.ID,
		Name:        e.Name,
		Kind:        e.Kind,
		NodeId:      e.NodeID,
		Params:      view,
		Masked:      masked(e.Kind, raw),
		PasswordSet: passwordSet,
		CreatedUnix: e.CreatedAt.Unix(),
		UpdatedUnix: e.UpdatedAt.Unix(),
	}
	for _, c := range chains {
		if slices.Contains(c.Members, e.ID) {
			out.ChainIds = append(out.ChainIds, c.ID)
		}
	}
	return out
}

// ListEgresses returns the egresses, or those that a node can use.
func (s *Service) ListEgresses(ctx context.Context, req *connect.Request[panelv1.ListEgressesRequest]) (*connect.Response[panelv1.ListEgressesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	nodeID := req.Msg.GetNodeId()
	if nodeID != "" {
		if _, err := s.db.NodeByID(ctx, nodeID); err != nil {
			return nil, s.readError("node", err)
		}
	}
	es, err := s.db.ListEgresses(ctx)
	if err != nil {
		return nil, s.fail("could not list the egresses", err)
	}
	cs, err := s.db.ListChains(ctx)
	if err != nil {
		return nil, s.fail("could not list the chains", err)
	}
	es = slices.DeleteFunc(es, func(e *store.Egress) bool { return nodeID != "" && e.NodeID != "" && e.NodeID != nodeID })
	return connect.NewResponse(&panelv1.ListEgressesResponse{Egresses: s.egressProtos(es, cs)}), nil
}

// GetEgress returns one egress.
func (s *Service) GetEgress(ctx context.Context, req *connect.Request[panelv1.GetEgressRequest]) (*connect.Response[panelv1.GetEgressResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	out, err := s.egressByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.GetEgressResponse{Egress: out}), nil
}

// egressByID is the API form of the egress with this id.
func (s *Service) egressByID(ctx context.Context, id string) (*panelv1.Egress, error) {
	e, err := s.db.EgressByID(ctx, id)
	if err != nil {
		return nil, s.readError("egress", err)
	}
	cs, err := s.db.ListChains(ctx)
	if err != nil {
		return nil, s.fail("could not list the chains", err)
	}
	return s.egressProtos([]*store.Egress{e}, cs)[0], nil
}

// CreateEgress makes an egress.
func (s *Service) CreateEgress(ctx context.Context, req *connect.Request[panelv1.CreateEgressRequest]) (*connect.Response[panelv1.CreateEgressResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	name, err := checkName(msg.GetName())
	if err != nil {
		return nil, err
	}
	if !validKind(msg.GetKind()) {
		return nil, invalid("kind must be %s", kindList)
	}
	params, err := paramsJSON(msg.GetKind(), msg.GetParams(), "")
	if err != nil {
		return nil, paramsError(err)
	}
	e := &store.Egress{ID: ids.New(), Name: name, Kind: msg.GetKind(), NodeID: strings.TrimSpace(msg.GetNodeId())}
	if e.ParamsEnc, err = proxies.SealEgressParams(s.key, e.ID, params); err != nil {
		return nil, s.fail("could not seal the parameters of an egress", err)
	}
	_, err = s.states.MutateEgresses(ctx, func(w *proxies.World) (func(context.Context) error, error) {
		if e.NodeID != "" && w.Node(e.NodeID) == nil {
			return nil, notFound("node")
		}
		w.SetEgress(e, params)
		return func(ctx context.Context) error { return s.db.CreateEgress(ctx, e) }, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "egress.create", "egress:"+e.ID, e.NodeID)
	s.log.Info("egress created", "egress", e.ID, "kind", e.Kind, "node", e.NodeID, "admin", admin.ID)
	return connect.NewResponse(&panelv1.CreateEgressResponse{Egress: egressProto(e, params, nil)}), nil
}

// UpdateEgress changes the name or the parameters of an egress.
func (s *Service) UpdateEgress(ctx context.Context, req *connect.Request[panelv1.UpdateEgressRequest]) (*connect.Response[panelv1.UpdateEgressResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	var name *string
	if msg.Name != nil {
		n, err := checkName(msg.GetName())
		if err != nil {
			return nil, err
		}
		name = &n
	}
	id := msg.GetId()
	changed := false
	_, befores, err := s.states.MutateEgressesChange(ctx, "egress.update egress:"+id, s.changeHooks(), func(w *proxies.World) (func(context.Context) error, error) {
		changed = false // the plan runs again after the before-runs
		cur := w.Egress(id)
		if cur == nil {
			return nil, notFound("egress")
		}
		next := *cur
		if name != nil {
			next.Name = *name
		}
		stored, err := w.EgressParams(id)
		if err != nil && msg.Params == nil {
			return nil, s.fail("could not open the parameters of an egress", err)
		}
		params := stored
		if msg.Params != nil {
			if params, err = paramsJSON(cur.Kind, msg.GetParams(), stored); err != nil {
				return nil, paramsError(err)
			}
		}
		if next.Name == cur.Name && params == stored {
			return nil, nil
		}
		if params != stored {
			if next.ParamsEnc, err = proxies.SealEgressParams(s.key, id, params); err != nil {
				return nil, s.fail("could not seal the parameters of an egress", err)
			}
		}
		w.SetEgress(&next, params)
		changed = true
		return func(ctx context.Context) error { return s.db.UpdateEgress(ctx, &next) }, nil
	})
	if err != nil {
		return nil, err
	}
	out, err := s.egressByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if changed {
		s.audit(ctx, admin.ID, "egress.update", "egress:"+id, out.GetNodeId())
	}
	return connect.NewResponse(&panelv1.UpdateEgressResponse{Egress: out, BeforeRunIds: befores}), nil
}

// DeleteEgress deletes an egress that no chain has.
func (s *Service) DeleteEgress(ctx context.Context, req *connect.Request[panelv1.DeleteEgressRequest]) (*connect.Response[panelv1.DeleteEgressResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetId()
	var nodeID string
	_, err = s.states.MutateEgresses(ctx, func(w *proxies.World) (func(context.Context) error, error) {
		cur := w.Egress(id)
		if cur == nil {
			return nil, notFound("egress")
		}
		nodeID = cur.NodeID
		var in []string
		for _, c := range w.Chains() {
			if slices.Contains(c.Members, id) {
				in = append(in, fmt.Sprintf("%q", c.Name))
			}
		}
		if len(in) > 0 {
			return nil, failedPrecondition("the egress is a member of the chains %s: take it out of them first", strings.Join(in, ", "))
		}
		w.RemoveEgress(id)
		return func(ctx context.Context) error { return s.db.DeleteEgress(ctx, id) }, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "egress.delete", "egress:"+id, nodeID)
	s.log.Info("egress deleted", "egress", id, "admin", admin.ID)
	return connect.NewResponse(&panelv1.DeleteEgressResponse{}), nil
}

// ValidateEgress says whether the panel takes the parameters of an egress.
func (s *Service) ValidateEgress(ctx context.Context, req *connect.Request[panelv1.ValidateEgressRequest]) (*connect.Response[panelv1.ValidateEgressResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	msg := req.Msg
	kind := msg.GetKind()
	refuse := func(problem string) (*connect.Response[panelv1.ValidateEgressResponse], error) {
		return connect.NewResponse(&panelv1.ValidateEgressResponse{Problem: problem}), nil
	}
	if !validKind(kind) {
		return refuse("the kind must be " + kindList)
	}
	stored := ""
	if id := msg.GetId(); id != "" {
		e, err := s.db.EgressByID(ctx, id)
		if err != nil {
			return nil, s.readError("egress", err)
		}
		if e.Kind != kind {
			return refuse("the egress is of kind " + e.Kind)
		}
		if stored, err = proxies.OpenEgressParams(s.key, e); err != nil {
			return nil, s.fail("could not open the parameters of an egress", err)
		}
	}
	raw, err := paramsJSON(kind, msg.GetParams(), stored)
	if err != nil {
		return refuse(err.Error())
	}
	resp := &panelv1.ValidateEgressResponse{Valid: true, Masked: masked(kind, raw)}
	if kind == store.EgressKindXrayURI {
		if p, err := state.ParseXrayURIParams(raw); err == nil {
			resp.Protocol, resp.Security, resp.Network = p.Server.Protocol, p.Server.Security, p.Server.Network
		}
	}
	return connect.NewResponse(resp), nil
}

// RefreshSubscription asks the nodes that run a subscription to fetch it again:
// its refresh nonce goes up, which changes the states of those nodes.
func (s *Service) RefreshSubscription(ctx context.Context, req *connect.Request[panelv1.RefreshSubscriptionRequest]) (*connect.Response[panelv1.RefreshSubscriptionResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetId()
	var nodeID string
	raised, err := s.states.MutateEgresses(ctx, func(w *proxies.World) (func(context.Context) error, error) {
		cur := w.Egress(id)
		if cur == nil {
			return nil, notFound("egress")
		}
		if cur.Kind != store.EgressKindXraySubscription {
			return nil, failedPrecondition("the egress is of kind %s: only one of kind xray-subscription has a subscription to fetch", cur.Kind)
		}
		params, err := w.EgressParams(id)
		if err != nil {
			return nil, s.fail("could not open the parameters of an egress", err)
		}
		nodeID = cur.NodeID
		next := *cur
		next.RefreshNonce++
		w.SetEgress(&next, params)
		return func(ctx context.Context) error { return s.db.UpdateEgress(ctx, &next) }, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "egress.refresh", "egress:"+id, nodeID)
	s.log.Info("subscription refresh asked for", "egress", id, "nodes", len(raised), "admin", admin.ID)
	return connect.NewResponse(&panelv1.RefreshSubscriptionResponse{NodeIds: raised}), nil
}

// GetNodeEgressHealth returns the health of the members of the chains of a
// node, with the names of the chains and the egresses.
func (s *Service) GetNodeEgressHealth(ctx context.Context, req *connect.Request[panelv1.GetNodeEgressHealthRequest]) (*connect.Response[panelv1.GetNodeEgressHealthResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	n, err := s.db.NodeByID(ctx, req.Msg.GetNodeId())
	if err != nil {
		return nil, s.readError("node", err)
	}
	resp := &panelv1.GetNodeEgressHealthResponse{NodeStatus: n.Status}
	members, reported, ok := s.ingestor.EgressHealth(n.ID)
	if !ok {
		resp.Stale = true // nothing reported since the panel started
		return connect.NewResponse(resp), nil
	}
	resp.ReportedUnix = reported.Unix()
	cs, err := s.db.ListChains(ctx)
	if err != nil {
		return nil, s.fail("could not list the chains", err)
	}
	es, err := s.db.ListEgresses(ctx)
	if err != nil {
		return nil, s.fail("could not list the egresses", err)
	}
	ps, err := s.db.ListProxies(ctx, store.ProxyFilter{NodeID: n.ID})
	if err != nil {
		return nil, s.fail("could not list the proxies", err)
	}
	chains := make(map[string]*store.EgressChain, len(cs))
	for _, c := range cs {
		chains[c.ID] = c
	}
	egresses := make(map[string]*store.Egress, len(es))
	for _, e := range es {
		egresses[e.ID] = e
	}
	now := s.now()
	limit := staleAfter(checkInterval(n, ps, chains))
	resp.Stale = n.Status != store.NodeStatusOnline || now.Sub(reported) > limit
	for _, m := range members {
		// A member of an egress of several is "<egress id>/<member key>".
		egressID, member, _ := strings.Cut(m.GetMemberKey(), "/")
		out := &panelv1.EgressMemberHealth{
			ChainId:     m.GetChainId(),
			EgressId:    egressID,
			Member:      member,
			Status:      m.GetStatus(),
			LatencyMs:   m.GetLatencyMs(),
			ExitIp:      m.GetExitIp(),
			CheckedUnix: m.GetCheckedUnix(),
			Stale:       resp.Stale || (m.GetCheckedUnix() > 0 && now.Sub(time.Unix(m.GetCheckedUnix(), 0)) > limit),
		}
		if c := chains[m.GetChainId()]; c != nil {
			out.ChainName = c.Name
		}
		switch e := egresses[egressID]; {
		case e != nil:
			out.EgressName, out.EgressKind = e.Name, e.Kind
		case egressID == proxies.ImplicitEgressID:
			out.EgressKind = store.EgressKindDirect
		}
		resp.Members = append(resp.Members, out)
	}
	return connect.NewResponse(resp), nil
}

// The age after which health says nothing of now: staleIntervals intervals of
// the checks of the node, and at least minStaleAfter. defaultCheckInterval is
// the interval of the edge when no check says (edge/egress/health.go).
const (
	staleIntervals       = 3
	minStaleAfter        = 2 * time.Minute
	defaultCheckInterval = 30 * time.Second
)

// staleAfter is how old the health that is checked every interval may be.
func staleAfter(interval time.Duration) time.Duration {
	return max(staleIntervals*interval, minStaleAfter)
}

// checkInterval is the interval of the health checks of a node, as the node
// works it out (reconcile/edgecfg.go, healthCheck): it runs one check for all
// of its chains, that of its default chain, or else of the first chain by id
// that it uses and that has a check; a check that leaves the interval out, or
// none, checks every 30 seconds.
func checkInterval(n *store.Node, ps []*store.Proxy, chains map[string]*store.EgressChain) time.Duration {
	hasCheck := func(c *store.EgressChain) bool {
		return c != nil && (c.Check.IntervalSeconds != 0 || c.Check.TimeoutSeconds != 0 || c.Check.FailThreshold != 0 ||
			c.Check.RecoverThreshold != 0 || len(c.Check.DCAddrs) > 0)
	}
	of := func(c *store.EgressChain) time.Duration {
		if c.Check.IntervalSeconds == 0 {
			return defaultCheckInterval
		}
		return time.Duration(c.Check.IntervalSeconds) * time.Second
	}
	if c := chains[n.DefaultChainID]; hasCheck(c) {
		return of(c)
	}
	used := map[string]bool{}
	if n.DefaultChainID != "" {
		used[n.DefaultChainID] = true
	}
	for _, p := range ps {
		if p.EgressChainID != "" {
			used[p.EgressChainID] = true
		}
		for _, c := range p.EgressScopeChains {
			used[c] = true
		}
	}
	for _, id := range slices.Sorted(maps.Keys(used)) {
		if c := chains[id]; hasCheck(c) {
			return of(c)
		}
	}
	return defaultCheckInterval
}

// SetNodeDnsMode sets how the containers of a node resolve names.
func (s *Service) SetNodeDnsMode(ctx context.Context, req *connect.Request[panelv1.SetNodeDnsModeRequest]) (*connect.Response[panelv1.SetNodeDnsModeResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	mode := strings.TrimSpace(req.Msg.GetDnsMode())
	switch mode {
	case "", state.DNSModeDoH, state.DNSModeSystem:
	default:
		return nil, invalid("dns_mode must be %s, %s or empty", state.DNSModeDoH, state.DNSModeSystem)
	}
	n, changed, before, err := s.modifyNode(ctx, req.Msg.GetNodeId(), "node.dns_mode "+cmp.Or(mode, "default"), func(w *proxies.World, n *store.Node) (bool, error) {
		if n.DNSMode == mode {
			return false, nil
		}
		n.DNSMode = mode
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if changed {
		s.audit(ctx, admin.ID, "node.dns_mode", "node:"+n.ID, n.ID)
	}
	return connect.NewResponse(&panelv1.SetNodeDnsModeResponse{Node: nodes.ToProto(ctx, s.db, n), BeforeRunId: before}), nil
}

// modifyNode changes the egress settings of a node with change, which runs
// inside MutateEgresses on the node of the World and says whether it changed
// it, and writes the settings that it changes: the default chain and the DNS
// mode. It returns the node as it is afterwards, with its new generation. The
// edit runs the change hooks, named what; it returns the id of the node's
// before-run too ("" for none).
func (s *Service) modifyNode(ctx context.Context, nodeID, what string, change func(w *proxies.World, n *store.Node) (bool, error)) (*store.Node, bool, string, error) {
	changed := false
	_, befores, err := s.states.MutateEgressesChange(ctx, what, s.changeHooks(), func(w *proxies.World) (func(context.Context) error, error) {
		changed = false // the plan runs again after the before-runs
		n := w.Node(nodeID)
		if n == nil {
			return nil, notFound("node")
		}
		ok, err := change(w, n)
		if err != nil || !ok {
			return nil, err
		}
		changed = true
		chain, mode := n.DefaultChainID, n.DNSMode
		return func(ctx context.Context) error {
			_, err := s.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
				n.DefaultChainID, n.DNSMode = chain, mode
				return nil
			})
			return err
		}, nil
	})
	if err != nil {
		return nil, false, "", err
	}
	n, err := s.db.NodeByID(ctx, nodeID)
	if err != nil {
		return nil, false, "", s.readError("node", err)
	}
	return n, changed, befores[nodeID], nil
}
