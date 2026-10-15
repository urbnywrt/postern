// Package proxies is the part of the panel that keeps the listeners and the
// proxies of the nodes and turns them into the desired state of each node:
//
//   - Service is the ListenerService, ProxyService and StatsService of the
//     panel API. Every change raises the desired generation of its node and
//     tells the node manager.
//   - StateBuilder builds the NodeState of a node for a generation, the
//     StateBuilder of the node manager, with the egress chains that the node
//     uses and their egresses (egress.go).
//   - Service.MutateEgresses is how the egress services (internal/panel/egress)
//     change the egresses, the chains and the egress settings of nodes: a
//     change is judged by the state of every node that it changes, the rules
//     of the node and its capabilities, before it is written.
//   - Catalog knows the engine releases and those of the egress providers
//     (Xray, psiphon-core), and uploads them to the nodes that need them, the
//     ArtifactEnsurer of the node manager.
//   - Ingestor takes the Watch records of the nodes: the status of the
//     proxies and the health of their egress members, minutes of statistics
//     and events, the Ingestor of the node manager.
//
// Wiring, in the panel:
//
//	catalog := proxies.NewCatalog(releaseCatalog, log)
//	ingestor := proxies.NewIngestor(db, log)
//	mgr.SetStateBuilder(proxies.NewStateBuilder(db, key, catalog, log))
//	mgr.SetIngestor(ingestor)
//	mgr.SetArtifactEnsurer(catalog)
//	svc := proxies.NewService(db, key, catalog, ingestor, mgr, log)
//
// The minutes of statistics that the Ingestor stores are rolled up into hours
// and days, and pruned, by the maintenance loop of the panel
// (internal/panel/server), which is the only one: this package starts no loop
// of its own.
package proxies

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	mrand "math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/webrules"
)

// writeTimeout bounds the end of a mutation: the write, the raise of the
// generation and the notification. They run to the end once they start, also
// when the caller goes away, because a change that is written has to reach its
// node.
const writeTimeout = 30 * time.Second

// errInternal is all that a caller is told of an error of the panel itself.
// What it was is in the log.
var errInternal = errors.New("internal error")

// Notifier is told about every node whose desired generation went up. The
// node manager is one: it pushes the new state.
type Notifier interface {
	Notify(nodeID string)
}

// Service is the ListenerService, the ProxyService and the StatsService of
// the panel.
//
// Every call needs an admin: the auth middleware refuses calls without a
// session, and the service checks again, so that it is safe however it is
// mounted.
//
// A change is checked twice: the values on their own, with errors that say
// which value is wrong, and then the whole state of the node after the change
// by the rules of the node, so that a change that the node would refuse (and
// with it the whole state of the node) is never stored. Then the change is
// written, the desired generation of the node is raised, and the notifier is
// told, in this order: a state that the manager builds when the generation has
// gone up has the change.
type Service struct {
	db       *store.DB
	key      seal.Key
	catalog  *Catalog
	ingestor *Ingestor
	notifier Notifier
	log      *slog.Logger
	pool     []string // the domains that a new proxy gets one of
	// domains checks the domain of a WEB proxy before it is stored; nil
	// checks nothing. certs sends imported certificates to the nodes; nil
	// sends nothing.
	domains DomainChecker
	certs   CertPusher
	// now is the clock: imported certificates are judged by it.
	now func() time.Time

	// nextGen raises the desired generation of a node:
	// store.DB.NextNodeGeneration. Tests watch it.
	nextGen func(ctx context.Context, nodeID string) (uint64, error)

	// hooks run diagnostics before and after an edit of a proxy's egress
	// chains or version pin (SetChangeHooks).
	hooks changeHooks
}

var (
	_ panelv1connect.ListenerServiceHandler = (*Service)(nil)
	_ panelv1connect.ProxyServiceHandler    = (*Service)(nil)
	_ panelv1connect.StatsServiceHandler    = (*Service)(nil)
)

// NewService returns the services on the database. key seals and opens the
// proxy secrets, catalog knows the engine versions, ingestor (which may be nil)
// knows the status and the latest minute of the proxies, and n (which may be
// nil) is told about every node whose desired state changed. A nil log
// discards the log.
func NewService(db *store.DB, key seal.Key, catalog *Catalog, ingestor *Ingestor, n Notifier, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db:       db,
		key:      key,
		catalog:  catalog,
		ingestor: ingestor,
		notifier: n,
		log:      log,
		pool:     DefaultDomainPool,
		nextGen:  db.NextNodeGeneration,
		now:      time.Now,
	}
}

// newID makes the id of a new row.
func newID() string { return ids.New() }

// requireAdmin returns the admin of the request, or the error to answer with.
func requireAdmin(ctx context.Context) (*store.Admin, error) {
	a, ok := auth.AdminFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return a, nil
}

// fail turns an error of the panel itself into the error that a caller gets,
// and logs it. A request that is gone or has run out of time says so, since
// that is not a fault.
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

func notFound(what string) error {
	return connect.NewError(connect.CodeNotFound, fmt.Errorf("no such %s", what))
}

// readError maps the error of reading one record.
func (s *Service) readError(what string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return notFound(what)
	}
	return s.fail("could not read a "+what, err)
}

// audit records what an admin did. A failure is logged and does not fail the
// call: what it records has happened.
func (s *Service) audit(ctx context.Context, adminID, action, target, nodeID string) {
	entry := &store.AuditEntry{AdminID: adminID, Action: action, Target: target, Details: map[string]string{"node": nodeID}}
	if err := s.db.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		s.log.Error("could not write the audit log", "action", action, "target", target, "err", err)
	}
}

// step is the write of a mutation.
type step struct {
	write func(ctx context.Context) error
	// unchecked skips the check of the state of the node: a delete, a pause or
	// a resume cannot make a state that the node takes into one that it
	// refuses, and must stay possible when the state is bad already (a delete
	// may be what mends it).
	unchecked bool
	// hook, when set, runs the change hooks around the change (R6-3).
	hook *hooked
}

// mutate changes the data of a node. Under the lock of the node data it reads
// the data of the node, lets plan change it in memory and say what to write,
// checks the state of the node after the change, writes, raises the desired
// generation of the node and notifies the notifier. A nil step from plan is no
// change: nothing is written and the generation stays.
//
// A step with a hook, while change hooks are set, is planned and checked, then
// the lock is released for the before-run (Before), and taken again: the data
// is read and the plan made and checked again, against the data as it is now
// (a change that no longer passes is refused, FAILED_PRECONDITION "the data
// changed meanwhile"), and the change is committed. After is then told of the
// generation that has it. It returns the new generation (0 for no change).
func (s *Service) mutate(ctx context.Context, nodeID string, plan func(nd *nodeData) (*step, error)) (uint64, error) {
	gen, _, err := s.mutateRun(ctx, nodeID, plan)
	return gen, err
}

// mutateRun is mutate that also returns the id of the before-run of a
// committed change ("" when it ran none).
func (s *Service) mutateRun(ctx context.Context, nodeID string, plan func(nd *nodeData) (*step, error)) (uint64, string, error) {
	nodeDataMu.Lock()
	st, err := s.planNode(ctx, nodeID, plan)
	if err != nil || st == nil {
		nodeDataMu.Unlock()
		return 0, "", err
	}
	h, on := s.hooks.get(ctx)
	if st.hook == nil || !on {
		defer nodeDataMu.Unlock()
		gen, err := s.commit(ctx, nodeID, st)
		return gen, "", err
	}
	nodeDataMu.Unlock()

	hk := *st.hook
	beforeRun := ""
	if h.Before != nil {
		beforeRun = h.Before(ctx, nodeID, hk.scope, hk.change)
	}
	nodeDataMu.Lock()
	st, err = s.planNode(ctx, nodeID, plan)
	if err != nil {
		nodeDataMu.Unlock()
		return 0, "", changedMeanwhile(err)
	}
	if st == nil { // nothing is left to change
		nodeDataMu.Unlock()
		return 0, "", nil
	}
	gen, err := s.commit(ctx, nodeID, st)
	nodeDataMu.Unlock()
	if err != nil {
		return gen, "", err
	}
	if h.After != nil {
		h.After(nodeID, hk.scope, hk.change, beforeRun, gen)
	}
	return gen, beforeRun, nil
}

// planNode reads the data of a node and lets plan change it, and checks the
// state after the change. The caller holds the lock of the node data.
func (s *Service) planNode(ctx context.Context, nodeID string, plan func(nd *nodeData) (*step, error)) (*step, error) {
	nd, err := loadNodeData(ctx, s.db, s.key, nodeID)
	if err != nil {
		return nil, s.readError("node", err)
	}
	// What the state asks of the node before the change; nil when it cannot
	// be made (see checkCapabilities).
	before, _ := assemble(nd, s.pool)
	st, err := plan(nd)
	if err != nil || st == nil {
		return nil, err
	}
	if !st.unchecked {
		if err := s.checkState(nd, before); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// commit writes a planned step, raises the desired generation of the node and
// notifies the notifier. The caller holds the lock of the node data.
func (s *Service) commit(ctx context.Context, nodeID string, st *step) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := st.write(ctx); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return 0, connect.NewError(connect.CodeNotFound, errors.New("the node, the listener or the proxy is gone"))
		case errors.Is(err, store.ErrConflict):
			return 0, connect.NewError(connect.CodeFailedPrecondition, errors.New("the change collides with data that changed meanwhile"))
		}
		return 0, s.fail("could not store a change", err)
	}
	gen, err := s.nextGen(ctx, nodeID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return 0, notFound("node") // deleted meanwhile, with what was written
		}
		return 0, s.fail("a change is stored, but the desired generation of its node could not be raised", err)
	}
	if s.notifier != nil {
		s.notifier.Notify(nodeID)
	}
	return gen, nil
}

// checkState checks the state of a node after a change by the rules of the
// node, and by its capabilities against the state before the change.
func (s *Service) checkState(nd *nodeData, before *nodev1.NodeState) error {
	st, err := assemble(nd, s.pool)
	if err == nil {
		err = validateState(st)
	}
	if err == nil {
		err = checkCapabilities(nd.node, before, st)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errSecret), errors.Is(err, errParams), errors.Is(err, errDNSCredential):
		return s.fail("could not open a secret of the node", err)
	}
	return connect.NewError(connect.CodeFailedPrecondition, err)
}

// ---- ListenerService ----------------------------------------------------------

// ListListeners returns the listeners of a node, or of every node.
func (s *Service) ListListeners(ctx context.Context, req *connect.Request[panelv1.ListListenersRequest]) (*connect.Response[panelv1.ListListenersResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	ls, err := s.db.ListListeners(ctx, req.Msg.GetNodeId())
	if err != nil {
		return nil, s.fail("could not list the listeners", err)
	}
	out := make([]*panelv1.Listener, 0, len(ls))
	for _, l := range ls {
		out = append(out, listenerProto(l))
	}
	return connect.NewResponse(&panelv1.ListListenersResponse{Listeners: out}), nil
}

// CreateListener adds a listener to a node.
func (s *Service) CreateListener(ctx context.Context, req *connect.Request[panelv1.CreateListenerRequest]) (*connect.Response[panelv1.CreateListenerResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	l := &store.Listener{ID: ids.New(), NodeID: msg.GetNodeId(), Port: msg.GetPort()}
	if l.Kind, err = checkKind(msg.GetKind()); err != nil {
		return nil, err
	}
	if l.BindIP, err = checkBindIP(l.Kind, msg.GetBindIp()); err != nil {
		return nil, err
	}
	if l.TrustedCIDRs, err = checkTrustedCIDRs(l.Kind, msg.GetTrustedCidrs()); err != nil {
		return nil, err
	}
	if err := checkPort(msg.GetPort()); err != nil {
		return nil, err
	}
	if err := checkListenerAddress(l.BindIP, l.Port); err != nil {
		return nil, err
	}
	if l.LinkHostOverride, err = optionalHost("link_host_override", msg.GetLinkHostOverride()); err != nil {
		return nil, err
	}
	if l.StrangerAction, err = checkStrangerAction(msg.GetStrangerAction()); err != nil {
		return nil, err
	}
	if l.MaskTarget, err = checkMaskTarget(msg.GetMaskTarget()); err != nil {
		return nil, err
	}
	if l.NonTLSAction, err = checkNonTLSAction(msg.GetNonTlsAction()); err != nil {
		return nil, err
	}

	var owners []store.PortOwner
	_, err = s.mutate(ctx, l.NodeID, func(nd *nodeData) (*step, error) {
		if err := checkMgmtPort(nd.node, l.Port); err != nil {
			return nil, err
		}
		if err := addressConflict(nd.listeners, l); err != nil {
			return nil, err
		}
		owners = nd.node.HostInfo.PortOwners
		nd.listeners = append(nd.listeners, l)
		return &step{write: func(ctx context.Context) error { return s.db.CreateListener(ctx, l) }}, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "listener.create", "listener:"+l.ID, l.NodeID)
	s.log.Info("listener created", "listener", l.ID, "node", l.NodeID, "admin", admin.ID)
	return connect.NewResponse(&panelv1.CreateListenerResponse{
		Listener:    listenerProto(l),
		PortTakenBy: portTakenBy(owners, l.BindIP, l.Port),
	}), nil
}

// UpdateListener changes the fields that the request sets.
func (s *Service) UpdateListener(ctx context.Context, req *connect.Request[panelv1.UpdateListenerRequest]) (*connect.Response[panelv1.UpdateListenerResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	cur, err := s.db.ListenerByID(ctx, msg.GetId())
	if err != nil {
		return nil, s.readError("listener", err)
	}
	// Every value is checked before anything is changed. The bind address
	// and the trusted CIDRs are judged by the kind of the listener, which
	// does not change.
	var change listenerChange
	if msg.BindIp != nil {
		ip, err := checkBindIP(cur.Kind, msg.GetBindIp())
		if err != nil {
			return nil, err
		}
		change.bindIP = &ip
	}
	if msg.TrustedCidrs != nil {
		cidrs, err := checkTrustedCIDRs(cur.Kind, msg.GetTrustedCidrs().GetCidrs())
		if err != nil {
			return nil, err
		}
		change.trusted, change.setTrusted = cidrs, true
	}
	if msg.Port != nil {
		if err := checkPort(msg.GetPort()); err != nil {
			return nil, err
		}
		port := msg.GetPort()
		change.port = &port
	}
	if msg.LinkHostOverride != nil {
		host, err := optionalHost("link_host_override", msg.GetLinkHostOverride())
		if err != nil {
			return nil, err
		}
		change.linkHost = &host
	}
	if msg.StrangerAction != nil {
		a, err := checkStrangerAction(msg.GetStrangerAction())
		if err != nil {
			return nil, err
		}
		change.stranger = &a
	}
	if msg.MaskTarget != nil {
		target, err := checkMaskTarget(msg.GetMaskTarget())
		if err != nil {
			return nil, err
		}
		change.maskTarget = &target
	}
	if msg.NonTlsAction != nil {
		a, err := checkNonTLSAction(msg.GetNonTlsAction())
		if err != nil {
			return nil, err
		}
		change.nonTLS = &a
	}

	var (
		out     *store.Listener
		changed bool
		owners  []store.PortOwner
	)
	_, err = s.mutate(ctx, cur.NodeID, func(nd *nodeData) (*step, error) {
		l := nd.listener(cur.ID)
		if l == nil {
			return nil, notFound("listener")
		}
		next := *l
		change.apply(&next)
		out = l
		owners = nd.node.HostInfo.PortOwners
		if sameListener(&next, l) {
			return nil, nil
		}
		if err := checkListenerAddress(next.BindIP, next.Port); err != nil {
			return nil, err
		}
		if err := checkMgmtPort(nd.node, next.Port); err != nil {
			return nil, err
		}
		if next.Port != l.Port || next.BindIP != l.BindIP {
			if err := checkHiddenMgmt(nd.node, l); err != nil {
				return nil, err
			}
		}
		if err := addressConflict(nd.listeners, &next); err != nil {
			return nil, err
		}
		*l = next
		changed = true
		return &step{write: func(ctx context.Context) error { return s.db.UpdateListener(ctx, l) }}, nil
	})
	if err != nil {
		return nil, err
	}
	if changed {
		s.audit(ctx, admin.ID, "listener.update", "listener:"+out.ID, out.NodeID)
	}
	return connect.NewResponse(&panelv1.UpdateListenerResponse{
		Listener:    listenerProto(out),
		PortTakenBy: portTakenBy(owners, out.BindIP, out.Port),
	}), nil
}

// listenerChange is what UpdateListener changes; nil fields stay.
type listenerChange struct {
	bindIP, linkHost, stranger, maskTarget, nonTLS *string
	port                                           *uint32
	trusted                                        []string
	setTrusted                                     bool
}

func (c listenerChange) apply(l *store.Listener) {
	if c.bindIP != nil {
		l.BindIP = *c.bindIP
	}
	if c.setTrusted {
		l.TrustedCIDRs = c.trusted
	}
	if c.port != nil {
		l.Port = *c.port
	}
	if c.linkHost != nil {
		l.LinkHostOverride = *c.linkHost
	}
	if c.stranger != nil {
		l.StrangerAction = *c.stranger
	}
	if c.maskTarget != nil {
		l.MaskTarget = *c.maskTarget
	}
	if c.nonTLS != nil {
		l.NonTLSAction = *c.nonTLS
	}
}

// sameListener reports whether two listeners have the same settings.
func sameListener(a, b *store.Listener) bool {
	return a.Kind == b.Kind && a.BindIP == b.BindIP && a.Port == b.Port && a.LinkHostOverride == b.LinkHostOverride &&
		a.StrangerAction == b.StrangerAction && a.MaskTarget == b.MaskTarget && a.NonTLSAction == b.NonTLSAction &&
		slices.Equal(a.TrustedCIDRs, b.TrustedCIDRs)
}

// DeleteListener deletes a listener that no proxy uses.
func (s *Service) DeleteListener(ctx context.Context, req *connect.Request[panelv1.DeleteListenerRequest]) (*connect.Response[panelv1.DeleteListenerResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	cur, err := s.db.ListenerByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, s.readError("listener", err)
	}
	_, err = s.mutate(ctx, cur.NodeID, func(nd *nodeData) (*step, error) {
		l := nd.listener(cur.ID)
		if l == nil {
			return nil, notFound("listener")
		}
		if err := checkHiddenMgmt(nd.node, l); err != nil {
			return nil, err
		}
		for _, p := range nd.proxies {
			if p.ListenerID == cur.ID {
				return nil, connect.NewError(connect.CodeFailedPrecondition,
					errors.New("proxies still use the listener: delete them or move them to another listener first"))
			}
		}
		return &step{unchecked: true, write: func(ctx context.Context) error { return s.db.DeleteListener(ctx, cur.ID) }}, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "listener.delete", "listener:"+cur.ID, cur.NodeID)
	s.log.Info("listener deleted", "listener", cur.ID, "node", cur.NodeID, "admin", admin.ID)
	return connect.NewResponse(&panelv1.DeleteListenerResponse{}), nil
}

// addressConflict returns the error for a listener l whose address cannot be
// next to the other listeners of its node: the same address, or 0.0.0.0 and a
// specific address on one port.
func addressConflict(listeners []*store.Listener, l *store.Listener) error {
	for _, o := range listeners {
		if o.ID == l.ID || o.Port != l.Port {
			continue
		}
		if sameIP(o.BindIP, l.BindIP) {
			return connect.NewError(connect.CodeAlreadyExists,
				fmt.Errorf("listener %s of the node has the address %s:%d", o.ID, o.BindIP, o.Port))
		}
		if isWildcard(o.BindIP) || isWildcard(l.BindIP) {
			return connect.NewError(connect.CodeAlreadyExists,
				fmt.Errorf("listener %s of the node is on %s:%d, and on one port the node listens either on 0.0.0.0 alone or on specific addresses only",
					o.ID, o.BindIP, o.Port))
		}
	}
	return nil
}

// portTakenBy returns the processes other than Postern that keep the edge from
// listening on bindIP and port, among the owners of ports that the node of the
// listener said there are (Node.HostInfo.PortOwners).
func portTakenBy(owners []store.PortOwner, bindIP string, port uint32) []*panelv1.PortOwner {
	ip, err := netip.ParseAddr(bindIP)
	if err != nil {
		return nil
	}
	var out []*panelv1.PortOwner
	for _, o := range owners {
		if o.Port == port && !o.Postern() && holds(o.Bind, ip.Unmap()) {
			out = append(out, &panelv1.PortOwner{Bind: o.Bind, Port: o.Port, Owner: o.Owner})
		}
	}
	return out
}

// holds reports whether a process that listens on the address bind keeps a
// listener on the IPv4 address ip from the same port: one of the two listens
// on every address (:: takes the IPv4 ones too, as Linux has it by default), or
// both on the same one. An IPv6 address of its own takes no IPv4 address.
func holds(bind string, ip netip.Addr) bool {
	b, err := netip.ParseAddr(bind)
	if err != nil {
		return false
	}
	switch b = b.Unmap(); {
	case b.IsUnspecified():
		return true
	case !b.Is4():
		return false
	}
	return ip.IsUnspecified() || b == ip
}

func sameIP(a, b string) bool {
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	if errX != nil || errY != nil {
		return a == b
	}
	return x == y
}

func isWildcard(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.IsUnspecified()
}

// optionalHost is checkHost for a host that may be empty.
func optionalHost(field, s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	return checkHost(field, s)
}

func listenerProto(l *store.Listener) *panelv1.Listener {
	return &panelv1.Listener{
		Id:               l.ID,
		NodeId:           l.NodeID,
		Kind:             l.Kind,
		BindIp:           l.BindIP,
		Port:             l.Port,
		LinkHostOverride: l.LinkHostOverride,
		StrangerAction:   l.StrangerAction,
		MaskTarget:       l.MaskTarget,
		NonTlsAction:     l.NonTLSAction,
		TrustedCidrs:     slices.Clone(l.TrustedCIDRs),
		CreatedUnix:      l.CreatedAt.Unix(),
		UpdatedUnix:      l.UpdatedAt.Unix(),
	}
}

// ---- ProxyService -------------------------------------------------------------

// ListProxies returns the proxies of a node, or of every node, that match the
// query.
func (s *Service) ListProxies(ctx context.Context, req *connect.Request[panelv1.ListProxiesRequest]) (*connect.Response[panelv1.ListProxiesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	ps, err := s.db.ListProxies(ctx, store.ProxyFilter{NodeID: req.Msg.GetNodeId()})
	if err != nil {
		return nil, s.fail("could not list the proxies", err)
	}
	vv, err := s.versionView(ctx)
	if err != nil {
		return nil, s.fail("could not read the versions", err)
	}
	query := strings.ToLower(strings.TrimSpace(req.Msg.GetQuery()))
	engine := strings.TrimSpace(req.Msg.GetEngine())
	out := make([]*panelv1.Proxy, 0, len(ps))
	for _, p := range ps {
		if query != "" && !matches(p, query) {
			continue
		}
		if engine != "" && cmp.Or(p.Engine, store.EngineTelemt) != engine {
			continue
		}
		n := vv.nodes[p.NodeID]
		if n == nil {
			continue // its node is gone meanwhile
		}
		// Each row carries the judgement of the outdated filter, so that the
		// mark of a row and the filter agree. Without the filter, a catalog
		// that cannot be read costs the marks, not the list.
		outdated, err := s.outdated(ctx, vv, n, p)
		if err != nil && req.Msg.GetOutdated() {
			return nil, s.fail("could not read the catalog", err)
		}
		if req.Msg.GetOutdated() && !outdated {
			continue
		}
		pp := s.proxyProto(p, n, vv.ch)
		pp.Outdated = outdated
		out = append(out, pp)
	}
	return connect.NewResponse(&panelv1.ListProxiesResponse{Proxies: out}), nil
}

// versionView is what the API form of a proxy takes besides the proxy: its
// node and the channel versions, read once per call.
type versionView struct {
	nodes  map[string]*store.Node
	ch     *channelData
	newest map[string]string // engine/channel/arch → the newest version, "" for none
}

// versionView reads the nodes and the channel data.
func (s *Service) versionView(ctx context.Context) (*versionView, error) {
	ns, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	ch, err := loadChannelData(ctx, s.db)
	if err != nil {
		return nil, err
	}
	vv := &versionView{nodes: make(map[string]*store.Node, len(ns)), ch: ch, newest: map[string]string{}}
	for _, n := range ns {
		vv.nodes[n.ID] = n
	}
	return vv, nil
}

// outdated reports whether a proxy is outdated: its node reports it served by
// another engine or version than the effective one, or the effective version
// is older than the newest release of its engine on its channel that the
// architecture of the node can run. A proxy that its node has not reported
// yet is judged by the newest release alone.
func (s *Service) outdated(ctx context.Context, vv *versionView, n *store.Node, p *store.Proxy) (bool, error) {
	eff := vv.ch.effective(n, p)
	if rep, ok := s.ingestor.ProxyReport(n.ID, p.ID); ok && rep.RunningVersion != "" {
		if rep.RunningVersion != eff.Version || (rep.RunningEngine != nodev1.Engine_ENGINE_UNSPECIFIED && engineName(rep.RunningEngine) != eff.Engine) {
			return true, nil
		}
	}
	arch := cmp.Or(n.Arch, defaultArch)
	channel := vv.ch.channel(n)
	key := eff.Engine + "/" + channel + "/" + arch
	newest, ok := vv.newest[key]
	if !ok {
		var err error
		if newest, err = s.catalog.Newest(ctx, eff.Engine, channel, []string{arch}); err != nil {
			return false, err
		}
		vv.newest[key] = newest
	}
	return newest != "" && newest != eff.Version && release.Newer(newest, eff.Version), nil
}

// proxyView is the API form of one proxy, with its node and the channel data
// read for it.
func (s *Service) proxyView(ctx context.Context, p *store.Proxy) (*panelv1.Proxy, error) {
	n, err := s.db.NodeByID(ctx, p.NodeID)
	if err != nil {
		return nil, err
	}
	ch, err := loadChannelData(ctx, s.db)
	if err != nil {
		return nil, err
	}
	return s.proxyProto(p, n, ch), nil
}

// proxyResponse is the API form of a proxy for the answer of a call about it,
// or the error to answer with.
func (s *Service) proxyResponse(ctx context.Context, p *store.Proxy) (*panelv1.Proxy, error) {
	out, err := s.proxyView(ctx, p)
	if err != nil {
		return nil, s.readError("node", err)
	}
	return out, nil
}

// matches reports whether the id, name, note or domain of a proxy contains
// query, which is in lower case.
func matches(p *store.Proxy, query string) bool {
	for _, field := range []string{p.ID, p.Name, p.Note, p.Domain} {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

// GetProxy returns one proxy.
func (s *Service) GetProxy(ctx context.Context, req *connect.Request[panelv1.GetProxyRequest]) (*connect.Response[panelv1.GetProxyResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	p, err := s.db.ProxyByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, s.readError("proxy", err)
	}
	out, err := s.proxyResponse(ctx, p)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.GetProxyResponse{Proxy: out}), nil
}

// CreateProxy adds an enabled fake-TLS proxy to a listener, on telemt or on
// mtg. An mtg proxy has no ad tag, no engine overrides and the middle proxies
// off, and sits on a listener whose mask target is a public IP, by the rules
// of the node (its validator says what is wrong); its node needs the
// capability engine-mtg.
func (s *Service) CreateProxy(ctx context.Context, req *connect.Request[panelv1.CreateProxyRequest]) (*connect.Response[panelv1.CreateProxyResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	p := &store.Proxy{
		ID:              ids.New(), // the secret is sealed for it
		NodeID:          msg.GetNodeId(),
		ListenerID:      msg.GetListenerId(),
		Enabled:         true,
		LimitDevices:    msg.GetLimits().GetDevices(),
		LimitConnsTotal: msg.GetLimits().GetConnsTotal(),
		LimitConnsPerIP: msg.GetLimits().GetConnsPerIp(),
	}
	if p.Engine, err = checkEngine(msg.GetEngine()); err != nil {
		return nil, err
	}
	if p.Type, err = checkProxyType(msg.GetType()); err != nil {
		return nil, err
	}
	web := p.Type == store.ProxyTypeWeb
	if p.Name, err = checkName(msg.GetName()); err != nil {
		return nil, err
	}
	if p.Note, err = checkNote(msg.GetNote()); err != nil {
		return nil, err
	}
	var webIn webSettings
	switch {
	case web:
		if p.Domain, err = checkWebDomain(msg.GetDomain()); err != nil {
			return nil, err
		}
		if webIn, err = checkWebSettings(msg.GetWeb()); err != nil {
			return nil, err
		}
	case msg.GetWeb() != nil:
		return nil, invalid("web settings are for a proxy of type web")
	case strings.TrimSpace(msg.GetDomain()) != "":
		if p.Domain, err = checkDomain(msg.GetDomain()); err != nil {
			return nil, err
		}
	}
	secret, err := s.secretOf(msg.GetSecret())
	if err != nil {
		return nil, err
	}
	if p.AdTag, err = checkAdTag(msg.GetAdTag()); err != nil {
		return nil, err
	}
	if p.UseMiddleProxy, err = checkMiddleProxy(msg.GetUseMiddleProxy()); err != nil {
		return nil, err
	}
	p.EgressChainID = strings.TrimSpace(msg.GetEgressChainId())
	if p.EgressScopeChains, err = checkScopeChains(msg.GetEgressScopeChains()); err != nil {
		return nil, err
	}
	if p.SecretEnc, err = seal.Seal(s.key, []byte(secret), SecretAAD(p.ID)); err != nil {
		return nil, s.fail("could not seal a proxy secret", err)
	}
	var warnings []string
	if web {
		// The lookup runs before the lock of the node data (mutate): a slow
		// resolver must not hold up the other mutations or the state builder.
		if warnings, err = s.preflightProxyDomain(ctx, p.NodeID, p.Domain); err != nil {
			return nil, err
		}
	}

	pushCert := false
	_, err = s.mutate(ctx, p.NodeID, func(nd *nodeData) (*step, error) {
		l := nd.listener(p.ListenerID)
		if l == nil {
			return nil, notFound("listener on the node")
		}
		if !web && l.Kind != store.ListenerKindTLS {
			return nil, invalid("a fake-TLS proxy needs a tls listener")
		}
		// The version is checked for the architecture of the node.
		var err error
		if p.EngineVersionPolicy, p.EngineVersion, err = s.checkVersion(ctx, p.Engine, msg.GetEngineVersion(), nd.node.Arch); err != nil {
			return nil, err
		}
		if err := checkProxyChains(nd, p); err != nil {
			return nil, err
		}
		used := domainsOn(nd, p.ListenerID, "")
		if p.Domain == "" {
			d, ok := pickDomain(s.pool, used)
			if !ok {
				return nil, errPoolUsedUp()
			}
			p.Domain = d
		} else if used[state.FoldDomain(p.Domain)] {
			return nil, errDomainTaken()
		}
		if web {
			if err := s.checkWebDomainFree(ctx, p.Domain, p.ID); err != nil {
				return nil, err
			}
			if pushCert, err = s.applyWeb(ctx, nd, p, webIn); err != nil {
				return nil, err
			}
		}
		nd.proxies = append(nd.proxies, p)
		nd.secrets[p.ID] = secret
		return &step{write: func(ctx context.Context) error { return s.db.CreateProxy(ctx, p) }}, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "proxy.create", "proxy:"+p.ID, p.NodeID)
	s.log.Info("proxy created", "proxy", p.ID, "node", p.NodeID, "listener", p.ListenerID, "type", p.Type, "engine", p.Engine, "admin", admin.ID)
	if pushCert && s.certs != nil {
		s.certs.PushCertificates(p.NodeID)
	}
	out, err := s.proxyResponse(ctx, p)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.CreateProxyResponse{Proxy: out, Warnings: append(warnings, s.certWarnings(p)...)}), nil
}

// UpdateProxy changes the fields that the request sets. It never changes the
// engine (a switch is a rollout), and refuses a change that the node would
// refuse, such as an ad tag on an mtg proxy, with the node's words.
func (s *Service) UpdateProxy(ctx context.Context, req *connect.Request[panelv1.UpdateProxyRequest]) (*connect.Response[panelv1.UpdateProxyResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	change, err := s.proxyChangeOf(req.Msg)
	if err != nil {
		return nil, err
	}
	cur, err := s.db.ProxyByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, s.readError("proxy", err)
	}
	var warnings []string
	if cur.Type == store.ProxyTypeWeb {
		// A new domain or listener of a WEB proxy is looked up before the
		// lock of the node data (see CreateProxy). The plan checks the domain
		// again (checkWebDomain) and the uniqueness, under the lock.
		domain := cur.Domain
		if change.domain != nil {
			if domain, err = checkWebDomain(*change.domain); err != nil {
				return nil, err
			}
		}
		if domain != cur.Domain || (change.listenerID != nil && *change.listenerID != cur.ListenerID) {
			if warnings, err = s.preflightProxyDomain(ctx, cur.NodeID, domain); err != nil {
				return nil, err
			}
		}
	}
	var (
		out      *store.Proxy
		changed  bool
		pushCert bool
	)
	_, beforeRun, err := s.mutateRun(ctx, cur.NodeID, func(nd *nodeData) (*step, error) {
		// The plan runs again after a before-run: it starts afresh.
		changed, pushCert = false, false
		p := nd.proxy(cur.ID)
		if p == nil {
			return nil, notFound("proxy")
		}
		out = p
		next, err := s.applyProxyChange(ctx, nd, p, change)
		if err != nil || next == nil {
			return nil, err
		}
		pushCert = next.CertSHA256 != p.CertSHA256
		hook := proxyEditHook(p.ID, pinOf(p), pinOf(next))
		*p = *next
		changed = true
		return &step{write: func(ctx context.Context) error { return s.db.UpdateProxy(ctx, p) }, hook: hook}, nil
	})
	if err != nil {
		return nil, err
	}
	if changed {
		s.audit(ctx, admin.ID, "proxy.update", "proxy:"+out.ID, out.NodeID)
	}
	if pushCert && s.certs != nil {
		s.certs.PushCertificates(out.NodeID)
	}
	resp, err := s.proxyResponse(ctx, out)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.UpdateProxyResponse{Proxy: resp, Warnings: append(warnings, s.certWarnings(out)...),
		BeforeRunId: beforeRun}), nil
}

// RestartInstance raises the restart nonce of a proxy by one: its node starts
// a new generation of the proxy's engine (the fix recreate_instance). It
// returns the desired generation that has it. Errors are Connect errors. The
// caller audits it.
func (s *Service) RestartInstance(ctx context.Context, proxyID string) (uint64, error) {
	cur, err := s.db.ProxyByID(ctx, proxyID)
	if err != nil {
		return 0, s.readError("proxy", err)
	}
	return s.mutate(ctx, cur.NodeID, func(nd *nodeData) (*step, error) {
		p := nd.proxy(cur.ID)
		if p == nil {
			return nil, notFound("proxy")
		}
		p.RestartNonce++
		next := *p
		return &step{write: func(ctx context.Context) error { return s.db.UpdateProxy(ctx, &next) }}, nil
	})
}

// ReissueCert raises the certificate reissue nonce of a WEB proxy (the fix
// reissue_cert): its node issues the certificate again, also a valid one. It
// is refused (FAILED_PRECONDITION) for a certificate the node does not issue:
// a proxy that is not WEB, one behind a web server (an http-upstream
// listener, where the web server in front owns the certificate), and one of
// cert_mode imported.
// It returns the node's desired generation that has the change.
func (s *Service) ReissueCert(ctx context.Context, proxyID string) (uint64, error) {
	cur, err := s.db.ProxyByID(ctx, proxyID)
	if err != nil {
		return 0, s.readError("proxy", err)
	}
	refuse := func(format string, args ...any) error {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(format, args...))
	}
	return s.mutate(ctx, cur.NodeID, func(nd *nodeData) (*step, error) {
		p := nd.proxy(cur.ID)
		if p == nil {
			return nil, notFound("proxy")
		}
		if p.Type != store.ProxyTypeWeb {
			return nil, refuse("the proxy is not a WEB proxy: it has no certificate of its own")
		}
		if l := nd.listener(p.ListenerID); l != nil && l.Kind == store.ListenerKindHTTPUpstream {
			return nil, refuse("the proxy is behind a web server: the web server in front owns the certificate of %s", p.Domain)
		}
		if p.CertMode != webrules.CertModeACME {
			return nil, refuse("the certificate of %s is imported (cert_mode %s): the node does not issue it; import a new one", p.Domain, p.CertMode)
		}
		p.CertReissueNonce++
		next := *p
		return &step{write: func(ctx context.Context) error { return s.db.UpdateProxy(ctx, &next) }}, nil
	})
}

// proxyChange is what UpdateProxy changes; nil fields stay. An empty domain
// is a new one from the pool; the secret is the new one, random already when
// the request asked for that. scopes are the new scope chains when setScopes
// is set.
type proxyChange struct {
	listenerID, name, note, domain, secret, adTag *string
	limits                                        *panelv1.ProxyLimits
	version                                       *string // the requested engine_version, checked against the node
	useMiddleProxy                                *string
	chain                                         *string
	scopes                                        map[string]string
	setScopes                                     bool
	// web are the new WEB settings when setWeb is set. The domain of a WEB
	// proxy, when given, was checked as one (checkWebDomain) only if the
	// request says so; the type is only known with the proxy, so the check
	// is made again then.
	web    webSettings
	setWeb bool
}

// proxyChangeOf checks the values of an UpdateProxy request.
func (s *Service) proxyChangeOf(msg *panelv1.UpdateProxyRequest) (proxyChange, error) {
	var c proxyChange
	if msg.ListenerId != nil {
		id := strings.TrimSpace(msg.GetListenerId())
		c.listenerID = &id
	}
	if msg.Name != nil {
		name, err := checkName(msg.GetName())
		if err != nil {
			return c, err
		}
		c.name = &name
	}
	if msg.Note != nil {
		note, err := checkNote(msg.GetNote())
		if err != nil {
			return c, err
		}
		c.note = &note
	}
	if msg.Domain != nil {
		d := ""
		if strings.TrimSpace(msg.GetDomain()) != "" {
			var err error
			if d, err = checkDomain(msg.GetDomain()); err != nil {
				return c, err
			}
		}
		c.domain = &d
	}
	if msg.Secret != nil {
		secret, err := s.secretOf(msg.GetSecret())
		if err != nil {
			return c, err
		}
		c.secret = &secret
	}
	if msg.Limits != nil {
		c.limits = msg.GetLimits()
	}
	if msg.AdTag != nil {
		tag, err := checkAdTag(msg.GetAdTag())
		if err != nil {
			return c, err
		}
		c.adTag = &tag
	}
	if msg.EngineVersion != nil {
		v := msg.GetEngineVersion()
		c.version = &v
	}
	if msg.UseMiddleProxy != nil {
		setting, err := checkMiddleProxy(msg.GetUseMiddleProxy())
		if err != nil {
			return c, err
		}
		c.useMiddleProxy = &setting
	}
	if msg.EgressChainId != nil {
		chain := strings.TrimSpace(msg.GetEgressChainId())
		c.chain = &chain
	}
	if msg.EgressScopeChains != nil {
		scopes, err := checkScopeChains(msg.GetEgressScopeChains().GetChains())
		if err != nil {
			return c, err
		}
		c.scopes, c.setScopes = scopes, true
	}
	if msg.Web != nil {
		web, err := checkWebSettings(msg.GetWeb())
		if err != nil {
			return c, err
		}
		c.web, c.setWeb = web, true
	}
	return c, nil
}

// proxyScopes are the scopes that a proxy can have chains of its own for: what
// an engine does, as the edge tells it (internal/edge/egress): "me", its
// connections to the middle proxies of Telegram, and "fetch", what it
// downloads.
var proxyScopes = []string{"fetch", "me"}

// checkScopeChains returns the scope chains of a request without the scopes
// that have no chain, and with the spaces around the ids taken away; nil for
// none. A scope that is not one of proxyScopes is invalid.
func checkScopeChains(m map[string]string) (map[string]string, error) {
	var out map[string]string
	for _, scope := range slices.Sorted(maps.Keys(m)) {
		if !slices.Contains(proxyScopes, scope) {
			return nil, invalid("egress_scope_chains: the scope %.32q is neither me nor fetch", scope)
		}
		chain := strings.TrimSpace(m[scope])
		if chain == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[scope] = chain
	}
	return out, nil
}

// checkProxyChains checks that the chain and the scope chains of a proxy are
// chains that its node can use: chains of every node, and its own.
func checkProxyChains(nd *nodeData, p *store.Proxy) error {
	check := func(field, id string) error {
		c := nd.eg.chains[id]
		switch {
		case c == nil:
			return connect.NewError(connect.CodeNotFound, fmt.Errorf("%s: no such egress chain", field))
		case !usableBy(c.NodeID, nd.node.ID):
			return invalid("%s: the egress chain belongs to another node", field)
		}
		return nil
	}
	if p.EgressChainID != "" {
		if err := check("egress_chain_id", p.EgressChainID); err != nil {
			return err
		}
	}
	for _, scope := range slices.Sorted(maps.Keys(p.EgressScopeChains)) {
		if err := check("egress_scope_chains["+scope+"]", p.EgressScopeChains[scope]); err != nil {
			return err
		}
	}
	return nil
}

// applyProxyChange returns p with the change made, or nil when the change
// changes nothing. It changes the secrets of nd for a new secret.
func (s *Service) applyProxyChange(ctx context.Context, nd *nodeData, p *store.Proxy, c proxyChange) (*store.Proxy, error) {
	next := *p
	web := p.Type == store.ProxyTypeWeb
	if c.setWeb && !web {
		return nil, invalid("web settings are for a proxy of type web")
	}
	if c.listenerID != nil && *c.listenerID != next.ListenerID {
		l := nd.listener(*c.listenerID)
		if l == nil {
			return nil, notFound("listener on the node")
		}
		if !web && l.Kind != store.ListenerKindTLS {
			return nil, invalid("a fake-TLS proxy needs a tls listener")
		}
		next.ListenerID = *c.listenerID
	}
	if c.name != nil {
		next.Name = *c.name
	}
	if c.note != nil {
		next.Note = *c.note
	}
	used := domainsOn(nd, next.ListenerID, p.ID)
	if c.domain != nil {
		d := *c.domain
		if web {
			var err error
			if d, err = checkWebDomain(d); err != nil {
				return nil, err
			}
		} else if d == "" {
			// A new domain: not the one that the proxy has either.
			taken := map[string]bool{state.FoldDomain(p.Domain): true}
			for k := range used {
				taken[k] = true
			}
			var ok bool
			if d, ok = pickDomain(s.pool, taken); !ok {
				return nil, errPoolUsedUp()
			}
		}
		next.Domain = d
	}
	if (next.ListenerID != p.ListenerID || next.Domain != p.Domain) && used[state.FoldDomain(next.Domain)] {
		return nil, errDomainTaken()
	}
	if c.limits != nil {
		next.LimitDevices, next.LimitConnsTotal, next.LimitConnsPerIP = c.limits.GetDevices(), c.limits.GetConnsTotal(), c.limits.GetConnsPerIp()
	}
	if c.adTag != nil {
		next.AdTag = *c.adTag
	}
	if c.version != nil {
		policy, version, err := s.checkVersion(ctx, next.Engine, *c.version, nd.node.Arch)
		if err != nil {
			return nil, err
		}
		next.EngineVersionPolicy, next.EngineVersion = policy, version
	}
	if c.useMiddleProxy != nil {
		next.UseMiddleProxy = *c.useMiddleProxy
	}
	if c.chain != nil || c.setScopes {
		if c.chain != nil {
			next.EgressChainID = *c.chain
		}
		if c.setScopes {
			next.EgressScopeChains = c.scopes
		}
		if err := checkProxyChains(nd, &next); err != nil {
			return nil, err
		}
	}
	if web {
		if next.Domain != p.Domain {
			if err := s.checkWebDomainFree(ctx, next.Domain, p.ID); err != nil {
				return nil, err
			}
		}
		// The settings are applied again whenever the listener or the
		// domain changes: what they allow depends on both (the certificate
		// is for the domain).
		if c.setWeb || next.ListenerID != p.ListenerID || next.Domain != p.Domain {
			w := c.web
			if !c.setWeb {
				w = webSettingsOf(p)
			}
			if _, err := s.applyWeb(ctx, nd, &next, w); err != nil {
				return nil, err
			}
		}
	}
	newSecret := false
	if c.secret != nil {
		if old, err := nd.secret(p.ID); err != nil || old != *c.secret {
			sealed, err := seal.Seal(s.key, []byte(*c.secret), SecretAAD(p.ID))
			if err != nil {
				return nil, s.fail("could not seal a proxy secret", err)
			}
			next.SecretEnc = sealed
			nd.secrets[p.ID] = *c.secret
			delete(nd.bad, p.ID)
			newSecret = true
		}
	}
	if !newSecret && sameProxy(&next, p) {
		return nil, nil
	}
	return &next, nil
}

// sameProxy reports whether two versions of a proxy have the same settings, the
// secret aside.
func sameProxy(a, b *store.Proxy) bool {
	return a.ListenerID == b.ListenerID && a.Name == b.Name && a.Note == b.Note && a.Domain == b.Domain &&
		a.LimitDevices == b.LimitDevices && a.LimitConnsTotal == b.LimitConnsTotal && a.LimitConnsPerIP == b.LimitConnsPerIP &&
		a.AdTag == b.AdTag && a.EngineVersionPolicy == b.EngineVersionPolicy && a.EngineVersion == b.EngineVersion &&
		a.UseMiddleProxy == b.UseMiddleProxy && a.Enabled == b.Enabled &&
		a.EgressChainID == b.EgressChainID && maps.Equal(a.EgressScopeChains, b.EgressScopeChains) &&
		a.WebBasePath == b.WebBasePath && a.WebSecretMode == b.WebSecretMode && a.WebCarrier == b.WebCarrier &&
		a.CertMode == b.CertMode && a.DNSCredentialID == b.DNSCredentialID && a.ACMEEmail == b.ACMEEmail &&
		a.CertSHA256 == b.CertSHA256
}

// webSettingsOf are the stored WEB settings of a proxy as a request would
// give them, without a certificate: applyWeb keeps the stored one then.
func webSettingsOf(p *store.Proxy) webSettings {
	return webSettings{
		basePath: p.WebBasePath, secretMode: p.WebSecretMode, carrier: p.WebCarrier,
		certMode: p.CertMode, dnsCredentialID: p.DNSCredentialID, acmeEmail: p.ACMEEmail,
	}
}

// DeleteProxy deletes a proxy.
func (s *Service) DeleteProxy(ctx context.Context, req *connect.Request[panelv1.DeleteProxyRequest]) (*connect.Response[panelv1.DeleteProxyResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	cur, err := s.db.ProxyByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, s.readError("proxy", err)
	}
	_, err = s.mutate(ctx, cur.NodeID, func(nd *nodeData) (*step, error) {
		if nd.proxy(cur.ID) == nil {
			return nil, notFound("proxy")
		}
		return &step{unchecked: true, write: func(ctx context.Context) error { return s.db.DeleteProxy(ctx, cur.ID) }}, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "proxy.delete", "proxy:"+cur.ID, cur.NodeID)
	s.log.Info("proxy deleted", "proxy", cur.ID, "node", cur.NodeID, "admin", admin.ID)
	return connect.NewResponse(&panelv1.DeleteProxyResponse{}), nil
}

// SetProxyEnabled pauses or resumes a proxy.
func (s *Service) SetProxyEnabled(ctx context.Context, req *connect.Request[panelv1.SetProxyEnabledRequest]) (*connect.Response[panelv1.SetProxyEnabledResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	enabled := req.Msg.GetEnabled()
	cur, err := s.db.ProxyByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, s.readError("proxy", err)
	}
	var (
		out     *store.Proxy
		changed bool
	)
	_, err = s.mutate(ctx, cur.NodeID, func(nd *nodeData) (*step, error) {
		p := nd.proxy(cur.ID)
		if p == nil {
			return nil, notFound("proxy")
		}
		out = p
		if p.Enabled == enabled {
			return nil, nil
		}
		p.Enabled = enabled
		changed = true
		return &step{unchecked: true, write: func(ctx context.Context) error { return s.db.UpdateProxy(ctx, p) }}, nil
	})
	if err != nil {
		return nil, err
	}
	if changed {
		action := "proxy.disable"
		if enabled {
			action = "proxy.enable"
		}
		s.audit(ctx, admin.ID, action, "proxy:"+out.ID, out.NodeID)
	}
	resp, err := s.proxyResponse(ctx, out)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.SetProxyEnabledResponse{Proxy: resp}), nil
}

// GetProxyLinks returns the links of a proxy and a QR code of the tg link, as
// [LinksOf] builds them.
func (s *Service) GetProxyLinks(ctx context.Context, req *connect.Request[panelv1.GetProxyLinksRequest]) (*connect.Response[panelv1.GetProxyLinksResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	p, err := s.db.ProxyByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, s.readError("proxy", err)
	}
	lk, err := LinksOf(ctx, s.db, s.key, p)
	switch {
	case errors.Is(err, ErrNoLinkHost):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, store.ErrNotFound):
		return nil, s.readError("listener or node of the proxy", err)
	case err != nil:
		return nil, s.fail("could not build the links of a proxy", err)
	}
	return connect.NewResponse(&panelv1.GetProxyLinksResponse{Tg: lk.TG, Https: lk.HTTPS, QrSvg: lk.QRSVG}), nil
}

// ErrNoLinkHost is the error of [LinksOf] for a fake-TLS proxy whose listener
// has no link host override and whose node has no link host: there is no
// address to put in a link.
var ErrNoLinkHost = errors.New("neither the listener nor the node has a host for links")

// Links are the links of a proxy, and the parameters that a client is given by
// hand, as they are in the link: for a fake-TLS proxy the host, the port and
// the fake-TLS secret ("ee", the secret, the domain in hex); for a WEB proxy
// the server (the domain, with the base path after a slash, not
// percent-encoded) and the secret of the link, and no port.
type Links struct {
	TG     string // the tg:// link
	HTTPS  string // the https://t.me/... link
	QRSVG  string // an SVG image of the QR code of TG
	Server string
	Port   string // "" for a WEB proxy
	Secret string
}

// LinksOf builds the links of a proxy, which carry its secret. A fake-TLS proxy
// is reached at the link host override of its listener, or else the link host
// of its node, on the port of the listener (links.FakeTLS); without either it
// is [ErrNoLinkHost]. A WEB proxy is reached at its domain and base path
// (links.Web), and needs no link host. The admin's links and the public page's
// are built here, so they are the same bytes.
//
// A listener or node that is gone is [store.ErrNotFound]. No error carries the
// secret. The QR codes of the newest 256 links are kept, by the text of the
// link, so that a page that is built for every request does not encode the
// same links again.
func LinksOf(ctx context.Context, db *store.DB, key seal.Key, p *store.Proxy) (Links, error) {
	secret, err := openSecret(key, p)
	if err != nil {
		return Links{}, err
	}
	var out Links
	if p.Type == store.ProxyTypeWeb {
		w := links.Web{Domain: p.Domain, BasePath: p.WebBasePath, SecretHex: secret, Mode: p.WebSecretMode}
		if out.TG, err = w.TG(); err != nil {
			return Links{}, fmt.Errorf("proxy %s: %w", p.ID, err)
		}
		out.HTTPS, _ = w.HTTPS()   // the same inputs as TG, which went through
		out.Secret, _ = w.Secret() // likewise
		out.Server = p.Domain
		if p.WebBasePath != "" {
			out.Server += "/" + p.WebBasePath
		}
	} else {
		l, err := db.ListenerByID(ctx, p.ListenerID)
		if err != nil {
			return Links{}, err
		}
		n, err := db.NodeByID(ctx, p.NodeID)
		if err != nil {
			return Links{}, err
		}
		host := cmp.Or(l.LinkHostOverride, n.LinkHost)
		if host == "" {
			return Links{}, ErrNoLinkHost
		}
		f := links.FakeTLS{Host: host, Port: uint16(l.Port), SecretHex: secret, Domain: p.Domain}
		out.TG, out.HTTPS = f.TG(), f.HTTPS()
		out.Server, out.Port, out.Secret = host, strconv.FormatUint(uint64(l.Port), 10), links.FakeTLSSecret(secret, p.Domain)
	}
	if out.QRSVG, err = qrs.get(out.TG); err != nil {
		return Links{}, err
	}
	return out, nil
}

// qrMemoSize is how many QR codes the memo keeps: at about 6 KB an image, a
// megabyte and a half at most.
const qrMemoSize = 256

// qrs is the memo of QR codes that LinksOf uses.
var qrs = &qrMemo{svgs: map[string]string{}}

// A qrMemo keeps the QR codes of the links that were asked for last, by the
// text of the link. When it is full the oldest entry goes.
type qrMemo struct {
	mu    sync.Mutex
	svgs  map[string]string
	order []string // the keys of svgs, oldest first
}

// get returns the QR code of text, from the memo or made now.
func (m *qrMemo) get(text string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if svg, ok := m.svgs[text]; ok {
		return svg, nil
	}
	svg, err := QRSVG(text)
	if err != nil {
		return "", err
	}
	if len(m.order) >= qrMemoSize {
		delete(m.svgs, m.order[0])
		m.order = m.order[1:]
	}
	m.svgs[text] = svg
	m.order = append(m.order, text)
	return svg, nil
}

// secretOf returns the secret that a request gives, checked, or a new random
// one when it gives none.
func (s *Service) secretOf(given string) (string, error) {
	if strings.TrimSpace(given) != "" {
		return checkSecret(given)
	}
	var b [secretHexLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", s.fail("could not make a proxy secret", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// checkEngine returns the engine of a new proxy: telemt when the request names
// none, else telemt or mtg.
func checkEngine(e string) (string, error) {
	switch e = strings.TrimSpace(e); e {
	case "":
		return store.EngineTelemt, nil
	case store.EngineTelemt, store.EngineMtg:
		return e, nil
	}
	return "", invalid("engine %.32q is not one the panel knows: telemt or mtg", e)
}

// checkVersion returns the version policy and the version of a proxy of an
// engine for the engine version that a request gives: none follows the
// channel of the node; one that the catalog knows is pinned, as long as the
// catalog has a pinned SHA-256 of it for the architecture of the node (the
// desired state names it by that). One without is refused as not pinned yet,
// and the catalog starts preparing it, so that a later request succeeds.
func (s *Service) checkVersion(ctx context.Context, engine, v, arch string) (policy, version string, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return store.EnginePolicyChannel, "", nil
	}
	engine = cmp.Or(engine, store.EngineTelemt)
	if !s.catalog.Known(ctx, engine, v) {
		return "", "", invalid("engine_version %.64q is not a version of %s that the panel knows", v, engine)
	}
	arch = cmp.Or(arch, defaultArch)
	switch _, err := s.catalog.Ref(ctx, engine, v, arch); {
	case errors.Is(err, releases.ErrNoPin), errors.Is(err, releases.ErrUnknown):
		s.catalog.Prepare(engine, v, arch)
		return "", "", connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("%s %s is not pinned yet for %s: the panel is preparing it; try again later", engine, v, arch))
	case err != nil:
		return "", "", s.fail("could not read the catalog", err)
	}
	return store.EnginePolicyPinned, v, nil
}

// domainsOn returns the domains of the proxies of a listener, folded (see
// state.FoldDomain), leaving out one proxy.
func domainsOn(nd *nodeData, listenerID, except string) map[string]bool {
	used := map[string]bool{}
	for _, p := range nd.proxies {
		if p.ListenerID == listenerID && p.ID != except {
			used[state.FoldDomain(p.Domain)] = true
		}
	}
	return used
}

// pickDomain picks a domain of the pool that is not taken, at random.
func pickDomain(pool []string, taken map[string]bool) (string, bool) {
	var free []string
	for _, d := range pool {
		if !taken[state.FoldDomain(d)] {
			free = append(free, d)
		}
	}
	if len(free) == 0 {
		return "", false
	}
	return free[mrand.IntN(len(free))], true //nolint:gosec // a pick among public domains, not a secret
}

func errPoolUsedUp() error {
	return connect.NewError(connect.CodeFailedPrecondition,
		errors.New("every domain of the pool is in use on the listener: give the proxy a domain"))
}

func errDomainTaken() error {
	return connect.NewError(connect.CodeAlreadyExists,
		errors.New("another proxy of the listener has the domain (letter case and a dot at the end aside)"))
}

// proxyProto is the API form of a proxy on its node. It has no secret.
func (s *Service) proxyProto(p *store.Proxy, n *store.Node, ch *channelData) *panelv1.Proxy {
	eff := ch.effective(n, p)
	return &panelv1.Proxy{
		Id:         p.ID,
		NodeId:     p.NodeID,
		ListenerId: p.ListenerID,
		Type:       p.Type,
		Name:       p.Name,
		Note:       p.Note,
		Enabled:    p.Enabled,
		Domain:     p.Domain,
		Limits: &panelv1.ProxyLimits{
			Devices:    p.LimitDevices,
			ConnsTotal: p.LimitConnsTotal,
			ConnsPerIp: p.LimitConnsPerIP,
		},
		AdTag:               p.AdTag,
		Engine:              eff.Engine,
		EngineVersion:       eff.Version,
		EngineVersionPinned: eff.Source == SourcePinned,
		VersionSource:       eff.Source,
		Channel:             ch.channel(n),
		UseMiddleProxy:      cmp.Or(p.UseMiddleProxy, store.MiddleProxyAuto),
		Status:              s.statusProto(p),
		CreatedUnix:         p.CreatedAt.Unix(),
		UpdatedUnix:         p.UpdatedAt.Unix(),
		EgressChainId:       p.EgressChainID,
		EgressScopeChains:   scopeChainsOf(p),
		Web:                 webProto(p),
	}
}

// statusProto is what the node of a proxy last reported about it.
func (s *Service) statusProto(p *store.Proxy) *panelv1.ProxyStatus {
	st, ok := s.ingestor.ProxyReport(p.NodeID, p.ID)
	if !ok {
		return &panelv1.ProxyStatus{Phase: phaseName(0)}
	}
	return &panelv1.ProxyStatus{
		Phase:              phaseName(st.Phase),
		Reason:             st.Reason,
		RunningVersion:     st.RunningVersion,
		InstanceGeneration: st.InstanceGeneration,
		ReportedUnix:       st.Reported.Unix(),
		RunningEngine:      engineName(st.RunningEngine),
		FailedVersion:      st.FailedVersion,
	}
}

// ---- versions -----------------------------------------------------------------

// AffectedByChannel returns the proxies of a node whose effective version would
// change if the node followed channel ("" for the default of the panel): what
// a change of the channel of the node, or of the default channel for a node
// without one, alters. The list is by proxy name, then id.
func (s *Service) AffectedByChannel(ctx context.Context, nodeID, channel string) ([]*panelv1.AffectedProxy, error) {
	n, err := s.db.NodeByID(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	ch, err := loadChannelData(ctx, s.db)
	if err != nil {
		return nil, err
	}
	ps, err := s.db.ListProxies(ctx, store.ProxyFilter{NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	var out []*panelv1.AffectedProxy
	for _, p := range ps {
		from := ch.effective(n, p)
		to := EffectiveVersion(p, channel, ch.defaultChannel, ch.versions)
		if from.Version == to.Version {
			continue
		}
		out = append(out, &panelv1.AffectedProxy{ProxyId: p.ID, Name: p.Name, NodeId: n.ID, FromVersion: from.Version, ToVersion: to.Version})
	}
	slices.SortFunc(out, func(a, b *panelv1.AffectedProxy) int {
		return cmp.Or(strings.Compare(a.GetName(), b.GetName()), strings.Compare(a.GetProxyId(), b.GetProxyId()))
	})
	return out, nil
}

// NotifyChannel raises the desired generation of every node on a channel
// ("" is every node on the default channel) and notifies the notifier: what a
// moved channel version (component) asks. The nodes are read and bumped
// under the lock of the node data.
func (s *Service) NotifyChannel(ctx context.Context, component, channel string) error {
	ns, err := s.db.ListNodes(ctx)
	if err != nil {
		return err
	}
	ch, err := loadChannelData(ctx, s.db)
	if err != nil {
		return err
	}
	var ids []string
	for _, n := range ns {
		if ch.channel(n) == cmp.Or(channel, ch.defaultChannel) {
			ids = append(ids, n.ID)
		}
	}
	s.log.Info("a channel moved; the nodes on it are told", "component", component, "channel", channel, "nodes", len(ids))
	return s.WriteVersions(ctx, func(context.Context) ([]string, error) { return ids, nil })
}

// WriteVersions is the locked path for writes that change what the proxies or
// the providers of nodes run without a mutation of their own (a channel
// change, the items of a rollout): it runs write under the lock of the node
// data, then raises the desired generation of every node that write returns
// and notifies the notifier, so that a state built after the write has it.
// The nodes to bump are decided by write, under the lock, so that a change of
// the channel table meanwhile cannot make the set stale. A node that is gone
// is skipped. The write and the bumps run to their end once they start.
func (s *Service) WriteVersions(ctx context.Context, write func(ctx context.Context) (bump []string, err error)) error {
	nodeDataMu.Lock()
	defer nodeDataMu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	nodeIDs, err := write(ctx)
	if err != nil {
		return err
	}
	for _, id := range slices.Compact(slices.Sorted(slices.Values(nodeIDs))) {
		if _, err := s.nextGen(ctx, id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return fmt.Errorf("raise the desired generation of node %s: %w", id, err)
		}
		if s.notifier != nil {
			s.notifier.Notify(id)
		}
	}
	return nil
}

// ---- StatsService -------------------------------------------------------------

// ProxyLive returns the latest minute and the status of a proxy.
func (s *Service) ProxyLive(ctx context.Context, req *connect.Request[panelv1.ProxyLiveRequest]) (*connect.Response[panelv1.ProxyLiveResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	p, err := s.db.ProxyByID(ctx, req.Msg.GetProxyId())
	if err != nil {
		return nil, s.readError("proxy", err)
	}
	resp := &panelv1.ProxyLiveResponse{Status: s.statusProto(p)}
	if m, ok := s.ingestor.minuteOf(p.NodeID, p.ID); ok {
		resp.Minute = &panelv1.LiveMinute{
			MinuteUnix:  m.minute.Unix(),
			Up:          m.up,
			Down:        m.down,
			ConnsNew:    m.connsNew,
			ConnsPeak:   m.connsPeak,
			Devices:     m.devices,
			ConnsActive: m.connsActive,
		}
	}
	return connect.NewResponse(resp), nil
}

// ProxySeries returns the traffic of a proxy over a range of time that ends
// at the end of the current period.
func (s *Service) ProxySeries(ctx context.Context, req *connect.Request[panelv1.ProxySeriesRequest]) (*connect.Response[panelv1.ProxySeriesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	span, err := SeriesSpan(req.Msg.GetRange())
	if err != nil {
		return nil, err
	}
	p, err := s.db.ProxyByID(ctx, req.Msg.GetProxyId())
	if err != nil {
		return nil, s.readError("proxy", err)
	}
	settings, _, err := s.db.StatsSettings(ctx)
	if err != nil {
		return nil, s.fail("could not read the statistics settings", err)
	}
	from, to, step := SeriesWindow(span, s.now(), settings.Retention())
	stats, err := s.db.ProxySeries(ctx, p.ID, from, to, settings.Retention())
	if err != nil {
		return nil, s.fail("could not read the statistics of a proxy", err)
	}
	points := make([]*panelv1.SeriesPoint, 0, len(stats))
	for _, st := range stats {
		points = append(points, &panelv1.SeriesPoint{
			TsUnix:    st.TS.Unix(),
			Up:        st.Up,
			Down:      st.Down,
			ConnsNew:  st.ConnsNew,
			ConnsPeak: st.ConnsPeak,
			Devices:   st.Devices,
		})
	}
	return connect.NewResponse(&panelv1.ProxySeriesResponse{
		StepSeconds: uint32(step / time.Second),
		FromUnix:    from.Unix(),
		ToUnix:      to.Unix(),
		Points:      points,
	}), nil
}

// The ranges of the statistics API, by name: how far back a series or a total
// reaches. "1y" is 365 days.
var seriesSpans = map[string]time.Duration{
	"1h":  time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour,
	"1y":  365 * 24 * time.Hour,
}

// SeriesSpan returns how far back the range of a series or a total named r
// reaches: "1h", "24h" (also what "" means), "7d", "30d", "90d" or "1y". Any
// other name is an INVALID_ARGUMENT error for the caller.
func SeriesSpan(r string) (time.Duration, error) {
	if r == "" {
		r = "24h"
	}
	span, ok := seriesSpans[r]
	if !ok {
		return 0, invalid("range must be 1h, 24h, 7d, 30d, 90d or 1y")
	}
	return span, nil
}

// SeriesWindow returns the periods [from, to) of a series over span at now,
// and their step: the step is the resolution that the store reads for the span
// by the retention r (store.SeriesStep: minutes while the span fits the
// minutes that are kept, hours while it fits the hours, days beyond), and the
// periods end at the end of the current one (UTC), so that the latest point
// is the period that now is in.
func SeriesWindow(span time.Duration, now time.Time, r store.Retention) (from, to time.Time, step time.Duration) {
	step = store.SeriesStep(span, r)
	to = now.UTC().Truncate(step).Add(step)
	return to.Add(-span), to, step
}

// OpenSecret returns the secret of a proxy in the form it is sealed, handed to
// the nodes and taken out by the scrubber of diagnostics: its 32 hex digits
// (SecretAAD is its additional data). Never log it.
func OpenSecret(key seal.Key, p *store.Proxy) (string, error) { return openSecret(key, p) }
