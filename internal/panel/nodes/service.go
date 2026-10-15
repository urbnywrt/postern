package nodes

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/version"
)

// Limits on what an admin types.
const (
	maxNameChars = 64
	maxNoteChars = 1024
	maxHostLen   = 253 // a DNS name
	maxLabelLen  = 63

	// A management port of 0 is a random port in this range: high, and above
	// the range that Linux hands out to outgoing connections by default
	// (32768-60999), so that the agent does not find it taken by one of them.
	randomPortMin = 61000
	randomPortMax = 65535
)

// errInternal is all that a caller is told of an error of the panel itself.
// What it was is in the log.
var errInternal = errors.New("internal error")

// Notifier is told when a node is created, changed or deleted. The Manager is
// one: it connects to a new node, reconnects to a node whose address changed,
// and lets a deleted node go.
type Notifier interface {
	Notify(nodeID string)
}

// Service is the NodeService of the panel, and the downloads of node bundles
// and of the node kit (see [Service.BundleHandler] and [Service.KitHandler]).
//
// Every call needs an admin: the auth middleware refuses calls without a
// session, and the service checks again, so that it is safe however it is
// mounted.
type Service struct {
	db        *store.DB
	key       seal.Key
	ca        *pki.CA
	notifier  Notifier
	log       *slog.Logger
	kitDir    string       // the directory of the node kit, see WithKitDir; "" for none
	kitSrc    KitSource    // the binary of the kit, see WithKitSource; nil: the image's
	switcher  MgmtSwitcher // see WithMgmtSwitcher; nil for none
	nodeImage string       // the node image of the one-command install, see WithNodeImage; "" for none
	// sources writes artifact_source (SetArtifactSourceWriter); nil refuses it.
	sources ArtifactSourceWriter
	// states writes what the state of a node is made of under the lock of the
	// node data (SetStateWriter); nil writes it directly.
	states StateWriter
	// joinLimits counts the failed joins per client address (see Join).
	joinLimits *auth.Limiter
	// callerIP is the address of the client of a request; auth.CallerIP, but
	// for tests that call the service directly.
	callerIP func(context.Context) (netip.Addr, bool)
	// joinHostOK tells whether a join from an address may take it as the
	// management address of a node that has none; publicUnicast but for tests.
	joinHostOK func(netip.Addr) bool
	// cloudflare are the ranges of Cloudflare (WithCloudflareRanges); nil for
	// none.
	cloudflare AddrRanges
	// kitTimeoutOverride replaces the write timeout of a kit download, the
	// constant kitWriteTimeout, when it is more than zero: tests make it
	// shorter. See kitTimeout.
	kitTimeoutOverride time.Duration
}

var _ panelv1connect.NodeServiceHandler = (*Service)(nil)

// NewService returns the NodeService on the database. ca issues the
// certificates of new nodes, key seals their private keys, and n, which may be
// nil, is told about every node that changes. A nil log discards the log.
// Without [WithKitDir] among opts the panel has no node kit.
func NewService(db *store.DB, key seal.Key, ca *pki.CA, n Notifier, log *slog.Logger, opts ...Option) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		db: db, key: key, ca: ca, notifier: n, log: log,
		joinLimits: auth.NewLimiter(), callerIP: auth.CallerIP, joinHostOK: publicUnicast,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// notify tells the notifier about a node, if there is one.
func (s *Service) notify(nodeID string) {
	if s.notifier != nil {
		s.notifier.Notify(nodeID)
	}
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

// storeError maps the errors of the store that a caller can act on.
func (s *Service) storeError(what string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("no such node"))
	case errors.Is(err, store.ErrConflict):
		return connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the node is still in use: an egress chain of it is used by another node or a proxy of another node"))
	}
	return s.fail(what, err)
}

func invalid(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

// audit records what an admin did. A failure is logged and does not fail the
// call: what it records has happened.
func (s *Service) audit(ctx context.Context, adminID, action, nodeID string) {
	s.auditDetails(ctx, adminID, action, nodeID, nil)
}

// auditDetails is audit with details.
func (s *Service) auditDetails(ctx context.Context, adminID, action, nodeID string, details map[string]string) {
	entry := &store.AuditEntry{AdminID: adminID, Action: action, Target: "node:" + nodeID, Details: details}
	if err := s.db.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		s.log.Error("could not write the audit log", "action", action, "node", nodeID, "err", err)
	}
}

// ListNodes returns every node, in the order they were created.
func (s *Service) ListNodes(ctx context.Context, _ *connect.Request[panelv1.ListNodesRequest]) (*connect.Response[panelv1.ListNodesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	list, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, s.storeError("could not list the nodes", err)
	}
	def := defaultChannel(ctx, s.db)
	if err != nil {
		return nil, s.fail("could not list the nodes", err)
	}
	out := make([]*panelv1.Node, 0, len(list))
	for _, n := range list {
		out = append(out, toProto(n, def))
	}
	return connect.NewResponse(&panelv1.ListNodesResponse{Nodes: out}), nil
}

// GetNode returns one node.
func (s *Service) GetNode(ctx context.Context, req *connect.Request[panelv1.GetNodeRequest]) (*connect.Response[panelv1.GetNodeResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	n, err := s.db.NodeByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, s.storeError("could not read a node", err)
	}
	return connect.NewResponse(&panelv1.GetNodeResponse{Node: s.proto(ctx, n)}), nil
}

// CreateNode adds a node and issues its certificate.
func (s *Service) CreateNode(ctx context.Context, req *connect.Request[panelv1.CreateNodeRequest]) (*connect.Response[panelv1.CreateNodeResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	n, err := s.createNode(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "node.create", n.ID)
	s.log.Info("node created", "node", n.ID, "admin", admin.ID)
	return connect.NewResponse(&panelv1.CreateNodeResponse{
		Node:           s.proto(ctx, n),
		BundleUrl:      BundleURL(n.ID),
		InstallCommand: installCommand,
	}), nil
}

// createNode validates the request, issues the certificate of the node, stores
// the node and tells the notifier. Its errors are Connect errors.
func (s *Service) createNode(ctx context.Context, msg *panelv1.CreateNodeRequest) (*store.Node, error) {
	name, err := checkName(msg.GetName())
	if err != nil {
		return nil, err
	}
	// An empty management address is allowed: a node that joins with a token
	// gets the address it joins from (see Join), or an admin fills it in later.
	var mgmtHost string
	if strings.TrimSpace(msg.GetMgmtHost()) != "" {
		if mgmtHost, err = checkHost("mgmt_host", msg.GetMgmtHost()); err != nil {
			return nil, err
		}
	}
	port := msg.GetMgmtPort()
	switch {
	case port == 0:
		port = uint32(randomPortMin + rand.IntN(randomPortMax-randomPortMin+1)) //nolint:gosec // a port number, not a secret
	case port > 65535:
		return nil, invalid("mgmt_port must be 1 to 65535")
	}
	linkHost := mgmtHost
	if strings.TrimSpace(msg.GetLinkHost()) != "" {
		if linkHost, err = checkHost("link_host", msg.GetLinkHost()); err != nil {
			return nil, err
		}
	}

	// The id is made here because the certificate names it.
	id := ids.New()
	certPEM, keyPEM, err := s.ca.IssueServer(nodeCommonName(id), []string{nodeDNSName(id)}, nil)
	if err != nil {
		return nil, s.fail("could not issue a node certificate", err)
	}
	fingerprint, err := pki.Fingerprint(certPEM)
	if err != nil {
		return nil, s.fail("could not take the fingerprint of a node certificate", err)
	}
	keyEnc, err := seal.Seal(s.key, keyPEM, nodeKeyAAD(id))
	clear(keyPEM)
	if err != nil {
		return nil, s.fail("could not seal a node key", err)
	}

	n := &store.Node{
		ID:              id,
		Name:            name,
		MgmtHost:        mgmtHost,
		MgmtPort:        port,
		LinkHost:        linkHost,
		CertFingerprint: fingerprint,
		CertPEM:         string(certPEM),
		KeyEnc:          keyEnc,
		Status:          store.NodeStatusProvisioning,
	}
	if err := s.db.CreateNode(ctx, n); err != nil {
		return nil, s.fail("could not store a node", err)
	}
	s.notify(n.ID)
	return n, nil
}

// UpdateNode changes the fields that the request sets.
func (s *Service) UpdateNode(ctx context.Context, req *connect.Request[panelv1.UpdateNodeRequest]) (*connect.Response[panelv1.UpdateNodeResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg

	// Everything is checked before the node is read, so that the change itself
	// is a quick read-modify-write that does not undo what the connection
	// manager writes at the same time.
	var change nodeChange
	if msg.Name != nil {
		name, err := checkName(msg.GetName())
		if err != nil {
			return nil, err
		}
		change.name = &name
	}
	if msg.MgmtHost != nil {
		host, err := checkHost("mgmt_host", msg.GetMgmtHost())
		if err != nil {
			return nil, err
		}
		change.mgmtHost = &host
	}
	if msg.MgmtPort != nil {
		port := msg.GetMgmtPort()
		if port < 1 || port > 65535 {
			return nil, invalid("mgmt_port must be 1 to 65535")
		}
		change.mgmtPort = &port
	}
	if msg.LinkHost != nil {
		host := ""
		if strings.TrimSpace(msg.GetLinkHost()) != "" {
			if host, err = checkHost("link_host", msg.GetLinkHost()); err != nil {
				return nil, err
			}
		}
		change.linkHost = &host
	}
	if msg.Note != nil {
		note, err := checkNote(msg.GetNote())
		if err != nil {
			return nil, err
		}
		change.note = &note
	}
	if msg.ArtifactSource != nil {
		if err := s.writeArtifactSource(ctx, msg.GetId(), msg.GetArtifactSource()); err != nil {
			return nil, err
		}
	}

	n, err := s.db.ModifyNode(ctx, msg.GetId(), change.apply)
	if err != nil {
		return nil, s.storeError("could not update a node", err)
	}
	s.notify(n.ID)
	s.audit(ctx, admin.ID, "node.update", n.ID)
	return connect.NewResponse(&panelv1.UpdateNodeResponse{Node: s.proto(ctx, n)}), nil
}

// nodeChange is what UpdateNode changes; nil fields stay.
type nodeChange struct {
	name, mgmtHost, linkHost, note *string
	mgmtPort                       *uint32
}

// apply changes a node. It runs inside the write transaction of ModifyNode.
func (c nodeChange) apply(n *store.Node) error {
	if c.name != nil {
		n.Name = *c.name
	}
	if c.mgmtHost != nil {
		n.MgmtHost = *c.mgmtHost
	}
	if c.mgmtPort != nil {
		n.MgmtPort = *c.mgmtPort
	}
	if c.linkHost != nil {
		n.LinkHost = *c.linkHost
		if n.LinkHost == "" {
			n.LinkHost = n.MgmtHost
		}
	}
	if c.note != nil {
		n.Note = *c.note
	}
	return nil
}

// DeleteNode deletes a node with everything that belongs to it.
func (s *Service) DeleteNode(ctx context.Context, req *connect.Request[panelv1.DeleteNodeRequest]) (*connect.Response[panelv1.DeleteNodeResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetId()
	if err := s.db.DeleteNode(ctx, id); err != nil {
		return nil, s.storeError("could not delete a node", err)
	}
	s.notify(id)
	s.audit(ctx, admin.ID, "node.delete", id)
	s.log.Info("node deleted", "node", id, "admin", admin.ID)
	return connect.NewResponse(&panelv1.DeleteNodeResponse{}), nil
}

// GetNodeInstall says how to install a node by hand: its bundle, the node kit
// of each architecture, whether the panel has it, and the install command.
// Whether a kit is there is looked at for each call.
func (s *Service) GetNodeInstall(ctx context.Context, req *connect.Request[panelv1.GetNodeInstallRequest]) (*connect.Response[panelv1.GetNodeInstallResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	n, err := s.db.NodeByID(ctx, req.Msg.GetNodeId())
	if err != nil {
		return nil, s.storeError("could not read a node", err)
	}
	kits := make([]*panelv1.NodeKit, 0, len(kitArches))
	for _, arch := range kitArches {
		kits = append(kits, &panelv1.NodeKit{
			Arch:      arch,
			Url:       KitURL(arch),
			Available: s.kitAvailable(arch),
			// The binary of the kit is built with the panel, so it has its
			// version.
			Version: version.Version,
		})
	}
	return connect.NewResponse(&panelv1.GetNodeInstallResponse{
		BundleUrl:      BundleURL(n.ID),
		Kits:           kits,
		InstallCommand: installCommand,
		NodeImage:      s.nodeImage,
	}), nil
}

// ToProto is the API form of a node, for the services that answer with one.
// db gives the default channel of the panel, for the engine channel of a node
// that has none of its own.
func ToProto(ctx context.Context, db *store.DB, n *store.Node) *panelv1.Node {
	return toProto(n, defaultChannel(ctx, db))
}

// proto is the API form of a node.
func (s *Service) proto(ctx context.Context, n *store.Node) *panelv1.Node {
	return toProto(n, defaultChannel(ctx, s.db))
}

// defaultChannel is the channel that nodes without one of their own follow:
// the setting versions.default_channel, stable when it is not set. An error
// of reading it is logged nowhere: the answer is for display, and stable is
// what the setting means when it is missing.
func defaultChannel(ctx context.Context, db *store.DB) string {
	def := store.ChannelStable
	if _, err := db.GetSetting(ctx, store.SettingDefaultChannel, &def); err != nil || def == "" {
		return store.ChannelStable
	}
	return def
}

// toProto is the API form of a node, with defaultChannel the channel of the
// panel for a node without one. It carries nothing secret: no key, and no
// certificate either, which is not a secret but has no use in the API.
func toProto(n *store.Node, defaultChannel string) *panelv1.Node {
	out := &panelv1.Node{
		Id:                   n.ID,
		Name:                 n.Name,
		MgmtHost:             n.MgmtHost,
		MgmtPort:             n.MgmtPort,
		LinkHost:             n.LinkHost,
		Status:               n.Status,
		AgentVersion:         n.AgentVersion,
		EdgeVersion:          n.EdgeVersion,
		Arch:                 n.Arch,
		Os:                   n.HostInfo.OS,
		PublicIps:            n.PublicIPs,
		DesiredGeneration:    n.DesiredGeneration,
		AppliedGeneration:    n.AppliedGeneration,
		Note:                 n.Note,
		LastError:            lastError(n),
		Capabilities:         n.HostInfo.Capabilities,
		DefaultChainId:       n.DefaultChainID,
		DnsMode:              n.DNSMode,
		EngineChannel:        cmp.Or(n.EngineChannel, defaultChannel),
		EngineChannelDefault: n.EngineChannel == "",
		MgmtMode:             n.MgmtMode,
		MgmtSni:              n.MgmtSNI,
		MgmtPublicPort:       n.MgmtPublicPort,
		PreviousAgentVersion: n.HostInfo.Binaries.Previous,
		NodeBinaries:         n.HostInfo.Binaries.Versions,
		Healthy:              n.HostInfo.Healthy,
		Warnings:             n.HostInfo.Warnings,
		ArtifactSource:       cmp.Or(n.ArtifactSource, store.ArtifactSourcePanel),
		PanelAddrs:           slices.Clone(n.PanelAddrs),
	}
	for _, o := range n.HostInfo.PortOwners {
		out.PortOwners = append(out.PortOwners, &panelv1.PortOwner{Bind: o.Bind, Port: o.Port, Owner: o.Owner, Postern: o.Postern()})
	}
	if n.LastSeenAt != nil {
		out.LastSeenUnix = n.LastSeenAt.Unix()
	}
	return out
}

// lastError is why a node does not run the state that the panel wants it to:
// why it refused the desired state of the panel, which is about the newest
// state, before why its last pass failed, which is about an older one then.
func lastError(n *store.Node) string {
	if n.StateRejection != "" {
		return "the node refused the desired state of the panel: " + n.StateRejection
	}
	return n.LastError
}

// checkName returns the name without the spaces around it: 1 to 64
// characters of valid UTF-8 and no control characters.
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

// checkNote accepts a note of at most 1024 characters of valid UTF-8.
func checkNote(s string) (string, error) {
	switch {
	case !utf8.ValidString(s):
		return "", invalid("note is not valid UTF-8")
	case utf8.RuneCountInString(s) > maxNoteChars:
		return "", invalid("note has more than %d characters", maxNoteChars)
	}
	return s, nil
}

// checkHost returns the host without the spaces around it, if it is an IP
// address or a host name. field names it in the error.
func checkHost(field, s string) (string, error) {
	host := strings.TrimSpace(s)
	if host == "" {
		return "", invalid("%s is empty", field)
	}
	if !validHost(host) {
		return "", invalid("%s must be an IP address (IPv6 without brackets) or a host name, without a scheme, port or path", field)
	}
	return host, nil
}

// validHost reports whether host is an IP address without a zone, or a host
// name: dot-separated labels of 1 to 63 letters, digits and hyphens, which do
// not start or end with a hyphen, at most 253 characters in all, and a last
// label that is not all digits (that would be a mistyped IPv4 address).
func validHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	if len(host) > maxHostLen {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.ContainsFunc(last, func(r rune) bool { return r < '0' || r > '9' })
}

// ArtifactSourceWriter stores where a node gets its artifacts, "panel" or
// "direct" ("" is panel), refusing direct for a node without the capability
// artifact-direct, and raises the desired generation of the node when it
// changes. Errors are Connect errors whose message says why.
// proxies.Service is the one.
type ArtifactSourceWriter interface {
	WriteArtifactSource(ctx context.Context, nodeID, source string) error
}

// SetArtifactSourceWriter sets what UpdateNode writes artifact_source with.
// Call it before the service serves.
func (s *Service) SetArtifactSourceWriter(w ArtifactSourceWriter) { s.sources = w }

// writeArtifactSource writes the artifact source of a node, before the rest
// of an UpdateNode, so that a refusal changes nothing.
func (s *Service) writeArtifactSource(ctx context.Context, nodeID, source string) error {
	switch strings.TrimSpace(source) {
	case "", store.ArtifactSourcePanel, store.ArtifactSourceDirect:
	default:
		return invalid("artifact_source must be %s or %s", store.ArtifactSourcePanel, store.ArtifactSourceDirect)
	}
	if s.sources == nil {
		return connect.NewError(connect.CodeUnimplemented, errors.New("this panel cannot change where nodes get their artifacts"))
	}
	err := s.sources.WriteArtifactSource(ctx, nodeID, strings.TrimSpace(source))
	var ce *connect.Error
	if err != nil && !errors.As(err, &ce) {
		return s.storeError("could not change where a node gets its artifacts", err)
	}
	return err
}

// StateWriter writes, under the lock of the node data, what the desired state
// of nodes is made of, then raises the desired generation of the nodes that
// write returns and notifies them. proxies.Service.WriteVersions is the one.
type StateWriter interface {
	WriteVersions(ctx context.Context, write func(ctx context.Context) (bump []string, err error)) error
}

// SetStateWriter sets what RollEdge writes with. Call it before the service
// serves.
func (s *Service) SetStateWriter(w StateWriter) { s.states = w }

// RollEdge raises the edge roll nonce of a node by one: the node starts a new
// generation of its edge beside the running one (the fix roll_edge). It
// returns the desired generation of the node that has it. It never touches a
// version or a rollout. Errors are Connect errors; the caller audits it.
func (s *Service) RollEdge(ctx context.Context, nodeID string) (uint64, error) {
	write := func(ctx context.Context) ([]string, error) {
		if _, err := s.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
			n.EdgeRollNonce++
			return nil
		}); err != nil {
			return nil, err
		}
		return []string{nodeID}, nil
	}
	var err error
	if s.states != nil {
		err = s.states.WriteVersions(ctx, write)
	} else if _, err = write(ctx); err == nil {
		if _, err = s.db.NextNodeGeneration(ctx, nodeID); err == nil {
			s.notify(nodeID)
		}
	}
	if err != nil {
		return 0, s.storeError("could not roll the edge of a node", err)
	}
	n, err := s.db.NodeByID(ctx, nodeID)
	if err != nil {
		return 0, s.storeError("could not read a node", err)
	}
	return n.DesiredGeneration, nil
}
