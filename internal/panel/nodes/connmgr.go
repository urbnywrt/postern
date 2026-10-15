package nodes

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
)

// timing is how the manager paces itself. Tests make it quicker.
type timing struct {
	minBackoff     time.Duration // the first wait before connecting or pushing again; the waits double from it
	maxBackoff     time.Duration // the longest of those waits
	offlineAfter   time.Duration // how long an online node may be disconnected before it is offline
	stableAfter    time.Duration // a connection that lasted this long is reconnected without waiting long
	dialTimeout    time.Duration // the TCP connection and the TLS handshake, each
	callTimeout    time.Duration // GetInfo and ApplyState
	resyncEvery    time.Duration // how often a connected node is asked again whether it has its state
	ingestAttempts int           // how often a record is offered to the ingestor before it is skipped
	switchTimeout  time.Duration // how long a switch of the management mode may take (SetMgmtMode)
	switchPoll     time.Duration // how often a switch looks whether the node applied its state
}

var defaultTiming = timing{
	minBackoff:     time.Second,
	maxBackoff:     time.Minute,
	offlineAfter:   30 * time.Second,
	stableAfter:    30 * time.Second,
	dialTimeout:    10 * time.Second,
	callTimeout:    30 * time.Second,
	resyncEvery:    5 * time.Minute,
	ingestAttempts: 3,
	switchTimeout:  time.Minute,
	switchPoll:     250 * time.Millisecond,
}

const (
	// The HTTP/2 health check of a connection: a ping when nothing has come
	// for pingAfter, and the connection is dropped when the answer takes
	// longer than pingTimeout. A node that vanishes without closing the
	// connection is noticed this way.
	pingAfter   = 15 * time.Second
	pingTimeout = 10 * time.Second

	// maxMessage bounds a message from a node, so that no node can make the
	// panel allocate without bound.
	maxMessage = 16 << 20

	// maxGenerationGap is how far the desired generation of the panel may be
	// behind the one that a node has for the manager to move it past by
	// itself. More is not a restored backup but a node that is wrong, or
	// hostile, and is left for an operator.
	maxGenerationGap = 1000

	// Bounds on what the panel stores of what a node says about itself.
	maxInfoLen       = 256
	maxPublicIPs     = 32
	maxReasonLen     = 1024
	maxCapabilities  = 32
	maxCapabilityLen = 64
	maxPortOwners    = 256
	maxOwnerLen      = 128
)

// The severities of the events that the manager records.
const (
	severityInfo  = "info"
	severityWarn  = "warn"
	severityError = "error"
)

var (
	// ErrUnknownNode is returned by [Manager.Client] for a node that the
	// manager does not know: it does not exist, or the manager has not
	// started.
	ErrUnknownNode = errors.New("nodes: unknown node")

	// ErrNotConnected is returned by [Manager.Client] for a node that the
	// manager is not connected to at the moment.
	ErrNotConnected = errors.New("nodes: the node is not connected")

	// errReconnect ends a session whose node has a new address or pin.
	errReconnect = errors.New("the connection settings of the node changed")

	// errNodeGone ends a session whose node was deleted.
	errNodeGone = errors.New("the node was deleted")

	// errUnchanged makes ModifyNode write nothing.
	errUnchanged = errors.New("unchanged")

	// errGenerationGap is a node that is too far ahead of the panel for the
	// manager to catch up with by itself.
	errGenerationGap = fmt.Errorf("the node is more than %d generations ahead of the panel", maxGenerationGap)
)

// StateBuilder builds the desired state of a node for a generation.
type StateBuilder interface {
	Build(ctx context.Context, nodeID string, generation uint64) (*nodev1.NodeState, error)
}

// Ingestor stores the records that nodes stream: state reports, statistics
// and events. It gets every record, state reports included; the manager
// itself takes the applied generation from state reports. A record may come
// more than once (after the panel was stopped between storing it and moving
// the cursor past it), so storing it has to be idempotent where that matters.
type Ingestor interface {
	OnWatch(ctx context.Context, nodeID string, ev *nodev1.WatchResponse) error
}

// NodeForgetter is an Ingestor that keeps something of a node in memory (the
// statuses of its proxies, the health of its egresses): the manager tells it
// to let go of a node that was deleted, once the node's session has ended.
type NodeForgetter interface {
	ForgetNode(nodeID string)
}

// ArtifactEnsurer makes sure that a node has the artifacts that a state needs,
// uploading those that it lacks. The manager calls it after building a state
// and before every ApplyState of it, and again whenever it looks at a node that
// has its state (at every connection and every resync): a state goes to the
// node also when its artifacts cannot all be provided, and the node reports the
// proxies whose engine it lacks as failed until it has it. info is a fresh
// answer of GetInfo.
type ArtifactEnsurer interface {
	EnsureArtifacts(ctx context.Context, nodeID string, info *nodev1.GetInfoResponse, state *nodev1.NodeState, client nodev1connect.NodeServiceClient) error
}

// A ConnectHook is told of every node that connected, with its client,
// after the node is online and before its state is looked at: what has to be
// on the node besides its state goes then (the imported certificates of its
// WEB proxies, proxies.CertSync). It runs on the goroutine of the node and
// returns when it is done; ctx ends with the connection.
type ConnectHook interface {
	OnConnected(ctx context.Context, nodeID string, client nodev1connect.NodeServiceClient)
}

// Manager keeps a connection to every node, one goroutine per node.
//
// The connection is gRPC (connect-go) over HTTP/2 and mutual TLS: the panel
// presents its client certificate, sends "<lower-case id>.internal" as the
// SNI (or the management SNI of a node in hidden management, through its public
// port), and accepts only the certificate whose
// fingerprint it stored for the node, issued by its CA. A node without a
// valid stored fingerprint or without a management address is not connected
// to at all: its status is error.
//
// Once connected, the manager asks the node for its info (versions, platform,
// public IPs, generations) and stores it, and the node is online. It follows
// the Watch stream of the node from the stored cursor, hands every record to
// the Ingestor, and stores the cursor after each one, so that a new
// connection resumes after the last record that was handled.
//
// It pushes the desired state when the node has not accepted the desired
// generation of the panel: at every connection, when told by Notify, and
// every few minutes. Mutators raise the generation (store.NextNodeGeneration)
// and then call Notify; the manager builds the state of that generation,
// has the artifacts ensured, and calls ApplyState, again and again with a
// growing wait (1 s to 60 s) until the node accepts it. An artifact that cannot
// be provided does not hold the state back; it is tried again every few
// minutes. Every answer of GetInfo refreshes what the node says about itself.
//
// A node that has been disconnected for 30 seconds is offline; one that has
// never answered stays provisioning. Errors are logged, without secrets.
type Manager struct {
	db  *store.DB
	key seal.Key
	ca  *pki.CA
	log *slog.Logger
	cfg timing
	now func() time.Time

	mu         sync.Mutex
	builder    StateBuilder
	ingestor   Ingestor
	ensurer    ArtifactEnsurer
	hook       ConnectHook
	mgmtWriter MgmtWriter
	switching  map[string]bool // the nodes whose management mode SetMgmtMode is switching
	ctx        context.Context // of Start; nil before Start
	cancel     context.CancelFunc
	closed     bool
	runners    map[string]*runner
	wg         sync.WaitGroup // the loader and the runners

	credMu sync.Mutex
	creds  *clientCreds // the client certificate of the panel, once loaded

	sigMu   sync.Mutex
	signals map[string]*agentSignal // by node, see AgentSignal
}

// The kinds of the agent's events that AgentSignal counts.
const (
	eventAgentStarted    = "agent_started"
	eventAgentRolledBack = "agent_rolled_back"
)

// An AgentSignal is what this panel has seen of the life of the agent of a
// node since it started: how often it connected to the agent, the agent
// version of the last connection, and how many agent_started and
// agent_rolled_back records the agent sent. A node update watches it: a new
// connection is a reconnection (an agent that restarted, or a path that
// changed), and a start or a rollback that it did not expect fails it. The
// counts only grow; they start at zero when the panel starts.
type AgentSignal struct {
	Connects   uint64
	Version    string
	Starts     uint64
	RolledBack uint64
}

// agentSignal is the AgentSignal of a node and the sequence number of the last
// record counted, so that a record the node sends again is not counted twice.
type agentSignal struct {
	AgentSignal
	lastSeq uint64
}

// AgentSignal returns what the manager has seen of the agent of a node.
func (m *Manager) AgentSignal(nodeID string) AgentSignal {
	m.sigMu.Lock()
	defer m.sigMu.Unlock()
	if s := m.signals[nodeID]; s != nil {
		return s.AgentSignal
	}
	return AgentSignal{}
}

func (m *Manager) signalLocked(nodeID string) *agentSignal {
	if m.signals == nil {
		m.signals = map[string]*agentSignal{}
	}
	s := m.signals[nodeID]
	if s == nil {
		s = &agentSignal{}
		m.signals[nodeID] = s
	}
	return s
}

// noteConnected counts a connection to the agent of a node.
func (m *Manager) noteConnected(nodeID, version string) {
	m.sigMu.Lock()
	defer m.sigMu.Unlock()
	s := m.signalLocked(nodeID)
	s.Connects++
	s.Version = version
}

// noteRecord counts a record of the Watch stream of a node that is an
// agent_started or agent_rolled_back event, once by its sequence number.
func (m *Manager) noteRecord(nodeID string, rec *nodev1.WatchResponse) {
	kind := rec.GetEvent().GetKind()
	if kind != eventAgentStarted && kind != eventAgentRolledBack {
		return
	}
	m.sigMu.Lock()
	defer m.sigMu.Unlock()
	s := m.signalLocked(nodeID)
	if seq := rec.GetSeq(); seq != 0 {
		if seq <= s.lastSeq {
			return
		}
		s.lastSeq = seq
	}
	if kind == eventAgentStarted {
		s.Starts++
	} else {
		s.RolledBack++
	}
}

// StoreInfo stores what a node said about itself in an answer of GetInfo that
// someone else asked for (a node update), as the manager stores its own
// answers. It writes only a change.
func (m *Manager) StoreInfo(ctx context.Context, nodeID string, info *nodev1.GetInfoResponse) error {
	_, err := m.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
		if changed, _ := takeInfo(n, info); !changed {
			return errUnchanged
		}
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

// SetBackoff sets the shortest and the longest wait before the manager
// connects to a node again; tests make them short. Call it before Start.
func (m *Manager) SetBackoff(minWait, maxWait time.Duration) {
	m.cfg.minBackoff, m.cfg.maxBackoff = minWait, maxWait
}

// clientCreds is the client certificate of the panel and its key, as PEM.
type clientCreds struct {
	certPEM, keyPEM []byte
}

// NewManager returns a manager that connects to the nodes in db with the
// client certificate of the panel, which it loads, or issues from ca, on first
// use (see loadOrCreateClientCert). A nil log discards the log.
func NewManager(db *store.DB, key seal.Key, ca *pki.CA, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Manager{
		db:      db,
		key:     key,
		ca:      ca,
		log:     log,
		cfg:     defaultTiming,
		now:     time.Now,
		runners: map[string]*runner{},
	}
}

// SetStateBuilder sets what builds the desired states. Until there is one, no
// state is pushed.
func (m *Manager) SetStateBuilder(b StateBuilder) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.builder = b
}

// SetIngestor sets what stores the records that nodes stream. Without one the
// records are only used for the applied generation, and the cursor still moves
// past them.
func (m *Manager) SetIngestor(i Ingestor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ingestor = i
}

// SetArtifactEnsurer sets what provides nodes with the artifacts of a state
// before it is applied. Without one, states are applied as they are.
func (m *Manager) SetArtifactEnsurer(e ArtifactEnsurer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensurer = e
}

// SetConnectHook sets what is told of every node that connects.
func (m *Manager) SetConnectHook(h ConnectHook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hook = h
}

func (m *Manager) connectHook() ConnectHook {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hook
}

func (m *Manager) stateBuilder() StateBuilder {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.builder
}

func (m *Manager) getIngestor() Ingestor {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ingestor
}

func (m *Manager) artifactEnsurer() ArtifactEnsurer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensurer
}

// Start loads the nodes and connects to each of them, in the background, until
// ctx is done or Close is called. Later calls do nothing.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx != nil || m.closed {
		return
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.load(m.ctx)
}

// load starts a runner for every node in the database, and tries again until
// the database answers.
func (m *Manager) load(ctx context.Context) {
	defer m.wg.Done()
	wait := backoff{min: m.cfg.minBackoff, max: m.cfg.maxBackoff}
	for {
		list, err := m.db.ListNodes(ctx)
		if err == nil {
			for _, n := range list {
				m.Notify(n.ID)
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		m.log.Error("could not list the nodes; trying again", "err", err)
		if !sleep(ctx, wait.next()) {
			return
		}
	}
}

// Close stops every connection and waits until the goroutines of the manager
// have returned. The manager cannot be started again.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	m.mu.Lock()
	clear(m.runners)
	m.mu.Unlock()
}

// Notify tells the manager that a node was created, changed or deleted, or
// that its desired generation went up. The manager connects to a node that is
// new to it, reconnects when the address or the pin of the node changed, lets
// a deleted node go, and otherwise pushes the desired state if the node does
// not have it. Notify does not block. Before Start and after Close it does
// nothing: Start reads every node anyway.
func (m *Manager) Notify(nodeID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil || m.closed || m.ctx.Err() != nil {
		return
	}
	if r, ok := m.runners[nodeID]; ok {
		r.poke()
		return
	}
	r := newRunner(m, nodeID)
	m.runners[nodeID] = r
	m.wg.Add(1)
	go r.run(m.ctx)
}

// Client returns a client of the node that uses the connection of the
// manager, for calls such as StreamLogs and UploadArtifact. The client works
// while that connection lasts: when it ends, calls in flight fail and new ones
// are refused, and Client has to be asked again. It is [ErrUnknownNode] for a
// node that the manager does not run, and [ErrNotConnected] while it is not
// connected to the node.
func (m *Manager) Client(nodeID string) (nodev1connect.NodeServiceClient, error) {
	m.mu.Lock()
	r := m.runners[nodeID]
	m.mu.Unlock()
	if r == nil {
		return nil, ErrUnknownNode
	}
	if c := r.currentClient(); c != nil {
		return c, nil
	}
	return nil, ErrNotConnected
}

// retire removes the runner of a node that is gone. When the runner was poked
// in the meantime it stays, and has to look at its node again: no poke is
// lost.
func (m *Manager) retire(r *runner) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-r.wake:
		return false
	default:
	}
	if m.runners[r.id] == r {
		delete(m.runners, r.id)
	}
	return true
}

// clientCredentials returns the client certificate of the panel, loading it on
// first use. An error is not kept: the next call tries again.
func (m *Manager) clientCredentials(ctx context.Context) (*clientCreds, error) {
	m.credMu.Lock()
	defer m.credMu.Unlock()
	if m.creds == nil {
		certPEM, keyPEM, err := loadOrCreateClientCert(ctx, m.db, m.key, m.ca)
		if err != nil {
			return nil, err
		}
		m.creds = &clientCreds{certPEM: certPEM, keyPEM: keyPEM}
	}
	return m.creds, nil
}

// target is where and how the manager connects to a node.
type target struct {
	addr       string // host:port of the agent
	serverName string // the SNI
	pin        string // the fingerprint of the certificate of the node, lower case
}

// errAwaitingHost is the reason targetOf gives for a node that has no
// management host yet: it was made for a join with a token, and gets one when
// the node joins from a public address or an admin fills it in. That is no
// fault, and the manager waits for the node to change.
var errAwaitingHost = errors.New("the node has no management host yet")

// targetOf returns the target of a node, or the reason that the manager must
// not connect to it.
func targetOf(n *store.Node) (target, error) {
	if n.MgmtHost == "" {
		return target{}, errAwaitingHost
	}
	if n.MgmtPort == 0 || n.MgmtPort > 65535 {
		return target{}, errors.New("the node has no management address")
	}
	pin := strings.ToLower(n.CertFingerprint)
	if pin == "" {
		return target{}, errors.New("the node has no certificate fingerprint to pin, and the panel does not connect on the CA alone")
	}
	if raw, err := hex.DecodeString(pin); err != nil || len(raw) != 32 {
		return target{}, errors.New("the stored certificate fingerprint of the node is not a SHA-256 in hex")
	}
	// A node with a public port and a management SNI is reached through its
	// edge (hidden management, see mgmt.go for why the port decides and not
	// the mode); any other on its own port, with the name in its certificate.
	port, sni := n.MgmtPort, nodeDNSName(n.ID)
	if n.MgmtPublicPort != 0 && n.MgmtSNI != "" {
		port, sni = n.MgmtPublicPort, n.MgmtSNI
	}
	return target{
		addr:       net.JoinHostPort(n.MgmtHost, strconv.FormatUint(uint64(port), 10)),
		serverName: sni,
		pin:        pin,
	}, nil
}

// newClient returns a NodeService client for a target, and a function that
// closes every connection that the client made and makes it unusable.
func (m *Manager) newClient(ctx context.Context, t target) (nodev1connect.NodeServiceClient, func(), error) {
	creds, err := m.clientCredentials(ctx)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := pki.ClientTLSConfig(m.ca.CertPEM, creds.certPEM, creds.keyPEM, t.serverName, t.pin)
	if err != nil {
		return nil, nil, err
	}
	conns := &connSet{conns: map[net.Conn]struct{}{}}
	dialer := &net.Dialer{Timeout: m.cfg.dialTimeout, KeepAlive: 30 * time.Second}
	var protocols http.Protocols
	protocols.SetHTTP2(true) // gRPC needs HTTP/2; nothing else is offered
	tr := &http.Transport{
		// No Proxy: the connection to a node never goes through a proxy
		// from the environment.
		DialContext:         conns.wrap(dialer.DialContext),
		TLSClientConfig:     cfg,
		TLSHandshakeTimeout: m.cfg.dialTimeout,
		Protocols:           &protocols,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: pingAfter, PingTimeout: pingTimeout},
		IdleConnTimeout:     90 * time.Second,
	}
	client := nodev1connect.NewNodeServiceClient(&http.Client{Transport: tr}, "https://"+t.addr,
		connect.WithGRPC(), connect.WithReadMaxBytes(maxMessage))
	closeAll := func() {
		conns.close()
		tr.CloseIdleConnections()
	}
	return client, closeAll, nil
}

// connSet holds the connections of one session, so that they all close when
// the session ends: CloseIdleConnections alone would leave a connection open
// while a stream that was just canceled is still being torn down, and calls
// made through [Manager.Client] keep theirs busy.
type connSet struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// wrap returns dial with every connection it makes added to the set. Once the
// set is closed, it makes none.
func (cs *connSet) wrap(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		cs.mu.Lock()
		defer cs.mu.Unlock()
		if cs.closed {
			_ = c.Close()
			return nil, net.ErrClosed
		}
		cs.conns[c] = struct{}{}
		return c, nil
	}
}

// close closes the connections of the set and every one that it would make.
func (cs *connSet) close() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.closed = true
	for c := range cs.conns {
		_ = c.Close()
	}
	cs.conns = nil
}

// isTrustError reports whether a connection failed because the node did not
// prove that it is the node: a certificate that is not the pinned one, or not
// one of the CA. Retrying does not mend that; an operator has to look.
func isTrustError(err error) bool {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	return errors.Is(err, pki.ErrPinMismatch) || errors.As(err, &unknown) || errors.As(err, &invalid)
}

// backoff is a wait that doubles from min to max.
type backoff struct {
	min, max, cur time.Duration
}

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.min
	} else {
		b.cur = min(2*b.cur, b.max)
	}
	return b.cur
}

func (b *backoff) reset() { b.cur = 0 }

// sleep waits for d, and reports false when ctx was done first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// runner is the goroutine of one node. It connects, holds the session while
// the connection lasts, and connects again.
type runner struct {
	m    *Manager
	id   string
	log  *slog.Logger
	wake chan struct{} // capacity 1: a poke that has not been looked at yet

	mu     sync.Mutex
	client nodev1connect.NodeServiceClient // of the current session; nil without one

	// The rest belongs to the goroutine of the runner.
	status        string    // the stored status, as last read or written
	disconnected  time.Time // when the last session ended, or when the runner started
	reconnect     backoff
	push          backoff
	pushAfter     time.Time // no push before then: the wait after a push that failed
	tried         uint64    // the generation of the last push that was tried
	lastProblem   string    // the last problem logged as a warning or an error
	lastRejection string    // the generation and reason of the last rejection recorded as an event
	warnedBuilder bool      // that there is no state builder was logged

	lastArtifactProblem string // why the artifacts could not be provided, as last logged as a warning
	hiddenFails         int    // connections through the public port that failed in a row (hidden management)
}

func newRunner(m *Manager, id string) *runner {
	return &runner{
		m:         m,
		id:        id,
		log:       m.log.With("node", id),
		wake:      make(chan struct{}, 1),
		reconnect: backoff{min: m.cfg.minBackoff, max: m.cfg.maxBackoff},
		push:      backoff{min: m.cfg.minBackoff, max: m.cfg.maxBackoff},
	}
}

// poke wakes the runner up to look at its node again.
func (r *runner) poke() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *runner) currentClient() nodev1connect.NodeServiceClient {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.client
}

func (r *runner) setClient(c nodev1connect.NodeServiceClient) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.client = c
}

func (r *runner) run(ctx context.Context) {
	defer r.m.wg.Done()
	// The stored status may say online from before the panel started; from
	// here on, the node has not been heard from.
	r.disconnected = r.m.now()
	for ctx.Err() == nil {
		n, err := r.m.db.NodeByID(ctx, r.id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if r.m.retire(r) {
				if f, ok := r.m.getIngestor().(NodeForgetter); ok {
					f.ForgetNode(r.id)
				}
				r.log.Info("the node was deleted; the panel no longer connects to it")
				return
			}
			continue
		case err != nil:
			if ctx.Err() == nil {
				r.log.Error("could not read the node", "err", err)
				r.pause(ctx, r.reconnect.next())
			}
			continue
		}
		r.status = n.Status
		r.markOfflineIfDue(ctx)

		t, err := targetOf(n)
		if errors.Is(err, errAwaitingHost) {
			// The node keeps its status (provisioning, for a new one) until a
			// join or an admin gives it an address; the change pokes the runner.
			r.log.Debug("the node has no management host yet; waiting for a join or an admin to set it")
			r.pause(ctx, r.m.cfg.maxBackoff)
			continue
		}
		if err != nil {
			r.fault(ctx, err)
			r.pause(ctx, r.m.cfg.maxBackoff)
			continue
		}

		started := time.Now()
		established, err := r.connect(ctx, t, nil)
		if ctx.Err() != nil {
			return
		}
		if plain, hidden := plainTargetOf(n, t); hidden {
			established, err = r.hiddenFallback(ctx, t, plain, established, err)
			if ctx.Err() != nil {
				return
			}
		}
		if established {
			r.disconnected = r.m.now()
			if time.Since(started) >= r.m.cfg.stableAfter {
				r.reconnect.reset()
			}
		}
		switch {
		case errors.Is(err, errReconnect), errors.Is(err, errNodeGone):
			continue // look at the node again, now
		case isTrustError(err):
			r.fault(ctx, err)
		default:
			r.problem(slog.LevelWarn, "the connection to the node failed", err)
		}
		r.pause(ctx, r.reconnect.next())
	}
}

// pause waits for d, or until the runner is poked or ctx is done. Meanwhile it
// marks an online node offline when it has been disconnected for long enough.
func (r *runner) pause(ctx context.Context, d time.Duration) {
	wait := time.NewTimer(d)
	defer wait.Stop()
	var offline <-chan time.Time
	if r.status == store.NodeStatusOnline {
		t := time.NewTimer(max(time.Until(r.disconnected.Add(r.m.cfg.offlineAfter)), 0))
		defer t.Stop()
		offline = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
			return
		case <-wait.C:
			return
		case <-offline:
			offline = nil
			r.markOfflineIfDue(ctx)
		}
	}
}

// markOfflineIfDue marks an online node offline when it has been disconnected
// for offlineAfter.
func (r *runner) markOfflineIfDue(ctx context.Context) {
	if r.status != store.NodeStatusOnline || time.Since(r.disconnected) < r.m.cfg.offlineAfter {
		return
	}
	if r.setStatus(ctx, store.NodeStatusOffline, store.NodeStatusOnline) {
		r.log.Warn("the node is offline", "disconnected_for", time.Since(r.disconnected).Round(time.Second))
		r.event(ctx, "node.offline", severityWarn, "the agent has not answered since "+r.disconnected.UTC().Format(time.RFC3339), nil)
	}
}

// fault records a problem that retrying does not mend: the status is error,
// and the problem is logged and recorded as an event once.
func (r *runner) fault(ctx context.Context, err error) {
	r.problem(slog.LevelError, "the panel cannot talk to the node", err)
	if r.setStatus(ctx, store.NodeStatusError, "") {
		r.event(ctx, "node.error", severityError, err.Error(), nil)
	}
}

// problem logs a problem at level, or at debug level when it is the one that
// was logged last, so that a node that stays unreachable does not fill the log.
func (r *runner) problem(level slog.Level, msg string, err error) {
	if text := err.Error(); text != r.lastProblem {
		r.lastProblem = text
		r.log.Log(context.Background(), level, msg, "err", err)
		return
	}
	r.log.Debug(msg, "err", err)
}

// setStatus stores the status of the node and reports whether it changed it.
// from, when not empty, is the only status that it changes.
func (r *runner) setStatus(ctx context.Context, status, from string) bool {
	var prev string
	_, err := r.m.db.ModifyNode(ctx, r.id, func(n *store.Node) error {
		prev = n.Status
		if n.Status == status || (from != "" && n.Status != from) {
			return errUnchanged
		}
		n.Status = status
		return nil
	})
	switch {
	case errors.Is(err, errUnchanged):
		r.status = prev
		return false
	case err != nil:
		if ctx.Err() == nil && !errors.Is(err, store.ErrNotFound) {
			r.log.Error("could not store the status of the node", "status", status, "err", err)
		}
		return false
	}
	r.status = status
	return true
}

// event records an event of the node. A failure is logged and goes no further.
func (r *runner) event(ctx context.Context, kind, severity, message string, details map[string]string) {
	ev := &store.Event{NodeID: r.id, Kind: kind, Severity: severity, Message: message, Details: details}
	if err := r.m.db.AppendEvent(ctx, ev); err != nil && ctx.Err() == nil {
		r.log.Error("could not record an event", "kind", kind, "err", err)
	}
}

// connect connects to the node and serves the connection until it fails, the
// node changes or ctx is done. established reports whether the node answered.
func (r *runner) connect(ctx context.Context, t target, hiddenFor *target) (established bool, err error) {
	client, closeAll, err := r.m.newClient(ctx, t)
	if err != nil {
		return false, err
	}
	defer closeAll()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	info, err := r.getInfo(ctx, client)
	if err != nil {
		return false, err
	}
	n, err := r.connected(ctx, info)
	if err != nil {
		return true, err
	}
	if hiddenFor != nil {
		r.log.Warn("the node is reached through its plain management port: the hidden path is down", "plain", t.addr, "hidden", hiddenFor.addr)
		r.event(ctx, "node.mgmt_fallback", severityWarn,
			"reached through the plain port "+t.addr+": the hidden management path "+hiddenFor.addr+" is down", nil)
	}
	r.setClient(client)
	defer r.setClient(nil)
	if h := r.m.connectHook(); h != nil {
		h.OnConnected(ctx, r.id, client)
	}

	s := &session{r: r, client: client, target: t, hiddenFor: hiddenFor, info: info, nodeHas: info.GetDesiredGeneration()}
	return true, s.serve(ctx, n.WatchCursor)
}

// getInfo calls GetInfo.
func (r *runner) getInfo(ctx context.Context, client nodev1connect.NodeServiceClient) (*nodev1.GetInfoResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, r.m.cfg.callTimeout)
	defer cancel()
	resp, err := client.GetInfo(ctx, connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		return nil, fmt.Errorf("get info: %w", err)
	}
	return resp.Msg, nil
}

// connected stores what the node said about itself, and that it is online.
func (r *runner) connected(ctx context.Context, info *nodev1.GetInfoResponse) (*store.Node, error) {
	now := r.m.now()
	var prev string
	var panelMoved bool
	n, err := r.m.db.ModifyNode(ctx, r.id, func(n *store.Node) error {
		prev = n.Status
		_, panelMoved = takeInfo(n, info)
		n.AppliedGeneration = info.GetAppliedGeneration()
		n.Status = store.NodeStatusOnline
		n.LastSeenAt = &now
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errNodeGone
	case err != nil:
		return nil, fmt.Errorf("store the info of the node: %w", err)
	}
	r.status = store.NodeStatusOnline
	r.lastProblem = ""
	r.m.noteConnected(r.id, n.AgentVersion)
	if prev != store.NodeStatusOnline {
		r.log.Info("the node is online", "agent_version", n.AgentVersion, "arch", n.Arch)
		r.event(ctx, "node.online", severityInfo, "the panel connected to the agent", nil)
	}
	if panelMoved {
		if n, err = r.panelMoved(ctx, n); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// panelMoved raises the desired generation of the node after it saw the panel
// come from another address: the addresses that it lets probe its proxies are
// in its state (NodeSettings.probe_sources). n is the node as stored; it is
// returned with the new generation.
func (r *runner) panelMoved(ctx context.Context, n *store.Node) (*store.Node, error) {
	gen, err := r.m.db.NextNodeGeneration(ctx, r.id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errNodeGone
	case err != nil:
		return nil, fmt.Errorf("raise the generation after the address of the panel changed: %w", err)
	}
	r.log.Info("the node sees the panel come from another address; it gets a new state", "panel_addrs", n.PanelAddrs, "generation", gen)
	next := *n
	next.DesiredGeneration = gen
	return &next, nil
}

// storeInfo stores what the node said about itself in an answer of GetInfo
// (see takeInfo). It writes only a change.
func (r *runner) storeInfo(ctx context.Context, info *nodev1.GetInfoResponse) {
	var panelMoved bool
	n, err := r.m.db.ModifyNode(ctx, r.id, func(n *store.Node) error {
		changed, moved := takeInfo(n, info)
		panelMoved = moved
		if !changed {
			return errUnchanged
		}
		return nil
	})
	if err != nil && !errors.Is(err, errUnchanged) && !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
		r.log.Error("could not store the info of the node", "err", err)
	}
	if err == nil && panelMoved {
		if _, err := r.panelMoved(ctx, n); err != nil && !errors.Is(err, errNodeGone) && ctx.Err() == nil {
			r.log.Error("could not give the node its new panel address", "err", err)
		}
	}
}

// session is one connection to a node.
type session struct {
	r       *runner
	client  nodev1connect.NodeServiceClient
	target  target
	info    *nodev1.GetInfoResponse // the latest answer of GetInfo
	nodeHas uint64                  // the generation that the node has accepted
	// policy is the IP policy that the Watch of the session was opened with.
	policy nodev1.IpPolicy
	// hiddenFor is the hidden target of the node while the session runs on
	// its plain port instead, because the hidden path is down; nil otherwise.
	hiddenFor *target
}

// serve follows the Watch stream from cursor and pushes the desired state,
// until the stream or a call fails, the node changes, or ctx is done.
func (s *session) serve(ctx context.Context, cursor uint64) error {
	r := s.r
	// The reader opens the stream itself: opening it waits for the headers
	// of the response, and a node sends none until it has a record to send,
	// while the session has to go on meanwhile.
	watchCtx, stopWatch := context.WithCancel(ctx)
	records := make(chan *nodev1.WatchResponse)
	ended := make(chan error, 1)
	var reader sync.WaitGroup
	reader.Add(1)
	s.policy = r.m.watchPolicy(ctx)
	req := &nodev1.WatchRequest{Cursor: cursor, IpPolicy: s.policy}
	go func() {
		defer reader.Done()
		ended <- watch(watchCtx, s.client, req, records)
	}()
	defer func() {
		stopWatch() // ends the stream, and with it the reader
		reader.Wait()
	}()

	retry := time.NewTimer(time.Hour)
	retry.Stop()
	defer retry.Stop()
	resync := time.NewTicker(r.m.cfg.resyncEvery)
	defer resync.Stop()

	due := true
	if wait := time.Until(r.pushAfter); wait > 0 {
		due = false
		retry.Reset(wait)
	}
	var info *nodev1.GetInfoResponse
	if due {
		info = s.info // fresh from connecting: no need to ask again
	}
	for {
		if due {
			due = false
			after, err := s.sync(ctx, info)
			if err != nil {
				return err
			}
			info = nil
			if after > 0 {
				r.pushAfter = time.Now().Add(after)
				retry.Reset(after)
			} else {
				r.pushAfter = time.Time{}
				retry.Stop()
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-ended:
			if err == nil {
				err = errors.New("the node ended the stream")
			}
			return fmt.Errorf("watch: %w", err)
		case rec := <-records:
			s.handle(ctx, rec)
		case <-r.wake:
			newer, err := s.refresh(ctx)
			if err != nil {
				return err
			}
			if newer {
				// A new desired state may well mend one that was rejected:
				// no reason to wait.
				r.push.reset()
				r.pushAfter = time.Time{}
				retry.Stop()
				due = true
			}
		case <-retry.C:
			due = true
		case <-resync.C:
			if s.hiddenFor != nil && r.m.probe(ctx, *s.hiddenFor) == nil {
				r.log.Info("the hidden management path answers again; the panel goes back to it")
				return errReconnect
			}
			if r.pushAfter.IsZero() {
				due = true
			}
		}
	}
}

// watchPolicy is the IP policy that a Watch is opened with: the panel's
// current one, so that the node sends nothing of the addresses of clients that
// the panel does not keep (R6-5). A policy that cannot be read is off: what is
// not known to be allowed is not sent.
func (m *Manager) watchPolicy(ctx context.Context) nodev1.IpPolicy {
	st, _, err := m.db.StatsSettings(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.Error("could not read the IP policy; the node is watched with the policy off", "err", err)
		}
		return nodev1.IpPolicy_IP_POLICY_OFF
	}
	switch st.IPPolicy {
	case store.IPPolicyFull:
		return nodev1.IpPolicy_IP_POLICY_FULL
	case store.IPPolicyCountries:
		return nodev1.IpPolicy_IP_POLICY_COUNTRIES
	}
	return nodev1.IpPolicy_IP_POLICY_OFF
}

// watch opens the Watch stream of a node with req and passes its records on
// until the stream ends or ctx is done. It returns what ended the stream: nil
// when the node closed it.
func watch(ctx context.Context, client nodev1connect.NodeServiceClient, req *nodev1.WatchRequest, records chan<- *nodev1.WatchResponse) error {
	stream, err := client.Watch(ctx, connect.NewRequest(req))
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	for stream.Receive() {
		select {
		case records <- stream.Msg():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return stream.Err()
}

// refresh looks at the node again after a poke. It ends the session when the
// node is gone or connects differently now, and otherwise reports whether
// the node has to be brought to another generation.
func (s *session) refresh(ctx context.Context) (bool, error) {
	n, err := s.r.m.db.NodeByID(ctx, s.r.id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, errNodeGone
	case err != nil:
		if ctx.Err() == nil {
			s.r.log.Error("could not read the node", "err", err)
		}
		return true, nil // sync reads it again, and waits when that fails
	}
	want := s.target
	if s.hiddenFor != nil {
		want = *s.hiddenFor // a session on the plain port stands in for it
	}
	if t, err := targetOf(n); err != nil || t != want {
		return false, errReconnect
	}
	// The node filters what it sends by the policy that the Watch was opened
	// with (R6-5): under a new one the Watch is opened again, so that a node
	// watched under countries sends the client addresses once it is full.
	if s.r.m.watchPolicy(ctx) != s.policy {
		s.r.log.Info("the IP policy changed; the node is watched again under the new one")
		return false, errReconnect
	}
	switch {
	case n.DesiredGeneration == s.nodeHas:
		return false, nil
	case !s.r.pushAfter.IsZero() && n.DesiredGeneration == s.r.tried:
		return false, nil // the same push is due again soon; a poke does not hurry it
	}
	return true, nil
}

// sync brings the node to the desired generation of the panel when it does not
// have it: it builds the state, has its artifacts ensured and applies it. info
// is a fresh answer of GetInfo, or nil to ask for one.
//
// It returns how long to wait before trying again after a push that failed,
// or 0 when there is nothing left to do. An error means that the node did not
// answer, which ends the session.
func (s *session) sync(ctx context.Context, info *nodev1.GetInfoResponse) (time.Duration, error) {
	r := s.r
	if info == nil {
		var err error
		if info, err = r.getInfo(ctx, s.client); err != nil {
			return 0, err
		}
		// What the node says about itself changes without a new connection:
		// the edge that runs after the operator rolled it, the capabilities
		// after an update.
		r.storeInfo(ctx, info)
	}
	s.info = info
	s.nodeHas = info.GetDesiredGeneration()

	n, err := r.m.db.NodeByID(ctx, r.id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return 0, errNodeGone
	case err != nil:
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		r.log.Error("could not read the node", "err", err)
		return r.push.next(), nil
	}
	desired := n.DesiredGeneration
	if s.nodeHas > desired {
		if desired, err = s.catchUp(ctx, desired); err != nil {
			switch {
			case ctx.Err() != nil:
				return 0, ctx.Err()
			case errors.Is(err, errGenerationGap):
				r.fault(ctx, err)
				return r.m.cfg.maxBackoff, nil
			}
			r.log.Error("could not raise the desired generation of the node", "err", err)
			return r.push.next(), nil
		}
	}
	if desired == 0 || s.nodeHas >= desired {
		if n.StateRejection != "" {
			r.keepRejection(ctx, "") // it has the state now
		}
		if desired != 0 {
			s.recheckArtifacts(ctx, info, desired)
		}
		r.push.reset()
		return 0, nil
	}
	r.tried = desired

	builder := r.m.stateBuilder()
	if builder == nil {
		if !r.warnedBuilder {
			r.warnedBuilder = true
			r.log.Warn("there is no state builder; the state of the node is not pushed", "generation", desired)
		}
		return r.push.next(), nil
	}
	state, err := builder.Build(ctx, r.id, desired)
	if err == nil && state.GetGeneration() != desired {
		err = fmt.Errorf("the state builder returned generation %d for generation %d", state.GetGeneration(), desired)
	}
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		r.log.Error("could not build the state of the node", "generation", desired, "err", err)
		return r.push.next(), nil
	}
	if err := s.ensureArtifacts(ctx, info, state); err != nil && ctx.Err() != nil {
		return 0, ctx.Err()
	}
	// The state goes to the node also when its artifacts could not all be
	// provided: the node reports the proxies whose engine it lacks as failed
	// and serves the rest, and the artifacts are tried again at every resync.
	resp, err := s.apply(ctx, state)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		r.log.Warn("could not apply the state", "generation", desired, "err", err)
		return r.push.next(), nil
	}
	if !resp.GetAccepted() {
		r.rejected(ctx, desired, resp.GetReason())
		return r.push.next(), nil
	}
	s.nodeHas = desired
	r.push.reset()
	r.lastRejection = ""
	if n.StateRejection != "" {
		r.keepRejection(ctx, "")
	}
	r.log.Info("the node accepted its state", "generation", desired)
	return 0, nil
}

// recheckArtifacts provides a node that has its desired state with the
// artifacts of that state that it lacks: the state was pushed also when they
// could not all be provided, and they are tried again whenever the panel
// looks at the node (at every connection and every resync). Without an
// artifact ensurer there is nothing to do.
func (s *session) recheckArtifacts(ctx context.Context, info *nodev1.GetInfoResponse, generation uint64) {
	r := s.r
	builder := r.m.stateBuilder()
	if builder == nil || r.m.artifactEnsurer() == nil {
		return
	}
	state, err := builder.Build(ctx, r.id, generation)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Debug("could not build the state of the node to look at its artifacts", "generation", generation, "err", err)
		}
		return
	}
	_ = s.ensureArtifacts(ctx, info, state) // logged there
}

// ensureArtifacts has the artifact ensurer, if there is one, provide the node
// with the artifacts of a state, and logs why it could not: at warning level
// when the reason is new, so that a download that keeps failing at every
// resync does not fill the log. info is a fresh answer of GetInfo.
func (s *session) ensureArtifacts(ctx context.Context, info *nodev1.GetInfoResponse, state *nodev1.NodeState) error {
	r := s.r
	e := r.m.artifactEnsurer()
	if e == nil {
		return nil
	}
	err := e.EnsureArtifacts(ctx, r.id, info, state, s.client)
	switch {
	case err == nil:
		r.lastArtifactProblem = ""
	case ctx.Err() != nil:
	case err.Error() != r.lastArtifactProblem:
		r.lastArtifactProblem = err.Error()
		r.log.Warn("could not provide the node with the artifacts of its state; the node fails the proxies that need them until it has them",
			"generation", state.GetGeneration(), "err", err)
	default:
		r.log.Debug("could not provide the node with the artifacts of its state", "generation", state.GetGeneration(), "err", err)
	}
	return err
}

// apply calls ApplyState.
func (s *session) apply(ctx context.Context, state *nodev1.NodeState) (*nodev1.ApplyStateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, s.r.m.cfg.callTimeout)
	defer cancel()
	resp, err := s.client.ApplyState(ctx, connect.NewRequest(&nodev1.ApplyStateRequest{State: state}))
	if err != nil {
		return nil, fmt.Errorf("apply state: %w", err)
	}
	return resp.Msg, nil
}

// rejected logs a state that the node turned down, records it as an event
// once for each generation and reason, and keeps the reason with the node
// until the node has the desired generation (see Node.StateRejection).
func (r *runner) rejected(ctx context.Context, generation uint64, reason string) {
	reason = clip(cmp.Or(reason, "the node gave no reason"), maxReasonLen)
	gen := strconv.FormatUint(generation, 10)
	r.log.Warn("the node rejected its state", "generation", generation, "reason", reason)
	if key := gen + "\x00" + reason; key != r.lastRejection {
		r.lastRejection = key
		r.event(ctx, "node.state_rejected", severityWarn, reason, map[string]string{"generation": gen})
	}
	r.keepRejection(ctx, reason)
}

// keepRejection stores why the node refused its desired state, "" once it has
// it. It writes only a change.
func (r *runner) keepRejection(ctx context.Context, reason string) {
	_, err := r.m.db.ModifyNode(ctx, r.id, func(n *store.Node) error {
		if n.StateRejection == reason {
			return errUnchanged
		}
		n.StateRejection = reason
		return nil
	})
	if err != nil && !errors.Is(err, errUnchanged) && !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
		r.log.Error("could not store why the node refused its state", "err", err)
	}
}

// catchUp moves the desired generation of the panel past the one that the
// node has. That happens when the node kept a state from an earlier life of
// the panel (a restored backup) or from an earlier install, and would turn
// every state of the panel down as stale. The generation goes up the only way
// that it goes up, one at a time, and no further than maxGenerationGap.
func (s *session) catchUp(ctx context.Context, desired uint64) (uint64, error) {
	if s.nodeHas-desired > maxGenerationGap {
		return 0, fmt.Errorf("%w: the node has generation %d, the panel %d", errGenerationGap, s.nodeHas, desired)
	}
	s.r.log.Warn("the node has a newer generation than the panel; moving the panel's past it",
		"node_generation", s.nodeHas, "panel_generation", desired)
	for desired <= s.nodeHas {
		g, err := s.r.m.db.NextNodeGeneration(ctx, s.r.id)
		if err != nil {
			return 0, err
		}
		desired = g
	}
	return desired, nil
}

// clip returns s as valid UTF-8 of at most n bytes.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// takeInfo puts what a node says about itself (GetInfo) into its record, within
// bounds: the versions of its agent and of the edge that runs, its platform,
// its public addresses, its capabilities, the agent binaries it has installed
// (and which of them have a kept signature), whether its agent is healthy, the
// warnings of its build, and the address that it saw the panel come from
// (panelAddrs). It reports whether that changed the record, and whether it
// changed the addresses of the panel, which the state of the node holds.
func takeInfo(n *store.Node, info *nodev1.GetInfoResponse) (changed, panelMoved bool) {
	next := *n
	next.AgentVersion = clip(info.GetAgentVersion(), maxInfoLen)
	next.EdgeVersion = clip(info.GetEdgeVersion(), maxInfoLen)
	next.Arch = clip(info.GetArch(), maxInfoLen)
	next.HostInfo.OS = clip(info.GetOs(), maxInfoLen)
	next.HostInfo.Capabilities = capabilities(info.GetCapabilities())
	next.HostInfo.PortOwners = portOwners(info.GetPortOwners())
	next.PublicIPs = publicIPs(info.GetPublicIps())
	b := info.GetBinaries()
	next.HostInfo.Binaries = store.NodeBinaries{
		Versions: capabilities(b.GetVersions()),
		Current:  clip(b.GetCurrent(), maxCapabilityLen),
		Previous: clip(b.GetPrevious(), maxCapabilityLen),
		Signed:   capabilities(b.GetSignedVersions()),
	}
	next.HostInfo.Healthy = info.GetHealthy()
	next.HostInfo.Warnings = capabilities(info.GetWarnings())
	next.PanelAddrs = panelAddrs(n.PanelAddrs, info.GetPeerAddr())
	panelMoved = !slices.Equal(next.PanelAddrs, n.PanelAddrs)
	changed = panelMoved || next.AgentVersion != n.AgentVersion || next.EdgeVersion != n.EdgeVersion || next.Arch != n.Arch ||
		next.HostInfo.OS != n.HostInfo.OS || !slices.Equal(next.HostInfo.Capabilities, n.HostInfo.Capabilities) ||
		!slices.Equal(next.HostInfo.PortOwners, n.HostInfo.PortOwners) || !slices.Equal(next.PublicIPs, n.PublicIPs) ||
		!slices.Equal(next.HostInfo.Binaries.Versions, n.HostInfo.Binaries.Versions) ||
		!slices.Equal(next.HostInfo.Binaries.Signed, n.HostInfo.Binaries.Signed) ||
		next.HostInfo.Binaries.Current != n.HostInfo.Binaries.Current ||
		next.HostInfo.Binaries.Previous != n.HostInfo.Binaries.Previous ||
		next.HostInfo.Healthy != n.HostInfo.Healthy || !slices.Equal(next.HostInfo.Warnings, n.HostInfo.Warnings)
	*n = next
	return changed, panelMoved
}

// panelAddrs returns the addresses that a node saw the panel come from: prev
// with peer, the source of the call as the node reports it, in place of the
// address of its family, the last IPv4 and the last IPv6 one, in that order. A
// peer that is not the unicast address of one host without a zone leaves prev
// as it is.
func panelAddrs(prev []string, peer string) []string {
	a, err := netip.ParseAddr(peer)
	if err != nil || a.Zone() != "" {
		return prev
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return prev
	}
	var v4, v6 string
	for _, p := range prev {
		if pa, err := netip.ParseAddr(p); err == nil {
			if pa.Is4() {
				v4 = pa.String()
			} else {
				v6 = pa.String()
			}
		}
	}
	if a.Is4() {
		v4 = a.String()
	} else {
		v6 = a.String()
	}
	var out []string
	for _, s := range []string{v4, v6} {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// portOwners returns the owners of ports that a node reports with an IP
// address (in its usual form) and a port, each owner clipped, and no more than
// maxPortOwners of them.
func portOwners(list []*nodev1.PortOwner) []store.PortOwner {
	var out []store.PortOwner
	for _, o := range list {
		addr, err := netip.ParseAddr(o.GetBind())
		if err != nil || addr.Zone() != "" || o.GetPort() == 0 || o.GetPort() > 65535 {
			continue
		}
		out = append(out, store.PortOwner{Bind: addr.String(), Port: o.GetPort(), Owner: clip(o.GetOwner(), maxOwnerLen)})
		if len(out) == maxPortOwners {
			break
		}
	}
	return out
}

// capabilities returns the capabilities that a node reports, each clipped,
// and no more than maxCapabilities of them.
func capabilities(list []string) []string {
	var out []string
	for _, c := range list {
		if c = clip(c, maxCapabilityLen); c != "" {
			out = append(out, c)
		}
		if len(out) == maxCapabilities {
			break
		}
	}
	return out
}

// publicIPs returns the addresses that are IP addresses, in their usual form,
// and no more than maxPublicIPs of them.
func publicIPs(list []string) []string {
	var out []string
	for _, s := range list {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || addr.Zone() != "" {
			continue
		}
		out = append(out, addr.String())
		if len(out) == maxPublicIPs {
			break
		}
	}
	return out
}
