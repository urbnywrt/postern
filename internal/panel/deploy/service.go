// Package deploy installs nodes over SSH (spec §9): the DeployService of the
// panel. The panel logs in to the server of a node with sshx, finds out what
// the server is (the preflight, an embedded script that prints its facts as
// one JSON object), and installs the node in a job of the job runner: it
// copies the node kit of the architecture of the server and the bundle of the
// node, runs install.sh, removes the bundle and waits for the node to come
// online. The log of the job is what the admin follows in the UI.
//
// When the panel has a node image and the request a valid panel address, the
// install takes the Docker path instead: no kit, no bundle, no install.sh; it
// removes the container of an earlier agent, makes a join token and starts the
// node with the Docker command that nodes.RenderDockerCommand renders, and
// the node joins the panel with the token.
//
// The panel sends credentials only to a server whose host key an admin has
// confirmed, keeps them only when asked to, sealed, and never logs them; the
// job runner replaces them by *** in the log of a job.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/jobs"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/sshx"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	// jobKind is the kind of the jobs of this package.
	jobKind = "install"

	// Bounds on what an admin sends.
	maxHostLen    = 253
	maxLabelLen   = 63
	maxUserLen    = 64
	maxPassword   = 1 << 10
	maxPrivateKey = 64 << 10
	maxPassphrase = 1 << 10
)

// The timings of the service, which tests shorten.
const (
	// preflightTimeout bounds the preflight script.
	preflightTimeout = 2 * time.Minute
	// longTimeout bounds each long step of an install: the install of Docker,
	// an upload, install.sh.
	longTimeout = 15 * time.Minute
	// stepTimeout bounds each short command of an install.
	stepTimeout = time.Minute
	// cleanupTimeout bounds the removal of the bundle, which runs also when
	// the job has been cancelled.
	cleanupTimeout = 30 * time.Second
	// onlineTimeout is how long an install waits for the node to come online,
	// and onlinePoll how often it looks.
	onlineTimeout = 3 * time.Minute
	onlinePoll    = time.Second
	// notifyEvery is how many looks apart the connection manager is told
	// again to look at the node, which it does at once instead of after its
	// back-off.
	notifyEvery = 5
)

// errInternal is all that a caller is told of an error of the panel itself.
var errInternal = errors.New("internal error")

// A Notifier is told to look at a node at once: the connection manager, which
// connects to the agent of a node that was just installed instead of waiting
// for its back-off.
type Notifier interface {
	Notify(nodeID string)
}

// Config is what the service works with.
type Config struct {
	DB *store.DB
	// Key seals the credentials that admins ask the panel to keep.
	Key seal.Key
	// Nodes has the node kits and the bundles of the nodes.
	Nodes *nodes.Service
	// Notifier, which may be nil, is told about a node that was installed.
	Notifier Notifier
	Jobs     *jobs.Runner
	// Log is where the service logs; nil discards it. It never gets a
	// credential.
	Log *slog.Logger
}

// Service is the DeployService of the panel. Every call needs an admin.
type Service struct {
	db       *store.DB
	key      seal.Key
	nodes    *nodes.Service
	notifier Notifier
	jobs     *jobs.Runner
	log      *slog.Logger

	// Tests shorten these.
	onlineTimeout time.Duration
	onlinePoll    time.Duration
	now           func() time.Time
}

var _ panelv1connect.DeployServiceHandler = (*Service)(nil)

// NewService returns the DeployService.
func NewService(cfg Config) *Service {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{db: cfg.DB, key: cfg.Key, nodes: cfg.Nodes, notifier: cfg.Notifier, jobs: cfg.Jobs, log: log,
		onlineTimeout: onlineTimeout, onlinePoll: onlinePoll, now: time.Now}
}

// requireAdmin returns the admin of the request, or the error to answer with.
func requireAdmin(ctx context.Context) (*store.Admin, error) {
	a, ok := auth.AdminFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return a, nil
}

func invalid(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

func precondition(format string, args ...any) error {
	return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(format, args...))
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

// node returns the node of a request.
func (s *Service) node(ctx context.Context, id string) (*store.Node, error) {
	n, err := s.db.NodeByID(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such node"))
	case err != nil:
		return nil, s.fail("could not read a node", err)
	}
	return n, nil
}

// audit records what an admin did. A failure is logged and does not fail the
// call.
func (s *Service) audit(ctx context.Context, adminID, action, nodeID string) {
	entry := &store.AuditEntry{AdminID: adminID, Action: action, Target: "node:" + nodeID}
	if err := s.db.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		s.log.Error("could not write the audit log", "action", action, "node", nodeID, "err", err)
	}
}

// GetTarget says how the panel last reached the server of a node.
func (s *Service) GetTarget(ctx context.Context, req *connect.Request[panelv1.GetTargetRequest]) (*connect.Response[panelv1.GetTargetResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	n, err := s.node(ctx, req.Msg.GetNodeId())
	if err != nil {
		return nil, err
	}
	out := &panelv1.GetTargetResponse{}
	t, err := s.db.SSHTargetByNode(ctx, n.ID)
	switch {
	case err == nil:
		out.Target = &panelv1.SshTarget{Host: t.Host, Port: t.Port, User: t.User, HostKey: t.HostKey, HostKeyType: t.HostKeyType}
		out.SavedCredentials = t.AuthKind
	case !errors.Is(err, store.ErrNotFound):
		return nil, s.fail("could not read the SSH target of a node", err)
	}
	// Only an install: a node that runs a job of another kind has no job here.
	j, err := s.db.RunningJobByNode(ctx, n.ID, jobKind)
	switch {
	case err == nil:
		out.RunningJobId = j.ID
	case !errors.Is(err, store.ErrNotFound):
		return nil, s.fail("could not read the jobs of a node", err)
	}
	return connect.NewResponse(out), nil
}

// Preflight logs in to the server of a node and reports what it found.
func (s *Service) Preflight(ctx context.Context, req *connect.Request[panelv1.PreflightRequest]) (*connect.Response[panelv1.PreflightResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	n, err := s.node(ctx, msg.GetNodeId())
	if err != nil {
		return nil, err
	}
	target, err := checkTarget(msg.GetTarget())
	if err != nil {
		return nil, err
	}
	panelURL, _, err := s.dockerPath(msg.GetPanelUrl())
	if err != nil {
		return nil, err
	}
	if msg.GetReplaceHostKey() && msg.GetCredentials().GetUseSaved() {
		// The saved credentials were given for the server of the old key.
		return nil, invalid("the saved credentials are not sent to a server whose host key is replaced: give the credentials")
	}
	stored, err := s.storedTarget(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	authn, err := s.credentials(n.ID, msg.GetCredentials(), target, stored)
	if err != nil {
		return nil, err
	}
	target = effectiveHostKey(target, stored, msg.GetReplaceHostKey())

	client, hk, err := sshx.Dial(ctx, target, authn)
	if err != nil {
		var changed *sshx.HostKeyChangedError
		switch {
		case errors.Is(err, sshx.ErrHostKeyUnconfirmed) && hk != nil:
			return connect.NewResponse(&panelv1.PreflightResponse{Result: &panelv1.PreflightResponse_HostKey{
				HostKey: &panelv1.HostKey{Fingerprint: hk.Fingerprint, Type: hk.KeyType}}}), nil
		case errors.As(err, &changed):
			return connect.NewResponse(&panelv1.PreflightResponse{Result: &panelv1.PreflightResponse_HostKeyChanged{
				HostKeyChanged: &panelv1.HostKeyChanged{
					Confirmed: &panelv1.HostKey{Fingerprint: changed.Want, Type: changed.WantType},
					Presented: &panelv1.HostKey{Fingerprint: changed.Got, Type: changed.GotType},
				}}}), nil
		}
		return nil, sshError(err)
	}
	defer func() { _ = client.Close() }()
	target.HostKeyType = hk.KeyType
	if !sameTarget(stored, target) {
		if err := s.saveTarget(ctx, n.ID, target, stored, nil); err != nil {
			return nil, s.fail("could not store the SSH target of a node", err)
		}
		s.keyConfirmed(ctx, admin.ID, n.ID, stored, target)
	}

	report, err := s.preflight(ctx, client, n, target.Host, panelURL != "")
	if err != nil {
		return nil, sshError(err)
	}
	s.log.Info("preflight of a node", "node", n.ID, "admin", admin.ID, "host", target.Host, "user", target.User,
		"blockers", len(report.Blockers(false)), "method", report.Method)
	return connect.NewResponse(&panelv1.PreflightResponse{Result: &panelv1.PreflightResponse_Report{Report: reportProto(report)}}), nil
}

// keyConfirmed records that an admin confirmed the host key of t, a decision of
// trust, when it is not the key that the panel kept for the server.
func (s *Service) keyConfirmed(ctx context.Context, adminID, nodeID string, stored *store.SSHTarget, t sshx.Target) {
	if sameServer(stored, t) && stored.HostKey == t.HostKey {
		return
	}
	s.audit(ctx, adminID, "node.ssh_host_key", nodeID)
	s.log.Info("SSH host key of a node confirmed", "node", nodeID, "admin", adminID, "host", t.Host,
		"fingerprint", t.HostKey, "type", t.HostKeyType)
}

// preflight runs the preflight on the server, which the panel reached at the
// host dialed, and makes its report, for the Docker path when docker says so.
func (s *Service) preflight(ctx context.Context, client *sshx.Client, n *store.Node, dialed string, docker bool) (*Report, error) {
	ctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	out := &cappedBuffer{max: maxPreflightOutput}
	before := s.now()
	code, err := client.Run(ctx, preflightCommand(n.MgmtPort, ""), nil, out)
	after := s.now()
	switch {
	case err != nil:
		return nil, fmt.Errorf("the preflight: %w", err)
	case out.over:
		return nil, badAnswerError{fmt.Errorf("the preflight printed more than %d bytes", maxPreflightOutput)}
	case code != 0:
		return nil, badAnswerError{fmt.Errorf("the preflight failed with exit code %d: %s", code, orUnknown(firstLine(out.b)))}
	}
	facts, err := parsePreflight(out.b)
	if err != nil {
		return nil, badAnswerError{fmt.Errorf("the answer of the server could not be read: %w", err)}
	}
	return newReport(reportInput{facts: facts, dialed: dialed, mgmtPort: n.MgmtPort, docker: docker,
		kit: s.kitAvailable, before: before, after: after}), nil
}

// dockerPath returns the panel address, checked, and the node image of an
// install on the Docker path, which an install takes when the panel has a
// node image and raw is set; both are empty for the kit path (no node image,
// or raw empty). A raw that is set but not a valid panel address
// (nodes.CheckPanelURL) is an InvalidArgument error, not the kit path: the
// admin asked for the Docker path.
func (s *Service) dockerPath(raw string) (panelURL, image string, err error) {
	image = s.nodes.NodeImage()
	if image == "" || raw == "" {
		return "", "", nil
	}
	u, err := nodes.CheckPanelURL(raw)
	if err != nil {
		return "", "", invalid("panel_url: %v", err)
	}
	return u, image, nil
}

// kitAvailable reports whether the panel has the node kit of arch.
func (s *Service) kitAvailable(arch string) bool {
	k, err := s.nodes.OpenKit(arch)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// badAnswerError is an answer of a server that the panel cannot use.
type badAnswerError struct{ err error }

func (e badAnswerError) Error() string { return e.err.Error() }
func (e badAnswerError) Unwrap() error { return e.err }

// sshError is the Connect error of an SSH connection or command that failed.
func sshError(err error) error {
	var bad badAnswerError
	switch {
	case errors.Is(err, sshx.ErrAuth), errors.Is(err, sshx.ErrKeyPassphrase):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, sshx.ErrSudoPassword), errors.Is(err, sshx.ErrNoBase64), errors.As(err, &bad):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	}
	return connect.NewError(connect.CodeUnavailable, err)
}

// Install starts the job that installs a node.
func (s *Service) Install(ctx context.Context, req *connect.Request[panelv1.InstallRequest]) (*connect.Response[panelv1.InstallResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	n, err := s.node(ctx, msg.GetNodeId())
	if err != nil {
		return nil, err
	}
	target, err := checkTarget(msg.GetTarget())
	if err != nil {
		return nil, err
	}
	panelURL, image, err := s.dockerPath(msg.GetPanelUrl())
	if err != nil {
		return nil, err
	}
	stored, err := s.storedTarget(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	authn, err := s.credentials(n.ID, msg.GetCredentials(), target, stored)
	if err != nil {
		return nil, err
	}
	target = effectiveHostKey(target, stored, false)
	if target.HostKey == "" {
		return nil, precondition("the host key of the server has not been confirmed: run the preflight first")
	}
	in := &install{
		s: s, adminID: admin.ID, node: n, target: target, auth: authn, stored: stored,
		installDocker: msg.GetInstallDocker(), remember: msg.GetRemember(),
	}
	secrets := []string{authn.Password, string(authn.PrivateKeyPEM), authn.Passphrase}
	in.panelURL, in.image = panelURL, image
	var bundleTar []byte
	if !in.docker() {
		// The kit path: the bundle, which holds the private key of the node.
		bundle, err := s.nodes.Bundle(ctx, n.ID)
		switch {
		case errors.Is(err, nodes.ErrNoBundle):
			return nil, precondition("the node has no certificate, so there is no bundle to install it with")
		case err != nil:
			return nil, s.fail("could not make the bundle of a node", err)
		}
		bundleTar, err = bundle.MarshalTar()
		keyPEM := bundle.KeyPEM
		if err != nil {
			clear(keyPEM)
			return nil, s.fail("could not make the bundle of a node", err)
		}
		in.bundle = bundleTar
		secrets = append(secrets, string(keyPEM))
		clear(keyPEM)
	}
	id, err := s.jobs.Start(ctx, n.ID, jobKind, secrets, in.run)
	switch {
	case errors.Is(err, jobs.ErrBusy):
		clear(bundleTar)
		return nil, precondition("the node is running a job already")
	case errors.Is(err, jobs.ErrClosed):
		clear(bundleTar)
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the panel is stopping"))
	case err != nil:
		clear(bundleTar)
		return nil, s.fail("could not start an install", err)
	}
	s.audit(ctx, admin.ID, "node.install", n.ID)
	s.log.Info("install of a node started", "node", n.ID, "admin", admin.ID, "job", id, "host", target.Host, "user", target.User,
		"install_docker", in.installDocker, "remember", in.remember, "docker_path", in.docker())
	return connect.NewResponse(&panelv1.InstallResponse{JobId: id}), nil
}

// job returns the install with this id. A job of another kind is not found
// here, as one that does not exist: this service neither shows nor cancels it, running or not.
func (s *Service) job(ctx context.Context, id string) (jobs.Job, error) {
	j, err := s.jobs.Get(ctx, id)
	if err == nil && j.Kind != jobKind {
		err = jobs.ErrNotFound
	}
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		return jobs.Job{}, connect.NewError(connect.CodeNotFound, errors.New("no such job"))
	case err != nil:
		return jobs.Job{}, s.fail("could not read a job", err)
	}
	return j, nil
}

// GetJob returns an install job, with its log. A job of another kind is not found.
func (s *Service) GetJob(ctx context.Context, req *connect.Request[panelv1.GetJobRequest]) (*connect.Response[panelv1.GetJobResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	j, err := s.job(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	out := &panelv1.Job{Id: j.ID, NodeId: j.NodeID, Kind: j.Kind, Status: j.Status, Log: j.Log, Error: j.Error,
		StartedUnix: j.StartedAt.Unix()}
	if j.FinishedAt != nil {
		out.FinishedUnix = j.FinishedAt.Unix()
	}
	return connect.NewResponse(&panelv1.GetJobResponse{Job: out}), nil
}

// CancelJob cancels a running install job. A job of another kind is not found,
// and keeps running.
func (s *Service) CancelJob(ctx context.Context, req *connect.Request[panelv1.CancelJobRequest]) (*connect.Response[panelv1.CancelJobResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetId()
	j, err := s.job(ctx, id)
	switch {
	case err != nil:
		return nil, err
	case j.Status != jobs.StatusRunning:
		return nil, precondition("the job is not running")
	}
	// A job that has ended meanwhile has nothing left to cancel.
	if err := s.jobs.Cancel(id); err != nil && !errors.Is(err, jobs.ErrNotFound) {
		return nil, s.fail("could not cancel a job", err)
	}
	s.audit(ctx, admin.ID, "job.cancel", j.NodeID)
	s.log.Info("job cancelled", "job", id, "node", j.NodeID, "admin", admin.ID)
	return connect.NewResponse(&panelv1.CancelJobResponse{}), nil
}

// ---- targets -----------------------------------------------------------------

// keyTypes are the types of host keys that a target may name.
var keyTypes = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA}

var (
	// userRe is a user name: letters, digits and . _ @ -, not starting with
	// a dot or a hyphen, perhaps ending in $ (a machine account).
	userRe = regexp.MustCompile(`^[A-Za-z0-9_@][A-Za-z0-9._@-]*\$?$`)
	// fingerprintRe is a SHA-256 fingerprint as ssh-keygen -l prints it.
	fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// checkTarget checks a target that an admin sent, and returns it for sshx.
func checkTarget(t *panelv1.SshTarget) (sshx.Target, error) {
	if t == nil {
		return sshx.Target{}, invalid("the target is missing")
	}
	host := strings.TrimSpace(t.GetHost())
	switch {
	case host == "":
		return sshx.Target{}, invalid("the host of the target is empty")
	case !validHost(host):
		return sshx.Target{}, invalid("the host must be an IP address (IPv6 without brackets) or a host name, without a port")
	case t.GetPort() > 65535:
		return sshx.Target{}, invalid("the port must be 1 to 65535")
	case t.GetUser() == "" || len(t.GetUser()) > maxUserLen || !userRe.MatchString(t.GetUser()):
		return sshx.Target{}, invalid("the user must be 1 to %d letters, digits and . _ @ -", maxUserLen)
	case t.GetHostKey() != "" && !fingerprintRe.MatchString(t.GetHostKey()):
		return sshx.Target{}, invalid("the host key must be a SHA-256 fingerprint (SHA256:...)")
	case t.GetHostKeyType() != "" && (t.GetHostKey() == "" || !slices.Contains(keyTypes, t.GetHostKeyType())):
		return sshx.Target{}, invalid("the type of the host key is not one that the panel takes")
	}
	port := int(t.GetPort())
	if port == 0 {
		port = sshx.DefaultPort
	}
	return sshx.Target{Host: host, Port: port, User: t.GetUser(), HostKey: t.GetHostKey(), HostKeyType: t.GetHostKeyType()}, nil
}

// storedTarget returns the SSH target that the panel keeps for a node, nil
// when it keeps none.
func (s *Service) storedTarget(ctx context.Context, nodeID string) (*store.SSHTarget, error) {
	t, err := s.db.SSHTargetByNode(ctx, nodeID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, s.fail("could not read the SSH target of a node", err)
	}
	return t, nil
}

// sameServer reports whether a stored target is the server of t: the same
// host and port.
func sameServer(stored *store.SSHTarget, t sshx.Target) bool {
	return stored != nil && stored.Host == t.Host && int(stored.Port) == t.Port
}

// sameTarget reports whether a stored target is t: the same server, user and
// host key.
func sameTarget(stored *store.SSHTarget, t sshx.Target) bool {
	return sameServer(stored, t) && stored.User == t.User && stored.HostKey == t.HostKey && stored.HostKeyType == t.HostKeyType
}

// effectiveHostKey is the host key that the panel checks the server of t
// against: the key that it keeps for the server, which the target cannot
// override, unless the admin replaces it (replace); or else the key that the
// admin confirmed in the request; or none, for a first contact, which is also
// what replacing the kept key without a new one comes to.
func effectiveHostKey(t sshx.Target, stored *store.SSHTarget, replace bool) sshx.Target {
	if !replace && sameServer(stored, t) && stored.HostKey != "" {
		t.HostKey, t.HostKeyType = stored.HostKey, stored.HostKeyType
	}
	return t
}

// saveTarget keeps the target of a node with the host key that the server
// presented. With auth, the credentials are kept, sealed, when remember says
// so, and forgotten otherwise; without it, the credentials that are kept stay
// when they are for the same server, user and host key: those of a server
// whose key changed are forgotten.
func (s *Service) saveTarget(ctx context.Context, nodeID string, t sshx.Target, stored *store.SSHTarget, keep *keepCredentials) error {
	rec := &store.SSHTarget{NodeID: nodeID, Host: t.Host, Port: uint32(t.Port), User: t.User, HostKey: t.HostKey, HostKeyType: t.HostKeyType}
	switch {
	case keep != nil && keep.remember:
		kind, enc, err := s.sealCredentials(nodeID, keep.auth)
		if err != nil {
			return err
		}
		rec.AuthKind, rec.SecretEnc = kind, enc
	case keep == nil && sameServer(stored, t) && stored.User == t.User && stored.HostKey == t.HostKey:
		rec.AuthKind, rec.SecretEnc = stored.AuthKind, stored.SecretEnc
	}
	return s.db.PutSSHTarget(ctx, rec)
}

// keepCredentials says what to do with the credentials of an install.
type keepCredentials struct {
	auth     sshx.Auth
	remember bool
}

// validHost reports whether host is an IP address without a zone, or a host
// name: dot-separated labels of 1 to 63 letters, digits and hyphens, which do
// not start or end with a hyphen, at most 253 characters in all, and a last
// label that is not all digits. (The same rule as for the hosts of nodes.)
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

// ---- reports -----------------------------------------------------------------

// reportProto is the API form of a report.
func reportProto(r *Report) *panelv1.PreflightReport {
	f := r.Facts
	out := &panelv1.PreflightReport{
		Os:               f.OS.PrettyName,
		Machine:          f.Machine,
		Arch:             f.Arch,
		KitAvailable:     r.KitAvailable,
		InstallDir:       r.InstallDir,
		InstallMethod:    r.Method,
		DockerInstalled:  f.Docker.Installed,
		DockerVersion:    f.Docker.Version,
		ComposeVersion:   f.Docker.ComposeVersion,
		UsernsRemap:      f.Docker.UsernsRemap,
		DiskPath:         f.DiskPath,
		ClockSkewSeconds: int64(r.ClockSkew / time.Second),
		HttpsPort:        portProto(r.HTTPSPort),
		MgmtPort:         portProto(r.MgmtPort),
	}
	if r.DialedIP.IsValid() {
		out.DialedIp = r.DialedIP.String()
	}
	if f.Disk != nil {
		out.DiskFreeBytes, out.DiskTotalBytes = f.Disk.FreeBytes, f.Disk.TotalBytes
	}
	for _, l := range f.Listeners {
		s := &panelv1.ListeningSocket{Port: uint32(l.Port)}
		if l.Addr.IsValid() {
			s.Address = l.Addr.String()
		}
		for _, p := range l.Processes {
			s.Processes = append(s.Processes, fmt.Sprintf("%s (pid %d)", orUnknown(p.Name), p.PID))
		}
		out.Listening = append(out.Listening, s)
	}
	for _, a := range f.PublicIPs {
		out.PublicIps = append(out.PublicIps, a.String())
	}
	if out.DialedIp != "" && !slices.Contains(out.PublicIps, out.DialedIp) {
		out.PublicIps = append(out.PublicIps, out.DialedIp)
	}
	for _, is := range r.Issues {
		out.Issues = append(out.Issues, &panelv1.PreflightIssue{Code: is.Code, Severity: is.Severity, Message: is.Message,
			Params: is.Params, FixedByDockerInstall: is.FixedByDockerInstall})
	}
	return out
}

func portProto(c PortCheck) *panelv1.PortCheck {
	return &panelv1.PortCheck{Port: uint32(c.Port), Free: c.Free, Postern: c.Postern, Owner: c.Owner}
}

// cappedBuffer keeps the first max bytes written to it, and notes that more
// came.
type cappedBuffer struct {
	b    []byte
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.max - len(c.b); n > room {
		c.over = true
		p = p[:max(room, 0)]
	}
	c.b = append(c.b, p...)
	return n, nil
}
