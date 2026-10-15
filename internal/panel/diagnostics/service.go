package diagnostics

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// The limits of ListRuns.
const (
	defaultRunsLimit = 20
	maxRunsLimit     = 50
)

// Service is the DiagnosticsService of the panel. Every procedure needs an
// admin.
type Service struct {
	panelv1connect.UnimplementedDiagnosticsServiceHandler

	db     *store.DB
	runner *Runner
	feed   *Feed
	key    *seal.Key
	log    *slog.Logger
	fixes  *fixer // SetFixes; nil applies none
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithFeed gives the service the problem feed of ListProblems; without it
// ListProblems is Unimplemented.
func WithFeed(f *Feed) ServiceOption { return func(s *Service) { s.feed = f } }

// WithKey gives the service the key of the proxies' secrets, which the
// journal takes out of what nodes wrote; without it the journal takes out the
// client addresses only. The service shares the key; it makes no copy.
func WithKey(k *seal.Key) ServiceOption { return func(s *Service) { s.key = k } }

var _ panelv1connect.DiagnosticsServiceHandler = (*Service)(nil)

// NewService returns the service of a runner. A nil log discards the log.
func NewService(db *store.DB, runner *Runner, log *slog.Logger, opts ...ServiceOption) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{db: db, runner: runner, log: log}
	for _, o := range opts {
		o(s)
	}
	return s
}

func requireAdmin(ctx context.Context) (*store.Admin, error) {
	a, ok := auth.AdminFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return a, nil
}

// fail turns an error into the error that a caller gets, and logs one of the
// panel itself.
func (s *Service) fail(what string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New(what+": not found"))
	case errors.Is(err, ErrScope):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, errors.New("the request was canceled"))
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, errors.New("the request took too long"))
	}
	s.log.Error(what, "err", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

// StartRun starts a manual run, or returns the node's run in progress.
func (s *Service) StartRun(ctx context.Context, req *connect.Request[panelv1.StartRunRequest]) (*connect.Response[panelv1.StartRunResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	nodeID, scope := req.Msg.GetNodeId(), req.Msg.GetScope()
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("node_id is required"))
	}
	if scope == "" {
		scope = ScopeNode
	}
	audit := func() error {
		return s.db.AppendAudit(ctx, &store.AuditEntry{AdminID: admin.ID, Action: "diagnostics.run", Target: "node:" + nodeID,
			Details: map[string]string{"scope": scope}})
	}
	id, _, err := s.runner.StartManual(ctx, nodeID, scope, admin.ID, audit)
	if err != nil {
		return nil, s.fail("could not start the run", err)
	}
	return connect.NewResponse(&panelv1.StartRunResponse{RunId: id}), nil
}

// GetRun returns a run with its results.
func (s *Service) GetRun(ctx context.Context, req *connect.Request[panelv1.GetRunRequest]) (*connect.Response[panelv1.DiagnosticRun], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if req.Msg.GetRunId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("run_id is required"))
	}
	run, err := s.db.DiagnosticRun(ctx, req.Msg.GetRunId())
	if err != nil {
		return nil, s.fail("the run", err)
	}
	var caps []string
	if n, err := s.db.NodeByID(ctx, run.NodeID); err == nil {
		caps = n.HostInfo.Capabilities
	}
	return connect.NewResponse(runProto(run, caps)), nil
}

// ListRuns returns the runs of a node or of a proxy, newest first.
func (s *Service) ListRuns(ctx context.Context, req *connect.Request[panelv1.ListRunsRequest]) (*connect.Response[panelv1.ListRunsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	limit := int(req.Msg.GetLimit())
	switch {
	case limit == 0:
		limit = defaultRunsLimit
	case limit > maxRunsLimit:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("limit is at most 50"))
	}
	nodeID, scopes, err := s.whose(ctx, req.Msg.GetNodeId(), req.Msg.GetProxyId())
	if err != nil {
		return nil, err
	}
	runs, err := s.db.ListDiagnosticRuns(ctx, nodeID, scopes, limit)
	if err != nil {
		return nil, s.fail("could not list the runs", err)
	}
	out := &panelv1.ListRunsResponse{Runs: make([]*panelv1.DiagnosticRun, 0, len(runs))}
	for _, r := range runs {
		out.Runs = append(out.Runs, runProto(r, nil))
	}
	return connect.NewResponse(out), nil
}

// whose resolves node_id or proxy_id: the node, and the scopes of a proxy.
func (s *Service) whose(ctx context.Context, nodeID, proxyID string) (string, []string, error) {
	switch {
	case nodeID == "" && proxyID == "":
		return "", nil, connect.NewError(connect.CodeInvalidArgument, errors.New("node_id or proxy_id is required"))
	case nodeID != "" && proxyID != "":
		return "", nil, connect.NewError(connect.CodeInvalidArgument, errors.New("node_id and proxy_id cannot both be set"))
	case proxyID != "":
		p, err := s.db.ProxyByID(ctx, proxyID)
		if err != nil {
			return "", nil, s.fail("the proxy", err)
		}
		return p.NodeID, []string{ScopeNode, "proxy:" + p.ID}, nil
	}
	if _, err := s.db.NodeByID(ctx, nodeID); err != nil {
		return "", nil, s.fail("the node", err)
	}
	return nodeID, nil, nil
}

// LatestChecks returns the light checks of a node, or of a proxy's scope.
func (s *Service) LatestChecks(ctx context.Context, req *connect.Request[panelv1.LatestChecksRequest]) (*connect.Response[panelv1.LatestChecksResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	nodeID, _, err := s.whose(ctx, req.Msg.GetNodeId(), req.Msg.GetProxyId())
	if err != nil {
		return nil, err
	}
	scope := ScopeNode
	if id := req.Msg.GetProxyId(); id != "" {
		scope = "proxy:" + id
	}
	sc, err := resolveScope(ctx, s.db, nodeID, scope)
	if err != nil {
		return nil, s.fail("the scope", err)
	}
	checks, err := s.db.NodeChecks(ctx, nodeID)
	if err != nil {
		return nil, s.fail("could not read the checks", err)
	}
	in := targetsOf(sc)
	out := &panelv1.LatestChecksResponse{}
	for _, c := range checks {
		if !in(c.Target) {
			continue
		}
		x := resultProto(store.DiagnosticResult{CheckID: c.CheckID, Layer: c.Layer, Target: c.Target, Status: c.Status,
			Summary: c.Summary, Evidence: c.Evidence, Hint: c.Hint, Fix: c.Fix, Vantage: VantageNode, CheckedAt: c.CheckedAt},
			sc.node.HostInfo.Capabilities)
		x.SinceUnix = c.Since.Unix()
		out.Results = append(out.Results, x)
	}
	return connect.NewResponse(out), nil
}

// runProto is a run as the API gives it; caps are the capabilities of its
// node, for whether its fixes are available.
func runProto(r *store.DiagnosticRun, caps []string) *panelv1.DiagnosticRun {
	out := &panelv1.DiagnosticRun{
		Id: r.ID, NodeId: r.NodeID, Scope: r.Scope, Reason: r.Reason, Change: r.Change, RelatedRunId: r.RelatedRunID,
		State: r.State, Error: r.Error, StartedUnix: r.StartedAt.Unix(), Regressed: r.Regressed,
	}
	if r.FinishedAt != nil {
		out.FinishedUnix = r.FinishedAt.Unix()
	}
	// The counts are stored when the run ends; a run read with its results
	// counts them, also while it is running.
	counts := map[string]int{StatusOK: r.OK, StatusWarn: r.Warn, StatusFail: r.Fail, StatusSkip: r.Skip}
	if len(r.Results) > 0 {
		counts = map[string]int{}
	}
	for _, x := range r.Results {
		out.Results = append(out.Results, resultProto(x, caps))
		counts[x.Status]++
	}
	out.OkCount, out.WarnCount = uint32(counts[StatusOK]), uint32(counts[StatusWarn])
	out.FailCount, out.SkipCount = uint32(counts[StatusFail]), uint32(counts[StatusSkip])
	return out
}

func resultProto(x store.DiagnosticResult, caps []string) *panelv1.CheckResult {
	ok, why := FixAvailable(x.Fix, x.Target, caps)
	return &panelv1.CheckResult{
		Id: x.CheckID, Layer: x.Layer, Target: x.Target, Status: x.Status, Summary: x.Summary, Evidence: x.Evidence,
		Hint: x.Hint, Fix: x.Fix, FixAvailable: ok, FixUnavailableReason: why, Vantage: x.Vantage,
		CheckedUnix: x.CheckedAt.Unix(),
	}
}
