package probes

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// probeNowEvery is how often ProbeNow may probe the same proxy.
const probeNowEvery = 5 * time.Second

// historyRanges are the ranges of ProbeHistory.
var historyRanges = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

// Service is the ProbeService of the panel. Every procedure needs an admin:
// the auth middleware refuses calls without a session, and the service checks
// again.
type Service struct {
	db    *store.DB
	sched *Scheduler
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	lastRun map[string]time.Time // when ProbeNow last probed a proxy, by id
}

var _ panelv1connect.ProbeServiceHandler = (*Service)(nil)

// NewService returns the service of the scheduler. A nil log discards the log.
func NewService(db *store.DB, sched *Scheduler, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{db: db, sched: sched, log: log, now: time.Now, lastRun: map[string]time.Time{}}
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
		return connect.NewError(connect.CodeNotFound, errors.New("no such proxy"))
	case errors.Is(err, ErrNotProbeable):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, errors.New("the request was canceled"))
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, errors.New("the request took too long"))
	}
	s.log.Error(what, "err", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

// release gives back the slot of a proxy taken at, unless another call has
// taken it since: a call that failed before it probed does not use it up.
func (s *Service) release(proxyID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastRun[proxyID].Equal(at) {
		delete(s.lastRun, proxyID)
	}
}

// take takes the slot of ProbeNow for a proxy, if 5 seconds have passed since
// it was taken last, and returns when it was taken.
func (s *Service) take(proxyID string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if last, ok := s.lastRun[proxyID]; ok && now.Sub(last) < probeNowEvery {
		return time.Time{}, false
	}
	for id, t := range s.lastRun { // forget the slots that are over
		if now.Sub(t) >= probeNowEvery {
			delete(s.lastRun, id)
		}
	}
	s.lastRun[proxyID] = now
	return now, true
}

// ProbeNow probes a proxy now: one call per proxy every 5 seconds, audited.
func (s *Service) ProbeNow(ctx context.Context, req *connect.Request[panelv1.ProbeNowRequest]) (*connect.Response[panelv1.ProbeNowResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetProxyId()
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("proxy_id is required"))
	}
	if _, err := s.db.ProxyByID(ctx, id); err != nil {
		return nil, s.fail("could not read the proxy", err)
	}
	at, ok := s.take(id)
	if !ok {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("the proxy was probed less than 5 seconds ago"))
	}
	entry := &store.AuditEntry{AdminID: admin.ID, Action: "probe.run", Target: "proxy:" + id}
	if err := s.db.AppendAudit(ctx, entry); err != nil {
		s.release(id, at)
		return nil, s.fail("could not write the audit log", err)
	}
	p, l1, err := s.sched.Probe(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotProbeable) {
			s.release(id, at) // nothing was probed
		}
		return nil, s.fail("could not probe the proxy", err)
	}
	return connect.NewResponse(&panelv1.ProbeNowResponse{
		Kind: p.Kind, Ok: p.OK, LatencyMs: p.LatencyMS, Error: p.Error, L1Ok: l1,
	}), nil
}

// ProbeHistory returns the probes of a proxy over the range and the uptime of
// each vantage.
func (s *Service) ProbeHistory(ctx context.Context, req *connect.Request[panelv1.ProbeHistoryRequest]) (*connect.Response[panelv1.ProbeHistoryResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	id := req.Msg.GetProxyId()
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("proxy_id is required"))
	}
	span, ok := historyRanges[req.Msg.GetRange()]
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(`range is "24h" or "7d"`))
	}
	if _, err := s.db.ProxyByID(ctx, id); err != nil {
		return nil, s.fail("could not read the proxy", err)
	}
	now := s.now()
	ps, err := s.db.Probes(ctx, id, "", now.Add(-span), now.Add(time.Second))
	if err != nil {
		return nil, s.fail("could not read the probes", err)
	}
	out := &panelv1.ProbeHistoryResponse{Points: make([]*panelv1.ProbePoint, 0, len(ps)), Uptimes: uptimes(ps)}
	for _, p := range ps {
		out.Points = append(out.Points, &panelv1.ProbePoint{
			Ts: p.TS.Unix(), Vantage: p.Vantage, Kind: p.Kind, Ok: p.OK, LatencyMs: p.LatencyMS, Error: p.Error,
			L1Ok: l1OK(p),
		})
	}
	return connect.NewResponse(out), nil
}

// l1OK says whether a stored probe of the panel reached the proxy with the
// secret (the fake-TLS handshake): it passed, or only no datacenter answered
// through it (the error that newProbe gives then, ErrNoDatacenterL1). The
// node's probes do not tell.
func l1OK(p store.Probe) bool {
	if p.Vantage != VantagePanel || p.Kind != KindL2 {
		return false
	}
	return p.OK || p.Error == ErrNoDatacenterL1
}

// uptimes is the share of probes that passed, per vantage, by vantage.
func uptimes(ps []store.Probe) []*panelv1.ProbeUptime {
	by := map[string]*panelv1.ProbeUptime{}
	for _, p := range ps {
		u := by[p.Vantage]
		if u == nil {
			u = &panelv1.ProbeUptime{Vantage: p.Vantage}
			by[p.Vantage] = u
		}
		u.Total++
		if p.OK {
			u.Ok++
		}
	}
	out := make([]*panelv1.ProbeUptime, 0, len(by))
	for _, u := range by {
		u.Uptime = float64(u.Ok) / float64(u.Total)
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Vantage < out[j].Vantage })
	return out
}
