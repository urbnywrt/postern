package geodb

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// errInternal is all that a caller is told of an error of the panel itself.
// What it was is in the log.
var errInternal = errors.New("internal error")

// Audit actions of this package, and what they are about.
const (
	auditUpload  = "geoip.upload"
	auditRefresh = "geoip.refresh"
	auditEnabled = "geoip.enabled"
	auditTarget  = "geoip"
)

// Service is the GeoIPService of the panel: the status of the country
// database, a refresh now, and the switch that turns country lookups on and
// off. Refreshing and switching are audited.
//
// Every call needs an admin: the auth middleware refuses calls without a
// session, and the service checks again, so that it is safe however it is
// mounted.
type Service struct {
	m   *Manager
	log *slog.Logger
}

var _ panelv1connect.GeoIPServiceHandler = (*Service)(nil)

// NewService returns the GeoIPService of the manager. A nil log discards the
// log.
func NewService(m *Manager, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{m: m, log: log}
}

// requireAdmin returns the admin of the request, or the error to answer with.
func requireAdmin(ctx context.Context) (*store.Admin, error) {
	a, ok := auth.AdminFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return a, nil
}

// fail turns an error of the panel itself into the error that a caller gets, and
// logs it. A request that is gone or has run out of time says so, since that is
// not a fault.
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

// GetGeoIP says whether country lookups are enabled and which database the
// panel has.
func (s *Service) GetGeoIP(ctx context.Context, _ *connect.Request[panelv1.GetGeoIPRequest]) (*connect.Response[panelv1.GetGeoIPResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	st, err := s.m.Status(ctx)
	if err != nil {
		return nil, s.fail("could not read the status of the country database", err)
	}
	return connect.NewResponse(&panelv1.GetGeoIPResponse{Status: statusProto(st)}), nil
}

// RefreshGeoIP looks for a newer database now. A look that finds none to get is
// no error of the call: the answer is the status, and the error is in it.
func (s *Service) RefreshGeoIP(ctx context.Context, _ *connect.Request[panelv1.RefreshGeoIPRequest]) (*connect.Response[panelv1.RefreshGeoIPResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.m.Refresh(ctx)
	var failed *failure
	switch {
	case err == nil, errors.As(err, &failed):
		// The failure is in the status, which is what the screen shows.
	default:
		return nil, s.fail("could not refresh the country database", err)
	}
	s.m.audit(ctx, admin.ID, auditRefresh, nil)
	return connect.NewResponse(&panelv1.RefreshGeoIPResponse{Status: statusProto(st)}), nil
}

// SetGeoIPEnabled turns country lookups on or off.
func (s *Service) SetGeoIPEnabled(ctx context.Context, req *connect.Request[panelv1.SetGeoIPEnabledRequest]) (*connect.Response[panelv1.SetGeoIPEnabledResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	on := req.Msg.GetEnabled()
	st, err := s.m.SetEnabled(ctx, on)
	if err != nil {
		return nil, s.fail("could not change whether country lookups are enabled", err)
	}
	s.m.audit(ctx, admin.ID, auditEnabled, map[string]string{"enabled": strconv.FormatBool(on)})
	s.log.Info("country lookups switched", "enabled", on, "admin", admin.ID)
	return connect.NewResponse(&panelv1.SetGeoIPEnabledResponse{Status: statusProto(st)}), nil
}

// audit records what an admin did. A failure is logged and does not fail the
// call: what it records has happened.
func (m *Manager) audit(ctx context.Context, adminID, action string, details map[string]string) {
	entry := &store.AuditEntry{AdminID: adminID, Action: action, Target: auditTarget, Details: details}
	if err := m.db.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		m.log.Error("could not write the audit log", "action", action, "err", err)
	}
}

// statusProto is the API form of a status, with the words of the attribution
// that DB-IP asks for.
func statusProto(s Status) *panelv1.GeoIPStatus {
	out := &panelv1.GeoIPStatus{
		Enabled:        s.Enabled,
		Present:        s.Present,
		Month:          s.Month,
		Size:           s.Size,
		Sha256:         s.SHA256,
		Error:          s.Error,
		Attribution:    geoip.Attribution,
		AttributionUrl: geoip.AttributionURL,
		Licence:        geoip.Licence,
	}
	if !s.Built.IsZero() {
		out.BuiltUnix = s.Built.Unix()
	}
	if !s.Fetched.IsZero() {
		out.FetchedUnix = s.Fetched.Unix()
	}
	if !s.Checked.IsZero() {
		out.CheckedUnix = s.Checked.Unix()
	}
	return out
}
