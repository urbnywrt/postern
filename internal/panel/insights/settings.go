// Package insights holds the statistics settings of the panel (how long the
// statistics are kept, the IP policy, the probes) and what goes to the nodes
// because of them: a new generation of every node that a change concerns, and
// the country database (GeoIPSync).
package insights

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// CapStatsV2 is the capability of a node that takes the statistics of slice 6:
// countries, member minutes, the IP retention and UploadGeoIP.
const CapStatsV2 = "stats-v2"

// Audit of this package.
const (
	auditUpdate = "settings.update"
	auditTarget = "settings:stats"
)

// geoipBumpTimeout bounds the bump of the nodes after the country database
// changed, which runs on the goroutine of the change.
const geoipBumpTimeout = time.Minute

// errInternal is all that a caller is told of an error of the panel itself.
var errInternal = errors.New("internal error")

// A Notifier is told that the desired generation of a node went up (the node
// manager).
type Notifier interface {
	Notify(nodeID string)
}

// SettingsService is the SettingsService of the panel, and what sends a new
// generation to the nodes when a setting that their state holds changes.
type SettingsService struct {
	db  *store.DB
	n   Notifier
	log *slog.Logger
}

var _ panelv1connect.SettingsServiceHandler = (*SettingsService)(nil)

// NewSettingsService returns the service. A nil notifier notifies nothing; a
// nil log discards the log.
func NewSettingsService(db *store.DB, n Notifier, log *slog.Logger) *SettingsService {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &SettingsService{db: db, n: n, log: log}
}

// EnsureDefaults stores the settings at the first start of a panel that has
// no IP policy stored, and bumps every node once, so that the nodes get the
// policy countries deliberately, not with the next change that has nothing to
// do with it (M9). With a policy stored it does nothing.
func (s *SettingsService) EnsureDefaults(ctx context.Context) error {
	cur, stored, err := s.db.StatsSettings(ctx)
	if err != nil {
		return fmt.Errorf("insights: ensure the default settings: %w", err)
	}
	if stored {
		return nil
	}
	if _, err := s.db.ApplyStatsSettings(ctx, cur); err != nil {
		return fmt.Errorf("insights: ensure the default settings: %w", err)
	}
	s.log.Info("stored the default statistics settings; every node gets them", "ip_policy", cur.IPPolicy)
	if err := s.BumpNodes(ctx, nil); err != nil {
		return fmt.Errorf("insights: ensure the default settings: %w", err)
	}
	return nil
}

// BumpNodes raises the desired generation of every node that match accepts
// (every node for a nil match) and notifies the manager of each. A node that
// is deleted meanwhile is skipped; the other errors are joined.
func (s *SettingsService) BumpNodes(ctx context.Context, match func(*store.Node) bool) error {
	ns, err := s.db.ListNodes(ctx)
	if err != nil {
		return fmt.Errorf("insights: bump the nodes: %w", err)
	}
	var errs []error
	for _, n := range ns {
		if match != nil && !match(n) {
			continue
		}
		if _, err := s.db.NextNodeGeneration(ctx, n.ID); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				errs = append(errs, fmt.Errorf("node %s: %w", n.ID, err))
			}
			continue
		}
		if s.n != nil {
			s.n.Notify(n.ID)
		}
	}
	return errors.Join(errs...)
}

// GeoIPChanged is what the country database tells when the database that is
// sent to the nodes may have changed (geodb.Manager.OnChange): while the
// policy uses countries, every node that takes the database (stats-v2) gets a
// state that names the new one.
func (s *SettingsService) GeoIPChanged(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), geoipBumpTimeout)
	defer cancel()
	st, _, err := s.db.StatsSettings(ctx)
	if err != nil {
		s.log.Error("could not read the statistics settings after the country database changed", "err", err)
		return
	}
	if st.IPPolicy != store.IPPolicyFull && st.IPPolicy != store.IPPolicyCountries {
		return
	}
	if err := s.BumpNodes(ctx, HasStatsV2); err != nil {
		s.log.Error("could not send the new country database to the nodes", "err", err)
	}
}

// HasStatsV2 reports whether a node reported the capability stats-v2.
func HasStatsV2(n *store.Node) bool { return slices.Contains(n.HostInfo.Capabilities, CapStatsV2) }

// requireAdmin returns the admin of the request, or the error to answer with.
func requireAdmin(ctx context.Context) (*store.Admin, error) {
	a, ok := auth.AdminFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return a, nil
}

// fail is the package's fail on the log of the service.
func (s *SettingsService) fail(what string, err error) error {
	return fail(s.log, what, err)
}

// fail turns an error of the panel itself into the error that a caller gets,
// and logs it to log.
func fail(log *slog.Logger, what string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, errors.New("the request was canceled"))
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, errors.New("the request took too long"))
	}
	log.Error(what, "err", err)
	return connect.NewError(connect.CodeInternal, errInternal)
}

// GetStatsSettings returns the settings and the addresses that the nodes see
// the panel come from.
func (s *SettingsService) GetStatsSettings(ctx context.Context, _ *connect.Request[panelv1.GetStatsSettingsRequest]) (*connect.Response[panelv1.GetStatsSettingsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := s.response(ctx)
	if err != nil {
		return nil, s.fail("could not read the statistics settings", err)
	}
	return connect.NewResponse(resp), nil
}

// response is the answer of GetStatsSettings and UpdateStatsSettings.
func (s *SettingsService) response(ctx context.Context) (*panelv1.GetStatsSettingsResponse, error) {
	st, _, err := s.db.StatsSettings(ctx)
	if err != nil {
		return nil, err
	}
	ns, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := &panelv1.GetStatsSettingsResponse{Settings: settingsProto(st)}
	for _, n := range ns {
		for _, a := range n.PanelAddrs {
			out.PanelAddresses = append(out.PanelAddresses, &panelv1.PanelAddress{NodeId: n.ID, Addr: a, Shared: Shared(a)})
		}
	}
	return out, nil
}

// UpdateStatsSettings validates and stores the settings, with what the new IP
// policy deletes, in one transaction (store.ApplyStatsSettings), audits it and,
// when the IP policy, ip_days or the extra probe sources changed, bumps every
// node.
func (s *SettingsService) UpdateStatsSettings(ctx context.Context, req *connect.Request[panelv1.UpdateStatsSettingsRequest]) (*connect.Response[panelv1.GetStatsSettingsResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	in := req.Msg.GetSettings()
	if in == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("settings are required"))
	}
	next := store.StatsSettings{
		MinutesHours: in.GetMinutesHours(), HoursDays: in.GetHoursDays(), IPDays: in.GetIpDays(),
		IPPolicy: in.GetIpPolicy(), ProbeIntervalMinutes: in.GetProbeIntervalMinutes(),
		ExtraProbeSources: slices.Clone(in.GetExtraProbeSources()),
	}
	if err := next.Validate(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// Valid, so each is an address: kept in its usual form, once.
	var sources []string
	for _, src := range next.ExtraProbeSources {
		a := netip.MustParseAddr(src).Unmap().String()
		if !slices.Contains(sources, a) {
			sources = append(sources, a)
		}
	}
	next.ExtraProbeSources = sources

	prev, _, err := s.db.StatsSettings(ctx)
	if err != nil {
		return nil, s.fail("could not read the statistics settings", err)
	}
	deleted, err := s.db.ApplyStatsSettings(ctx, next)
	if err != nil {
		return nil, s.fail("could not store the statistics settings", err)
	}
	s.audit(ctx, admin.ID, next, deleted)
	if prev.IPPolicy != next.IPPolicy || prev.IPDays != next.IPDays || !slices.Equal(prev.ExtraProbeSources, next.ExtraProbeSources) {
		if err := s.BumpNodes(context.WithoutCancel(ctx), nil); err != nil {
			s.log.Error("could not send the new statistics settings to every node", "err", err)
		}
	}
	resp, err := s.response(ctx)
	if err != nil {
		return nil, s.fail("could not read the statistics settings", err)
	}
	return connect.NewResponse(resp), nil
}

// GetStorage says how much room the database takes.
func (s *SettingsService) GetStorage(ctx context.Context, _ *connect.Request[panelv1.GetStorageRequest]) (*connect.Response[panelv1.Storage], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	info, err := s.db.Storage(ctx)
	if err != nil {
		return nil, s.fail("could not read the size of the database", err)
	}
	return connect.NewResponse(&panelv1.Storage{FileBytes: info.FileBytes, FreeBytes: info.FreeBytes, Rows: info.Rows}), nil
}

// audit records the settings that an admin stored, and what they deleted. A
// failure is logged: what it records has happened.
func (s *SettingsService) audit(ctx context.Context, adminID string, st store.StatsSettings, d store.Deleted) {
	details := map[string]string{
		"minutes_hours":          strconv.FormatUint(uint64(st.MinutesHours), 10),
		"hours_days":             strconv.FormatUint(uint64(st.HoursDays), 10),
		"ip_days":                strconv.FormatUint(uint64(st.IPDays), 10),
		"ip_policy":              st.IPPolicy,
		"probe_interval_minutes": strconv.FormatUint(uint64(st.ProbeIntervalMinutes), 10),
		"extra_probe_sources":    strings.Join(st.ExtraProbeSources, ","),
	}
	if d.Sightings > 0 {
		details["deleted_sightings"] = strconv.FormatInt(d.Sightings, 10)
	}
	if d.CountryRows > 0 {
		details["deleted_country_rows"] = strconv.FormatInt(d.CountryRows, 10)
	}
	entry := &store.AuditEntry{AdminID: adminID, Action: auditUpdate, Target: auditTarget, Details: details}
	if err := s.db.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		s.log.Error("could not write the audit log", "action", auditUpdate, "err", err)
	}
}

// settingsProto is the API form of the settings.
func settingsProto(s store.StatsSettings) *panelv1.StatsSettings {
	return &panelv1.StatsSettings{
		MinutesHours: s.MinutesHours, HoursDays: s.HoursDays, IpDays: s.IPDays, IpPolicy: s.IPPolicy,
		ProbeIntervalMinutes: s.ProbeIntervalMinutes, ExtraProbeSources: slices.Clone(s.ExtraProbeSources),
	}
}

// cgnat is the shared address space of carriers (RFC 6598).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Shared reports whether an address may be more than the panel's own: private
// (RFC 1918), unique local (fc00::/7), link-local, or in 100.64.0.0/10. An
// address that does not parse is not reported shared.
func Shared(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
}
