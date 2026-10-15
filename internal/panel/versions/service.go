// Package versions is the VersionService of the panel: the catalog of the
// releases of every component, the channels that nodes follow, the rollouts
// that move a channel or switch engines one step at a time, and the update of
// the panel itself.
//
// This file holds the service type, how it is mounted, and what every
// procedure shares. The procedures live in files of their own, which later
// changes add: catalog.go (components and releases), channels.go, rollouts.go
// and panel.go, each with the dependencies it needs, set on the Service. Until
// a procedure is added it answers that it is not implemented, through the
// embedded handler.
package versions

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// Service is the VersionService of the panel.
//
// Every call needs an admin: the auth middleware refuses calls without a
// session, the handler of [Service.Handler] refuses them again, and a procedure
// asks requireAdmin first, so that the service is safe however it is mounted,
// whichever procedures it has.
type Service struct {
	panelv1connect.UnimplementedVersionServiceHandler
	db       *store.DB
	log      *slog.Logger
	rollouts *rollout.Runner      // set by SetRollouts; nil until then
	catalog  *releases.Catalog    // set by SetCatalog; nil until then
	proxies  Proxies              // set by SetProxies; nil until then
	releases *selfupdate.Releases // set by SetReleases; nil until then
	panel    panelUpdate          // set by SetUpdater; no updater until then
}

var _ panelv1connect.VersionServiceHandler = (*Service)(nil)

// New returns the VersionService on the database. A nil log discards the log.
func New(db *store.DB, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{db: db, log: log}
}

// Handler returns the path and the handler of the service, as
// panelv1connect.NewVersionServiceHandler does, with every call behind
// [auth.RequireAdmin]: a request that the auth middleware found no admin for is
// answered with a Connect error of code unauthenticated (HTTP 401), whichever
// procedure it is for.
func (s *Service) Handler(opts ...connect.HandlerOption) (string, http.Handler) {
	path, h := panelv1connect.NewVersionServiceHandler(s, opts...)
	return path, auth.RequireAdmin(h)
}

// requireAdmin returns the admin of the request, or the error to answer with: a
// Connect error of code unauthenticated. A procedure calls it first.
func requireAdmin(ctx context.Context) (*store.Admin, error) {
	a, ok := auth.AdminFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return a, nil
}

// audit records what the admin of the request did: the action (for example
// "versions.rollout.start"), what it was about (for example "rollout:<id>") and
// details, which may be nil. What the panel did by itself, with no admin in the
// context, is recorded without one. A failure is logged and does not fail the
// call: what it records has happened.
func (s *Service) audit(ctx context.Context, action, target string, details map[string]string) {
	entry := &store.AuditEntry{Action: action, Target: target, Details: details}
	if a, ok := auth.AdminFrom(ctx); ok {
		entry.AdminID = a.ID
	}
	if err := s.db.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		s.log.Error("could not write the audit log", "action", action, "target", target, "err", err)
	}
}
