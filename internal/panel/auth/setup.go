package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// setupTokenTTL is how long the setup token is good for.
const setupTokenTTL = time.Hour

// setupToken is the one-time token that lets the first admin be made.
type setupToken struct {
	value   string
	expires time.Time
}

// initSetup makes the setup token if the panel has no admin. It is kept in
// memory only: a restart makes a new one, which is how an operator who has lost
// the first gets another. If it cannot be told whether there is an admin, there
// is no token, which is the safe side.
func (s *Service) initSetup() {
	n, err := s.db.CountAdmins(context.Background())
	if err != nil {
		s.log.Error("could not count the admins, so no setup token was made", "err", err)
		return
	}
	if n > 0 {
		return
	}
	value, err := randomToken()
	if err != nil {
		s.log.Error("could not make a setup token", "err", err)
		return
	}
	s.setup = &setupToken{value: value, expires: s.now().Add(setupTokenTTL)}
}

// SetupToken returns the setup token, for the one who starts the panel to show
// it to the operator once; the service does not write it to the log. There is
// one when the service started without an admin; it is good for an hour, and
// until the first Setup that succeeds.
func (s *Service) SetupToken() (token string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setup == nil || !s.now().Before(s.setup.expires) {
		return "", false
	}
	return s.setup.value, true
}

// matches reports whether token is the setup token and it is still good. The
// caller holds s.mu.
func (s *Service) setupTokenMatches(token string) bool {
	if s.setup == nil || !s.now().Before(s.setup.expires) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.setup.value)) == 1
}

func errSetupDone() error {
	return connect.NewError(connect.CodeFailedPrecondition, errors.New("the panel is already set up"))
}

func errSetupToken() error {
	return connect.NewError(connect.CodePermissionDenied,
		errors.New("the setup token is wrong or has expired; restart the panel to get a new one"))
}

// GetSetupStatus says whether the panel has an admin.
func (s *Service) GetSetupStatus(ctx context.Context, _ *connect.Request[panelv1.GetSetupStatusRequest]) (*connect.Response[panelv1.GetSetupStatusResponse], error) {
	n, err := s.db.CountAdmins(ctx)
	if err != nil {
		return nil, s.fail("could not count the admins", err)
	}
	return connect.NewResponse(&panelv1.GetSetupStatusResponse{NeedsSetup: n == 0}), nil
}

// Setup makes the first admin, if the token is the setup token. The token is
// used up by the first Setup that succeeds; one that is turned down for the user
// name or the password leaves it, so that a typo does not mean a restart.
func (s *Service) Setup(ctx context.Context, req *connect.Request[panelv1.SetupRequest]) (*connect.Response[panelv1.SetupResponse], error) {
	ci := s.callOf(ctx, req.Header(), req.Peer())
	msg := req.Msg

	// The cheap checks come first, so that nobody can make the panel hash
	// passwords without the token.
	if err := s.checkNoAdmin(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	known := s.setupTokenMatches(msg.GetSetupToken())
	s.mu.Unlock()
	if !known {
		// Anybody can send a wrong token, as often as they like: debug, not a warning.
		s.log.Debug("setup refused, wrong or expired token", "ip", ci.ip)
		return nil, errSetupToken()
	}
	username := normalizeUsername(msg.GetUsername())
	if err := checkUsername(username); err != nil {
		return nil, err
	}
	if err := checkNewPassword(msg.GetPassword()); err != nil {
		return nil, err
	}
	hash, err := s.hashPassword(ctx, msg.GetPassword())
	if err != nil {
		return nil, s.fail("could not hash a password", err)
	}

	// Two requests with the right token may both be here. The token is used up,
	// and the admin made, under the lock, so only one of them is.
	cctx, cancel := commitContext(ctx)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.db.CountAdmins(cctx)
	if err != nil {
		return nil, s.fail("could not count the admins", err)
	}
	if n > 0 {
		s.setup = nil
		return nil, errSetupDone()
	}
	if !s.setupTokenMatches(msg.GetSetupToken()) {
		return nil, errSetupToken()
	}
	admin := &store.Admin{Username: username, PasswordHash: hash, CreatedAt: s.now()}
	if err := s.db.CreateAdmin(cctx, admin); err != nil {
		return nil, s.fail("could not create the first admin", err)
	}
	s.setup = nil
	s.log.Info("the panel was set up", "admin", admin.ID, "ip", ci.ip)
	s.audit(ctx, "auth.setup", admin, ci, nil)
	return connect.NewResponse(&panelv1.SetupResponse{}), nil
}

// checkNoAdmin returns the error of Setup for a panel that has an admin, and
// drops the setup token, which has no use any more.
func (s *Service) checkNoAdmin(ctx context.Context) error {
	n, err := s.db.CountAdmins(ctx)
	if err != nil {
		return s.fail("could not count the admins", err)
	}
	if n > 0 {
		s.mu.Lock()
		s.setup = nil
		s.mu.Unlock()
		return errSetupDone()
	}
	return nil
}
