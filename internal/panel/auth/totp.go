package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/totp"
)

const (
	// totpIssuer is the name that authenticator apps show for the account.
	totpIssuer = "Postern"

	// totpStep is the length of a step of TOTP. internal/totp does not export
	// it; authenticator apps all use 30 seconds.
	totpStep = 30 * time.Second

	// pendingTotpTTL is how long a secret that BeginTotp made waits for
	// ConfirmTotp.
	pendingTotpTTL = 10 * time.Minute
)

// pendingTotp is a secret that BeginTotp has made and ConfirmTotp has not
// confirmed yet. It is kept in memory, so it does not outlive the panel and is
// never written down in the clear.
type pendingTotp struct {
	secret  string
	expires time.Time
}

// totpAAD is the additional data that a TOTP secret is sealed with, which ties it
// to the admin it belongs to.
func totpAAD(adminID string) []byte { return []byte("totp:" + adminID) }

// totpStepKey is the key of the setting that holds the step of the last code of
// TOTP that was accepted for an admin.
func totpStepKey(adminID string) string { return "auth.totp_step." + adminID }

// BeginTotp makes a secret for the admin and returns it. TOTP is on only when
// ConfirmTotp has seen a code made from it.
func (s *Service) BeginTotp(ctx context.Context, req *connect.Request[panelv1.BeginTotpRequest]) (*connect.Response[panelv1.BeginTotpResponse], error) {
	ci, err := s.requireSession(ctx, req.Header(), req.Peer())
	if err != nil {
		return nil, err
	}
	// A secret that is on is not replaced by asking for another: whoever has the
	// session could lock the admin out. TOTP is turned off first, which takes
	// the password and a code.
	if len(ci.admin.TOTPSecretEnc) > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP is on already; turn it off first"))
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return nil, s.fail("could not make a TOTP secret", err)
	}

	now := s.now()
	s.pendMu.Lock()
	for id, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, id)
		}
	}
	s.pending[ci.admin.ID] = pendingTotp{secret: secret, expires: now.Add(pendingTotpTTL)}
	s.pendMu.Unlock()

	return connect.NewResponse(&panelv1.BeginTotpResponse{
		Secret:     secret,
		OtpauthUri: totp.URI(secret, ci.admin.Username, totpIssuer),
	}), nil
}

// pendingFor returns the secret that waits for the admin, if there is one that
// has not run out of time.
func (s *Service) pendingFor(adminID string) (pendingTotp, bool) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	p, ok := s.pending[adminID]
	if !ok || !s.now().Before(p.expires) {
		delete(s.pending, adminID)
		return pendingTotp{}, false
	}
	return p, true
}

// ConfirmTotp turns TOTP on, if the code is one of the secret that BeginTotp
// made. It asks for the password: whoever holds a session can begin a set-up with
// a secret of their own, and must not be able to finish it, which would lock the
// admin out of the account. The code is used up: it cannot be used to sign in
// straight away.
func (s *Service) ConfirmTotp(ctx context.Context, req *connect.Request[panelv1.ConfirmTotpRequest]) (*connect.Response[panelv1.ConfirmTotpResponse], error) {
	ci, err := s.requireSession(ctx, req.Header(), req.Peer())
	if err != nil {
		return nil, err
	}
	p, ok := s.pendingFor(ci.admin.ID)
	if !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no TOTP set-up is in progress; start again"))
	}
	// The password is asked for before the code is looked at. The code is of a
	// secret that this very session made, so it says nothing that the session does
	// not know; the password is the proof.
	if err := s.confirm(ctx, ci, req.Msg.GetPassword(), "", false); err != nil {
		return nil, err
	}
	step, ok := matchStep(p.secret, cleanCode(req.Msg.GetCode()), s.now())
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the verification code is wrong"))
	}
	sealed, err := seal.Seal(s.key, []byte(p.secret), totpAAD(ci.admin.ID))
	if err != nil {
		return nil, s.fail("could not seal a TOTP secret", err)
	}

	err = s.withAdmin(ctx, ci, func(ctx context.Context, a *store.Admin) error {
		if len(a.TOTPSecretEnc) > 0 {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP is on already"))
		}
		if a.PasswordHash != ci.admin.PasswordHash {
			return errChangedMeanwhile() // the password that was checked is not the password
		}
		a.TOTPSecretEnc = sealed
		if err := s.db.UpdateAdmin(ctx, a); err != nil {
			return s.fail("could not write an admin", err)
		}
		if err := s.db.PutSetting(ctx, totpStepKey(a.ID), step); err != nil {
			// TOTP is on. The code that confirmed it may be used once more.
			s.log.Warn("could not note the step of a TOTP code", "admin", a.ID, "err", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.pendMu.Lock()
	delete(s.pending, ci.admin.ID)
	s.pendMu.Unlock()
	s.log.Info("TOTP turned on", "admin", ci.admin.ID, "ip", ci.ip)
	s.audit(ctx, "auth.totp_enabled", ci.admin, ci, nil)
	return connect.NewResponse(&panelv1.ConfirmTotpResponse{}), nil
}

// DisableTotp turns TOTP off, for the password and a code, and ends all the
// sessions of the admin.
func (s *Service) DisableTotp(ctx context.Context, req *connect.Request[panelv1.DisableTotpRequest]) (*connect.Response[panelv1.DisableTotpResponse], error) {
	ci, err := s.requireSession(ctx, req.Header(), req.Peer())
	if err != nil {
		return nil, err
	}
	if len(ci.admin.TOTPSecretEnc) == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP is not on"))
	}
	if err := s.confirm(ctx, ci, req.Msg.GetPassword(), cleanCode(req.Msg.GetCode()), true); err != nil {
		return nil, err
	}

	var cookie *http.Cookie
	err = s.withAdmin(ctx, ci, func(ctx context.Context, a *store.Admin) error {
		if !sameCredentials(a, ci.admin) {
			return errChangedMeanwhile()
		}
		c, err := s.replaceSessions(ctx, a, ci, func(a *store.Admin) { a.TOTPSecretEnc = nil })
		if err != nil {
			return err
		}
		cookie = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.log.Info("TOTP turned off", "admin", ci.admin.ID, "ip", ci.ip)
	s.audit(ctx, "auth.totp_disabled", ci.admin, ci, nil)

	resp := connect.NewResponse(&panelv1.DisableTotpResponse{})
	resp.Header().Add("Set-Cookie", cookie.String())
	return resp, nil
}

// matchStep reports whether code is a code of secret for the step of t, or the
// one before or after it, which is what internal/totp accepts, and which step
// it is: the number of 30-second steps since the Unix epoch. If it fits more
// than one step, which is a chance of one in a million, it is the latest.
func matchStep(secret, code string, t time.Time) (step int64, ok bool) {
	if !totp.Verify(secret, code, t) {
		return 0, false
	}
	current := t.Unix() / int64(totpStep/time.Second)
	found := false
	for n := current - 1; n <= current+1; n++ {
		c, err := totp.Code(secret, time.Unix(n*int64(totpStep/time.Second), 0))
		if err == nil && subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			step, found = n, true
		}
	}
	return step, found
}

// acceptCode reports whether code is a current code of the TOTP secret of the
// admin, one that has not been used. It remembers the step of an accepted code,
// and refuses that step and the ones before it from then on, so that a code that
// has been seen, by someone who looked over a shoulder or sat in the middle of
// the connection, cannot be used again while it is still within the window. The
// check and the note are one step under the lock, so two requests with the same
// code cannot both pass.
func (s *Service) acceptCode(ctx context.Context, admin *store.Admin, code string) (bool, error) {
	plain, err := seal.Open(s.key, admin.TOTPSecretEnc, totpAAD(admin.ID))
	if err != nil {
		return false, fmt.Errorf("open the TOTP secret of an admin: %w", err)
	}
	step, ok := matchStep(string(plain), code, s.now())
	if !ok {
		return false, nil
	}

	ctx, cancel := commitContext(ctx)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	var last int64
	if _, err := s.db.GetSetting(ctx, totpStepKey(admin.ID), &last); err != nil {
		return false, err
	}
	if step <= last {
		return false, nil
	}
	if err := s.db.PutSetting(ctx, totpStepKey(admin.ID), step); err != nil {
		return false, err
	}
	return true, nil
}
