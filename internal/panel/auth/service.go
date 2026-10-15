// Package auth signs the admins of the panel in. It is the AuthService, the
// sessions that it starts, and the middleware that lets only admins call the
// other services of the panel.
//
// # Credentials
//
// An admin has a user name, which is not case-sensitive and is stored in lower
// case, a password, and, if the admin wants, TOTP. Passwords have at least 12
// characters and at most 256 bytes, and are stored as argon2id hashes (see
// internal/passwd). Every hash and every check takes 64 MiB while it runs, so
// at most two run at once, and a password of more than 256 bytes is turned down
// before it is hashed. A TOTP secret is stored sealed with the master key and
// the additional data "totp:<admin id>" (see internal/seal), and a code is
// accepted once: the panel remembers the step of the last code that it has
// accepted for an admin, and refuses that step and every step before it.
//
// What a stolen session can do is limited by asking for the credentials again.
// ChangePassword takes the current password, and a code when TOTP is on;
// ConfirmTotp takes the password, so that nobody with a session can enrol an
// authenticator of their own; DisableTotp takes the password and a code.
//
// # Sessions
//
// A session is a random token of 256 bits that the browser holds in an HttpOnly,
// SameSite=Strict cookie, and that the database knows by its SHA-256 only, so a
// copy of the database does not sign anybody in. A session lasts a week from its
// last touch, and is touched at most once an hour. Changing the password and
// turning TOTP off end every session of the admin, including the one that asked,
// which is replaced by a new one for the caller so that nobody is signed out of
// the browser that they are using.
//
// # Limits
//
// Five failed attempts to sign in within 15 minutes lock the address that they
// came from, for 15 minutes, and every lock after that for twice as long as the
// one before, up to a day. Five of them for one user name from one address lock
// that user name for that address the same way, also when a success from the
// address in between has cleared its own count. A user name is never locked for
// everybody: anybody who knows the name of the admin could keep the admin out.
// A refusal says when to try again in a Retry-After header.
//
// Against an attack that is spread over many addresses there is a slowdown, and
// no lock: while more than 100 attempts, from all the addresses together, have
// failed within the last minute, every attempt waits a second before anything
// about it is looked up or checked.
//
// A user name that does not exist is limited like one that does, waits as long
// and is checked as slowly, so that neither the answer nor the time says which
// names exist. The password that ChangePassword, ConfirmTotp and DisableTotp ask
// for again, and the codes that the first and the last ask for, count on the
// same limits and wait the same.
//
// The address that an attempt is counted under is the one that the connection
// comes from. Behind a reverse proxy that would be the address of the proxy for
// every client, so a request from a proxy of the panel is counted under the
// address that the proxy puts in X-Forwarded-For. Which peers are proxies is
// configured, see [WithTrustedProxies]: by default the loopback, and nothing is
// one for being on a private network. A header from any other peer is ignored.
// So is X-Forwarded-Proto, which says whether the client is on https, and so
// whether the session cookie is Secure: it is believed from a proxy only, and
// of its values the last only, the one that the proxy wrote.
//
// # Concurrency
//
// The record of an admin is written whole, so two requests that change it, say a
// sign-in that notes its time and a change of the password, could undo each
// other. All writes to it, and all that create a session, are made one at a time
// under a lock, on a fresh copy, and a sign-in that has checked the credentials
// that were there when it began makes its session only if they are still there.
// Whatever the order of a password change and the sign-ins around it, no session
// that was made with the old password survives it.
package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/passwd"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	minPasswordChars = 12
	maxPasswordBytes = 256

	// A user name is 1 to 64 characters. The bytes are bounded too, so that a name
	// with many bytes to the character is not made a key of the limiter.
	maxUsernameChars = 64
	maxUsernameBytes = 256

	// maxPasswordWork is how many passwords are hashed or checked at once.
	maxPasswordWork = 2

	// commitTimeout bounds the changes to the record of an admin, which go on
	// when the client has gone, so that they are done or not done as a whole.
	commitTimeout = 10 * time.Second

	// The keys of the limiter: an address (see ipKey), and an address and a user
	// name (see pairKey).
	ipKeyPrefix   = "ip:"
	pairKeyPrefix = "pair:"
)

// errInternal is the only thing that a caller is told of an error of the panel
// itself. What it was is in the log.
var errInternal = errors.New("internal error")

// dummyHash is the hash that a password is checked against when the user does
// not exist: one of the cost that every hash has, made once.
var dummyHash = sync.OnceValue(func() string {
	h, err := passwd.Hash("a password that nobody has")
	if err != nil {
		panic("auth: " + err.Error()) // crypto/rand has failed, and nothing can be done
	}
	return h
})

// Service is the AuthService of the panel, and the middleware that goes with it.
type Service struct {
	db  *store.DB
	key seal.Key
	log *slog.Logger

	// What tests replace.
	now    func() time.Time
	hash   func(password string) (string, error)
	verify func(encoded, password string) (bool, error)
	sleep  func(ctx context.Context, d time.Duration) error // the wait of the slowdown
	dummy  string                                           // see dummyHash

	// trusted holds the proxies of the panel, the peers whose X-Forwarded-For is
	// believed, see clientIP and WithTrustedProxies.
	trusted []netip.Prefix

	limits     *limiter
	failAudits auditLimiter   // see auditFailure
	recent     recentFailures // the failures of every address, for the slowdown
	slots      chan struct{}  // a slot is taken while a password is hashed or checked

	// mu serialises the writes to the record of an admin, the creation of
	// sessions, the steps of TOTP codes, and the setup token. It is not held while
	// a password is hashed or checked.
	mu    sync.Mutex
	setup *setupToken // nil: none

	pendMu  sync.Mutex
	pending map[string]pendingTotp // by admin id: secrets that wait to be confirmed
}

var _ panelv1connect.AuthServiceHandler = (*Service)(nil)

// NewService returns the AuthService on the database, sealing with key. If the
// database has no admin yet it makes the setup token, see [Service.SetupToken].
// A nil log discards the log. The options say which peers are proxies, see
// [WithTrustedProxies]; by default only the loopback is.
func NewService(db *store.DB, key seal.Key, log *slog.Logger, opts ...Option) *Service {
	return newService(db, key, log, time.Now, opts...)
}

func newService(db *store.DB, key seal.Key, log *slog.Logger, now func() time.Time, opts ...Option) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		db:      db,
		key:     key,
		log:     log,
		now:     now,
		hash:    passwd.Hash,
		verify:  passwd.Verify,
		sleep:   sleepCtx,
		dummy:   dummyHash(),
		slots:   make(chan struct{}, maxPasswordWork),
		pending: make(map[string]pendingTotp),
		trusted: defaultTrustedProxies(),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.limits = newLimiter(func() time.Time { return s.now() })
	s.initSetup()
	return s
}

// hashPassword hashes a password, when one of the slots for passwords is free.
func (s *Service) hashPassword(ctx context.Context, password string) (string, error) {
	if err := s.acquire(ctx); err != nil {
		return "", err
	}
	defer s.release()
	return s.hash(password)
}

// checkPassword checks a password against a hash, when a slot is free. A wrong
// password is false and no error.
func (s *Service) checkPassword(ctx context.Context, encoded, password string) (bool, error) {
	if err := s.acquire(ctx); err != nil {
		return false, err
	}
	defer s.release()
	return s.verify(encoded, password)
}

// acquire waits for a slot, and gives up when the request is gone.
func (s *Service) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) release() { <-s.slots }

// failure turns an error of the panel itself into the error that a caller gets,
// and logs it. A request that is gone or has run out of time says so and is not
// logged, since that is not a fault of the panel.
func (s *Service) failure(what string, err error) *connect.Error {
	switch {
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, errors.New("the request was canceled"))
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, errors.New("the request took too long"))
	}
	s.log.Error(what, "err", err)
	return connect.NewError(connect.CodeInternal, errInternal)
}

// fail is failure as an error, for the procedures to return.
func (s *Service) fail(what string, err error) error { return s.failure(what, err) }

// warn logs a failure that does not stop the request that met it. A request
// that is gone is not one.
func (s *Service) warn(msg string, err error, args ...any) {
	if errors.Is(err, context.Canceled) {
		return
	}
	s.log.Warn(msg, append(args, "err", err)...)
}

func errBadCredentials() error {
	return connect.NewError(connect.CodeUnauthenticated, errors.New("invalid user name or password"))
}

func errNotSignedIn() error {
	return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
}

func errChangedMeanwhile() error {
	return connect.NewError(connect.CodeAborted, errors.New("the credentials changed in the meantime; try again"))
}

// tooManyAttempts is the refusal of an attempt that the limiter did not let in.
func tooManyAttempts(wait time.Duration) error {
	secs := max(int(math.Ceil(wait.Seconds())), 1)
	err := connect.NewError(connect.CodeResourceExhausted,
		fmt.Errorf("too many failed attempts; try again in %d seconds", secs))
	err.Meta().Set("Retry-After", strconv.Itoa(secs))
	return err
}

// pairKey is the key under which the limiter counts the attempts from an
// address, as ipKey gives it, for one user name. An address has no "|", so the
// key of one pair is never the key of another.
func pairKey(ip, username string) string { return pairKeyPrefix + ip + "|" + username }

// slowDown makes an attempt that the limiter has let in wait for slowWait while
// many attempts have failed of late, from all the addresses together (see
// recentFailures). It is called before anything about the attempt is looked up
// or checked, so that it waits the same for every user name, whether it exists
// or not. It returns the error of ctx when the request is gone before the wait
// is over: the attempt was not checked, and is no failure.
func (s *Service) slowDown(ctx context.Context) error {
	if !s.recent.many(s.now()) {
		return nil
	}
	return s.sleep(ctx, slowWait)
}

// commitContext is ctx without its cancellation, and with a time limit.
func commitContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), commitTimeout)
}

// normalizeUsername is the form in which user names are compared and stored.
func normalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// checkUsername reports what is wrong with a user name that is normalized.
func checkUsername(name string) error {
	if n := utf8.RuneCountInString(name); n < 1 || n > maxUsernameChars {
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the user name must have 1 to %d characters", maxUsernameChars))
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return connect.NewError(connect.CodeInvalidArgument,
				errors.New("the user name must not contain spaces or control characters"))
		}
	}
	return nil
}

// checkNewPassword reports what is wrong with a password that is to be set.
func checkNewPassword(password string) error {
	if len(password) > maxPasswordBytes {
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the password must not be longer than %d bytes", maxPasswordBytes))
	}
	if utf8.RuneCountInString(password) < minPasswordChars {
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the password must have at least %d characters", minPasswordChars))
	}
	return nil
}

// cleanCode removes the spaces that people type, or paste, into a code: apps
// show it as two groups of three.
func cleanCode(code string) string { return strings.Join(strings.Fields(code), "") }

// requireSession returns the call, which has a session if it came through the
// middleware with a good cookie, and the error for a caller that is not signed
// in. A procedure that is not public calls it first, so that it does not depend
// on the middleware being there.
func (s *Service) requireSession(ctx context.Context, h http.Header, peer connect.Peer) (*callInfo, error) {
	ci := s.callOf(ctx, h, peer)
	if ci.admin == nil || ci.session == nil {
		return nil, errNotSignedIn()
	}
	return ci, nil
}

// Login checks the user name and the password, and the code if the admin has
// TOTP, and starts a session.
func (s *Service) Login(ctx context.Context, req *connect.Request[panelv1.LoginRequest]) (*connect.Response[panelv1.LoginResponse], error) {
	ci := s.callOf(ctx, req.Header(), req.Peer())
	username := normalizeUsername(req.Msg.GetUsername())
	password := req.Msg.GetPassword()
	code := cleanCode(req.Msg.GetTotpCode())

	// The attempt counts on its address, and on its address and its user name.
	// A name that is too long to be one is not made a key: nobody has it.
	ip := ipKey(ci.ip)
	keys := []string{ipKeyPrefix + ip}
	if utf8.RuneCountInString(username) <= maxUsernameChars && len(username) <= maxUsernameBytes {
		keys = append(keys, pairKey(ip, username))
	}
	att, wait := s.limits.begin(keys...)
	if att == nil {
		s.log.Debug("sign-in refused, too many failed attempts", "ip", ci.ip, "wait", wait)
		return nil, tooManyAttempts(wait)
	}
	defer att.release()
	if err := s.slowDown(ctx); err != nil {
		return nil, s.fail("could not wait to check a sign-in", err)
	}

	admin, err := s.db.AdminByUsername(ctx, username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		admin = nil
	case err != nil:
		return nil, s.fail("could not look up an admin", err)
	}

	// A user that does not exist is checked against a hash of the same cost, so
	// that the answer does not come sooner for a name that nobody has.
	encoded := s.dummy
	if admin != nil {
		encoded = admin.PasswordHash
	}
	ok := false
	if len(password) <= maxPasswordBytes {
		ok, err = s.checkPassword(ctx, encoded, password)
		if err != nil {
			return nil, s.fail("could not check a password", err)
		}
	}
	if admin == nil || !ok {
		s.failed(ctx, att, ci, admin, "auth.login_failed", "wrong password")
		return nil, errBadCredentials()
	}

	if len(admin.TOTPSecretEnc) > 0 {
		if code == "" {
			// The password is right, and the second step is to come: that is not
			// a failure, and nothing is counted.
			return connect.NewResponse(&panelv1.LoginResponse{TotpRequired: true}), nil
		}
		good, err := s.acceptCode(ctx, admin, code)
		if err != nil {
			return nil, s.fail("could not check a TOTP code", err)
		}
		if !good {
			s.failed(ctx, att, ci, admin, "auth.login_failed", "wrong code")
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid verification code"))
		}
	}

	cookie, err := s.completeLogin(ctx, admin, ci, cookieToken(req.Header()))
	if err != nil {
		return nil, err
	}
	att.succeed()
	s.log.Info("signed in", "admin", admin.ID, "ip", ci.ip)
	s.audit(ctx, "auth.login", admin, ci, nil)

	resp := connect.NewResponse(&panelv1.LoginResponse{})
	resp.Header().Add("Set-Cookie", cookie.String())
	return resp, nil
}

// failed counts the attempt as a failure, for the limits and for the slowdown,
// logs it, and the locks that it made, and writes it to the audit log as
// action, see auditFailure. The user name that was typed is not
// logged: it may be a password that went into the wrong field.
func (s *Service) failed(ctx context.Context, att *attempt, ci *callInfo, admin *store.Admin, action, reason string) {
	locked := att.fail()
	s.auditFailure(ctx, action, admin, ci, reason)
	s.recent.add(s.now())
	who := []any{}
	if admin != nil {
		who = append(who, "admin", admin.ID)
	}
	s.log.Warn("sign-in failed", append([]any{"ip", ci.ip, "reason", reason}, who...)...)
	for _, key := range locked {
		if strings.HasPrefix(key, ipKeyPrefix) {
			s.log.Warn("address locked after too many failed attempts", "ip", ci.ip)
		} else {
			s.log.Warn("user name locked for an address after too many failed attempts", append([]any{"ip", ci.ip}, who...)...)
		}
	}
}

// completeLogin makes the session of an admin whose credentials Login has
// checked. It does so only if they are the ones that are there now: a password
// change that came in between has ended the sessions that it was meant to end,
// and this must not make a new one.
func (s *Service) completeLogin(ctx context.Context, checked *store.Admin, ci *callInfo, oldToken string) (*http.Cookie, error) {
	ctx, cancel := commitContext(ctx)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()

	fresh, err := s.db.AdminByID(ctx, checked.ID)
	if err != nil {
		return nil, s.fail("could not read an admin", err)
	}
	if !sameCredentials(fresh, checked) {
		return nil, errChangedMeanwhile()
	}
	cookie, err := s.startSession(ctx, fresh.ID, ci)
	if err != nil {
		return nil, s.fail("could not start a session", err)
	}

	now := s.now()
	fresh.LastLoginAt = &now
	if err := s.db.UpdateAdmin(ctx, fresh); err != nil {
		s.log.Warn("could not note the time of a sign-in", "admin", fresh.ID, "err", err)
	}
	// The browser had a session, which its new cookie replaces. Sessions that
	// nobody has used for a week are deleted now and then; this is the time.
	if oldToken != "" {
		s.dropSession(ctx, hashToken(oldToken))
	}
	if _, err := s.db.DeleteExpiredSessions(ctx, now); err != nil {
		s.log.Warn("could not delete expired sessions", "err", err)
	}
	return cookie, nil
}

// sameCredentials reports whether two copies of an admin have the same password
// and the same TOTP secret.
func sameCredentials(a, b *store.Admin) bool {
	return a.PasswordHash == b.PasswordHash && bytes.Equal(a.TOTPSecretEnc, b.TOTPSecretEnc)
}

// Logout ends the session of the caller.
func (s *Service) Logout(ctx context.Context, req *connect.Request[panelv1.LogoutRequest]) (*connect.Response[panelv1.LogoutResponse], error) {
	ci, err := s.requireSession(ctx, req.Header(), req.Peer())
	if err != nil {
		return nil, err
	}
	dctx, cancel := commitContext(ctx)
	defer cancel()
	if err := s.db.DeleteSession(dctx, ci.session.TokenHash); err != nil {
		return nil, s.fail("could not delete a session", err)
	}
	s.log.Info("signed out", "admin", ci.admin.ID)

	resp := connect.NewResponse(&panelv1.LogoutResponse{})
	resp.Header().Add("Set-Cookie", clearCookie(ci.secure).String())
	return resp, nil
}

// Me describes the admin of the session.
func (s *Service) Me(ctx context.Context, req *connect.Request[panelv1.MeRequest]) (*connect.Response[panelv1.MeResponse], error) {
	ci, err := s.requireSession(ctx, req.Header(), req.Peer())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.MeResponse{
		Username:    ci.admin.Username,
		TotpEnabled: len(ci.admin.TOTPSecretEnc) > 0,
	}), nil
}

// ChangePassword sets a new password, and ends all the sessions of the admin.
// It asks for the current password, and, when the admin has TOTP on, for a code:
// a session that was stolen, with a password that was seen, must not be enough
// to take the account over.
func (s *Service) ChangePassword(ctx context.Context, req *connect.Request[panelv1.ChangePasswordRequest]) (*connect.Response[panelv1.ChangePasswordResponse], error) {
	ci, err := s.requireSession(ctx, req.Header(), req.Peer())
	if err != nil {
		return nil, err
	}
	next := req.Msg.GetNewPassword()
	if err := checkNewPassword(next); err != nil {
		return nil, err
	}
	// Whether a code is needed is what it was when the request began. If TOTP is
	// turned on in the meantime, withAdmin sees that the secret has changed, and
	// the call is refused instead of being let through without one.
	withCode := len(ci.admin.TOTPSecretEnc) > 0
	if err := s.confirm(ctx, ci, req.Msg.GetCurrentPassword(), cleanCode(req.Msg.GetTotpCode()), withCode); err != nil {
		return nil, err
	}
	hash, err := s.hashPassword(ctx, next)
	if err != nil {
		return nil, s.fail("could not hash a password", err)
	}

	var cookie *http.Cookie
	err = s.withAdmin(ctx, ci, func(ctx context.Context, a *store.Admin) error {
		if !sameCredentials(a, ci.admin) {
			return errChangedMeanwhile()
		}
		c, err := s.replaceSessions(ctx, a, ci, func(a *store.Admin) { a.PasswordHash = hash })
		if err != nil {
			return err
		}
		cookie = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.log.Info("password changed", "admin", ci.admin.ID, "ip", ci.ip)
	s.audit(ctx, "auth.password_changed", ci.admin, ci, nil)

	resp := connect.NewResponse(&panelv1.ChangePasswordResponse{})
	resp.Header().Add("Set-Cookie", cookie.String())
	return resp, nil
}

// confirm asks a signed-in admin for the password again, and for a code of TOTP
// when withCode is set, before a change that matters: ChangePassword,
// ConfirmTotp and DisableTotp. A wrong answer is a failed attempt like one at the
// door, on the same limits: a stolen session must not be a way to guess the
// password at the speed of argon2.
func (s *Service) confirm(ctx context.Context, ci *callInfo, password, code string, withCode bool) error {
	ip := ipKey(ci.ip)
	att, wait := s.limits.begin(ipKeyPrefix+ip, pairKey(ip, ci.admin.Username))
	if att == nil {
		return tooManyAttempts(wait)
	}
	defer att.release()
	if err := s.slowDown(ctx); err != nil {
		return s.fail("could not wait to check a password", err)
	}

	ok := false
	if len(password) <= maxPasswordBytes {
		var err error
		ok, err = s.checkPassword(ctx, ci.admin.PasswordHash, password)
		if err != nil {
			return s.fail("could not check a password", err)
		}
	}
	if !ok {
		s.failed(ctx, att, ci, ci.admin, "auth.reauth_failed", "wrong password when confirming a change")
		return connect.NewError(connect.CodePermissionDenied, errors.New("the password is wrong"))
	}
	if withCode {
		good, err := s.acceptCode(ctx, ci.admin, code)
		if err != nil {
			return s.fail("could not check a TOTP code", err)
		}
		if !good {
			s.failed(ctx, att, ci, ci.admin, "auth.reauth_failed", "wrong code when confirming a change")
			return connect.NewError(connect.CodePermissionDenied, errors.New("the verification code is wrong"))
		}
	}
	att.succeed()
	return nil
}

// withAdmin runs fn on a fresh copy of the admin of the caller, under the lock
// of the admin records, and only if the session of the caller has not been ended
// in the meantime. fn changes the admin, and writes it.
func (s *Service) withAdmin(ctx context.Context, ci *callInfo, fn func(ctx context.Context, fresh *store.Admin) error) error {
	ctx, cancel := commitContext(ctx)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.SessionByTokenHash(ctx, ci.session.TokenHash); errors.Is(err, store.ErrNotFound) {
		return errNotSignedIn()
	} else if err != nil {
		return s.fail("could not look up a session", err)
	}
	fresh, err := s.db.AdminByID(ctx, ci.admin.ID)
	if err != nil {
		return s.fail("could not read an admin", err)
	}
	return fn(ctx, fresh)
}

// replaceSessions applies a change to the admin, which is the record that is
// there now, ends every session of the admin, and starts one for the caller. The
// sessions go first: if that fails, nothing has changed, and if the change fails,
// the admin has to sign in again, which is safe. The caller holds the lock.
func (s *Service) replaceSessions(ctx context.Context, a *store.Admin, ci *callInfo, change func(*store.Admin)) (*http.Cookie, error) {
	if err := s.db.DeleteSessionsForAdmin(ctx, a.ID); err != nil {
		return nil, s.fail("could not end the sessions of an admin", err)
	}
	change(a)
	if err := s.db.UpdateAdmin(ctx, a); err != nil {
		return nil, s.fail("could not write an admin", err)
	}
	cookie, err := s.startSession(ctx, a.ID, ci)
	if err != nil {
		return nil, s.fail("could not start a session", err)
	}
	return cookie, nil
}
