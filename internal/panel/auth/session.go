package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// CookieName is the name of the session cookie.
const CookieName = "postern_session"

const (
	// sessionTTL is how long a session lasts after it was started or last
	// touched. A session that is used is touched when more than touchEvery has
	// passed since the last time, so that a busy session costs a write an hour.
	sessionTTL = 7 * 24 * time.Hour
	touchEvery = time.Hour

	tokenBytes = 32
	tokenLen   = 43 // the length of 32 bytes in unpadded base64url

	// maxUserAgent bounds what is stored of the User-Agent header, which the
	// client chooses.
	maxUserAgent = 256

	// maxPublicBody bounds the body of a request to a procedure that anybody can
	// call. The messages of those are a few hundred bytes.
	maxPublicBody = 64 << 10
)

// publicProcedures can be called without a session.
var publicProcedures = map[string]bool{
	panelv1connect.AuthServiceGetSetupStatusProcedure: true,
	panelv1connect.AuthServiceSetupProcedure:          true,
	panelv1connect.AuthServiceLoginProcedure:          true,
	panelv1connect.HealthServiceCheckProcedure:        true,
	panelv1connect.JoinServiceJoinProcedure:           true,
}

// randomToken returns 32 bytes from crypto/rand as unpadded base64url.
func randomToken() (string, error) {
	var raw [tokenBytes]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("auth: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// newToken returns the token of a new session, which goes into the cookie, and
// the hash that the database keeps of it.
func newToken() (token, hash string, err error) {
	token, err = randomToken()
	if err != nil {
		return "", "", err
	}
	return token, hashToken(token), nil
}

// hashToken is the SHA-256 of the token as it is written in the cookie, in hex.
// The token has 256 bits of its own, so a fast hash is enough: there is nothing
// to guess.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// validToken reports whether s has the form of a token. A cookie that does not
// is not looked up.
func validToken(s string) bool {
	if len(s) != tokenLen {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) == tokenBytes
}

// callKey is the key of the context value that Middleware sets.
type callKey struct{}

// callInfo is what is known of a request: where it comes from, and who sent it.
type callInfo struct {
	ip      string // the address of the client, see clientIP
	secure  bool   // the connection of the client is TLS
	ua      string
	session *store.Session // nil: no valid session
	admin   *store.Admin   // nil: no valid session
}

// callOf returns what Middleware found out about the request. A call that did
// not come through the middleware has no session, so a procedure that needs
// one refuses it; the address and the rest come from the headers and the peer.
func (s *Service) callOf(ctx context.Context, h http.Header, peer connect.Peer) *callInfo {
	if ci, ok := ctx.Value(callKey{}).(*callInfo); ok {
		return ci
	}
	return &callInfo{ip: s.clientIP(peer.Addr, h), secure: s.forwardedHTTPS(peer.Addr, h), ua: userAgent(h)}
}

// CallerIP returns the address of the client of a request as [Service.Middleware]
// resolved it: the peer, or the client that a trusted proxy reports. It is
// false for a request that did not come through the middleware, or whose
// address could not be read.
func CallerIP(ctx context.Context) (netip.Addr, bool) {
	ci, _ := ctx.Value(callKey{}).(*callInfo)
	if ci == nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(ci.ip)
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// IPKey is the key under which a [Limiter] should count an address, as the
// sign-in does: an IPv6 address counts as its /64.
func IPKey(a netip.Addr) string { return ipKey(a.String()) }

// AdminFrom returns the admin whose session the request carries. It is only set
// by [Service.Middleware], and a handler that is for admins only has to ask. The
// admin is a copy, which the handler may change.
func AdminFrom(ctx context.Context) (*store.Admin, bool) {
	ci, _ := ctx.Value(callKey{}).(*callInfo)
	if ci == nil || ci.admin == nil {
		return nil, false
	}
	a := *ci.admin
	a.TOTPSecretEnc = slices.Clone(ci.admin.TOTPSecretEnc)
	if ci.admin.LastLoginAt != nil {
		t := *ci.admin.LastLoginAt
		a.LastLoginAt = &t
	}
	return &a, true
}

var (
	serviceName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
	methodName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// procedureOf returns the Connect procedure that a request path ends in, as
// "/<service>/<method>", where the service is a protobuf name with a package. It
// looks at the last two segments only, so that the answer is the same whether or
// not the middleware sits outside a prefix such as /api that is stripped later,
// and whether or not the path has a stray slash.
func procedureOf(path string) (string, bool) {
	segments := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	if len(segments) < 2 {
		return "", false
	}
	service, method := segments[len(segments)-2], segments[len(segments)-1]
	if !serviceName.MatchString(service) || !methodName.MatchString(method) {
		return "", false
	}
	return "/" + service + "/" + method, true
}

var errorWriter = connect.NewErrorWriter()

// refuse answers a request with a Connect error, in the form of the protocol
// that the request uses.
func refuse(w http.ResponseWriter, r *http.Request, err error) {
	_ = errorWriter.Write(w, r, err) // the client is gone if this fails
}

// RequireAdmin returns a handler that passes a request on to next only if
// [Service.Middleware] has found an admin for it, and answers every other request
// with a Connect error of code unauthenticated (HTTP 401). It is for the routes
// that are not Connect procedures, which the middleware lets through for their
// handlers to decide, such as a download that is for admins only:
//
//	mux.Handle("GET /nodes/{id}/bundle.tar", auth.RequireAdmin(bundleHandler))
//
// It does not depend on the middleware having run. Without it there is no admin
// in the context, and so no way in.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := AdminFrom(r.Context()); !ok {
			refuse(w, r, errNotSignedIn())
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware finds the admin that a request belongs to and makes a call to a
// Connect procedure that needs one fail if there is none.
//
// A request that carries the session cookie of a live session gets the admin in
// its context, see [AdminFrom]. A request to a procedure that is not public
// and has no such session is answered with a Connect error of code
// unauthenticated (HTTP 401), and goes no further. The public procedures are
// AuthService.GetSetupStatus, Setup and Login, and HealthService.Check; the
// bodies of requests to them are limited to 64 KiB.
//
// A request is a call to a procedure when its path ends in /<service>/<method>
// of a service with a protobuf package name, whatever comes before; so it is the
// same behind a prefix that is stripped later. Anything else, the SPA and its
// assets or a download, passes through with the admin in its context if the
// cookie is good. A route of that kind that is for admins only is put behind
// [RequireAdmin], or its handler asks [AdminFrom] itself.
//
// A session that is more than an hour into its week is touched: it is extended
// to a whole week from now, and the response carries the cookie again with a new
// lifetime. If the database cannot tell whether the session is good, the answer
// to a call is a Connect error of code internal, and a handler of another route
// finds no admin.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		procedure, isProcedure := procedureOf(r.URL.Path)
		public := isProcedure && publicProcedures[procedure]
		if public && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxPublicBody)
		}

		ci := &callInfo{ip: s.clientIP(r.RemoteAddr, r.Header), secure: s.isSecure(r), ua: userAgent(r.Header)}
		if !public {
			if token := cookieToken(r.Header); token != "" {
				sess, admin, touched, err := s.resolve(r.Context(), token)
				switch {
				case err != nil:
					// Logged as a fault, unless the client has gone: then it says
					// canceled, to nobody.
					failure := s.failure("could not look up a session", err)
					if isProcedure {
						refuse(w, r, failure)
						return
					}
				case sess != nil:
					ci.session, ci.admin = sess, admin
					if touched {
						http.SetCookie(w, s.cookie(token, sess.ExpiresAt, ci.secure))
					}
				}
			}
			if isProcedure && ci.admin == nil {
				refuse(w, r, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required")))
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callKey{}, ci)))
	})
}

// cookieToken returns the token in the session cookie, or "" if there is none
// or it cannot be one.
func cookieToken(h http.Header) string {
	r := http.Request{Header: h}
	c, err := r.Cookie(CookieName)
	if err != nil || !validToken(c.Value) {
		return ""
	}
	return c.Value
}

// resolve finds the live session of a token and its admin. It returns a nil
// session when the token names none, or one that has expired or whose admin is
// gone; those are deleted. It touches a session that has not been touched for
// touchEvery, and says so.
func (s *Service) resolve(ctx context.Context, token string) (sess *store.Session, admin *store.Admin, touched bool, err error) {
	hash := hashToken(token)
	sess, err = s.db.SessionByTokenHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}

	now := s.now()
	if !now.Before(sess.ExpiresAt) {
		s.dropSession(ctx, hash)
		return nil, nil, false, nil
	}
	admin, err = s.db.AdminByID(ctx, sess.AdminID)
	if errors.Is(err, store.ErrNotFound) {
		s.dropSession(ctx, hash)
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}

	// The session was extended to a whole week when it was last touched, so
	// less than a week minus touchEvery is left when that was touchEvery ago.
	if sess.ExpiresAt.Sub(now) < sessionTTL-touchEvery {
		expires := now.Add(sessionTTL).Truncate(time.Second).UTC()
		switch err := s.db.TouchSession(ctx, hash, expires); {
		case errors.Is(err, store.ErrNotFound):
			return nil, nil, false, nil // ended by a request that was faster
		case err != nil:
			// The session is good; it is only not extended this time.
			s.warn("could not extend a session", err)
		default:
			sess.ExpiresAt = expires
			touched = true
		}
	}
	return sess, admin, touched, nil
}

// dropSession deletes a session that is of no use any more.
func (s *Service) dropSession(ctx context.Context, hash string) {
	if err := s.db.DeleteSession(ctx, hash); err != nil {
		s.warn("could not delete a session", err)
	}
}

// startSession makes a session of the admin for the client of the call and
// returns the cookie for it. The caller puts the cookie into its response.
func (s *Service) startSession(ctx context.Context, adminID string, ci *callInfo) (*http.Cookie, error) {
	token, hash, err := newToken()
	if err != nil {
		return nil, err
	}
	now := s.now()
	sess := &store.Session{
		TokenHash: hash,
		AdminID:   adminID,
		IP:        ci.ip,
		UserAgent: ci.ua,
		CreatedAt: now,
		ExpiresAt: now.Add(sessionTTL),
	}
	if err := s.db.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	return s.cookie(token, sess.ExpiresAt, ci.secure), nil
}

// cookie is the session cookie for a token that is good until expires: HttpOnly,
// so that a script of the page cannot read it, SameSite=Strict, so that another
// site cannot make the browser send it, and Secure when the client is on TLS.
func (s *Service) cookie(token string, expires time.Time, secure bool) *http.Cookie {
	maxAge := int(expires.Sub(s.now()).Round(time.Second) / time.Second)
	return &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires.UTC(),
		MaxAge:   max(maxAge, 1),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// clearCookie is the cookie that makes the browser forget the session.
func clearCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Path:     "/",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// isSecure reports whether the client is on TLS: the connection is, or a proxy
// of the panel says that its connection from the client is (see
// forwardedHTTPS). The Secure attribute of the session cookie depends on it.
func (s *Service) isSecure(r *http.Request) bool {
	return r.TLS != nil || s.forwardedHTTPS(r.RemoteAddr, r.Header)
}

// forwardedHTTPS reports whether a proxy of the panel says, in
// X-Forwarded-Proto, that its client connected to it with https. The header is
// believed on the terms of X-Forwarded-For (see clientIP): only when the peer of
// the request, remoteAddr, is a proxy of the panel; from any other peer it says
// nothing. Of its values, which a proxy that appends to the header lists after
// the ones that it got, only the last counts, the one that the proxy wrote: the
// ones before it may be the client's own.
func (s *Service) forwardedHTTPS(remoteAddr string, h http.Header) bool {
	peer, ok := parseAddr(remoteAddr)
	if !ok || !s.trustsProxy(peer) {
		return false
	}
	lines := h.Values("X-Forwarded-Proto")
	if len(lines) == 0 {
		return false
	}
	last := lines[len(lines)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	return strings.EqualFold(strings.TrimSpace(last), "https")
}

// userAgent returns the User-Agent header as far as it is kept.
func userAgent(h http.Header) string {
	ua := strings.ToValidUTF8(h.Get("User-Agent"), "")
	if len(ua) > maxUserAgent {
		ua = ua[:maxUserAgent]
		for !utf8.ValidString(ua) {
			ua = ua[:len(ua)-1]
		}
	}
	return ua
}

// clientIP returns the address that a request is counted under: the one that
// the connection comes from, or, when the connection comes from a proxy of the
// panel, the one that the proxy reports in X-Forwarded-For.
//
// The proxies are the prefixes in s.trusted (see [WithTrustedProxies]) and
// nothing else: an address is not a proxy for being on the loopback, on a
// private network or link-local. A request from any other address says nothing
// with its X-Forwarded-For, which is then ignored, so that a client on the
// Internet cannot choose the address that it is counted under. For a proxy, the
// list is read from the right, the end that the proxies write, and skips the
// proxies; the first address that is not one is the client. Entries to the left
// of it are not trusted, since the client may have put them there. A list that
// holds nothing but proxies gives its first entry, and one that cannot be read,
// the address of the connection.
//
// "unknown" is returned if the address of the connection cannot be read.
func (s *Service) clientIP(remoteAddr string, h http.Header) string {
	peer, ok := parseAddr(remoteAddr)
	if !ok {
		return "unknown"
	}
	if !s.trustsProxy(peer) {
		return peer.String()
	}
	var entries []string
	for _, line := range h.Values("X-Forwarded-For") {
		for _, e := range strings.Split(line, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		addr, ok := parseAddr(entries[i])
		if !ok {
			return peer.String()
		}
		if !s.trustsProxy(addr) {
			return addr.String()
		}
	}
	if len(entries) > 0 {
		if addr, ok := parseAddr(entries[0]); ok {
			return addr.String()
		}
	}
	return peer.String()
}

// trustsProxy reports whether addr is one of the proxies of the panel: a request
// from it may carry an X-Forwarded-For that is believed, and an address in such a
// header that is one is skipped on the way to the client.
func (s *Service) trustsProxy(addr netip.Addr) bool {
	return slices.ContainsFunc(s.trusted, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// parseAddr reads an address, with or without a port, as it is written in
// RemoteAddr or in X-Forwarded-For. An IPv4 address that is written as IPv6 is
// an IPv4 address, and a zone is dropped.
func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return normalize(ap.Addr()), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return normalize(a), true
	}
	return netip.Addr{}, false
}

func normalize(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// ipKey is the key under which the limiter counts an address. An IPv6 address
// counts as its /64: the customer of an ISP has at least that many, and a limit
// per address would be one in 2^64 of the limit that is meant.
func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}
