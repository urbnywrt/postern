package auth

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The audit log of the AuthService: the setup, sign-ins and failed sign-ins,
// and the changes of a password and of TOTP. An entry has the user name and the
// address that the request came from, and never a password, a code or a token.
//
// A failed sign-in costs nobody anything, so they are written down at most once
// a minute for an address, and at most maxFailedAuditsPerMinute times a minute
// in all. The next entry that is written says how many were left out before it.

// maxFailedAuditsPerMinute bounds the entries of failed sign-ins in a minute,
// from all the addresses together.
const maxFailedAuditsPerMinute = 20

// audit writes an entry for what admin did, after the change has been made, and
// also when the client has gone. A failure to write is logged only.
func (s *Service) audit(ctx context.Context, action string, admin *store.Admin, ci *callInfo, details map[string]string) {
	entry := &store.AuditEntry{TS: s.now(), Action: action, Details: map[string]string{"source": ci.ip}}
	if admin != nil {
		entry.AdminID = admin.ID
		entry.Target = "admin:" + admin.ID
		entry.Details["username"] = admin.Username
	}
	for k, v := range details {
		entry.Details[k] = v
	}
	if err := s.db.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		s.log.Error("could not write the audit log", "action", action, "err", err)
	}
}

// auditFailure writes the entry of a failed attempt, if auditLimiter lets it.
// admin is nil for a user name that nobody has, which is not written down: it
// may be a password that went into the wrong field.
func (s *Service) auditFailure(ctx context.Context, action string, admin *store.Admin, ci *callInfo, reason string) {
	ok, suppressed := s.failAudits.allow(ci.ip, s.now())
	if !ok {
		return
	}
	details := map[string]string{"reason": reason}
	if suppressed > 0 {
		details["suppressed"] = strconv.Itoa(suppressed)
	}
	s.audit(ctx, action, admin, ci, details)
}

// auditLimiter lets one failed attempt of an address a minute be written down,
// and at most maxFailedAuditsPerMinute in all, and counts the others.
type auditLimiter struct {
	mu         sync.Mutex
	minute     time.Time
	written    map[string]bool // the addresses written down in this minute
	suppressed int             // left out since the last entry
}

// allow reports whether a failure from source at now is written down, and how
// many were left out before it, which the caller writes with it.
func (l *auditLimiter) allow(source string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if m := now.Truncate(time.Minute); !m.Equal(l.minute) || l.written == nil {
		l.minute = m
		l.written = make(map[string]bool)
	}
	if l.written[source] || len(l.written) >= maxFailedAuditsPerMinute {
		l.suppressed++
		return false, 0
	}
	l.written[source] = true
	n := l.suppressed
	l.suppressed = 0
	return true, n
}
