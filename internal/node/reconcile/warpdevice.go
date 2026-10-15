package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"time"

	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/providers/warp"
)

// The WARP device of an egress that is no longer desired is deleted at
// Cloudflare before the account of the egress goes (forgetEgress): the account
// holds the token that the deletion takes, and without it nothing can delete the
// device any more. So the record and the account stay until the device is
// deleted, or Cloudflare says that it is gone already (warp.ErrDeviceGone).
//
// A deletion that fails is tried again a minute later, then twice as late after
// each further failure, six hours apart at the most. The state of it is in the
// record of the egress (state.WARPDeletion), which is saved: a new agent
// process keeps to it. After a week of failures the deletion is given up with a
// warning and an event that name the egress: the account then stays, for the
// owner of the node to delete the device by hand. So it does at once when the
// account cannot be read. A deletion that the end of the agent cuts short is no
// failure: the agent tries again when it starts.
//
// The log says each change once: the first failure, the deletion, a device
// gone already, the end of the agent, giving up. It never says a credential:
// the errors of warp.Delete hold none, and neither does the path of the account.

const (
	// warpRetryFirst is the wait after the first failure of a deletion, and
	// warpRetryMax the longest wait.
	warpRetryFirst = time.Minute
	warpRetryMax   = 6 * time.Hour
	// warpGiveUpAfter is how long a deletion is tried, from its first failure.
	warpGiveUpAfter = 7 * 24 * time.Hour

	// evEgressWARPDeviceKept says that the deletion of the WARP device of a
	// deleted egress is given up, and its account kept.
	evEgressWARPDeviceKept = "egress_warp_device_kept"
)

// deleteWARPDevice deletes the WARP device of an egress that is no longer
// desired, when it has one (an account, or the registration that a
// registration which stopped half-way kept), and reports whether what is left
// of the egress may go: the device is deleted, was gone already, or there is
// none (no account file). It reports false, and the record and the account
// stay, while the deletion fails or waits for its next attempt, when the end of
// the agent cuts it short, and once it is given up. An account that cannot be
// read deletes nothing: the deletion is given up at once.
func (p *pass) deleteWARPDevice(id string) bool {
	acctPath := filepath.Join(p.r.Store.Paths.EgressStateDir(id), warpAccountFile)
	rec := p.rt.Egresses[id]
	if d := rec.WARPDeletion; d != nil && d.GaveUp {
		return false
	}
	now := p.r.now()
	acct, err := warp.LoadRegistration(acctPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true
	case err != nil:
		p.keepWARPAccount(id, rec, state.WARPDeletion{FirstFailed: now}, acctPath,
			fmt.Sprintf("its WARP account cannot be read (%v), so its device cannot be deleted", err))
		return false
	}
	if d := rec.WARPDeletion; d != nil && now.Before(d.NextAttempt) {
		return false
	}

	ctx, cancel := context.WithTimeout(p.ctx, warpTimeout)
	err = p.r.deleteWARP(ctx, acct)
	cancel()
	log := p.r.log().With("egress", id)
	switch {
	case err == nil && rec.WARPDeletion != nil:
		log.Info("deleted the WARP device of a deleted egress", "attempts", rec.WARPDeletion.Failures+1)
		return true
	case err == nil:
		log.Info("deleted the WARP device of a deleted egress")
		return true
	case errors.Is(err, warp.ErrDeviceGone):
		log.Info("the WARP device of a deleted egress was gone at Cloudflare already")
		return true
	case p.ctx.Err() != nil:
		log.Info("the agent stops: the WARP device of a deleted egress is deleted when it starts again")
		return false
	}

	d := state.WARPDeletion{FirstFailed: now}
	if rec.WARPDeletion != nil {
		d = *rec.WARPDeletion
	}
	d.Failures++
	if failing := now.Sub(d.FirstFailed); failing >= warpGiveUpAfter {
		p.keepWARPAccount(id, rec, d, acctPath, fmt.Sprintf("its WARP device could not be deleted at Cloudflare for %d days (%d attempts; the last: %v)",
			int(failing/(24*time.Hour)), d.Failures, err))
		return false
	}
	wait := warpRetryAfter(d.Failures)
	d.NextAttempt = now.Add(wait)
	if d.Failures == 1 {
		log.Warn("could not delete the WARP device of a deleted egress at Cloudflare; its account stays, and the deletion is tried again later",
			"retry_in", wait, "err", err)
	}
	rec.WARPDeletion = &d
	p.rt.Egresses[id] = rec
	return false
}

// keepWARPAccount gives up the deletion of the WARP device of an egress, for
// why: the record says so, the account stays, for the owner of the node to
// delete the device by hand, and a warning event that names the egress says
// where it is.
func (p *pass) keepWARPAccount(id string, rec state.EgressRecord, d state.WARPDeletion, acctPath, why string) {
	d.GaveUp, d.NextAttempt = true, time.Time{}
	rec.WARPDeletion = &d
	p.rt.Egresses[id] = rec
	p.r.event(evEgressWARPDeviceKept, sevWarning, "",
		fmt.Sprintf("egress %s: %s. The deletion is not tried any more; the account stays in %s, "+
			"for the owner of the node to delete the device by hand", id, why, acctPath),
		map[string]string{"egress": id, "attempts": strconv.Itoa(d.Failures)})
}

// warpRetryAfter is the wait after the failures-th failure in a row of the
// deletion of a WARP device: warpRetryFirst, twice as long after each further
// failure, warpRetryMax at the most.
func warpRetryAfter(failures int) time.Duration {
	wait := warpRetryFirst
	for i := 1; i < failures && wait < warpRetryMax; i++ {
		wait *= 2
	}
	return min(wait, warpRetryMax)
}
