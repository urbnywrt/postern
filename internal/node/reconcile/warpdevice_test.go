package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/providers/warp"
)

// The deletion of the WARP device of an egress that is no longer desired
// (warpdevice.go): the account stays until Cloudflare has deleted the device,
// or says that it is gone; a deletion that fails is tried again after a
// backoff, and given up after a week.

// removedWARPEgress runs a WARP egress "cf", then takes it out of the desired
// state and lets its generation drain: the next pass deletes its device. It
// returns the path of its account.
func removedWARPEgress(t *testing.T, h *harness) string {
	t.Helper()
	h.apply(h.providerState(1, &nodev1.Egress{Id: "cf", Kind: nodev1.EgressKind_EGRESS_KIND_WARP, ParamsJson: "{}"}))
	h.pass()
	h.apply(h.baseState(2))
	h.pass()
	h.clock.Advance(2 * time.Minute)
	return filepath.Join(h.paths.EgressStateDir("cf"), "warp-account.json")
}

// captureLogs sends the log of the harness's reconciler to a buffer.
func captureLogs(h *harness) *lockedBuffer {
	logs := &lockedBuffer{}
	h.r.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logs
}

// failingDelete makes every deletion of a WARP device fail as Cloudflare
// failing would, and counts them.
func failingDelete(h *harness) *int {
	n := new(int)
	h.warp.setDeleteHook(func(context.Context) error {
		*n++
		return errors.New("warp: deleting the device: HTTP 503 Service Unavailable")
	})
	return n
}

// warpDeletion is the state of the deletion of the device of egress "cf" in
// the runtime record on disk; nil when there is none.
func warpDeletion(t *testing.T, h *harness) *state.WARPDeletion {
	t.Helper()
	rec, ok := h.runtime().Egresses["cf"]
	if !ok {
		t.Fatal("the record of the egress is gone")
	}
	return rec.WARPDeletion
}

func assertKept(t *testing.T, h *harness, acct string) {
	t.Helper()
	if _, err := os.Stat(acct); err != nil {
		t.Errorf("the account: %v, want it kept", err)
	}
	if _, ok := h.runtime().Egresses["cf"]; !ok {
		t.Error("the record of the egress is gone, want it kept")
	}
}

func assertForgotten(t *testing.T, h *harness, acct string) {
	t.Helper()
	if _, err := os.Stat(acct); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the account is still there: %v", err)
	}
	if _, ok := h.runtime().Egresses["cf"]; ok {
		t.Error("the record of the egress is still there")
	}
}

// assertNoWARPSecrets fails the test when the log or an event holds a
// credential of the WARP account.
func assertNoWARPSecrets(t *testing.T, h *harness, log string) {
	t.Helper()
	a := testWARPAccount()
	for _, s := range []string{a.PrivateKey, a.Token} {
		if strings.Contains(log, s) {
			t.Error("the log holds a credential of the WARP account")
		}
	}
	assertNoEgressSecretsInEvents(t, h)
}

// A deletion that fails keeps the account and the record, and is tried again
// after a minute, then after two, also by a new agent process; once it goes
// through, the account and the record go. The log says so once per change.
func TestWARPDeletionThatFailsIsTriedAgainLater(t *testing.T) {
	h := newHarness(t)
	logs := captureLogs(h)
	acct := removedWARPEgress(t, h)
	attempts := failingDelete(h)

	h.pass()
	if *attempts != 1 {
		t.Fatalf("%d attempts, want 1", *attempts)
	}
	assertKept(t, h, acct)
	d := warpDeletion(t, h)
	if d == nil || d.Failures != 1 || !d.FirstFailed.Equal(h.clock.Now()) ||
		!d.NextAttempt.Equal(h.clock.Now().Add(time.Minute)) || d.GaveUp {
		t.Fatalf("deletion = %+v, want 1 failure now and the next attempt a minute later", d)
	}

	// Nothing is tried before the minute is over, by this agent or a new one.
	h.clock.Advance(59 * time.Second)
	h.pass()
	h.r = h.newReconciler()
	h.r.Log = slog.New(slog.NewTextHandler(logs, nil))
	h.pass()
	if *attempts != 1 {
		t.Fatalf("%d attempts within the backoff, want 1", *attempts)
	}

	// Then it is tried again; it fails again, and the wait doubles.
	h.clock.Advance(time.Second)
	h.pass()
	if *attempts != 2 {
		t.Fatalf("%d attempts after the backoff, want 2", *attempts)
	}
	if d := warpDeletion(t, h); d == nil || d.Failures != 2 || !d.NextAttempt.Equal(h.clock.Now().Add(2*time.Minute)) {
		t.Fatalf("deletion = %+v, want 2 failures and the next attempt two minutes later", d)
	}
	assertKept(t, h, acct)

	// It goes through: the device, the account and the record go.
	h.warp.setDeleteHook(nil)
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if !slices.Equal(h.warp.deleted, []string{testWARPAccount().ID}) {
		t.Errorf("deleted devices = %v", h.warp.deleted)
	}
	assertForgotten(t, h, acct)

	log := logs.String()
	if n := strings.Count(log, "could not delete the WARP device"); n != 1 {
		t.Errorf("the failure is logged %d times, want once:\n%s", n, log)
	}
	if n := strings.Count(log, "deleted the WARP device"); n != 1 {
		t.Errorf("the deletion is logged %d times, want once:\n%s", n, log)
	}
	assertNoWARPSecrets(t, h, log)
}

// Cloudflare says that the device is gone already: the account and the record
// go, as after a deletion.
func TestWARPDeletionOfADeviceGoneAlready(t *testing.T) {
	h := newHarness(t)
	logs := captureLogs(h)
	acct := removedWARPEgress(t, h)
	h.warp.setDeleteHook(func(context.Context) error {
		return fmt.Errorf("%w (HTTP 404 Not Found)", warp.ErrDeviceGone)
	})
	h.pass()
	assertForgotten(t, h, acct)
	log := logs.String()
	if !strings.Contains(log, "gone at Cloudflare already") {
		t.Errorf("the log does not say that the device was gone:\n%s", log)
	}
	if strings.Contains(log, "could not delete") {
		t.Errorf("a device that is gone is taken for a failure:\n%s", log)
	}
	assertNoWARPSecrets(t, h, log)
}

// The end of the agent cuts a retry short: the account and the record stay,
// the retry counts as no failure, and the new agent tries again at once.
func TestWARPDeletionRetryCutShortKeepsTheAccount(t *testing.T) {
	h := newHarness(t)
	acct := removedWARPEgress(t, h)
	failingDelete(h)
	h.pass()
	h.clock.Advance(time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.warp.setDeleteHook(func(dctx context.Context) error {
		cancel() // the agent stops
		select {
		case <-dctx.Done():
			return dctx.Err()
		case <-time.After(10 * time.Second):
			t.Error("the retry was not cut short with the agent")
			return errors.New("not cut short")
		}
	})
	if err := h.r.reconcileOnce(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("pass = %v, want it cut short", err)
	}
	assertKept(t, h, acct)
	if d := warpDeletion(t, h); d == nil || d.Failures != 1 {
		t.Fatalf("deletion = %+v, want the one failure of before", d)
	}

	h.warp.setDeleteHook(nil)
	h.r = h.newReconciler()
	h.pass()
	if !slices.Equal(h.warp.deleted, []string{testWARPAccount().ID}) {
		t.Errorf("deleted devices = %v", h.warp.deleted)
	}
	assertForgotten(t, h, acct)
}

// A week of failures: the waits double from a minute up to six hours, then
// the deletion is given up with a warning and an event that name the egress,
// and is not tried any more. The account stays, for the owner of the node to
// delete the device by hand.
func TestWARPDeletionIsGivenUpAfterAWeek(t *testing.T) {
	h := newHarness(t)
	logs := captureLogs(h)
	acct := removedWARPEgress(t, h)
	attempts := failingDelete(h)
	start := h.clock.Now()

	h.pass()
	var waits []time.Duration
	for range 100 {
		d := warpDeletion(t, h)
		if d == nil {
			t.Fatal("no state of the deletion")
		}
		if d.GaveUp {
			break
		}
		wait := d.NextAttempt.Sub(h.clock.Now())
		waits = append(waits, wait)
		h.clock.Advance(wait)
		h.pass()
	}
	d := warpDeletion(t, h)
	if d == nil || !d.GaveUp {
		t.Fatalf("deletion = %+v after %d attempts, want it given up", d, *attempts)
	}
	if took := h.clock.Now().Sub(start); took < 7*24*time.Hour || took > 7*24*time.Hour+6*time.Hour {
		t.Errorf("given up %v after the first failure, want a week (and at most one wait more)", took)
	}
	want := time.Minute
	for i, w := range waits {
		if w != want {
			t.Fatalf("wait %d = %v, want %v (all: %v)", i+1, w, want, waits)
		}
		want = min(2*want, 6*time.Hour)
	}
	if d.Failures != *attempts {
		t.Errorf("%d failures noted, %d attempts made", d.Failures, *attempts)
	}

	evs := h.eventsOf(evEgressWARPDeviceKept)
	if len(evs) != 1 || evs[0].GetSeverity() != sevWarning || !strings.Contains(evs[0].GetMessage(), "egress cf") ||
		evs[0].GetDetails()["egress"] != "cf" {
		t.Fatalf("events %s = %v, want one warning that names the egress", evEgressWARPDeviceKept, evs)
	}

	// Not tried any more, by this agent or a new one; the account stays.
	before := *attempts
	h.clock.Advance(30 * 24 * time.Hour)
	h.pass()
	h.r = h.newReconciler()
	h.r.Log = slog.New(slog.NewTextHandler(logs, nil))
	h.pass()
	if *attempts != before {
		t.Errorf("%d attempts after the deletion was given up", *attempts-before)
	}
	assertKept(t, h, acct)

	log := logs.String()
	if n := strings.Count(log, "could not delete the WARP device"); n != 1 {
		t.Errorf("the failure is logged %d times, want once:\n%s", n, log)
	}
	if n := strings.Count(log, "event="+evEgressWARPDeviceKept); n != 1 {
		t.Errorf("giving up is logged %d times, want once:\n%s", n, log)
	}
	assertNoWARPSecrets(t, h, log)
}

// An account that cannot be read deletes no device, and is not removed either:
// the deletion is given up at once, with the warning event, and the file stays
// for the owner of the node.
func TestWARPDeletionWithAnUnreadableAccountKeepsIt(t *testing.T) {
	h := newHarness(t)
	logs := captureLogs(h)
	acct := removedWARPEgress(t, h)
	if err := os.WriteFile(acct, []byte("{not an account"), 0o600); err != nil {
		t.Fatal(err)
	}
	attempts := failingDelete(h)
	h.pass()
	h.clock.Advance(24 * time.Hour)
	h.pass()
	if *attempts != 0 {
		t.Errorf("%d deletions with an account that cannot be read", *attempts)
	}
	assertKept(t, h, acct)
	if d := warpDeletion(t, h); d == nil || !d.GaveUp {
		t.Errorf("deletion = %+v, want it given up", d)
	}
	if evs := h.eventsOf(evEgressWARPDeviceKept); len(evs) != 1 || !strings.Contains(evs[0].GetMessage(), "egress cf") {
		t.Errorf("events %s = %v, want one that names the egress", evEgressWARPDeviceKept, evs)
	}
	assertNoWARPSecrets(t, h, logs.String())
}

// An egress whose deletion failed is used again: its device is the egress's
// again, and is not deleted; when it goes once more, its deletion starts
// afresh, at once.
func TestWARPDeletionStopsWhenTheEgressIsUsedAgain(t *testing.T) {
	h := newHarness(t)
	acct := removedWARPEgress(t, h)
	attempts := failingDelete(h)
	h.pass()
	for range 3 {
		h.clock.Advance(warpDeletion(t, h).NextAttempt.Sub(h.clock.Now()))
		h.pass()
	}
	if d := warpDeletion(t, h); d == nil || d.Failures != 4 || !d.NextAttempt.Equal(h.clock.Now().Add(8*time.Minute)) {
		t.Fatalf("deletion = %+v, want 4 failures and the next attempt 8 minutes away", d)
	}

	h.apply(h.providerState(3, &nodev1.Egress{Id: "cf", Kind: nodev1.EgressKind_EGRESS_KIND_WARP, ParamsJson: "{}"}))
	h.pass()
	if d := warpDeletion(t, h); d != nil {
		t.Errorf("deletion = %+v while the egress is used again, want none", d)
	}
	if rec := h.runtime().Egresses["cf"]; rec.Generation == 0 {
		t.Errorf("record = %+v, want the egress served again", rec)
	}
	if *attempts != 4 {
		t.Errorf("%d attempts, want no more while the egress is used", *attempts)
	}
	if _, err := os.Stat(acct); err != nil {
		t.Fatalf("the account: %v", err)
	}

	// Taken out again: drained, and then deleted at once, although the old
	// backoff has six minutes left.
	h.apply(h.baseState(4))
	h.pass()
	h.clock.Advance(2 * time.Minute)
	h.warp.setDeleteHook(nil)
	h.pass()
	if !slices.Equal(h.warp.deleted, []string{testWARPAccount().ID}) {
		t.Errorf("deleted devices = %v, want the device deleted at the first attempt", h.warp.deleted)
	}
	assertForgotten(t, h, acct)
}
