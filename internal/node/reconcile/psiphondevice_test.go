package reconcile

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	psiphonDevID    = "ps-device-1"
	psiphonDevToken = "ps-token-0123456789" // gitleaks:allow (a fake token)
)

// writeIdentity writes the identity file that warp-plus kept in a cache.
func writeIdentity(t *testing.T, cacheDir, id, token string) {
	t.Helper()
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := `{"private_key":"k","id":"` + id + `","token":"` + token + `","account":{}}`
	if err := os.WriteFile(filepath.Join(cacheDir, psiphonIdentityFile), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertNoPsiphonSecrets(t *testing.T, h *harness, logs string) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	texts := []string{logs}
	for _, ev := range h.events {
		texts = append(texts, protoText(ev))
	}
	for _, text := range texts {
		if strings.Contains(text, psiphonDevToken) || strings.Contains(text, psiphonDevID) {
			t.Errorf("a log or an event reveals the device: %s", text)
		}
	}
}

// Deleting a PSIPHON egress deletes the WARP device that warp-plus registered
// before its directory goes; a failed deletion does not hold the removal back,
// is kept and tried again on a later pass, and nothing secret is logged.
func TestPsiphonDeviceDeletedWithTheEgress(t *testing.T) {
	h := newHarness(t)
	var logs bytes.Buffer
	h.r.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.apply(h.providerState(1, psiphonEgress("DE")))
	h.pass()
	writeIdentity(t, filepath.Join(h.paths.EgressDir("ps"), "cache-g1"), psiphonDevID, psiphonDevToken)

	h.warp.setDeleteHook(func(_ context.Context) error { return errors.New("HTTP 503") })
	h.apply(h.baseState(2))
	h.pass()
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if _, err := os.Stat(h.paths.EgressDir("ps")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed deletion held the removal back: %v", err)
	}
	pending, _ := os.ReadDir(filepath.Join(h.paths.StateDir(), "psiphon-devices"))
	if len(pending) != 1 {
		t.Fatalf("pending devices = %d, want 1", len(pending))
	}
	if info, err := pending[0].Info(); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Errorf("pending record mode = %v, %v; want 0600", info, err)
	}

	// Not before the wait is over, then the next pass deletes it.
	h.warp.setDeleteHook(nil)
	h.pass()
	if len(h.warp.deleted) != 0 {
		t.Errorf("tried again too early: %v", h.warp.deleted)
	}
	h.clock.Advance(psiphonRetryEvery)
	h.pass()
	if !slices.Equal(h.warp.deleted, []string{psiphonDevID}) {
		t.Errorf("deleted = %v, want the device", h.warp.deleted)
	}
	if pending, _ := os.ReadDir(filepath.Join(h.paths.StateDir(), "psiphon-devices")); len(pending) != 0 {
		t.Errorf("the record of the deleted device stays: %d", len(pending))
	}
	assertNoPsiphonSecrets(t, h, logs.String())
}

// An egress that warp-plus ran moves to Psiphon's own client (a new
// generation, blue-green): the new generation does not take a copy of the
// cache of warp-plus, so it never holds the WARP device that warp-plus
// registered; once the old generation is removed, its cache goes and the
// device is deleted, once, and leaves no record.
func TestPsiphonDeviceOfWarpPlusDeletedOnTheSwitch(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, psiphonEgress("DE")))
	h.pass()
	dir := h.paths.EgressDir("ps")
	// g1 stands for a generation of warp-plus: its cache holds the identity.
	writeIdentity(t, filepath.Join(dir, "cache-g1"), psiphonDevID, psiphonDevToken)

	h.apply(h.providerState(2, psiphonEgress("NL")))
	h.pass()
	if _, err := os.Stat(filepath.Join(dir, "cache-g2", psiphonIdentityFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the new generation took the identity of warp-plus: %v", err)
	}
	if len(h.warp.deleted) != 0 {
		t.Fatalf("deleted %v while g1 still runs", h.warp.deleted)
	}
	h.clock.Advance(2 * time.Minute)
	h.pass() // g1 is removed, and its cache with it
	if !slices.Equal(h.warp.deleted, []string{psiphonDevID}) {
		t.Fatalf("deleted = %v, want the device of warp-plus", h.warp.deleted)
	}
	if _, err := os.Stat(filepath.Join(dir, "cache-g1")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cache of warp-plus stays: %v", err)
	}

	h.apply(h.baseState(3))
	h.pass()
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if !slices.Equal(h.warp.deleted, []string{psiphonDevID}) {
		t.Errorf("deleted = %v, want the device once", h.warp.deleted)
	}
	if _, err := os.Stat(filepath.Join(h.paths.StateDir(), "psiphon-devices")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a record of a deleted device: %v", err)
	}
}

// A device that cannot be deleted for 7 days is given up: the record goes, one
// event says so without naming the device, and nothing is tried any more.
func TestPsiphonDeviceGivenUpAfterSevenDays(t *testing.T) {
	h := newHarness(t)
	var logs bytes.Buffer
	h.r.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.apply(h.providerState(1, psiphonEgress("DE")))
	h.pass()
	writeIdentity(t, filepath.Join(h.paths.EgressDir("ps"), "cache-g1"), psiphonDevID, psiphonDevToken)
	calls := 0
	h.warp.setDeleteHook(func(_ context.Context) error { calls++; return errors.New("HTTP 401") })
	h.apply(h.baseState(2))
	h.pass()
	h.clock.Advance(2 * time.Minute)
	h.pass()
	dir := filepath.Join(h.paths.StateDir(), "psiphon-devices")
	if pending, _ := os.ReadDir(dir); len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}

	h.clock.Advance(6 * 24 * time.Hour)
	h.pass()
	if pending, _ := os.ReadDir(dir); len(pending) != 1 {
		t.Fatalf("given up too early: pending = %d", len(pending))
	}
	h.clock.Advance(25 * time.Hour)
	before := calls
	h.pass()
	if pending, _ := os.ReadDir(dir); len(pending) != 0 {
		t.Errorf("the record stays after 7 days: %d", len(pending))
	}
	if calls != before {
		t.Error("a deletion was tried at the give-up")
	}
	h.pass()
	n := 0
	h.mu.Lock()
	for _, ev := range h.events {
		if strings.Contains(protoText(ev), evPsiphonDeviceGiveUp) {
			n++
		}
	}
	h.mu.Unlock()
	if n != 1 {
		t.Errorf("give-up events = %d, want 1", n)
	}
	assertNoPsiphonSecrets(t, h, logs.String())
}
