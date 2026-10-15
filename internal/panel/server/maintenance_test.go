package server

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// fakeStore records the calls of the maintenance and fails them when it is told
// to. Its statistics settings are settings, the defaults when that is nil, or
// the error settingsErr.
type fakeStore struct {
	mu          sync.Mutex
	calls       []string
	nows        []time.Time
	retentions  []store.Retention // of each call of rollup and prune
	fail        map[string]error
	settings    *store.StatsSettings
	settingsErr error
}

func (f *fakeStore) call(name string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	f.nows = append(f.nows, now)
	return f.fail[name]
}

func (f *fakeStore) StatsSettings(context.Context) (store.StatsSettings, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.settingsErr != nil:
		return store.StatsSettings{}, false, f.settingsErr
	case f.settings == nil:
		return store.DefaultStatsSettings(), false, nil
	}
	return *f.settings, true, nil
}

func (f *fakeStore) setSettings(s *store.StatsSettings, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settings, f.settingsErr = s, err
}

func (f *fakeStore) stats(name string, now time.Time, r store.Retention) error {
	f.mu.Lock()
	f.retentions = append(f.retentions, r)
	f.mu.Unlock()
	return f.call(name, now)
}

func (f *fakeStore) RollupStats(_ context.Context, now time.Time, r store.Retention) error {
	return f.stats("rollup", now, r)
}

func (f *fakeStore) PruneStats(_ context.Context, now time.Time, r store.Retention) error {
	return f.stats("prune", now, r)
}

func (f *fakeStore) PruneEvents(_ context.Context, now time.Time) (int64, error) {
	return 0, f.call("events", now)
}

func (f *fakeStore) DeleteExpiredSessions(_ context.Context, now time.Time) (int64, error) {
	return 0, f.call("sessions", now)
}

func (f *fakeStore) snapshot() ([]string, []time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...), append([]time.Time(nil), f.nows...)
}

func (f *fakeStore) retentionsSoFar() []store.Retention {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.Retention(nil), f.retentions...)
}

// runLoop runs the maintenance until the test stops it.
func runLoop(t *testing.T, m maintenanceStore, every time.Duration, now func() time.Time, log *slog.Logger) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMaintenance(ctx, m, every, now, log)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(waitFor):
				t.Error("the maintenance did not stop when its context was done")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func TestMaintenanceRunsEverythingAtOnceAndEveryInterval(t *testing.T) {
	f := &fakeStore{}
	clock := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(time.Minute) // every reading of the clock is another time
		return clock
	}
	stop := runLoop(t, f, 10*time.Millisecond, now, nil)
	eventually(t, "three rounds", func() bool { calls, _ := f.snapshot(); return len(calls) >= 12 })
	stop()

	calls, nows := f.snapshot()
	if len(calls)%4 != 0 {
		t.Fatalf("a round was cut short: %v", calls)
	}
	for i := 0; i+3 < len(calls); i += 4 {
		round := strings.Join(calls[i:i+4], ",")
		if round != "rollup,prune,events,sessions" {
			t.Errorf("round %d: %s, want rollup,prune,events,sessions", i/4, round)
		}
		// One reading of the clock for the round, so that the tasks agree on the time.
		if !nows[i].Equal(nows[i+1]) || !nows[i].Equal(nows[i+2]) || !nows[i].Equal(nows[i+3]) {
			t.Errorf("round %d did not use one time: %v", i/4, nows[i:i+4])
		}
		if i > 0 && !nows[i].After(nows[i-1]) {
			t.Errorf("round %d used the time of the round before", i/4)
		}
	}
}

// The first round is not an hour away: a panel that is restarted more often
// than that would never run one.
func TestMaintenanceRunsFirstAtOnce(t *testing.T) {
	f := &fakeStore{}
	runLoop(t, f, time.Hour, time.Now, nil)
	eventually(t, "the first round", func() bool { calls, _ := f.snapshot(); return len(calls) == 4 })
}

func TestMaintenanceStopsWithItsContext(t *testing.T) {
	f := &fakeStore{}
	stop := runLoop(t, f, time.Hour, time.Now, nil)
	eventually(t, "the first round", func() bool { calls, _ := f.snapshot(); return len(calls) == 4 })
	stop()
	calls, _ := f.snapshot()
	time.Sleep(20 * time.Millisecond)
	if again, _ := f.snapshot(); len(again) != len(calls) {
		t.Error("the maintenance went on after its context was done")
	}
}

// Every failure is an error in the log, and one does not keep the others from
// running, nor the loop from going on.
func TestMaintenanceLogsEveryFailureAtErrorLevelAndGoesOn(t *testing.T) {
	logs := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f := &fakeStore{fail: map[string]error{
		"rollup":   errors.New("rollup went wrong"),
		"prune":    errors.New("prune went wrong"),
		"events":   errors.New("events went wrong"),
		"sessions": errors.New("sessions went wrong"),
	}}
	stop := runLoop(t, f, 10*time.Millisecond, time.Now, log)
	eventually(t, "two rounds", func() bool { calls, _ := f.snapshot(); return len(calls) >= 8 })
	stop()

	calls, _ := f.snapshot()
	for _, name := range []string{"rollup", "prune", "events", "sessions"} {
		n := 0
		for _, c := range calls {
			if c == name {
				n++
			}
		}
		if n < 2 {
			t.Errorf("%s ran %d times; a failure of another task, or of an earlier round, stopped it", name, n)
		}
	}
	text := logs.String()
	for _, what := range []string{"rollup went wrong", "prune went wrong", "events went wrong", "sessions went wrong"} {
		var seen int
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, what) {
				seen++
				if !strings.Contains(line, "level=ERROR") {
					t.Errorf("%q is logged below the error level: %s", what, line)
				}
			}
		}
		if seen < 2 {
			t.Errorf("%q was logged %d times, want once per round", what, seen)
		}
	}
}

// Nothing that fails because the panel is stopping is an error of the panel.
func TestMaintenanceDoesNotLogWhatIsCutOffByTheStop(t *testing.T) {
	logs := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancelling := &cancelOnCall{cancel: cancel}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMaintenance(ctx, cancelling, time.Hour, time.Now, log)
	}()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("the maintenance did not stop")
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("a stop was logged as an error:\n%s", logs.String())
	}
}

// cancelOnCall stops the context at its first call and fails with its error, as a
// database call does that is cut off by the stop.
type cancelOnCall struct {
	cancel context.CancelFunc
}

func (c *cancelOnCall) StatsSettings(context.Context) (store.StatsSettings, bool, error) {
	return store.DefaultStatsSettings(), false, nil
}
func (c *cancelOnCall) RollupStats(ctx context.Context, _ time.Time, _ store.Retention) error {
	c.cancel()
	return ctx.Err()
}
func (c *cancelOnCall) PruneStats(ctx context.Context, _ time.Time, _ store.Retention) error {
	return ctx.Err()
}
func (c *cancelOnCall) PruneEvents(ctx context.Context, _ time.Time) (int64, error) {
	return 0, ctx.Err()
}
func (c *cancelOnCall) DeleteExpiredSessions(ctx context.Context, _ time.Time) (int64, error) {
	return 0, ctx.Err()
}

// With the real database: an expired session goes, a good one stays.
func TestMaintenanceDeletesExpiredSessions(t *testing.T) {
	p := newPanel(t)
	ctx := context.Background()
	admin := &store.Admin{Username: "alice", PasswordHash: "hash"}
	if err := p.srv.db.CreateAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for hash, expires := range map[string]time.Time{
		"expired-long-ago": now.Add(-48 * time.Hour),
		"expired-a-second": now.Add(-time.Second),
		"good":             now.Add(time.Hour),
	} {
		if err := p.srv.db.CreateSession(ctx, &store.Session{TokenHash: hash, AdminID: admin.ID, CreatedAt: now.Add(-72 * time.Hour), ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}
	runLoop(t, p.srv.db, time.Hour, time.Now, nil)
	eventually(t, "the expired sessions to go", func() bool {
		_, err1 := p.srv.db.SessionByTokenHash(ctx, "expired-long-ago")
		_, err2 := p.srv.db.SessionByTokenHash(ctx, "expired-a-second")
		return errors.Is(err1, store.ErrNotFound) && errors.Is(err2, store.ErrNotFound)
	})
	if _, err := p.srv.db.SessionByTokenHash(ctx, "good"); err != nil {
		t.Errorf("a session that has not expired was deleted: %v", err)
	}
}

// And the server runs it: it is not only a function that nobody calls.
func TestServeRunsTheMaintenance(t *testing.T) {
	p := newPanel(t)
	p.srv.maintenanceEvery = 10 * time.Millisecond
	ctx := context.Background()
	admin := &store.Admin{Username: "alice", PasswordHash: "hash"}
	if err := p.srv.db.CreateAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := p.srv.db.CreateSession(ctx, &store.Session{TokenHash: "old", AdminID: admin.ID, CreatedAt: time.Now().Add(-72 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := serve(t, p.srv)
	r.ready()
	eventually(t, "the expired session to go", func() bool {
		_, err := p.srv.db.SessionByTokenHash(ctx, "old")
		return errors.Is(err, store.ErrNotFound)
	})
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
}

// The default is an hour.
func TestMaintenanceIntervalIsAnHourByDefault(t *testing.T) {
	p := newPanel(t)
	if p.srv.maintenanceEvery != time.Hour {
		t.Errorf("maintenanceEvery = %v, want 1h", p.srv.maintenanceEvery)
	}
}

// With the real database: events of more than 30 days go, newer ones stay.
func TestMaintenancePrunesOldEvents(t *testing.T) {
	p := newPanel(t)
	ctx := context.Background()
	now := time.Now()
	for id, age := range map[string]time.Duration{
		"forty-days": 40 * 24 * time.Hour,
		"a-week":     7 * 24 * time.Hour,
	} {
		if err := p.srv.db.AppendEvent(ctx, &store.Event{ID: id, TS: now.Add(-age), Kind: "node.online"}); err != nil {
			t.Fatal(err)
		}
	}
	runLoop(t, p.srv.db, time.Hour, time.Now, nil)
	eventually(t, "the old event to go", func() bool {
		evs, err := p.srv.db.ListEvents(ctx, 10, "")
		return err == nil && len(evs) == 1 && evs[0].ID == "a-week"
	})
}

// The retention of a round is the one that is stored when the round starts: a
// change of the settings is used from the next round on, and a panel that has
// none uses the defaults. The rollup and the prune of a round agree on it.
func TestMaintenanceUsesTheStoredRetention(t *testing.T) {
	f := &fakeStore{}
	stop := runLoop(t, f, 10*time.Millisecond, time.Now, nil)
	defaults := store.Retention{Minutes: 48 * time.Hour, Hours: 90 * 24 * time.Hour, IPs: 7 * 24 * time.Hour}
	eventually(t, "a round with the defaults", func() bool { return len(f.retentionsSoFar()) >= 2 })

	stored := store.DefaultStatsSettings()
	stored.MinutesHours, stored.HoursDays, stored.IPDays = 6, 7, 1
	f.setSettings(&stored, nil)
	short := store.Retention{Minutes: 6 * time.Hour, Hours: 7 * 24 * time.Hour, IPs: 24 * time.Hour}
	eventually(t, "a round with the stored retention", func() bool {
		rs := f.retentionsSoFar()
		return rs[len(rs)-1] == short
	})
	stop()

	rs := f.retentionsSoFar()
	if rs[0] != defaults || rs[1] != defaults {
		t.Errorf("the first round used %+v and %+v, want the defaults %+v", rs[0], rs[1], defaults)
	}
	for i := 0; i+1 < len(rs); i += 2 {
		if rs[i] != rs[i+1] || (rs[i] != defaults && rs[i] != short) {
			t.Errorf("round %d: rollup with %+v, prune with %+v", i/2, rs[i], rs[i+1])
		}
	}
}

// Settings that cannot be read do not stop the prune, which keeps addresses
// from staying past their time: the round prunes by the longest retention of
// the statistics that a setting may have, which deletes none that a valid one
// would keep, and by the shortest of the addresses. The rest of the round runs,
// and the failure is an error in the log.
func TestMaintenanceFallsBackWhenTheSettingsCannotBeRead(t *testing.T) {
	logs := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	f := &fakeStore{settingsErr: errors.New("settings went wrong")}
	stop := runLoop(t, f, 10*time.Millisecond, time.Now, log)
	eventually(t, "two rounds", func() bool { calls, _ := f.snapshot(); return len(calls) >= 8 })
	stop()

	calls, _ := f.snapshot()
	if len(calls) < 4 || strings.Join(calls[:4], ",") != "rollup,prune,events,sessions" {
		t.Fatalf("calls = %v, want every task in every round", calls)
	}
	safe := store.Retention{Minutes: 168 * time.Hour, Hours: 730 * 24 * time.Hour, IPs: 24 * time.Hour}
	for i, r := range f.retentionsSoFar() {
		if r != safe {
			t.Errorf("call %d of rollup or prune used %+v, want %+v", i, r, safe)
		}
	}
	var seen bool
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "settings went wrong") {
			seen = true
			if !strings.Contains(line, "level=ERROR") {
				t.Errorf("the failure is logged below the error level: %s", line)
			}
		}
	}
	if !seen {
		t.Errorf("the failure is not logged:\n%s", logs.String())
	}
}

// With the real database: the minutes of a node are pruned at the retention
// that is stored, and at 48 hours while none is.
func TestMaintenancePrunesByTheStoredRetention(t *testing.T) {
	for _, tt := range []struct {
		name         string
		minutesHours uint32 // 0: no settings are stored
		keeps7h      bool
	}{
		{"no settings", 0, true},
		{"minutes for 6 hours", 6, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := newPanel(t)
			ctx := context.Background()
			db := p.srv.db
			node := &store.Node{Name: "n"}
			if err := db.CreateNode(ctx, node); err != nil {
				t.Fatal(err)
			}
			if tt.minutesHours != 0 {
				s := store.DefaultStatsSettings()
				s.MinutesHours = tt.minutesHours
				if _, err := db.ApplyStatsSettings(ctx, s); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now()
			for _, age := range []time.Duration{7 * time.Hour, 49 * time.Hour} {
				if err := db.UpsertNodeMinute(ctx, store.NodeStat{NodeID: node.ID, TS: now.Add(-age), Conns: 1}); err != nil {
					t.Fatal(err)
				}
			}
			minutes := func(from, to time.Time) int { // both spans read the table of minutes
				t.Helper()
				s, err := db.NodeSeries(ctx, node.ID, from, to, store.DefaultStatsSettings().Retention())
				if err != nil {
					t.Fatal(err)
				}
				return len(s)
			}

			// The prune goes in steps: the minute of 49 hours ago goes before
			// that of 7 hours, if that goes at all.
			runLoop(t, db, time.Hour, time.Now, nil)
			eventually(t, "the minutes to be pruned", func() bool {
				gone49h := minutes(now.Add(-50*time.Hour), now.Add(-48*time.Hour)) == 0
				return gone49h && (tt.keeps7h || minutes(now.Add(-8*time.Hour), now) == 0)
			})
			if kept := minutes(now.Add(-8*time.Hour), now) == 1; kept != tt.keeps7h {
				t.Errorf("the minute of 7 hours ago: kept = %v, want %v", kept, tt.keeps7h)
			}
		})
	}
}
