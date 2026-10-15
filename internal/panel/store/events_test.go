package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestEventRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	e := &Event{
		TS:       testNow,
		NodeID:   "NODE1",
		ProxyID:  "PROXY1",
		Kind:     "proxy.failed",
		Severity: "error",
		Message:  "engine exited",
		Details:  map[string]string{"exit_code": "1", "reason": "oom"},
	}
	if err := db.AppendEvent(ctx, e); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	if len(e.ID) != 26 {
		t.Fatalf("ID = %q, want a ULID", e.ID)
	}
	got, err := db.ListEvents(ctx, 10, "")
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], e) {
		t.Errorf("events = %+v, want [%+v]", got, e)
	}
}

func TestEventDefaults(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)
	e := &Event{Kind: "node.online"}
	if err := db.AppendEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	want := &Event{ID: e.ID, TS: testNow, Kind: "node.online", Severity: "info"}
	if !reflect.DeepEqual(e, want) {
		t.Errorf("record after Append = %+v, want %+v", e, want)
	}
	got, err := db.ListEvents(ctx, 10, "")
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("events = %+v, %v; want [%+v]", got, err, want)
	}
	if got[0].Details != nil {
		t.Errorf("Details = %v, want nil", got[0].Details)
	}
}

func TestListEventsOrderAndFilter(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// Appended out of order: the newest comes first, and events of the same
	// second come in the order they were appended, newest first.
	type spec struct {
		node string
		at   time.Duration
	}
	var ids []string // by append order
	for _, s := range []spec{
		{"A", 10 * time.Second}, {"B", 30 * time.Second}, {"A", 20 * time.Second},
		{"B", 20 * time.Second}, {"", 40 * time.Second},
	} {
		e := &Event{TS: testNow.Add(s.at), NodeID: s.node, Kind: "k"}
		if err := db.AppendEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	idsOf := func(es []*Event) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.ID)
		}
		return out
	}

	got, err := db.ListEvents(ctx, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	// 40s (#4), 30s (#1), 20s (#3 appended after #2), 10s (#0)
	want := []string{ids[4], ids[1], ids[3], ids[2], ids[0]}
	if !slices.Equal(idsOf(got), want) {
		t.Errorf("all events = %v, want %v", idsOf(got), want)
	}

	got, err = db.ListEvents(ctx, 100, "A")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{ids[2], ids[0]}; !slices.Equal(idsOf(got), want) {
		t.Errorf("events of A = %v, want %v", idsOf(got), want)
	}

	got, err = db.ListEvents(ctx, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{ids[4], ids[1]}; !slices.Equal(idsOf(got), want) {
		t.Errorf("two newest events = %v, want %v", idsOf(got), want)
	}

	got, err = db.ListEvents(ctx, 100, "no-such-node")
	if err != nil || len(got) != 0 {
		t.Errorf("events of an unknown node = %v, %v; want none", got, err)
	}
}

func TestListEventsLimits(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	const total = 120
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range total {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO events (id, ts, kind) VALUES (?, ?, 'k')`, fmt.Sprintf("E%03d", i), i); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ limit, want int }{
		{0, defaultEventLimit}, // no limit given
		{-5, defaultEventLimit},
		{7, 7},
		{total + 1000, total}, // fewer rows than the limit
	} {
		got, err := db.ListEvents(ctx, tt.limit, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != tt.want {
			t.Errorf("ListEvents(limit %d) returned %d events, want %d", tt.limit, len(got), tt.want)
		}
	}
	if defaultEventLimit != 100 || maxEventLimit != 1000 {
		t.Errorf("defaultEventLimit = %d, maxEventLimit = %d; documented as 100 and 1000", defaultEventLimit, maxEventLimit)
	}
}

func TestAppendAudit(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	a := &AuditEntry{
		TS:      testNow,
		AdminID: "ADMIN1",
		Action:  "proxy.create",
		Target:  "proxy:PROXY1",
		Details: map[string]string{"name": "alpha"},
	}
	if err := db.AppendAudit(ctx, a); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if len(a.ID) != 26 {
		t.Fatalf("ID = %q, want a ULID", a.ID)
	}
	var (
		id, adminID, action, target, details string
		ts                                   int64
	)
	err := db.sql.QueryRowContext(ctx, `SELECT id, ts, admin_id, action, target, details FROM audit_log`).
		Scan(&id, &ts, &adminID, &action, &target, &details)
	if err != nil {
		t.Fatal(err)
	}
	if id != a.ID || ts != testNow.Unix() || adminID != "ADMIN1" || action != "proxy.create" || target != "proxy:PROXY1" {
		t.Errorf("row = %s %d %s %s %s", id, ts, adminID, action, target)
	}
	var d map[string]string
	if err := json.Unmarshal([]byte(details), &d); err != nil || !reflect.DeepEqual(d, a.Details) {
		t.Errorf("details = %s (%v), want %v", details, err, a.Details)
	}

	// Without a time, or any details.
	db.now = fixedClock(testNow.Add(time.Hour))
	b := &AuditEntry{Action: "login"}
	if err := db.AppendAudit(ctx, b); err != nil {
		t.Fatal(err)
	}
	if !b.TS.Equal(testNow.Add(time.Hour)) {
		t.Errorf("TS = %v, want the clock", b.TS)
	}
	var raw string
	if err := db.sql.QueryRowContext(ctx, `SELECT details FROM audit_log WHERE id = ?`, b.ID).Scan(&raw); err != nil || raw != "{}" {
		t.Errorf("details = %q, %v; want {}", raw, err)
	}
}

func TestEventsOutliveWhatTheyName(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	if err := db.AppendEvent(ctx, &Event{NodeID: node.ID, Kind: "node.online"}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteNode(ctx, node.ID); err != nil {
		t.Fatal(err)
	}
	got, err := db.ListEvents(ctx, 10, node.ID)
	if err != nil || len(got) != 1 {
		t.Errorf("events of the deleted node = %v, %v; want the one event kept", got, err)
	}
}

// Events are kept for 30 days: what is older goes, in batches, and the audit
// log stays.
// PruneEvents leaves the write lock free between its batches, as RollupStats
// and PruneStats do between their steps: a write there gets it at once. It
// does not pause after the last batch.
func TestPruneEventsPausesBetweenBatches(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	const old = 2*pruneEventsBatch + 7 // three batches
	mustExec(t, db, `WITH RECURSIVE seq(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM seq WHERE i + 1 < ?)
		INSERT INTO events (id, ts, kind) SELECT printf('old-%05d', i), ? - i, 'node.online' FROM seq`,
		old, testNow.Add(-31*24*time.Hour).Unix())
	pauses := 0
	db.steps.onPause = func() {
		pauses++
		start := time.Now()
		if err := db.PutSetting(ctx, "test", pauses); err != nil {
			t.Errorf("a write at pause %d: %v", pauses, err)
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("a write at pause %d waited %s for the lock", pauses, took)
		}
	}
	if n, err := db.PruneEvents(ctx, testNow); err != nil || n != old {
		t.Fatalf("PruneEvents = %d, %v; want %d", n, err, old)
	}
	if pauses != 2 {
		t.Errorf("PruneEvents paused %d times, want 2", pauses)
	}
}

func TestPruneEvents(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := testNow
	add := func(id string, age time.Duration) {
		t.Helper()
		if err := db.AppendEvent(ctx, &Event{ID: id, TS: now.Add(-age), Kind: "node.online"}); err != nil {
			t.Fatal(err)
		}
	}
	const old = 2*pruneEventsBatch + 7 // three batches
	mustExec(t, db, `WITH RECURSIVE seq(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM seq WHERE i + 1 < ?)
		INSERT INTO events (id, ts, kind) SELECT printf('old-%05d', i), ? - i, 'node.online' FROM seq`,
		old, now.Add(-31*24*time.Hour).Unix())
	add("thirty-days-and-a-second", 30*24*time.Hour+time.Second)
	add("thirty-days", 30*24*time.Hour)
	add("yesterday", 24*time.Hour)
	if err := db.AppendAudit(ctx, &AuditEntry{TS: now.Add(-365 * 24 * time.Hour), Action: "proxy.create"}); err != nil {
		t.Fatal(err)
	}

	n, err := db.PruneEvents(ctx, now)
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	if n != old+1 {
		t.Errorf("PruneEvents deleted %d events, want %d", n, old+1)
	}
	got, err := db.ListEvents(ctx, maxEventLimit, "")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range got {
		ids = append(ids, e.ID)
	}
	if want := []string{"yesterday", "thirty-days"}; !slices.Equal(ids, want) {
		t.Errorf("events left = %v, want %v", ids, want)
	}
	if c := count(t, db, `SELECT count(*) FROM audit_log`); c != 1 {
		t.Errorf("%d audit entries left, want the one there was", c)
	}

	// Nothing more to delete is no error.
	if n, err := db.PruneEvents(ctx, now); err != nil || n != 0 {
		t.Errorf("PruneEvents again = %d, %v; want 0, nil", n, err)
	}
}

func TestHasEvent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.AppendEvent(ctx, &Event{Kind: "rollout_completed", Details: map[string]string{"rollout": "r1"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendEvent(ctx, &Event{Kind: "other"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind, value string
		want        bool
	}{{"rollout_completed", "r1", true}, {"rollout_completed", "r2", false}, {"rollout_failed", "r1", false}} {
		got, err := db.HasEvent(ctx, tc.kind, "rollout", tc.value)
		if err != nil || got != tc.want {
			t.Errorf("HasEvent(%s, %s) = %v, %v; want %v", tc.kind, tc.value, got, err, tc.want)
		}
	}
}
