package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func eventIDs(es []*Event) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.ID)
	}
	return out
}

func auditIDs(as []*AuditEntry) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.ID)
	}
	return out
}

func TestListEventsFiltered(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	t0 := testNow.Add(-time.Hour)
	add := func(id string, at time.Duration, node, proxy, kind, severity string) {
		t.Helper()
		if err := db.AppendEvent(ctx, &Event{ID: id, TS: t0.Add(at), NodeID: node, ProxyID: proxy, Kind: kind, Severity: severity}); err != nil {
			t.Fatal(err)
		}
	}
	add("E1", 0, "N1", "", "node.online", "info")
	add("E2", time.Minute, "N1", "P1", "proxy.failed", "error")
	add("E3", 2*time.Minute, "N2", "", "check.warning", "warning")
	add("E4", 3*time.Minute, "N2", "P2", "check.failed", "error")
	add("E5", 4*time.Minute, "N1", "", "edge.slow", "warn")
	add("E6", 5*time.Minute, "N1", "", "check.recovered", "info")

	cases := []struct {
		name string
		f    EventFilter
		want []string
	}{
		{"all, newest first", EventFilter{}, []string{"E6", "E5", "E4", "E3", "E2", "E1"}},
		{"node", EventFilter{NodeID: "N1"}, []string{"E6", "E5", "E2", "E1"}},
		{"proxy", EventFilter{ProxyID: "P2"}, []string{"E4"}},
		{"at least warning, warn included", EventFilter{MinSeverity: "warning"}, []string{"E5", "E4", "E3", "E2"}},
		{"at least error", EventFilter{MinSeverity: "error"}, []string{"E4", "E2"}},
		{"at least info", EventFilter{MinSeverity: "info"}, []string{"E6", "E5", "E4", "E3", "E2", "E1"}},
		{"kind prefix", EventFilter{KindPrefix: "check."}, []string{"E6", "E4", "E3"}},
		{"kind prefix is not a pattern", EventFilter{KindPrefix: "check%"}, nil},
		{"kind prefix with an underscore", EventFilter{KindPrefix: "check_"}, nil},
		{"from inclusive, to exclusive", EventFilter{From: t0.Add(time.Minute), To: t0.Add(4 * time.Minute)}, []string{"E4", "E3", "E2"}},
		{"combined", EventFilter{NodeID: "N2", MinSeverity: "error", KindPrefix: "check"}, []string{"E4"}},
		{"exact kind", EventFilter{NodeID: "N1", Kind: "proxy.failed"}, []string{"E2"}},
		{"exact kind is not a prefix", EventFilter{Kind: "check"}, nil},
	}
	for _, c := range cases {
		got, err := db.ListEventsFiltered(ctx, c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if ids := eventIDs(got); !slices.Equal(ids, c.want) {
			t.Errorf("%s: %v, want %v", c.name, ids, c.want)
		}
	}
	if _, err := db.ListEventsFiltered(ctx, EventFilter{MinSeverity: "loud"}); !errors.Is(err, ErrBadFilter) {
		t.Errorf("an unknown severity: %v, want ErrBadFilter", err)
	}
}

func TestListEventsFilteredPagesOverEqualTimes(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// Seven events in the same second, three in the one before.
	var want []string
	for i := range 10 {
		at := testNow
		if i < 3 {
			at = testNow.Add(-time.Second)
		}
		id := fmt.Sprintf("E%02d", i)
		if err := db.AppendEvent(ctx, &Event{ID: id, TS: at, Kind: "k"}); err != nil {
			t.Fatal(err)
		}
		want = append([]string{id}, want...)
	}
	var got []string
	var cur *Cursor
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("the paging does not end")
		}
		page, err := db.ListEventsFiltered(ctx, EventFilter{Limit: 3, Before: cur})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) > 3 {
			t.Fatalf("page of %d, want at most 3", len(page))
		}
		got = append(got, eventIDs(page)...)
		if len(page) < 3 {
			break
		}
		last := page[len(page)-1]
		cur = &Cursor{TS: last.TS, ID: last.ID}
	}
	if !slices.Equal(got, want) {
		t.Errorf("pages = %v, want %v", got, want)
	}
}

func TestJournalLimits(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for i := range 250 {
		if err := db.AppendEvent(ctx, &Event{ID: fmt.Sprintf("E%03d", i), TS: testNow, Kind: "k"}); err != nil {
			t.Fatal(err)
		}
		if err := db.AppendAudit(ctx, &AuditEntry{ID: fmt.Sprintf("A%03d", i), TS: testNow, Action: "a"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ limit, want int }{{0, 50}, {7, 7}, {200, 200}, {201, 201}, {1000, 201}} {
		es, err := db.ListEventsFiltered(ctx, EventFilter{Limit: c.limit})
		if err != nil {
			t.Fatal(err)
		}
		as, err := db.ListAudit(ctx, AuditFilter{Limit: c.limit})
		if err != nil {
			t.Fatal(err)
		}
		if len(es) != c.want || len(as) != c.want {
			t.Errorf("limit %d: %d events, %d audit entries, want %d", c.limit, len(es), len(as), c.want)
		}
	}
}

func TestListAudit(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	add := func(id string, at time.Duration, admin, action string) {
		t.Helper()
		if err := db.AppendAudit(ctx, &AuditEntry{ID: id, TS: testNow.Add(at), AdminID: admin, Action: action, Target: "node:N1",
			Details: map[string]string{"k": "v"}}); err != nil {
			t.Fatal(err)
		}
	}
	add("A1", 0, "AD1", "diagnostics.run")
	add("A2", time.Second, "AD2", "diagnostics.fix")
	add("A3", 2*time.Second, "AD1", "proxy.create")
	add("A4", 2*time.Second, "AD1", "diagnostics.fix")
	add("A5", 3*time.Second, "", "setup")

	cases := []struct {
		name string
		f    AuditFilter
		want []string
	}{
		{"all", AuditFilter{}, []string{"A5", "A4", "A3", "A2", "A1"}},
		{"admin", AuditFilter{AdminID: "AD1"}, []string{"A4", "A3", "A1"}},
		{"action prefix", AuditFilter{ActionPrefix: "diagnostics."}, []string{"A4", "A2", "A1"}},
		{"both", AuditFilter{AdminID: "AD1", ActionPrefix: "diagnostics.fix"}, []string{"A4"}},
		{"range", AuditFilter{From: testNow.Add(time.Second), To: testNow.Add(3 * time.Second)}, []string{"A4", "A3", "A2"}},
		{"after the cursor", AuditFilter{Before: &Cursor{TS: testNow.Add(2 * time.Second), ID: "A4"}}, []string{"A3", "A2", "A1"}},
	}
	for _, c := range cases {
		got, err := db.ListAudit(ctx, c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if ids := auditIDs(got); !slices.Equal(ids, c.want) {
			t.Errorf("%s: %v, want %v", c.name, ids, c.want)
		}
	}
	got, err := db.ListAudit(ctx, AuditFilter{AdminID: "AD2"})
	if err != nil || len(got) != 1 || got[0].Target != "node:N1" || got[0].Details["k"] != "v" || !got[0].TS.Equal(testNow.Add(time.Second)) {
		t.Errorf("entry = %+v, %v", got, err)
	}
}

// The filters of a proxy and of a node's kind are read by the indexes of
// 0015, not along the time of every event.
func TestEventsQueryPlans(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, c := range []struct {
		f     EventFilter
		index string
	}{
		{EventFilter{ProxyID: "P1"}, "events_proxy_id_ts_idx"},
		{EventFilter{ProxyID: "P1", Before: &Cursor{TS: testNow, ID: "E"}}, "events_proxy_id_ts_idx"},
		{EventFilter{NodeID: "N1", Kind: "node.error", From: testNow}, "events_node_id_kind_ts_idx"},
	} {
		q, args, err := eventsQuery(c.f)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := db.sql.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		_ = rows.Close()
		if !slices.ContainsFunc(plan, func(d string) bool { return strings.Contains(d, "USING INDEX "+c.index) }) {
			t.Errorf("%+v: plan %q, want %s", c.f, plan, c.index)
		}
	}
}
