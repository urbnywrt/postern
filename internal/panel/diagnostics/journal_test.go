package diagnostics

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestListJournalEventsPages(t *testing.T) {
	e := newEnv(t)
	a := newAPIFor(t, e, NewService(e.db, nil, nil))
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	// Five events of node N1 in one second, one in the second before, and
	// some that the filters leave out.
	var want []string
	for i := range 6 {
		ts := at
		if i == 0 {
			ts = at.Add(-time.Second)
		}
		id := fmt.Sprintf("E%d", i)
		if err := e.db.AppendEvent(e.ctx, &store.Event{ID: id, TS: ts, NodeID: "N1", Kind: "check.failed", Severity: "error"}); err != nil {
			t.Fatal(err)
		}
		want = append([]string{id}, want...)
	}
	for _, x := range []store.Event{
		{ID: "X1", TS: at, NodeID: "N2", Kind: "check.failed", Severity: "error"},
		{ID: "X2", TS: at, NodeID: "N1", Kind: "node.online", Severity: "error"},
		{ID: "X3", TS: at, NodeID: "N1", Kind: "check.recovered", Severity: "info"},
		{ID: "X4", TS: at.Add(time.Hour), NodeID: "N1", Kind: "check.failed", Severity: "error"},
	} {
		if err := e.db.AppendEvent(e.ctx, &x); err != nil {
			t.Fatal(err)
		}
	}
	req := &panelv1.ListJournalRequest{NodeId: "N1", MinSeverity: "warning", KindPrefix: "check.", ToUnix: at.Add(time.Minute).Unix(), Limit: 2}
	var got []string
	for pages := 0; ; pages++ {
		if pages > 4 {
			t.Fatal("the paging does not end")
		}
		res, err := a.admin.ListJournal(e.ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatal(err)
		}
		if n := len(res.Msg.GetEvents()); n > 2 || len(res.Msg.GetAudit()) != 0 {
			t.Fatalf("page of %d events and %d audit entries", n, len(res.Msg.GetAudit()))
		}
		for _, ev := range res.Msg.GetEvents() {
			got = append(got, ev.GetId())
		}
		if res.Msg.GetNextCursor() == "" {
			break
		}
		req.Cursor = res.Msg.GetNextCursor()
	}
	if !slices.Equal(got, want) {
		t.Errorf("pages = %v, want %v", got, want)
	}
}

// TestListJournalPagesAtTheMaximum: with limit 200, the documented maximum,
// 254 rows come in two pages (bug B2 of the real-server pass: the store cut
// the extra row off, so there was never a next page).
func TestListJournalPagesAtTheMaximum(t *testing.T) {
	e := newEnv(t)
	a := newAPIFor(t, e, NewService(e.db, nil, nil))
	at := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	for i := range 254 {
		ts := at.Add(time.Duration(i) * time.Second)
		if err := e.db.AppendEvent(e.ctx, &store.Event{ID: fmt.Sprintf("E%03d", i), TS: ts, NodeID: "N1", Kind: "check.failed", Severity: "error"}); err != nil {
			t.Fatal(err)
		}
		if err := e.db.AppendAudit(e.ctx, &store.AuditEntry{ID: fmt.Sprintf("A%03d", i), TS: ts, Action: "maxpage.test"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{"events", "audit"} {
		req := &panelv1.ListJournalRequest{Source: source, Limit: 200}
		if source == "audit" {
			req.ActionPrefix = "maxpage."
		}
		var sizes []int
		seen := map[string]bool{}
		for pages := 0; ; pages++ {
			if pages > 3 {
				t.Fatalf("%s: the paging does not end", source)
			}
			res, err := a.admin.ListJournal(e.ctx, connect.NewRequest(req))
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, ev := range res.Msg.GetEvents() {
				seen[ev.GetId()] = true
				n++
			}
			for _, au := range res.Msg.GetAudit() {
				seen[au.GetId()] = true
				n++
			}
			sizes = append(sizes, n)
			if res.Msg.GetNextCursor() == "" {
				break
			}
			req.Cursor = res.Msg.GetNextCursor()
		}
		if !slices.Equal(sizes, []int{200, 54}) || len(seen) != 254 {
			t.Errorf("%s: pages of %v, %d distinct rows; want [200 54], 254", source, sizes, len(seen))
		}
	}
}

func TestListJournalAudit(t *testing.T) {
	e := newEnv(t)
	a := newAPIFor(t, e, NewService(e.db, nil, nil))
	me, err := e.db.AdminByUsername(e.ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// After the sign-in of the test, which the audit log records too (auth.login),
	// so that these entries are the newest.
	at := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	for _, x := range []store.AuditEntry{
		{ID: "A1", TS: at, AdminID: me.ID, Action: "diagnostics.fix", Target: "node:N1", Details: map[string]string{"fix": "roll_edge"}},
		{ID: "A2", TS: at, AdminID: me.ID, Action: "diagnostics.run"},
		{ID: "A3", TS: at, AdminID: "GONE", Action: "diagnostics.fix"},
		{ID: "A4", TS: at, AdminID: me.ID, Action: "proxy.create"},
	} {
		if err := e.db.AppendAudit(e.ctx, &x); err != nil {
			t.Fatal(err)
		}
	}
	res, err := a.admin.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{Source: "audit", ActionPrefix: "diagnostics.fix"}))
	if err != nil {
		t.Fatal(err)
	}
	au := res.Msg.GetAudit()
	if len(au) != 2 || au[0].GetId() != "A3" || au[0].GetAdminName() != "" || au[1].GetId() != "A1" || au[1].GetAdminName() != "admin" ||
		au[1].GetTarget() != "node:N1" || au[1].GetDetails()["fix"] != "roll_edge" || au[1].GetTsUnix() != at.Unix() || res.Msg.GetNextCursor() != "" {
		t.Errorf("audit = %v, next %q", au, res.Msg.GetNextCursor())
	}
	res, err = a.admin.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{Source: "audit", AdminId: me.ID, Limit: 1}))
	if err != nil || len(res.Msg.GetAudit()) != 1 || res.Msg.GetAudit()[0].GetId() != "A4" || res.Msg.GetNextCursor() == "" {
		t.Fatalf("first page = %v, %v", res, err)
	}
	// An audit cursor is no events cursor.
	_, err = a.admin.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{Cursor: res.Msg.GetNextCursor()}))
	if codeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an audit cursor for the events: %v", err)
	}
}

func TestListJournalRefuses(t *testing.T) {
	e := newEnv(t)
	a := newAPIFor(t, e, NewService(e.db, nil, nil))
	if _, err := a.anon.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{})); codeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("anonymous: %v", err)
	}
	for name, req := range map[string]*panelv1.ListJournalRequest{
		"source":            {Source: "logs"},
		"limit":             {Limit: 201},
		"severity":          {MinSeverity: "loud"},
		"range":             {FromUnix: 20, ToUnix: 10},
		"negative":          {FromUnix: -1},
		"cursor":            {Cursor: "not a cursor!"},
		"forged cursor":     {Cursor: "ZTp4OkU"}, // "e:x:E"
		"audit filter":      {AdminId: "A"},
		"events filter":     {Source: "audit", NodeId: "N"},
		"severity of audit": {Source: "audit", MinSeverity: "error"},
	} {
		if _, err := a.admin.ListJournal(e.ctx, connect.NewRequest(req)); codeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if res, err := a.admin.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{Limit: 200})); err != nil || len(res.Msg.GetEvents()) != 0 {
		t.Errorf("limit 200: %v, %v", res, err)
	}
}
