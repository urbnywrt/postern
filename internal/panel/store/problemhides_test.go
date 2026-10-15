package store

import (
	"context"
	"testing"
	"time"
)

func TestProblemHides(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	at := time.Unix(1_700_000_000, 0)

	// Hide: stored with its fingerprint, the time and the admin.
	if err := db.HideProblem(ctx, &ProblemHide{Key: "a", Fingerprint: "fa", HiddenAt: at, AdminID: "adm"}); err != nil {
		t.Fatalf("HideProblem: %v", err)
	}
	if err := db.HideProblem(ctx, &ProblemHide{Key: "b", Fingerprint: "fb", HiddenAt: at}); err != nil {
		t.Fatalf("HideProblem: %v", err)
	}
	// Hiding again replaces the fingerprint.
	if err := db.HideProblem(ctx, &ProblemHide{Key: "b", Fingerprint: "fb2", HiddenAt: at.Add(time.Minute)}); err != nil {
		t.Fatalf("HideProblem again: %v", err)
	}

	// A matching fingerprint keeps the hide; a changed one deletes it.
	held, err := db.SettleProblemHides(ctx, map[string]string{"a": "fa", "b": "changed"}, false)
	if err != nil {
		t.Fatalf("SettleProblemHides: %v", err)
	}
	if len(held) != 1 || held["a"].AdminID != "adm" || !held["a"].HiddenAt.Equal(at) || held["a"].Fingerprint != "fa" {
		t.Errorf("held = %+v, want a only", held)
	}
	if c := count(t, db, `SELECT count(*) FROM problem_hides WHERE key = 'b'`); c != 0 {
		t.Errorf("the hide of a changed problem is left")
	}
	// The change brings it back: hiding it again holds with its new fingerprint.
	if err := db.HideProblem(ctx, &ProblemHide{Key: "b", Fingerprint: "changed", HiddenAt: at}); err != nil {
		t.Fatal(err)
	}

	// A partial view (a node's problems) does not delete what it does not see.
	held, err = db.SettleProblemHides(ctx, map[string]string{"b": "changed"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held["b"].Key != "b" {
		t.Errorf("held = %+v, want b", held)
	}
	if c := count(t, db, `SELECT count(*) FROM problem_hides`); c != 2 {
		t.Errorf("a partial view deleted hides: %d left, want 2", c)
	}

	// The whole feed: a problem that cleared loses its hide.
	held, err = db.SettleProblemHides(ctx, map[string]string{"b": "changed"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 {
		t.Errorf("held = %+v, want b", held)
	}
	if c := count(t, db, `SELECT count(*) FROM problem_hides WHERE key = 'a'`); c != 0 {
		t.Errorf("the hide of a cleared problem is left")
	}

	// Unhide deletes it, and says whether there was one.
	if ok, err := db.UnhideProblem(ctx, "b"); err != nil || !ok {
		t.Errorf("UnhideProblem = %v, %v; want true", ok, err)
	}
	if ok, err := db.UnhideProblem(ctx, "b"); err != nil || ok {
		t.Errorf("UnhideProblem twice = %v, %v; want false", ok, err)
	}
	if c := count(t, db, `SELECT count(*) FROM problem_hides`); c != 0 {
		t.Errorf("%d hides left, want 0", c)
	}
}
