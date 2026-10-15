package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestInsertProbe(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	probes := func() []string {
		t.Helper()
		return rowsOf(t, db, `SELECT proxy_id, ts, vantage, kind, ok, latency_ms, error FROM probes ORDER BY vantage, ts`)
	}
	when := at(10, 12, 0).Add(1500 * time.Millisecond) // stored to the second
	first := Probe{ProxyID: p.ID, TS: when, Vantage: "panel", Kind: "l2", Error: "unreachable"}
	if err := db.InsertProbe(ctx, first); err != nil {
		t.Fatalf("InsertProbe: %v", err)
	}
	ts := at(10, 12, 0).Unix() + 1
	want := []string{fmt.Sprintf("%s|%d|panel|l2|0|0|unreachable", p.ID, ts)}
	if got := probes(); !slices.Equal(got, want) {
		t.Fatalf("probes = %q, want %q", got, want)
	}

	// A probe that is there already is no error, and stays as it was.
	again := first
	again.OK, again.LatencyMS, again.Error = true, 80, ""
	if err := db.InsertProbe(ctx, again); err != nil {
		t.Errorf("InsertProbe of a probe that is there: %v", err)
	}
	if got := probes(); !slices.Equal(got, want) {
		t.Errorf("probes after the same one again = %q, want %q", got, want)
	}

	// Another vantage, or another kind, at the same time is another probe.
	if err := db.InsertProbe(ctx, Probe{ProxyID: p.ID, TS: when, Vantage: "node", Kind: "l2", OK: true, LatencyMS: 95}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertProbe(ctx, Probe{ProxyID: p.ID, TS: when, Vantage: "panel", Kind: "web", OK: true, LatencyMS: 7}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, `SELECT count(*) FROM probes`); n != 3 {
		t.Errorf("%d probes, want 3", n)
	}

	if err := db.InsertProbe(ctx, Probe{ProxyID: "01K6Y00000000000000000000Z", TS: when, Vantage: "panel", Kind: "l2"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("InsertProbe of a proxy that is not there: err = %v, want ErrNotFound", err)
	}
}
