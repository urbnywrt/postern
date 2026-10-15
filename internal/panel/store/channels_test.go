package store

import (
	"context"
	"reflect"
	"testing"
)

func TestChannelVersions(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)

	got, err := db.ChannelVersions(ctx)
	if err != nil {
		t.Fatalf("ChannelVersions: %v", err)
	}
	if !reflect.DeepEqual(got, seededChannels) {
		t.Fatalf("a new database has channel versions %v, want the seeded %v", got, seededChannels)
	}

	// A channel moves; the other channel of the engine, and the other engines,
	// do not.
	if err := db.SetChannelVersion(ctx, "telemt", ChannelLatest, "3.5.14"); err != nil {
		t.Fatalf("SetChannelVersion: %v", err)
	}
	// A component that has no rows yet gets one.
	if err := db.SetChannelVersion(ctx, "postern", ChannelStable, "v0.5.0"); err != nil {
		t.Fatalf("SetChannelVersion of a new component: %v", err)
	}
	got, err = db.ChannelVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{}
	for e, c := range seededChannels {
		want[e] = map[string]string{}
		for ch, v := range c {
			want[e][ch] = v
		}
	}
	want["telemt"][ChannelLatest] = "3.5.14"
	want["postern"] = map[string]string{ChannelStable: "v0.5.0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("channel versions = %v\nwant %v", got, want)
	}
	var updated int64
	if err := db.sql.QueryRowContext(ctx, `SELECT updated_at FROM engine_channels WHERE engine = 'telemt' AND channel = 'latest'`).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	if updated != testNow.Unix() {
		t.Errorf("updated_at = %d, want the clock %d", updated, testNow.Unix())
	}
	if n := count(t, db, `SELECT count(*) FROM engine_channels WHERE updated_at = 0`); n != 9 {
		t.Errorf("%d rows still at the seed time, want 9", n)
	}

	// Only stable and latest are channels.
	if err := db.SetChannelVersion(ctx, "telemt", "beta", "3.6.0"); err == nil {
		t.Error("SetChannelVersion of channel beta succeeded")
	}
	if n := count(t, db, `SELECT count(*) FROM engine_channels`); n != 11 {
		t.Errorf("%d rows, want 11", n)
	}
}
