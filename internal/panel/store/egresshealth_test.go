package store

import (
	"context"
	"slices"
	"testing"
	"time"
)

// putMemberMinute writes a minute of a member of a chain, with SQL.
func putMemberMinute(t *testing.T, db *DB, nodeID, chainID, memberKey string, ts time.Time, status string, latency int, exitIP string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO egress_health_1m (node_id, chain_id, member_key, ts, status, latency_ms, exit_ip) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		nodeID, chainID, memberKey, ts.Unix(), status, latency, exitIP)
}

// memberHour returns the hour of a member as
// "up|down|unknown|latency avg|latency max|exit ip", or nothing.
func memberHour(t *testing.T, db *DB, nodeID, chainID, memberKey string, ts time.Time) []string {
	t.Helper()
	return rowsOf(t, db, `SELECT minutes_up, minutes_down, minutes_unknown, latency_avg_ms, latency_max_ms, exit_ip
		FROM egress_health WHERE node_id = ? AND chain_id = ? AND member_key = ? AND ts = ?`,
		nodeID, chainID, memberKey, ts.Unix())
}

// Every member is its own: the same key in another chain, or on another node,
// is another member.
func TestMemberHoursPerChainAndNode(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	other := mustNode(t, db, "other")
	putMemberMinute(t, db, node.ID, "C1", "m1", at(10, 9, 0), "up", 10, "203.0.113.1")
	putMemberMinute(t, db, node.ID, "C2", "m1", at(10, 9, 0), "down", 0, "")
	putMemberMinute(t, db, other.ID, "C1", "m1", at(10, 9, 0), "unknown", 0, "203.0.113.3")
	if err := db.RollupStats(context.Background(), statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	for _, tt := range []struct {
		node, chain string
		want        string
	}{
		{node.ID, "C1", "1|0|0|10|10|203.0.113.1"},
		{node.ID, "C2", "0|1|0|0|0|"},
		{other.ID, "C1", "0|0|1|0|0|203.0.113.3"},
	} {
		if got := memberHour(t, db, tt.node, tt.chain, "m1", at(10, 9, 0)); !slices.Equal(got, []string{tt.want}) {
			t.Errorf("hour of m1 in %s on %s = %q, want %s", tt.chain, tt.node, got, tt.want)
		}
	}
}

// As for proxies, an hour of a member is made again only while all its minutes
// are there: the hour that the prune cut keeps its value, a whole hour is
// replaced, and an hour that has no row gets one.
func TestMemberHoursOfPrunedMinutes(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	ctx := context.Background()
	// The oldest minute that is kept is 10-08 12:30.
	mustExec(t, db, `INSERT INTO egress_health (node_id, chain_id, member_key, ts, minutes_up) VALUES (?, 'C1', 'm1', ?, 60)`, node.ID, at(8, 12, 0).Unix())
	putMemberMinute(t, db, node.ID, "C1", "m1", at(8, 12, 40), "down", 0, "")
	mustExec(t, db, `INSERT INTO egress_health (node_id, chain_id, member_key, ts, minutes_up) VALUES (?, 'C1', 'm1', ?, 60)`, node.ID, at(8, 13, 0).Unix())
	putMemberMinute(t, db, node.ID, "C1", "m1", at(8, 13, 5), "down", 0, "")
	putMemberMinute(t, db, node.ID, "C1", "m1", at(8, 11, 5), "up", 30, "203.0.113.4") // never rolled up

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	for _, tt := range []struct {
		hour time.Time
		want string
	}{
		{at(8, 12, 0), "60|0|0|0|0|"},
		{at(8, 13, 0), "0|1|0|0|0|"},
		{at(8, 11, 0), "1|0|0|30|30|203.0.113.4"},
	} {
		if got := memberHour(t, db, node.ID, "C1", "m1", tt.hour); !slices.Equal(got, []string{tt.want}) {
			t.Errorf("hour %s = %q, want %s", tt.hour.Format(time.DateTime), got, tt.want)
		}
	}
}
