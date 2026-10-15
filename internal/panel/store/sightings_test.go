package store

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// Where an address was seen adds up over the minutes: the first time is the
// earliest, the last the latest, the bytes are summed, and a country is
// replaced by one that is not empty. An address is stored in its usual form,
// an IPv4 address in IPv6 as IPv4, and what is not an address not at all.
func TestSightingsAddUp(t *testing.T) {
	db, node, p, q := ingestFixture(t)
	m1, m2, m3 := at(10, 11, 0), at(10, 11, 5), at(10, 11, 7)
	s := func(proxyID, ip, country string, first, last time.Time, bytes uint64) Sighting {
		return Sighting{ProxyID: proxyID, IP: ip, Country: country, FirstSeen: first, LastSeen: last, Bytes: bytes}
	}
	ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: m1, Sightings: []Sighting{
		s(p.ID, "198.51.100.7", "DE", m1.Add(10*time.Second), m1.Add(20*time.Second), 100),
		s(q.ID, "198.51.100.7", "DE", m1, m1, 1), // another proxy: another row
		s(p.ID, "2001:DB8::7", "", m1, m1, 2),
		s(p.ID, "::ffff:198.51.100.8", "nl", m1, m1, 3),
		s(p.ID, "not an address", "DE", m1, m1, 4),
	}})
	ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: m2, Sightings: []Sighting{
		s(p.ID, "198.51.100.7", "", m2, m2.Add(30*time.Second), 50), // no country: the one there stays
	}})
	ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: m3, Sightings: []Sighting{
		s(p.ID, "198.51.100.7", "NL", m1, m1.Add(5*time.Second), 1), // reported late: only the first time moves
	}})

	want := sortedRows(
		fmt.Sprintf("%s|198.51.100.7|%d|%d|151|NL", p.ID, m1.Unix(), m2.Unix()+30),
		fmt.Sprintf("%s|198.51.100.7|%d|%d|1|DE", q.ID, m1.Unix(), m1.Unix()),
		fmt.Sprintf("%s|2001:db8::7|%d|%d|2|", p.ID, m1.Unix(), m1.Unix()),
		fmt.Sprintf("%s|198.51.100.8|%d|%d|3|", p.ID, m1.Unix(), m1.Unix()),
	)
	got := rowsOf(t, db, `SELECT proxy_id, ip, first_seen, last_seen, bytes, country FROM ip_sightings`)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("sightings = %q\nwant %q", got, want)
	}
}

// A proxy keeps at most 100,000 addresses: the prune deletes those that were
// seen last the longest ago, and leaves the other proxies alone.
func TestPruneStatsCapsTheSightingsOfAProxy(t *testing.T) {
	db, _, p, q := statsFixture(t)
	storePolicy(t, db, IPPolicyFull)
	ctx := context.Background()
	base := statsNow.Add(-24 * time.Hour)
	mustExec(t, db, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100005)
		INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen, bytes)
		SELECT ?, printf('2001:db8::%x:%x', i / 65536, i % 65536), ?, ? + i, 1 FROM n`, p.ID, base.Unix(), base.Unix())
	for i := range 3 {
		putSighting(t, db, q.ID, fmt.Sprintf("192.0.2.%d", i+1), base)
	}

	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM ip_sightings WHERE proxy_id = ?`, p.ID); n != 100000 {
		t.Errorf("%d sightings of the proxy, want 100000", n)
	}
	if n := count(t, db, `SELECT count(*) FROM ip_sightings WHERE proxy_id = ? AND last_seen <= ?`, p.ID, base.Unix()+5); n != 0 {
		t.Errorf("%d of the 5 sightings that were seen last the longest ago are left", n)
	}
	if n := count(t, db, `SELECT count(*) FROM ip_sightings WHERE proxy_id = ?`, q.ID); n != 3 {
		t.Errorf("%d sightings of the other proxy, want 3", n)
	}
}
