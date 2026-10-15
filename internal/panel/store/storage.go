package store

import (
	"context"
	"fmt"
)

// StorageInfo is how much room the database takes: the size of its file, the
// part of it that is free pages (what a VACUUM would give back), and how many
// rows the tables that grow have, by table name.
type StorageInfo struct {
	FileBytes, FreeBytes int64
	Rows                 map[string]int64
}

// storageTables are the tables whose rows Storage counts: statistics, probes,
// sightings, events and diagnostic runs.
var storageTables = []string{
	"stats_proxy_1m", "stats_proxy_1h", "stats_proxy_1d",
	"stats_node_1m", "stats_node_1h", "stats_node_1d",
	"stats_country_1m", "stats_country_1h", "stats_country_1d",
	"egress_health_1m", "egress_health", "stats_batches",
	"probes", "ip_sightings", "events", "diagnostic_runs", "diagnostic_results",
}

// Storage reports the size of the database and the rows of its growing tables.
func (db *DB) Storage(ctx context.Context) (StorageInfo, error) {
	var pages, size, free int64
	for _, p := range []struct {
		pragma string
		dst    *int64
	}{{"page_count", &pages}, {"page_size", &size}, {"freelist_count", &free}} {
		if err := db.sql.QueryRowContext(ctx, "PRAGMA "+p.pragma).Scan(p.dst); err != nil {
			return StorageInfo{}, fmt.Errorf("store: storage: %s: %w", p.pragma, err)
		}
	}
	info := StorageInfo{FileBytes: pages * size, FreeBytes: free * size, Rows: make(map[string]int64, len(storageTables))}
	for _, t := range storageTables {
		var n int64
		if err := db.sql.QueryRowContext(ctx, "SELECT count(*) FROM "+t).Scan(&n); err != nil {
			return StorageInfo{}, fmt.Errorf("store: storage: %s: %w", t, err)
		}
		info.Rows[t] = n
	}
	return info, nil
}
