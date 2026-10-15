package store

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

// mustNode creates a node that has nothing but a name.
func mustNode(t *testing.T, db *DB, name string) *Node {
	t.Helper()
	n := &Node{Name: name}
	if err := db.CreateNode(context.Background(), n); err != nil {
		t.Fatalf("CreateNode(%s): %v", name, err)
	}
	return n
}

// mustExec runs a statement that has to work.
func mustExec(t *testing.T, db *DB, query string, args ...any) {
	t.Helper()
	if _, err := db.sql.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// insertChain adds an egress chain with SQL: a chain with an id of the test and
// no members. An empty nodeID makes the chain global.
func insertChain(t *testing.T, db *DB, id, nodeID string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO egress_chains (id, name, node_id) VALUES (?, ?, ?)`, id, "chain "+id, nullString(nodeID))
}

// fullNode is a node with every field set to a value of its own, so that a
// column that is read or written in the wrong place shows.
func fullNode() *Node {
	seen := testNow.Add(time.Minute)
	return &Node{
		Name:              "node-1",
		MgmtHost:          "node-1.example.com",
		MgmtPort:          8443,
		MgmtMode:          MgmtModeHidden,
		MgmtSNI:           "cdn.example.com",
		MgmtPublicPort:    443,
		LinkHost:          "proxy.example.com",
		CertFingerprint:   "0a1b2c",
		CertPEM:           "fake-certificate-pem",
		KeyEnc:            []byte("sealed-private-key"),
		DesiredGeneration: 7,
		AppliedGeneration: 5,
		WatchCursor:       99,
		AgentVersion:      "0.1.0",
		EdgeVersion:       "0.1.1",
		Arch:              "arm64",
		HostInfo:          HostInfo{OS: "Debian GNU/Linux 12"},
		DNSMode:           "system",
		PublicIPs:         []string{"192.0.2.10", "2001:db8::10"},
		Status:            NodeStatusOnline,
		LastSeenAt:        &seen,
		Note:              "primary",
		LastError:         "edge g1 does not answer",
		StateRejection:    `invalid node state: listener "l1": port 70000 is outside 1-65535`,
		PanelAddrs:        []string{"203.0.113.9", "2001:db8::9"},
		EdgeRollNonce:     4,
		EngineChannel:     ChannelLatest,
		ProviderVersions:  map[string]string{"xray": "v26.3.27", "warp-plus": "v1.2.6"},
		CreatedAt:         testNow,
		UpdatedAt:         testNow.Add(2 * time.Minute),
	}
}

func TestSetNodeProviderVersion(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)
	n := mustNode(t, db, "n1")
	later := testNow.Add(time.Minute)
	db.now = fixedClock(later)

	versions := func() map[string]string {
		t.Helper()
		got, err := db.NodeByID(ctx, n.ID)
		if err != nil {
			t.Fatalf("NodeByID: %v", err)
		}
		if got.UpdatedAt != later {
			t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, later)
		}
		return got.ProviderVersions
	}
	set := func(component, version string) {
		t.Helper()
		if err := db.SetNodeProviderVersion(ctx, n.ID, component, version); err != nil {
			t.Fatalf("SetNodeProviderVersion(%s, %q): %v", component, version, err)
		}
	}

	set("xray", "v26.3.27")
	if got, want := versions(), map[string]string{"xray": "v26.3.27"}; !reflect.DeepEqual(got, want) {
		t.Errorf("versions = %v, want %v", got, want)
	}
	set("warp-plus", "v1.2.6")
	set("xray", "v26.4.0")
	if got, want := versions(), map[string]string{"xray": "v26.4.0", "warp-plus": "v1.2.6"}; !reflect.DeepEqual(got, want) {
		t.Errorf("versions = %v, want %v", got, want)
	}
	set("xray", "")
	if got, want := versions(), map[string]string{"warp-plus": "v1.2.6"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after removing xray: versions = %v, want %v", got, want)
	}
	set("warp-plus", "")
	if got := versions(); got != nil {
		t.Errorf("after removing everything: versions = %v, want none", got)
	}
	set("xray", "")
	if got := versions(); got != nil {
		t.Errorf("after removing what is not there: versions = %v, want none", got)
	}

	if err := db.SetNodeProviderVersion(ctx, n.ID, "", "v1"); err == nil {
		t.Error("SetNodeProviderVersion without a component succeeded")
	}
	if err := db.SetNodeProviderVersion(ctx, "01NOPE", "xray", "v1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetNodeProviderVersion of an unknown node: err = %v, want ErrNotFound", err)
	}
	if n := count(t, db, `SELECT count(*) FROM nodes`); n != 1 {
		t.Errorf("%d nodes, want 1", n)
	}
}

// A database of the first version keeps its nodes when it is migrated, and they
// have no errors.
func TestNodeErrorsMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	first, err := fs.ReadFile(embeddedMigrations(), "0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := mustOpenFS(t, path, map[string]string{"0001_init.sql": string(first)}, time.Now)
	n := &Node{ID: "01K6Y0000000000000000000N1", Name: "before the migration"}
	mustExec(t, old, `INSERT INTO nodes (id, name, agent_version, created_at, updated_at) VALUES (?, ?, '0.1.0', 1, 1)`, n.ID, n.Name)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	got, err := db.NodeByID(context.Background(), n.ID)
	if err != nil {
		t.Fatalf("NodeByID after the migration: %v", err)
	}
	if got.Name != n.Name || got.AgentVersion != "0.1.0" || got.LastError != "" || got.StateRejection != "" {
		t.Errorf("node after the migration = %+v", got)
	}
	got.LastError, got.StateRejection = "e", "r"
	if err := db.UpdateNode(context.Background(), got); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if again, err := db.NodeByID(context.Background(), n.ID); err != nil || again.LastError != "e" || again.StateRejection != "r" {
		t.Errorf("node after an update = %+v, %v", again, err)
	}
}

func TestNodeRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := fullNode()
	if err := db.CreateNode(ctx, n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if len(n.ID) != 26 {
		t.Fatalf("ID = %q, want a ULID", n.ID)
	}
	got, err := db.NodeByID(ctx, n.ID)
	if err != nil {
		t.Fatalf("NodeByID: %v", err)
	}
	if !reflect.DeepEqual(got, n) {
		t.Errorf("node = %+v\nwant   %+v", got, n)
	}
}

func TestNodeDefaults(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)
	n := &Node{Name: "n"}
	if err := db.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	want := &Node{
		ID: n.ID, Name: "n", MgmtMode: MgmtModePort, Status: NodeStatusProvisioning,
		CreatedAt: testNow, UpdatedAt: testNow,
	}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("record after Create = %+v, want %+v", n, want)
	}
	got, err := db.NodeByID(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored node = %+v, want %+v", got, want)
	}
	if got.KeyEnc != nil || got.LastSeenAt != nil || got.PublicIPs != nil {
		t.Errorf("unset fields came back set: %+v", got)
	}
}

func TestNodeKeepsGivenID(t *testing.T) {
	db := newTestDB(t)
	n := &Node{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Name: "n"}
	if err := db.CreateNode(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if n.ID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("ID = %q, want the one that was given", n.ID)
	}
	if err := db.CreateNode(context.Background(), &Node{ID: n.ID, Name: "again"}); !errors.Is(err, ErrConflict) {
		t.Errorf("a second node with the same ID: err = %v, want ErrConflict", err)
	}
}

func TestNodeNotFound(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.NodeByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("NodeByID err = %v, want ErrNotFound", err)
	}
	if err := db.UpdateNode(ctx, &Node{ID: "nope", Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateNode err = %v, want ErrNotFound", err)
	}
	if err := db.DeleteNode(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteNode err = %v, want ErrNotFound", err)
	}
	if _, err := db.NextNodeGeneration(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("NextNodeGeneration err = %v, want ErrNotFound", err)
	}
	if _, err := db.ModifyNode(ctx, "nope", func(*Node) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("ModifyNode err = %v, want ErrNotFound", err)
	}
}

func TestListNodes(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if got, err := db.ListNodes(ctx); err != nil || len(got) != 0 {
		t.Fatalf("ListNodes of an empty database = %v, %v", got, err)
	}
	// Listed by creation time, whatever the names or ids are.
	var want []string
	for i, name := range []string{"charlie", "alpha", "bravo"} {
		n := &Node{Name: name, CreatedAt: testNow.Add(time.Duration(i) * time.Second)}
		if err := db.CreateNode(ctx, n); err != nil {
			t.Fatal(err)
		}
		want = append(want, n.ID)
	}
	got, err := db.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, n := range got {
		ids = append(ids, n.ID)
	}
	if !slices.Equal(ids, want) {
		t.Errorf("ListNodes order = %v, want %v", ids, want)
	}
}

func TestUpdateNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := fullNode()
	if err := db.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	other := mustNode(t, db, "other")

	db.now = fixedClock(testNow.Add(time.Hour))
	n.Name = "renamed"
	n.MgmtHost = "node-2.example.com"
	n.MgmtPort = 9443
	n.MgmtMode = MgmtModePort
	n.MgmtSNI = ""
	n.LinkHost = "link.example.com"
	n.CertFingerprint = "ffee"
	n.CertPEM = "other-pem"
	n.KeyEnc = nil
	n.AppliedGeneration = 6
	n.WatchCursor = 100
	n.AgentVersion = "0.2.0"
	n.EdgeVersion = "0.2.1"
	n.Arch = "amd64"
	n.HostInfo = HostInfo{OS: "Alpine"}
	n.PublicIPs = nil
	n.Status = NodeStatusOffline
	n.LastSeenAt = nil
	n.Note = ""
	n.PanelAddrs = []string{"192.0.2.9"}
	n.EdgeRollNonce = 5
	if err := db.UpdateNode(ctx, n); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if !n.UpdatedAt.Equal(testNow.Add(time.Hour)) {
		t.Errorf("UpdatedAt = %v, want the time of the update", n.UpdatedAt)
	}
	got, err := db.NodeByID(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, n) {
		t.Errorf("after update = %+v\nwant         %+v", got, n)
	}
	if !got.CreatedAt.Equal(testNow) {
		t.Errorf("CreatedAt changed to %v", got.CreatedAt)
	}
	if o, _ := db.NodeByID(ctx, other.ID); !reflect.DeepEqual(o, other) {
		t.Errorf("another node changed: %+v", o)
	}
}

// UpdateNode must not take the generation counter back to the value that the
// record happened to hold when it was read.
func TestUpdateNodeLeavesDesiredGenerationAlone(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n")
	stale, err := db.NodeByID(ctx, n.ID) // desired_generation 0
	if err != nil {
		t.Fatal(err)
	}
	for want := uint64(1); want <= 3; want++ {
		if got, err := db.NextNodeGeneration(ctx, n.ID); err != nil || got != want {
			t.Fatalf("NextNodeGeneration = %d, %v; want %d", got, err, want)
		}
	}
	stale.Name = "renamed from a stale record"
	if err := db.UpdateNode(ctx, stale); err != nil {
		t.Fatal(err)
	}
	got, _ := db.NodeByID(ctx, n.ID)
	if got.DesiredGeneration != 3 || got.Name != stale.Name {
		t.Errorf("desired = %d, name = %q; want 3 and the new name", got.DesiredGeneration, got.Name)
	}
}

func TestModifyNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)
	n := mustNode(t, db, "n")
	if _, err := db.NextNodeGeneration(ctx, n.ID); err != nil {
		t.Fatal(err)
	}

	db.now = fixedClock(testNow.Add(time.Minute))
	got, err := db.ModifyNode(ctx, n.ID, func(m *Node) error {
		m.AppliedGeneration = 1
		m.Status = NodeStatusOnline
		// What the function does to these is ignored.
		m.ID = "other"
		m.DesiredGeneration = 99
		return nil
	})
	if err != nil {
		t.Fatalf("ModifyNode: %v", err)
	}
	if got.ID != n.ID || got.DesiredGeneration != 1 || got.AppliedGeneration != 1 || got.Status != NodeStatusOnline {
		t.Errorf("ModifyNode returned %+v", got)
	}
	if !got.UpdatedAt.Equal(testNow.Add(time.Minute)) {
		t.Errorf("UpdatedAt = %v", got.UpdatedAt)
	}
	stored, _ := db.NodeByID(ctx, n.ID)
	if !reflect.DeepEqual(stored, got) {
		t.Errorf("stored = %+v, returned = %+v", stored, got)
	}

	// An error from the function abandons the change.
	boom := errors.New("boom")
	if _, err := db.ModifyNode(ctx, n.ID, func(m *Node) error {
		m.Name = "never stored"
		return boom
	}); !errors.Is(err, boom) {
		t.Errorf("err = %v, want the error of the function", err)
	}
	if stored, _ := db.NodeByID(ctx, n.ID); stored.Name != "n" {
		t.Errorf("name = %q after a failed ModifyNode", stored.Name)
	}
}

// Writers that read a node and write it back must not lose each other's
// changes: every ModifyNode sees the result of the one before it.
func TestModifyNodeDoesNotLoseUpdates(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n")

	const writers = 10
	var wg sync.WaitGroup
	for range writers {
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, err := db.ModifyNode(ctx, n.ID, func(m *Node) error { m.WatchCursor++; return nil }); err != nil {
				t.Errorf("ModifyNode: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := db.ModifyNode(ctx, n.ID, func(m *Node) error { m.AppliedGeneration++; return nil }); err != nil {
				t.Errorf("ModifyNode: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := db.NextNodeGeneration(ctx, n.ID); err != nil {
				t.Errorf("NextNodeGeneration: %v", err)
			}
		}()
	}
	wg.Wait()
	got, err := db.NodeByID(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WatchCursor != writers || got.AppliedGeneration != writers || got.DesiredGeneration != writers {
		t.Errorf("cursor = %d, applied = %d, desired = %d; want %d each",
			got.WatchCursor, got.AppliedGeneration, got.DesiredGeneration, writers)
	}
}

func TestNextNodeGeneration(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	a := mustNode(t, db, "a")
	b := mustNode(t, db, "b")
	for want := uint64(1); want <= 3; want++ {
		if got, err := db.NextNodeGeneration(ctx, a.ID); err != nil || got != want {
			t.Errorf("a: NextNodeGeneration = %d, %v; want %d", got, err, want)
		}
	}
	// Each node counts for itself.
	if got, err := db.NextNodeGeneration(ctx, b.ID); err != nil || got != 1 {
		t.Errorf("b: NextNodeGeneration = %d, %v; want 1", got, err)
	}
	if stored, _ := db.NodeByID(ctx, a.ID); stored.DesiredGeneration != 3 {
		t.Errorf("stored desired generation = %d, want 3", stored.DesiredGeneration)
	}
}

func TestNextNodeGenerationConcurrent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n")

	const goroutines, each = 20, 5
	results := make(chan uint64, goroutines*each)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				g, err := db.NextNodeGeneration(ctx, n.ID)
				if err != nil {
					t.Errorf("NextNodeGeneration: %v", err)
					return
				}
				results <- g
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := map[uint64]bool{}
	for g := range results {
		if seen[g] {
			t.Errorf("generation %d was handed out twice", g)
		}
		seen[g] = true
	}
	for g := uint64(1); g <= goroutines*each; g++ {
		if !seen[g] {
			t.Errorf("generation %d was never handed out", g)
		}
	}
	if stored, _ := db.NodeByID(ctx, n.ID); stored.DesiredGeneration != goroutines*each {
		t.Errorf("stored desired generation = %d, want %d", stored.DesiredGeneration, goroutines*each)
	}
}

func TestDeleteNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	keep := mustNode(t, db, "keep")
	gone := mustNode(t, db, "gone")
	if err := db.DeleteNode(ctx, gone.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, err := db.NodeByID(ctx, gone.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted node is still there: %v", err)
	}
	if _, err := db.NodeByID(ctx, keep.ID); err != nil {
		t.Errorf("another node was deleted: %v", err)
	}
	if err := db.DeleteNode(ctx, gone.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteNode: err = %v, want ErrNotFound", err)
	}
}

// seedNode gives a node one of everything that belongs to a node: a listener, a
// proxy with its statistics, statistics of its own, an egress, a chain that is
// also its default chain and the chain of its proxy, a pool domain and a
// blacklist entry. It returns the id of the proxy.
func seedNode(t *testing.T, db *DB, n *Node) string {
	t.Helper()
	ctx := context.Background()
	l := &Listener{NodeID: n.ID, Port: 443}
	if err := db.CreateListener(ctx, l); err != nil {
		t.Fatal(err)
	}
	p := &Proxy{NodeID: n.ID, ListenerID: l.ID, Name: "p", SecretEnc: []byte("sealed")}
	if err := db.CreateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, q := range proxyRowQueries {
		mustExec(t, db, q, p.ID)
	}
	for _, q := range []string{
		`INSERT INTO stats_node_1m (node_id, ts) VALUES (?1, 60)`,
		`INSERT INTO stats_node_1h (node_id, ts) VALUES (?1, 3600)`,
		`INSERT INTO stats_node_1d (node_id, ts) VALUES (?1, 86400)`,
		`INSERT INTO domain_pool (domain, node_id) VALUES ('www.example.com', ?1)`,
		`INSERT INTO blacklist (cidr, node_id) VALUES ('192.0.2.0/24', ?1)`,
		`INSERT INTO egress_health_1m (node_id, chain_id, member_key, ts, status) VALUES (?1, 'C1', 'm1', 60, 'up')`,
		`INSERT INTO egress_health (node_id, chain_id, member_key, ts) VALUES (?1, 'C1', 'm1', 0)`,
		`INSERT INTO stats_batches (node_id, minute) VALUES (?1, 60)`,
		`INSERT INTO diagnostic_runs (id, node_id, scope, reason, state, started_at) VALUES ('R' || ?1, ?1, 'node', 'manual', 'done', 1)`,
		`INSERT INTO diagnostic_results (run_id, seq, check_id, layer, checked_at) VALUES ('R' || ?1, 1, 'host.docker', 'host', 1)`,
		`INSERT INTO node_checks (node_id, check_id, since, checked_at) VALUES (?1, 'host.docker', 1, 1)`,
		`INSERT INTO node_join_tokens (node_id, token_hash, created_at, expires_at) VALUES (?1, CAST(?1 AS BLOB), 1, 2)`,
	} {
		mustExec(t, db, q, n.ID)
	}
	mustExec(t, db, `INSERT INTO egresses (id, name, kind, node_id, created_at, updated_at) VALUES (?, 'e', 'direct', ?, 0, 0)`, "E"+n.ID, n.ID)
	chain := "C" + n.ID
	insertChain(t, db, chain, n.ID)
	mustExec(t, db, `UPDATE nodes SET default_chain_id = ? WHERE id = ?`, chain, n.ID)
	mustExec(t, db, `UPDATE proxies SET egress_chain_id = ? WHERE id = ?`, chain, p.ID)
	return p.ID
}

// Deleting a node takes everything of the node with it, and nothing of another
// node.
func TestDeleteNodeCascades(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	gone := mustNode(t, db, "gone")
	keep := mustNode(t, db, "keep")
	goneProxy := seedNode(t, db, gone)
	keepProxy := seedNode(t, db, keep)
	insertChain(t, db, "GLOBAL", "") // belongs to no node

	if err := db.DeleteNode(ctx, gone.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}

	for _, table := range []string{
		"listeners", "proxies", "egresses", "egress_chains", "domain_pool", "blacklist",
		"stats_node_1m", "stats_node_1h", "stats_node_1d",
		"egress_health_1m", "egress_health", "stats_batches", "diagnostic_runs", "node_checks",
		"node_join_tokens",
	} {
		q := `SELECT count(*) FROM ` + table + ` WHERE node_id = ?`
		if n := count(t, db, q, gone.ID); n != 0 {
			t.Errorf("%s: %d rows of the deleted node are left", table, n)
		}
		if n := count(t, db, q, keep.ID); n != 1 {
			t.Errorf("%s: %d rows of the other node, want 1", table, n)
		}
	}
	q := `SELECT count(*) FROM diagnostic_results WHERE run_id = 'R' || ?`
	if n := count(t, db, q, gone.ID); n != 0 {
		t.Errorf("diagnostic_results: %d rows of a run of the deleted node are left", n)
	}
	if n := count(t, db, q, keep.ID); n != 1 {
		t.Errorf("diagnostic_results: %d rows of a run of the other node, want 1", n)
	}
	for _, table := range proxyRowTables {
		q := `SELECT count(*) FROM ` + table + ` WHERE proxy_id = ?`
		if n := count(t, db, q, goneProxy); n != 0 {
			t.Errorf("%s: %d rows of the deleted proxy are left", table, n)
		}
		if n := count(t, db, q, keepProxy); n != 1 {
			t.Errorf("%s: %d rows of the other proxy, want 1", table, n)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM egress_chains WHERE id = 'GLOBAL'`); n != 1 {
		t.Error("the global chain was deleted")
	}
}

// A chain of a node that is still used by another node keeps the node.
func TestDeleteNodeRefusedWhileItsChainIsUsedElsewhere(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	owner := mustNode(t, db, "owner")
	user := mustNode(t, db, "user")
	l := mustListener(t, db, owner.ID, 443)
	p := mustProxy(t, db, owner.ID, l.ID, "p")
	insertChain(t, db, "SHARED", owner.ID)
	mustExec(t, db, `UPDATE nodes SET default_chain_id = 'SHARED' WHERE id = ?`, user.ID)

	if err := db.DeleteNode(ctx, owner.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("DeleteNode err = %v, want ErrConflict", err)
	}
	// All or nothing: the proxies are not deleted ahead of the node.
	if _, err := db.NodeByID(ctx, owner.ID); err != nil {
		t.Errorf("the node is gone although its delete failed: %v", err)
	}
	if _, err := db.ProxyByID(ctx, p.ID); err != nil {
		t.Errorf("the proxy is gone although the delete of its node failed: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM egress_chains WHERE id = 'SHARED'`); n != 1 {
		t.Error("the chain is gone although the delete failed")
	}
}

func TestNodeDefaultChain(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	insertChain(t, db, "CHAIN1", "")

	if err := db.CreateNode(ctx, &Node{Name: "n", DefaultChainID: "no-such-chain"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("CreateNode with an unknown chain: err = %v, want ErrNotFound", err)
	}
	n := &Node{Name: "n", DefaultChainID: "CHAIN1"}
	if err := db.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	got, _ := db.NodeByID(ctx, n.ID)
	if got.DefaultChainID != "CHAIN1" {
		t.Errorf("DefaultChainID = %q, want CHAIN1", got.DefaultChainID)
	}
	// A chain that a node uses cannot be deleted.
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM egress_chains WHERE id = 'CHAIN1'`); err == nil {
		t.Error("a chain that is the default of a node was deleted")
	}
	// The node goes back to having no default chain.
	n.DefaultChainID = ""
	if err := db.UpdateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.NodeByID(ctx, n.ID); got.DefaultChainID != "" {
		t.Errorf("DefaultChainID = %q, want empty", got.DefaultChainID)
	}
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM egress_chains WHERE id = 'CHAIN1'`); err != nil {
		t.Errorf("a chain that nothing uses could not be deleted: %v", err)
	}
}

func TestNodeCountersMustFitSQLite(t *testing.T) {
	db := newTestDB(t)
	for _, n := range []*Node{{Name: "n", WatchCursor: 1 << 63}, {Name: "n", EdgeRollNonce: 1 << 63}} {
		if err := db.CreateNode(context.Background(), n); err == nil {
			t.Errorf("CreateNode accepted %+v, which does not fit in a SQLite integer", n)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM nodes`); n != 0 {
		t.Errorf("a failed CreateNode left %d rows", n)
	}
}
