package store

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// mustEgress creates an egress of every node with a name and a kind.
func mustEgress(t *testing.T, db *DB, name, kind string) *Egress {
	t.Helper()
	e := &Egress{Name: name, Kind: kind}
	if err := db.CreateEgress(context.Background(), e); err != nil {
		t.Fatalf("CreateEgress(%s): %v", name, err)
	}
	return e
}

// mustChain creates a chain of the members, of every node when nodeID is empty.
func mustChain(t *testing.T, db *DB, name, nodeID string, members ...string) *EgressChain {
	t.Helper()
	c := &EgressChain{Name: name, NodeID: nodeID, Members: members}
	if err := db.CreateChain(context.Background(), c); err != nil {
		t.Fatalf("CreateChain(%s): %v", name, err)
	}
	return c
}

func TestEgressRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "node")
	want := &Egress{
		Name:         "socks out",
		Kind:         EgressKindSOCKS5,
		NodeID:       n.ID,
		ParamsEnc:    []byte("sealed-params"),
		RefreshNonce: 7,
		CreatedAt:    testNow,
		UpdatedAt:    testNow.Add(time.Minute),
	}
	if err := db.CreateEgress(ctx, want); err != nil {
		t.Fatalf("CreateEgress: %v", err)
	}
	if want.ID == "" {
		t.Fatal("CreateEgress gave the egress no id")
	}
	got, err := db.EgressByID(ctx, want.ID)
	if err != nil {
		t.Fatalf("EgressByID: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EgressByID = %+v\nwant %+v", got, want)
	}

	// The defaults: a creation time, the same time of the last update, no
	// parameters, no node.
	db.now = fixedClock(testNow.Add(time.Hour))
	bare := &Egress{Name: "warp", Kind: EgressKindWARP}
	if err := db.CreateEgress(ctx, bare); err != nil {
		t.Fatalf("CreateEgress: %v", err)
	}
	got, err = db.EgressByID(ctx, bare.ID)
	if err != nil {
		t.Fatalf("EgressByID: %v", err)
	}
	if !got.CreatedAt.Equal(testNow.Add(time.Hour)) || !got.UpdatedAt.Equal(got.CreatedAt) || got.ParamsEnc != nil || got.NodeID != "" {
		t.Errorf("egress with defaults = %+v", got)
	}
	if !reflect.DeepEqual(got, bare) {
		t.Errorf("the record = %+v, the stored one %+v", bare, got)
	}
}

func TestEgressErrors(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.EgressByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("EgressByID of an unknown id = %v, want ErrNotFound", err)
	}
	if err := db.CreateEgress(ctx, &Egress{Name: "x", Kind: EgressKindDirect, NodeID: "no-such-node"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("CreateEgress of an unknown node = %v, want ErrNotFound", err)
	}
	e := mustEgress(t, db, "a", EgressKindDirect)
	if err := db.CreateEgress(ctx, &Egress{ID: e.ID, Name: "b", Kind: EgressKindDirect}); !errors.Is(err, ErrConflict) {
		t.Errorf("CreateEgress of a taken id = %v, want ErrConflict", err)
	}
	if err := db.UpdateEgress(ctx, &Egress{ID: "nope", Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateEgress of an unknown id = %v, want ErrNotFound", err)
	}
	if err := db.DeleteEgress(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteEgress of an unknown id = %v, want ErrNotFound", err)
	}
}

func TestListEgresses(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if got, err := db.ListEgresses(ctx); err != nil || got != nil {
		t.Fatalf("ListEgresses of none = %v, %v; want nil", got, err)
	}
	db.now = fixedClock(testNow.Add(2 * time.Minute))
	b := mustEgress(t, db, "b", EgressKindHTTP)
	db.now = fixedClock(testNow)
	a := mustEgress(t, db, "a", EgressKindDirect)
	got, err := db.ListEgresses(ctx)
	if err != nil {
		t.Fatalf("ListEgresses: %v", err)
	}
	if len(got) != 2 || got[0].ID != a.ID || got[1].ID != b.ID {
		t.Errorf("ListEgresses = %v, want a then b (by creation)", got)
	}
}

func TestUpdateEgress(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "node")
	e := &Egress{Name: "sub", Kind: EgressKindXraySubscription, NodeID: n.ID, ParamsEnc: []byte("v1"), CreatedAt: testNow}
	if err := db.CreateEgress(ctx, e); err != nil {
		t.Fatal(err)
	}
	db.now = fixedClock(testNow.Add(time.Hour))
	change := *e
	change.Name, change.ParamsEnc, change.RefreshNonce = "subscription", []byte("v2"), 3
	// The kind and the node of an egress stay what they are.
	change.Kind, change.NodeID = EgressKindDirect, ""
	if err := db.UpdateEgress(ctx, &change); err != nil {
		t.Fatalf("UpdateEgress: %v", err)
	}
	if !change.UpdatedAt.Equal(testNow.Add(time.Hour)) {
		t.Errorf("UpdatedAt of the record = %v, want the time of the update", change.UpdatedAt)
	}
	got, err := db.EgressByID(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := *e
	want.Name, want.ParamsEnc, want.RefreshNonce, want.UpdatedAt = "subscription", []byte("v2"), 3, testNow.Add(time.Hour)
	if !reflect.DeepEqual(got, &want) {
		t.Errorf("after the update = %+v\nwant %+v", got, &want)
	}
}

func TestEgressInUseCannotBeDeleted(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	used := mustEgress(t, db, "used", EgressKindSOCKS5)
	other := mustEgress(t, db, "other", EgressKindDirect)
	c := mustChain(t, db, "chain", "", other.ID, used.ID)

	if err := db.DeleteEgress(ctx, used.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("DeleteEgress of a member of a chain = %v, want ErrConflict", err)
	}
	if _, err := db.EgressByID(ctx, used.ID); err != nil {
		t.Fatalf("the egress is gone after a refused delete: %v", err)
	}
	c.Members = []string{other.ID}
	if err := db.UpdateChain(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteEgress(ctx, used.ID); err != nil {
		t.Fatalf("DeleteEgress of an egress that no chain has: %v", err)
	}
	if _, err := db.EgressByID(ctx, used.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("EgressByID after the delete = %v, want ErrNotFound", err)
	}
}

func TestChainRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "node")
	a := mustEgress(t, db, "a", EgressKindDirect)
	b := mustEgress(t, db, "b", EgressKindHTTP)
	want := &EgressChain{
		Name:    "main",
		NodeID:  n.ID,
		Members: []string{b.ID, a.ID}, // the order is kept
		Check: ChainCheck{
			IntervalSeconds: 5, TimeoutSeconds: 3, FailThreshold: 2, RecoverThreshold: 1,
			DCAddrs: []string{"149.154.167.51:443"},
		},
		CreatedAt: testNow,
		UpdatedAt: testNow.Add(time.Minute),
	}
	if err := db.CreateChain(ctx, want); err != nil {
		t.Fatalf("CreateChain: %v", err)
	}
	got, err := db.ChainByID(ctx, want.ID)
	if err != nil {
		t.Fatalf("ChainByID: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ChainByID = %+v\nwant %+v", got, want)
	}

	// A chain without members or a check has none of either.
	bare := mustChain(t, db, "bare", "")
	if got, err = db.ChainByID(ctx, bare.ID); err != nil || got.Members != nil || !reflect.DeepEqual(got.Check, ChainCheck{}) || got.NodeID != "" {
		t.Errorf("bare chain = %+v, %v", got, err)
	}

	list, err := db.ListChains(ctx)
	if err != nil || len(list) != 2 || list[0].ID != want.ID || list[1].ID != bare.ID {
		t.Errorf("ListChains = %v, %v; want main then bare", list, err)
	}

	db.now = fixedClock(testNow.Add(time.Hour))
	want.Name, want.Members, want.Check = "renamed", []string{a.ID}, ChainCheck{IntervalSeconds: 9}
	if err := db.UpdateChain(ctx, want); err != nil {
		t.Fatalf("UpdateChain: %v", err)
	}
	if got, err = db.ChainByID(ctx, want.ID); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("after the update = %+v, %v\nwant %+v", got, err, want)
	}
	if !want.UpdatedAt.Equal(testNow.Add(time.Hour)) {
		t.Errorf("UpdatedAt = %v, want the time of the update", want.UpdatedAt)
	}

	if _, err := db.ChainByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ChainByID of an unknown id = %v, want ErrNotFound", err)
	}
	if err := db.UpdateChain(ctx, &EgressChain{ID: "nope", Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateChain of an unknown id = %v, want ErrNotFound", err)
	}
	if err := db.CreateChain(ctx, &EgressChain{Name: "x", NodeID: "no-such-node"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("CreateChain of an unknown node = %v, want ErrNotFound", err)
	}
}

// A chain that a node has as its default, or that a proxy uses as its chain or
// for a scope, cannot be deleted; one that nothing uses can.
func TestChainInUseCannotBeDeleted(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		use  func(t *testing.T, db *DB, node *Node, l *Listener, chainID string) func()
	}{
		{"the default chain of a node", func(t *testing.T, db *DB, node *Node, _ *Listener, chainID string) func() {
			node.DefaultChainID = chainID
			if err := db.UpdateNode(ctx, node); err != nil {
				t.Fatal(err)
			}
			return func() {
				node.DefaultChainID = ""
				if err := db.UpdateNode(ctx, node); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"the chain of a proxy", func(t *testing.T, db *DB, node *Node, l *Listener, chainID string) func() {
			p := mustProxy(t, db, node.ID, l.ID, "p")
			p.EgressChainID = chainID
			if err := db.UpdateProxy(ctx, p); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := db.DeleteProxy(ctx, p.ID); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"a scope chain of a proxy", func(t *testing.T, db *DB, node *Node, l *Listener, chainID string) func() {
			p := mustProxy(t, db, node.ID, l.ID, "p")
			p.EgressScopeChains = map[string]string{"fetch": "other", "me": chainID}
			if err := db.UpdateProxy(ctx, p); err != nil {
				t.Fatal(err)
			}
			return func() {
				p.EgressScopeChains = map[string]string{"fetch": "other"}
				if err := db.UpdateProxy(ctx, p); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			node := mustNode(t, db, "node")
			l := mustListener(t, db, node.ID, 443)
			c := mustChain(t, db, "chain", "")
			release := tc.use(t, db, node, l, c.ID)
			if err := db.DeleteChain(ctx, c.ID); !errors.Is(err, ErrConflict) {
				t.Fatalf("DeleteChain of a chain in use = %v, want ErrConflict", err)
			}
			if _, err := db.ChainByID(ctx, c.ID); err != nil {
				t.Fatalf("the chain is gone after a refused delete: %v", err)
			}
			release()
			if err := db.DeleteChain(ctx, c.ID); err != nil {
				t.Fatalf("DeleteChain of a chain that nothing uses: %v", err)
			}
			if err := db.DeleteChain(ctx, c.ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("DeleteChain again = %v, want ErrNotFound", err)
			}
		})
	}
}

// The egresses and chains of a node go with it.
func TestEgressesGoWithTheirNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "node")
	e := &Egress{Name: "own", Kind: EgressKindDirect, NodeID: n.ID}
	if err := db.CreateEgress(ctx, e); err != nil {
		t.Fatal(err)
	}
	c := mustChain(t, db, "own", n.ID, e.ID)
	global := mustEgress(t, db, "global", EgressKindDirect)
	if err := db.DeleteNode(ctx, n.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, err := db.EgressByID(ctx, e.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the egress of a deleted node: %v, want ErrNotFound", err)
	}
	if _, err := db.ChainByID(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the chain of a deleted node: %v, want ErrNotFound", err)
	}
	if _, err := db.EgressByID(ctx, global.ID); err != nil {
		t.Errorf("an egress of every node went with the node: %v", err)
	}
}

// A node whose default chain is a chain of its own, which its proxies use as
// well, is deleted with the chain and its egresses: what refers to the chain
// goes in the same delete.
func TestDeleteNodeWhoseDefaultChainIsItsOwn(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "node")
	e := &Egress{Name: "own", Kind: EgressKindDirect, NodeID: n.ID}
	if err := db.CreateEgress(ctx, e); err != nil {
		t.Fatal(err)
	}
	c := mustChain(t, db, "own", n.ID, e.ID)
	n.DefaultChainID = c.ID
	if err := db.UpdateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	l := mustListener(t, db, n.ID, 443)
	p := mustProxy(t, db, n.ID, l.ID, "p")
	p.EgressChainID, p.EgressScopeChains = c.ID, map[string]string{"me": c.ID}
	if err := db.UpdateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteNode(ctx, n.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, err := db.ChainByID(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the chain of the deleted node: %v, want ErrNotFound", err)
	}
	if _, err := db.EgressByID(ctx, e.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the egress of the deleted node: %v, want ErrNotFound", err)
	}
	if _, err := db.ProxyByID(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the proxy of the deleted node: %v, want ErrNotFound", err)
	}
}

func TestNodeDNSMode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := &Node{Name: "dns", DNSMode: "system"}
	if err := db.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	got, err := db.NodeByID(ctx, n.ID)
	if err != nil || got.DNSMode != "system" {
		t.Fatalf("DNSMode after CreateNode = %q, %v; want system", got.DNSMode, err)
	}
	got, err = db.ModifyNode(ctx, n.ID, func(n *Node) error { n.DNSMode = "doh"; return nil })
	if err != nil || got.DNSMode != "doh" {
		t.Fatalf("ModifyNode = %q, %v; want doh", got.DNSMode, err)
	}
	if got, err = db.NodeByID(ctx, n.ID); err != nil || got.DNSMode != "doh" {
		t.Errorf("DNSMode after ModifyNode = %q, %v; want doh", got.DNSMode, err)
	}
}

// A database of the second version keeps its nodes, egresses and chains when it
// is migrated: the nodes have the default DNS mode, the egresses no refresh,
// the chains the time 0.
func TestEgressMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	files := map[string]string{}
	for _, name := range []string{"0001_init.sql", "0002_node_errors.sql"} {
		body, err := fs.ReadFile(embeddedMigrations(), name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(body)
	}
	old := mustOpenFS(t, path, files, time.Now)
	mustExec(t, old, `INSERT INTO nodes (id, name, created_at, updated_at) VALUES ('N1', 'before', 1, 1)`)
	mustExec(t, old, `INSERT INTO egresses (id, name, kind, params_enc, created_at, updated_at) VALUES ('E1', 'e', 'socks5', x'01', 1, 1)`)
	mustExec(t, old, `INSERT INTO egress_chains (id, name, members) VALUES ('C1', 'c', '["E1"]')`)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if n, err := db.NodeByID(ctx, "N1"); err != nil || n.DNSMode != "" || n.Name != "before" {
		t.Errorf("node after the migration = %+v, %v", n, err)
	}
	if e, err := db.EgressByID(ctx, "E1"); err != nil || e.RefreshNonce != 0 || string(e.ParamsEnc) != "\x01" {
		t.Errorf("egress after the migration = %+v, %v", e, err)
	}
	if c, err := db.ChainByID(ctx, "C1"); err != nil || !reflect.DeepEqual(c.Members, []string{"E1"}) || !c.CreatedAt.Equal(time.Unix(0, 0)) {
		t.Errorf("chain after the migration = %+v, %v", c, err)
	}
}
