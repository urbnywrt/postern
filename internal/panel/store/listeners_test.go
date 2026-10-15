package store

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

// mustListener creates a TLS listener on a port.
func mustListener(t *testing.T, db *DB, nodeID string, port uint32) *Listener {
	t.Helper()
	l := &Listener{NodeID: nodeID, Port: port}
	if err := db.CreateListener(context.Background(), l); err != nil {
		t.Fatalf("CreateListener(%d): %v", port, err)
	}
	return l
}

func fullListener(nodeID string) *Listener {
	return &Listener{
		NodeID:           nodeID,
		Kind:             ListenerKindHTTPUpstream,
		BindIP:           "127.0.0.1",
		Port:             40443,
		LinkHostOverride: "edge.example.com",
		StrangerAction:   StrangerReject,
		MaskTarget:       "mask.example.com:443",
		NonTLSAction:     NonTLSHTTP400,
		TrustedCIDRs:     []string{"127.0.0.1/32", "198.51.100.0/24"},
		CreatedAt:        testNow,
		UpdatedAt:        testNow.Add(time.Minute),
	}
}

func TestListenerRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	l := fullListener(node.ID)
	if err := db.CreateListener(ctx, l); err != nil {
		t.Fatalf("CreateListener: %v", err)
	}
	if len(l.ID) != 26 {
		t.Fatalf("ID = %q, want a ULID", l.ID)
	}
	got, err := db.ListenerByID(ctx, l.ID)
	if err != nil {
		t.Fatalf("ListenerByID: %v", err)
	}
	if !reflect.DeepEqual(got, l) {
		t.Errorf("listener = %+v\nwant       %+v", got, l)
	}
}

func TestListenerDefaults(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)
	node := mustNode(t, db, "n")
	l := &Listener{NodeID: node.ID, BindIP: "0.0.0.0", Port: 443}
	if err := db.CreateListener(ctx, l); err != nil {
		t.Fatal(err)
	}
	want := &Listener{
		ID: l.ID, NodeID: node.ID, Kind: ListenerKindTLS, BindIP: "0.0.0.0", Port: 443,
		StrangerAction: StrangerMask, NonTLSAction: NonTLSDrop,
		CreatedAt: testNow, UpdatedAt: testNow,
	}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("record after Create = %+v, want %+v", l, want)
	}
	got, err := db.ListenerByID(ctx, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored listener = %+v, want %+v", got, want)
	}
	if got.TrustedCIDRs != nil {
		t.Errorf("TrustedCIDRs = %v, want nil", got.TrustedCIDRs)
	}
}

func TestListenerErrors(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")

	if err := db.CreateListener(ctx, &Listener{NodeID: "no-such-node", Port: 443}); !errors.Is(err, ErrNotFound) {
		t.Errorf("CreateListener on an unknown node: err = %v, want ErrNotFound", err)
	}
	if err := db.CreateListener(ctx, &Listener{NodeID: node.ID, Port: 0}); err == nil {
		t.Error("CreateListener accepted port 0")
	}
	if err := db.CreateListener(ctx, &Listener{NodeID: node.ID, Port: 65536}); err == nil {
		t.Error("CreateListener accepted port 65536")
	}
	if _, err := db.ListenerByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ListenerByID err = %v, want ErrNotFound", err)
	}
	if err := db.UpdateListener(ctx, &Listener{ID: "nope", NodeID: node.ID, Port: 443}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateListener err = %v, want ErrNotFound", err)
	}
	if err := db.DeleteListener(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteListener err = %v, want ErrNotFound", err)
	}
}

func TestListListeners(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	a := mustNode(t, db, "a")
	b := mustNode(t, db, "b")
	var wantA []string
	for i, port := range []uint32{8443, 443, 2053} {
		l := &Listener{NodeID: a.ID, Port: port, CreatedAt: testNow.Add(time.Duration(i) * time.Second)}
		if err := db.CreateListener(ctx, l); err != nil {
			t.Fatal(err)
		}
		wantA = append(wantA, l.ID)
	}
	lb := mustListener(t, db, b.ID, 443)

	ids := func(ls []*Listener) []string {
		var out []string
		for _, l := range ls {
			out = append(out, l.ID)
		}
		return out
	}
	got, err := db.ListListeners(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids(got), wantA) {
		t.Errorf("listeners of a = %v, want %v (by creation)", ids(got), wantA)
	}
	got, err = db.ListListeners(ctx, b.ID)
	if err != nil || !slices.Equal(ids(got), []string{lb.ID}) {
		t.Errorf("listeners of b = %v, %v; want [%s]", ids(got), err, lb.ID)
	}
	got, err = db.ListListeners(ctx, "")
	if err != nil || len(got) != 4 {
		t.Errorf("listeners of every node = %d, %v; want 4", len(got), err)
	}
	got, err = db.ListListeners(ctx, "no-such-node")
	if err != nil || len(got) != 0 {
		t.Errorf("listeners of an unknown node = %v, %v; want none", got, err)
	}
}

func TestUpdateListener(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	other := mustNode(t, db, "other")
	l := fullListener(node.ID)
	if err := db.CreateListener(ctx, l); err != nil {
		t.Fatal(err)
	}
	untouched := mustListener(t, db, node.ID, 8443)

	db.now = fixedClock(testNow.Add(time.Hour))
	l.Kind = ListenerKindTLS
	l.BindIP = "203.0.113.5"
	l.Port = 443
	l.LinkHostOverride = ""
	l.StrangerAction = StrangerDrop
	l.MaskTarget = ""
	l.NonTLSAction = NonTLSDrop
	l.TrustedCIDRs = nil
	if err := db.UpdateListener(ctx, l); err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	if !l.UpdatedAt.Equal(testNow.Add(time.Hour)) {
		t.Errorf("UpdatedAt = %v, want the time of the update", l.UpdatedAt)
	}
	got, err := db.ListenerByID(ctx, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, l) {
		t.Errorf("after update = %+v\nwant         %+v", got, l)
	}
	if !got.CreatedAt.Equal(testNow) {
		t.Errorf("CreatedAt changed to %v", got.CreatedAt)
	}
	if u, _ := db.ListenerByID(ctx, untouched.ID); !reflect.DeepEqual(u, untouched) {
		t.Errorf("another listener changed: %+v", u)
	}

	// A listener belongs to one node for good, and is found by id and node
	// together: the id of a listener of another node changes nothing.
	moved := *got
	moved.NodeID = other.ID
	moved.Port = 2053
	if err := db.UpdateListener(ctx, &moved); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateListener with the wrong node: err = %v, want ErrNotFound", err)
	}
	if after, _ := db.ListenerByID(ctx, l.ID); !reflect.DeepEqual(after, got) {
		t.Errorf("a listener was changed through the wrong node: %+v", after)
	}
}

func TestDeleteListener(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	gone := mustListener(t, db, node.ID, 443)
	keep := mustListener(t, db, node.ID, 8443)
	if err := db.DeleteListener(ctx, gone.ID); err != nil {
		t.Fatalf("DeleteListener: %v", err)
	}
	if _, err := db.ListenerByID(ctx, gone.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted listener is still there: %v", err)
	}
	if _, err := db.ListenerByID(ctx, keep.ID); err != nil {
		t.Errorf("another listener was deleted: %v", err)
	}
}

func TestListenerInUseCannotBeDeleted(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	p := &Proxy{NodeID: node.ID, ListenerID: l.ID, Name: "p", SecretEnc: []byte("sealed")}
	if err := db.CreateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteListener(ctx, l.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("DeleteListener err = %v, want ErrConflict", err)
	}
	if _, err := db.ListenerByID(ctx, l.ID); err != nil {
		t.Errorf("the listener is gone although the delete failed: %v", err)
	}
	// Once the proxy is gone, so can the listener be.
	if err := db.DeleteProxy(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteListener(ctx, l.ID); err != nil {
		t.Errorf("DeleteListener after the proxy was deleted: %v", err)
	}
}
