package nodes

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

type notified struct {
	mu  sync.Mutex
	ids []string
}

func (n *notified) Notify(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ids = append(n.ids, id)
}

// stateWriter is proxies.Service.WriteVersions, without the lock.
type stateWriter struct {
	db    *store.DB
	n     *notified
	calls int
}

func (w *stateWriter) WriteVersions(ctx context.Context, write func(ctx context.Context) ([]string, error)) error {
	w.calls++
	ids, err := write(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := w.db.NextNodeGeneration(ctx, id); err != nil {
			return err
		}
		w.n.Notify(id)
	}
	return nil
}

// RollEdge raises the edge roll nonce and the generation of the node, and
// notifies it, through the state writer when there is one; nothing else of
// the node changes.
func TestRollEdge(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, withWriter := range []bool{false, true} {
		n := &store.Node{Name: "n", MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: "203.0.113.10", EngineChannel: "stable"}
		if withWriter {
			n.Name = "w"
		}
		if err := db.CreateNode(ctx, n); err != nil {
			t.Fatal(err)
		}
		notes := &notified{}
		s := NewService(db, seal.Key{}, nil, notes, nil)
		w := &stateWriter{db: db, n: notes}
		if withWriter {
			s.SetStateWriter(w)
		}
		before, _ := db.NodeByID(ctx, n.ID)
		gen, err := s.RollEdge(ctx, n.ID)
		if err != nil {
			t.Fatalf("RollEdge: %v", err)
		}
		after, _ := db.NodeByID(ctx, n.ID)
		if after.EdgeRollNonce != before.EdgeRollNonce+1 || gen != before.DesiredGeneration+1 || after.DesiredGeneration != gen {
			t.Errorf("writer %v: nonce %d → %d, generation %d → %d (returned %d)", withWriter, before.EdgeRollNonce, after.EdgeRollNonce,
				before.DesiredGeneration, after.DesiredGeneration, gen)
		}
		if !slices.Equal(notes.ids, []string{n.ID}) || (withWriter && w.calls != 1) {
			t.Errorf("writer %v: notified %v, writer calls %d", withWriter, notes.ids, w.calls)
		}
		if after.EngineChannel != before.EngineChannel || after.AgentVersion != before.AgentVersion {
			t.Error("RollEdge changed more than the nonce")
		}
		_, err = s.RollEdge(ctx, "01K6Y00000000000000000000Z")
		var ce *connect.Error
		if !errors.As(err, &ce) || ce.Code() != connect.CodeNotFound {
			t.Errorf("an unknown node: %v", err)
		}
	}
}
