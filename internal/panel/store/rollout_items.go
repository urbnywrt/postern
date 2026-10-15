package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
)

// This file holds what a rollout does to the proxies of its items: it writes
// its target into them (ApplyItems), puts them back (RevertItems), leaves some
// on their previous version (DeferItems) and settles them all when it completes
// (FinishItems). Each call is one transaction, and none of them clobbers a
// proxy that someone else changed: such an item becomes detached, and the
// rollout leaves it alone from then on.

// itemOf reads one item of a rollout, [ErrNotFound] when there is none.
func itemOf(ctx context.Context, q dbtx, rolloutID, proxyID string) (RolloutItem, error) {
	it, err := scanItem(q.QueryRowContext(ctx, `SELECT `+itemColumns+` FROM rollout_items WHERE rollout_id = ? AND proxy_id = ?`, rolloutID, proxyID))
	if err != nil {
		return RolloutItem{}, queryNotFound(err, "rollout item")
	}
	return it, nil
}

func setItemState(ctx context.Context, q dbtx, rolloutID, proxyID, state string) error {
	_, err := q.ExecContext(ctx, `UPDATE rollout_items SET state = ? WHERE rollout_id = ? AND proxy_id = ?`, state, rolloutID, proxyID)
	return err
}

// proxyEngine returns the engine, the version policy and the version of a proxy
// of a node, and whether the proxy exists.
func proxyEngine(ctx context.Context, q dbtx, proxyID, nodeID string) (held [3]string, ok bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT engine, engine_version_policy, engine_version FROM proxies WHERE id = ? AND node_id = ?`,
		proxyID, nodeID).Scan(&held[0], &held[1], &held[2])
	if errors.Is(err, sql.ErrNoRows) {
		return held, false, nil
	}
	return held, err == nil, err
}

// writeProxyEngine writes the engine, the version policy and the version of a
// proxy, and the time of the update.
func writeProxyEngine(ctx context.Context, q dbtx, proxyID, nodeID string, e [3]string, now int64) error {
	_, err := q.ExecContext(ctx,
		`UPDATE proxies SET engine = ?, engine_version_policy = ?, engine_version = ?, updated_at = ? WHERE id = ? AND node_id = ?`,
		e[0], e[1], e[2], now, proxyID, nodeID)
	return err
}

// nodeSet collects the nodes whose proxies were written, each once, sorted.
type nodeSet map[string]struct{}

func (s nodeSet) add(id string) { s[id] = struct{}{} }

func (s nodeSet) sorted() []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for id := range s {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// ApplyItems writes the target of a rollout, the engine, the version policy
// (EnginePolicyRollout) and the version, into the proxies of the items, in one
// transaction, and returns the nodes of the proxies it wrote, sorted, so that
// the caller raises their generations. The items are found by their proxy in the
// rollout; one that is not an item of it is [ErrNotFound], and nothing is
// written.
//
// An item is written only while its proxy holds what the rollout expects: what
// it held when the rollout was made (an item that is pending or reverted), or
// what the rollout last wrote (an item that is applied, written again by a
// retry or by a step whose generation was not stored). A proxy that holds
// anything else was changed by someone else, as was one that is gone, and its
// item becomes detached: the rollout leaves it alone from then on. Items that
// are deferred or detached are not touched. The states are put back into items.
func (db *DB) ApplyItems(ctx context.Context, rolloutID string, items []RolloutItem, engine, policy, version string) ([]string, error) {
	if engine == "" || policy == "" {
		return nil, errors.New("store: apply items: no engine or policy")
	}
	target := [3]string{engine, policy, version}
	nodes := nodeSet{}
	out := make([]RolloutItem, len(items))
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		now := normTime(db.now()).Unix()
		for i := range items {
			it, err := itemOf(ctx, tx, rolloutID, items[i].ProxyID)
			if err != nil {
				return err
			}
			var want [3]string
			switch it.State {
			case ItemPending, ItemReverted:
				want = it.prev()
			case ItemApplied:
				want = target
			default:
				out[i] = it
				continue
			}
			held, ok, err := proxyEngine(ctx, tx, it.ProxyID, it.NodeID)
			if err != nil {
				return err
			}
			state := ItemDetached
			if ok && held == want {
				if err := writeProxyEngine(ctx, tx, it.ProxyID, it.NodeID, target, now); err != nil {
					return err
				}
				nodes.add(it.NodeID)
				state = ItemApplied
			}
			if err := setItemState(ctx, tx, rolloutID, it.ProxyID, state); err != nil {
				return err
			}
			it.State = state
			out[i] = it
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: apply items: %w", err)
	}
	copy(items, out)
	return nodes.sorted(), nil
}

// RevertItems puts the proxies of the items that are applied back to what they
// held when the rollout was made, in one transaction, and returns the nodes of
// the proxies it wrote, sorted. A proxy that no longer has the version policy
// that the rollout writes (EnginePolicyRollout) was changed by someone else, as
// was one that is gone: its item becomes detached and the proxy is left as it is.
// Items in other states are not touched. An item that is not of the rollout is
// [ErrNotFound], and nothing is written. The states are put back into items.
func (db *DB) RevertItems(ctx context.Context, rolloutID string, items []RolloutItem) ([]string, error) {
	nodes := nodeSet{}
	out := make([]RolloutItem, len(items))
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		now := normTime(db.now()).Unix()
		for i := range items {
			it, err := itemOf(ctx, tx, rolloutID, items[i].ProxyID)
			if err != nil {
				return err
			}
			if it.State != ItemApplied {
				out[i] = it
				continue
			}
			held, ok, err := proxyEngine(ctx, tx, it.ProxyID, it.NodeID)
			if err != nil {
				return err
			}
			state := ItemDetached
			if ok && held[1] == EnginePolicyRollout {
				if err := writeProxyEngine(ctx, tx, it.ProxyID, it.NodeID, it.prev(), now); err != nil {
					return err
				}
				nodes.add(it.NodeID)
				state = ItemReverted
			}
			if err := setItemState(ctx, tx, rolloutID, it.ProxyID, state); err != nil {
				return err
			}
			it.State = state
			out[i] = it
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: revert items: %w", err)
	}
	copy(items, out)
	return nodes.sorted(), nil
}

// DeferItems marks the items of these proxies deferred: they stay on their
// previous version, and are pinned at it when the rollout completes. Only an
// item that is pending or reverted can be deferred; one in another state is left
// as it is. A proxy that is not an item of the rollout is [ErrNotFound], and
// nothing is written.
func (db *DB) DeferItems(ctx context.Context, rolloutID string, proxyIDs []string) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		for _, id := range proxyIDs {
			res, err := tx.ExecContext(ctx,
				`UPDATE rollout_items SET state = ? WHERE rollout_id = ? AND proxy_id = ? AND state IN (?, ?)`,
				ItemDeferred, rolloutID, id, ItemPending, ItemReverted)
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err != nil {
				return err
			} else if n == 0 {
				if _, err := itemOf(ctx, tx, rolloutID, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: defer items: %w", err)
	}
	return nil
}

// UndeferItems puts the items of these proxies that are deferred back to
// pending, so that a step that is applied again (a retry) takes a proxy that
// was disabled and is enabled again. Items in other states are left as they
// are. A proxy that is not an item of the rollout is [ErrNotFound], and nothing
// is written.
func (db *DB) UndeferItems(ctx context.Context, rolloutID string, proxyIDs []string) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		for _, id := range proxyIDs {
			it, err := itemOf(ctx, tx, rolloutID, id)
			if err != nil {
				return err
			}
			if it.State == ItemDeferred {
				if err := setItemState(ctx, tx, rolloutID, id, ItemPending); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: undefer items: %w", err)
	}
	return nil
}

// checkAppliedPolicy refuses a policy for the applied items of a completed
// rollout that is neither of the two it may be.
func checkAppliedPolicy(policy string) error {
	if policy != EnginePolicyChannel && policy != EnginePolicyPinned {
		return fmt.Errorf("the policy must be %s or %s, not %q", EnginePolicyChannel, EnginePolicyPinned, policy)
	}
	return nil
}

// finishItems is FinishItems inside a transaction, for the rollout r.
func finishItems(ctx context.Context, tx *sql.Tx, r *Rollout, appliedPolicy string, now int64) (nodeSet, error) {
	if appliedPolicy == EnginePolicyPinned && r.ToVersion == "" {
		return nil, errors.New("the rollout has no version to pin the applied items at")
	}
	items, err := queryItems(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	nodes := nodeSet{}
	for _, it := range items {
		var settled [3]string
		switch it.State {
		case ItemApplied:
			held, ok, err := proxyEngine(ctx, tx, it.ProxyID, it.NodeID)
			if err != nil {
				return nil, err
			}
			settled = [3]string{held[0], appliedPolicy, r.ToVersion}
			if appliedPolicy == EnginePolicyChannel {
				settled[2] = ""
			}
			if ok && held == settled {
				continue // settled already
			}
			if !ok || held[1] != EnginePolicyRollout {
				if err := setItemState(ctx, tx, r.ID, it.ProxyID, ItemDetached); err != nil {
					return nil, err
				}
				continue
			}
		case ItemDeferred:
			held, ok, err := proxyEngine(ctx, tx, it.ProxyID, it.NodeID)
			if err != nil {
				return nil, err
			}
			if !ok {
				if err := setItemState(ctx, tx, r.ID, it.ProxyID, ItemDetached); err != nil {
					return nil, err
				}
				continue
			}
			pin := it.PrevVersion
			if pin == "" {
				pin = r.FromVersion
			}
			if pin == "" {
				continue // nothing to pin at: the proxy keeps following its channel, which did not move
			}
			settled = [3]string{it.PrevEngine, EnginePolicyPinned, pin}
			if held == settled {
				continue // settled already
			}
			if held != it.prev() {
				if err := setItemState(ctx, tx, r.ID, it.ProxyID, ItemDetached); err != nil {
					return nil, err
				}
				continue
			}
		default:
			continue
		}
		if err := writeProxyEngine(ctx, tx, it.ProxyID, it.NodeID, settled, now); err != nil {
			return nil, err
		}
		nodes.add(it.NodeID)
	}
	return nodes, nil
}

// FinishItems settles the proxies of a rollout that completes, in one
// transaction, and returns the nodes of the proxies it wrote, sorted. The
// proxies of applied items get appliedPolicy, EnginePolicyChannel (they follow
// their channel, which has moved to the version, and keep no version of their
// own) or EnginePolicyPinned (they stay at the ToVersion of the rollout). The
// proxies of deferred items are pinned at the version they had: their own when
// they were pinned, else the version that the channel had, the FromVersion of
// the rollout; when neither is known the proxy is left as it is.
//
// FinishItems can run again: a proxy that holds its settled values already is
// skipped, and its item keeps its state. A proxy that was changed by someone
// else in the meantime (an applied one without the rollout's policy, a
// deferred one that no longer holds what it held) is left as it is and its
// item becomes detached. The states of the other items do not change. A rollout
// that does not exist is [ErrNotFound]. [DB.CompleteRollout] does this, moves
// the channel and completes the rollout in one transaction.
func (db *DB) FinishItems(ctx context.Context, rolloutID, appliedPolicy string) ([]string, error) {
	if err := checkAppliedPolicy(appliedPolicy); err != nil {
		return nil, fmt.Errorf("store: finish items: %w", err)
	}
	var nodes nodeSet
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		r, err := rolloutByID(ctx, tx, rolloutID)
		if err != nil {
			return queryNotFound(err, "rollout")
		}
		nodes, err = finishItems(ctx, tx, r, appliedPolicy, normTime(db.now()).Unix())
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("store: finish items: %w", err)
	}
	return nodes.sorted(), nil
}
