package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	sqlite "modernc.org/sqlite"

	"github.com/urbnywrt/postern/internal/ids"
)

// This file holds the rollouts themselves: the types, the conflicts, and how a
// rollout is created, read, changed and completed. What a rollout does to the
// proxies of its items is in rollout_items.go.

// The values of Rollout.Kind.
const (
	RolloutVersion = "version" // a channel of a component to a version
	RolloutSwitch  = "switch"  // selected proxies to an engine
	RolloutNode    = "node"    // the agent and the edge of nodes
)

// The values of Rollout.Mode.
const (
	RolloutModeManual = "manual" // stops after each step until it is continued
	RolloutModeAuto   = "auto"   // goes on by itself after PauseSeconds
)

// The values of Rollout.Status. A rollout is active, and holds its nodes and
// its channel, while it is preparing, running, paused or failed; completed and
// aborted are over, for good.
const (
	RolloutPreparing = "preparing"
	RolloutRunning   = "running"
	RolloutPaused    = "paused"
	RolloutFailed    = "failed"
	RolloutCompleted = "completed"
	RolloutAborted   = "aborted"
)

// The values of RolloutStep.Status.
const (
	StepPending   = "pending"
	StepApplying  = "applying"
	StepVerifying = "verifying"
	StepDone      = "done"
	StepFailed    = "failed"
	StepReverted  = "reverted"
	StepSkipped   = "skipped"
)

// The values of RolloutItem.State.
const (
	ItemPending  = "pending"  // not touched yet
	ItemApplied  = "applied"  // the proxy holds the target of the rollout
	ItemReverted = "reverted" // put back to what it held, after a failed step
	ItemDetached = "detached" // changed by someone else; the rollout leaves it alone
	ItemDeferred = "deferred" // left on its previous version: its node was skipped, or the proxy is disabled
)

// ErrRolloutConflict is returned (as a [*RolloutConflict]) by
// [DB.CreateRollout] when another rollout holds what the new one needs: the
// channel of a version rollout, or one of its nodes. It is a conflict:
// errors.Is(err, ErrConflict) holds as well.
var ErrRolloutConflict = errors.New("store: another rollout is active")

// ErrRolloutOver is returned (wrapped, together with [ErrConflict]) by
// [DB.UpdateRollout] for a rollout that is completed or aborted and would be
// made active again, and by [DB.CompleteRollout] for one that was aborted. A
// rollout that is over let its nodes go, and stays over: a stale record cannot
// bring it back and hold the nodes twice.
var ErrRolloutOver = errors.New("store: the rollout is over")

// rolloutOver is the error for a rollout that is over.
func rolloutOver(id, status string) error {
	return fmt.Errorf("%w: %w: rollout %s is %s", ErrConflict, ErrRolloutOver, id, status)
}

// A RolloutConflict is the error of [DB.CreateRollout] when another rollout,
// Holder, is active for the same component and channel (NodeID is empty), or on
// the node NodeID.
type RolloutConflict struct {
	Holder    string // the id of the rollout that holds it
	NodeID    string // the node, or "" for a conflict on the channel
	Component string
	Channel   string
}

func (e *RolloutConflict) Error() string {
	if e.NodeID != "" {
		return fmt.Sprintf("%v: rollout %s holds node %s", ErrRolloutConflict, e.Holder, e.NodeID)
	}
	return fmt.Sprintf("%v: rollout %s is active for %s %s", ErrRolloutConflict, e.Holder, e.Component, e.Channel)
}

// Is makes the error both ErrRolloutConflict and ErrConflict for errors.Is.
func (e *RolloutConflict) Is(target error) bool {
	return target == ErrRolloutConflict || target == ErrConflict
}

// RolloutOptions are the choices made when a rollout was started that its steps
// need. They are kept as JSON; a field that is not set is left out.
type RolloutOptions struct {
	Agent         bool   `json:"agent,omitempty"`           // node rollouts: update the agent
	Edge          bool   `json:"edge,omitempty"`            // node rollouts: update the edge
	SkipOffline   bool   `json:"skip_offline,omitempty"`    // leave a node that is offline on its version
	CanaryProxyID string `json:"canary_proxy_id,omitempty"` // the proxy that went first
	CanaryNodeID  string `json:"canary_node_id,omitempty"`  // the node that went first
}

// A Rollout is a change that goes out one step at a time: a channel of a
// component to a version, selected proxies to an engine, or the agent and the
// edge of nodes to the version of the panel.
//
// A version rollout names its Channel, the version the channel has
// (FromVersion) and the version it goes to (ToVersion): [DB.CompleteRollout]
// moves the channel to ToVersion, and items that are left on their previous
// version are pinned at FromVersion when they followed the channel.
type Rollout struct {
	ID          string
	Kind        string // one of the Rollout kinds
	Component   string
	Channel     string // the channel that a version rollout moves; "" otherwise
	FromVersion string
	ToVersion   string
	ToEngine    string // the engine that a switch rollout switches to
	Options     RolloutOptions
	Mode        string // RolloutModeManual or RolloutModeAuto
	// PauseSeconds is the wait after a step in auto mode.
	PauseSeconds uint32
	Status       string // one of the Rollout statuses, RolloutPreparing by default
	CurrentStep  uint32 // the index of the step that runs, or ran last
	ResumeAt     *time.Time
	Error        string
	CreatedBy    string // the admin who started it
	CreatedAt    time.Time
	UpdatedAt    time.Time
	FinishedAt   *time.Time
}

// A RolloutStep is one step of a rollout: the canary proxy (ProxyID), the rest
// of its node, or one more node.
type RolloutStep struct {
	RolloutID string
	Index     uint32
	NodeID    string
	ProxyID   string // the canary proxy, when the step is one
	Status    string // one of the Step statuses
	// Generation is the desired generation of the node that the step wrote,
	// 0 while it has not: a step found at 0 when the panel starts runs its
	// Apply again.
	Generation uint64
	// StartedAt is when the step started. A step that is pending has none;
	// once a step is under way its start is kept, so that a step that a
	// restart of the panel resumes keeps its deadline; a retry queues the step
	// again (pending), and its next start is a fresh one.
	StartedAt  *time.Time
	FinishedAt *time.Time
	Error      string
}

// A RolloutItem is one proxy that a rollout changes, with what it held when the
// rollout was made, so that it can be put back.
type RolloutItem struct {
	RolloutID   string
	ProxyID     string
	NodeID      string
	StepIndex   uint32
	PrevEngine  string
	PrevPolicy  string
	PrevVersion string
	State       string // one of the Item states, ItemPending by default
}

// prev is what the proxy of an item held: its engine, version policy and
// version.
func (it RolloutItem) prev() [3]string {
	return [3]string{it.PrevEngine, it.PrevPolicy, it.PrevVersion}
}

// activeStatuses is the SQL list of the statuses in which a rollout holds its
// nodes and its channel: the one of the partial indexes of the schema.
const activeStatuses = `('preparing', 'running', 'paused', 'failed')`

// rolloutActive reports whether a rollout in this status holds its nodes.
func rolloutActive(status string) bool {
	switch status {
	case RolloutPreparing, RolloutRunning, RolloutPaused, RolloutFailed:
		return true
	}
	return false
}

// checkRolloutStatus refuses a status that is none of the six: whether a rollout
// holds its nodes depends on it.
func checkRolloutStatus(status string) error {
	switch status {
	case RolloutPreparing, RolloutRunning, RolloutPaused, RolloutFailed, RolloutCompleted, RolloutAborted:
		return nil
	}
	return fmt.Errorf("unknown rollout status %q", status)
}

// checkRolloutMode refuses a mode that is neither of the two.
func checkRolloutMode(mode string) error {
	switch mode {
	case RolloutModeManual, RolloutModeAuto:
		return nil
	}
	return fmt.Errorf("unknown rollout mode %q", mode)
}

// checkRollout refuses a rollout that the indexes or the completion cannot work
// with: a kind that is not one of the three (the per-channel index knows
// 'version' alone), a mode or a status that is not one of its values, no
// component, or a version rollout without its channel or its versions.
func checkRollout(r *Rollout) error {
	switch r.Kind {
	case RolloutVersion, RolloutSwitch, RolloutNode:
	default:
		return fmt.Errorf("unknown rollout kind %q", r.Kind)
	}
	if err := checkRolloutMode(r.Mode); err != nil {
		return err
	}
	if r.Component == "" {
		return errors.New("a rollout needs a component")
	}
	if r.Kind == RolloutVersion && (r.Channel == "" || r.FromVersion == "" || r.ToVersion == "") {
		return errors.New("a version rollout needs its channel, the version the channel has (FromVersion) and the version to go to (ToVersion)")
	}
	return checkRolloutStatus(r.Status)
}

// isUnique reports whether err is the violation of a UNIQUE index: what the two
// partial indexes of the rollouts raise.
func isUnique(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == sqliteConstraintUnique
}

const rolloutColumns = `id, kind, component, channel, from_version, to_version, to_engine, options, mode, pause_seconds,
	status, current_step, resume_at, error, created_by, created_at, updated_at, finished_at`

func scanRollout(s scanner) (*Rollout, error) {
	var (
		r                Rollout
		options          string
		pause, step      int64
		resume, finished sql.NullInt64
		created, updated int64
	)
	if err := s.Scan(&r.ID, &r.Kind, &r.Component, &r.Channel, &r.FromVersion, &r.ToVersion, &r.ToEngine, &options, &r.Mode, &pause,
		&r.Status, &step, &resume, &r.Error, &r.CreatedBy, &created, &updated, &finished); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(options), &r.Options); err != nil {
		return nil, fmt.Errorf("decode options: %w", err)
	}
	r.PauseSeconds, r.CurrentStep = uint32Of(pause), uint32Of(step)
	r.ResumeAt, r.FinishedAt = timePtrFromDB(resume), timePtrFromDB(finished)
	r.CreatedAt, r.UpdatedAt = timeFromDB(created), timeFromDB(updated)
	return &r, nil
}

const stepColumns = `rollout_id, idx, node_id, proxy_id, status, generation, started_at, finished_at, error`

func scanStep(s scanner) (RolloutStep, error) {
	var (
		st                RolloutStep
		idx, generation   int64
		started, finished sql.NullInt64
	)
	if err := s.Scan(&st.RolloutID, &idx, &st.NodeID, &st.ProxyID, &st.Status, &generation, &started, &finished, &st.Error); err != nil {
		return RolloutStep{}, err
	}
	st.Index, st.Generation = uint32Of(idx), uint64Of(generation)
	st.StartedAt, st.FinishedAt = timePtrFromDB(started), timePtrFromDB(finished)
	return st, nil
}

const itemColumns = `rollout_id, proxy_id, node_id, step_idx, prev_engine, prev_policy, prev_version, state`

func scanItem(s scanner) (RolloutItem, error) {
	var (
		it   RolloutItem
		step int64
	)
	if err := s.Scan(&it.RolloutID, &it.ProxyID, &it.NodeID, &step, &it.PrevEngine, &it.PrevPolicy, &it.PrevVersion, &it.State); err != nil {
		return RolloutItem{}, err
	}
	it.StepIndex = uint32Of(step)
	return it, nil
}

// CreateRollout stores r with the nodes it holds, its steps and its items, all
// or nothing. It gives r an ID if it has none, a creation time if it has none,
// RolloutPreparing as the status if that is empty, and the creation time as the
// time of the last update if that is not set; the steps and the items get the
// id of the rollout, and StepPending and ItemPending when they have no status
// or state; a pending step has no start. The rollout is checked first
// (checkRollout): its kind and mode have to be known, it needs a component, and
// a version rollout its channel and both versions.
//
// The rollout holds every node in nodeIDs and every node that a step or an
// item names, each once, so that no node a rollout touches is left for another
// to take; the hold is active while the status is (a rollout created over
// holds nothing). The schema allows one active version rollout per component
// and channel and one active rollout of any kind per node, and this is checked
// in the transaction that creates the rollout: the second of two that are
// created at once gets a [*RolloutConflict] that names the one that holds the
// channel or the node, and nothing of it is stored.
func (db *DB) CreateRollout(ctx context.Context, r *Rollout, nodeIDs []string, steps []RolloutStep, items []RolloutItem) error {
	c := *r
	if c.ID == "" {
		c.ID = ids.New()
	}
	if c.Status == "" {
		c.Status = RolloutPreparing
	}
	if err := checkRollout(&c); err != nil {
		return fmt.Errorf("store: create rollout: %w", err)
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = db.now()
	}
	c.CreatedAt = normTime(c.CreatedAt)
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	c.UpdatedAt = normTime(c.UpdatedAt)
	c.ResumeAt, c.FinishedAt = normTimePtr(c.ResumeAt), normTimePtr(c.FinishedAt)
	options, err := json.Marshal(c.Options)
	if err != nil {
		return fmt.Errorf("store: create rollout: encode options: %w", err)
	}
	active := boolInt(rolloutActive(c.Status))

	var nodes []string
	hold := func(id string) {
		if id != "" && !slices.Contains(nodes, id) {
			nodes = append(nodes, id)
		}
	}
	for _, id := range nodeIDs {
		hold(id)
	}
	outSteps := slices.Clone(steps)
	for i := range outSteps {
		s := &outSteps[i]
		s.RolloutID = c.ID
		if s.Status == "" {
			s.Status = StepPending
		}
		s.StartedAt, s.FinishedAt = normTimePtr(s.StartedAt), normTimePtr(s.FinishedAt)
		if s.Status == StepPending {
			s.StartedAt = nil
		}
		hold(s.NodeID)
	}
	outItems := slices.Clone(items)
	for i := range outItems {
		outItems[i].RolloutID = c.ID
		if outItems[i].State == "" {
			outItems[i].State = ItemPending
		}
		hold(outItems[i].NodeID)
	}

	err = db.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO rollouts (`+rolloutColumns+`) VALUES (`+placeholders(18)+`)`,
			c.ID, c.Kind, c.Component, c.Channel, c.FromVersion, c.ToVersion, c.ToEngine, string(options), c.Mode, int64(c.PauseSeconds),
			c.Status, int64(c.CurrentStep), nullTime(c.ResumeAt), c.Error, c.CreatedBy, c.CreatedAt.Unix(), c.UpdatedAt.Unix(), nullTime(c.FinishedAt))
		if isUnique(err) {
			conflict := &RolloutConflict{Component: c.Component, Channel: c.Channel}
			if err := tx.QueryRowContext(ctx,
				`SELECT id FROM rollouts WHERE kind = ? AND component = ? AND channel = ? AND status IN `+activeStatuses,
				RolloutVersion, c.Component, c.Channel).Scan(&conflict.Holder); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			return conflict
		}
		if err != nil {
			return mapErr(err, fkMissing)
		}
		for _, id := range nodes {
			_, err := tx.ExecContext(ctx, `INSERT INTO rollout_nodes (rollout_id, node_id, active) VALUES (?, ?, ?)`, c.ID, id, active)
			if isUnique(err) {
				conflict := &RolloutConflict{NodeID: id, Component: c.Component, Channel: c.Channel}
				if err := tx.QueryRowContext(ctx,
					`SELECT rollout_id FROM rollout_nodes WHERE node_id = ? AND active = 1`, id).Scan(&conflict.Holder); err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				return conflict
			}
			if err != nil {
				return mapErr(err, fkMissing)
			}
		}
		for _, s := range outSteps {
			gen, err := int64Of("generation", s.Generation)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO rollout_steps (`+stepColumns+`) VALUES (`+placeholders(9)+`)`,
				s.RolloutID, int64(s.Index), s.NodeID, s.ProxyID, s.Status, gen, nullTime(s.StartedAt), nullTime(s.FinishedAt), s.Error); err != nil {
				return mapErr(err, fkMissing)
			}
		}
		for _, it := range outItems {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO rollout_items (`+itemColumns+`) VALUES (`+placeholders(8)+`)`,
				it.RolloutID, it.ProxyID, it.NodeID, int64(it.StepIndex), it.PrevEngine, it.PrevPolicy, it.PrevVersion, it.State); err != nil {
				return mapErr(err, fkMissing)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: create rollout: %w", err)
	}
	*r = c
	copy(steps, outSteps)
	copy(items, outItems)
	return nil
}

// rolloutByID reads one rollout, sql.ErrNoRows when there is none.
func rolloutByID(ctx context.Context, q dbtx, id string) (*Rollout, error) {
	return scanRollout(q.QueryRowContext(ctx, `SELECT `+rolloutColumns+` FROM rollouts WHERE id = ?`, id))
}

// queryItems returns the items of a rollout, by step and then by proxy.
func queryItems(ctx context.Context, q dbtx, rolloutID string) ([]RolloutItem, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+itemColumns+` FROM rollout_items WHERE rollout_id = ? ORDER BY step_idx, proxy_id`, rolloutID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RolloutItem
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Rollout returns a rollout with its steps, by index, and its items, by step
// and then by proxy; [ErrNotFound] when there is none.
func (db *DB) Rollout(ctx context.Context, id string) (*Rollout, []RolloutStep, []RolloutItem, error) {
	r, err := rolloutByID(ctx, db.sql, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("store: rollout: %w", queryNotFound(err, "rollout"))
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT `+stepColumns+` FROM rollout_steps WHERE rollout_id = ? ORDER BY idx`, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("store: rollout steps: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var steps []RolloutStep
	for rows.Next() {
		s, err := scanStep(rows)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("store: rollout steps: %w", err)
		}
		steps = append(steps, s)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("store: rollout steps: %w", err)
	}
	items, err := queryItems(ctx, db.sql, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("store: rollout items: %w", err)
	}
	return r, steps, items, nil
}

// ListRollouts returns rollouts, newest first: every one, or only those that are
// active, and at most limit of them when limit is more than 0.
func (db *DB) ListRollouts(ctx context.Context, activeOnly bool, limit int) ([]*Rollout, error) {
	query := `SELECT ` + rolloutColumns + ` FROM rollouts`
	if activeOnly {
		query += ` WHERE status IN ` + activeStatuses
	}
	query += ` ORDER BY created_at DESC, id DESC`
	var args []any
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list rollouts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Rollout
	for rows.Next() {
		r, err := scanRollout(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list rollouts: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list rollouts: %w", err)
	}
	return out, nil
}

// updateRollout is the write of UpdateRollout, in a transaction. It applies in
// two cases only: the stored status is active, whatever the new one; or the
// stored status is over and the new one is the same (writing an end again
// changes nothing of it). A rollout that is over and would be made active
// again, or given the other end, is ErrRolloutOver; one that does not exist is
// ErrNotFound. A rollout that is over keeps the time it finished once it has
// one, which is returned, and lets its nodes go.
func updateRollout(ctx context.Context, tx *sql.Tx, r *Rollout, updated time.Time) (finished *time.Time, err error) {
	options, err := json.Marshal(r.Options)
	if err != nil {
		return nil, fmt.Errorf("encode options: %w", err)
	}
	over := !rolloutActive(r.Status)
	given := normTimePtr(r.FinishedAt)
	if over && given == nil {
		given = &updated
	}
	var stored sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`UPDATE rollouts SET from_version = ?, to_version = ?, to_engine = ?, options = ?, mode = ?, pause_seconds = ?,
		 status = ?, current_step = ?, resume_at = ?, error = ?, updated_at = ?,
		 finished_at = CASE WHEN ? THEN COALESCE(finished_at, ?) ELSE ? END
		 WHERE id = ? AND (status IN `+activeStatuses+` OR status = ?) RETURNING finished_at`,
		r.FromVersion, r.ToVersion, r.ToEngine, string(options), r.Mode, int64(r.PauseSeconds),
		r.Status, int64(r.CurrentStep), nullTime(normTimePtr(r.ResumeAt)), r.Error, updated.Unix(),
		boolInt(over), nullTime(given), nullTime(given),
		r.ID, r.Status).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		// No row took the write: there is none, or the one there is over and
		// r would change its end.
		var status string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM rollouts WHERE id = ?`, r.ID).Scan(&status); err != nil {
			return nil, queryNotFound(err, "rollout")
		}
		if rolloutActive(status) || status == r.Status {
			return nil, fmt.Errorf("rollout %s took no write although it is %s", r.ID, status) // cannot happen: the transaction holds the lock
		}
		return nil, rolloutOver(r.ID, status)
	}
	if err != nil {
		return nil, mapErr(err, fkMissing)
	}
	if over {
		if _, err := tx.ExecContext(ctx, `UPDATE rollout_nodes SET active = 0 WHERE rollout_id = ?`, r.ID); err != nil {
			return nil, err
		}
	}
	return timePtrFromDB(stored), nil
}

// UpdateRollout writes every field of r except the id, the kind, the component,
// the channel, who created it and when, and sets the time of the last update.
//
// A rollout that is over (completed or aborted) stays over, with the end it
// has: it lets its nodes go, in the same transaction, so that the next rollout
// can hold them, and a later write of an active status or of the other end, a
// stale record say, is refused with [ErrRolloutOver] (a conflict). Writing the
// same end again changes nothing of that: the time it finished is the one it
// has, now when it has none, and comes back in r. A rollout that does not exist
// is [ErrNotFound].
func (db *DB) UpdateRollout(ctx context.Context, r *Rollout) error {
	if err := checkRolloutStatus(r.Status); err != nil {
		return fmt.Errorf("store: update rollout: %w", err)
	}
	if err := checkRolloutMode(r.Mode); err != nil {
		return fmt.Errorf("store: update rollout: %w", err)
	}
	updated := normTime(db.now())
	var finished *time.Time
	err := db.withTx(ctx, func(tx *sql.Tx) (err error) {
		finished, err = updateRollout(ctx, tx, r, updated)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: update rollout: %w", err)
	}
	r.UpdatedAt, r.ResumeAt, r.FinishedAt = updated, normTimePtr(r.ResumeAt), finished
	return nil
}

// UpdateRolloutStep writes the status, the generation, the time it finished and
// the error of a step, found by its rollout and index. A step that is written
// pending (a retry queues it again) has no start, whatever s says. Otherwise the
// time it started is written only when none is stored: a stored one is never
// changed, so that a resume keeps the deadline of the step, and comes back in
// s. A step that does not exist is [ErrNotFound].
func (db *DB) UpdateRolloutStep(ctx context.Context, s *RolloutStep) error {
	gen, err := int64Of("generation", s.Generation)
	if err != nil {
		return fmt.Errorf("store: update rollout step: %w", err)
	}
	started, finished := normTimePtr(s.StartedAt), normTimePtr(s.FinishedAt)
	var stored sql.NullInt64
	err = db.sql.QueryRowContext(ctx,
		`UPDATE rollout_steps SET status = ?, generation = ?,
		 started_at = CASE WHEN ? THEN NULL ELSE COALESCE(started_at, ?) END, finished_at = ?, error = ?
		 WHERE rollout_id = ? AND idx = ? RETURNING started_at`,
		s.Status, gen, boolInt(s.Status == StepPending), nullTime(started), nullTime(finished), s.Error, s.RolloutID, int64(s.Index)).Scan(&stored)
	if err != nil {
		return fmt.Errorf("store: update rollout step: %w", queryNotFound(err, "rollout step"))
	}
	s.StartedAt, s.FinishedAt = timePtrFromDB(stored), finished
	return nil
}

// CompleteRollout completes a rollout, all in one transaction: a version
// rollout moves its channel to ToVersion, the proxies of the items are settled
// as [DB.FinishItems] does with appliedPolicy, and the rollout is completed (the
// status, the time it finished, its nodes let go). It returns the nodes whose
// proxies were written, sorted, so that the caller raises their generations.
// Being one transaction, a crash cannot leave a channel that has moved with
// proxies that were to stay behind still following it.
//
// A rollout that is completed already is left as it is, and no node is named:
// a restart of the panel may run the completion again. One that was aborted is
// [ErrRolloutOver]; one that does not exist is [ErrNotFound].
func (db *DB) CompleteRollout(ctx context.Context, id, appliedPolicy string) ([]string, error) {
	if err := checkAppliedPolicy(appliedPolicy); err != nil {
		return nil, fmt.Errorf("store: complete rollout: %w", err)
	}
	var nodes nodeSet
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		r, err := rolloutByID(ctx, tx, id)
		if err != nil {
			return queryNotFound(err, "rollout")
		}
		switch r.Status {
		case RolloutCompleted:
			return nil
		case RolloutAborted:
			return rolloutOver(r.ID, r.Status)
		}
		now := normTime(db.now())
		if r.Kind == RolloutVersion {
			if err := setChannelVersion(ctx, tx, r.Component, r.Channel, r.ToVersion, now.Unix()); err != nil {
				return err
			}
		}
		if nodes, err = finishItems(ctx, tx, r, appliedPolicy, now.Unix()); err != nil {
			return err
		}
		r.Status, r.ResumeAt = RolloutCompleted, nil
		_, err = updateRollout(ctx, tx, r, now)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("store: complete rollout: %w", err)
	}
	return nodes.sorted(), nil
}
