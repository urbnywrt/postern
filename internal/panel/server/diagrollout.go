package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/urbnywrt/postern/internal/panel/diagnostics"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// rolloutHookTimeout bounds a rollout hook: the 3 minutes that the
// diagnostics around a step wait for at most, and a margin.
const rolloutHookTimeout = 3*time.Minute + 15*time.Second

// rolloutHooks are the diagnostics before and after every rollout step
// (R6-3): they inform and never fail a step.
func rolloutHooks(db *store.DB, runner *diagnostics.Runner, changes *diagnostics.Changes, log *slog.Logger) rollout.Hooks {
	h := diagnostics.NewRolloutHooks(diagnostics.RolloutConfig{
		Runner:   runner,
		Suppress: changes,
		Items: func(ctx context.Context, id string) ([]store.RolloutItem, error) {
			_, _, items, err := db.Rollout(ctx, id)
			return items, err
		},
		BeforeRun: func(ctx context.Context, nodeID, change string) string {
			runs, err := db.DiagnosticRunsByChange(ctx, change)
			if err != nil {
				log.Warn("could not find the before-run of a rollout step", "node", nodeID, "change", change, "err", err)
				return ""
			}
			id := ""
			for _, r := range runs { // oldest first: the latest before-run of the node
				if r.NodeID == nodeID && r.Change == change && r.Reason == store.RunBeforeChange {
					id = r.ID
				}
			}
			return id
		},
		Log: log,
	})
	return rollout.Hooks{BeforeStep: h.BeforeStep, AfterStep: h.AfterStep}
}
