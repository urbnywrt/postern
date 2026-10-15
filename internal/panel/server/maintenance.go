package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// maintenanceStore is what the maintenance asks of the database, and the
// *store.DB answers.
type maintenanceStore interface {
	StatsSettings(ctx context.Context) (store.StatsSettings, bool, error)
	RollupStats(ctx context.Context, now time.Time, r store.Retention) error
	PruneStats(ctx context.Context, now time.Time, r store.Retention) error
	PruneEvents(ctx context.Context, now time.Time) (int64, error)
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)
}

// runMaintenance is the one maintenance loop of the panel. It runs a round at
// once and then every interval until ctx is done; a round
//
//   - reads how long the statistics are kept (StatsSettings, the defaults while
//     none are stored), at every round, so that a change of the settings is
//     used from the next round on,
//   - rolls the minutes of statistics up into hours and the hours into days
//     (RollupStats), so that the series of a week or a month have something to
//     read,
//   - deletes what is older than it is kept (PruneStats), so that the database
//     does not grow without end,
//   - deletes the events of more than 30 days ago (PruneEvents), in batches,
//     for the same reason: a node with a flapping proxy writes many,
//   - deletes the sessions that have expired (DeleteExpiredSessions): a session
//     that nobody asks for again is not found by anything else.
//
// A task that fails is logged at error level and does not keep the others from
// running, nor the next round from coming. Settings that cannot be read (one
// that a newer version stored, say) do not stop the prune, which keeps client
// addresses from staying past their time: the round uses
// store.FallbackRetention, which deletes no statistic that a valid setting
// would keep, and keeps addresses for the shortest time. What fails because
// ctx is done, the panel is stopping, is not an error.
//
// The first round is not an interval away, so that a panel that is restarted
// more often than that still gets its rounds.
//
// This is the one maintenance loop of the panel: nothing else in it rolls the
// statistics up or prunes them, so that the work is not done twice.
func runMaintenance(ctx context.Context, db maintenanceStore, every time.Duration, now func() time.Time, log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if every <= 0 {
		every = defaultMaintenanceEvery
	}
	round := func() {
		at := now()
		fail := func(what string, err error) {
			if err != nil && ctx.Err() == nil {
				log.Error("maintenance: "+what, "err", err)
			}
		}
		r := store.FallbackRetention()
		if s, _, err := db.StatsSettings(ctx); err != nil {
			fail("could not read the statistics settings; the statistics are pruned by the longest retention "+
				"that a setting may have, and the client addresses by the shortest", err)
		} else {
			r = s.Retention()
		}
		fail("could not roll the statistics up", db.RollupStats(ctx, at, r))
		fail("could not prune the statistics", db.PruneStats(ctx, at, r))
		_, err := db.PruneEvents(ctx, at)
		fail("could not prune the events", err)
		_, err = db.DeleteExpiredSessions(ctx, at)
		fail("could not delete the sessions that have expired", err)
	}

	round()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			round()
		}
	}
}
