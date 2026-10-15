package nodes

import (
	"context"
	"errors"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// handle takes one record of the Watch stream: the ingestor stores it, a
// state report gives the node its applied generation and the error of its last
// pass (none after a pass that went through), and the cursor moves past the
// record, in that order. A record whose storing is cut short by the end of the
// session keeps the cursor where it was, so that the node sends it again on the
// next connection.
func (s *session) handle(ctx context.Context, rec *nodev1.WatchResponse) {
	r := s.r
	if !r.ingest(ctx, rec) {
		return
	}
	r.m.noteRecord(r.id, rec)
	report := rec.GetState()
	now := r.m.now()
	_, err := r.m.db.ModifyNode(ctx, r.id, func(n *store.Node) error {
		if report != nil {
			n.AppliedGeneration = report.GetAppliedGeneration()
			n.LastError = clip(report.GetLastError(), maxReasonLen)
			// A report proves the node alive; a status of error is about the
			// trust in it or its generation, which a report does not mend.
			if n.Status != store.NodeStatusError {
				n.Status = store.NodeStatusOnline
			}
		}
		if seq := rec.GetSeq(); seq != 0 {
			n.WatchCursor = seq
		}
		n.LastSeenAt = &now
		return nil
	})
	if err != nil && ctx.Err() == nil && !errors.Is(err, store.ErrNotFound) {
		r.log.Error("could not store the cursor of the node", "seq", rec.GetSeq(), "err", err)
	}
}

// ingest hands a record to the ingestor, trying again with a growing wait when
// it fails, up to ingestAttempts times in all. A record that still fails is
// logged and skipped: one bad record must not hold up every record after it.
// ingest reports false when ctx ended before the record was stored.
func (r *runner) ingest(ctx context.Context, rec *nodev1.WatchResponse) bool {
	ing := r.m.getIngestor()
	if ing == nil {
		return true
	}
	wait := backoff{min: r.m.cfg.minBackoff, max: r.m.cfg.maxBackoff}
	for attempt := 1; ; attempt++ {
		err := ing.OnWatch(ctx, r.id, rec)
		if err == nil {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		if attempt >= r.m.cfg.ingestAttempts {
			r.log.Error("could not store a record of the node; it is skipped",
				"seq", rec.GetSeq(), "record", payloadOf(rec), "attempts", attempt, "err", err)
			return true
		}
		r.log.Warn("could not store a record of the node; trying again",
			"seq", rec.GetSeq(), "record", payloadOf(rec), "err", err)
		if !sleep(ctx, wait.next()) {
			return false
		}
	}
}

// payloadOf names what a record carries, for the log. The content itself is
// never logged.
func payloadOf(rec *nodev1.WatchResponse) string {
	switch rec.GetPayload().(type) {
	case *nodev1.WatchResponse_State:
		return "state"
	case *nodev1.WatchResponse_Stats:
		return "stats"
	case *nodev1.WatchResponse_Event:
		return "event"
	}
	return "unknown"
}
