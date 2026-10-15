package diag

import (
	"cmp"
	"slices"
	"strings"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

const (
	// confirmAfter is how soon a light check runs again when a run found it
	// worse than it was last reported: the worsening is reported only when
	// this rerun confirms it.
	confirmAfter = time.Minute
	// hysteresisUpTo is the longest cadence whose first failure after a start
	// is reported as warn ("failed once"), and fail only when the next run
	// fails too. Past the first report, the confirmation does this for every
	// check.
	hysteresisUpTo = time.Minute
)

// resultKey is a result of the light set.
type resultKey struct{ id, target string }

// lightSet is the latest reported light result of every check and target,
// and the worsenings that wait for a rerun to confirm them.
type lightSet struct {
	byUnit  map[unitKey][]Result
	pending map[resultKey]Result // a worse result than the reported one, not confirmed yet
}

func newLightSet() *lightSet {
	return &lightSet{byUnit: map[unitKey][]Result{}, pending: map[resultKey]Result{}}
}

// severity orders the statuses: ok and skip, then warn, then fail.
func severity(s nodev1.CheckStatus) int {
	switch s {
	case Fail:
		return 2
	case Warn:
		return 1
	}
	return 0
}

// put takes a run of a unit, rs. A result worse than the one last reported
// for its check and target is held back, the reported one kept, and the run
// asks for a rerun (confirm); the rerun reports the better of the two worse
// statuses, with its own texts, when it is still worse. A result as good or
// better is reported at once, and so is one with nothing reported before it
// (except that a check of a cadence up to hysteresisUpTo reports a first
// failure as warn, and waits for the next run to fail). changed is whether a
// status, a fix or a result of the set changed.
func (s *lightSet) put(k unitKey, c Check, rs []Result) (changed, confirm bool) {
	old := s.byUnit[k]
	before := signature(old)
	reported := map[resultKey]Result{}
	for _, r := range old {
		reported[resultKey{r.ID, r.Target}] = r
	}
	seen := map[resultKey]bool{}
	out := make([]Result, 0, len(rs))
	for _, r := range rs {
		rk := resultKey{r.ID, r.Target}
		seen[rk] = true
		last, had := reported[rk]
		held, waiting := s.pending[rk]
		delete(s.pending, rk)
		switch {
		case !had && r.Status == Fail && c.Every <= hysteresisUpTo:
			s.pending[rk] = r
			confirm = true
			r.Status = Warn
			r.Summary = clip("failed once: "+r.Summary, MaxSummary, true)
		case !had || severity(r.Status) <= severity(last.Status):
			// A first result, or no worse: reported at once.
		case waiting:
			// Confirmed: the better of the two worse runs, in the words of
			// the newer.
			if severity(held.Status) < severity(r.Status) {
				r.Status = held.Status
			}
		default:
			s.pending[rk] = r
			confirm = true
			r = last
		}
		out = append(out, r)
	}
	for rk := range reported {
		if !seen[rk] {
			delete(s.pending, rk)
		}
	}
	if len(out) == 0 {
		delete(s.byUnit, k)
	} else {
		s.byUnit[k] = out
	}
	return before != signature(out), confirm
}

// drop takes a unit's results out (its check or target is gone) and reports
// whether there were any.
func (s *lightSet) drop(k unitKey) bool {
	rs, ok := s.byUnit[k]
	for _, r := range rs {
		delete(s.pending, resultKey{r.ID, r.Target})
	}
	delete(s.byUnit, k)
	return ok && len(rs) > 0
}

// report is the whole light set, by id and target, with at most
// MaxRunEvidence of evidence in all.
func (s *lightSet) report() *nodev1.DiagnosticsReport {
	var all []Result
	for _, rs := range s.byUnit {
		all = append(all, rs...)
	}
	slices.SortFunc(all, func(a, b Result) int {
		return cmp.Or(strings.Compare(a.ID, b.ID), strings.Compare(a.Target, b.Target))
	})
	rep := &nodev1.DiagnosticsReport{}
	budget := MaxRunEvidence
	for _, r := range all {
		p := r.Proto()
		if len(p.Evidence) > budget {
			p.Evidence = clip(p.Evidence, max(budget, 0), false)
		}
		budget -= len(p.Evidence)
		rep.Results = append(rep.Results, p)
	}
	return rep
}

// signature is what a change of the set is judged by: id, target, status and
// fix of every result, in order.
func signature(rs []Result) string {
	var b strings.Builder
	sorted := slices.Clone(rs)
	slices.SortFunc(sorted, func(a, b Result) int {
		return cmp.Or(strings.Compare(a.ID, b.ID), strings.Compare(a.Target, b.Target))
	})
	for _, r := range sorted {
		b.WriteString(r.ID)
		b.WriteByte(0)
		b.WriteString(r.Target)
		b.WriteByte(0)
		b.WriteString(r.Status.String())
		b.WriteByte(0)
		b.WriteString(r.Fix)
		b.WriteByte(1)
	}
	return b.String()
}
