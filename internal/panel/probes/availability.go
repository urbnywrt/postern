package probes

import "time"

// Down reports whether a proxy is down by the panel's probes: its last two
// probes failed and the newer one is at most three intervals old. While the
// probes are off (interval 0) no proxy is down. The public page and the
// problem feed use it.
func (s *Scheduler) Down(proxyID string) bool {
	s.mu.Lock()
	rs, interval := s.last[proxyID], s.interval
	s.mu.Unlock()
	if interval <= 0 || len(rs) < 2 || rs[0].ok || rs[1].ok {
		return false
	}
	return !s.now().After(rs[0].ts.Add(time.Duration(downIntervals) * interval))
}
