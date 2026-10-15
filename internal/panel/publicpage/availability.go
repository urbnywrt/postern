package publicpage

import "github.com/urbnywrt/postern/internal/panel/store"

// available reports whether a proxy is shown with its links: it is not paused,
// its node is online, and its probes do not fail (WithProbeDown). A proxy
// whose node is unknown is not available.
func (s *Service) available(p *store.Proxy, n *store.Node) bool {
	if !p.Enabled || n == nil || n.Status != store.NodeStatusOnline {
		return false
	}
	return s.probeDown == nil || !s.probeDown(p.ID)
}
