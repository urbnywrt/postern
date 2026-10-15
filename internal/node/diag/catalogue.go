package diag

import "time"

// Ids of the checks of this package (spec 5.7, Global Constraints).
const (
	IDDocker        = "host.docker"
	IDClock         = "host.clock"
	IDDNS           = "host.dns"
	IDDisk          = "host.disk"
	IDMemory        = "host.memory"
	IDPorts         = "host.ports"
	IDPublicIPs     = "host.public_ips"
	IDReservedPorts = "host.reserved_ports"
	IDEdgeCaps      = "host.edge_caps"
	IDStats         = "host.stats"
	IDIngressBound  = "ingress.bound"
)

// Fixes this package's checks offer.
const FixDNSModeDoH = "set_dns_mode_doh"

// Catalogue is the checks of the host and the ingress, each with its own
// state (the history host.public_ips and host.edge_caps keep). The engine,
// egress and end-to-end checks are added to it by their packages' callers.
func Catalogue() []Check {
	ips := &publicIPHistory{}
	caps := &edgeCaps{}
	return []Check{
		{ID: IDDocker, Layer: LayerHost, Light: true, Every: time.Minute, Run: checkDocker},
		{ID: IDClock, Layer: LayerHost, Light: true, Every: 10 * time.Minute, Timeout: SlowTimeout, Run: checkClock},
		{ID: IDDNS, Layer: LayerHost, Light: true, Every: 10 * time.Minute, Timeout: SlowTimeout, Run: checkDNS},
		{ID: IDDisk, Layer: LayerHost, Light: true, Every: 10 * time.Minute, Run: checkDisk},
		{ID: IDMemory, Layer: LayerHost, Light: true, Every: 10 * time.Minute, Run: checkMemory},
		{ID: IDPorts, Layer: LayerHost, Light: true, Every: 10 * time.Minute, Run: checkPorts},
		{ID: IDPublicIPs, Layer: LayerHost, Light: true, Every: 10 * time.Minute, Run: ips.run},
		{ID: IDReservedPorts, Layer: LayerHost, Run: checkReservedPorts},
		{ID: IDEdgeCaps, Layer: LayerHost, Light: true, Every: 10 * time.Minute, Run: caps.run},
		{ID: IDStats, Layer: LayerHost, Light: true, Every: time.Minute, Run: checkStats},
		{ID: IDIngressBound, Layer: LayerIngress, Light: true, Every: time.Minute, Run: checkBound},
	}
}
