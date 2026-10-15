package agent

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/control"
)

const (
	// statsEvery is how often the edge's counters are taken (spec 5.8).
	statsEvery = 10 * time.Second
	// snapshotTimeout bounds one Snapshot call.
	snapshotTimeout = 3 * time.Second
	// maxSightings bounds the client addresses of one minute, some 50 bytes
	// each: a minute with more drops the rest (the panel takes up to 16 MiB
	// per record).
	maxSightings = 10000
	// maxMinuteAddrs bounds the client addresses one minute keeps in memory
	// for its countries; the edge's own bound on the addresses it counts is
	// far below it.
	maxMinuteAddrs = 200_000
	// maxCountries is how many countries of a proxy a minute names: the
	// others are summed under "".
	maxCountries = 50
	// maxMinuteProbes bounds the probe results of one minute.
	maxMinuteProbes = 1000
)

// ipMode is what the IP policy of the node lets the statistics do with the
// client addresses (spec 8.6): nothing (the edge is not even asked for them),
// count them by country, or also keep where each was seen.
type ipMode uint8

const (
	modeOff ipMode = iota
	modeCountries
	modeFull
)

// modeOf is the mode of an IP policy; unspecified, and any value this build
// does not know, is off.
func modeOf(p nodev1.IpPolicy) ipMode {
	switch p {
	case nodev1.IpPolicy_IP_POLICY_FULL:
		return modeFull
	case nodev1.IpPolicy_IP_POLICY_COUNTRIES:
		return modeCountries
	}
	return modeOff
}

// ---- aggregation ------------------------------------------------------------------

// aggregator turns observations, one every 10 s, into minutes of statistics.
//
// The edge's counters of traffic and connections only ever grow while an edge
// process runs. The aggregator keeps, per edge generation, the counters it saw
// last and adds the increments to the minute. Generations are told apart, so
// a handover (two generations side by side, then the old one gone) adds the
// increments of both; an edge process that restarts within its generation
// starts from zero again, which is taken as a fresh start, never as a negative
// increment. The refusal counters of the edge are taken the same way.
//
// A generation that was there when the agent started has counted traffic the
// agent did not watch: its first answer only sets the baseline. A generation
// that appears later, a proxy that appears in a generation, and a generation
// whose control socket came back (its container was started again) count
// from zero.
//
// The counters of the client IPs come only while the IP policy uses them
// (full or countries: they are asked for only then): when they come again,
// the edge has counted for an address what the agent did not watch, and their
// first answer is a baseline as well. full and countries share that baseline,
// so a switch between them never turns absolute counters into a spike (R6-5).
type aggregator struct {
	started     bool
	ipsReceived bool            // the last observation had the counters of the IPs
	preexisting map[uint64]bool // there at the first observation, until their first answer
	gens        map[uint64]*genCounters
	cpuBusy     uint64 // the last CPU sample
	cpuTotal    uint64
	netPrev     map[string]netCounters
	cur         *minuteAcc
	early       []*nodev1.ProbeResult // probes added before the first observation
	dropped     int                   // sightings the minute that observe returned left out
	overflow    int                   // addresses that minute left out of its countries (over maxMinuteAddrs)
	// country names the country of a client address, "" when unknown; nil
	// knows none.
	country func(ip string) string
}

// genCounters are the counters an edge generation reported last.
type genCounters struct {
	proxies map[string]counterBase
	ips     map[ipKey]uint64 // bytes
	refused refusals
	known   bool // refused holds an answer
}

type counterBase struct{ up, down, conns uint64 }

type refusals struct{ prehello, total, evicted uint64 }

type ipKey struct{ proxy, ip string }

type memberKey struct{ chain, member string }

// minuteAcc is the minute being collected.
type minuteAcc struct {
	start    int64 // unix time of its first second
	proxies  map[string]*proxyAcc
	ips      map[ipKey]*nodev1.IpSighting // under full only
	addrs    map[ipKey]uint64             // bytes of every address sighted, for the countries; never buffered
	members  map[memberKey]*nodev1.MemberMinute
	probes   []*nodev1.ProbeResult
	refused  refusals
	dropped  int // sightings over maxSightings
	overflow int // addresses over maxMinuteAddrs, left out of the countries
	cpuBusy  uint64
	cpuTotal uint64
	netRx    uint64
	netTx    uint64
	host     *hostSample // the last one
	conns    uint32      // peak of the edge's active connections
}

type proxyAcc struct {
	up, down, connsNew       uint64
	peak, devices, connsLast uint32
}

func newAggregator() *aggregator {
	return &aggregator{preexisting: map[uint64]bool{}, gens: map[uint64]*genCounters{}, netPrev: map[string]netCounters{}}
}

func newMinute(start int64) *minuteAcc {
	return &minuteAcc{
		start: start, proxies: map[string]*proxyAcc{}, ips: map[ipKey]*nodev1.IpSighting{},
		addrs: map[ipKey]uint64{}, members: map[memberKey]*nodev1.MemberMinute{},
	}
}

func (m *minuteAcc) proxy(id string) *proxyAcc {
	p := m.proxies[id]
	if p == nil {
		p = &proxyAcc{}
		m.proxies[id] = p
	}
	return p
}

// observe takes one observation made at now: the snapshot of every edge
// generation whose control socket is there (nil for one that did not answer)
// and a sample of the host (nil for none). received says whether the
// snapshots were asked for the counters of the client IPs; mode is what the
// minute may keep of them (never more than received allows). It returns the
// previous minute when now is the first observation of a later one, else nil.
func (a *aggregator) observe(now time.Time, snaps map[uint64]*edgev1.SnapshotResponse, host *hostSample, received bool, mode ipMode) *nodev1.StatsBatch {
	minute := now.Unix() - now.Unix()%60
	var out *nodev1.StatsBatch
	switch {
	case a.cur == nil:
		a.cur = newMinute(minute)
		a.cur.probes, a.early = a.early, nil
	case minute > a.cur.start:
		out = a.cur.batch(a.country)
		a.dropped, a.overflow = a.cur.dropped, a.cur.overflow
		a.cur = newMinute(minute)
	}
	// A clock that went back adds to the current minute: a minute is never
	// made twice.
	if !received {
		mode = modeOff
	}

	first := !a.started
	a.started = true
	ipBaseline := received && !a.ipsReceived // the addresses come again
	a.ipsReceived = received
	for gen := range a.gens {
		if _, there := snaps[gen]; !there {
			delete(a.gens, gen) // the edge process is gone
		}
	}
	for gen := range a.preexisting {
		if _, there := snaps[gen]; !there {
			delete(a.preexisting, gen)
		}
	}
	if first {
		for gen := range snaps {
			a.preexisting[gen] = true
		}
	}

	active := map[string]uint32{}
	devices := map[string]uint32{}
	var newest *edgev1.SnapshotResponse
	for _, gen := range slices.Sorted(maps.Keys(snaps)) {
		s := snaps[gen]
		if s == nil {
			continue
		}
		newest = s
		g, known := a.gens[gen]
		baseline := false
		if !known {
			g = &genCounters{proxies: map[string]counterBase{}, ips: map[ipKey]uint64{}}
			a.gens[gen] = g
			baseline = a.preexisting[gen]
			delete(a.preexisting, gen)
		}
		a.proxyCounters(g, s, baseline, active, devices)
		a.refusalCounters(g, s, baseline)
		a.ipCounters(g, s, baseline || ipBaseline, mode, now)
	}
	if newest != nil {
		a.cur.memberHealth(newest.GetHealth())
	}

	var total uint32
	for id := range active {
		a.cur.proxy(id)
	}
	for id, p := range a.cur.proxies {
		n := active[id]
		p.connsLast = n
		p.peak = max(p.peak, n)
		p.devices = max(p.devices, devices[id])
		total = satAdd32(total, n)
	}
	a.cur.conns = max(a.cur.conns, total)

	if host != nil && host.ok() {
		a.hostSample(host)
	}
	return out
}

func (a *aggregator) proxyCounters(g *genCounters, s *edgev1.SnapshotResponse, baseline bool, active, devices map[string]uint32) {
	seen := map[string]bool{}
	for _, pc := range s.GetProxies() {
		id := pc.GetProxyId()
		seen[id] = true
		cur := counterBase{up: pc.GetBytesUp(), down: pc.GetBytesDown(), conns: pc.GetConnsTotal()}
		prev, ok := g.proxies[id]
		var d counterBase
		switch {
		case baseline:
			// Counted before the agent watched.
		case !ok:
			d = cur // new in a process the agent watches: all of it is new
		case cur.up < prev.up || cur.down < prev.down || cur.conns < prev.conns:
			d = cur // the process started again
		default:
			d = counterBase{up: cur.up - prev.up, down: cur.down - prev.down, conns: cur.conns - prev.conns}
		}
		g.proxies[id] = cur
		acc := a.cur.proxy(id)
		acc.up += d.up
		acc.down += d.down
		acc.connsNew += d.conns
		active[id] = satAdd32(active[id], pc.GetConnsActive())
		devices[id] = satAdd32(devices[id], pc.GetDevicesActive())
	}
	for id := range g.proxies {
		if !seen[id] {
			delete(g.proxies, id) // a restarted process has not seen it yet
		}
	}
}

// refusalCounters adds the increments of the edge's refusal counters, by the
// rules of the proxy counters.
func (a *aggregator) refusalCounters(g *genCounters, s *edgev1.SnapshotResponse, baseline bool) {
	cur := refusals{prehello: s.GetRefusedPrehello(), total: s.GetRefusedTotal(), evicted: s.GetEvictedPrehello()}
	prev := g.refused
	var d refusals
	switch {
	case baseline:
	case !g.known:
		d = cur
	case cur.prehello < prev.prehello || cur.total < prev.total || cur.evicted < prev.evicted:
		d = cur
	default:
		d = refusals{prehello: cur.prehello - prev.prehello, total: cur.total - prev.total, evicted: cur.evicted - prev.evicted}
	}
	g.refused, g.known = cur, true
	a.cur.refused.prehello += d.prehello
	a.cur.refused.total += d.total
	a.cur.refused.evicted += d.evicted
}

func (a *aggregator) ipCounters(g *genCounters, s *edgev1.SnapshotResponse, baseline bool, mode ipMode, now time.Time) {
	seen := map[ipKey]bool{}
	for _, ic := range s.GetIps() {
		k := ipKey{proxy: ic.GetProxyId(), ip: ic.GetIp()}
		seen[k] = true
		prev, ok := g.ips[k]
		var d uint64
		switch {
		case baseline:
		case !ok || ic.GetBytes() < prev:
			d = ic.GetBytes() // the edge started counting the address again
		default:
			d = ic.GetBytes() - prev
		}
		g.ips[k] = ic.GetBytes()
		if mode == modeOff {
			continue
		}
		at := ic.GetLastSeenUnix()
		if at == 0 {
			at = now.Unix()
		}
		if !a.cur.sighted(ic, d, at) {
			continue
		}
		a.cur.addr(k, d)
		if mode == modeFull {
			a.cur.sight(k, d, at)
		}
	}
	for k := range g.ips {
		if !seen[k] {
			delete(g.ips, k)
		}
	}
}

// sighted reports whether a client address counts as seen in the minute: it
// moved bytes, has a connection open, or was last seen within the minute.
func (m *minuteAcc) sighted(ic *edgev1.IpCounters, bytes uint64, at int64) bool {
	inMinute := at >= m.start && at < m.start+60
	return bytes > 0 || ic.GetConnsActive() > 0 || inMinute
}

// addr counts a sighted address for the countries of the minute.
func (m *minuteAcc) addr(k ipKey, bytes uint64) {
	if _, ok := m.addrs[k]; !ok && len(m.addrs) >= maxMinuteAddrs {
		m.overflow++
		return
	}
	m.addrs[k] += bytes
}

// sight records where a sighted client address was seen (policy full).
func (m *minuteAcc) sight(k ipKey, bytes uint64, at int64) {
	s := m.ips[k]
	if s == nil {
		if len(m.ips) >= maxSightings {
			m.dropped++
			return
		}
		s = &nodev1.IpSighting{ProxyId: k.proxy, Ip: k.ip, FirstSeen: at, LastSeen: at}
		m.ips[k] = s
	}
	s.FirstSeen = min(s.FirstSeen, at)
	s.LastSeen = max(s.LastSeen, at)
	s.Bytes += bytes
}

// memberHealth takes the egress members' health of the newest edge
// generation: the last status, the latency while up, the last exit IP.
func (m *minuteAcc) memberHealth(health []*edgev1.MemberHealth) {
	for _, h := range health {
		k := memberKey{chain: h.GetChainId(), member: h.GetMemberKey()}
		mm := m.members[k]
		if mm == nil {
			mm = &nodev1.MemberMinute{ChainId: k.chain, MemberKey: k.member}
			m.members[k] = mm
		}
		mm.Status = h.GetStatus()
		mm.LatencyMs = 0
		if mm.Status == "up" {
			mm.LatencyMs = h.GetLatencyMs()
		}
		if ip := h.GetExitIp(); ip != "" {
			mm.ExitIp = ip
		}
	}
}

// addProbe adds a probe result to the minute being collected; one over
// maxMinuteProbes is left out and reported false.
func (a *aggregator) addProbe(p *nodev1.ProbeResult) bool {
	list := &a.early
	if a.cur != nil {
		list = &a.cur.probes
	}
	if len(*list) >= maxMinuteProbes {
		return false
	}
	*list = append(*list, proto.Clone(p).(*nodev1.ProbeResult))
	return true
}

// limit drops from the minute being collected what mode no longer keeps:
// where addresses were seen below full, every address below countries.
func (a *aggregator) limit(mode ipMode) {
	if a.cur == nil {
		return
	}
	if mode < modeFull {
		a.cur.ips = map[ipKey]*nodev1.IpSighting{}
		a.cur.dropped = 0
	}
	if mode < modeCountries {
		a.cur.addrs = map[ipKey]uint64{}
		a.cur.overflow = 0
	}
}

func (a *aggregator) hostSample(h *hostSample) {
	m := a.cur
	if a.cpuTotal > 0 && h.cpuTotal > a.cpuTotal && h.cpuBusy >= a.cpuBusy {
		m.cpuBusy += h.cpuBusy - a.cpuBusy
		m.cpuTotal += h.cpuTotal - a.cpuTotal
	}
	a.cpuBusy, a.cpuTotal = h.cpuBusy, h.cpuTotal
	for name, cur := range h.net {
		prev, ok := a.netPrev[name]
		if !ok {
			continue // a new interface: from here on
		}
		m.netRx += counterDelta(prev.rx, cur.rx)
		m.netTx += counterDelta(prev.tx, cur.tx)
	}
	a.netPrev = maps.Clone(h.net)
	m.host = h
}

// counterDelta is the increment of a counter that may have started over.
func counterDelta(prev, cur uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

func satAdd32(a, b uint32) uint32 {
	if a > math.MaxUint32-b {
		return math.MaxUint32
	}
	return a + b
}

func clampUint32(n uint64) uint32 {
	return uint32(min(n, math.MaxUint32))
}

// batch is the minute as the panel gets it, or nil when it saw nothing.
// country names the country of an address (nil: none known).
func (m *minuteAcc) batch(country func(string) string) *nodev1.StatsBatch {
	b := &nodev1.StatsBatch{MinuteUnix: m.start}
	for _, id := range slices.Sorted(maps.Keys(m.proxies)) {
		p := m.proxies[id]
		b.Proxies = append(b.Proxies, &nodev1.ProxyMinute{
			ProxyId: id, Up: p.up, Down: p.down, ConnsNew: clampUint32(p.connsNew),
			ConnsPeak: p.peak, Devices: p.devices, ConnsActive: p.connsLast,
		})
	}
	for _, k := range slices.SortedFunc(maps.Keys(m.ips), func(x, y ipKey) int {
		return cmp.Or(strings.Compare(x.proxy, y.proxy), strings.Compare(x.ip, y.ip))
	}) {
		b.Ips = append(b.Ips, m.ips[k])
	}
	b.Countries = countryMinutes(m.addrs, country)
	for _, k := range slices.SortedFunc(maps.Keys(m.members), func(x, y memberKey) int {
		return cmp.Or(strings.Compare(x.chain, y.chain), strings.Compare(x.member, y.member))
	}) {
		b.Members = append(b.Members, m.members[k])
	}
	b.Probes = m.probes
	r := m.refused
	if h := m.host; h != nil || r != (refusals{}) {
		nm := &nodev1.NodeMinute{
			NetRx: m.netRx, NetTx: m.netTx, Conns: m.conns,
			RefusedPrehello: r.prehello, RefusedTotal: r.total, EvictedPrehello: r.evicted,
		}
		if h != nil {
			nm.MemUsed, nm.MemTotal, nm.Load1 = h.memUsed, h.memTotal, h.load1
			nm.DiskUsed, nm.DiskTotal = h.diskUsed, h.diskTotal
		}
		if m.cpuTotal > 0 {
			nm.Cpu = 100 * float64(m.cpuBusy) / float64(m.cpuTotal)
		}
		b.Node = nm
	}
	if len(b.Proxies) == 0 && len(b.Ips) == 0 && b.Node == nil && len(b.Countries) == 0 &&
		len(b.Members) == 0 && len(b.Probes) == 0 {
		return nil
	}
	return b
}

// countryMinutes groups the addresses of a minute by proxy and country: how
// many there were and their bytes. A proxy names at most maxCountries
// countries, those of the most bytes; the rest are summed under "" (unknown).
// Sorted by proxy, then country.
func countryMinutes(addrs map[ipKey]uint64, country func(string) string) []*nodev1.CountryMinute {
	type group struct {
		ips   uint32
		bytes uint64
	}
	byProxy := map[string]map[string]*group{}
	for k, bytes := range addrs {
		c := ""
		if country != nil {
			c = country(k.ip)
		}
		groups := byProxy[k.proxy]
		if groups == nil {
			groups = map[string]*group{}
			byProxy[k.proxy] = groups
		}
		g := groups[c]
		if g == nil {
			g = &group{}
			groups[c] = g
		}
		g.ips = satAdd32(g.ips, 1)
		g.bytes += bytes
	}
	var out []*nodev1.CountryMinute
	for _, proxy := range slices.Sorted(maps.Keys(byProxy)) {
		groups := byProxy[proxy]
		if len(groups) > maxCountries {
			named := slices.SortedFunc(maps.Keys(groups), func(x, y string) int {
				return cmp.Or(cmp.Compare(groups[y].bytes, groups[x].bytes), strings.Compare(x, y))
			})
			named = slices.DeleteFunc(named, func(c string) bool { return c == "" })
			rest := groups[""]
			if rest == nil {
				rest = &group{}
				groups[""] = rest
			}
			for _, c := range named[maxCountries-1:] {
				rest.ips = satAdd32(rest.ips, groups[c].ips)
				rest.bytes += groups[c].bytes
				delete(groups, c)
			}
		}
		for _, c := range slices.Sorted(maps.Keys(groups)) {
			g := groups[c]
			out = append(out, &nodev1.CountryMinute{ProxyId: proxy, Country: c, Ips: g.ips, Bytes: g.bytes})
		}
	}
	return out
}

// ---- host metrics ---------------------------------------------------------------

// hostSample is one reading of the host's counters (spec 5.8). The agent runs
// in the host's network and process namespaces, so /proc is the host's.
type hostSample struct {
	cpuBusy, cpuTotal   uint64 // clock ticks since boot, all CPUs
	memTotal, memUsed   uint64 // bytes; used = total - available
	load1               float64
	diskTotal, diskUsed uint64                 // bytes, the file system of POSTERN_HOME
	net                 map[string]netCounters // bytes by interface, without loopback and container plumbing
}

type netCounters struct{ rx, tx uint64 }

func (h *hostSample) ok() bool { return h.cpuTotal > 0 || h.memTotal > 0 }

// readHostSample reads the counters from proc (the /proc file system) and the
// use of the file system that holds diskPath. What cannot be read stays zero.
func readHostSample(proc fs.FS, diskPath string) hostSample {
	var h hostSample
	if data, err := fs.ReadFile(proc, "stat"); err == nil {
		h.cpuBusy, h.cpuTotal = parseProcStat(data)
	}
	if data, err := fs.ReadFile(proc, "meminfo"); err == nil {
		h.memTotal, h.memUsed = parseMeminfo(data)
	}
	if data, err := fs.ReadFile(proc, "loadavg"); err == nil {
		if f := strings.Fields(string(data)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil && v >= 0 && !math.IsInf(v, 0) {
				h.load1 = v
			}
		}
	}
	if data, err := fs.ReadFile(proc, "net/dev"); err == nil {
		h.net = parseNetDev(data)
	}
	h.diskTotal, h.diskUsed = diskUsage(diskPath)
	return h
}

// parseProcStat reads the "cpu" line: busy and total clock ticks.
func parseProcStat(data []byte) (busy, total uint64) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		// user nice system idle iowait irq softirq steal; guest time is in
		// user already.
		var v [8]uint64
		for i := 0; i < 8 && i+1 < len(f); i++ {
			v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
			total += v[i]
		}
		idle := v[3] + v[4]
		if idle > total {
			return 0, 0
		}
		return total - idle, total
	}
	return 0, 0
}

func parseMeminfo(data []byte) (total, used uint64) {
	var free, avail uint64
	hasAvail := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		switch key {
		case "MemTotal":
			total = v
		case "MemFree":
			free = v
		case "MemAvailable":
			avail, hasAvail = v, true
		}
	}
	if !hasAvail {
		avail = free
	}
	if avail > total {
		return total, 0
	}
	return total, total - avail
}

// parseNetDev reads /proc/net/dev: bytes received and sent by interface. The
// loopback and the plumbing of containers (veth pairs, bridges) are left
// out: their traffic is also on the real interfaces or never leaves the host.
func parseNetDev(data []byte) map[string]netCounters {
	out := map[string]netCounters{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[name] = netCounters{rx: rx, tx: tx}
	}
	return out
}

// ---- edge snapshots ---------------------------------------------------------------

// snapshotSource returns, for every edge generation whose control socket is
// there, its snapshot, or nil when it did not answer. The snapshots have the
// counters of the client IPs when ips is set.
type snapshotSource interface {
	take(ctx context.Context, ips bool) map[uint64]*edgev1.SnapshotResponse
}

// socketSnapshots finds the edge generations by their control sockets,
// data/run/edge-g<N>.sock: a socket is there for as long as its edge runs
// (and after a crash, until the edge comes up again).
type socketSnapshots struct {
	dir     string
	timeout time.Duration
	clients map[uint64]edgev1connect.EdgeControlServiceClient
}

func newSocketSnapshots(dir string, timeout time.Duration) *socketSnapshots {
	return &socketSnapshots{dir: dir, timeout: timeout, clients: map[uint64]edgev1connect.EdgeControlServiceClient{}}
}

func (s *socketSnapshots) take(ctx context.Context, ips bool) map[uint64]*edgev1.SnapshotResponse {
	out := map[uint64]*edgev1.SnapshotResponse{}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		num, ok := strings.CutPrefix(e.Name(), "edge-g")
		if !ok {
			continue
		}
		num, ok = strings.CutSuffix(num, ".sock")
		gen, err := strconv.ParseUint(num, 10, 64)
		if !ok || err != nil || gen == 0 || e.Type()&fs.ModeSocket == 0 {
			continue
		}
		c := s.clients[gen]
		if c == nil {
			c = control.NewClient(filepath.Join(s.dir, e.Name()))
			s.clients[gen] = c
		}
		cctx, cancel := context.WithTimeout(ctx, s.timeout)
		resp, err := c.Snapshot(cctx, connect.NewRequest(&edgev1.SnapshotRequest{IncludeIps: ips}))
		cancel()
		if err != nil {
			out[gen] = nil
			continue
		}
		out[gen] = resp.Msg
	}
	for gen := range s.clients {
		if _, there := out[gen]; !there {
			delete(s.clients, gen)
		}
	}
	return out
}

// ---- collector --------------------------------------------------------------------

// statsCollector takes an observation at every tick and publishes every
// finished minute. mu guards the aggregator, which the probes of the node
// and the changes of the IP policy reach as well.
type statsCollector struct {
	source   snapshotSource
	journal  *journal
	proc     fs.FS
	diskPath string
	mode     func() ipMode // what the node's IP policy lets the minute keep
	log      *slog.Logger

	mu  sync.Mutex
	agg *aggregator
	// The last minute that left addresses out of its countries, and how
	// many times it did (host.stats).
	overflowAt time.Time
	overflowN  int
}

// tick takes one observation, made at t. The edge is asked for the counters
// of the client IPs only when the IP policy uses them (M4); what the minute
// keeps of them is the least the policy allowed while the snapshots were
// taken, and what it allows when the minute goes out.
func (c *statsCollector) tick(ctx context.Context, t time.Time) {
	asked := c.mode()
	snaps := c.source.take(ctx, asked != modeOff)
	host := readHostSample(c.proc, c.diskPath)
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.agg.observe(t, snaps, &host, asked != modeOff, min(asked, c.mode()))
	if b == nil {
		return
	}
	// The policy may have gone down within the minute (limit took the open
	// minute's addresses then, and this is the last word).
	mode := c.mode()
	if mode < modeFull {
		b.Ips = nil
	} else if n := c.agg.dropped; n > 0 {
		c.log.Warn("agent: too many client addresses in a minute; the rest are left out", "minute", b.GetMinuteUnix(), "left_out", n)
	}
	if mode < modeCountries {
		b.Countries = nil
	} else if n := c.agg.overflow; n > 0 {
		// Once a minute at most: the minute that just closed.
		c.log.Warn("agent: too many client addresses in a minute for its countries; the rest are left out", "minute", b.GetMinuteUnix(), "left_out", n)
		c.overflowAt, c.overflowN = time.Unix(b.GetMinuteUnix(), 0), n
	}
	c.journal.stats(b)
}

// overflow is the last minute whose addresses went over the bound of its
// countries, and how many times one was left out; zero when none did.
func (c *statsCollector) overflow() (time.Time, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overflowAt, c.overflowN
}

// limit drops from the open minute what mode no longer keeps. A tick that
// is publishing a minute finishes first.
func (c *statsCollector) limit(mode ipMode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agg.limit(mode)
}

// addProbe adds the result of a probe the node ran to the open minute, at
// most maxMinuteProbes a minute.
func (c *statsCollector) addProbe(p *nodev1.ProbeResult) {
	c.mu.Lock()
	ok := c.agg.addProbe(p)
	c.mu.Unlock()
	if !ok {
		c.log.Warn("agent: too many probe results in a minute; the rest are left out", "proxy", clipText(p.GetProxyId(), 64))
	}
}

// run makes an observation at every tick until ctx ends or ticks is closed.
func (c *statsCollector) run(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-ticks:
			if !ok {
				return
			}
			c.tick(ctx, t)
		}
	}
}
