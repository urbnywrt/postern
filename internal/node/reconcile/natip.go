package reconcile

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/node/state"
)

// The NAT address of the middle proxy (spec 5.5, Ruling S2-15). A proxy that
// uses the middle proxy and names no nat_ip presents the exit address of its
// way to the middle proxies: the first member that the edge reports up of the
// chain that its middle-proxy traffic takes, its scope chain "me" when it has
// one, its own chain (or the node's default) otherwise. Only a public IPv4
// address counts: the middle proxies are reached over IPv4.
//
// What a new generation renders with, in this order:
//
//  1. the exit address. A generation that has no NAT address of its own to
//     keep (a first generation, or the serving one rendered without one: the
//     middle proxy was off, the proxy named its own, or none was known) takes
//     the one the edge reports now, as soon as it is known. One that has an
//     address changes it only for an exit address reported by two
//     observations in a row (one per pass, and per check of the edge: two
//     passes that read the same check are one observation), and an engine is
//     rolled from one address to another once per natRollEvery at the most,
//     a limit that starts afresh with the agent: an exit address that comes
//     and goes does not roll the engine every time;
//  2. the address of the generation that serves, while no exit address is
//     known: members that are down, or checked anew after a roll of the edge or
//     of a provider, do not roll the engine;
//  3. for a chain of direct members only (Ruling S2-15), the address the node
//     itself goes out from: the source address of the first member when it is
//     a public IPv4 address (bind_ip), the node's public IPv4 address
//     otherwise. A direct member bound to an interface goes out through a
//     tunnel: its chain waits for the exit address, as those of proxy and
//     provider members do;
//  4. none: no NAT line.

// natRollEvery is the least time between two generations of an engine that
// a change of its NAT address, from one address to another, makes. The agent
// keeps it in memory: it starts afresh when the agent starts.
const natRollEvery = 10 * time.Minute

// cgnat is the shared address space of carrier-grade NAT, which is no public
// address.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isPublicIPv4 reports whether a is a public IPv4 address (or such an address
// mapped into IPv6): global unicast, not private, not carrier-grade NAT.
func isPublicIPv4(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// meChain is the chain the middle-proxy traffic of a proxy takes.
func meChain(st *nodev1.NodeState, pr *nodev1.Proxy) string {
	exists := func(id string) bool {
		for _, c := range st.GetChains() {
			if c.GetId() == id {
				return true
			}
		}
		return false
	}
	if c := pr.GetEgressScopeChains()[egress.ScopeME]; c != "" && exists(c) {
		return c
	}
	return cmp.Or(pr.GetEgressChainId(), st.GetSettings().GetDefaultChainId())
}

// exitIPv4 is the exit address of the first member of chain that is up in the
// health hs (in the order of the chain, as the edge reports it): a public IPv4
// address, "" when that member has none, or no member is up; and when the
// edge checked that member last, 0 when it does not say or no member is up.
func exitIPv4(hs []*edgev1.MemberHealth, chain string) (string, int64) {
	for _, h := range hs {
		if h.GetChainId() != chain || h.GetStatus() != "up" {
			continue
		}
		a, err := netip.ParseAddr(h.GetExitIp())
		if err != nil || !isPublicIPv4(a) {
			return "", h.GetCheckedUnix()
		}
		return a.Unmap().String(), h.GetCheckedUnix()
	}
	return "", 0
}

// exitObservation is what the agent saw of the exit address of a chain: the
// address in the last two observations, and when the edge checked the member
// of the last one (0 when it is not known).
type exitObservation struct {
	prev, cur string
	checked   int64
}

// observeExits takes the exit address of every chain from the health hs that
// the current edge reports: one observation, of which the last two are kept
// (see natAddress), unless it is the check of the edge that the last one was.
func (r *Reconciler) observeExits(st *nodev1.NodeState, hs []*edgev1.MemberHealth) {
	seen := make(map[string]exitObservation, len(st.GetChains()))
	for _, c := range st.GetChains() {
		id := c.GetId()
		old := r.exitSeen[id]
		exit, checked := exitIPv4(hs, id)
		if checked != 0 && checked == old.checked && exit == old.cur {
			seen[id] = old // the same check again: no new observation
			continue
		}
		seen[id] = exitObservation{prev: old.cur, cur: exit, checked: checked}
	}
	r.exitSeen = seen
}

// exitOf is the exit address of a chain in the last observation, and whether
// the observation before had the same.
func (r *Reconciler) exitOf(chain string) (exit string, steady bool) {
	seen := r.exitSeen[chain]
	return seen.cur, seen.cur != "" && seen.prev == seen.cur
}

// directSource is the address that the traffic of a chain of direct members
// goes out from, when no exit address is known: the source address of its
// first member when that is a public IPv4 address, else the node's public
// IPv4 address. It is "" for a chain with a member that is not direct, or
// that is bound to an interface (see above), or with no member at all.
func (p *pass) directSource(chain string) string {
	egresses := map[string]*nodev1.Egress{}
	for _, e := range p.st.GetEgresses() {
		egresses[e.GetId()] = e
	}
	var members []string
	for _, c := range p.st.GetChains() {
		if c.GetId() == chain {
			members = c.GetMemberEgressIds()
		}
	}
	if len(members) == 0 {
		return ""
	}
	first := ""
	for i, id := range members {
		e := egresses[id]
		if e.GetKind() != nodev1.EgressKind_EGRESS_KIND_DIRECT {
			return ""
		}
		params, err := state.ParseDirectParams(e.GetParamsJson())
		if err != nil || params.Interface != "" {
			return ""
		}
		if a, err := netip.ParseAddr(params.BindIP); i == 0 && err == nil && isPublicIPv4(a) {
			first = a.Unmap().String()
		}
	}
	if first != "" {
		return first
	}
	return p.r.publicIPv4()
}

// natAddress is the NAT address a new generation of proxy pr renders with,
// when it uses the middle proxy and names none (see above).
func (p *pass) natAddress(pr *nodev1.Proxy) string {
	chain := meChain(p.st, pr)
	exit, steady := p.r.exitOf(chain)
	have := p.rt.Instances[pr.GetId()].NatIP // that of the serving generation
	if have == "" {
		// Nothing to keep: no damping holds back a missing address.
		if exit != "" {
			return exit
		}
		return p.directSource(chain)
	}
	if exit == "" || !steady || p.r.natRolledRecently(pr.GetId()) {
		return have
	}
	return exit
}

// natRolledRecently reports whether the NAT address of a proxy made a new
// generation of its engine within natRollEvery.
func (r *Reconciler) natRolledRecently(id string) bool {
	at, ok := r.natRolls[id]
	return ok && r.now().Before(at.Add(natRollEvery))
}

// natChanged reports whether the NAT address of a proxy that uses the middle
// proxy is not the one its plan has: the health of the edge has changed since.
func (p *pass) natChanged() bool {
	for id, pl := range p.plans {
		pr := p.proxies[id]
		if pr == nil || !pr.GetUseMiddleProxy() || pr.GetNatIp() != "" || pl.err != nil {
			continue
		}
		if p.natAddress(pr) != pl.proxy.GetNatIp() {
			return true
		}
	}
	return false
}

// observeEgress takes the health of the members from the current edge (its
// events with it, and an observation of the exit addresses), and plans again
// when a NAT address has changed. An edge that does not answer leaves the
// health as it was, and makes no observation.
func (p *pass) observeEgress() error {
	ctx, cancel := context.WithTimeout(p.ctx, edgeCallTimeout)
	snap, err := p.edge.Snapshot(ctx)
	cancel()
	if err != nil {
		p.r.log().Warn("could not read the health of the egress members", "edge_generation", p.edgeGen, "err", err)
		return nil
	}
	p.r.setEgressHealth(snap.GetHealth())
	p.r.observeExits(p.st, snap.GetHealth())
	for id := range p.r.natRolls {
		if !p.r.natRolledRecently(id) {
			delete(p.r.natRolls, id)
		}
	}
	if p.natChanged() {
		return p.plan()
	}
	return nil
}

// ---- the events of the members (Ruling 40) ---------------------------------------

// Event kinds of the members of the chains.
const (
	evEgressMemberDown = "egress_member_down"
	evEgressMemberUp   = "egress_member_up"
	evEgressFailover   = "egress_failover"
)

// healthEvents reports what changed between two reports of the edge's health:
// a member that went down or came back up, and a chain whose active member,
// the first that is not down (the one the edge dials first), changed. The first
// report of an agent process is the baseline and reports nothing.
func (r *Reconciler) healthEvents(hs []*edgev1.MemberHealth) {
	status := map[string]string{}
	chains := map[string][]string{} // member → its chains
	active := map[string]string{}   // chain → its active member, "" for none
	for _, h := range hs {
		k, c := h.GetMemberKey(), h.GetChainId()
		status[k] = h.GetStatus()
		chains[k] = append(chains[k], c)
		if _, seen := active[c]; !seen {
			active[c] = ""
		}
		if active[c] == "" && h.GetStatus() != "down" {
			active[c] = k
		}
	}
	if r.memberStatus != nil {
		for _, k := range slices.Sorted(maps.Keys(status)) {
			prev, known := r.memberStatus[k]
			details := map[string]string{"member": k, "chains": strings.Join(chains[k], ",")}
			switch {
			case !known || prev == status[k]:
			case status[k] == "down":
				r.event(evEgressMemberDown, sevWarning, "",
					fmt.Sprintf("egress member %s is down (chains %s)", k, details["chains"]), details)
			case status[k] == "up" && prev == "down":
				r.event(evEgressMemberUp, sevInfo, "",
					fmt.Sprintf("egress member %s is up again (chains %s)", k, details["chains"]), details)
			}
		}
		for _, c := range slices.Sorted(maps.Keys(active)) {
			prev, known := r.activeMember[c]
			if !known || prev == active[c] {
				continue
			}
			sev, to := sevWarning, active[c]
			if to == "" {
				sev, to = sevError, "no member: every member is down"
			}
			r.event(evEgressFailover, sev, "",
				fmt.Sprintf("chain %s: the connections go through %s now, no longer through %s", c, to, cmp.Or(prev, "no member")),
				map[string]string{"chain": c, "from": prev, "to": active[c]})
		}
	}
	r.memberStatus, r.activeMember = status, active
}
