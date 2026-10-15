package reconcile

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/psiphoncore"
	"github.com/urbnywrt/postern/internal/providers/warp"
)

// The egress providers (spec 5.6). An egress of kind XRAY_URI,
// XRAY_SUBSCRIPTION, WARP or PSIPHON is served by a provider instance, a
// container of Xray or Psiphon with a SOCKS5 port on 127.0.0.1 per member,
// one instance per egress that a chain in use takes: a chain of an enabled
// proxy (its own, the node's default for one that names none, and its scope
// chains) or the node's default chain. A member is a member of every chain that
// lists the egress, in the order of the chain, and a subscription expands into
// its servers in its own order.
//
// An instance is made like an engine's (blue-green): a new generation gets new
// ports, its files and its container, and once its ports answer the edge gets
// the chains with them (SetConfig) and the old generation drains: it is
// removed two minutes later, the connections through it having had that time.
// What the instance runs is identified by a hash of its rendered files (with
// stand-ins for the ports and the paths, and the members in the order of their
// keys), the provider, its binary and the mounts; a member is keyed by its
// server (egressuri.Server.Key), so a subscription refreshed with the same
// servers, in whatever order and under whatever names, keeps its instance and
// the ports of its members.

const (
	// egressDrainAfter is how long a provider generation that the edge no longer
	// has in a chain keeps running for the connections through it.
	egressDrainAfter = 2 * time.Minute
	// defaultEgressReadyTimeout bounds the wait for the SOCKS ports of a new
	// provider generation. Psiphon is ready only once its tunnel is up.
	defaultEgressReadyTimeout = 90 * time.Second
	// maxEgressMembers bounds the members of an egress: a subscription may list
	// hundreds of servers, and each is a port, an outbound and a health check.
	maxEgressMembers = 64

	roleEgress = "egress"

	// warpAccountFile is the account of the WARP device of an egress, in its
	// state directory (state.Paths.EgressStateDir).
	warpAccountFile = "warp-account.json"
	// The keys of the one member of a WARP and of a PSIPHON egress.
	warpMemberKey    = "warp"
	psiphonMemberKey = "psiphon"
	// memberKeySep joins the id of an egress and the key of one of its members
	// into the key of the member in a chain of the edge.
	memberKeySep = "/"
	// warpPlusProvider is the binary name of warp-plus, which ran PSIPHON
	// egresses before Psiphon's own client did: a record of an older agent may
	// still name it for a generation that keeps a cache (egresscache.go).
	warpPlusProvider = "warp-plus"
)

// keepsCache reports whether the generations of a provider, by its binary
// name, each have a cache directory (egresscache.go).
func keepsCache(provider string) bool {
	return provider == psiphoncore.Binary || provider == warpPlusProvider
}

// Event kinds of the egresses.
const (
	evEgressStarting      = "egress_starting"
	evEgressServing       = "egress_serving"
	evEgressDraining      = "egress_draining"
	evEgressRemoved       = "egress_removed"
	evEgressFailed        = "egress_failed"
	evEgressMissing       = "egress_missing"
	evEgressRestarted     = "egress_restarted"
	evEgressMemberInvalid = "egress_member_invalid"
	evEgressMembersCapped = "egress_members_capped"
)

// isProviderKind reports whether egresses of kind k are served by a provider
// instance, and not by the edge itself.
func isProviderKind(k nodev1.EgressKind) bool {
	switch k {
	case nodev1.EgressKind_EGRESS_KIND_XRAY_URI, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
		nodev1.EgressKind_EGRESS_KIND_WARP, nodev1.EgressKind_EGRESS_KIND_PSIPHON:
		return true
	}
	return false
}

// providerMembers are the members of the chains of the edge for an egress of a
// provider: one socks5 member per member of its serving instance, on its port,
// keyed <egress id>/<member key>, in the order of the record; none while no
// instance serves it.
func providerMembers(id string, rec state.EgressRecord) []*edgev1.ChainMember {
	if rec.Generation == 0 {
		return nil
	}
	out := make([]*edgev1.ChainMember, 0, len(rec.Members))
	for _, m := range rec.Members {
		out = append(out, &edgev1.ChainMember{Key: id + memberKeySep + m.Key, Kind: "socks5", Addr: loopback(m.Port)})
	}
	return out
}

// usedChains are the chains in use: those of the enabled proxies (their own,
// or the node's default, and their scope chains) and the node's default chain.
func usedChains(st *nodev1.NodeState) map[string]bool {
	def := st.GetSettings().GetDefaultChainId()
	used := map[string]bool{}
	if def != "" {
		used[def] = true
	}
	for _, p := range st.GetProxies() {
		if !p.GetEnabled() {
			continue
		}
		used[cmp.Or(p.GetEgressChainId(), def)] = true
		for _, c := range p.GetEgressScopeChains() {
			used[c] = true
		}
	}
	delete(used, "")
	return used
}

// neededEgresses are the egresses of a provider that a chain in use takes, by
// id.
func neededEgresses(st *nodev1.NodeState) map[string]*nodev1.Egress {
	egresses := map[string]*nodev1.Egress{}
	for _, e := range st.GetEgresses() {
		egresses[e.GetId()] = e
	}
	used := usedChains(st)
	out := map[string]*nodev1.Egress{}
	for _, c := range st.GetChains() {
		if !used[c.GetId()] {
			continue
		}
		for _, id := range c.GetMemberEgressIds() {
			if e := egresses[id]; e != nil && isProviderKind(e.GetKind()) {
				out[id] = e
			}
		}
	}
	return out
}

// egressPlan is what the instance of an egress needs.
type egressPlan struct {
	egress   *nodev1.Egress
	driver   providers.Driver
	provider string // the provider's binary name: "xray", "psiphon-core"
	version  string
	sha      string // the checksum the desired state pins for the binary
	binary   string // host path of the binary
	// ref is the stored artifact, for its trial record (artifactgc.go).
	ref artifacts.Ref
	// members are the members that can be rendered, in the order of the chains.
	members []providers.Member
	country string // PSIPHON
	// propagationChannel and sponsor are the partner ids of a PSIPHON egress,
	// "" for the defaults.
	propagationChannel, sponsor string
	cache                       bool // PSIPHON: the instance has a cache of Psiphon's data (egresscache.go)
	hash                        string
	err                         error // the egress cannot have an instance now: why
}

func (p *pass) egressGenDir(id string, gen uint64) string {
	return filepath.Join(p.r.Store.Paths.EgressDir(id), "g"+genString(gen))
}

// convergeEgresses brings every egress of a provider to what the desired state
// wants of it: an instance for each one a chain in use takes, the drain of the
// others. It returns an error only for failures of the node's own machinery;
// an egress that cannot be served is reported and the pass goes on.
func (p *pass) convergeEgresses() error {
	needed := neededEgresses(p.st)
	for _, id := range slices.Sorted(maps.Keys(needed)) {
		if err := p.convergeEgress(id, needed[id]); err != nil {
			return err
		}
		if err := p.boundary(); err != nil {
			return err
		}
	}
	// The rest drain: a serving generation of an egress that no chain in use
	// takes leaves the chains with the next push.
	for _, id := range slices.Sorted(maps.Keys(p.rt.Egresses)) {
		rec := p.rt.Egresses[id]
		if needed[id] != nil || rec.Generation == 0 {
			continue
		}
		p.putEgressRecord(id, p.retireEgress(id, rec))
	}
	p.r.keepEgressStatus(p.egressStatusIDs(needed))
	// Forget the memory of egresses that are not needed.
	for id := range p.r.egressFailures {
		if needed[id] == nil {
			delete(p.r.egressFailures, id)
		}
	}
	for id := range p.r.warpFailures {
		if needed[id] == nil {
			delete(p.r.warpFailures, id)
		}
	}
	for key := range p.r.problems {
		if what, id, ok := strings.Cut(key, ":"); ok && isEgressProblem(what) && needed[id] == nil {
			delete(p.r.problems, key)
		}
	}
	return nil
}

// egressStatusIDs are the egresses that should have an instance status: the
// needed ones and those with instances left, serving or draining.
func (p *pass) egressStatusIDs(needed map[string]*nodev1.Egress) map[string]bool {
	ids := map[string]bool{}
	for id := range needed {
		ids[id] = true
	}
	for id, rec := range p.rt.Egresses {
		if rec.Generation > 0 || len(rec.Draining) > 0 {
			ids[id] = true
		}
	}
	return ids
}

// isEgressProblem reports whether a kind of problem (see Reconciler.problem) is
// one of an egress.
func isEgressProblem(what string) bool {
	switch what {
	case "egress", "invalid", "cap", "sub":
		return true
	}
	return false
}

// retireEgress moves the serving generation of an egress to the draining ones.
func (p *pass) retireEgress(id string, rec state.EgressRecord) state.EgressRecord {
	old := rec.Generation
	rec.Draining = append(rec.Draining, state.DrainingEgress{
		Generation: old, ContainerName: providers.ContainerName(id, old), Since: p.r.now(),
	})
	rec.Generation, rec.Hash, rec.Members, rec.ServingSince = 0, "", nil, time.Time{}
	rec.PreviousBinaryPath = previousBinary(rec.PreviousBinaryPath, rec.BinaryPath, "")
	rec.Provider, rec.Version, rec.BinaryPath = "", "", ""
	rec.LastGeneration = max(rec.LastGeneration, old)
	p.rt.Egresses[id] = rec
	p.reportEgress(id, nil, egressPhaseDraining, "no chain in use takes the egress", "")
	p.r.event(evEgressDraining, sevInfo, "", fmt.Sprintf("egress %s: generation %d drains: no chain in use takes the egress", id, old),
		map[string]string{"egress": id, "generation": genString(old)})
	return rec
}

// convergeEgress makes sure that the instance of a needed egress runs what it
// should.
func (p *pass) convergeEgress(id string, e *nodev1.Egress) error {
	rec := p.rt.Egresses[id]
	if rec.WARPDeletion != nil {
		// Used again, and its WARP device with it: a deletion that failed
		// before is over, and one that comes later starts afresh.
		rec.WARPDeletion = nil
		p.rt.Egresses[id] = rec
	}
	pl := p.planEgress(e)
	if pl.err != nil {
		if rec.Generation > 0 {
			p.egressProblem(id, "plan", pl.err.Error()+"; generation "+genString(rec.Generation)+" keeps serving")
		} else {
			p.egressProblem(id, "plan", pl.err.Error())
		}
		p.egressFailStatus(id, pl, rec, pl.err.Error())
		return nil
	}
	if rec.Generation > 0 && rec.Hash == pl.hash {
		// It runs what it should: the members keep their ports, and only their
		// order follows the subscription.
		rec.Members = orderMembers(rec.Members, pl.members)
		p.rt.Egresses[id] = rec
		delete(p.r.egressFailures, id)
		p.r.clearProblem("egress:" + id)
		p.reportEgress(id, pl, egressPhaseServing, "", "")
		return nil
	}
	if f, ok := p.r.egressFailures[id]; ok {
		if f.hash != pl.hash {
			delete(p.r.egressFailures, id) // another target: tried at once
		} else if p.r.now().Before(f.at.Add(orDefault(p.r.retryAfter, defaultRetryAfter))) {
			p.egressFailStatus(id, pl, rec, f.reason)
			return nil
		}
	}
	// A new generation runs the binary only once its trial passed; one that
	// serves is never touched by this.
	if v := p.checkArtifact(pl.ref, pl.driver); !v.ok {
		reason := v.reason
		if rec.Generation > 0 {
			reason += "; generation " + genString(rec.Generation) + " keeps serving"
		}
		if p.r.problem("egress:"+id, reason) {
			p.r.event(v.event(), v.severity(), "", fmt.Sprintf("egress %s: %s", id, reason),
				map[string]string{"egress": id, "step": "artifact", "engine": pl.provider, "version": pl.version, "arch": p.r.Arch})
		}
		p.egressFailStatus(id, pl, rec, v.reason)
		return nil
	}
	return p.egressBlueGreen(id, pl, rec)
}

// egressProblem reports, once while it lasts, that an egress cannot be served.
func (p *pass) egressProblem(id, step, reason string) {
	if !p.r.problem("egress:"+id, reason) {
		return
	}
	p.r.event(evEgressFailed, sevError, "", fmt.Sprintf("egress %s: %s", id, reason),
		map[string]string{"egress": id, "step": step})
}

// orderMembers returns the members of rec in the order of want, by key; the
// ports stay. A member of rec that want does not have keeps its place at the
// end (it cannot happen while the hashes are equal).
func orderMembers(rec []state.EgressMember, want []providers.Member) []state.EgressMember {
	byKey := map[string]state.EgressMember{}
	for _, m := range rec {
		byKey[m.Key] = m
	}
	out := make([]state.EgressMember, 0, len(rec))
	for _, m := range want {
		if r, ok := byKey[m.Key]; ok {
			out = append(out, r)
			delete(byKey, m.Key)
		}
	}
	for _, m := range rec {
		if _, left := byKey[m.Key]; left {
			out = append(out, m)
		}
	}
	return out
}

// planEgress works out the members of an egress, its binary and the hash of the
// instance it needs. A member that the provider cannot take is left out and
// reported; an egress that has none left cannot be served.
func (p *pass) planEgress(e *nodev1.Egress) *egressPlan {
	id := e.GetId()
	pl := &egressPlan{egress: e, driver: p.r.Providers[e.GetKind()]}
	if pl.driver == nil {
		pl.err = fmt.Errorf("no provider for egresses of kind %s", e.GetKind())
		return pl
	}
	if err := providers.CheckEgressID(id); err != nil {
		pl.err = err
		return pl
	}
	pl.provider = pl.driver.BinaryName()
	if _, err := pl.driver.ArtifactFile(p.r.Arch); err != nil {
		// The provider has no binary for this node (an architecture that it is not built for).
		pl.err = err
		return pl
	}
	pl.sha, pl.binary, pl.version, pl.ref = p.resolveProviderArtifact(pl.provider)
	if pl.binary == "" {
		pl.err = errors.New(pl.version) // the reason
		pl.version = ""
		return pl
	}
	rest, err := p.egressMembers(e)
	if err != nil {
		pl.err = err
		return pl
	}
	if e.GetKind() == nodev1.EgressKind_EGRESS_KIND_PSIPHON {
		params, err := state.ParsePsiphonParams(e.GetParamsJson())
		if err != nil {
			pl.err = err
			return pl
		}
		pl.country = params.Country
		pl.propagationChannel, pl.sponsor = params.PropagationChannelID, params.SponsorID
		pl.cache = true
	}

	// The members that can be rendered, maxEgressMembers at the most, in their
	// order: Render names those it cannot take, which are left out, and is
	// asked again with the next ones in their places.
	var members []providers.Member
	var invalid []*providers.MemberError
	var files map[string][]byte
	for {
		n := min(maxEgressMembers-len(members), len(rest))
		members, rest = append(members, rest[:n]...), rest[n:]
		if len(members) == 0 {
			break
		}
		files, err = pl.driver.Render(p.standIn(id, pl, members))
		if err == nil {
			break
		}
		merrs := providers.MemberErrors(err)
		bad := map[string]bool{}
		for _, me := range merrs {
			bad[me.Key] = true
		}
		before := len(members)
		members = slices.DeleteFunc(members, func(m providers.Member) bool { return bad[m.Key] })
		if len(members) == before {
			pl.err = fmt.Errorf("cannot render the instance: %w", err)
			return pl
		}
		invalid = append(invalid, merrs...)
	}
	p.reportInvalidMembers(id, invalid)
	if len(members) == 0 {
		pl.err = errors.New("no member that the provider can take")
		return pl
	}
	if left := len(rest); left > 0 {
		if p.r.problem("cap:"+id, strconv.Itoa(left)) {
			p.r.event(evEgressMembersCapped, sevWarning, "",
				fmt.Sprintf("egress %s: %d members at the most; %d servers are left out", id, maxEgressMembers, left),
				map[string]string{"egress": id, "left_out": strconv.Itoa(left)})
		}
	} else {
		p.r.clearProblem("cap:" + id)
	}
	pl.members = members
	pl.hash = egressHash(pl, p.r.RunnerImage, p.resolvConf() != "", files)
	return pl
}

// reportInvalidMembers reports the members left out, by key and field, never
// with their values: once while the set of them lasts.
func (p *pass) reportInvalidMembers(id string, invalid []*providers.MemberError) {
	var keys []string
	for _, me := range invalid {
		keys = append(keys, me.Key+":"+me.Field)
	}
	if len(keys) == 0 {
		p.r.clearProblem("invalid:" + id)
		return
	}
	if !p.r.problem("invalid:"+id, strings.Join(keys, ",")) {
		return
	}
	for _, me := range invalid {
		p.r.event(evEgressMemberInvalid, sevWarning, "",
			fmt.Sprintf("egress %s: member %s is left out: %s: %s", id, me.Key, me.Field, me.Reason),
			map[string]string{"egress": id, "member": me.Key, "field": me.Field})
	}
}

// standIn is the instance a plan is rendered as for its hash: stand-ins for
// the ports (by the order of the keys) and the paths, which change with every
// generation, and the members in the order of their keys, so that the order of
// a subscription is not part of what an instance runs.
func (p *pass) standIn(id string, pl *egressPlan, members []providers.Member) providers.Instance {
	ms := slices.Clone(members)
	slices.SortFunc(ms, func(a, b providers.Member) int { return strings.Compare(a.Key, b.Key) })
	for i := range ms {
		ms[i].Port = uint16(providers.MinPort + i)
	}
	in := providers.Instance{
		EgressID: id, Generation: 1, Kind: pl.egress.GetKind(), Members: ms, Country: pl.country,
		PropagationChannelID: pl.propagationChannel, SponsorID: pl.sponsor,
		InstanceDir: "/" + hashToken, BinaryPath: "/" + hashToken, RunnerImage: p.r.RunnerImage,
	}
	if pl.cache {
		in.CacheDir = "/" + hashToken
	}
	return in
}

// egressHash identifies what a provider instance runs: the provider, its
// version and the checksum of its binary, the image, the mounts, and the
// rendered files.
func egressHash(pl *egressPlan, runnerImage string, resolvConf bool, files map[string][]byte) string {
	h := sha256.New()
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	field("postern-egress-instance-v1")
	field(pl.provider)
	field(pl.version)
	field(pl.sha)
	field(runnerImage)
	field(pl.egress.GetKind().String())
	field(strconv.FormatBool(resolvConf))
	field(strconv.FormatBool(pl.cache))
	for _, name := range slices.Sorted(maps.Keys(files)) {
		field(name)
		field(string(files[name]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// egressMembers are the members of an egress, in the order of the chains,
// each once (by key).
func (p *pass) egressMembers(e *nodev1.Egress) ([]providers.Member, error) {
	switch e.GetKind() {
	case nodev1.EgressKind_EGRESS_KIND_XRAY_URI:
		params, err := state.ParseXrayURIParams(e.GetParamsJson())
		if err != nil {
			return nil, err
		}
		return []providers.Member{{Key: params.Server.Key(), Server: params.Server}}, nil
	case nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION:
		return p.subscriptionMembers(e)
	case nodev1.EgressKind_EGRESS_KIND_WARP:
		acct, err := p.warpAccount(e.GetId())
		if err != nil {
			return nil, err
		}
		return []providers.Member{{Key: warpMemberKey, WARP: acct}}, nil
	case nodev1.EgressKind_EGRESS_KIND_PSIPHON:
		return []providers.Member{{Key: psiphonMemberKey}}, nil
	}
	return nil, fmt.Errorf("egresses of kind %s have no provider", e.GetKind())
}

// serversToMembers makes members of servers, each once by its key (Key leaves
// the password out, so two accounts on one server are one member: Ruling
// S2-10), the first taking the place.
func serversToMembers(servers []*egressuri.Server) []providers.Member {
	seen := map[string]bool{}
	var out []providers.Member
	for _, s := range servers {
		if s == nil {
			continue
		}
		k := s.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, providers.Member{Key: k, Server: s})
	}
	return out
}

// warpAccount returns the account of the WARP device of an egress: the one in
// its file, or a new registration, kept in the state directory of the egress,
// which no container mounts (0700). A registration that failed is not tried
// again for a while: Cloudflare limits the rate of them.
func (p *pass) warpAccount(id string) (*warp.Account, error) {
	retry := orDefault(p.r.retryAfter, defaultRetryAfter)
	if f, ok := p.r.warpFailures[id]; ok && p.r.now().Before(f.at.Add(retry)) {
		return nil, errors.New(f.reason)
	}
	dir := p.r.Store.Paths.EgressStateDir(id)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, fmt.Errorf("the account directory of the WARP device: %w", err)
	}
	ctx, cancel := context.WithTimeout(p.ctx, warpTimeout)
	defer cancel()
	acct, err := p.r.loadOrRegisterWARP(ctx, filepath.Join(dir, warpAccountFile))
	if err != nil {
		err = fmt.Errorf("the WARP device: %w", err) // never holds a credential
		if p.ctx.Err() == nil {
			p.r.warpFailures[id] = failure{at: p.r.now(), reason: err.Error()}
		}
		return nil, err
	}
	delete(p.r.warpFailures, id)
	return acct, nil
}

// warpTimeout bounds the registration of a WARP device (two requests of 15 s at
// the most) and its deletion.
const warpTimeout = time.Minute

// ensurePrivateDir makes dir, and its parents, with mode 0700 for dir itself.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700) //nolint:gosec // a directory: 0700 is the least that lets its owner in
}

// resolveProviderArtifact finds the stored binary of a provider for the node's
// architecture: the first artifact of the desired state for the provider (its
// binary name) and the architecture. It returns its checksum, host path,
// version and store reference, or "", "" and why the binary is missing.
func (p *pass) resolveProviderArtifact(provider string) (sha, path, version string, ref artifacts.Ref) {
	for _, a := range p.st.GetArtifacts() {
		if !strings.EqualFold(a.GetEngine(), provider) || a.GetArch() != p.r.Arch {
			continue
		}
		ref = artifacts.Ref{
			Engine: a.GetEngine(), Version: a.GetVersion(), Arch: a.GetArch(), SHA256: a.GetSha256(),
			FileName: a.GetFileName(), Binary: cmp.Or(a.GetBinary(), provider),
		}
		if !p.r.Artifacts.Has(ref) {
			p.wantDownload(a, ref)
			return "", "", fmt.Sprintf("artifact missing: %s %s for %s is not on the node (or does not match its checksum)", provider, a.GetVersion(), p.r.Arch), artifacts.Ref{}
		}
		return strings.ToLower(a.GetSha256()), p.r.Artifacts.BinaryPath(ref), a.GetVersion(), ref
	}
	return "", "", fmt.Sprintf("artifact missing: the desired state names no artifact of %s for %s", provider, p.r.Arch), artifacts.Ref{}
}

// nextEgressGeneration is one more than every generation the egress ever had.
func (p *pass) nextEgressGeneration(id string, rec state.EgressRecord) uint64 {
	g := max(rec.Generation, rec.LastGeneration)
	for _, d := range rec.Draining {
		g = max(g, d.Generation)
	}
	for cg := range p.egressContainers[id] {
		g = max(g, cg)
	}
	return g + 1
}

// egressBlueGreen starts a new generation of an egress's instance beside the
// one that serves (if any), waits until its SOCKS ports answer, and then gives
// the edge its ports; the old generation drains. Whatever fails before removes
// the new generation and leaves the old one serving.
func (p *pass) egressBlueGreen(id string, pl *egressPlan, rec state.EgressRecord) error {
	gen := p.nextEgressGeneration(id, rec)
	rec.LastGeneration = gen
	p.rt.Egresses[id] = rec // the number is used, whatever happens next
	name := providers.ContainerName(id, gen)
	log := p.r.log().With("egress", id, "generation", gen)
	created := false
	cleanup := func() {
		if created {
			if err := p.removeContainer(name, true); err != nil {
				log.Warn("could not remove a failed egress generation", "err", err)
			}
		}
		p.forgetEgressInstance(id, gen)
	}
	abort := func(err error, backoff bool) {
		cleanup()
		if p.ctx.Err() != nil {
			return // shutting down: not the provider's fault
		}
		if backoff {
			p.r.egressFailures[id] = failure{hash: pl.hash, at: p.r.now(), reason: err.Error()}
		}
		verb := "could not start"
		if rec.Generation > 0 {
			verb = "could not start, generation " + genString(rec.Generation) + " keeps serving"
		}
		p.egressProblem(id, "start", fmt.Sprintf("generation %d %s: %v", gen, verb, err))
		p.egressFailStatus(id, pl, rec, err.Error())
	}

	in := providers.Instance{
		EgressID: id, Generation: gen, Kind: pl.egress.GetKind(), Country: pl.country,
		PropagationChannelID: pl.propagationChannel, SponsorID: pl.sponsor,
		InstanceDir: p.egressGenDir(id, gen),
		BinaryPath:  pl.binary, RunnerImage: p.r.RunnerImage, ResolvConf: p.resolvConf(),
	}
	ports := map[string]uint16{}
	for _, m := range pl.members {
		port, err := p.r.alloc().Alloc(p.rt, state.EgressPortKey(id, gen, m.Key), state.RangeEgressSocks)
		if err != nil {
			abort(fmt.Errorf("allocating ports: %w", err), false)
			return nil
		}
		ports[m.Key] = port
		m.Port = port
		in.Members = append(in.Members, m)
	}
	slices.SortFunc(in.Members, func(a, b providers.Member) int { return strings.Compare(a.Key, b.Key) })

	// The cache first: what Render writes may name it (Psiphon's data root).
	if pl.cache {
		dir, err := p.seedCache(id, gen)
		if err != nil {
			abort(fmt.Errorf("the cache directory: %w", err), false)
			return nil
		}
		in.CacheDir = dir
	}
	files, err := pl.driver.Render(in)
	if err != nil {
		abort(fmt.Errorf("rendering the config: %w", err), false)
		return nil
	}
	owned, _ := pl.driver.(providers.RunnerOwnedFiles)
	if err := p.writeEgressDir(in.InstanceDir, files, owned != nil && owned.FilesOwnedByRunner()); err != nil {
		abort(fmt.Errorf("writing the instance files: %w", err), false)
		return nil
	}
	if err := in.CheckHostPaths(); err != nil {
		abort(err, false)
		return nil
	}
	if err := p.ensureImage(); err != nil {
		cleanup()
		return err
	}
	spec := pl.driver.Container(in)
	spec.Name = name
	if spec.Labels == nil {
		spec.Labels = map[string]string{}
	}
	spec.Labels[labelManaged], spec.Labels[labelRole] = "true", roleEgress
	spec.Labels[labelID], spec.Labels[labelGeneration] = id, genString(gen)
	created, err = p.createAndStart(spec)
	if err != nil {
		abort(err, false)
		return nil
	}
	p.r.event(evEgressStarting, sevInfo, "", fmt.Sprintf("egress %s: generation %d started (%s %s, %d members)", id, gen, pl.provider, pl.version, len(in.Members)),
		map[string]string{"egress": id, "generation": genString(gen), "provider": pl.provider, "version": pl.version})
	if rec.Generation > 0 {
		p.reportEgress(id, pl, egressPhaseServing, "starting generation "+genString(gen), "")
	} else {
		p.reportEgress(id, pl, egressPhaseStarting, "starting generation "+genString(gen), "")
	}

	if err := p.waitEgressReady(pl.driver, in, name); err != nil {
		abort(err, true)
		return p.ctx.Err()
	}

	// The switch: the record first, then the edge.
	next := state.EgressRecord{
		Generation: gen, Hash: pl.hash, Provider: pl.provider, Version: pl.version, BinaryPath: pl.binary,
		ServingSince: p.r.now(), Draining: rec.Draining, LastGeneration: gen,
		PreviousBinaryPath:  previousBinary(rec.PreviousBinaryPath, rec.BinaryPath, pl.binary),
		SubscriptionFetched: rec.SubscriptionFetched, SubscriptionURL: rec.SubscriptionURL, SubscriptionNonce: rec.SubscriptionNonce,
	}
	for _, m := range pl.members {
		next.Members = append(next.Members, state.EgressMember{Key: m.Key, Port: ports[m.Key]})
	}
	if rec.Generation > 0 {
		next.Draining = append(slices.Clone(rec.Draining), state.DrainingEgress{
			Generation: rec.Generation, ContainerName: providers.ContainerName(id, rec.Generation), Since: p.r.now(),
		})
	}
	p.rt.Egresses[id] = next
	delete(p.r.egressFailures, id)
	p.r.clearProblem("egress:" + id)
	p.reportEgress(id, pl, egressPhaseServing, "", "")
	if err := p.saveRuntime(); err != nil {
		return err
	}
	if err := p.pushEdgeConfig(); err != nil {
		return err
	}
	msg := fmt.Sprintf("egress %s: generation %d serves", id, gen)
	if rec.Generation > 0 {
		msg += fmt.Sprintf("; generation %d drains", rec.Generation)
		p.r.event(evEgressDraining, sevInfo, "", fmt.Sprintf("egress %s: generation %d drains", id, rec.Generation),
			map[string]string{"egress": id, "generation": genString(rec.Generation)})
	}
	p.r.event(evEgressServing, sevInfo, "", msg, map[string]string{"egress": id, "generation": genString(gen)})
	return nil
}

// waitEgressReady polls the provider until every member port answers, and
// fails at once when its container stops on the way.
func (p *pass) waitEgressReady(d providers.Driver, in providers.Instance, name string) error {
	timeout := orDefault(p.r.egressReadyTimeout, defaultEgressReadyTimeout)
	ctx, cancel := context.WithTimeout(p.ctx, timeout)
	defer cancel()
	var last error
	for {
		if err := p.checkContainer(ctx, name, "provider"); err != nil {
			return err
		}
		if last = d.Ready(ctx, in); last == nil {
			return nil
		}
		if err := sleep(ctx, orDefault(p.r.readyPoll, defaultReadyPoll)); err != nil {
			if p.ctx.Err() != nil {
				return p.ctx.Err()
			}
			return fmt.Errorf("the provider is not ready after %v: %v", timeout, last)
		}
	}
}

// ---- files ------------------------------------------------------------------

// writeEgressDir creates the directory of a provider generation with the
// rendered files, as writeInstanceDir does for an engine (Ruling 14): the
// directory root:65534 0750, the files root:65534 0640 (they hold credentials).
// The directory of the egress above it is root's alone (0700): only the
// generation's directory and the cache are mounted into a container. A
// leftover directory of the same name is replaced. With runnerOwned the files
// are 65534's, 0600 (providers.RunnerOwnedFiles).
func (p *pass) writeEgressDir(dir string, files map[string][]byte, runnerOwned bool) error {
	mode, uid := os.FileMode(instanceFileMode), 0
	if runnerOwned {
		mode, uid = 0o600, engineUID
	}
	if err := ensurePrivateDir(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := p.mkdirOwned(dir, instanceDirMode, 0, engineGID); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if !filepath.IsLocal(name) || strings.ContainsRune(name, filepath.Separator) || strings.Contains(name, "/") {
			return fmt.Errorf("the provider rendered a file outside the instance directory: %q", name)
		}
		path := filepath.Join(dir, name)
		if err := writePrivateFile(path, files[name], mode); err != nil {
			return err
		}
		if err := p.chown(path, uid, engineGID); err != nil {
			return err
		}
	}
	return nil
}

// ---- adoption -----------------------------------------------------------------

// adoptEgresses squares the record of the egresses with the provider
// containers that exist, as adoptEngines does for the engines: a serving
// generation whose container is gone is forgotten (the egress gets a new one),
// a stopped one is started again, draining generations whose container is gone
// are forgotten, and containers the record does not know are removed.
func (p *pass) adoptEgresses() {
	for _, id := range slices.Sorted(maps.Keys(p.rt.Egresses)) {
		rec := p.rt.Egresses[id]
		if rec.Generation > 0 {
			gen := rec.Generation
			c, ok := p.egressContainers[id][gen]
			drop := func(why string) {
				p.r.event(evEgressMissing, sevWarning, "",
					fmt.Sprintf("egress %s: the container of generation %d %s; a new generation will be started", id, gen, why),
					map[string]string{"egress": id, "generation": genString(gen)})
				p.forgetEgressInstance(id, gen)
				rec.Generation, rec.Hash, rec.Members, rec.ServingSince = 0, "", nil, time.Time{}
				rec.LastGeneration = max(rec.LastGeneration, gen)
			}
			switch {
			case !ok:
				drop("is gone")
			case c.State == "dead" || c.State == "removing":
				p.removeEgressContainer(id, gen, c.Name)
				drop("is dead")
			case c.State == "created" || c.State == "exited":
				// Docker would make a missing bind source an empty root-owned
				// directory: the binary, the files and Psiphon's cache are
				// checked first.
				in := providers.Instance{BinaryPath: rec.BinaryPath, InstanceDir: p.egressGenDir(id, gen)}
				if keepsCache(rec.Provider) {
					in.CacheDir = p.cacheGenDir(id, gen)
				}
				err := in.CheckHostPaths()
				if err == nil {
					ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
					err = p.r.Docker.Start(ctx, c.Name)
					cancel()
				}
				if err != nil {
					p.removeEgressContainer(id, gen, c.Name)
					drop(fmt.Sprintf("was not running and cannot be started again (%v)", err))
				} else {
					p.r.event(evEgressRestarted, sevWarning, "",
						fmt.Sprintf("egress %s: generation %d was not running and was started again", id, gen),
						map[string]string{"egress": id, "generation": genString(gen)})
				}
			}
		}
		var keep []state.DrainingEgress
		for _, d := range rec.Draining {
			if _, ok := p.egressContainers[id][d.Generation]; ok {
				keep = append(keep, d)
				continue
			}
			p.forgetEgressInstance(id, d.Generation)
		}
		rec.Draining = keep
		p.rt.Egresses[id] = rec
	}

	for _, id := range slices.Sorted(maps.Keys(p.egressContainers)) {
		for _, gen := range slices.Sorted(maps.Keys(p.egressContainers[id])) {
			if p.knownEgress(id, gen) {
				continue
			}
			c := p.egressContainers[id][gen]
			if err := p.removeContainer(c.Name, false); err != nil {
				p.r.log().Warn("could not remove an unknown egress container", "container", c.Name, "err", err)
				continue
			}
			if _, ok := p.rt.Egresses[id]; ok {
				p.removeEgressGenDir(id, gen)
			}
			p.r.event(evOrphanRemoved, sevInfo, "",
				fmt.Sprintf("removed the egress container %s that the runtime record does not know", c.Name),
				map[string]string{"container": c.Name, "egress": id})
		}
	}
}

// removeEgressContainer removes the container of a generation that is being
// given up, and takes it out of the inventory.
func (p *pass) removeEgressContainer(id string, gen uint64, name string) {
	if err := p.removeContainer(name, false); err != nil {
		p.r.log().Warn("could not remove an egress container", "container", name, "err", err)
		return
	}
	delete(p.egressContainers[id], gen)
}

// knownEgress reports whether the record has generation gen of an egress,
// serving or draining.
func (p *pass) knownEgress(id string, gen uint64) bool {
	rec, ok := p.rt.Egresses[id]
	if !ok {
		return false
	}
	if rec.Generation == gen {
		return true
	}
	for _, d := range rec.Draining {
		if d.Generation == gen {
			return true
		}
	}
	return false
}

// forgetEgressInstance releases the ports and removes the files of a provider
// generation, its cache too unless that is the canonical cache.
func (p *pass) forgetEgressInstance(id string, gen uint64) {
	prefix := state.EgressPortPrefix(id, gen)
	for key := range p.rt.Ports {
		if strings.HasPrefix(key, prefix) {
			p.r.alloc().Release(p.rt, key)
		}
	}
	p.removeEgressGenDir(id, gen)
	p.removeCache(id, gen)
	delete(p.r.policyOff, providers.ContainerName(id, gen))
}

func (p *pass) removeEgressGenDir(id string, gen uint64) {
	if err := os.RemoveAll(p.egressGenDir(id, gen)); err != nil {
		p.r.log().Warn("could not remove the directory of an egress generation", "egress", id, "generation", gen, "err", err)
	}
}

// putEgressRecord stores the record of an egress.
func (p *pass) putEgressRecord(id string, rec state.EgressRecord) {
	p.rt.Egresses[id] = rec
}

// ---- drain and removal ------------------------------------------------------------

// drainEgresses removes the draining provider generations whose two minutes
// are over, and forgets the egresses that are no longer desired once their
// last generation is gone: the device of a WARP egress is deleted at
// Cloudflare, and the directories of the egress go.
func (p *pass) drainEgresses() {
	p.retryPsiphonDevices()
	now := p.r.now()
	desired := map[string]bool{}
	for _, e := range p.st.GetEgresses() {
		desired[e.GetId()] = true
	}
	for _, id := range slices.Sorted(maps.Keys(p.rt.Egresses)) {
		rec := p.rt.Egresses[id]
		var keep []state.DrainingEgress
		for _, d := range rec.Draining {
			name := cmp.Or(d.ContainerName, providers.ContainerName(id, d.Generation))
			p.restartOff(name)
			if now.Sub(d.Since) < egressDrainAfter {
				keep = append(keep, d)
				continue
			}
			if err := p.removeContainer(name, true); err != nil {
				p.r.log().Warn("could not remove a draining egress generation", "egress", id, "generation", d.Generation, "err", err)
				keep = append(keep, d)
				continue
			}
			p.forgetEgressInstance(id, d.Generation)
			p.r.event(evEgressRemoved, sevInfo, "", fmt.Sprintf("egress %s: generation %d removed", id, d.Generation),
				map[string]string{"egress": id, "generation": genString(d.Generation)})
		}
		rec.Draining = keep
		p.rt.Egresses[id] = rec
		if !desired[id] && rec.Generation == 0 && len(rec.Draining) == 0 {
			p.forgetEgress(id)
			continue
		}
		p.tidyCaches(id, rec)
	}
	p.r.keepEgressStatus(p.egressStatusIDs(neededEgresses(p.st)))
}

// forgetEgress removes what is left of an egress that is no longer desired and
// has no generation: the WARP device it registered (the device of a
// registration that never completed too), its account, its cached
// subscription, the cache of Psiphon, and its record. While the device is not
// deleted, all of it stays, and the deletion is tried again later
// (deleteWARPDevice).
func (p *pass) forgetEgress(id string) {
	if !p.deleteWARPDevice(id) {
		return
	}
	p.releaseEgressDevices(id)
	paths := p.r.Store.Paths
	for _, dir := range []string{paths.EgressStateDir(id), paths.EgressDir(id)} {
		if err := os.RemoveAll(dir); err != nil {
			p.r.log().Warn("could not remove a directory of a deleted egress", "egress", id, "dir", filepath.Base(dir), "err", err)
		}
	}
	delete(p.rt.Egresses, id)
}

// gcEgressPorts releases egress ports that belong to no serving or draining
// generation (left by a crash).
func (p *pass) gcEgressPorts() {
	live := map[string]bool{}
	for id, rec := range p.rt.Egresses {
		if rec.Generation > 0 {
			live[state.EgressPortPrefix(id, rec.Generation)] = true
		}
		for _, d := range rec.Draining {
			live[state.EgressPortPrefix(id, d.Generation)] = true
		}
	}
	for key := range p.rt.Ports {
		if !strings.HasPrefix(key, "egr:") {
			continue
		}
		if i := strings.LastIndexByte(key, ':'); i < 0 || !live[key[:i+1]] {
			p.r.alloc().Release(p.rt, key)
		}
	}
}

// sweepEgressDirs removes the directories of provider generations that the
// record does not have (left by a crash), and the directories of egresses
// that are neither desired nor recorded. The directory of a desired egress
// keeps its cached subscription and its cache.
func (p *pass) sweepEgressDirs() {
	keep := map[string]bool{} // the directories of the egresses, by name
	for _, e := range p.st.GetEgresses() {
		keep[filepath.Base(p.r.Store.Paths.EgressDir(e.GetId()))] = true
	}
	ids := map[string]string{} // directory name → egress id, for the recorded ones
	for id := range p.rt.Egresses {
		name := filepath.Base(p.r.Store.Paths.EgressDir(id))
		keep[name] = true
		ids[name] = id
	}
	root := p.r.Store.Paths.InstancesDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, "egr-") {
			continue
		}
		if !keep[name] {
			if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
				p.r.log().Warn("could not remove the directory of an unknown egress", "dir", name, "err", err)
			}
			continue
		}
		id, recorded := ids[name]
		if !recorded {
			continue
		}
		subs, err := os.ReadDir(filepath.Join(root, name))
		if err != nil {
			continue
		}
		for _, s := range subs {
			gen, ok := generationDir(s.Name())
			if !s.IsDir() || !ok || p.knownEgress(id, gen) {
				continue
			}
			if err := os.RemoveAll(filepath.Join(root, name, s.Name())); err != nil {
				p.r.log().Warn("could not remove a stale egress generation directory", "egress", id, "dir", s.Name(), "err", err)
			}
		}
	}
}

// generationDir reads the name of the directory of a provider generation,
// g<digits>.
func generationDir(name string) (uint64, bool) {
	digits, ok := strings.CutPrefix(name, "g")
	if !ok || digits == "" {
		return 0, false
	}
	gen, err := strconv.ParseUint(digits, 10, 64)
	return gen, err == nil && gen > 0
}
