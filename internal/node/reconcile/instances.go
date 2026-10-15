package reconcile

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/state"
)

// Ownership of the instance files (Ruling 14): the directory and the rendered
// files stay root's, readable by the engine's group; only data/, the engine's
// data_path, belongs to the engine. A compromised engine cannot rewrite its
// own configuration.
const (
	engineUID = 65534
	engineGID = 65534

	instanceDirMode  = 0o750 // root:65534
	instanceFileMode = 0o640 // root:65534
	dataDirName      = "data"
	dataDirMode      = 0o750 // 65534:65534
)

// probeSource is the client address in the PROXY header of the readiness
// probe: loopback, and a port no real client has.
var probeSource = netip.MustParseAddrPort("127.0.0.1:1")

// hashToken and the ports 1, 2, 3 stand in for what changes with every
// generation when the instance hash is computed.
const hashToken = "instance-hash"

// proxyPlan is what a proxy needs, computed once per pass.
type proxyPlan struct {
	proxy   *nodev1.Proxy // the desired proxy with its NAT address filled in
	driver  engines.Driver
	engine  string // "telemt"
	version string
	hash    string
	err     error // the proxy cannot be rendered

	sha        string // the checksum the desired state pins for the binary (lower case)
	binary     string // host path of the engine binary; empty when missing
	missingWhy string // why the artifact is missing
	// ref is the stored artifact, for its trial record (artifactgc.go); the
	// zero value when the binary is missing.
	ref artifacts.Ref
	// natIP is the NAT address of the middle proxy taken from the exit address
	// of the egress (natip.go), "" when the proxy names its own or has none.
	natIP string
	// fronting is the fronting address of an engine that fronts from the node
	// itself (mtg, fronting.go); the zero value for telemt.
	fronting netip.AddrPort
}

func engineName(e nodev1.Engine) string {
	return strings.ToLower(strings.TrimPrefix(e.String(), "ENGINE_"))
}

func engineContainerName(proxyID string, gen uint64) string {
	return "postern-eng-" + strings.ToLower(proxyID) + "-g" + genString(gen)
}

func instanceDirName(proxyID string, gen uint64) string {
	return "eng-" + strings.ToLower(proxyID) + "-g" + genString(gen)
}

func (p *pass) instanceDir(proxyID string, gen uint64) string {
	return filepath.Join(p.r.Store.Paths.InstancesDir(), instanceDirName(proxyID, gen))
}

// ---- plan -------------------------------------------------------------------

// plan allocates the test listeners' ports and works out what every proxy
// needs.
func (p *pass) plan() error {
	p.reserveListenerPorts()
	keep := map[string]bool{}
	for _, l := range p.st.GetListeners() {
		key := state.TestListenerPortKey(l.GetId())
		keep[key] = true
		if _, err := p.r.alloc().Alloc(p.rt, key, state.RangeService); err != nil {
			return fmt.Errorf("the test listener of %s: %w", l.GetId(), err)
		}
	}
	prefix := state.TestListenerPortKey("")
	for key := range p.rt.Ports {
		if strings.HasPrefix(key, prefix) && !keep[key] {
			p.r.alloc().Release(p.rt, key)
		}
	}

	shown := map[string]bool{}
	for _, pr := range p.sortedProxies() {
		pl := p.planProxy(pr)
		p.plans[pr.GetId()] = pl
		shown[pr.GetId()] = true
		rec := p.rt.Instances[pr.GetId()]
		if rec.Generation > 0 && pl.err == nil && rec.Hash == pl.hash {
			// The engine already is what the proxy wants, so whatever changed
			// lives in the edge alone: the route key follows the proxy at once
			// (a move to another listener needs no new generation).
			rec.ListenerID, rec.Domain = pr.GetListenerId(), pr.GetDomain()
			if rec.BinaryPath == "" {
				rec.BinaryPath = pl.binary
			}
			p.rt.Instances[pr.GetId()] = rec
		}
		switch {
		case !pr.GetEnabled():
			p.report(pr.GetId(), nodev1.ProxyPhase_PROXY_PHASE_PAUSED, "")
		case rec.Generation > 0 && pl.err == nil && rec.Hash == pl.hash:
			// The certificates step, next, decides a WEB proxy's status.
			p.report(pr.GetId(), nodev1.ProxyPhase_PROXY_PHASE_SERVING, "")
		case rec.Generation > 0:
			p.report(pr.GetId(), nodev1.ProxyPhase_PROXY_PHASE_SERVING, "an update is pending")
		default:
			p.report(pr.GetId(), nodev1.ProxyPhase_PROXY_PHASE_PENDING, "")
		}
	}
	for id, rec := range p.rt.Instances {
		if !shown[id] && (rec.Generation > 0 || len(rec.Draining) > 0) {
			p.report(id, nodev1.ProxyPhase_PROXY_PHASE_DRAINING, "the proxy was deleted")
			shown[id] = true
		}
	}
	p.r.keepStatus(shown)
	// Forget the memory of proxies that are gone, so that one added again
	// under the same id starts afresh.
	for id := range p.r.failures {
		if p.proxies[id] == nil {
			delete(p.r.failures, id)
		}
	}
	for key := range p.r.problems {
		if what, id, ok := strings.Cut(key, ":"); ok && isProxyProblem(what) && p.proxies[id] == nil {
			delete(p.r.problems, key)
		}
	}
	return nil
}

// reserveListenerPorts keeps the allocator off the ports of the listeners of
// the desired state: the validator refuses a listener in the node's internal
// ranges, and this is the second lock on the door, so that no test listener,
// engine or SOCKS port can ever be a listener's.
func (p *pass) reserveListenerPorts() {
	var ports []uint16
	for _, l := range p.st.GetListeners() {
		if port := l.GetPort(); port > 0 && port <= 65535 {
			ports = append(ports, uint16(port))
		}
	}
	p.r.alloc().Reserve(ports...)
}

// isProxyProblem reports whether a kind of problem (see problemKeys) is one of
// a proxy.
func isProxyProblem(what string) bool {
	switch what {
	case "render", "artifact", "start":
		return true
	}
	return false
}

// planProxy renders the proxy with stand-ins for the per-generation values to
// get the hash of the instance it needs, and finds its engine binary.
func (p *pass) planProxy(pr *nodev1.Proxy) *proxyPlan {
	pl := &proxyPlan{
		proxy:   proto.Clone(pr).(*nodev1.Proxy),
		driver:  p.r.Drivers[pr.GetEngine()],
		engine:  engineName(pr.GetEngine()),
		version: pr.GetEngineVersion(),
	}
	// The middle proxy needs the address it sees the proxy at when the proxy
	// names none: the exit address of its way to the middle proxies (natip.go).
	if pl.proxy.GetUseMiddleProxy() && pl.proxy.GetNatIp() == "" {
		pl.proxy.NatIp = p.natAddress(pr)
		pl.natIP = pl.proxy.GetNatIp()
	}
	if pl.driver == nil {
		pl.err = fmt.Errorf("no driver for engine %s", pr.GetEngine())
		return pl
	}
	// The vhost of a WEB proxy names the public address its domain points to
	// (web.go); until it is known the proxy cannot be rendered.
	if isWeb(pr) && pr.GetWeb() != nil {
		addr, err := p.webPublicAddr(pr)
		if err != nil {
			pl.err = err
			return pl
		}
		pl.proxy.Web.PublicAddr = addr
	}
	pl.sha, pl.binary, pl.missingWhy, pl.ref = p.resolveArtifact(pr, pl.driver)
	if frontsDirectly(pr.GetEngine()) && pr.GetEnabled() {
		front, err := p.frontingAddr(pr)
		if err != nil {
			pl.err = err
			return pl
		}
		pl.fronting = front
	}
	files, err := pl.driver.Render(engines.Instance{
		Proxy: pl.proxy, InstanceID: hashToken, ListenPort: 1, APIPort: 2, SocksPort: 3,
		APIToken: hashToken, InstanceDir: "/" + hashToken, BinaryPath: "/" + hashToken, RunnerImage: p.r.RunnerImage,
		FrontingAddr: pl.fronting,
	})
	if err != nil {
		pl.err = err
		return pl
	}
	var logEnv []string
	if ll, ok := pl.driver.(engines.LogLeveler); ok {
		logEnv = ll.LogEnv()
	}
	pl.hash = instanceHash(pl.engine, pl.version, pl.sha, p.r.RunnerImage, p.resolvConf() != "", logEnv, pl.proxy, files)
	return pl
}

// instanceHash identifies what an instance runs: the engine, its version and
// the checksum of its binary, the image of its container, the middle-proxy
// settings, the rendered files, whether the container mounts the resolv.conf
// of the edge's DNS forwarder, the log environment of the container, and
// the proxy's restart nonce when it is set. A new binary or image, the mount
// or the log environment coming or going, and a new nonce roll the instance
// like a new configuration does.
func instanceHash(engine, version, artifactSHA, runnerImage string, resolvConf bool, logEnv []string, pr *nodev1.Proxy, files map[string][]byte) string {
	h := sha256.New()
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	field("postern-engine-instance-v2")
	field(engine)
	field(version)
	field(artifactSHA)
	field(runnerImage)
	field(strconv.FormatBool(pr.GetUseMiddleProxy()))
	field(pr.GetNatIp())
	for _, name := range slices.Sorted(maps.Keys(files)) {
		field(name)
		field(string(files[name]))
	}
	// The mount adds a field at the end, so that an instance without it keeps
	// the hash it had before there was a forwarder: an update of the agent does
	// not roll the engines of a node whose edge has none.
	if resolvConf {
		field("mount " + resolvConfMount)
	}
	// The log environment of the container (engines.LogLeveler, Ruling S6-4):
	// an engine started before it, or with another one, rolls once by
	// blue-green, so that no generation keeps logging at a level that names
	// clients. None (an engine without one) adds nothing.
	if len(logEnv) > 0 {
		field("log " + strings.Join(logEnv, "\n"))
	}
	// The restart nonce too: only when it is set, so that an update of the
	// agent rolls no engine, and a new value rolls the proxy by blue-green.
	if n := pr.GetRestartNonce(); n != 0 {
		field("restart " + strconv.FormatUint(n, 10))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// resolveArtifact finds the stored binary of the proxy's engine version for
// the node's architecture. It returns the checksum the desired state pins for
// it (lower case; empty when the state names none), the host path and the
// store reference, or "" and why the binary is missing. Whether the binary is
// usable (its trial) is judged only when a new generation needs it: see
// checkArtifact.
func (p *pass) resolveArtifact(pr *nodev1.Proxy, d engines.Driver) (sha, path, missing string, ref artifacts.Ref) {
	name := engineName(pr.GetEngine())
	what := fmt.Sprintf("%s %s for %s", name, pr.GetEngineVersion(), p.r.Arch)
	for _, a := range p.st.GetArtifacts() {
		if !strings.EqualFold(a.GetEngine(), name) || a.GetVersion() != pr.GetEngineVersion() || a.GetArch() != p.r.Arch {
			continue
		}
		sha = strings.ToLower(a.GetSha256())
		ref = artifacts.Ref{
			Engine: a.GetEngine(), Version: a.GetVersion(), Arch: a.GetArch(), SHA256: a.GetSha256(),
			FileName: a.GetFileName(), Binary: cmp.Or(a.GetBinary(), d.BinaryName()),
		}
		if !p.r.Artifacts.Has(ref) {
			p.wantDownload(a, ref)
			return sha, "", "artifact missing: " + what + " is not on the node (or does not match its checksum)", artifacts.Ref{}
		}
		return sha, p.r.Artifacts.BinaryPath(ref), "", ref
	}
	return "", "", "artifact missing: the desired state names no artifact for " + what, artifacts.Ref{}
}

// ---- adoption -----------------------------------------------------------------

// adoptEngines squares the runtime record with the engine containers that
// exist: a serving instance whose container is gone is forgotten (the proxy
// gets a new generation), a stopped one is started again, draining instances
// whose container is gone are forgotten, and containers the record does not
// know are removed.
func (p *pass) adoptEngines() {
	for _, id := range slices.Sorted(maps.Keys(p.rt.Instances)) {
		rec := p.rt.Instances[id]
		if rec.Generation > 0 {
			c, ok := p.engines[id][rec.Generation]
			switch {
			case !ok:
				p.r.event(evInstanceMissing, sevWarning, id,
					fmt.Sprintf("the container of generation %d of proxy %s is gone; a new generation will be started", rec.Generation, id),
					map[string]string{"generation": genString(rec.Generation)})
				p.dropServing(id, &rec)
			case c.State == "dead" || c.State == "removing":
				p.removeServingContainer(id, rec.Generation, c.Name)
				p.r.event(evInstanceMissing, sevWarning, id,
					fmt.Sprintf("the container of generation %d of proxy %s is dead; a new generation will be started", rec.Generation, id),
					map[string]string{"generation": genString(rec.Generation)})
				p.dropServing(id, &rec)
			case c.State == "created" || c.State == "exited":
				// Docker would create a missing bind source as an empty root
				// directory and start the engine against it: check first.
				in := engines.Instance{BinaryPath: rec.BinaryPath, InstanceDir: p.instanceDir(id, rec.Generation)}
				err := in.CheckHostPaths()
				if err == nil {
					ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
					err = p.r.Docker.Start(ctx, c.Name)
					cancel()
				}
				if err != nil {
					p.removeServingContainer(id, rec.Generation, c.Name)
					p.r.event(evInstanceMissing, sevWarning, id,
						fmt.Sprintf("generation %d of proxy %s was not running and cannot be started again (%v); a new generation will be started", rec.Generation, id, err),
						map[string]string{"generation": genString(rec.Generation)})
					p.dropServing(id, &rec)
				} else {
					p.r.event(evInstanceRestart, sevWarning, id,
						fmt.Sprintf("generation %d of proxy %s was not running and was started again", rec.Generation, id),
						map[string]string{"generation": genString(rec.Generation)})
				}
			}
		}
		var keep []state.DrainingInstance
		for _, d := range rec.Draining {
			if _, ok := p.engines[id][d.Generation]; ok {
				keep = append(keep, d)
				continue
			}
			p.forgetInstance(id, d.Generation)
		}
		rec.Draining = keep
		p.putRecord(id, rec)
	}

	for _, id := range slices.Sorted(maps.Keys(p.engines)) {
		for _, gen := range slices.Sorted(maps.Keys(p.engines[id])) {
			if p.known(id, gen) {
				continue
			}
			c := p.engines[id][gen]
			if err := p.removeContainer(c.Name, false); err != nil {
				p.r.log().Warn("could not remove an unknown engine container", "container", c.Name, "err", err)
				continue
			}
			p.removeInstanceDir(id, gen)
			p.r.event(evOrphanRemoved, sevInfo, id,
				fmt.Sprintf("removed the engine container %s that the runtime record does not know", c.Name),
				map[string]string{"container": c.Name})
		}
	}
}

// removeServingContainer removes the container of a serving generation that
// is being given up, and takes it out of the inventory so that it is not
// taken for an orphan afterwards.
func (p *pass) removeServingContainer(id string, gen uint64, name string) {
	if err := p.removeContainer(name, false); err != nil {
		p.r.log().Warn("could not remove an engine container", "container", name, "err", err)
		return // still there: the orphan sweep tries again
	}
	delete(p.engines[id], gen)
}

// known reports whether the runtime record has generation gen of a proxy,
// serving or draining.
func (p *pass) known(id string, gen uint64) bool {
	rec, ok := p.rt.Instances[id]
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

// dropServing forgets the serving instance of a record (its container is
// gone): its ports and files go, its generation number stays used.
func (p *pass) dropServing(id string, rec *state.InstanceRecord) {
	p.forgetInstance(id, rec.Generation)
	*rec = state.InstanceRecord{
		Draining:       rec.Draining,
		LastGeneration: max(rec.LastGeneration, rec.Generation),
	}
}

// forgetInstance releases the ports and removes the files of a generation.
func (p *pass) forgetInstance(id string, gen uint64) {
	p.releasePorts(id, gen)
	p.removeInstanceDir(id, gen)
	delete(p.r.policyOff, engineContainerName(id, gen))
}

func (p *pass) releasePorts(id string, gen uint64) {
	prefix := state.EnginePortPrefix(id, gen)
	for key := range p.rt.Ports {
		if strings.HasPrefix(key, prefix) {
			p.r.alloc().Release(p.rt, key)
		}
	}
}

func (p *pass) removeInstanceDir(id string, gen uint64) {
	if err := os.RemoveAll(p.instanceDir(id, gen)); err != nil {
		p.r.log().Warn("could not remove an instance directory", "proxy", id, "generation", gen, "err", err)
	}
}

// putRecord stores a record, or drops it when it holds nothing for a proxy
// that is no longer wanted. A record of a desired proxy stays, even empty, for
// its LastGeneration.
func (p *pass) putRecord(id string, rec state.InstanceRecord) {
	if rec.Generation == 0 && len(rec.Draining) == 0 && (p.proxies == nil || p.proxies[id] == nil) {
		delete(p.rt.Instances, id)
		return
	}
	p.rt.Instances[id] = rec
}

// ---- converge -----------------------------------------------------------------

// converge brings one proxy to its desired instance. It returns an error only
// for failures of the node's own machinery (the edge, the runtime record), which
// end the pass; a proxy that cannot be served is reported and the pass goes on.
func (p *pass) converge(pr *nodev1.Proxy) error {
	id := pr.GetId()
	pl := p.plans[id]
	rec := p.rt.Instances[id]
	if !pr.GetEnabled() {
		// Paused: the route goes, the instance stays for a quick resume.
		p.report(id, nodev1.ProxyPhase_PROXY_PHASE_PAUSED, "")
		return nil
	}
	if pl.err != nil {
		reason := "cannot render the engine config: " + pl.err.Error()
		if p.r.problem("render:"+id, reason) {
			p.r.event(evRenderFailed, sevError, id, fmt.Sprintf("proxy %s: %s", id, reason), nil)
		}
		p.failStatus(id, rec, reason)
		return nil
	}
	p.r.clearProblem("render:" + id)
	if rec.Generation > 0 && rec.Hash == pl.hash {
		delete(p.r.failures, id)
		if pl.binary == "" {
			// It serves, but could not be started again (Docker needs the
			// binary to restart the container).
			reason := pl.missingWhy + "; the running generation keeps serving"
			if p.r.problem("artifact:"+id, reason) {
				p.r.event(evArtifactMissing, sevWarning, id, fmt.Sprintf("proxy %s: %s", id, reason),
					map[string]string{"engine": pl.engine, "version": pl.version, "arch": p.r.Arch})
			}
			p.report(id, nodev1.ProxyPhase_PROXY_PHASE_SERVING, reason)
			return nil
		}
		p.r.clearProblem(problemKeys(id)...)
		p.reportServing(pr)
		return nil
	}
	if f, ok := p.r.failures[id]; ok {
		if f.hash != pl.hash {
			// The proxy wants something else now: the failed attempt is
			// forgotten, and the new target is tried at once.
			delete(p.r.failures, id)
		} else if p.r.now().Before(f.at.Add(orDefault(p.r.retryAfter, defaultRetryAfter))) {
			p.failStatus(id, rec, f.reason)
			return nil
		}
	}
	if pl.binary == "" {
		if p.r.problem("artifact:"+id, pl.missingWhy) {
			p.r.event(evArtifactMissing, sevError, id, fmt.Sprintf("proxy %s: %s", id, pl.missingWhy),
				map[string]string{"engine": pl.engine, "version": pl.version, "arch": p.r.Arch})
		}
		p.failStatus(id, rec, pl.missingWhy)
		return nil
	}
	// The binary is there; a new generation runs it only once its trial
	// passed (a serving generation is never touched by this).
	if v := p.checkArtifact(pl.ref, pl.driver); !v.ok {
		if p.r.problem("artifact:"+id, v.reason) {
			p.r.event(v.event(), v.severity(), id, fmt.Sprintf("proxy %s: %s", id, v.reason),
				map[string]string{"engine": pl.engine, "version": pl.version, "arch": p.r.Arch})
		}
		p.failStatus(id, rec, v.reason)
		return nil
	}
	p.r.clearProblem("artifact:" + id)
	return p.blueGreen(pr, pl, rec)
}

// previousBinary is the rollback target of a record whose binary goes from
// old to next: old when next is another one, else the previous one as it was
// (a generation that runs the same binary replaces nothing).
func previousBinary(previous, old, next string) string {
	if old != "" && old != next {
		return old
	}
	return previous
}

// failStatus reports a proxy whose desired instance could not be started: as
// serving when an older generation still serves it, as failed otherwise, and
// with the engine and the version of the desired instance as failed_engine and
// failed_version (the plan's; the desired proxy's when the plan has none).
func (p *pass) failStatus(id string, rec state.InstanceRecord, reason string) {
	phase := nodev1.ProxyPhase_PROXY_PHASE_FAILED
	if rec.Generation > 0 {
		phase, reason = nodev1.ProxyPhase_PROXY_PHASE_SERVING, "upgrade aborted: "+reason
	}
	pr := p.proxies[id]
	ps := proxyStatus(id, phase, reason, rec, pr)
	ps.FailedEngine, ps.FailedVersion = pr.GetEngine(), pr.GetEngineVersion()
	if pl := p.plans[id]; pl != nil && pl.version != "" {
		ps.FailedVersion = pl.version
	}
	p.setStatus(ps)
}

// nextGeneration is one more than every generation the proxy ever had.
func (p *pass) nextGeneration(id string, rec state.InstanceRecord) uint64 {
	g := max(rec.Generation, rec.LastGeneration)
	for _, d := range rec.Draining {
		g = max(g, d.Generation)
	}
	for cg := range p.engines[id] {
		g = max(g, cg)
	}
	return g + 1
}

// blueGreen starts a new generation of the proxy's instance beside the one
// that serves (if any) and moves the route to it once it is ready and passes
// the probe (spec 5.5). Whatever fails before the move removes the new
// generation and leaves the old one serving.
func (p *pass) blueGreen(pr *nodev1.Proxy, pl *proxyPlan, rec state.InstanceRecord) error {
	id := pr.GetId()
	gen := p.nextGeneration(id, rec)
	rec.LastGeneration = gen
	p.rt.Instances[id] = rec // the number is used, whatever happens next
	name := engineContainerName(id, gen)
	in := engines.Instance{
		Proxy:        pl.proxy,
		InstanceID:   instanceDirName(id, gen),
		Generation:   gen,
		InstanceDir:  p.instanceDir(id, gen),
		BinaryPath:   pl.binary,
		RunnerImage:  p.r.RunnerImage,
		FrontingAddr: pl.fronting,
	}
	log := p.r.log().With("proxy", id, "generation", gen)
	created := false
	// cleanup removes what was made of the new generation.
	cleanup := func() {
		delete(p.starting, id)
		if created {
			if err := p.removeContainer(name, false); err != nil {
				log.Warn("could not remove a failed engine generation", "err", err)
			}
		}
		p.removeInstanceDir(id, gen)
		p.releasePorts(id, gen)
	}
	// abort is the end of a generation that failed: cleaned up, reported, and
	// with backoff not tried again with the same configuration for a while
	// (readiness and probe failures cost up to a minute and a half each).
	abort := func(err error, backoff bool) {
		cleanup()
		if p.ctx.Err() != nil {
			return // shutting down: not the engine's fault
		}
		reason := err.Error()
		if backoff {
			p.r.failures[id] = failure{hash: pl.hash, at: p.r.now(), reason: reason}
		}
		p.failStatus(id, rec, reason)
		if !backoff && !p.r.problem("start:"+id, reason) {
			return // reported already; the next pass tries again
		}
		kind, verb := evInstanceFailed, "could not start"
		if rec.Generation > 0 {
			kind, verb = evUpgradeAborted, "upgrade aborted, generation "+genString(rec.Generation)+" keeps serving"
		}
		p.r.event(kind, sevError, id, fmt.Sprintf("proxy %s, generation %d: %s: %s", id, gen, verb, reason),
			map[string]string{"generation": genString(gen)})
	}

	var ports [3]uint16
	for i, role := range []struct{ role, rng string }{
		{state.PortListen, state.RangeEngine}, {state.PortAPI, state.RangeEngineAPI}, {state.PortSocks, state.RangeEdgeSocks},
	} {
		port, err := p.r.alloc().Alloc(p.rt, state.EnginePortKey(id, gen, role.role), role.rng)
		if err != nil {
			abort(fmt.Errorf("allocating ports: %w", err), false)
			return nil
		}
		ports[i] = port
	}
	in.ListenPort, in.APIPort, in.SocksPort = ports[0], ports[1], ports[2]
	in.APIToken = newToken()

	files, err := pl.driver.Render(in)
	if err != nil {
		abort(fmt.Errorf("rendering the config: %w", err), false)
		return nil
	}
	if err := p.writeInstanceDir(in.InstanceDir, files); err != nil {
		abort(fmt.Errorf("writing the instance files: %w", err), false)
		return nil
	}
	if err := in.CheckHostPaths(); err != nil {
		abort(err, false)
		return nil
	}

	// The way out first: the engine connects through the edge from the start.
	// A failure here is the node's, not the proxy's: the pass ends.
	p.starting[id] = startingInstance{gen: gen, socks: in.SocksPort}
	if err := p.pushEdgeConfig(); err != nil {
		cleanup()
		return err
	}
	if err := p.ensureImage(); err != nil {
		cleanup()
		return err
	}
	spec := withResolvConf(pl.driver.Container(in), p.resolvConf())
	spec.Name = name
	if spec.Labels == nil {
		spec.Labels = map[string]string{}
	}
	spec.Labels[labelManaged], spec.Labels[labelRole] = "true", roleEngine
	spec.Labels[labelID], spec.Labels[labelGeneration] = id, genString(gen)
	created, err = p.createAndStart(spec)
	if err != nil {
		abort(err, false)
		return nil
	}
	p.report(id, nodev1.ProxyPhase_PROXY_PHASE_STARTING, "starting generation "+genString(gen))
	p.r.event(evInstanceStarting, sevInfo, id, fmt.Sprintf("proxy %s: generation %d started", id, gen),
		map[string]string{"generation": genString(gen), "engine": pl.engine, "version": pl.version})

	if err := p.waitReady(pl.driver, in, name); err != nil {
		abort(err, true)
		return p.ctx.Err()
	}
	probe := p.probe
	if isWeb(pr) {
		probe = p.probeWeb // a web listener speaks HTTP, not fake TLS
	}
	if err := probe(pl.proxy, in.ListenPort); err != nil {
		abort(err, true)
		return p.ctx.Err()
	}
	if err := p.gate(pl.proxy, in); err != nil {
		abort(err, true)
		return p.ctx.Err()
	}
	p.report(id, nodev1.ProxyPhase_PROXY_PHASE_READY, "generation "+genString(gen)+" is ready")

	// The move. The record is saved first: the agent may die at any moment,
	// and the edge config can always be rebuilt from the record.
	// The route key moves with the switch: from now on the edge routes the
	// proxy's desired (listener, domain) to this generation.
	next := state.InstanceRecord{
		Generation: gen, Hash: pl.hash, Engine: pl.engine, Version: pl.version,
		ListenerID: pr.GetListenerId(), Domain: pr.GetDomain(), BinaryPath: pl.binary, NatIP: pl.natIP,
		ListenPort: in.ListenPort, APIPort: in.APIPort, SocksPort: in.SocksPort, APIToken: in.APIToken,
		ServingSince: p.r.now(), Draining: rec.Draining, LastGeneration: gen,
		PreviousBinaryPath: previousBinary(rec.PreviousBinaryPath, rec.BinaryPath, pl.binary),
	}
	if rec.Generation > 0 {
		next.Draining = append(slices.Clone(rec.Draining), state.DrainingInstance{
			Generation: rec.Generation, ContainerName: engineContainerName(id, rec.Generation),
			Since: p.r.now(), ListenPort: rec.ListenPort,
		})
		if rec.NatIP != "" && next.NatIP != "" && next.NatIP != rec.NatIP {
			p.r.natRolls[id] = p.r.now() // a roll from one NAT address to another (natip.go)
		}
	}
	p.rt.Instances[id] = next
	delete(p.starting, id)
	delete(p.r.failures, id)
	p.r.clearProblem(problemKeys(id)...)
	if err := p.saveRuntime(); err != nil {
		return err
	}
	if err := p.pushEdgeConfig(); err != nil {
		return err
	}
	p.reportServing(pr)
	msg := fmt.Sprintf("proxy %s: generation %d serves", id, gen)
	if rec.Generation > 0 {
		msg += fmt.Sprintf("; generation %d drains", rec.Generation)
		p.r.event(evInstanceDraining, sevInfo, id, fmt.Sprintf("proxy %s: generation %d drains", id, rec.Generation),
			map[string]string{"generation": genString(rec.Generation)})
	}
	p.r.event(evInstanceServing, sevInfo, id, msg, map[string]string{"generation": genString(gen)})
	return nil
}

// waitReady polls the driver until the engine is ready, and fails at once when
// its container stops on the way (a crash shows only there).
func (p *pass) waitReady(d engines.Driver, in engines.Instance, name string) error {
	timeout := orDefault(p.r.readyTimeout, defaultReadyTimeout)
	ctx, cancel := context.WithTimeout(p.ctx, timeout)
	defer cancel()
	var last error
	for {
		if err := p.checkRunning(ctx, name); err != nil {
			return err
		}
		if last = d.Ready(ctx, in); last == nil {
			return nil
		}
		if err := sleep(ctx, orDefault(p.r.readyPoll, defaultReadyPoll)); err != nil {
			if p.ctx.Err() != nil {
				return p.ctx.Err()
			}
			return fmt.Errorf("the engine is not ready after %v: %v", timeout, last)
		}
	}
}

// checkRunning fails when the engine container exited, died, restarts or is
// gone.
func (p *pass) checkRunning(ctx context.Context, name string) error {
	return p.checkContainer(ctx, name, "engine")
}

// checkContainer fails when the container of a what ("engine", "provider")
// exited, died, restarts or is gone.
func (p *pass) checkContainer(ctx context.Context, name, what string) error {
	d, err := p.r.Docker.Inspect(ctx, name)
	switch {
	case errors.Is(err, dockerapi.ErrNotFound):
		return fmt.Errorf("the %s container is gone", what)
	case err != nil:
		return nil // cannot tell; readiness decides
	}
	switch d.State {
	case "exited", "dead":
		return fmt.Errorf("the %s container exited with code %d (see its log)", what, d.ExitCode)
	case "restarting":
		return fmt.Errorf("the %s container keeps restarting (see its log)", what)
	}
	return nil
}

// probe runs the L1 fake-TLS probe straight against the engine, with a PROXY
// header as the edge sends it. It tries a few times: the engine may need a
// moment after it said it is ready.
func (p *pass) probe(pr *nodev1.Proxy, port uint16) error {
	secret, err := hex.DecodeString(pr.GetSecret())
	if err != nil {
		return errors.New("the proxy secret is not hex")
	}
	addr := loopback(port)
	attempts := orDefault(p.r.probeAttempts, defaultProbeAttempts)
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			if err := sleep(p.ctx, orDefault(p.r.readyPoll, defaultReadyPoll)); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(p.ctx, orDefault(p.r.probeTimeout, defaultProbeTimeout))
		last = p.r.Probe(ctx, addr, pr.GetDomain(), secret, probeSource)
		cancel()
		if last == nil {
			return nil
		}
		if p.ctx.Err() != nil {
			return p.ctx.Err()
		}
	}
	return fmt.Errorf("the fake-TLS probe failed: %v", last)
}

// ---- deleted proxies and draining ---------------------------------------------------

// retireDeleted moves the serving instance of every proxy that is no longer
// desired to draining. Its route is gone already: the edge got the table
// without it.
func (p *pass) retireDeleted() {
	for _, id := range slices.Sorted(maps.Keys(p.rt.Instances)) {
		rec := p.rt.Instances[id]
		if p.proxies[id] != nil || rec.Generation == 0 {
			continue
		}
		old := rec.Generation
		rec.Draining = append(rec.Draining, state.DrainingInstance{
			Generation: old, ContainerName: engineContainerName(id, old),
			Since: p.r.now(), ListenPort: rec.ListenPort,
		})
		rec = state.InstanceRecord{Draining: rec.Draining, LastGeneration: max(rec.LastGeneration, old)}
		p.rt.Instances[id] = rec
		p.report(id, nodev1.ProxyPhase_PROXY_PHASE_DRAINING, "the proxy was deleted")
		p.r.event(evInstanceDraining, sevInfo, id, fmt.Sprintf("proxy %s was deleted: generation %d drains", id, old),
			map[string]string{"generation": genString(old)})
	}
}

// drain removes the draining generations that have no connections left (by
// the edge's counters) or whose drain time is over. It reports whether it
// removed any.
func (p *pass) drain() (removed bool) {
	active, countsOK := p.snapshots()
	now := p.r.now()
	for _, id := range slices.Sorted(maps.Keys(p.rt.Instances)) {
		rec := p.rt.Instances[id]
		if len(rec.Draining) == 0 {
			continue
		}
		var keep []state.DrainingInstance
		for _, d := range rec.Draining {
			name := cmp.Or(d.ContainerName, engineContainerName(id, d.Generation))
			p.restartOff(name)
			expired := now.Sub(d.Since) >= p.r.drainAfter()
			idle := countsOK && active[id][loopback(d.ListenPort)] == 0
			if !expired && !idle {
				keep = append(keep, d)
				continue
			}
			if err := p.removeContainer(name, true); err != nil {
				p.r.log().Warn("could not remove a draining engine", "proxy", id, "generation", d.Generation, "err", err)
				keep = append(keep, d)
				continue
			}
			p.forgetInstance(id, d.Generation)
			removed = true
			why := "no connections left"
			if expired {
				why = "the drain time is over"
			}
			p.r.event(evInstanceRemoved, sevInfo, id,
				fmt.Sprintf("proxy %s: generation %d removed (%s)", id, d.Generation, why),
				map[string]string{"generation": genString(d.Generation)})
		}
		rec.Draining = keep
		p.putRecord(id, rec)
		if _, still := p.rt.Instances[id]; !still {
			p.r.keepStatus(p.statusIDs())
		}
	}
	return removed
}

// restartOff sets the restart policy of a draining container to "no" (spec
// 5.1), once per container and agent process.
func (p *pass) restartOff(name string) {
	if p.r.policyOff[name] {
		return
	}
	ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
	defer cancel()
	err := p.r.Docker.SetRestartPolicy(ctx, name, "no")
	if err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
		p.r.log().Warn("could not turn off the restart policy of a draining engine", "container", name, "err", err)
		return
	}
	p.r.policyOff[name] = true
}

// statusIDs are the proxies that should have a status: the desired ones and
// those with instances left.
func (p *pass) statusIDs() map[string]bool {
	ids := map[string]bool{}
	for id := range p.proxies {
		ids[id] = true
	}
	for id := range p.rt.Instances {
		ids[id] = true
	}
	return ids
}

// gcPorts releases engine ports that belong to no serving or draining
// generation (left by a crash).
func (p *pass) gcPorts() {
	live := map[string]bool{}
	for id, rec := range p.rt.Instances {
		if rec.Generation > 0 {
			live[state.EnginePortPrefix(id, rec.Generation)] = true
		}
		for _, d := range rec.Draining {
			live[state.EnginePortPrefix(id, d.Generation)] = true
		}
	}
	for key := range p.rt.Ports {
		if !strings.HasPrefix(key, "eng:") {
			continue
		}
		if i := strings.LastIndexByte(key, ':'); i < 0 || !live[key[:i+1]] {
			p.r.alloc().Release(p.rt, key)
		}
	}
}

// sweepInstanceDirs removes engine instance directories that belong to no
// serving or draining generation (left by a crash).
func (p *pass) sweepInstanceDirs() {
	keep := map[string]bool{}
	for id, rec := range p.rt.Instances {
		if rec.Generation > 0 {
			keep[instanceDirName(id, rec.Generation)] = true
		}
		for _, d := range rec.Draining {
			keep[instanceDirName(id, d.Generation)] = true
		}
	}
	dir := p.r.Store.Paths.InstancesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !isEngineInstanceDir(name) || keep[name] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			p.r.log().Warn("could not remove a stale instance directory", "dir", name, "err", err)
		}
	}
}

// isEngineInstanceDir matches "eng-<id>-g<digits>".
func isEngineInstanceDir(name string) bool {
	if !strings.HasPrefix(name, "eng-") {
		return false
	}
	i := strings.LastIndex(name, "-g")
	if i <= len("eng-") || i+2 >= len(name) {
		return false
	}
	_, err := strconv.ParseUint(name[i+2:], 10, 64)
	return err == nil
}

// ---- files ------------------------------------------------------------------

// writeInstanceDir creates the instance directory with the rendered files
// (Ruling 14): the directory root:65534 0750, the files root:65534 0640 (they
// hold the secret and the API token), and data/ 65534:65534 0750 for the
// engine's own files. A leftover directory of the same name is replaced.
// Ownership is set when the agent runs as root (as on a node); otherwise it is
// left alone and only the modes are set.
func (p *pass) writeInstanceDir(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := p.mkdirOwned(dir, instanceDirMode, 0, engineGID); err != nil {
		return err
	}
	if err := p.mkdirOwned(filepath.Join(dir, dataDirName), dataDirMode, engineUID, engineGID); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if !filepath.IsLocal(name) {
			return fmt.Errorf("the driver rendered a file outside the instance directory: %q", name)
		}
		path := filepath.Join(dir, name)
		if sub := filepath.Dir(path); sub != dir {
			if err := p.mkdirAllOwned(dir, sub); err != nil {
				return err
			}
		}
		if err := writePrivateFile(path, files[name], instanceFileMode); err != nil {
			return err
		}
		if err := p.chown(path, 0, engineGID); err != nil {
			return err
		}
	}
	return nil
}

func (p *pass) mkdirOwned(dir string, mode os.FileMode, uid, gid int) error {
	if err := os.Mkdir(dir, mode); err != nil {
		return err
	}
	if err := os.Chmod(dir, mode); err != nil { // not the umask's business
		return err
	}
	return p.chown(dir, uid, gid)
}

// mkdirAllOwned creates the directories from root (which exists) down to sub.
func (p *pass) mkdirAllOwned(root, sub string) error {
	rel, err := filepath.Rel(root, sub)
	if err != nil {
		return err
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		if info, err := os.Stat(cur); err == nil && info.IsDir() {
			continue
		}
		if err := p.mkdirOwned(cur, instanceDirMode, 0, engineGID); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

// chown sets the owner when the agent runs as root. Without root (a developer
// machine) it cannot, and the files keep the agent's owner.
func (p *pass) chown(path string, uid, gid int) error {
	if os.Geteuid() != 0 {
		p.r.notRootOnce.Do(func() {
			p.r.log().Warn("the agent does not run as root: engine instance files keep its owner, and engines may not be able to read them")
		})
		return nil
	}
	return os.Chown(path, uid, gid)
}

// writePrivateFile creates a new file with exactly mode perm and flushes it.
func writePrivateFile(path string, data []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	return f.Sync()
}
