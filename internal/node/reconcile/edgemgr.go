package reconcile

import (
	"context"
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
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/selfupdate"
	"github.com/urbnywrt/postern/internal/node/state"
)

// Container labels and roles (Global Constraints).
const (
	labelManaged    = "postern.managed"
	labelRole       = "postern.role"
	labelID         = "postern.id"
	labelGeneration = "postern.generation"

	roleEdge   = "edge"
	roleEngine = "engine"
)

// Where the edge container sees things. The host side is the node's layout
// (POSTERN_HOME); inside the container it is always /opt/postern.
const (
	edgeBinaryMount = "/opt/postern/bin/postern-node"
	edgeDataMount   = "/opt/postern/data/edge"
	edgeRunMount    = "/opt/postern/data/run"
	edgeCertsMount  = "/opt/postern/data/certs"
)

// edgeContainer is an edge container found by its labels.
type edgeContainer struct {
	name  string
	gen   uint64
	state string
}

// edgeAlive reports whether an edge container is up or on its way up again:
// Docker restarts a crashed one, and a paused one is the operator's choice.
func edgeAlive(state string) bool {
	return state == "running" || state == "restarting" || state == "paused"
}

func edgeContainerName(gen uint64) string { return "postern-edge-g" + genString(gen) }

// ensureEdge makes sure the newest edge generation runs and makes it the
// current one. The newest is the highest generation the runtime record or any
// edge container knows. When its container is gone or stopped, a new
// generation is made (spec 7: the config first, then the container, then wait
// until it answers); a number is never used twice. A new generation is made as
// well when the capabilities of the newest are not the ones the desired state
// needs (edgeNeedsNetRaw): a container keeps those it was created with. Every
// other generation is drained, but only once the current one answers.
//
// The operator's roll (Ruling 44, see state.Paths.EdgeRollPath) makes a new
// generation beside the newest while that one runs: it is made as above, and
// the generation that ran before drains like any other once the new one
// answers. A new generation that does not come up is removed, and the one that
// ran stays the current one. A roll asked for while the newest needs other
// capabilities is the new generation that those make. The panel's roll, a new
// NodeSettings.edge_roll_nonce (takeRollNonce), goes the same way, with the
// agent's own binary like the file roll.
//
// UpdateEdge's roll (RollEdge) goes the same way too, on the binary it names;
// when no edge runs, or the newest needs other capabilities, the generation
// made for that runs it. A generation made for another reason (a crash, the
// capabilities, a container that was never started) takes the binary of the
// generation it replaces (edgeBinaryFor). The runtime record keeps the binary
// of every generation (EdgeBinaries).
func (p *pass) ensureEdge() error {
	high := p.rt.EdgeGeneration
	for _, e := range p.edges {
		high = max(high, e.gen)
	}
	var cur *edgeContainer
	for i := range p.edges {
		if p.edges[i].gen == high {
			cur = &p.edges[i]
		}
	}
	healthy := false
	// A roll that the agent did not finish (it was killed after the new
	// generation was made) left a newer generation beside the one that served,
	// the record's: it takes over only as a roll would, by the bind rule.
	if old := p.rt.EdgeGeneration; cur != nil && old != 0 && old < high && p.edgeLive(old) {
		took, err := p.settleRoll(old, high, cur)
		if err != nil {
			return err
		}
		if took {
			healthy = true
		} else {
			high = old
			cur = nil
			for i := range p.edges {
				if p.edges[i].gen == high {
					cur = &p.edges[i]
				}
			}
		}
	}
	netRaw := edgeNeedsNetRaw(p.st)
	capsOK := (p.rt.EdgeNetRaw == high) == netRaw
	roll := p.takeRoll()
	nonceRoll := p.takeRollNonce(cur != nil && edgeAlive(cur.state))
	req := p.takeRollRequest()
	if req != nil {
		// What the edge mounts is what UpdateEdge verified.
		if err := selfupdate.Rehash(req.binary, req.sum); err != nil {
			p.rollDone(0, fmt.Errorf("the binary changed after it was verified: %w", err))
			req = nil
		}
	}
	switch {
	case cur != nil && edgeAlive(cur.state) && capsOK && (roll || nonceRoll || req != nil):
		next := p.nextEdgeGeneration(high)
		binary, why := p.r.NodeBinaryPath, "the operator asked for an edge roll"
		if req != nil {
			binary, why = req.binary, "UpdateEdge asked for an edge roll to "+filepath.Base(req.binary)
		}
		p.r.event(evEdgeRoll, sevInfo, "",
			fmt.Sprintf("%s: generation %d starts beside generation %d, which then drains", why, next, high),
			map[string]string{"generation": genString(next), "from": genString(high)})
		netRawGen := p.rt.EdgeNetRaw // that of the generation that runs, for a roll that fails
		err := p.createEdge(next, netRaw, binary)
		if err == nil {
			err = p.checkRollBinds(high, next)
		}
		if err != nil {
			if p.ctx.Err() != nil {
				return err // the agent stops: the next start finds both generations
			}
			p.abandonEdge(next, high, err)
			p.rt.EdgeNetRaw = netRawGen
			if req != nil {
				p.rollDone(0, fmt.Errorf("%w: %v", ErrEdgeRollFailed, err))
			}
			break
		}
		p.rt.EdgePreviousBinary = p.edgeBinaryOf(high)
		high, healthy = next, true
		if req != nil {
			p.rollDone(next, nil)
		}
	case cur != nil && edgeAlive(cur.state) && capsOK:
	case cur != nil && cur.state == "created" && capsOK && req == nil:
		// Created by an agent that died before it started it. Its bind
		// sources are checked like a new edge's first; its config was
		// written before it was created, and is written again if it is gone.
		if err := p.prepareEdgeHost(p.edgeBinaryFor(high)); err != nil {
			return err
		}
		if _, err := os.Stat(p.r.Store.Paths.EdgeConfigPath(high)); errors.Is(err, fs.ErrNotExist) {
			if err := p.writeEdgeConfig(high); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
		err := p.r.Docker.Start(ctx, cur.name)
		cancel()
		if err != nil {
			return fmt.Errorf("starting edge g%d: %w", high, err)
		}
		if err := p.waitEdgeHealthy(high); err != nil {
			return err
		}
		healthy = true
	default:
		if cur != nil && !capsOK && (edgeAlive(cur.state) || cur.state == "created") {
			p.r.log().Info("the edge needs other capabilities: a new generation takes over",
				"edge_generation", high, "net_raw", netRaw)
		}
		binary := p.edgeBinaryFor(high)
		if req != nil {
			binary = req.binary
		}
		prev, netRawGen := high, p.rt.EdgeNetRaw
		// UpdateEdge's generation beside one that serves goes by the bind
		// rule like any roll.
		bindRule := req != nil && cur != nil && edgeAlive(cur.state)
		high = p.nextEdgeGeneration(high)
		err := p.createEdge(high, netRaw, binary)
		if err == nil && bindRule {
			err = p.checkRollBinds(prev, high)
			if err != nil && p.ctx.Err() == nil {
				p.abandonEdge(high, prev, err)
				p.rt.EdgeNetRaw = netRawGen
				p.rollDone(0, fmt.Errorf("%w: %v", ErrEdgeRollFailed, err))
				high = prev
				break
			}
		}
		if err != nil {
			if req != nil {
				p.rollDone(0, fmt.Errorf("%w: %v", ErrEdgeRollFailed, err))
			}
			return err
		}
		if req != nil {
			if bindRule {
				p.rt.EdgePreviousBinary = p.edgeBinaryOf(prev)
			}
			p.rollDone(high, nil)
		}
		healthy = true
	}
	p.edgeGen = high
	p.edge = p.r.edge(high)
	p.rt.EdgeGeneration = high

	// Forget what belongs to generations that are gone (removed by hand).
	present := map[uint64]bool{high: true}
	for _, e := range p.edges {
		present[e.gen] = true
	}
	for gen := range p.r.edgeDrains {
		if !present[gen] {
			delete(p.r.edgeDrains, gen)
		}
	}
	for gen := range p.r.edgeClients {
		if !present[gen] {
			delete(p.r.edgeClients, gen)
		}
	}
	for gen := range p.rt.EdgeBinaries {
		if !present[gen] {
			delete(p.rt.EdgeBinaries, gen)
		}
	}

	olds := 0
	for _, e := range p.edges {
		if e.gen != high {
			olds++
		}
	}
	if olds == 0 {
		return nil
	}
	if !healthy {
		// The old generations go only when the current one answers.
		if err := p.waitEdgeHealthy(high); err != nil {
			return err
		}
	}
	for i := range p.edges {
		if p.edges[i].gen != high && p.retireEdge(p.edges[i]) {
			p.edges[i].state = "removed" // no longer asked for counters
		}
	}
	return nil
}

// problemRoll is the key of a roll request that cannot be taken among the
// reported problems (see Reconciler.problem).
const problemRoll = "edge-roll"

// takeRoll takes the operator's request for an edge roll, if there is one: it
// deletes the file and reports whether it was there. A request that cannot be
// deleted is not taken, since it would roll the edge on every pass; that is
// logged once.
func (p *pass) takeRoll() bool {
	path := p.r.Store.Paths.EdgeRollPath()
	err := os.Remove(path)
	switch {
	case err == nil:
		p.r.clearProblem(problemRoll)
		return true
	case errors.Is(err, fs.ErrNotExist):
		p.r.clearProblem(problemRoll)
		return false
	}
	if p.r.problem(problemRoll, err.Error()) {
		p.r.log().Warn("the request for an edge roll cannot be deleted, so it is not acted on", "file", path, "err", err)
	}
	return false
}

// takeRollNonce takes the panel's request for an edge roll, if there is one:
// a NodeSettings.edge_roll_nonce other than the one the runtime record holds
// (the fix roll_edge). The nonce is recorded at once, whatever comes of the
// roll, so that a roll that fails is not tried again on every pass: the
// operator asks again. It reports whether a roll is to be made, which is only
// while an edge runs (running says so): a node without one makes its first
// edge anyway, and records the nonce without a roll.
func (p *pass) takeRollNonce(running bool) bool {
	want := p.st.GetSettings().GetEdgeRollNonce()
	if want == p.rt.EdgeRollNonce {
		return false
	}
	p.rt.EdgeRollNonce = want
	if !running {
		p.r.log().Info("edge roll nonce recorded without a roll: no edge runs yet", "nonce", want)
		return false
	}
	p.r.event(evEdgeRollRequest, sevInfo, "",
		fmt.Sprintf("the panel asked for an edge roll (nonce %d)", want),
		map[string]string{"nonce": strconv.FormatUint(want, 10)})
	return true
}

// nextEdgeGeneration is the number of a new edge generation, which is recorded
// as used at once: one more than every generation the node has had, also one
// that did not come up and was removed.
func (p *pass) nextEdgeGeneration(high uint64) uint64 {
	next := max(high, p.rt.EdgeLastGeneration) + 1
	p.rt.EdgeLastGeneration = next
	return next
}

// abandonEdge removes generation gen, which a roll made and which did not come
// up (cause): its container, its config and its socket. Generation running,
// which it was to replace, goes on as the current one. The number stays used.
func (p *pass) abandonEdge(gen, running uint64, cause error) {
	log := p.r.log().With("edge_generation", gen)
	if err := p.removeContainerWithin(edgeContainerName(gen), true, edgeStopTimeout); err != nil {
		log.Warn("could not remove an edge generation that did not come up", "err", err)
	}
	delete(p.r.edgeClients, gen)
	delete(p.rt.EdgeBinaries, gen)
	paths := p.r.Store.Paths
	for _, f := range []string{paths.EdgeConfigPath(gen), paths.EdgeSocketPath(gen)} {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Warn("could not remove a file of an edge generation that did not come up", "file", filepath.Base(f), "err", err)
		}
	}
	p.r.event(evEdgeRollFailed, sevError, "",
		fmt.Sprintf("edge roll: generation %d did not come up and was removed (%v); generation %d goes on serving", gen, cause, running),
		map[string]string{"generation": genString(gen), "running": genString(running)})
}

// maxEdgeVersion bounds the version of an edge that an event quotes.
const maxEdgeVersion = 128

// checkEdgeVersion asks the current edge for its version, once per generation,
// and reports an edge that runs another version than the agent (Ruling 38):
// after an update of the node the edge keeps the binary it was started with
// until the operator rolls it (install.sh --roll-edge, Ruling 44). The agent
// does not roll it by itself: the data plane changes when the operator says
// so. An edge that does not answer is asked again by the next pass. It never
// fails the pass.
func (p *pass) checkEdgeVersion() error {
	r := p.r
	if r.Version == "" || r.edgeVersionChecked == p.edgeGen {
		return nil
	}
	r.edgeVersionOK = false // not known of this generation until it answers
	ctx, cancel := context.WithTimeout(p.ctx, edgeCallTimeout)
	h, err := p.edge.Health(ctx)
	cancel()
	if err != nil {
		return nil
	}
	r.edgeVersionChecked = p.edgeGen
	have := h.GetVersion()
	if len(have) > maxEdgeVersion {
		have = strings.ToValidUTF8(have[:maxEdgeVersion], "")
	}
	r.edgeVersionOK = have == r.Version
	if have == r.Version {
		return nil
	}
	runs := have
	if runs == "" {
		runs = "an older version that does not report it"
	}
	r.event(evEdgeOutdated, sevWarning, "",
		fmt.Sprintf("edge generation %d runs %s, the agent %s: an edge keeps the binary it was started with until it is rolled "+
			"(the roll of the edge in the panel, or data/run/roll-edge on the node: install.sh --roll-edge)",
			p.edgeGen, runs, r.Version),
		map[string]string{"generation": genString(p.edgeGen), "edge_version": have, "agent_version": r.Version})
	return nil
}

// prepareEdgeHost checks the bind sources of an edge container before it is
// started: the directories exist (Docker would make a missing one itself,
// empty and root-owned) and the node binary it mounts is a regular executable
// file.
func (p *pass) prepareEdgeHost(binary string) error {
	paths := p.r.Store.Paths
	for _, dir := range []string{paths.EdgeDir(), paths.RunDir(), paths.CertsDir()} {
		if err := checkBindSource(dir); err != nil {
			return fmt.Errorf("edge: %w", err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("edge: %w", err)
		}
	}
	if err := checkNodeBinary(binary); err != nil {
		return fmt.Errorf("edge: %w", err)
	}
	return nil
}

// writeEdgeConfig writes the config file of edge generation gen (spec 7: before
// the generation starts). It carries egress credentials: root only.
func (p *pass) writeEdgeConfig(gen uint64) error {
	cfg := p.edgeConfig(gen)
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("edge: encoding the config: %w", err)
	}
	if err := state.WriteFileAtomic(p.r.Store.Paths.EdgeConfigPath(gen), data, 0o600); err != nil {
		return fmt.Errorf("edge: writing the config of g%d: %w", gen, err)
	}
	return nil
}

// createEdge writes the config of generation gen, creates and starts the
// container on binary (the host path of the node binary it mounts), with
// CAP_NET_RAW when netRaw is set, and waits until it answers with that
// generation. The runtime record notes the generation that has the capability,
// and the binary of the generation, as soon as the container exists.
func (p *pass) createEdge(gen uint64, netRaw bool, binary string) error {
	if err := p.prepareEdgeHost(binary); err != nil {
		return err
	}
	if err := p.writeEdgeConfig(gen); err != nil { // fresh, also over a leftover
		return err
	}
	if err := p.ensureImage(); err != nil {
		return err
	}
	created, err := p.createAndStart(p.r.edgeSpec(gen, netRaw, binary))
	if created {
		p.recordEdgeBinary(gen, binary)
		p.rt.EdgeNetRaw = 0
		if netRaw {
			p.rt.EdgeNetRaw = gen
		}
		// Saved at once: an agent killed before the pass ends finds the new
		// generation's binary and number on its next start (settleRoll).
		if serr := p.saveRuntime(); serr != nil {
			p.r.log().Warn("the runtime record cannot be saved after a new edge generation was made", "edge_generation", gen, "err", serr)
		}
	}
	if err != nil {
		return fmt.Errorf("edge g%d: %w", gen, err)
	}
	p.r.event(evEdgeStarted, sevInfo, "", fmt.Sprintf("edge generation %d started", gen),
		map[string]string{"generation": genString(gen)})
	if err := p.waitEdgeHealthy(gen); err != nil {
		return err
	}
	return nil
}

// edgeSpec is the container of edge generation gen (spec 5.1): root without
// capabilities but NET_BIND_SERVICE, and NET_RAW when netRaw is set (a member
// of a chain is tied to an interface), a read-only root file system, the node
// binary (binary, its host path) read-only, the edge and run directories, the certificates read-only.
// Its stop timeout is edgeStopTimeout, so that a stop which names no timeout
// (the daemon shutting down) leaves the edge the time it needs to drain, and
// its limit of open files is edgeOpenFiles, or fs.nr_open of the host when
// that is lower (see edgeNofile).
func (r *Reconciler) edgeSpec(gen uint64, netRaw bool, binary string) dockerapi.ContainerSpec {
	paths := r.Store.Paths
	g := genString(gen)
	stopSeconds := int(edgeStopTimeout / time.Second)
	nofile := r.edgeNofile()
	caps := []string{"NET_BIND_SERVICE"}
	if netRaw {
		caps = append(caps, "NET_RAW")
	}
	return dockerapi.ContainerSpec{
		Name:          edgeContainerName(gen),
		Image:         r.RunnerImage,
		User:          "0:0",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		Entrypoint: []string{
			edgeBinaryMount, "edge",
			"--config", edgeDataMount + "/config-g" + g + ".json",
			"--socket", edgeRunMount + "/edge-g" + g + ".sock",
		},
		Binds: []string{
			binary + ":" + edgeBinaryMount + ":ro",
			paths.EdgeDir() + ":" + edgeDataMount,
			paths.RunDir() + ":" + edgeRunMount,
			paths.CertsDir() + ":" + edgeCertsMount + ":ro",
		},
		CapDrop:     []string{"ALL"},
		CapAdd:      caps,
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels: map[string]string{
			labelManaged:    "true",
			labelRole:       roleEdge,
			labelID:         roleEdge,
			labelGeneration: g,
		},
		ReadOnly:    true,
		Ulimits:     []dockerapi.Ulimit{{Name: "nofile", Soft: nofile, Hard: nofile}},
		LogMaxSize:  "10m",
		LogMaxFile:  3,
		StopTimeout: &stopSeconds,
	}
}

// edgeNofile returns the limit of open files of a new edge container, from
// fs.nr_open of the host as it is now (see edgeOpenFileLimit), and logs it the
// first time.
func (r *Reconciler) edgeNofile() int64 {
	read := r.readFile
	if read == nil {
		read = os.ReadFile
	}
	limit, nrOpen, err := edgeOpenFileLimit(read)
	r.nofileOnce.Do(func() {
		if err != nil {
			r.log().Warn("cannot read fs.nr_open of the host; the edge's limit of open files is the default", "nofile", limit, "err", err)
			return
		}
		r.log().Info("the edge's limit of open files", "nofile", limit, "fs_nr_open", nrOpen)
	})
	return limit
}

// edgeOpenFileLimit returns the limit of open files of the edge container:
// edgeOpenFiles, or fs.nr_open of the host when that is lower. No process may
// have more open files than fs.nr_open, and a container whose limit is over it
// cannot be started. read reads a file as os.ReadFile does. When fs.nr_open
// cannot be read, or is not a positive number, the limit is edgeOpenFiles,
// nrOpen is 0 and err says why.
func edgeOpenFileLimit(read func(name string) ([]byte, error)) (limit, nrOpen int64, err error) {
	b, err := read(nrOpenFile)
	if err != nil {
		return edgeOpenFiles, 0, fmt.Errorf("reading %s: %w", nrOpenFile, err)
	}
	text := strings.TrimSpace(string(b))
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n <= 0 {
		return edgeOpenFiles, 0, fmt.Errorf("%s holds %.32q, not a positive number", nrOpenFile, text)
	}
	return min(n, edgeOpenFiles), n, nil
}

// waitEdgeHealthy polls the edge's Health until it reports generation gen.
// A container that exits on the way fails at once.
func (p *pass) waitEdgeHealthy(gen uint64) error {
	timeout := orDefault(p.r.edgeStartTimeout, defaultEdgeStartTimeout)
	ctx, cancel := context.WithTimeout(p.ctx, timeout)
	defer cancel()
	client := p.r.edge(gen)
	name := edgeContainerName(gen)
	var last error
	for {
		if d, err := p.r.Docker.Inspect(ctx, name); err == nil {
			if d.State == "exited" || d.State == "dead" {
				return fmt.Errorf("edge g%d exited with code %d (see its log)", gen, d.ExitCode)
			}
		} else if errors.Is(err, dockerapi.ErrNotFound) {
			return fmt.Errorf("edge g%d: the container is gone", gen)
		}
		callCtx, callCancel := context.WithTimeout(ctx, edgeCallTimeout)
		h, err := client.Health(callCtx)
		callCancel()
		switch {
		case err == nil && h.GetGeneration() == gen:
			return nil
		case err == nil:
			last = fmt.Errorf("it reports generation %d", h.GetGeneration())
		default:
			last = err
		}
		if err := sleep(ctx, orDefault(p.r.edgePoll, defaultEdgePoll)); err != nil {
			if p.ctx.Err() != nil {
				return p.ctx.Err()
			}
			return fmt.Errorf("edge g%d does not answer after %v: %v", gen, timeout, last)
		}
	}
}

// rollBlockedBy returns the first of failures, the listeners the new
// generation could not bind, whose address (from listeners, the configuration
// of the new generation) the running generation has bound (oldBound, as its
// Health reports them); nil when there is none. The addresses are compared
// parsed, not as text: a bind_ip that is not in canonical form (an IPv6
// address with upper-case or leading zeros) must not miss what running has
// bound, which would let the roll through.
func rollBlockedBy(listeners []*edgev1.EdgeListener, oldBound []string, failures []*edgev1.ListenerFailure) *edgev1.ListenerFailure {
	bound := map[netip.AddrPort]bool{}
	for _, a := range oldBound {
		if ap, err := netip.ParseAddrPort(a); err == nil {
			bound[ap] = true
		}
	}
	addrs := map[string]netip.AddrPort{} // listener id → the address it binds
	for _, l := range listeners {
		if ip, err := netip.ParseAddr(l.GetBindIp()); err == nil {
			addrs[l.GetId()] = netip.AddrPortFrom(ip, uint16(l.GetPort()))
		}
	}
	for _, f := range failures {
		if bound[addrs[f.GetListenerId()]] {
			return f
		}
	}
	return nil // every failure is one running has too, or of a new listener
}

// edgeRetire is the progress of an outgoing edge generation.
type edgeRetire struct {
	since     time.Time // retiring began: the force-stop deadline runs from here
	policyOff bool      // its restart policy is "no"
	drained   bool      // it accepted Drain
}

// retireEdge drains an edge generation that is not the current one (spec 7):
// restart policy "no", Drain over its socket, and removal once it has exited
// or the drain time is over. A generation that is not running is removed at
// once. A step that fails is tried again by the next pass; the drain time
// runs from the first attempt either way. It reports whether the container
// was removed.
func (p *pass) retireEdge(e edgeContainer) (removed bool) {
	log := p.r.log().With("edge_generation", e.gen)
	if edgeAlive(e.state) {
		st := p.r.edgeDrains[e.gen]
		if st == nil {
			st = &edgeRetire{since: p.r.now()}
			p.r.edgeDrains[e.gen] = st
			p.r.event(evEdgeDraining, sevInfo, "", fmt.Sprintf("edge generation %d drains", e.gen),
				map[string]string{"generation": genString(e.gen)})
		}
		if p.r.now().Sub(st.since) < edgeDrainSeconds*time.Second+edgeDrainGrace {
			if !st.policyOff {
				ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
				err := p.r.Docker.SetRestartPolicy(ctx, e.name, "no")
				cancel()
				if err == nil || errors.Is(err, dockerapi.ErrNotFound) {
					st.policyOff = true
				} else {
					log.Warn("could not turn off the restart policy of an old edge; trying again later", "err", err)
				}
			}
			if !st.drained {
				ctx, cancel := context.WithTimeout(p.ctx, edgeCallTimeout)
				err := p.r.edge(e.gen).Drain(ctx, edgeDrainSeconds)
				cancel()
				if err == nil {
					st.drained = true
				} else {
					log.Warn("could not ask an old edge to drain; trying again later", "err", err)
				}
			}
			return false
		}
		log.Warn("an old edge did not exit after its drain time; stopping it")
	}
	if err := p.removeContainerWithin(e.name, edgeAlive(e.state), edgeStopTimeout); err != nil {
		log.Warn("could not remove an old edge", "err", err)
		return false
	}
	delete(p.r.edgeDrains, e.gen)
	delete(p.r.edgeClients, e.gen)
	paths := p.r.Store.Paths
	for _, f := range []string{paths.EdgeConfigPath(e.gen), paths.EdgeSocketPath(e.gen)} {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Warn("could not remove a file of an old edge", "file", filepath.Base(f), "err", err)
		}
	}
	p.r.event(evEdgeRemoved, sevInfo, "", fmt.Sprintf("edge generation %d removed", e.gen),
		map[string]string{"generation": genString(e.gen)})
	return true
}

// pushEdgeConfig sends the whole table to the current edge. The listeners the
// edge could not bind fail the proxies on them, and nothing else (see
// noteListenerFailures); when every listener failed, the pass fails with the
// reasons, as a configuration that could not be applied does.
func (p *pass) pushEdgeConfig() error {
	cfg := p.edgeConfig(p.edgeGen)
	ctx, cancel := context.WithTimeout(p.ctx, edgeCallTimeout)
	defer cancel()
	failed, err := p.edge.SetConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("edge g%d: %w", p.edgeGen, err)
	}
	return p.noteListenerFailures(cfg, failed)
}

// noteListenerFailures takes the listeners of cfg that the edge could not
// bind: every proxy on one of them is reported FAILED with the reason, the
// proxies on the other listeners keep their status, and a change in the set
// is logged. It returns an error only when every listener of cfg failed: then
// the node serves nothing, and the pass fails with the reasons.
func (p *pass) noteListenerFailures(cfg *edgev1.EdgeConfig, failed []*edgev1.ListenerFailure) error {
	now := map[string]string{}
	for _, f := range failed {
		now[f.GetListenerId()] = f.GetReason()
	}
	if !maps.Equal(now, p.r.listenerFailed) {
		for id, reason := range now {
			if p.r.listenerFailed[id] != reason {
				p.r.log().Warn("the edge cannot bind a listener; its proxies are failed, the others serve, and the edge tries again",
					"edge_generation", p.edgeGen, "listener", id, "err", reason)
			}
		}
		for id := range p.r.listenerFailed {
			if _, still := now[id]; !still {
				p.r.log().Info("the edge binds a listener that had failed", "edge_generation", p.edgeGen, "listener", id)
			}
		}
		p.r.listenerFailed = now
	}
	if len(now) == 0 {
		return nil
	}
	for _, pr := range p.sortedProxies() {
		if !pr.GetEnabled() {
			continue // paused: it has no route, and keeps its status
		}
		if reason, ok := now[pr.GetListenerId()]; ok {
			p.report(pr.GetId(), nodev1.ProxyPhase_PROXY_PHASE_FAILED,
				fmt.Sprintf("listener %s could not bind: %s", pr.GetListenerId(), reason))
		}
	}
	if len(now) < len(cfg.GetListeners()) {
		return nil
	}
	reasons := make([]string, 0, len(now))
	for _, id := range slices.Sorted(maps.Keys(now)) {
		reasons = append(reasons, fmt.Sprintf("listener %s could not bind: %s", id, now[id]))
	}
	return fmt.Errorf("edge g%d: no listener could be bound: %s", p.edgeGen, strings.Join(reasons, "; "))
}

// checkRollBinds checks that edge generation next, which is to take over from
// generation running, binds every listener that running has bound: one it
// fails while running serves it would go dark with the roll. A listener that
// fails in both, or that running does not have, does not block the roll. When
// running cannot be asked, there is nothing to compare with.
func (p *pass) checkRollBinds(running, next uint64) error {
	ctx, cancel := context.WithTimeout(p.ctx, edgeCallTimeout)
	defer cancel()
	newH, err := p.r.edge(next).Health(ctx)
	if err != nil {
		return fmt.Errorf("edge g%d does not answer: %w", next, err)
	}
	if len(newH.GetListenerFailures()) == 0 {
		return nil
	}
	oldH, err := p.r.edge(running).Health(ctx)
	if err != nil {
		p.r.log().Warn("the running edge cannot be asked what it binds; the roll goes on", "edge_generation", running, "err", err)
		return nil
	}
	// What running has bound is the measure: a listener that fails in running
	// too, or that running does not have, is not among its bound addresses.
	if f := rollBlockedBy(p.edgeConfig(next).GetListeners(), oldH.GetBound(), newH.GetListenerFailures()); f != nil {
		return fmt.Errorf("listener %s could not bind in generation %d while generation %d serves it: %s", f.GetListenerId(), next, running, f.GetReason())
	}
	return nil
}

// snapshots adds up the active connections per proxy and backend over every
// edge generation that runs (an old one still relays its connections). ok is
// false when one of them could not be asked: then nobody can tell that a
// backend is idle.
func (p *pass) snapshots() (active map[string]map[string]uint32, ok bool) {
	active = map[string]map[string]uint32{}
	ok = true
	gens := []uint64{p.edgeGen}
	for _, e := range p.edges {
		if e.gen != p.edgeGen && edgeAlive(e.state) {
			gens = append(gens, e.gen)
		}
	}
	for _, gen := range gens {
		client := p.edge
		if gen != p.edgeGen {
			client = p.r.edge(gen)
		}
		ctx, cancel := context.WithTimeout(p.ctx, edgeCallTimeout)
		snap, err := client.Snapshot(ctx)
		cancel()
		if err != nil {
			p.r.log().Warn("could not read the edge's counters", "edge_generation", gen, "err", err)
			ok = false
			continue
		}
		if gen == p.edgeGen {
			p.r.setEgressHealth(snap.GetHealth())
		}
		for _, pc := range snap.GetProxies() {
			for backend, n := range pc.GetBackendActive() {
				if active[pc.GetProxyId()] == nil {
					active[pc.GetProxyId()] = map[string]uint32{}
				}
				active[pc.GetProxyId()][backend] += n
			}
		}
	}
	return active, ok
}

// ---- docker helpers -------------------------------------------------------------

// ensureImage makes sure the runner image is present (the daemon refuses to
// create a container from a missing image), once per pass.
func (p *pass) ensureImage() error {
	if p.imageReady {
		return nil
	}
	ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
	ok, err := p.r.Docker.ImageExists(ctx, p.r.RunnerImage)
	cancel()
	if err != nil {
		return fmt.Errorf("checking the runner image: %w", err)
	}
	if !ok {
		p.r.log().Info("pulling the runner image", "image", p.r.RunnerImage)
		ctx, cancel := context.WithTimeout(p.ctx, pullTimeout)
		err := p.r.Docker.Pull(ctx, p.r.RunnerImage)
		cancel()
		if err != nil {
			return fmt.Errorf("pulling the runner image: %w", err)
		}
	}
	p.imageReady = true
	return nil
}

// createAndStart creates and starts a container; created says whether the
// container exists afterwards.
func (p *pass) createAndStart(spec dockerapi.ContainerSpec) (created bool, err error) {
	ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
	defer cancel()
	if _, err := p.r.Docker.Create(ctx, spec); err != nil {
		return false, fmt.Errorf("creating %s: %w", spec.Name, err)
	}
	if err := p.r.Docker.Start(ctx, spec.Name); err != nil {
		return true, fmt.Errorf("starting %s: %w", spec.Name, err)
	}
	return true, nil
}

// removeContainer stops (when asked) and removes a container; one that is
// already gone is fine. It also works while the pass's context is being
// cancelled, so that a half-made generation is not left behind.
func (p *pass) removeContainer(name string, stop bool) error {
	return p.removeContainerWithin(name, stop, stopTimeout)
}

// removeContainerWithin is removeContainer with grace, the time the container
// has after SIGTERM before Docker kills it.
func (p *pass) removeContainerWithin(name string, stop bool, grace time.Duration) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(p.ctx), dockerTimeout+grace)
	defer cancel()
	if stop {
		if err := p.r.Docker.Stop(ctx, name, grace); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			p.r.log().Warn("could not stop a container; removing it by force", "container", name, "err", err)
		}
	}
	if err := p.r.Docker.Remove(ctx, name, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
		return err
	}
	return nil
}

// checkBindSource rejects a host path that cannot be the source of a bind
// mount: it must be absolute (Docker takes anything else for a volume name)
// and cannot hold ':' (the separator of a bind spec).
func checkBindSource(path string) error {
	switch {
	case !filepath.IsAbs(path):
		return fmt.Errorf("the host path %q is not absolute", path)
	case strings.Contains(path, ":"):
		return fmt.Errorf("the host path %q contains ':'", path)
	}
	return nil
}

// checkNodeBinary verifies the binary mounted into the edge: Docker would
// create a missing bind source as an empty directory and start the edge
// anyway.
func checkNodeBinary(path string) error {
	if err := checkBindSource(path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	switch {
	case err != nil:
		return fmt.Errorf("the node binary: %w", err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("the node binary %s is not a regular file", path)
	case info.Mode().Perm()&0o111 == 0:
		return fmt.Errorf("the node binary %s is not executable", path)
	}
	return nil
}
