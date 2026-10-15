package reconcile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/trial"
)

// Artifacts on the node: which ones a new generation may run, and which ones
// go.
//
// An artifact is present for a new generation only when it is stored (Has) and
// its trial record says that it passed. One without a record (stored before
// trials existed, or whose upload could not try it) is tried in the pass that
// needs it; when the trial cannot run, the artifact stays untried and the
// generation is not started this pass. A serving generation is never touched:
// its binary is judged only when a new generation is to run it. The trial
// runs synchronously, inside the pass: a pass that meets an untried artifact
// waits for its trial, up to trial.DefaultTimeout per artifact, before it goes
// on with the egresses and the edge.
//
// Garbage collection runs after a pass, at most once an hour, and removes the
// artifacts that nothing needs: not named by the desired state, not mounted by
// any managed container, not pointed at by the runtime record (the binary an
// instance or egress runs, and the one it ran before: its rollback target),
// and not among the two most recently used versions, with a passed trial, of
// their engine and architecture. Stale stage directories of the store go too.
// Every pass also removes orphan trial containers (Global Constraints): ones
// no running trial of this agent owns, older than twice the trial timeout.

const (
	roleTrial = "trial"
	// gcEvery is how often the artifacts are collected, at most.
	gcEvery = time.Hour
	// staleStageAge is the age at which a stage directory of the store is
	// taken for abandoned: an upload takes minutes at the most.
	staleStageAge = time.Hour
	// keepVersions is how many of the most recently used versions of every
	// engine and architecture GC keeps, whatever else holds them.
	keepVersions = 2
	// orphanTrialAge is the age at which a trial container that no running
	// trial owns is an orphan (Global Constraints: 2 × the timeout).
	orphanTrialAge = 2 * trial.DefaultTimeout
	// stagePrefix starts the names of the store's scratch directories
	// (artifacts.Store.Put).
	stagePrefix = ".stage-"
)

// ---- usability ------------------------------------------------------------------

// artifactVerdict is what the node knows of an artifact's trial: ok when a
// new generation may run it, otherwise tried says whether a trial judged it
// (unusable) or none could run yet (untried), and reason why.
type artifactVerdict struct {
	ok     bool
	tried  bool
	reason string
}

func (v artifactVerdict) event() string {
	if v.tried {
		return evArtifactUnusable
	}
	return evArtifactUntried
}

func (v artifactVerdict) severity() string {
	if v.tried {
		return sevError
	}
	return sevWarning
}

// checkArtifact judges a stored artifact for a new generation: by its trial
// record when it has one, else by a trial run now (once per artifact and
// pass), which is recorded when it ran. driver is the engine or provider
// driver, which knows the trial of its binary.
func (p *pass) checkArtifact(ref artifacts.Ref, driver any) artifactVerdict {
	what := fmt.Sprintf("%s %s for %s", ref.Engine, ref.Version, ref.Arch)
	if rec, ok := p.r.Artifacts.Trial(ref); ok {
		if rec.OK {
			return artifactVerdict{ok: true, tried: true}
		}
		return artifactVerdict{tried: true, reason: "artifact unusable: " + what + ": " + rec.Reason}
	}
	if v, ok := p.verdicts[ref]; ok {
		return v
	}
	v := p.tryArtifact(ref, driver, what)
	p.verdicts[ref] = v
	return v
}

// tryArtifact runs the trial of an artifact without a record and records the
// outcome when there is one.
func (p *pass) tryArtifact(ref artifacts.Ref, driver any, what string) artifactVerdict {
	untried := func(why string) artifactVerdict {
		return artifactVerdict{reason: "artifact not tried yet: " + what + ": " + why}
	}
	trialer, ok := driver.(engines.Trialer)
	switch {
	case !ok:
		return untried("no trial is known for " + ref.Engine)
	case p.r.Trials == nil:
		return untried("the node has no trial runner")
	}
	log := p.r.log().With("engine", ref.Engine, "version", ref.Version, "arch", ref.Arch)
	log.Info("trying the artifact out before its first use")
	res := p.r.Trials.Run(p.ctx, p.r.Artifacts.BinaryPath(ref), ref.Binary, trialer.Trial(ref.Version))
	if !res.Ran {
		log.Warn("the trial of the artifact did not run", "reason", res.Reason)
		return untried(res.Reason)
	}
	rec := artifacts.TrialRecord{OK: res.OK, Reason: res.Reason, At: p.r.now(), Image: p.r.RunnerImage}
	if err := p.r.Artifacts.RecordTrial(ref, rec); err != nil {
		// An outcome the node cannot keep is no outcome: the next pass tries
		// again, and GetInfo never shows a verdict that is not on disk.
		log.Error("the trial record could not be written", "err", err)
		return untried("recording the trial: " + err.Error())
	}
	if !res.OK {
		return artifactVerdict{tried: true, reason: "artifact unusable: " + what + ": " + res.Reason}
	}
	return artifactVerdict{ok: true, tried: true}
}

// ---- orphan trial containers ------------------------------------------------------

// sweepTrials removes the orphan trial containers the inventory found: those
// not in flight at the node's runner and older than orphanTrialAge. A trial of
// UploadArtifact that runs now is in flight, and is never one. Nothing here
// fails the pass.
func (p *pass) sweepTrials() error {
	var inFlight map[string]bool
	if p.r.Trials != nil {
		inFlight = p.r.Trials.InFlight()
	}
	now := p.r.now()
	for _, c := range p.trialContainers {
		if inFlight[c.Name] || now.Sub(c.Created) <= orphanTrialAge {
			continue
		}
		if err := p.removeContainer(c.Name, false); err != nil {
			p.r.log().Warn("could not remove an orphan trial container", "container", c.Name, "err", err)
			continue
		}
		p.r.event(evOrphanRemoved, sevInfo, "",
			fmt.Sprintf("removed the trial container %s that no running trial owns", c.Name),
			map[string]string{"container": c.Name})
	}
	return nil
}

// ---- garbage collection -----------------------------------------------------------

// collectArtifacts removes the artifacts that nothing needs and the stale
// stage directories, at most once an hour. It needs the inventory of the
// mounts of every managed container: when Docker cannot give it, nothing is
// removed this time, and the next pass tries again (lastGC marks only a
// collection that ran).
func (p *pass) collectArtifacts() {
	now := p.r.now()
	if !p.r.lastGC.IsZero() && now.Sub(p.r.lastGC) < gcEvery {
		return
	}
	log := p.r.log()

	mounted, err := p.mountedPaths()
	if err != nil {
		log.Warn("artifacts not collected: the mounts of the containers are not known", "err", err)
		return
	}
	p.r.lastGC = now
	for _, rec := range p.rt.Instances {
		for _, path := range []string{rec.BinaryPath, rec.PreviousBinaryPath} {
			if path != "" {
				mounted = append(mounted, filepath.Clean(path))
			}
		}
	}
	for _, rec := range p.rt.Egresses {
		for _, path := range []string{rec.BinaryPath, rec.PreviousBinaryPath} {
			if path != "" {
				mounted = append(mounted, filepath.Clean(path))
			}
		}
	}
	desired := map[string]bool{}
	for _, a := range p.st.GetArtifacts() {
		desired[artifactKey(a.GetEngine(), a.GetVersion(), a.GetArch())] = true
	}

	stored := p.r.Artifacts.List()
	recent := p.recentVersions(stored, now)
	for _, ref := range stored {
		key := artifactKey(ref.Engine, ref.Version, ref.Arch)
		dir := p.r.Artifacts.Dir(ref)
		if desired[key] || recent[key] || dir == "" || slices.ContainsFunc(mounted, func(path string) bool { return within(path, dir) }) {
			continue
		}
		if err := p.r.Artifacts.Remove(ref); err != nil {
			log.Warn("could not remove an artifact", "engine", ref.Engine, "version", ref.Version, "arch", ref.Arch, "err", err)
			continue
		}
		p.r.event(evArtifactRemoved, sevInfo, "",
			fmt.Sprintf("removed the artifact %s %s for %s that nothing needs", ref.Engine, ref.Version, ref.Arch),
			map[string]string{"engine": ref.Engine, "version": ref.Version, "arch": ref.Arch, "sha256": strings.ToLower(ref.SHA256)})
	}
	p.removeStaleStages(now)
}

// mountedPaths lists the host paths every managed container binds (Binds of
// its inspect answer), cleaned. Every Docker call has its own deadline, so
// that many containers do not time the inventory out. A container that went
// away between the list and its inspection binds nothing.
func (p *pass) mountedPaths() ([]string, error) {
	list, err := p.listManaged()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range list {
		d, err := p.inspectOne(c.ID)
		if errors.Is(err, dockerapi.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, b := range d.Binds {
			host, _, _ := strings.Cut(b, ":")
			if host != "" {
				out = append(out, filepath.Clean(host))
			}
		}
	}
	return out, nil
}

// listManaged lists the managed containers, running or not, under one
// Docker deadline.
func (p *pass) listManaged() ([]dockerapi.Container, error) {
	ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
	defer cancel()
	return p.r.Docker.List(ctx, map[string]string{labelManaged: "true"}, true)
}

// inspectOne inspects one container under one Docker deadline.
func (p *pass) inspectOne(id string) (*dockerapi.ContainerDetails, error) {
	ctx, cancel := context.WithTimeout(p.ctx, dockerTimeout)
	defer cancel()
	return p.r.Docker.Inspect(ctx, id)
}

// recentVersions is the set of the keepVersions most recently used versions
// of every engine and architecture among the stored artifacts, by the time of
// their last trial, or of their upload (the binary's modification time) when
// they were never tried. A version whose trial failed is never a rollback
// target and takes no slot.
func (p *pass) recentVersions(stored []artifacts.Ref, now time.Time) map[string]bool {
	type used struct {
		key string
		at  time.Time
	}
	byGroup := map[string][]used{}
	for _, ref := range stored {
		at := time.Time{}
		if rec, ok := p.r.Artifacts.Trial(ref); ok {
			if !rec.OK {
				continue
			}
			at = rec.At
		} else if info, err := os.Stat(p.r.Artifacts.BinaryPath(ref)); err == nil {
			at = info.ModTime()
		}
		if at.After(now) {
			at = now // a clock that went back does not make an artifact the newest forever
		}
		group := strings.ToLower(ref.Engine) + "/" + ref.Arch
		byGroup[group] = append(byGroup[group], used{artifactKey(ref.Engine, ref.Version, ref.Arch), at})
	}
	out := map[string]bool{}
	for _, list := range byGroup {
		slices.SortStableFunc(list, func(a, b used) int { return b.at.Compare(a.at) })
		for i, u := range list {
			if i >= keepVersions {
				break
			}
			out[u.key] = true
		}
	}
	return out
}

// removeStaleStages removes the scratch directories of the store older than
// staleStageAge: what an upload that died left behind.
func (p *pass) removeStaleStages(now time.Time) {
	entries, err := os.ReadDir(p.r.Artifacts.Root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), stagePrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < staleStageAge {
			continue
		}
		dir := filepath.Join(p.r.Artifacts.Root, e.Name())
		if err := os.RemoveAll(dir); err != nil {
			p.r.log().Warn("could not remove a stale stage directory of the artifact store", "dir", dir, "err", err)
			continue
		}
		p.r.log().Info("removed a stale stage directory of the artifact store", "dir", dir)
	}
}

// artifactKey names an artifact by engine (case folded), version and
// architecture.
func artifactKey(engine, version, arch string) string {
	return strings.ToLower(engine) + "/" + version + "/" + arch
}

// within reports whether path is dir or inside it.
func within(path, dir string) bool {
	dir = filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}
