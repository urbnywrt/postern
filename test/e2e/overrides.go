//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/release"
)

// The versions of upstream releases that the job of the stable list tries
// (scripts/stable.sh e2e, docs/releasing.md): with one of these set, the
// release host of the run serves that release of the component, its bytes and
// its checksum file from upstream, and the tests that run the component run
// it instead of the version they would take: TestPanelToNodeFakeTLS and
// TestVersions telemt, TestVersions mtg, TestEgressChainFailover Xray.
// (psiphon-core publishes no releases: its versions are pinned by hand.)
var overrideVars = []struct{ component, name string }{
	{"telemt", "POSTERN_E2E_TELEMT_VERSION"},
	{"mtg", "POSTERN_E2E_MTG_VERSION"},
	{"xray", "POSTERN_E2E_XRAY_VERSION"},
}

// overrideOf returns the version that the run is to try for the component,
// "" for none.
func overrideOf(component string) string {
	for _, o := range overrideVars {
		if o.component == component {
			return os.Getenv(o.name)
		}
	}
	return ""
}

// anyOverride names the first override that is set, "" when none is: a run
// with one may not skip a test, or a candidate would pass untried.
func anyOverride() string {
	for _, o := range overrideVars {
		if v := os.Getenv(o.name); v != "" {
			return o.name + "=" + v
		}
	}
	return ""
}

// checkOverrides fails the test for an override that is not a version.
func (e *env) checkOverrides() {
	e.t.Helper()
	for _, o := range overrideVars {
		if v := os.Getenv(o.name); v != "" && !release.ValidVersion(v) {
			e.fatalf("%s=%q is not a version", o.name, v)
		}
	}
}

// upstreamRelease downloads the asset of the component's release ver for the
// architecture of the run, and its checksum file when the component has one,
// from upstream (GitHub), as the release host serves them.
func (e *env) upstreamRelease(component, ver string) map[string][]byte {
	e.t.Helper()
	comp, ok := releases.ComponentOf(component)
	if !ok {
		e.fatalf("the panel knows no component %s", component)
	}
	file := comp.AssetName(ver, runtime.GOARCH)
	files := map[string][]byte{file: e.download(comp.DownloadURL(ver, file), 200<<20)}
	if comp.Sums.File != "" {
		sums := comp.SumsFile(ver, file)
		files[sums] = e.download(comp.DownloadURL(ver, sums), 64<<10)
	}
	e.logf("%s %s from upstream: %s and its checksum file", component, ver, file)
	return files
}

// download fetches u, at most limit bytes.
func (e *env) download(u string, limit int64) []byte {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		e.fatalf("%v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.fatalf("downloading %s: %v", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		e.fatalf("downloading %s: %s", u, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		e.fatalf("downloading %s: %v", u, err)
	}
	if int64(len(data)) > limit {
		e.fatalf("downloading %s: larger than %d bytes", u, limit)
	}
	return data
}

// prepareRelease waits until the panel's catalog lists the release of the
// component (its first poll of the release host), and prepares it: the panel
// pins its SHA-256 from the checksum file and checks it.
func (e *env) prepareRelease(a *api, component, ver string) {
	e.t.Helper()
	e.waitFor(fmt.Sprintf("%s %s in the catalog", component, ver), 3*time.Minute, 2*time.Second,
		func(ctx context.Context) (bool, string, error) {
			r, err := a.versions.ListReleases(ctx, connect.NewRequest(&panelv1.ListReleasesRequest{Component: component}))
			if err != nil {
				return false, "", fmt.Errorf("ListReleases: %w", err)
			}
			var have []string
			for _, rel := range r.Msg.GetReleases() {
				if rel.GetVersion() == ver {
					return true, "listed", nil
				}
				have = append(have, rel.GetVersion())
			}
			return false, fmt.Sprintf("%v", have), nil
		})
	r, err := a.versions.PrepareRelease(e.ctx, connect.NewRequest(&panelv1.PrepareReleaseRequest{Component: component, Version: ver}))
	if err != nil {
		e.fatalf("PrepareRelease(%s %s): %v", component, ver, err)
	}
	for _, as := range r.Msg.GetRelease().GetAssets() {
		e.logf("%s %s for %s: %s, SHA-256 from %s", component, ver, as.GetArch(), as.GetState(), as.GetShaSource())
	}
}

// addUpstream puts the upstream release ver of the component into the release
// list of its repository on the release host.
func (e *env) addUpstream(h *releaseHost, component, ver string) {
	e.t.Helper()
	comp, ok := releases.ComponentOf(component)
	if !ok {
		e.fatalf("the panel knows no component %s", component)
	}
	h.add(comp.Repo, ver, e.upstreamRelease(component, ver))
}

// providerOverrides returns the environment of a panel that gets the
// providers that the run tries from a release host of the run, and those
// providers with their versions; nothing when the run tries none.
func (e *env) providerOverrides() (panelEnv []string, versions map[string]string) {
	e.t.Helper()
	versions = map[string]string{}
	for _, component := range []string{"xray"} {
		if v := overrideOf(component); v != "" {
			versions[component] = v
		}
	}
	if len(versions) == 0 {
		return nil, nil
	}
	h := e.newReleaseHost()
	for component, v := range versions {
		e.addUpstream(h, component, v)
	}
	return []string{"POSTERN_GITHUB_API=" + h.base}, versions
}

// rollProviders puts the node on the providers' versions, before it runs any
// egress: it follows the channel latest, and a version rollout of each
// provider moves the channel to the version.
func (e *env) rollProviders(a *api, nodeID string, versions map[string]string) {
	e.t.Helper()
	if len(versions) == 0 {
		return
	}
	r, err := a.versions.SetNodeChannel(e.ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{NodeId: nodeID, Channel: "latest", Confirm: true}))
	if err != nil || !r.Msg.GetApplied() {
		e.fatalf("SetNodeChannel(latest): applied %v, %v", r.Msg.GetApplied(), err)
	}
	for component, v := range versions {
		e.prepareRelease(a, component, v)
		sr, err := a.versions.StartRollout(e.ctx, connect.NewRequest(&panelv1.StartRolloutRequest{
			Kind: "version", Component: component, Channel: "latest", ToVersion: v, Mode: "auto", PauseSeconds: 2,
		}))
		if err != nil {
			e.fatalf("StartRollout(%s %s): %v", component, v, err)
		}
		id := sr.Msg.GetRollout().GetId()
		e.waitFor(fmt.Sprintf("the rollout of %s %s", component, v), 10*time.Minute, time.Second, func(ctx context.Context) (bool, string, error) {
			g, err := a.versions.GetRollout(ctx, connect.NewRequest(&panelv1.GetRolloutRequest{Id: id}))
			if err != nil {
				return false, "", fmt.Errorf("GetRollout: %w", err)
			}
			ro := g.Msg.GetRollout()
			switch ro.GetStatus() {
			case "completed":
				return true, "completed", nil
			case "failed", "aborted":
				return false, "", fmt.Errorf("the rollout is %s: %s", ro.GetStatus(), ro.GetError())
			}
			return false, ro.GetStatus(), nil
		})
	}
}
