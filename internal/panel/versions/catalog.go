package versions

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// SetCatalog gives the service the release catalog that ListComponents,
// ListReleases, RefreshReleases, PrepareRelease and RecheckRelease work on.
// Without one they answer that they are not implemented.
func (s *Service) SetCatalog(c *releases.Catalog) { s.catalog = c }

// errNoCatalog is the answer of the catalog procedures of a service that has
// no catalog.
var errNoCatalog = connect.NewError(connect.CodeUnimplemented, errors.New("the release catalog is not available"))

// ListComponents returns every component with the versions of its channels,
// the newest release of each channel for the architectures of the nodes, and
// the state of its feed, with the default channel of the panel and whether
// prereleases are followed.
func (s *Service) ListComponents(ctx context.Context, _ *connect.Request[panelv1.ListComponentsRequest]) (*connect.Response[panelv1.ListComponentsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.catalog == nil {
		return nil, errNoCatalog
	}
	resp, err := s.components(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// components builds the ListComponentsResponse.
func (s *Service) components(ctx context.Context) (*panelv1.ListComponentsResponse, error) {
	chans, err := s.db.ChannelVersions(ctx)
	if err != nil {
		return nil, internal(err)
	}
	archs, err := s.catalog.NodeArchs(ctx)
	if err != nil {
		return nil, internal(err)
	}
	resp := &panelv1.ListComponentsResponse{DefaultChannel: store.ChannelStable}
	if _, err := s.db.GetSetting(ctx, store.SettingDefaultChannel, &resp.DefaultChannel); err != nil {
		return nil, internal(err)
	}
	if _, err := s.db.GetSetting(ctx, store.SettingIncludePrereleases, &resp.IncludePrereleases); err != nil {
		return nil, internal(err)
	}
	followed, err := s.followedChannels(ctx, cmp.Or(resp.DefaultChannel, store.ChannelStable))
	if err != nil {
		return nil, internal(err)
	}
	for _, comp := range releases.Components {
		pc := &panelv1.Component{Name: comp.Name, Kind: comp.Kind, ChannelVersions: map[string]string{}, Newest: map[string]string{},
			FollowedChannels: followed[comp.Name]}
		for ch, v := range chans[comp.Name] {
			pc.ChannelVersions[ch] = v
		}
		for _, ch := range []string{store.ChannelStable, store.ChannelLatest} {
			v, err := s.catalog.Newest(ctx, comp.Name, ch, archs)
			if err != nil {
				return nil, internal(err)
			}
			if v != "" {
				pc.Newest[ch] = v
			}
		}
		feed, err := s.db.Feed(ctx, s.catalog.Source(ctx, comp).ListURL())
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, internal(err)
		}
		if err == nil {
			pc.CheckedUnix, pc.FeedError = feed.CheckedAt.Unix(), feed.LastError
			if feed.CheckedAt.IsZero() {
				pc.CheckedUnix = 0
			}
		}
		resp.Components = append(resp.Components, pc)
	}
	return resp, nil
}

// followedChannels returns, by engine, the channels that a proxy follows,
// sorted: a proxy that the rollout of the channel would take
// (rollout.FollowsEngine). def is the default channel. Providers are not in
// it: telling what a node runs means assembling its state.
func (s *Service) followedChannels(ctx context.Context, def string) (map[string][]string, error) {
	nodes, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]*store.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	ps, err := s.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	add := func(comp, channel string) {
		if !slices.Contains(out[comp], channel) {
			out[comp] = append(out[comp], channel)
		}
	}
	channels := []string{store.ChannelStable, store.ChannelLatest}
	for _, p := range ps {
		n := byID[p.NodeID]
		if n == nil {
			continue
		}
		for _, comp := range []string{store.EngineTelemt, store.EngineMtg} {
			for _, ch := range channels {
				if rollout.FollowsEngine(n, p, def, comp, ch) {
					add(comp, ch)
				}
			}
		}
	}
	for _, chans := range out {
		slices.Sort(chans)
	}
	return out, nil
}

// ListReleases returns the releases of a component, newest first, each with
// the channels whose version it is.
func (s *Service) ListReleases(ctx context.Context, req *connect.Request[panelv1.ListReleasesRequest]) (*connect.Response[panelv1.ListReleasesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.catalog == nil {
		return nil, errNoCatalog
	}
	// postern, which the proto names among the components, is the releases of
	// Postern that the panel knows (a release source, an upload); they follow
	// no channel (GetPanelVersion has the rest).
	if req.Msg.Component == selfupdate.ComponentPostern {
		rels, err := s.db.ListReleases(ctx, selfupdate.ComponentPostern)
		if err != nil {
			return nil, internal(err)
		}
		resp := &panelv1.ListReleasesResponse{}
		for _, rel := range rels {
			resp.Releases = append(resp.Releases, toRelease(rel, nil))
		}
		return connect.NewResponse(resp), nil
	}
	comp, err := componentArg(req.Msg.Component)
	if err != nil {
		return nil, err
	}
	rels, err := s.db.ListReleases(ctx, comp.Name)
	if err != nil {
		return nil, internal(err)
	}
	chans, err := s.db.ChannelVersions(ctx)
	if err != nil {
		return nil, internal(err)
	}
	resp := &panelv1.ListReleasesResponse{}
	for _, rel := range rels {
		resp.Releases = append(resp.Releases, toRelease(rel, chans[comp.Name]))
	}
	return connect.NewResponse(resp), nil
}

// RefreshReleases polls the feed of a component, or of every component, now.
// A component refreshed less than a minute ago, or whose source does not
// answer, is UNAVAILABLE; the others are still polled, and the response of a
// call that went through lists the components as ListComponents does.
func (s *Service) RefreshReleases(ctx context.Context, req *connect.Request[panelv1.RefreshReleasesRequest]) (*connect.Response[panelv1.RefreshReleasesResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.catalog == nil {
		return nil, errNoCatalog
	}
	var names []string
	if req.Msg.Component != "" {
		comp, err := componentArg(req.Msg.Component)
		if err != nil {
			return nil, err
		}
		names = []string{comp.Name}
	} else {
		for _, comp := range releases.Components {
			names = append(names, comp.Name)
		}
	}
	var errs []error
	for _, name := range names {
		err := s.catalog.Refresh(ctx, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		if !errors.Is(err, releases.ErrTooSoon) {
			// A refusal within the minute did nothing, and is not audited.
			s.audit(ctx, "versions.releases.refresh", "component:"+name, nil)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	list, err := s.components(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.RefreshReleasesResponse{Components: list.Components}), nil
}

// PrepareRelease downloads, verifies and checks the assets of a release for
// the given architectures, or for those of the nodes when none are given
// (FAILED_PRECONDITION when there are no nodes either). An asset that fails a
// check is FAILED_PRECONDITION; a source that does not answer UNAVAILABLE.
func (s *Service) PrepareRelease(ctx context.Context, req *connect.Request[panelv1.PrepareReleaseRequest]) (*connect.Response[panelv1.PrepareReleaseResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.catalog == nil {
		return nil, errNoCatalog
	}
	comp, err := componentArg(req.Msg.Component)
	if err != nil {
		return nil, err
	}
	if !s.catalog.Known(ctx, comp.Name, req.Msg.Version) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no release %s %s", comp.Name, req.Msg.Version))
	}
	archs := req.Msg.Archs
	for _, a := range archs {
		if !slices.Contains(releases.Archs, a) {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown architecture %q", a))
		}
	}
	if len(archs) == 0 {
		if archs, err = s.catalog.NodeArchs(ctx); err != nil {
			return nil, internal(err)
		}
		if len(archs) == 0 {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no architectures: there is no node to take them from"))
		}
	}
	s.audit(ctx, "versions.releases.prepare", "release:"+comp.Name+"/"+req.Msg.Version, map[string]string{"archs": strings.Join(archs, ",")})
	if err := s.catalog.Prepare(ctx, comp.Name, req.Msg.Version, archs); err != nil {
		return nil, catalogError(err)
	}
	rel, err := s.release(ctx, comp.Name, req.Msg.Version)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.PrepareReleaseResponse{Release: rel}), nil
}

// RecheckRelease puts an asset back to unchecked and prepares it again.
func (s *Service) RecheckRelease(ctx context.Context, req *connect.Request[panelv1.RecheckReleaseRequest]) (*connect.Response[panelv1.RecheckReleaseResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.catalog == nil {
		return nil, errNoCatalog
	}
	comp, err := componentArg(req.Msg.Component)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(releases.Archs, req.Msg.Arch) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown architecture %q", req.Msg.Arch))
	}
	s.audit(ctx, "versions.releases.recheck", "release:"+comp.Name+"/"+req.Msg.Version, map[string]string{"arch": req.Msg.Arch})
	if err := s.catalog.Recheck(ctx, comp.Name, req.Msg.Version, req.Msg.Arch); err != nil {
		return nil, catalogError(err)
	}
	rel, err := s.release(ctx, comp.Name, req.Msg.Version)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.RecheckReleaseResponse{Release: rel}), nil
}

// release reads one release for a response.
func (s *Service) release(ctx context.Context, component, version string) (*panelv1.Release, error) {
	rel, err := s.db.ReleaseOf(ctx, component, version)
	if err != nil {
		return nil, internal(err)
	}
	chans, err := s.db.ChannelVersions(ctx)
	if err != nil {
		return nil, internal(err)
	}
	return toRelease(rel, chans[component]), nil
}

// componentArg returns the component named, or INVALID_ARGUMENT.
func componentArg(name string) (releases.Component, error) {
	comp, ok := releases.ComponentOf(name)
	if !ok {
		return releases.Component{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown component %q", name))
	}
	return comp, nil
}

// catalogError turns an error of the catalog into a Connect error: no such
// release or asset is NOT_FOUND; an asset that failed a check, or has no pin,
// FAILED_PRECONDITION; a refresh too soon, or a source that does not answer,
// UNAVAILABLE.
func catalogError(err error) error {
	switch {
	case errors.Is(err, releases.ErrUnknown), errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, releases.ErrUnusable), errors.Is(err, releases.ErrChecksumMismatch), errors.Is(err, releases.ErrNoPin):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	default:
		return connect.NewError(connect.CodeUnavailable, err)
	}
}

// internal is a Connect error of code internal for a failure of the database.
func internal(err error) error {
	return connect.NewError(connect.CodeInternal, err)
}

// toRelease converts a release, with the channels (of its component) whose
// version it is, sorted.
func toRelease(rel *store.Release, chans map[string]string) *panelv1.Release {
	out := &panelv1.Release{
		Component: rel.Engine, Version: rel.Version, Stable: rel.Stable, Prerelease: rel.Prerelease,
		Source: rel.Source, Notes: rel.Notes, Url: rel.URL,
	}
	if !rel.PublishedAt.IsZero() {
		out.PublishedUnix = rel.PublishedAt.Unix()
	}
	archs := make([]string, 0, len(rel.Assets))
	for arch := range rel.Assets {
		archs = append(archs, arch)
	}
	sort.Strings(archs)
	for _, arch := range archs {
		a := rel.Assets[arch]
		out.Assets = append(out.Assets, &panelv1.ReleaseAsset{Arch: arch, File: a.File, Sha256: a.SHA256, ShaSource: a.SHASource,
			State: a.State, Reason: a.Reason, Size: a.Size, NodeId: a.NodeID})
	}
	for ch, v := range chans {
		if v == rel.Version {
			out.Channels = append(out.Channels, ch)
		}
	}
	sort.Strings(out.Channels)
	return out
}
