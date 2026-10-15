package versions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/version"
)

// panelUpdate is what the panel's own update needs: the updater, the
// function that stops the panel for its restart (after the answer), and the
// one that says whether the node kit of the image is signed.
type panelUpdate struct {
	u         *selfupdate.Updater
	restart   func()
	kitSigned func() bool
}

// SetUpdater gives the service the panel's updater. restart is called once
// UpdatePanel has installed a version: the server stops as on SIGTERM (the
// answer is sent first) and the process exits with selfupdate.ExitRestart.
// kitSigned says whether the node kit that the image carries has signature
// files (they are not verified here; the node verifies them on install); nil
// is false.
func (s *Service) SetUpdater(u *selfupdate.Updater, restart func(), kitSigned func() bool) {
	s.panel = panelUpdate{u: u, restart: restart, kitSigned: kitSigned}
}

// testKeysWarning is the key warning of a binary that trusts test keys.
const testKeysWarning = "test-release-keys"

// GetPanelVersion says which version the panel runs and which image it
// started from, whether it can update itself and why not (the launcher, bin,
// the release key, the nodes that the newest release would leave behind, spec
// section 6), the newer releases of Postern, what the last update did, whether
// the image's node kit is signed and whether the panel trusts test keys.
func (s *Service) GetPanelVersion(ctx context.Context, _ *connect.Request[panelv1.GetPanelVersionRequest]) (*connect.Response[panelv1.GetPanelVersionResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	out := &panelv1.GetPanelVersionResponse{Version: version.Version, Commit: version.Commit, Date: version.Date,
		TrustsTestKeys: slices.Contains(release.KeyWarnings(), testKeysWarning)}
	if s.panel.kitSigned != nil {
		out.KitSigned = s.panel.kitSigned()
	}
	last, err := selfupdate.LastUpdate(ctx, s.db)
	if err != nil {
		return nil, internal(err)
	}
	out.LastUpdate = last
	u := s.panel.u
	if u == nil {
		out.CannotUpdateReason = "the panel has no updater"
		return connect.NewResponse(out), nil
	}
	out.ImageVersion = u.ImageVersion(ctx)
	newer, err := u.Newer(ctx)
	if err != nil {
		return nil, internal(err)
	}
	for i := range newer {
		out.Releases = append(out.Releases, toRelease(&newer[i], nil))
	}
	out.CanUpdate, out.CannotUpdateReason = u.Available(ctx)
	if out.CanUpdate && len(newer) > 0 {
		old, floor, err := u.OldNodes(ctx, newer[0].Version)
		if err != nil {
			return nil, internal(err)
		}
		if len(old) > 0 {
			out.CanUpdate = false
			out.CannotUpdateReason = fmt.Sprintf("these nodes run an agent older than %s, the oldest that %s supports: %s; update them first",
				floor, newer[0].Version, strings.Join(old, ", "))
		}
	}
	return connect.NewResponse(out), nil
}

// UpdatePanel installs a release of Postern as the panel's binary and
// restarts the panel into it: the answer says so, and then the panel stops.
// A refusal (a version that is not newer, a node too old, a panel that its
// launcher did not start, a binary that does not run) is FailedPrecondition
// with the reason.
func (s *Service) UpdatePanel(ctx context.Context, req *connect.Request[panelv1.UpdatePanelRequest]) (*connect.Response[panelv1.UpdatePanelResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.panel.u == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the panel has no updater"))
	}
	v := req.Msg.GetVersion()
	err := s.panel.u.Update(ctx, v)
	switch {
	case errors.Is(err, selfupdate.ErrRestart):
		if s.panel.restart != nil {
			s.panel.restart()
		}
		return connect.NewResponse(&panelv1.UpdatePanelResponse{Version: v, Restarting: true}), nil
	case errors.Is(err, selfupdate.ErrBadVersion):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, selfupdate.ErrRefused):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		s.log.Error("the update of the panel failed", "version", v, "err", err)
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return nil, internal(errors.New("the update returned without restarting"))
}

// SetReleases gives the service Postern's own release source, which
// GetReleaseSource and SetReleaseSource work on (its database and the key of
// the sealed tokens). Without one they answer that they are not implemented.
func (s *Service) SetReleases(r *selfupdate.Releases) { s.releases = r }

// errNoReleases is the answer of the release-source procedures of a service
// that has no release source.
var errNoReleases = connect.NewError(connect.CodeUnimplemented, errors.New("the release source is not available"))

// GetReleaseSource says where the releases of Postern come from, whether the
// tokens are set (never the tokens) and whether prereleases are followed.
func (s *Service) GetReleaseSource(ctx context.Context, _ *connect.Request[panelv1.GetReleaseSourceRequest]) (*connect.Response[panelv1.GetReleaseSourceResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.releases == nil {
		return nil, errNoReleases
	}
	src, err := s.releaseSource(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.GetReleaseSourceResponse{Source: src}), nil
}

// SetReleaseSource changes where the releases of Postern come from, whether
// prereleases are followed, and the tokens: a token that is not set in the
// request stays, an empty one is removed, another replaces it. The tokens are
// sealed and never logged or returned. The source is checked
// (selfupdate.ValidateSource) before anything is written. Audited as
// versions.release_source.set, without the tokens.
func (s *Service) SetReleaseSource(ctx context.Context, req *connect.Request[panelv1.SetReleaseSourceRequest]) (*connect.Response[panelv1.SetReleaseSourceResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.releases == nil {
		return nil, errNoReleases
	}
	in := req.Msg.GetSource()
	if in == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("no source"))
	}
	rs := store.ReleaseSource{Kind: in.GetKind(), BaseURL: in.GetBaseUrl(), Repo: in.GetRepo()}
	if err := selfupdate.ValidateSource(rs); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	err := selfupdate.SetSource(ctx, s.releases.DB, s.releases.Key, rs, in.GetIncludePrereleases(), req.Msg.Token, req.Msg.GithubToken)
	if err != nil {
		return nil, internal(fmt.Errorf("set release source: %w", err))
	}
	// The releases that GetPanelVersion lists come from the new source now.
	if s.panel.u != nil {
		s.panel.u.ForgetListed()
	}
	details := map[string]string{"kind": rs.Kind, "repo": rs.Repo, "base_url": rs.BaseURL,
		"include_prereleases": fmt.Sprint(in.GetIncludePrereleases())}
	if req.Msg.Token != nil {
		details["token"] = changed(*req.Msg.Token)
	}
	if req.Msg.GithubToken != nil {
		details["github_token"] = changed(*req.Msg.GithubToken)
	}
	s.audit(ctx, "versions.release_source.set", "settings:"+store.SettingReleaseSource, details)
	src, err := s.releaseSource(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.SetReleaseSourceResponse{Source: src}), nil
}

// changed says what happened to a token, for the audit log: "set" or "removed".
func changed(token string) string {
	if token == "" {
		return "removed"
	}
	return "set"
}

// releaseSource reads the source as the API shows it.
func (s *Service) releaseSource(ctx context.Context) (*panelv1.ReleaseSource, error) {
	rs, err := s.db.ReleaseSource(ctx)
	if err != nil {
		return nil, internal(err)
	}
	out := &panelv1.ReleaseSource{Kind: rs.Kind, BaseUrl: rs.BaseURL, Repo: rs.Repo}
	if _, err := s.db.GetSetting(ctx, store.SettingIncludePrereleases, &out.IncludePrereleases); err != nil {
		return nil, internal(err)
	}
	if _, out.HasToken, err = s.db.SealedSetting(ctx, store.SettingSourceToken); err != nil {
		return nil, internal(err)
	}
	if _, out.HasGithubToken, err = s.db.SealedSetting(ctx, store.SettingGitHubToken); err != nil {
		return nil, internal(err)
	}
	return out, nil
}
