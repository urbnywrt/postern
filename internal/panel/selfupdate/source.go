// Package selfupdate is how the panel gets Postern's own releases: the
// release source (the Postern repository on GitHub or a Gitea, from the
// settings, with sealed tokens), a cache of binaries that are kept only with
// a verifying minisign signature, and the upload of a signed bundle by an
// admin for a panel that cannot reach the source. Installing a binary is Task
// 11b's.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/version"
)

// ComponentPostern is the component of Postern's own releases in the store.
const ComponentPostern = "postern"

// The limits of release traffic (Global Constraints, HTTP).
const (
	maxBinary       = 256 << 20 // a binary
	maxSignature    = 64 << 10  // a .minisig
	downloadTimeout = 5 * time.Minute
)

// The answers of the source.
var (
	// ErrBadSource is returned for a release source that cannot be used: an
	// unknown kind, a Gitea without an https:// base, a repo that is not
	// owner/name.
	ErrBadSource = errors.New("selfupdate: bad release source")
	// ErrNoRelease is returned when the source lists no release of the version.
	ErrNoRelease = errors.New("selfupdate: the release source has no such release")
	// ErrNoAsset is returned when the release has no asset of the name (or no
	// .minisig for it).
	ErrNoAsset = errors.New("selfupdate: the release has no such asset")
	// ErrTooLarge is returned for a download that is larger than its limit.
	ErrTooLarge = errors.New("selfupdate: the download is too large")
)

// Releases finds Postern's releases for the panel.
type Releases struct {
	DB *store.DB
	// Key opens the sealed tokens of the settings.
	Key seal.Key
	// HTTP is the client of release traffic; nil is releases.NewHTTPClient.
	HTTP *http.Client
	// Limiter paces the API requests; nil makes one. The panel gives the
	// catalog's, so that every API request shares it.
	Limiter *releases.Limiter
	// APIBase is the API of GitHub; "" is releases.DefaultGitHubAPI (the panel
	// sets it from POSTERN_GITHUB_API).
	APIBase string
	// Cache is where the binaries are kept.
	Cache *Cache
	Log   *slog.Logger
}

// A Source is the release source as the settings say, with its token (which
// is never logged) and whether prereleases are listed.
type Source struct {
	Kind        string // releases.SourceGitHub or releases.SourceGitea
	APIBase     string // the API of GitHub, or the base URL of the Gitea
	Repo        string // owner/name
	Token       string
	Prereleases bool

	http *http.Client
	lim  *releases.Limiter
}

// Source returns the release source of the settings (releases.source and
// releases.include_prereleases) with the sealed token: the source token, or
// for GitHub the GitHub token when there is no source token.
func (r *Releases) Source(ctx context.Context) (*Source, error) {
	rs, err := r.DB.ReleaseSource(ctx)
	if err != nil {
		return nil, err
	}
	if err := ValidateSource(rs); err != nil {
		return nil, err
	}
	src := &Source{Kind: rs.Kind, APIBase: rs.BaseURL, Repo: rs.Repo, Token: r.sealedToken(ctx, store.SettingSourceToken), http: r.HTTP, lim: r.Limiter}
	if src.Kind == releases.SourceGitHub {
		src.APIBase = r.APIBase
		if src.APIBase == "" {
			src.APIBase = releases.DefaultGitHubAPI
		}
		if src.Token == "" {
			src.Token = r.sealedToken(ctx, store.SettingGitHubToken)
		}
	}
	if _, err := r.DB.GetSetting(ctx, store.SettingIncludePrereleases, &src.Prereleases); err != nil {
		return nil, err
	}
	if src.http == nil {
		src.http = releases.NewHTTPClient()
	}
	return src, nil
}

// sealedToken returns the token that the sealed setting key holds, "" for none
// or when it cannot be opened (which is logged, without the token).
func (r *Releases) sealedToken(ctx context.Context, key string) string {
	sealed, ok, err := r.DB.SealedSetting(ctx, key)
	if err != nil || !ok {
		if err != nil {
			r.log().Error("could not read a token", "setting", key, "err", err)
		}
		return ""
	}
	plain, err := seal.Open(r.Key, sealed, []byte("setting:"+key))
	if err != nil {
		r.log().Error("could not open a token", "setting", key, "err", err)
		return ""
	}
	return string(plain)
}

func (r *Releases) log() *slog.Logger {
	if r.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Log
}

// ValidateSource reports whether a release source can be used: kind github
// (no base URL: the panel's GitHub API is used) or gitea (an https:// base URL,
// http:// for a loopback host, without userinfo, query or fragment), and a
// repo of the form owner/name made of letters, digits, '.', '_' and '-'.
func ValidateSource(s store.ReleaseSource) error {
	switch s.Kind {
	case releases.SourceGitHub:
		if s.BaseURL != "" {
			return fmt.Errorf("%w: a GitHub source takes no base URL (POSTERN_GITHUB_API sets the API)", ErrBadSource)
		}
	case releases.SourceGitea:
		u, err := url.Parse(s.BaseURL)
		if err != nil || checkScheme(s.BaseURL) != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return fmt.Errorf("%w: a Gitea source needs an https:// base URL", ErrBadSource)
		}
	default:
		return fmt.Errorf("%w: kind %q is not github or gitea", ErrBadSource, s.Kind)
	}
	owner, name, ok := strings.Cut(s.Repo, "/")
	if !ok || !repoWord(owner) || !repoWord(name) {
		return fmt.Errorf("%w: the repository is not owner/name", ErrBadSource)
	}
	return nil
}

// repoWord reports whether s is one part of a repository name.
func repoWord(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// SetSource stores the release source and whether prereleases are followed,
// and the tokens: a nil token leaves the stored one as it is, an empty one
// removes it, another replaces it. A token is sealed with key and the AAD
// "setting:<key>" and never stored in plain text.
func SetSource(ctx context.Context, db *store.DB, key seal.Key, s store.ReleaseSource, prereleases bool, token, githubToken *string) error {
	if err := ValidateSource(s); err != nil {
		return err
	}
	if err := db.PutReleaseSource(ctx, s); err != nil {
		return err
	}
	if err := db.PutSetting(ctx, store.SettingIncludePrereleases, prereleases); err != nil {
		return err
	}
	for _, t := range []struct {
		setting string
		value   *string
	}{{store.SettingSourceToken, token}, {store.SettingGitHubToken, githubToken}} {
		if t.value == nil {
			continue
		}
		var sealed []byte
		if *t.value != "" {
			var err error
			if sealed, err = seal.Seal(key, []byte(*t.value), []byte("setting:"+t.setting)); err != nil {
				return err
			}
		}
		if err := db.PutSealedSetting(ctx, t.setting, sealed); err != nil {
			return err
		}
	}
	return nil
}

// feed returns the source as the feed reader takes it.
func (s *Source) feed() releases.FeedSource {
	return releases.FeedSource{Kind: s.Kind, APIBase: s.APIBase, Repo: s.Repo, Token: s.Token}
}

// List returns the releases of the source, newest first (by release.Compare,
// equal versions by their strings), without prereleases unless the setting
// follows them. The release with tag engines-stable is not a version and is
// never listed. The list is read whole every time: nothing of it is stored,
// so a 304 would say nothing (F8).
func (s *Source) List(ctx context.Context) ([]releases.FeedRelease, error) {
	rels, _, _, _, err := releases.FetchReleases(ctx, s.http, s.lim, s.feed(), "", true)
	if err != nil {
		return nil, err
	}
	out := rels[:0]
	for _, r := range rels {
		if !isPosternTag(r.Tag) || r.Prerelease && !s.Prereleases {
			continue
		}
		out = append(out, r)
	}
	slices.SortStableFunc(out, func(a, b releases.FeedRelease) int {
		if c := release.Compare(b.Tag, a.Tag); c != 0 {
			return c
		}
		return strings.Compare(b.Tag, a.Tag)
	})
	return out, nil
}

// Release returns the release of the source whose tag is version (string
// equality), prerelease or not, or ErrNoRelease.
func (s *Source) Release(ctx context.Context, ver string) (*releases.FeedRelease, error) {
	rels, _, _, _, err := releases.FetchReleases(ctx, s.http, s.lim, s.feed(), "", true)
	if err != nil {
		return nil, err
	}
	for i := range rels {
		if rels[i].Tag == ver {
			return &rels[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNoRelease, ver)
}

// host returns the host of the API, to which alone the token is sent.
func (s *Source) host() string {
	u, err := url.Parse(s.APIBase)
	if err != nil {
		return ""
	}
	return u.Host
}

// open starts a GET of u with the panel's User-Agent and the token when u is
// on the source's host (F9: a Gitea serves its attachments from its own host;
// GitHub's downloads are on another host and get none), and returns the body,
// which the caller closes. Only https:// is taken, http:// for a loopback host
// (tests). The whole download has downloadTimeout.
func (s *Source) open(ctx context.Context, u string) (io.ReadCloser, error) {
	if err := checkScheme(u); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("selfupdate: %w", err)
	}
	req.Header.Set("User-Agent", "postern-panel/"+version.Version)
	if s.Token != "" && req.URL.Host != "" && req.URL.Host == s.host() {
		if s.Kind == releases.SourceGitea {
			req.Header.Set("Authorization", "token "+s.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+s.Token)
		}
	}
	hc := s.http
	if hc == nil {
		hc = releases.NewHTTPClient()
	}
	resp, err := hc.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("selfupdate: fetch %s: %w", redact(u), redactErr(err))
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("selfupdate: fetch %s: HTTP %d", redact(u), resp.StatusCode)
	}
	return &body{ReadCloser: resp.Body, cancel: cancel}, nil
}

// A body is a response body whose Close ends the download's timeout.
type body struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *body) Close() error {
	defer b.cancel()
	return b.ReadCloser.Close()
}

// download fetches u whole, at most max bytes, as open does.
func (s *Source) download(ctx context.Context, u string, max int64) ([]byte, error) {
	rc, err := s.open(ctx, u)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, fmt.Errorf("selfupdate: fetch %s: %w", redact(u), redactErr(err))
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: %s", ErrTooLarge, redact(u))
	}
	return b, nil
}

// redactErr strips the URL of a url.Error, which could carry a query.
func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, redact(ue.URL), ue.Err)
	}
	return err
}

// checkScheme refuses a URL that is not https://, unless its host is a
// loopback address, where http:// is taken.
func checkScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("selfupdate: %w", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("selfupdate: release traffic is https only: %s", redact(raw))
}

// redact returns u without its query and userinfo, for logs and errors.
func redact(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "<url>"
	}
	p.RawQuery, p.Fragment, p.User = "", "", nil
	return p.String()
}

// isPosternTag reports whether tag is a Postern release tag, vX.Y.Z (a "v"
// and a digit): the tag engines-stable, which carries the stable list, is a
// valid version string but no release.
func isPosternTag(tag string) bool {
	return len(tag) > 1 && tag[0] == 'v' && tag[1] >= '0' && tag[1] <= '9'
}
