package releases

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"aead.dev/minisign"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/version"
)

// DefaultGitHubAPI is the API base of GitHub, used when Config.APIBase and the
// environment variable POSTERN_GITHUB_API are empty.
const DefaultGitHubAPI = "https://api.github.com"

// The answers of the catalog.
var (
	ErrUnknown  = errors.New("releases: unknown component, version or architecture")
	ErrNoPin    = errors.New("releases: the asset has no pinned SHA-256 yet")
	ErrNotReady = errors.New("releases: the asset is not prepared")
	ErrUnusable = errors.New("releases: the asset is unusable")
)

// Config configures a Catalog.
type Config struct {
	DB *store.DB
	// Key opens the sealed tokens of the settings.
	Key seal.Key
	// Keys gives the trusted public keys of a key set; nil is release.TrustedKeys.
	Keys func(release.KeySet) ([]minisign.PublicKey, error)
	// Dir is where the assets are kept: <Dir>/<component>/<version>/<file>.
	Dir string
	// HTTP is the client of release traffic; nil is NewHTTPClient.
	HTTP *http.Client
	// APIBase is the API of GitHub; "" is DefaultGitHubAPI. (The panel sets it
	// from POSTERN_GITHUB_API; the catalog reads no environment itself.)
	APIBase string
	// Limiter paces the API requests; nil makes one. The panel shares one
	// between every user of the APIs.
	Limiter *Limiter
	Log     *slog.Logger
	Now     func() time.Time
	// PosternVersion is the version of this panel, whose release holds the
	// files of the Postern components (psiphon-core); "" is version.Version.
	PosternVersion string
}

// A Catalog keeps the releases of the components: it seeds the built-in ones,
// prepares assets (download, verify, extract, check) and answers what a node
// may be given.
type Catalog struct {
	db      *store.DB
	key     seal.Key
	keys    func(release.KeySet) ([]minisign.PublicKey, error)
	dir     string
	http    *http.Client
	apiBase string
	lim     *Limiter
	log     *slog.Logger
	now     func() time.Time
	// posternTag is the tag of the release of Postern that this panel is, ""
	// for a build that is no release.
	posternTag string

	mu    sync.Mutex
	locks map[string]*fileLock // by the path of the asset file

	// stableMu serialises ApplyStable: the tracker's refreshStable and the
	// bundle upload both apply lists.
	stableMu sync.Mutex

	// The tracker (tracker.go): when each component was last refreshed by
	// hand, when the stable list and the archive GC are next due, the
	// background work (the Prepares of found versions) and the context it
	// runs in, that of Run.
	refreshed  map[string]time.Time
	stableNext time.Time
	gcNext     time.Time
	bg         sync.WaitGroup
	bgCtx      context.Context
}

// A fileLock serialises the Prepares of one file: concurrent Prepares wait for
// the one download.
type fileLock struct {
	mu   sync.Mutex
	refs int
}

// New returns a catalog. It does not touch the database: call Seed.
func New(cfg Config) *Catalog {
	c := &Catalog{
		db: cfg.DB, key: cfg.Key, keys: cfg.Keys, dir: cfg.Dir, http: cfg.HTTP,
		apiBase: cfg.APIBase, lim: cfg.Limiter, log: cfg.Log, now: cfg.Now,
		locks: map[string]*fileLock{}, refreshed: map[string]time.Time{},
		posternTag: PosternTag(cmp.Or(cfg.PosternVersion, version.Version)),
	}
	if c.keys == nil {
		c.keys = release.TrustedKeys
	}
	if c.http == nil {
		c.http = NewHTTPClient()
	}
	if c.apiBase == "" {
		c.apiBase = DefaultGitHubAPI
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.lim == nil {
		c.lim = NewLimiter(c.now)
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	return c
}

// Limiter returns the limiter that every API request of the catalog goes
// through, for the other users of the APIs to share.
func (c *Catalog) Limiter() *Limiter { return c.lim }

// Source returns the feed source of a component: its repository on GitHub,
// with the panel's GitHub token when one is set. (A Postern component is
// downloaded from the release source of Postern: see sourceOf.)
func (c *Catalog) Source(ctx context.Context, comp Component) FeedSource {
	return FeedSource{Kind: SourceGitHub, APIBase: c.apiBase, Repo: comp.Repo, Token: c.githubToken(ctx)}
}

// sourceOf is where the files of a component are downloaded from, with which
// token: Source, or the release source of Postern for a Postern component.
func (c *Catalog) sourceOf(ctx context.Context, comp Component) (FeedSource, error) {
	if comp.Postern {
		return c.posternSource(ctx)
	}
	return c.Source(ctx, comp), nil
}

// githubToken returns the GitHub token of the settings, "" for none or when it
// cannot be opened (which is logged).
func (c *Catalog) githubToken(ctx context.Context) string {
	return c.sealedToken(ctx, store.SettingGitHubToken)
}

// sealedToken returns the token that the sealed setting key holds, "" for none
// or when it cannot be opened (which is logged, without the token).
func (c *Catalog) sealedToken(ctx context.Context, key string) string {
	sealed, ok, err := c.db.SealedSetting(ctx, key)
	if err != nil || !ok {
		if err != nil {
			c.log.Error("could not read a token", "setting", key, "err", err)
		}
		return ""
	}
	plain, err := seal.Open(c.key, sealed, []byte("setting:"+key))
	if err != nil {
		c.log.Error("could not open a token", "setting", key, "err", err)
		return ""
	}
	return string(plain)
}

// NodeArchs returns the architectures of the nodes, each once, sorted: what
// an asset is prepared for when nothing else is asked.
func (c *Catalog) NodeArchs(ctx context.Context) ([]string, error) {
	nodes, err := c.db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range nodes {
		if n.Arch == "" || seen[n.Arch] {
			continue
		}
		seen[n.Arch] = true
		out = append(out, n.Arch)
	}
	sort.Strings(out)
	return out, nil
}

// Seed stores the built-in releases: source builtin, stable, each asset pinned
// with its built-in SHA-256 (sha_source builtin), state unchecked until it is
// prepared. A release that is there keeps what it has (its notes, its states):
// only the pins are written, and a pin never changes. It runs on every start.
// The channel rows are not touched: the migration seeds them, once.
func (c *Catalog) Seed(ctx context.Context) error {
	rs, err := c.db.ReleaseSource(ctx)
	if err != nil {
		return err
	}
	for _, b := range builtins {
		comp, _ := ComponentOf(b.Component)
		// A Postern component is in the release of Postern that this panel is.
		tag, relURL := b.Tag, comp.ReleaseURL(b.Tag)
		download := func(file string) string { return comp.DownloadURL(tag, file) }
		if comp.Postern {
			tag, relURL = c.posternTag, PosternReleaseURL(rs, c.posternTag)
			download = func(file string) string { return PosternDownloadURL(rs, tag, file) }
		}
		rel := &store.Release{Engine: b.Component, Version: b.Version, Tag: tag, Source: store.SourceBuiltin, Stable: true,
			URL: relURL, FetchedAt: c.now()}
		if old, err := c.db.ReleaseOf(ctx, b.Component, b.Version); err == nil {
			rel = old
			rel.Source, rel.Stable = store.SourceBuiltin, true
			if comp.Postern {
				rel.Tag, rel.URL = tag, relURL // the files of this panel's release
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		rel.Assets = map[string]store.ReleaseAsset{}
		for arch, a := range b.Assets {
			rel.Assets[arch] = store.ReleaseAsset{File: a.File, URL: download(a.File),
				SHA256: a.SHA256, SHASource: store.SHASourceBuiltin}
		}
		err := c.db.UpsertRelease(ctx, rel)
		if errors.Is(err, store.ErrChecksumChanged) {
			// A pin from another source got there first and disagrees with
			// the built-in one: the built-in pin cannot be written over it (a
			// pin never changes), the start goes on, and the event says so.
			c.event(ctx, EventChecksumMismatch, "error",
				fmt.Sprintf("%s %s: a pinned SHA-256 disagrees with the built-in one; the built-in pin was not written", b.Component, b.Version),
				map[string]string{"component": b.Component, "version": b.Version, "source": store.SHASourceBuiltin, "from": "seed"})
			continue
		}
		if err != nil {
			return fmt.Errorf("releases: seed %s %s: %w", b.Component, b.Version, err)
		}
	}
	return nil
}

// asset returns the component, the release and the asset of this architecture,
// or ErrUnknown.
func (c *Catalog) asset(ctx context.Context, component, version, arch string) (Component, *store.Release, store.ReleaseAsset, error) {
	comp, ok := ComponentOf(component)
	if !ok {
		return Component{}, nil, store.ReleaseAsset{}, fmt.Errorf("%w: component %q", ErrUnknown, component)
	}
	rel, err := c.db.ReleaseOf(ctx, component, version)
	if errors.Is(err, store.ErrNotFound) {
		return comp, nil, store.ReleaseAsset{}, fmt.Errorf("%w: %s %s", ErrUnknown, component, version)
	}
	if err != nil {
		return comp, nil, store.ReleaseAsset{}, err
	}
	a, ok := rel.Assets[arch]
	if !ok {
		return comp, rel, a, fmt.Errorf("%w: %s %s has no asset for %s", ErrUnknown, component, version, arch)
	}
	if !safeFileName(a.File) {
		return comp, rel, a, fmt.Errorf("releases: %s %s %s: unsafe file name", component, version, arch)
	}
	return comp, rel, a, nil
}

// safeFileName reports whether name is a plain file name: one path element,
// not . or .., no separator of either kind.
func safeFileName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`) &&
		filepath.Base(name) == name && !strings.HasPrefix(name, ".")
}

// path returns where the asset file is kept.
func (c *Catalog) path(comp Component, version, file string) string {
	return filepath.Join(c.dir, comp.Name, version, file)
}

// lock takes the lock of the file at p and returns the function that gives it
// back.
func (c *Catalog) lock(p string) func() {
	c.mu.Lock()
	l := c.locks[p]
	if l == nil {
		l = &fileLock{}
		c.locks[p] = l
	}
	l.refs++
	c.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		c.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(c.locks, p)
		}
		c.mu.Unlock()
	}
}

// Prepare gets the asset of this version of a component for each of archs
// ready for the nodes: the expected SHA-256 by the checksum rules, the
// download (to a temporary file, renamed only once its SHA-256 matched), the
// extraction of the binary and the static-ELF check. The asset ends ready, or
// unusable with the reason (event release_unusable), or, when something that
// is not a finding failed (the network, the disk), as it was. A file that is
// already there and has the expected SHA-256 is not downloaded again. An
// asset that is unusable is left so, with ErrUnusable: only Recheck lifts the
// verdict. The errors of the architectures are joined.
//
// The static-ELF check is never weakened: a built-in asset whose binary fails
// it is set unusable too. R5-4 keeps a built-in asset's state from other
// sources (a checksum file, the stable list, a node's trial), not from the
// panel's own check of the file that the built-in SHA-256 names.
func (c *Catalog) Prepare(ctx context.Context, component, version string, archs []string) error {
	var errs []error
	for _, arch := range archs {
		if err := c.prepareArch(ctx, component, version, arch); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Catalog) prepareArch(ctx context.Context, component, version, arch string) error {
	comp, rel, a, err := c.asset(ctx, component, version, arch)
	if err != nil {
		return err
	}
	if a.State == store.AssetUnusable {
		// The verdict stands (a node's trial, a disagreeing source) until
		// Recheck lifts it: a file that matches the pin does not undo it.
		return fmt.Errorf("%w: %s %s %s: %s", ErrUnusable, comp.Name, rel.Version, arch, a.Reason)
	}
	dst := c.path(comp, rel.Version, a.File)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // G301: the nodes' engine files are public; the directory is the panel's data
		return err
	}
	unlock := c.lock(dst)
	defer unlock()

	src, err := c.sourceOf(ctx, comp)
	if err != nil {
		return err
	}
	exp, err := c.expected(ctx, comp, rel, arch, a, &src)
	if err != nil {
		return err
	}

	// The file, from the disk when it is there and is the expected one, else
	// from the network.
	sha, size := "", int64(0)
	if _, err := os.Stat(dst); err == nil {
		sha, size, err = fileSHA256(dst)
		if err != nil {
			return err
		}
		if exp.sha != "" && sha != exp.sha {
			_ = os.Remove(dst)
			_ = os.Remove(keptSignature(dst)) // it was for that file
			sha = ""
		}
	}
	if sha == "" {
		tmp := dst + ".part"
		sha, size, err = c.downloadTo(ctx, a.URL, &src, tmp)
		if err != nil {
			return err
		}
		if exp.sha != "" && sha != exp.sha {
			_ = os.Remove(tmp)
			return c.mismatch(ctx, comp, rel, arch, exp, sha)
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}

	reason := ""
	if comp.Postern {
		// The signature of the release of Postern that holds the file.
		if reason, err = c.checkSignature(ctx, comp, rel, arch, a, &src, dst); err != nil {
			return err
		}
	}
	if reason == "" {
		reason, err = c.checkBinary(ctx, dst, a.File, comp.MemberPath(rel.Version, arch), arch)
		if err != nil {
			return err
		}
	}
	if reason != "" {
		if exp.sha == "" {
			// TOFU: a download that fails is neither kept nor pinned.
			_ = os.Remove(dst)
		}
		c.setUnusable(ctx, comp, rel, arch, reason)
		return fmt.Errorf("%w: %s %s %s: %s", ErrUnusable, comp.Name, rel.Version, arch, reason)
	}

	// Ready: pin the SHA-256 that was found when there was none, record the
	// size and the verdict, and touch nothing else of the release: what was
	// read before the download (its stable flag, its notes) may be stale.
	return c.db.PinAsset(ctx, comp.Name, rel.Version, arch, sha, exp.source, size, store.AssetReady)
}

// Ref returns the artifact reference of the asset: what a desired state names.
// Any version whose asset has a pinned SHA-256 for arch is named, ready or not
// (F10); one without is ErrNoPin.
func (c *Catalog) Ref(ctx context.Context, component, version, arch string) (*nodev1.ArtifactRef, error) {
	comp, rel, a, err := c.asset(ctx, component, version, arch)
	if err != nil {
		return nil, err
	}
	return c.ref(comp, rel, arch, a)
}

func (c *Catalog) ref(comp Component, rel *store.Release, arch string, a store.ReleaseAsset) (*nodev1.ArtifactRef, error) {
	if a.SHA256 == "" {
		return nil, fmt.Errorf("%w: %s %s %s", ErrNoPin, comp.Name, rel.Version, arch)
	}
	return &nodev1.ArtifactRef{Engine: comp.Name, Version: rel.Version, Arch: arch, Sha256: a.SHA256,
		FileName: a.File, Url: a.URL, Binary: comp.Binary}, nil
}

// Ready says whether the asset may be uploaded to a node: it is ready and its
// file is there. An unusable asset is ErrUnusable, with the reason; one that is
// not prepared is ErrNotReady.
func (c *Catalog) Ready(ctx context.Context, component, version, arch string) error {
	comp, rel, a, err := c.asset(ctx, component, version, arch)
	if err != nil {
		return err
	}
	switch a.State {
	case store.AssetUnusable:
		return fmt.Errorf("%w: %s %s %s: %s", ErrUnusable, comp.Name, rel.Version, arch, a.Reason)
	case store.AssetReady:
		if _, err := os.Stat(c.path(comp, rel.Version, a.File)); err != nil {
			return fmt.Errorf("%w: %s %s %s: the file is gone", ErrNotReady, comp.Name, rel.Version, arch)
		}
		return nil
	}
	return fmt.Errorf("%w: %s %s %s", ErrNotReady, comp.Name, rel.Version, arch)
}

// Open opens the asset file for an upload, with its reference. The file is
// hashed while it is read: a SHA-256 at its end that is not the pinned one
// fails the read with ErrChecksumMismatch, deletes the file and puts the asset
// back to unchecked.
//
// Open does not gate on the asset's state: it opens the file of an asset that
// is unusable, or not yet ready, as long as it is pinned and the file is
// there. Ready is the gate; a caller that uploads asks it first.
func (c *Catalog) Open(ctx context.Context, component, version, arch string) (io.ReadCloser, *nodev1.ArtifactRef, error) {
	comp, rel, a, err := c.asset(ctx, component, version, arch)
	if err != nil {
		return nil, nil, err
	}
	ref, err := c.ref(comp, rel, arch, a)
	if err != nil {
		return nil, nil, err
	}
	p := c.path(comp, rel.Version, a.File)
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: %s %s %s: the file is gone", ErrNotReady, comp.Name, rel.Version, arch)
	}
	if err != nil {
		return nil, nil, err
	}
	hr := &hashReader{f: f, h: sha256.New(), want: a.SHA256}
	hr.onMismatch = func() {
		_ = os.Remove(p)
		bg := context.WithoutCancel(ctx)
		if err := c.db.SetAssetState(bg, comp.Name, rel.Version, arch, store.AssetUnchecked, "the file changed on disk", ""); err != nil {
			c.log.Error("could not reset an asset", "component", comp.Name, "version", rel.Version, "arch", arch, "err", err)
		}
		c.event(bg, EventChecksumMismatch, "error",
			fmt.Sprintf("%s %s %s: the file on disk has another SHA-256 than the pinned one; removed", comp.Name, rel.Version, arch),
			map[string]string{"component": comp.Name, "version": rel.Version, "arch": arch, "expected": a.SHA256, "from": "disk"})
	}
	return hr, ref, nil
}

// A hashReader reads a file and compares its SHA-256 with want at its end.
type hashReader struct {
	f          *os.File
	h          hash.Hash
	want       string
	done       bool
	onMismatch func()
}

func (r *hashReader) Read(p []byte) (int, error) {
	n, err := r.f.Read(p)
	if n > 0 {
		_, _ = r.h.Write(p[:n])
	}
	if errors.Is(err, io.EOF) && !r.done {
		r.done = true
		if got := hex.EncodeToString(r.h.Sum(nil)); got != r.want {
			r.onMismatch()
			return n, fmt.Errorf("%w: the file on disk", ErrChecksumMismatch)
		}
	}
	return n, err
}

func (r *hashReader) Close() error { return r.f.Close() }

// MarkUnusable records that a node's trial of the asset failed (only a trial
// that ran, Task 9). An asset that is not built in becomes unusable for that
// arch; a built-in one keeps its state (R5-4) and gets the node and the reason
// as a note, so that one node cannot block a channel's version everywhere.
// Both record the event release_unusable.
func (c *Catalog) MarkUnusable(ctx context.Context, component, version, arch, nodeID, reason string) error {
	comp, rel, a, err := c.asset(ctx, component, version, arch)
	if err != nil {
		return err
	}
	details := map[string]string{"component": comp.Name, "version": rel.Version, "arch": arch, "node_id": nodeID, "reason": reason}
	if a.SHASource == store.SHASourceBuiltin {
		if err := c.db.SetAssetState(ctx, comp.Name, rel.Version, arch, a.State, reason, nodeID); err != nil {
			return err
		}
		details["builtin"] = "true"
		c.event(ctx, EventUnusable, "warning",
			fmt.Sprintf("%s %s %s failed its trial on node %s (%s); the built-in pin keeps its state", comp.Name, rel.Version, arch, nodeID, reason), details)
		return nil
	}
	if err := c.db.SetAssetState(ctx, comp.Name, rel.Version, arch, store.AssetUnusable, reason, nodeID); err != nil {
		return err
	}
	c.event(ctx, EventUnusable, "warning",
		fmt.Sprintf("%s %s %s is unusable: failed its trial on node %s (%s)", comp.Name, rel.Version, arch, nodeID, reason), details)
	return nil
}

// Recheck puts an asset back to unchecked and prepares it again.
func (c *Catalog) Recheck(ctx context.Context, component, version, arch string) error {
	comp, rel, _, err := c.asset(ctx, component, version, arch)
	if err != nil {
		return err
	}
	if err := c.db.SetAssetState(ctx, comp.Name, rel.Version, arch, store.AssetUnchecked, "", ""); err != nil {
		return err
	}
	return c.Prepare(ctx, component, version, []string{arch})
}

// Known reports whether the catalog has this version of the component.
func (c *Catalog) Known(ctx context.Context, component, version string) bool {
	_, err := c.db.ReleaseOf(ctx, component, version)
	return err == nil
}

// InChannel reports whether the version of the component is in the channel:
// stable holds the stable releases; latest adds every other release, the
// prereleases only with the setting releases.include_prereleases. A version
// that is not known is in no channel.
func (c *Catalog) InChannel(ctx context.Context, component, channel, version string) (bool, error) {
	if channel != store.ChannelStable && channel != store.ChannelLatest {
		return false, fmt.Errorf("releases: unknown channel %q", channel)
	}
	rel, err := c.db.ReleaseOf(ctx, component, version)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return c.inChannel(ctx, rel, channel)
}

func (c *Catalog) inChannel(ctx context.Context, rel *store.Release, channel string) (bool, error) {
	if rel.Stable {
		return true, nil
	}
	if channel == store.ChannelStable {
		return false, nil
	}
	if !rel.Prerelease {
		return true, nil
	}
	var include bool
	if _, err := c.db.GetSetting(ctx, store.SettingIncludePrereleases, &include); err != nil {
		return false, err
	}
	return include, nil
}

// Newest returns the newest version of the component in the channel that has
// an asset for every one of archs and is unusable for none of them, "" when
// there is none.
func (c *Catalog) Newest(ctx context.Context, component, channel string, archs []string) (string, error) {
	if channel != store.ChannelStable && channel != store.ChannelLatest {
		return "", fmt.Errorf("releases: unknown channel %q", channel)
	}
	rels, err := c.db.ListReleases(ctx, component)
	if err != nil {
		return "", err
	}
	for _, rel := range rels {
		in, err := c.inChannel(ctx, rel, channel)
		if err != nil {
			return "", err
		}
		if !in {
			continue
		}
		ok := true
		for _, arch := range archs {
			a, has := rel.Assets[arch]
			if !has || a.State == store.AssetUnusable {
				ok = false
				break
			}
		}
		if ok {
			return rel.Version, nil
		}
	}
	return "", nil
}
