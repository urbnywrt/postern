package selfupdate

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// UploadRoute is the path of the upload: POST, with the bundle as the body. A
// panel mounts [UploadHandler] under it.
const UploadRoute = "/api/releases/upload"

// The limits of an upload.
const (
	MaxUpload     = 256 << 20 // the bundle (Global Constraints, HTTP)
	maxStableList = 1 << 20   // engines-stable.json, as the catalog takes it
	stableFile    = "engines-stable.json"
	auditUpload   = "releases.upload"
	auditRefused  = "releases.upload.refused"
)

// A StableApplier takes a signed stable list: the release catalog.
type StableApplier interface {
	ApplyStable(ctx context.Context, list, sig []byte) error
}

// UploadConfig configures the upload.
type UploadConfig struct {
	Cache *Cache
	DB    *store.DB
	// Stable takes the engines-stable.json of a bundle; nil leaves the list
	// unapplied (and says so).
	Stable StableApplier
	Log    *slog.Logger
	// MaxBytes is the most a bundle may be; 0 is MaxUpload.
	MaxBytes int64
	Now      func() time.Time
	// Providers takes the binaries of the components that a release of
	// Postern builds besides itself (psiphon-core-linux-<arch>): the release
	// catalog. nil refuses them.
	Providers ProviderTaker
}

// A ProviderTaker keeps the binaries of the components that Postern builds
// (psiphon-core) for the nodes: the release catalog.
type ProviderTaker interface {
	// PinnedVersion returns the version of the component whose pin for arch
	// is sha, or an error that says there is none.
	PinnedVersion(ctx context.Context, component, arch, sha string) (string, error)
	// TakeUploaded keeps the verified file at path with its signature and
	// prepares it for the nodes; it returns the version.
	TakeUploaded(ctx context.Context, component, arch, path string, sig []byte) (string, error)
}

// providerComponents are the components besides Postern's own binaries that a
// bundle may hold: their assets are named <component>-linux-<arch> and signed
// "postern <component> <version> linux/<arch>" like the others.
var providerComponents = []string{"psiphon-core"}

// ProviderAsset returns the name of a provider binary's release asset.
func ProviderAsset(component, arch string) string { return component + "-" + binaryOS + "-" + arch }

// bundleAsset returns the component and the architecture of a binary that a
// bundle may hold: a release asset (ParseAsset) or a provider binary.
func bundleAsset(name string) (component, arch string, provider, ok bool) {
	if comp, a, ok := ParseAsset(name); ok {
		return comp, a, false, true
	}
	for _, comp := range providerComponents {
		for _, a := range archs {
			if name == ProviderAsset(comp, a) {
				return comp, a, true, true
			}
		}
	}
	return "", "", false, false
}

// bundleSignature reports whether name is the .minisig of a binary that a
// bundle may hold, and returns that binary's name.
func bundleSignature(name string) (asset string, ok bool) {
	asset, ok = strings.CutSuffix(name, ".minisig")
	if !ok {
		return "", false
	}
	_, _, _, ok = bundleAsset(asset)
	return asset, ok
}

// UploadResult is the JSON answer of the upload.
type UploadResult struct {
	// Version is the version of the bundle, as the signatures name it; "" when
	// the bundle has no binary with a readable signature.
	Version string `json:"version"`
	// Accepted says whether the binaries were taken into the cache and the
	// release recorded: every present one verified. Otherwise nothing is kept.
	Accepted bool `json:"accepted"`
	// Assets is every binary (or .minisig) the bundle named, with its verdict.
	Assets []AssetResult `json:"assets"`
	// Ignored are the members that are not release assets: paths, other names.
	Ignored []string `json:"ignored,omitempty"`
	// Stable is what became of engines-stable.json, when the bundle holds one.
	Stable *StableResult `json:"stable,omitempty"`
	// Error says why the whole bundle was refused before its assets were looked
	// at, for example "no binary in the bundle".
	Error string `json:"error,omitempty"`
}

// An AssetResult is the verdict on one asset.
type AssetResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// A StableResult says what became of the stable list of a bundle.
type StableResult struct {
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
}

// UploadHandler is POST /api/releases/upload: an admin sends a release bundle
// (postern-vX.Y.Z-bundle.tar: the binaries with their .minisig, and
// optionally engines-stable.json with its .minisig), Content-Type
// application/x-tar, at most 256 MiB, for a panel that cannot reach the
// release source. Only members with a known asset name are read (no paths),
// into a temporary directory; every binary needs its valid .minisig; the set
// is accepted only whole: when every present binary verified (by a release
// key, for its component, version, linux and architecture, a static ELF), the
// directory is moved into the cache at once and the release is recorded
// (component postern, source upload); otherwise nothing is kept and the
// answer lists each asset's reason (HTTP 422). The stable list goes to
// ApplyStable only when the rest was accepted. A bundle may hold the
// psiphon-core-linux-<arch> binaries too, signed like the others: each has to
// be the binary that the release catalog pins for its arch (any version of
// psiphon-core), and goes to the catalog (UploadConfig.Providers), not to the
// cache, so that the nodes get it from a panel that is no published release.
// The answer is an
// [UploadResult]. A bundle that is not a tar, or is cut short, is a 400; one
// over the limit a 413; one of a version whose upload is in flight a 409. A
// list without its .minisig (or the other way round) refuses the bundle whole,
// as any other half pair does. A version whose bytes differ from the recorded
// pin or the cached files is refused before anything is written (S5-13). An
// accepted upload is audited as releases.upload with the SHA-256 of every
// asset, a refused one as releases.upload.refused with the reasons.
//
// The route is not a Connect procedure, so the handler is wrapped in
// [auth.RequireAdmin]: a request without an admin session gets a 401 before
// its body is read.
func UploadHandler(cfg UploadConfig) http.Handler {
	return auth.RequireAdmin(http.HandlerFunc(cfg.serveUpload))
}

// inflight is the set of versions whose upload is being committed: a second
// upload of one version at the same time is refused with a 409 rather than
// racing the first for the version directory.
var inflight = struct {
	sync.Mutex
	versions map[string]bool
}{versions: map[string]bool{}}

// claim takes the version for an upload; it reports false when another
// upload holds it. unclaim gives it back.
func claim(version string) bool {
	inflight.Lock()
	defer inflight.Unlock()
	if inflight.versions[version] {
		return false
	}
	inflight.versions[version] = true
	return true
}

func unclaim(version string) {
	inflight.Lock()
	delete(inflight.versions, version)
	inflight.Unlock()
}

// errBusy says that an upload of the version is in flight.
var errBusy = errors.New("an upload of this version is in progress")

func (cfg UploadConfig) log() *slog.Logger {
	if cfg.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return cfg.Log
}

func (cfg UploadConfig) serveUpload(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		h.Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-tar" && !strings.HasPrefix(ct, "application/x-tar;") {
		http.Error(w, "the bundle has to be sent as application/x-tar", http.StatusUnsupportedMediaType)
		return
	}
	limit := cfg.MaxBytes
	if limit <= 0 {
		limit = MaxUpload
	}
	tooLarge := "the bundle is over " + strconv.FormatInt(limit, 10) + " bytes"
	if r.ContentLength > limit {
		http.Error(w, tooLarge, http.StatusRequestEntityTooLarge)
		return
	}

	res, err := cfg.upload(r.Context(), http.MaxBytesReader(w, r.Body, limit))
	var overRun *http.MaxBytesError
	var bad *bundleError
	switch {
	case err == nil:
	case errors.As(err, &overRun):
		http.Error(w, tooLarge, http.StatusRequestEntityTooLarge)
		return
	case errors.As(err, &bad):
		http.Error(w, bad.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, errBusy):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case r.Context().Err() != nil:
		return // the admin went away: nobody is left to answer
	default:
		cfg.log().Error("could not take an uploaded release bundle", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Audited either way: an accepted upload as releases.upload with the
	// SHA-256 of every asset, a refused one as releases.upload.refused with
	// the reasons.
	status := http.StatusUnprocessableEntity
	action := auditRefused
	if res.Accepted {
		status, action = http.StatusOK, auditUpload
	}
	adminID := ""
	if admin, ok := auth.AdminFrom(r.Context()); ok {
		adminID = admin.ID
	}
	details := map[string]string{"version": res.Version}
	if res.Error != "" {
		details["error"] = res.Error
	}
	for _, a := range res.Assets {
		if a.OK {
			details["sha256:"+a.Name] = a.SHA256
		} else {
			details["refused:"+a.Name] = a.Reason
		}
	}
	if res.Stable != nil && res.Stable.Reason != "" {
		details["stable"] = res.Stable.Reason
	}
	entry := &store.AuditEntry{AdminID: adminID, Action: action, Target: "release:" + ComponentPostern + ":" + res.Version, Details: details}
	if err := cfg.DB.AppendAudit(context.WithoutCancel(r.Context()), entry); err != nil {
		cfg.log().Error("could not write the audit log", "action", action, "err", err)
	}
	cfg.log().Info("release bundle "+map[bool]string{true: "uploaded", false: "refused"}[res.Accepted],
		"version", res.Version, "assets", len(res.Assets), "admin", adminID)
	data, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	_, _ = w.Write(data) // the client is gone if this fails
}

// A bundleError is a bundle that cannot be read at all: not a tar, cut short.
type bundleError struct{ err error }

func (e *bundleError) Error() string { return "the bundle cannot be read: " + e.err.Error() }
func (e *bundleError) Unwrap() error { return e.err }

// A part is one member of the bundle that was kept for a look: its path in
// the temporary directory.
type part struct{ path string }

// upload reads the bundle and decides on it, as UploadHandler documents.
func (cfg UploadConfig) upload(ctx context.Context, body io.Reader) (res *UploadResult, err error) {
	res = &UploadResult{Assets: []AssetResult{}}
	tmp, err := tempDir(cfg.Cache.Dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }() // gone already when it was renamed whole

	parts, err := cfg.unpack(ctx, body, tmp, res)
	if err != nil {
		return nil, err
	}
	version, verdicts := cfg.judge(parts, res)
	res.Version = version
	if len(res.Assets) == 0 {
		res.Error = "no binary in the bundle"
		return res, nil
	}
	accepted := version != "" && len(verdicts) > 0
	for _, v := range res.Assets {
		accepted = accepted && v.OK
	}
	// The stable list: read now, applied once the binaries are in. (A part
	// that is not there has the zero path.)
	list, sig := parts[stableFile].path, parts[stableFile+".minisig"].path
	var listData, sigData []byte
	if list != "" || sig != "" || res.Stable != nil {
		if res.Stable == nil {
			res.Stable = &StableResult{}
		}
		switch {
		case res.Stable.Reason != "": // twice
		case list == "":
			res.Stable.Reason = "a .minisig with no " + stableFile
		case sig == "":
			res.Stable.Reason = "no .minisig for " + stableFile
		default:
			if listData, err = os.ReadFile(list); err != nil {
				return nil, err
			}
			if sigData, err = os.ReadFile(sig); err != nil {
				return nil, err
			}
		}
		if res.Stable.Reason != "" {
			accepted = false
		}
	}
	if !accepted {
		return res, nil
	}

	// S5-13: the bytes of a version never change. A verified asset whose
	// SHA-256 differs from the recorded pin of the release, or from what the
	// cache holds for it, refuses the whole bundle before anything is written.
	if !claim(version) {
		return nil, errBusy
	}
	defer unclaim(version)
	// The cache's lock of the version, which Put takes as well: nothing
	// fetched is renamed over the files between the check and the commit.
	unlock := cfg.Cache.lockVersion(version)
	defer unlock()
	var own, providers []verdict
	for _, v := range verdicts {
		if v.provider {
			providers = append(providers, v)
		} else {
			own = append(own, v)
		}
	}
	if err := cfg.refuseChanged(ctx, version, own, res); err != nil {
		return nil, err
	}
	cfg.refuseUnpinned(ctx, providers, res)
	for _, v := range res.Assets {
		accepted = accepted && v.OK
	}
	if !accepted {
		return res, nil
	}

	// Postern's own binaries first, the provider binaries only once those are
	// in: a failure of the own ones leaves nothing taken by the catalog. commit
	// may rename tmp whole, so the provider files wait in a directory of their own.
	var held string
	if len(providers) > 0 {
		if held, err = tempDir(cfg.Cache.Dir); err != nil {
			return nil, err
		}
		defer func() { _ = os.RemoveAll(held) }()
		for _, v := range providers {
			for _, name := range []string{v.asset, v.asset + ".minisig"} {
				if err := os.Rename(filepath.Join(tmp, name), filepath.Join(held, name)); err != nil {
					return nil, err
				}
			}
		}
	}
	if len(own) > 0 {
		if err := cfg.commit(ctx, tmp, version, own); err != nil {
			return nil, err
		}
	}
	for _, v := range providers {
		sig, err := os.ReadFile(filepath.Join(held, v.asset+".minisig"))
		if err != nil {
			return nil, err
		}
		if _, err := cfg.Providers.TakeUploaded(ctx, v.comp, v.arch, filepath.Join(held, v.asset), sig); err != nil {
			return nil, fmt.Errorf("the release catalog did not take %s: %w", v.asset, err)
		}
	}
	res.Accepted = true
	if res.Stable != nil {
		cfg.applyStable(ctx, listData, sigData, res.Stable)
	}
	return res, nil
}

// unpack reads the tar into tmp: only members whose name is a release asset,
// its .minisig, or the stable list and its .minisig; anything else is listed
// as ignored and skipped. A name twice is an error of that asset.
func (cfg UploadConfig) unpack(ctx context.Context, body io.Reader, tmp string, res *UploadResult) (map[string]part, error) {
	parts := map[string]part{}
	twice := map[string]bool{}
	tr := tar.NewReader(body)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var overRun *http.MaxBytesError
			if errors.As(err, &overRun) {
				return nil, err
			}
			return nil, &bundleError{err}
		}
		name := hdr.Name
		limit := int64(maxBinary)
		switch {
		case hdr.Typeflag != tar.TypeReg || sparse(hdr):
			res.Ignored = append(res.Ignored, name)
			continue
		case name == stableFile:
			limit = maxStableList
		case name == stableFile+".minisig":
			limit = maxSignature
		default:
			if _, ok := bundleSignature(name); ok {
				limit = maxSignature
			} else if _, _, _, ok := bundleAsset(name); !ok {
				res.Ignored = append(res.Ignored, name)
				continue
			}
		}
		if _, dup := parts[name]; dup {
			twice[name] = true
		}
		p := filepath.Join(tmp, name) //nolint:gosec // G305: name is one of the known asset names by now (no path in any of them)
		_, err = writeMember(p, tr, limit)
		if err != nil {
			var overRun *http.MaxBytesError
			if errors.As(err, &overRun) {
				return nil, err
			}
			return nil, &bundleError{err}
		}
		parts[name] = part{path: p}
	}
	for name := range twice {
		asset := strings.TrimSuffix(name, ".minisig")
		if asset == stableFile {
			res.Stable = &StableResult{Reason: "the bundle holds " + name + " twice"}
		} else {
			res.Assets = append(res.Assets, AssetResult{Name: asset, Reason: "the bundle holds " + name + " twice"})
		}
		delete(parts, asset)
		delete(parts, asset+".minisig")
	}
	return parts, nil
}

// writeMember copies a member to p, at most limit+1 bytes; over the limit it
// is an error. (A limit here keeps a lying header from filling the disk; the
// whole bundle is under MaxUpload anyway.)
func writeMember(p string, r io.Reader, limit int64) (n int64, err error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // G302,G304: the panel's temporary directory; the name is a known asset name
	if err != nil {
		return 0, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	n, err = io.Copy(f, io.LimitReader(r, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, fmt.Errorf("%s is over %d bytes", filepath.Base(p), limit)
	}
	return n, nil
}

// A verdict is a verified binary of the bundle.
type verdict struct {
	asset, arch, comp, sha string
	provider               bool // a provider binary (psiphon-core): for the catalog
}

// judge verifies every binary of parts against its .minisig and returns the
// version of the bundle (what the signatures name, "" when they disagree or
// none is readable) and the binaries that verified. Every binary and every
// stray signature gets an AssetResult.
func (cfg UploadConfig) judge(parts map[string]part, res *UploadResult) (string, []verdict) {
	names := make([]string, 0, len(parts))
	for name := range parts {
		if _, _, _, ok := bundleAsset(name); ok {
			names = append(names, name)
		} else if asset, ok := bundleSignature(name); ok {
			if _, has := parts[asset]; !has {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)

	// The version comes from the signatures: the trusted comment of each
	// names one, and VerifyWith then checks that comment cryptographically
	// against what the asset's name says. Every signature has to name the
	// same version (string equality).
	version := ""
	versions := map[string]bool{}
	type pending struct {
		name   string
		sig    []byte
		signed release.Signed
	}
	var todo []pending
	for _, name := range names {
		if asset, ok := bundleSignature(name); ok {
			res.Assets = append(res.Assets, AssetResult{Name: asset, Reason: "a .minisig with no asset"})
			continue
		}
		sigPart, ok := parts[name+".minisig"]
		if !ok {
			res.Assets = append(res.Assets, AssetResult{Name: name, Reason: "no .minisig"})
			continue
		}
		sig, err := os.ReadFile(sigPart.path)
		if err != nil {
			res.Assets = append(res.Assets, AssetResult{Name: name, Reason: "the .minisig cannot be read"})
			continue
		}
		comp, arch, _, _ := bundleAsset(name)
		v, err := commentVersion(sig, comp, arch)
		if err != nil {
			res.Assets = append(res.Assets, AssetResult{Name: name, Reason: err.Error()})
			continue
		}
		if !isPosternTag(v) {
			res.Assets = append(res.Assets, AssetResult{Name: name, Reason: "the signature names " + v + ", which is not a Postern release version (vX.Y.Z)"})
			continue
		}
		versions[v] = true
		todo = append(todo, pending{name: name, sig: sig, signed: release.Signed{Component: comp, Version: v, OS: binaryOS, Arch: arch}})
	}
	if len(versions) == 1 {
		for v := range versions {
			version = v
		}
	}
	var out []verdict
	for _, p := range todo {
		if len(versions) > 1 {
			res.Assets = append(res.Assets, AssetResult{Name: p.name, Reason: "the signature names version " + p.signed.Version + ", another asset another version"})
			continue
		}
		sha, err := cfg.Cache.verifyFile(parts[p.name].path, p.sig, p.signed)
		if err != nil {
			res.Assets = append(res.Assets, AssetResult{Name: p.name, Reason: err.Error()})
			continue
		}
		res.Assets = append(res.Assets, AssetResult{Name: p.name, OK: true, SHA256: sha})
		_, _, provider, _ := bundleAsset(p.name)
		out = append(out, verdict{asset: p.name, arch: p.signed.Arch, comp: p.signed.Component, sha: sha, provider: provider})
	}
	sort.Slice(res.Assets, func(i, j int) bool { return res.Assets[i].Name < res.Assets[j].Name })
	return version, out
}

// commentVersion reads the version that the trusted comment of sig names for
// the component and the arch ("postern <component> <version> linux/<arch>").
// It is only a reading: VerifyWith checks the comment against the signature.
func commentVersion(sig []byte, comp, arch string) (string, error) {
	var parsed minisign.Signature
	if err := parsed.UnmarshalText(sig); err != nil {
		return "", fmt.Errorf("%w: %v", release.ErrBadSignature, err)
	}
	prefix := "postern " + comp + " "
	suffix := " " + binaryOS + "/" + arch
	v, ok := strings.CutPrefix(parsed.TrustedComment, prefix)
	if ok {
		v, ok = strings.CutSuffix(v, suffix)
	}
	if !ok || !release.ValidVersion(v) {
		return "", fmt.Errorf("%w: the signature is for %q, and one for %s<version>%s is wanted", release.ErrWrongArtifact, parsed.TrustedComment, prefix, suffix)
	}
	return v, nil
}

// commit moves the verified binaries and their signatures from tmp into the
// cache (the directory is renamed in whole when the version is new, else each
// pair is moved in) and records the release.
func (cfg UploadConfig) commit(ctx context.Context, tmp, version string, verdicts []verdict) error {
	dst := filepath.Join(cfg.Cache.Dir, version)
	for _, v := range verdicts {
		if err := os.Chmod(filepath.Join(tmp, v.asset), 0o755); err != nil { //nolint:gosec // G302: a binary
			return err
		}
	}
	if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
		// Everything else in tmp was already decided; rename whole, then
		// drop what is not a verified binary or its signature.
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		want := map[string]bool{}
		for _, v := range verdicts {
			want[v.asset], want[v.asset+".minisig"] = true, true
		}
		entries, err := os.ReadDir(dst)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !want[e.Name()] {
				_ = os.Remove(filepath.Join(dst, e.Name()))
			}
		}
	} else if err != nil {
		return err
	} else {
		// The version is cached already: refuseChanged saw to it that what
		// is there has the same bytes, so only what is missing is added.
		for _, v := range verdicts {
			if _, cached := cfg.Cache.cachedSHA(version, v.asset); cached {
				continue
			}
			if err := commit(filepath.Join(tmp, v.asset), filepath.Join(dst, v.asset)); err != nil {
				return err
			}
		}
	}
	return cfg.record(ctx, version, verdicts)
}

// refuseUnpinned marks every verified provider binary that the catalog does
// not pin (or that there is no catalog for): such an upload is refused whole,
// before anything is written.
func (cfg UploadConfig) refuseUnpinned(ctx context.Context, providers []verdict, res *UploadResult) {
	for _, v := range providers {
		reason := ""
		if cfg.Providers == nil {
			reason = "this panel has no release catalog to keep " + v.comp + " in"
		} else if _, err := cfg.Providers.PinnedVersion(ctx, v.comp, v.arch, v.sha); err != nil {
			reason = "not a " + v.comp + " binary that this panel pins for " + v.arch + ": " + err.Error()
		}
		if reason == "" {
			continue
		}
		for i := range res.Assets {
			if res.Assets[i].Name == v.asset {
				res.Assets[i].OK, res.Assets[i].Reason = false, reason
			}
		}
	}
}

// refuseChanged marks every verified asset whose SHA-256 differs from the
// pin that the recorded release holds for it, or from the bytes the cache
// holds for it (S5-13): such an upload is refused whole, and nothing is
// written. Only the row's pin for the same file counts (an arch's row names
// one file).
func (cfg UploadConfig) refuseChanged(ctx context.Context, version string, verdicts []verdict, res *UploadResult) error {
	rel, err := cfg.DB.ReleaseOf(ctx, ComponentPostern, version)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	refuse := func(name, reason string) {
		for i := range res.Assets {
			if res.Assets[i].Name == name {
				res.Assets[i].OK, res.Assets[i].Reason = false, reason
			}
		}
	}
	for _, v := range verdicts {
		if pin := otherPin(rel, v.asset, v.sha); pin != "" {
			refuse(v.asset, "the recorded release "+version+" has other bytes for this asset (pinned sha256 "+pin+"); a new build needs a new version")
			continue
		}
		if have, ok := cfg.Cache.cachedSHA(version, v.asset); ok && have != v.sha {
			refuse(v.asset, "the cache holds "+version+" with other bytes for this asset (sha256 "+have+"); a new build needs a new version")
		}
	}
	return nil
}

// record writes the release: component postern, source upload, with the node
// binary of each arch as its asset (the panel's when the bundle has no node
// binary for the arch), pinned to its SHA-256 (source signed) and ready. The
// row has one asset per arch and a pin never changes, so an arch that the
// recorded release already has an asset for is left as it is: a later bundle
// adds only the arches that are missing. The panel binary of an arch is
// pinned besides, under PanelPinKey(arch); the cache finds it by its name.
func (cfg UploadConfig) record(ctx context.Context, version string, verdicts []verdict) error {
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	return recordRelease(ctx, cfg.DB, now(), version, store.SourceUpload, verdicts)
}

// recordRelease writes the release of the verified assets as record says,
// with source as the row's source when the row is new.
func recordRelease(ctx context.Context, db *store.DB, now time.Time, version, source string, verdicts []verdict) error {
	old, err := db.ReleaseOf(ctx, ComponentPostern, version)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	oldAssets := map[string]store.ReleaseAsset{}
	if old != nil {
		source, oldAssets = old.Source, old.Assets
	}
	rel := &store.Release{Engine: ComponentPostern, Version: version, Tag: version, Source: source, FetchedAt: now, Assets: map[string]store.ReleaseAsset{}}
	pin := func(key string, v verdict) {
		rel.Assets[key] = store.ReleaseAsset{File: v.asset, SHA256: v.sha, SHASource: store.SHASourceSigned, State: store.AssetReady, CheckedAt: now}
	}
	for _, v := range verdicts {
		// The panel binary has a key of its own, so that it is pinned
		// whatever the arch's key holds.
		if v.comp == componentPanel {
			if _, has := oldAssets[PanelPinKey(v.arch)]; !has {
				pin(PanelPinKey(v.arch), v)
			}
		}
		if _, has := oldAssets[v.arch]; has {
			continue
		}
		if a, ok := rel.Assets[v.arch]; ok && a.File == NodeAsset(v.arch) {
			continue
		}
		pin(v.arch, v)
	}
	// A pin that would change is a hard error: refuseChanged compared the
	// bytes with the row before anything was written, so it cannot happen
	// short of a concurrent writer.
	return db.UpsertRelease(ctx, rel)
}

// applyStable gives the catalog the stable list of the bundle.
func (cfg UploadConfig) applyStable(ctx context.Context, list, sig []byte, res *StableResult) {
	if cfg.Stable == nil {
		res.Reason = "the panel has no release catalog to apply the list to"
		return
	}
	err := cfg.Stable.ApplyStable(ctx, list, sig)
	if err != nil {
		res.Reason = err.Error()
		return
	}
	res.Applied = true
}

// sparse reports whether a member is a sparse file (GNU or PAX sparse map):
// its reader makes the holes up as zeros, so a few bytes of bundle could
// stand for 256 MiB of file. A release bundle has no such member.
func sparse(hdr *tar.Header) bool {
	if hdr.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}

// PanelPinKey is the key of the release row's assets under which the panel
// binary of arch is pinned. The key of the arch itself holds the node binary
// (or the panel's, when a bundle has no node binary for the arch).
func PanelPinKey(arch string) string { return "panel-" + arch }

// otherPin returns a SHA-256 that the release row pins for the file asset
// (under the arch's key or the panel's key) and that is not sha; "" when every
// pin of the file is sha, or there is none.
func otherPin(rel *store.Release, asset, sha string) string {
	for _, a := range pinsOf(rel, asset) {
		if a != sha {
			return a
		}
	}
	return ""
}

// pinsOf returns the SHA-256 pins that the release row holds for the file
// asset.
func pinsOf(rel *store.Release, asset string) []string {
	if rel == nil {
		return nil
	}
	comp, arch, ok := ParseAsset(asset)
	if !ok {
		return nil
	}
	keys := []string{arch}
	if comp == componentPanel {
		keys = append(keys, PanelPinKey(arch))
	}
	var pins []string
	for _, k := range keys {
		if a, has := rel.Assets[k]; has && a.File == asset && a.SHA256 != "" {
			pins = append(pins, a.SHA256)
		}
	}
	return pins
}
