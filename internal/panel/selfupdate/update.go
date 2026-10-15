package selfupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/version"
)

// The files of the self-update, in the data directory (spec §7, the launcher
// contract of deploy/panel/launcher.sh).
const (
	// DatabaseFile is the database of the panel in the data directory.
	DatabaseFile = "postern.db"
	// DefaultImageBinary is the binary of the panel in its Docker image, which
	// the launcher runs when there is no bin/current (POSTERN_PANEL_BIN
	// overrides it, as it does for the launcher).
	DefaultImageBinary = "/usr/local/bin/postern-panel"
	// EnvImageBinary overrides DefaultImageBinary.
	EnvImageBinary = "POSTERN_PANEL_BIN"
	// ExitRestart is the exit status of a panel that installed a new version:
	// Docker starts the launcher again, which runs bin/current.
	ExitRestart = 75

	binDir       = "bin"
	journalFile  = "run/selfupdate.json"
	rollbackFile = "run/launcher/rollback"
	// imageNoteFile says that a newer image replaced the self-updated binary
	// (recoverer.imageIsNewer), until the image binary has recorded it.
	imageNoteFile = "run/image-newer"
	binPrefix     = "postern-panel-"
	trialTimeout  = 10 * time.Second
	maxTrialOut   = 4 << 10
	newerTTL      = 10 * time.Minute
)

// The events and the audit action of the self-update.
const (
	AuditUpdateStarted    = "panel_update_started"
	EventUpdated          = "panel_updated"
	EventUpdateRolledBack = "panel_update_rolled_back"
	EventUpdateAbandoned  = "panel_update_abandoned"
	EventImageNewer       = "panel_image_newer"
)

var (
	// ErrRestart is returned by Update once the new version is installed: the
	// caller answers, stops the panel as on SIGTERM, and exits with
	// ExitRestart. Recover returns it when a newer image binary wins.
	ErrRestart = errors.New("selfupdate: restart into the new version")
	// ErrRefused wraps the reason why Update does not install a version; it is
	// the operator's to act on (a node to update first, a downgrade, a panel
	// that was not started by its launcher).
	ErrRefused = errors.New("selfupdate: the update is refused")
)

// refuse returns ErrRefused with the reason.
func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// An Updater installs a release of Postern as the panel's binary: in
// <DataDir>/bin, as the launcher reads it.
type Updater struct {
	// DataDir is the data directory (/data).
	DataDir string
	// Releases is the release source and its cache of verified binaries.
	Releases *Releases
	DB       *store.DB
	// Version is the running version; "" is version.Version.
	Version string
	// HealthyFile is POSTERN_HEALTHY_FILE: set only when the launcher started
	// the panel, which an update needs.
	HealthyFile string
	// ImageBin is the binary of the image; "" is $POSTERN_PANEL_BIN or
	// DefaultImageBinary.
	ImageBin string
	// Arch is the architecture of the panel; "" is runtime.GOARCH.
	Arch string
	Now  func() time.Time
	// Exec runs a binary with arguments and returns its standard output; nil
	// runs it with a timeout of 10 s and an empty environment. Tests fake it.
	Exec func(ctx context.Context, path string, args ...string) ([]byte, error)
	Log  *slog.Logger

	mu         sync.Mutex // one update at a time
	restarting string     // the version installed, once Update has returned ErrRestart

	imageOnce sync.Once
	imageVer  string

	newerMu  sync.Mutex
	newerAt  time.Time
	newerFed []store.Release
}

func (u *Updater) version() string {
	if u.Version != "" {
		return u.Version
	}
	return version.Version
}

func (u *Updater) arch() string {
	if u.Arch != "" {
		return u.Arch
	}
	return runtime.GOARCH
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) log() *slog.Logger {
	if u.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return u.Log
}

func (u *Updater) imageBin() string { return imageBinary(u.ImageBin) }

// imageBinary is the binary of the image: bin, else $POSTERN_PANEL_BIN, else
// DefaultImageBinary.
func imageBinary(bin string) string {
	if bin != "" {
		return bin
	}
	if v := strings.TrimSpace(os.Getenv(EnvImageBinary)); v != "" {
		return v
	}
	return DefaultImageBinary
}

func (u *Updater) exec(ctx context.Context, path string, args ...string) ([]byte, error) {
	if u.Exec != nil {
		return u.Exec(ctx, path, args...)
	}
	return runBinary(ctx, path, args...)
}

// runBinary runs path with args for at most trialTimeout, with an empty
// environment (no marker path, no secret), and returns at most 4 KiB of its
// standard output.
func runBinary(ctx context.Context, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, trialTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: the binary is the panel's own, verified
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	out := &capped{max: maxTrialOut}
	cmd.Stdout = out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	return out.buf.Bytes(), err
}

// capped keeps the first max bytes written to it.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// Available reports whether the panel can update itself, and why not: it was
// started by its launcher (POSTERN_HEALTHY_FILE), <data>/bin is writable and
// a file there runs (a trial), and a release key is compiled in.
func (u *Updater) Available(ctx context.Context) (ok bool, reason string) {
	if u.HealthyFile == "" {
		return false, "POSTERN_HEALTHY_FILE is not set: the panel's launcher (deploy/panel/launcher.sh, run by the image's entrypoint for \"serve\") gave it no marker path, " +
			"which an update needs to restart into the new version and roll back a failed one; " +
			"start the panel through the image's entrypoint (restart the container with the compose file of this version)"
	}
	if u.Releases == nil || u.Releases.Cache == nil {
		return false, "the panel has no release source"
	}
	if keys, err := u.Releases.Cache.keys(); err != nil || len(keys) == 0 {
		return false, "no release key is compiled into this panel, so no release can be verified"
	}
	if err := u.trialBin(ctx); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// trialBin writes a small script into <data>/bin and runs it.
func (u *Updater) trialBin(ctx context.Context) error {
	dir := filepath.Join(u.DataDir, binDir)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: the binaries are public
		return fmt.Errorf("%s cannot be made: %w", dir, err)
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	p := filepath.Join(dir, ".trial-"+hex.EncodeToString(b[:]))
	defer func() { _ = os.Remove(p) }()
	const word = "postern-trial-ok"
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho "+word+"\n"), 0o700); err != nil { //nolint:gosec // G306: a script that has to run
		return fmt.Errorf("%s is not writable: %w", dir, err)
	}
	out, err := u.exec(ctx, p)
	if err != nil || !strings.Contains(string(out), word) {
		return fmt.Errorf("a file in %s does not run (is the volume mounted noexec?): %v", dir, err)
	}
	return nil
}

// minorFloor returns the oldest agent version that a panel of version v
// supports (spec §6: the previous minor): vX.(Y-1).0, or v(X-1).0.0 for a
// vX.0 (whose previous minor is the last of X-1, which is not known here). ok
// is false when v does not read as a version or has no previous minor.
func minorFloor(v string) (floor string, ok bool) {
	prefix := ""
	s := v
	if strings.HasPrefix(s, "v") {
		prefix, s = "v", s[1:]
	}
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return "", false
	}
	major, err1 := strconv.ParseUint(parts[0], 10, 32)
	minor, err2 := strconv.ParseUint(parts[1], 10, 32)
	if err1 != nil || err2 != nil {
		return "", false
	}
	switch {
	case minor > 0:
		return fmt.Sprintf("%s%d.%d.0", prefix, major, minor-1), true
	case major > 0:
		return fmt.Sprintf("%s%d.0.0", prefix, major-1), true
	}
	return "", false
}

// OldNodes returns the nodes whose agent is older than the previous minor of
// v, as "<name> (<agent version>)", and the floor. A node that has not
// reported a version yet is not counted.
func (u *Updater) OldNodes(ctx context.Context, v string) (names []string, floor string, err error) {
	floor, ok := minorFloor(v)
	if !ok {
		return nil, "", nil
	}
	nodes, err := u.DB.ListNodes(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, n := range nodes {
		if n.AgentVersion != "" && release.Compare(n.AgentVersion, floor) < 0 {
			names = append(names, n.Name+" ("+n.AgentVersion+")")
		}
	}
	return names, floor, nil
}

// A journal records an update in flight, in <data>/run/selfupdate.json, for
// Recover.
type journal struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Backup string `json:"backup"`
	At     int64  `json:"at"` // Unix seconds
	// Restoring is set by Recover once it has kept the failed database in
	// this directory and is putting the snapshot in place.
	Restoring string `json:"restoring,omitempty"`
}

// Update installs version v of the panel and returns ErrRestart, after which
// the caller stops the panel and exits with ExitRestart; the launcher then
// starts v, and rolls back to the running version if v does not get healthy
// (Recover restores the database then). It refuses (ErrRefused) a version
// that is not newer than the running one, while a node's agent is older than
// the previous minor of v (spec §6), and when Available says no. The panel
// binary and both node binaries of v are fetched into the cache (unless
// there), checked against the release's pins and pinned where the row has
// no pin yet (the panel binary under PanelPinKey), and the panel binary is
// copied into bin, verified again (signature, static ELF, its pin) and tried
// (`<binary> version` prints "<v> ("); its pin is checked once more right
// before it is moved in. Then the database is copied
// (store.Backup, VACUUM INTO), the journal written, the binary installed as
// bin/postern-panel-<v>, bin/previous pointed at what bin/current points to
// (the image binary, by its absolute path, when there is no bin/current) and
// bin/current at the new file. A failure before the links are switched
// leaves no journal and no new file.
func (u *Updater) Update(ctx context.Context, v string) (err error) {
	if !release.ValidVersion(v) {
		return fmt.Errorf("%w: %q", ErrBadVersion, v)
	}
	if !u.mu.TryLock() {
		return refuse("another update of the panel is in progress")
	}
	defer u.mu.Unlock()
	if u.restarting != "" {
		return refuse("the panel is restarting into %s", u.restarting)
	}
	running := u.version()
	if v == running {
		return refuse("the panel runs %s already", v)
	}
	if !release.Newer(v, running) {
		return refuse("%s is not newer than the running %s: the panel never downgrades itself (to go back to the image, remove /data/bin/current)", v, running)
	}
	if ok, reason := u.Available(ctx); !ok {
		return refuse("%s", reason)
	}
	old, floor, err := u.OldNodes(ctx, v)
	if err != nil {
		return err
	}
	if len(old) > 0 {
		return refuse("these nodes run an agent older than %s, the oldest that %s supports: %s; update them first", floor, v, strings.Join(old, ", "))
	}

	arch := u.arch()
	panelAsset := PanelAsset(arch)
	assets := []string{panelAsset, NodeAsset("amd64"), NodeAsset("arm64")}
	fetched, err := u.fetch(ctx, v, assets)
	if err != nil {
		return err
	}
	tmp, shas, err := u.stage(ctx, v, assets, panelAsset)
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(tmp)
		}
	}()
	// Every binary of the release is pinned in its row (the panel binary
	// under PanelPinKey), the first time from the verified, signed bytes; a
	// pin never changes.
	var vs []verdict
	for _, a := range assets {
		comp, a2, _ := ParseAsset(a)
		vs = append(vs, verdict{asset: a, arch: a2, comp: comp, sha: shas[a]})
	}
	source := store.SourceUpload
	if fetched {
		source = store.SourceUpstream
	}
	if err := recordRelease(ctx, u.DB, u.now(), v, source, vs); err != nil {
		return err
	}
	if err := u.checkPin(ctx, v, tmp); err != nil {
		return err
	}

	out, err := u.exec(ctx, tmp, "version")
	if !strings.HasPrefix(string(out), v+" (") {
		line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
		return refuse("the binary of %s does not run here: `version` printed %q (%v)", v, line, err)
	}

	backup, err := u.DB.Backup(ctx, "pre-"+v)
	if err != nil {
		return err
	}
	defer func() {
		if !installed {
			_ = os.Remove(backup) // nothing was installed: the copy is for nothing
		}
	}()
	j := journal{From: running, To: v, Backup: backup, At: u.now().Unix()}
	jPath := filepath.Join(u.DataDir, journalFile)
	if err := writeJSON(jPath, j); err != nil {
		return fmt.Errorf("selfupdate: write the journal: %w", err)
	}
	// The binary was run since it was checked: its bytes are checked against
	// the pin once more right before it is moved in.
	if err := u.checkPin(ctx, v, tmp); err != nil {
		_ = os.Remove(jPath)
		return err
	}
	u.audit(ctx, running, v, backup)
	if err := u.install(tmp, v); err != nil {
		_ = os.Remove(jPath)
		return err
	}
	installed = true

	u.log().Info("the panel installed a new version and restarts into it", "from", running, "to", v, "backup", backup)
	u.restarting = v
	return ErrRestart
}

// checkPin hashes the file p and compares it with the SHA-256 that the
// release row of v pins for the panel binary of the arch; a missing pin or
// another SHA-256 is refused.
func (u *Updater) checkPin(ctx context.Context, v, p string) error {
	rel, err := u.DB.ReleaseOf(ctx, ComponentPostern, v)
	if err != nil {
		return fmt.Errorf("selfupdate: read the release %s: %w", v, err)
	}
	asset := PanelAsset(u.arch())
	pin := rel.Assets[PanelPinKey(u.arch())]
	if pin.File != asset || pin.SHA256 == "" {
		return refuse("the release %s has no pinned sha256 for %s", v, asset)
	}
	sha, err := fileSHA(p)
	if err != nil {
		return err
	}
	if sha != pin.SHA256 {
		return refuse("the staged %s of %s has sha256 %s, but the release pins %s", asset, v, sha, pin.SHA256)
	}
	return nil
}

// fileSHA returns the SHA-256 of the file at p, lower-case hex.
func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// install moves the staged binary to bin/postern-panel-<v> and switches the
// links. When a link cannot be switched, the new file is removed again and
// bin/current is left as it was.
func (u *Updater) install(tmp, v string) error {
	dir := filepath.Join(u.DataDir, binDir)
	name := binPrefix + v
	dst := filepath.Join(dir, name)
	cur := filepath.Join(dir, "current")
	prev, err := os.Readlink(cur)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		prev = u.imageBin()
		if !filepath.IsAbs(prev) {
			return fmt.Errorf("selfupdate: the image binary %q is not an absolute path", prev)
		}
	case err != nil:
		return fmt.Errorf("selfupdate: read bin/current: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("selfupdate: install %s: %w", name, err)
	}
	if err := relink(dir, "previous", prev); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if err := relink(dir, "current", name); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

// relink points dir/name at target: a new link renamed over the old one.
func relink(dir, name, target string) error {
	tmp := filepath.Join(dir, "."+name+".new")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("selfupdate: link bin/%s: %w", name, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("selfupdate: link bin/%s: %w", name, err)
	}
	return nil
}

// fetch downloads the assets of v that the cache does not hold verified. It
// reports whether it downloaded anything.
func (u *Updater) fetch(ctx context.Context, v string, assets []string) (bool, error) {
	c := u.Releases.Cache
	var missing []string
	for _, a := range assets {
		if _, ok := c.cachedSHA(v, a); !ok {
			missing = append(missing, a)
		}
	}
	if len(missing) == 0 {
		return false, nil
	}
	src, err := u.Releases.Source(ctx)
	if err != nil {
		return false, err
	}
	if err := c.Fetch(ctx, src, v, missing); err != nil {
		return false, fmt.Errorf("selfupdate: fetch %s: %w", v, err)
	}
	return true, nil
}

// stage checks, under the cache's lock of v, that every asset is cached and
// verifies and that its SHA-256 is the one the release row pins for it (a
// cached file that fails verification counts as absent, so a Put may have
// replaced it); then it copies the panel binary into bin and verifies the
// copy (signature, static ELF, the same SHA-256). It returns the copy and the
// SHA-256 of each asset.
func (u *Updater) stage(ctx context.Context, v string, assets []string, panelAsset string) (string, map[string]string, error) {
	c := u.Releases.Cache
	shas := map[string]string{}
	var sig []byte
	tmp, err := func() (string, error) {
		defer c.lockVersion(v)()
		rel, err := u.DB.ReleaseOf(ctx, ComponentPostern, v)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return "", err
		}
		for _, a := range assets {
			sha, ok := c.cachedSHA(v, a)
			if !ok {
				return "", refuse("%s of %s is not in the cache, or no longer verifies", a, v)
			}
			if pin := otherPin(rel, a, sha); pin != "" {
				return "", refuse("the cached %s of %s has sha256 %s, but the release pins %s", a, v, sha, pin)
			}
			shas[a] = sha
		}
		p := c.path(v, panelAsset)
		if sig, err = os.ReadFile(p + ".minisig"); err != nil {
			return "", err
		}
		return copyInto(p, filepath.Join(u.DataDir, binDir), ".postern-panel-"+v+"-*")
	}()
	if err != nil {
		return "", nil, err
	}
	want, err := signed(v, panelAsset)
	if err == nil {
		var sha string
		if sha, err = c.verifyFile(tmp, sig, want); err == nil && sha != shas[panelAsset] {
			err = refuse("the copy of %s of %s has sha256 %s, not %s", panelAsset, v, sha, shas[panelAsset])
		}
	}
	if err == nil {
		err = os.Chmod(tmp, 0o755) //nolint:gosec // G302: a binary
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", nil, err
	}
	return tmp, shas, nil
}

// copyInto copies the file at src to a new temporary file in dir, named by
// pattern, and returns its path.
func copyInto(src, dir, pattern string) (path string, err error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(out.Name())
		}
	}()
	if _, err := io.Copy(out, io.LimitReader(in, maxBinary+1)); err != nil {
		return "", err
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	return out.Name(), nil
}

// writeJSON writes v as JSON to path atomically (a temporary file in the
// directory, synced, and a rename), 0600.
func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		_ = os.Remove(f.Name())
	}
	return err
}

// audit records panel_update_started, by the admin of ctx.
func (u *Updater) audit(ctx context.Context, from, to, backup string) {
	entry := &store.AuditEntry{Action: AuditUpdateStarted, Target: "release:" + ComponentPostern + ":" + to,
		Details: map[string]string{"from": from, "to": to, "backup": backup}}
	if a, ok := auth.AdminFrom(ctx); ok {
		entry.AdminID = a.ID
	}
	if err := u.DB.AppendAudit(context.WithoutCancel(ctx), entry); err != nil {
		u.log().Error("could not write the audit log", "action", AuditUpdateStarted, "err", err)
	}
}

// ImageVersion is the version that the image binary reports (`version`), ""
// when it cannot be run. It is asked once.
func (u *Updater) ImageVersion(ctx context.Context) string {
	u.imageOnce.Do(func() { u.imageVer = binaryVersion(ctx, u.exec, u.imageBin()) })
	return u.imageVer
}

// binaryVersion runs `<bin> version` and returns the version it prints before
// " (", "" when it does not run or prints something else.
func binaryVersion(ctx context.Context, run func(context.Context, string, ...string) ([]byte, error), bin string) string {
	out, err := run(ctx, bin, "version")
	if err != nil {
		return ""
	}
	v, _, ok := strings.Cut(string(out), " (")
	if !ok || !release.ValidVersion(v) {
		return ""
	}
	return v
}

// Newer returns the releases of Postern newer than the running version,
// newest first: those the panel has recorded (uploads, earlier fetches) and
// those the release source lists, which is asked at most every 10 minutes
// (a failure is logged and leaves the recorded ones).
func (u *Updater) Newer(ctx context.Context) ([]store.Release, error) {
	rows, err := u.DB.ListReleases(ctx, ComponentPostern)
	if err != nil {
		return nil, err
	}
	running := u.version()
	seen := map[string]bool{}
	var out []store.Release
	add := func(r store.Release) {
		if seen[r.Version] || !release.Newer(r.Version, running) {
			return
		}
		seen[r.Version] = true
		out = append(out, r)
	}
	for _, r := range rows {
		add(*r)
	}
	for _, r := range u.listed(ctx) {
		add(r)
	}
	slices.SortStableFunc(out, func(a, b store.Release) int {
		if c := release.Compare(b.Version, a.Version); c != 0 {
			return c
		}
		return strings.Compare(b.Version, a.Version)
	})
	return out, nil
}

// ForgetListed drops the list of the source that Newer keeps, so that the
// next Newer reads the source again: after the source or its prerelease
// setting changed.
func (u *Updater) ForgetListed() {
	u.newerMu.Lock()
	defer u.newerMu.Unlock()
	u.newerAt = time.Time{}
	u.newerFed = nil
}

// listed returns the releases of the source, from a list at most newerTTL
// old.
func (u *Updater) listed(ctx context.Context) []store.Release {
	u.newerMu.Lock()
	defer u.newerMu.Unlock()
	if !u.newerAt.IsZero() && u.now().Sub(u.newerAt) < newerTTL {
		return u.newerFed
	}
	u.newerAt = u.now()
	if u.Releases == nil {
		return nil
	}
	src, err := u.Releases.Source(ctx)
	if err == nil {
		var list []releases.FeedRelease
		if list, err = src.List(ctx); err == nil {
			u.newerFed = u.newerFed[:0]
			for _, r := range list {
				u.newerFed = append(u.newerFed, store.Release{Engine: ComponentPostern, Version: r.Tag, Tag: r.Tag,
					Source: store.SourceUpstream, Prerelease: r.Prerelease, PublishedAt: r.Published, URL: r.URL, Notes: r.Notes})
			}
		}
	}
	if err != nil {
		u.log().Warn("could not list the releases of Postern", "err", err)
	}
	return u.newerFed
}

// MinorFloor returns the oldest agent version that a panel of version v
// supports (spec §6: the previous minor), and false when v has none or does
// not read as a version.
func MinorFloor(v string) (string, bool) { return minorFloor(v) }
